"""Testy jednostkowe protokołu i transportu USB HID czytnika NFCplus."""

from __future__ import annotations

from pathlib import Path

import pytest

from nfcplus.cli import build_parser, main as cli_main
from nfcplus.dump import FACTORY_MIFARE_TRAILER, MifareDump
from nfcplus.ndef import build_ndef_uri_tlv, parse_ndef_tlv
from nfcplus.protocol import (
    END_NATIVE,
    END_PN532,
    REPORT_SIZE,
    START_NATIVE,
    START_PN532,
    ApduResponse,
    MifareWriteReport,
    NFCReader,
    ProtocolError,
    _crc16_a,
    build_frame,
    compute_checksum,
    convert_em4100_formats,
    decode_hid_prox,
    encode_em4100_t5577_blocks,
    encode_hid_t5577_blocks,
    parse_frame,
    parse_hex_bytes,
    sector_auth_from_keys,
)
from nfcplus.transport import HIDTransport, _enumerate_linux_hidraw, _parse_hidraw_uevent


def _make_response_frame(start: int, seq: int, payload: bytes, with_report_id: bool = False) -> bytes:
    end = END_NATIVE if start == START_NATIVE else END_PN532
    total_len = len(payload) + 6
    body = bytes([start, total_len, seq & 0xFF, (seq >> 8) & 0xFF]) + payload
    csum = compute_checksum(body)
    frame = (body + bytes([csum, end])).ljust(REPORT_SIZE, b"\x00")
    return (b"\x00" + frame) if with_report_id else frame


def _pn532_reply(cmd_code: int, data: bytes, seq: int = 0) -> bytes:
    return _make_response_frame(START_PN532, seq, bytes([0xD5, (cmd_code + 1) & 0xFF]) + data)


class MockHIDTransport(HIDTransport):
    """Atrapa transportu HID weryfikująca wysłane ramki i zwracająca zakolejkowane odpowiedzi."""

    def __init__(self, responses: list[bytes] | None = None) -> None:
        self._open = False
        self.sent: list[bytes] = []
        self.responses: list[bytes] = list(responses or [])

    @property
    def is_open(self) -> bool:
        return self._open

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def write(self, data: bytes) -> int:
        assert len(data) == REPORT_SIZE
        self.sent.append(data)
        return len(data)

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        if not self.responses:
            raise TimeoutError("Brak odpowiedzi w kolejce mocka.")
        return self.responses.pop(0)


def test_build_and_parse_native_frame() -> None:
    report = build_frame(b"\xff\x00\x68", seq=0x0002)
    assert len(report) == 64
    assert report[0] == 0x00
    assert report[1] == 0x01
    assert report[2] == 9  # len(3) + 6
    assert report[3:5] == b"\x02\x00"
    assert report[5:8] == b"\xff\x00\x68"
    expected_csum = (~sum(report[1:8])) & 0xFF
    assert report[8] == expected_csum
    assert report[9] == 0xFE

    start, seq, payload = parse_frame(report[1:])
    assert start == START_NATIVE
    assert seq == 2
    assert payload == b"\xff\x00\x68"


def test_parse_frame_strips_optional_report_id_and_validates_checksum() -> None:
    raw = _make_response_frame(START_PN532, seq=4, payload=b"\xd5\x4b\x00", with_report_id=True)
    start, seq, payload = parse_frame(raw)
    assert start == START_PN532
    assert seq == 4
    assert payload == b"\xd5\x4b\x00"

    bad = bytearray(raw[1:])
    bad[5] ^= 0xFF
    with pytest.raises(ProtocolError, match="sumy kontrolnej"):
        parse_frame(bytes(bad))


def test_get_device_info_and_beep() -> None:
    transport = MockHIDTransport(
        responses=[
            _make_response_frame(START_NATIVE, 0, b"V805N"),
            _make_response_frame(START_NATIVE, 2, b"wCopy NSR106-HIDIC V805N"),
            _make_response_frame(START_NATIVE, 4, b"\x90\x00"),
        ]
    )
    reader = NFCReader(transport)
    info = reader.get_device_info()
    assert info["firmware"] == "V805N"
    assert info["model"] == "wCopy NSR106-HIDIC V805N"
    assert "NFC V5.5 IC&HID" in info["display_name"]

    reader.beep(50)
    # 50 ms -> dur = 5
    _, seq, payload = parse_frame(transport.sent[2][1:])
    assert seq == 4
    assert payload == bytes([0xFF, 0x00, 0x40, 0x50, 0x04, 0x05, 0x01, 0x01, 0x01])


def test_scan_card_4byte_uid_and_mifare_ops() -> None:
    # Kolejka odpowiedzi dla init_rf=False + scan_card + auth + read + write
    uid = bytes.fromhex("12345678")
    inlist_data = bytes([0x01, 0x01, 0x00, 0x04, 0x08, 0x04]) + uid
    block_data = bytes(range(16))

    transport = MockHIDTransport(
        responses=[
            _pn532_reply(0x4A, inlist_data),  # InListPassiveTarget
            _pn532_reply(0x4E, b""),  # InPSL
            _pn532_reply(0x06, b"\x00\x90\x00"),  # ReadReg 0x6302 (set_crc)
            _pn532_reply(0x08, b"\x90\x00"),  # WriteReg 0x6302
            _pn532_reply(0x06, b"\x00\x90\x00"),  # ReadReg 0x6303
            _pn532_reply(0x08, b"\x90\x00"),  # WriteReg 0x6303
            _pn532_reply(0x06, b"\x10\x90\x00"),  # ReadReg 0x630D (set_parity)
            _pn532_reply(0x08, b"\x90\x00"),  # WriteReg 0x630D
            _pn532_reply(0x40, b"\x00"),  # Auth OK
            _pn532_reply(0x40, b"\x00" + block_data + b"\x90\x00"),  # Read Block
            _pn532_reply(0x40, b"\x00\x90\x00"),  # Write Block
        ]
    )
    reader = NFCReader(transport)
    card = reader.scan_card(init_rf=False)
    assert card is not None
    assert card.uid == uid
    assert card.atqa == b"\x04\x00"
    assert card.sak == 0x08
    assert card.card_type == "MIFARE Classic 1K"

    assert reader.mifare_auth(4, bytes.fromhex("FFFFFFFFFFFF"), card.uid, "A") is True
    assert reader.mifare_read_block(4) == block_data
    reader.mifare_write_block(4, block_data)

    # Weryfikacja ramki tunelu dla Write Block (ostatnia wysłana)
    _, _, last_payload = parse_frame(transport.sent[-1][1:])
    assert last_payload[:6] == b"\xff\x00\x00\x00\x15\xd4"
    assert last_payload[6:10] == b"\x40\x01\xa0\x04"
    assert last_payload[10:26] == block_data


def test_ntag_get_version_and_read_page_with_crc() -> None:
    ver_bytes = bytes.fromhex("0004040201000F03")  # 0x0F -> NTAG213
    ver_crc = _crc16_a(ver_bytes)
    page_bytes = b"NDEF"
    crc = _crc16_a(page_bytes)
    fast_read_resp = b"\x00" + page_bytes + crc + b"\x30\x00\x90\x00"

    transport = MockHIDTransport(
        responses=[
            _pn532_reply(0x40, b"\x00\x50" + ver_bytes + ver_crc + b"\x90\x00"),
            _pn532_reply(0x40, fast_read_resp),
            _pn532_reply(0x40, b"\x00\x90\x00"),
        ]
    )
    reader = NFCReader(transport)
    ver = reader.ntag_get_version()
    assert "NTAG213" in ver.name
    assert ver.total_pages == 45

    assert reader.ntag_read_page(4) == page_bytes
    reader.ntag_write_page(4, b"TEST")


def test_linux_hidraw_sysfs_enumeration(tmp_path: Path) -> None:
    dev_dir = tmp_path / "hidraw0" / "device"
    dev_dir.mkdir(parents=True)
    (dev_dir / "uevent").write_text(
        "DRIVER=hid-generic\nHID_ID=0003:00000416:0000B030\nHID_NAME=wCopy NSR106\nHID_UNIQ=1234\n",
        encoding="utf-8",
    )

    other_dir = tmp_path / "hidraw1" / "device"
    other_dir.mkdir(parents=True)
    (other_dir / "uevent").write_text(
        "HID_ID=0003:00001234:00005678\nHID_NAME=Mouse\n",
        encoding="utf-8",
    )

    parsed = _parse_hidraw_uevent((dev_dir / "uevent").read_text(encoding="utf-8"))
    assert parsed == (0x0416, 0xB030, "wCopy NSR106", "1234")

    found = _enumerate_linux_hidraw([(0x0416, 0xB030)], sysfs_root=tmp_path)
    assert len(found) == 1
    assert found[0].path == "/dev/hidraw0"
    assert found[0].vid_pid == "0416:b030"


def test_nsr122_pn532_framed_native_info_and_6300_no_card() -> None:
    transport = MockHIDTransport(
        responses=[
            _make_response_frame(START_PN532, 1, b"wCopy NSR122-HID V901N1"),
            _make_response_frame(START_PN532, 3, b"P37354833679"),
            _make_response_frame(START_PN532, 5, b"\x90\x01"),
            _pn532_reply(0x4A, b"\x63\x00", seq=7),
        ]
    )
    reader = NFCReader(transport)
    info = reader.get_device_info()
    assert info["firmware"] == "wCopy NSR122-HID V901N1"
    assert info["model"] == "P37354833679"
    reader.beep(80)
    assert reader.scan_card(init_rf=False) is None


def _encode_hid_wiegand_raw6(bit_length: int, data_bits: int) -> bytes:
    """Buduje 6-bajtowy wzorzec HID Prox z sentinelem i bitami parzystości Wiegand."""
    payload = (data_bits & ((1 << (bit_length - 2)) - 1)) << 1
    if bit_length == 33:
        upper = (payload >> 16) & ((1 << 16) - 1)
        lower = payload & ((1 << 17) - 1)
    elif bit_length % 2 == 0:
        half = bit_length // 2
        upper = (payload >> half) & ((1 << (half - 1)) - 1)
        lower = payload & ((1 << half) - 1)
    else:
        half = bit_length // 2
        upper = (payload >> (half + 1)) & ((1 << (half - 1)) - 1)
        lower = payload & ((1 << (half + 1)) - 1)

    p_even = upper.bit_count() % 2
    p_odd = 1 - (lower.bit_count() % 2)
    bits = (p_even << (bit_length - 1)) | payload | p_odd
    if bit_length < 37:
        w = ((1 << 37) | (1 << bit_length) | bits)
    else:
        w = bits
    return w.to_bytes(6, "big")


def test_read_em4100_native_and_nsr122_frames() -> None:
    id5 = bytes.fromhex("0102030405")
    transport = MockHIDTransport(
        responses=[
            _make_response_frame(START_NATIVE, 0, b"\x05" + id5),
            _make_response_frame(START_PN532, 3, b"\x05" + id5),
            _make_response_frame(START_PN532, 5, b"\x63\x00"),
        ]
    )
    reader = NFCReader(transport)

    card1 = reader.read_em4100(init_rf=False)
    assert card1 is not None
    assert card1.raw == id5
    assert card1.hex_id == "0102030405"
    assert card1.hex_spaced == "01 02 03 04 05"
    assert card1.decimal_10 == "0033752069"
    assert card1.wiegand_fc == 0x03
    assert card1.wiegand_cn == 0x0405
    assert card1.wiegand_26 == "00301029"

    _, _, sent_payload = parse_frame(transport.sent[0][1:])
    assert sent_payload == bytes.fromhex("FF0065051E48E8010000000000")

    card2 = reader.read_em4100(init_rf=False)
    assert card2 == card1

    assert reader.read_em4100(init_rf=False) is None


def test_decode_hid_prox_formats_and_parity() -> None:
    # 26-bit H10301: FC=42, CN=12345
    raw26 = _encode_hid_wiegand_raw6(26, (42 << 16) | 12345)
    assert raw26 == bytes.fromhex("002006546073")
    c26 = decode_hid_prox(raw26)
    assert c26 is not None
    assert c26.bit_length == 26
    assert c26.facility_code == 42
    assert c26.card_number == 12345
    assert c26.short_id == 0x06546073

    # Zły bit parzystości -> None
    bad26 = bytearray(raw26)
    bad26[-1] ^= 0x01
    assert decode_hid_prox(bytes(bad26)) is None

    # 37-bit H10304: FC=1025, CN=98765
    raw37 = _encode_hid_wiegand_raw6(37, (1025 << 19) | 98765)
    c37 = decode_hid_prox(raw37)
    assert c37 is not None
    assert c37.bit_length == 37
    assert c37.facility_code == 1025
    assert c37.card_number == 98765

    # 33-bit (bit 16 współdzielony) oraz 34-bit / 35-bit
    raw33 = _encode_hid_wiegand_raw6(33, 0x12345678)
    c33 = decode_hid_prox(raw33)
    assert c33 is not None
    assert c33.bit_length == 33
    assert c33.facility_code is None
    assert c33.card_number == 0x12345678

    raw34 = _encode_hid_wiegand_raw6(34, 0xABCDEF12)
    c34 = decode_hid_prox(raw34)
    assert c34 is not None
    assert c34.bit_length == 34
    assert c34.facility_code is None
    assert c34.card_number == 0xABCDEF12

    raw35 = _encode_hid_wiegand_raw6(35, 0x1ABCDEF12)
    c35 = decode_hid_prox(raw35)
    assert c35 is not None
    assert c35.bit_length == 35
    assert c35.facility_code is None
    assert c35.card_number == 0x1ABCDEF12

    # Wariant 16-bit (0x09 0x01) oraz surowy 48-bit (b0 != 0)
    c16 = decode_hid_prox(bytes.fromhex("090112340000"))
    assert c16 is not None
    assert c16.bit_length == 16
    assert c16.card_number == 0x1234

    craw = decode_hid_prox(bytes.fromhex("A1B2C3D4E5F6"))
    assert craw is not None
    assert craw.bit_length is None
    assert craw.raw_hex == "A1B2C3D4E5F6"


def test_read_hid_prox_retries_and_double_confirm() -> None:
    raw26 = _encode_hid_wiegand_raw6(26, (77 << 16) | 4321)
    good_payload = b"\x07\x00" + raw26

    transport = MockHIDTransport(
        responses=[
            _make_response_frame(START_PN532, 1, b"\x63\x00"),  # chwilowy brak
            _make_response_frame(START_PN532, 3, good_payload),  # 1. poprawny odczyt
            _make_response_frame(START_NATIVE, 4, good_payload),  # 2. potwierdzenie
        ]
    )
    reader = NFCReader(transport)
    card = reader.read_hid_prox(init_rf=False, retries=3, confirm_reads=2, retry_delay_s=0.0)
    assert card is not None
    assert card.bit_length == 26
    assert card.facility_code == 77
    assert card.card_number == 4321

    _, _, sent_payload = parse_frame(transport.sent[0][1:])
    assert sent_payload == bytes.fromhex("FF006A010008")

    # Rozbieżny drugi odczyt powinien zostać odrzucony
    raw26_other = _encode_hid_wiegand_raw6(26, (77 << 16) | 9999)
    transport_mismatch = MockHIDTransport(
        responses=[
            _make_response_frame(START_PN532, 1, good_payload),
            _make_response_frame(START_PN532, 3, b"\x07\x00" + raw26_other),
        ]
    )
    reader_mismatch = NFCReader(transport_mismatch)
    assert reader_mismatch.read_hid_prox(init_rf=False, retries=1, confirm_reads=2, retry_delay_s=0.0) is None


def test_cli_125k_and_hid_commands(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    assert parser.parse_args(["read-125k"]).command == "read-125k"
    assert parser.parse_args(["read-hid"]).command == "read-hid"
    assert parser.parse_args(["scan", "--all"]).all is True

    raw26 = _encode_hid_wiegand_raw6(26, (12 << 16) | 3456)
    id5 = bytes.fromhex("1122334455")

    # Pomijamy init_rf w teście CLI, aby nie kolejkować 15 odpowiedzi konfiguracji PN532
    monkeypatch.setattr(NFCReader, "init_rf", lambda self: None)

    def make_fake_open(responses: list[bytes]):
        def _fake_open(path=None):
            return None, MockHIDTransport(responses)

        return _fake_open

    monkeypatch.setattr(
        "nfcplus.cli.open_reader",
        make_fake_open(
            [
                _make_response_frame(START_PN532, 1, b"\x05" + id5),
                _make_response_frame(START_PN532, 3, b"\x90\x00"),
            ]
        ),
    )
    assert cli_main(["read-125k"]) == 0
    out_125k = capsys.readouterr().out
    assert "1122334455" in out_125k
    assert "0573785173" in out_125k
    assert "FC=051  CN=17493" in out_125k

    monkeypatch.setattr(
        "nfcplus.cli.open_reader",
        make_fake_open(
            [
                _make_response_frame(START_PN532, 1, b"\x07\x00" + raw26),
                _make_response_frame(START_PN532, 3, b"\x07\x00" + raw26),
                _make_response_frame(START_PN532, 5, b"\x90\x00"),
            ]
        ),
    )
    assert cli_main(["read-hid"]) == 0
    out_hid = capsys.readouterr().out
    assert "FC:       12" in out_hid
    assert "Card No:  3456" in out_hid

    monkeypatch.setattr(
        "nfcplus.cli.open_reader",
        make_fake_open(
            [
                _pn532_reply(0x4A, b"\x63\x00", seq=1),  # brak 13.56 MHz
                _make_response_frame(START_PN532, 3, b"\x05" + id5),  # EM4100
                *[_make_response_frame(START_PN532, 5 + i * 2, b"\x63\x00") for i in range(5)],  # brak HID
                _make_response_frame(START_PN532, 15, b"\x90\x00"),  # beep
            ]
        ),
    )
    assert cli_main(["scan", "--all"]) == 0
    out_all = capsys.readouterr().out
    assert "[125 kHz EM4100]" in out_all
    assert "1122334455" in out_all


class FakeMifareCardTransport(HIDTransport):
    """Symuluje kartę Mifare Classic w tunelu PN532 i rejestruje zapisane bloki (0xA0)."""

    def __init__(
        self,
        *,
        uid: bytes = bytes.fromhex("12345678"),
        sector_keys: dict[int, tuple[bytes, bytes]] | None = None,
        reject_block0_write: bool = False,
        readonly_key_a_sectors: set[int] | None = None,
    ) -> None:
        self._open = False
        self.uid = uid
        self.sector_keys = sector_keys or {}
        self.reject_block0_write = reject_block0_write
        self.readonly_key_a_sectors = readonly_key_a_sectors or set()
        self.sent: list[bytes] = []
        self.a0_writes: list[tuple[int, bytes]] = []
        self._pending: bytes | None = None
        self._selected = False
        self._authed_sector: int | None = None
        self._authed_type: str | None = None

    @property
    def is_open(self) -> bool:
        return self._open

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def write(self, data: bytes) -> int:
        self.sent.append(data)
        _, seq, payload = parse_frame(data[1:])
        assert payload[:5] == b"\xff\x00\x00\x00" or payload[:4] == b"\xff\x00\x00\x00"
        if payload[:4] == b"\xff\x00\x00\x00" and payload[5] == 0xD4:
            cmd = payload[6:]
            cmd_code = cmd[0]
            if cmd_code == 0x4A:  # InListPassiveTarget
                self._selected = True
                self._authed_sector = None
                self._authed_type = None
                reply = bytes([0x01, 0x01, 0x00, 0x04, 0x08, len(self.uid)]) + self.uid
            elif cmd_code == 0x4E:  # InPSL
                reply = b""
            elif cmd_code == 0x06:  # ReadRegister
                reg = (cmd[1] << 8) | cmd[2]
                val = 0x80 if reg in (0x6302, 0x6303) else 0x00
                reply = bytes([val, 0x90, 0x00])
            elif cmd_code == 0x08:  # WriteRegister
                reply = b"\x90\x00"
            elif cmd_code == 0x40:  # InDataExchange
                sub = cmd[2]
                blk = cmd[3]
                sector = blk // 4 if blk < 128 else 32 + (blk - 128) // 16
                if sub in (0x60, 0x61):  # Auth A / B
                    key = cmd[4:10]
                    ka, kb = self.sector_keys.get(
                        sector, (bytes.fromhex("FFFFFFFFFFFF"), bytes.fromhex("FFFFFFFFFFFF"))
                    )
                    expected = ka if sub == 0x60 else kb
                    if self._selected and expected is not None and key == expected:
                        self._authed_sector = sector
                        self._authed_type = "A" if sub == 0x60 else "B"
                        reply = b"\x00"
                    else:
                        self._selected = False
                        self._authed_sector = None
                        self._authed_type = None
                        reply = b"\x14"
                elif sub == 0xA0:  # Mifare Write
                    block_data = cmd[4:20]
                    self.a0_writes.append((blk, block_data))
                    if not self._selected or self._authed_sector != sector:
                        reply = b"\x14"
                    elif blk == 0 and self.reject_block0_write:
                        self._selected = False
                        reply = b"\x04\x90\x00"
                    elif sector in self.readonly_key_a_sectors and self._authed_type == "A":
                        self._selected = False
                        reply = b"\x04\x90\x00"
                    else:
                        reply = b"\x00\x90\x00"
                else:
                    reply = b"\x01"
            else:
                reply = b"\x90\x00"
            self._pending = _pn532_reply(cmd_code, reply, seq=seq)
        else:
            self._pending = _make_response_frame(START_PN532, seq, b"\x90\x00")
        return len(data)

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        assert self._pending is not None
        resp = self._pending
        self._pending = None
        return resp


def _make_valid_mini_dump(fill_byte: int = 0x42) -> MifareDump:
    dump = MifareDump.empty(20)  # 5 sektorów = 20 bloków
    for blk in range(20):
        if blk % 4 == 3:
            dump.set_block(blk, FACTORY_MIFARE_TRAILER)
        else:
            dump.set_block(blk, bytes([fill_byte ^ blk]) * 16)
    return dump


def test_write_mifare_dump_skips_block0_by_default_and_handles_no_trailers() -> None:
    dump = _make_valid_mini_dump()
    transport = FakeMifareCardTransport()
    reader = NFCReader(transport)

    report = reader.write_mifare_dump(dump, init_rf=False)
    assert report.skipped_blocks == [0]
    assert report.written_blocks == list(range(1, 20))
    assert report.failed_blocks == {}
    assert report.sector_auth == {s: (True, True) for s in range(5)}
    assert reader.last_sector_auth == report.sector_auth
    assert [blk for blk, _ in transport.a0_writes] == list(range(1, 20))

    # Z --no-trailers (write_trailers=False) pomijamy też bloki 3, 7, 11, 15, 19
    transport_no_tr = FakeMifareCardTransport()
    reader_no_tr = NFCReader(transport_no_tr)
    report_no_tr = reader_no_tr.write_mifare_dump(dump, write_trailers=False, init_rf=False)
    assert report_no_tr.skipped_blocks == [0, 3, 7, 11, 15, 19]
    assert [blk for blk, _ in transport_no_tr.a0_writes] == [
        b for b in range(1, 20) if b % 4 != 3
    ]


def test_write_mifare_dump_block0_enabled_and_non_cuid_rejection() -> None:
    dump = _make_valid_mini_dump()

    # Karta CUID przyjmuje blok 0
    cuid_transport = FakeMifareCardTransport(reject_block0_write=False)
    report_ok = NFCReader(cuid_transport).write_mifare_dump(dump, write_block0=True, init_rf=False)
    assert report_ok.skipped_blocks == []
    assert report_ok.written_blocks == list(range(20))
    assert report_ok.failed_blocks == {}
    assert cuid_transport.a0_writes[0] == (0, dump.get_block(0))

    # Zwykła karta odrzuca blok 0, ale zapis kolejnych bloków przebiega dalej bez wyjątku
    non_cuid_transport = FakeMifareCardTransport(reject_block0_write=True)
    report_rej = NFCReader(non_cuid_transport).write_mifare_dump(dump, write_block0=True, init_rf=False)
    assert 0 in report_rej.failed_blocks
    assert report_rej.written_blocks == list(range(1, 20))


def test_write_mifare_dump_blocks_invalid_access_bits_before_a0() -> None:
    dump = _make_valid_mini_dump()
    bad_trailer = bytes.fromhex("FFFFFFFFFFFF" + "00000000" + "FFFFFFFFFFFF")
    dump.set_block(7, bad_trailer)  # Sektor 1 trailer

    transport = FakeMifareCardTransport()
    report = NFCReader(transport).write_mifare_dump(dump, init_rf=False)

    assert 7 in report.failed_blocks
    assert "A0" in report.failed_blocks[7] or "bity dostępu" in report.failed_blocks[7]
    # Komenda A0 dla bloku 7 nie mogła zostać wysłana
    assert 7 not in [blk for blk, _ in transport.a0_writes]
    assert report.written_blocks == [b for b in range(1, 20) if b != 7]


def test_write_mifare_dump_factory_fallback_and_key_b_fallback() -> None:
    dump = _make_valid_mini_dump()
    custom_key = bytes.fromhex("A1B2C3D4E5F6")
    # Karta wymaga FF..FF w sektorach 0..4, a w sektorze 2 Key A jest tylko do odczytu
    transport = FakeMifareCardTransport(readonly_key_a_sectors={2})
    report = NFCReader(transport).write_mifare_dump(dump, keys=[custom_key], init_rf=False)

    assert report.failed_blocks == {}
    assert report.written_blocks == list(range(1, 20))
    assert report.sector_auth == {s: (True, True) for s in range(5)}


def test_format_mifare_card_zeros_data_skips_block0_and_restores_factory_trailer() -> None:
    transport = FakeMifareCardTransport()
    reader = NFCReader(transport)
    report = reader.format_mifare_card(sectors=5, init_rf=False)

    assert report.skipped_blocks == [0]
    assert report.failed_blocks == {}
    assert report.written_blocks == list(range(1, 20))

    writes_by_block = dict(transport.a0_writes)
    assert 0 not in writes_by_block
    for blk in range(1, 20):
        if blk % 4 == 3:
            assert writes_by_block[blk] == FACTORY_MIFARE_TRAILER
        else:
            assert writes_by_block[blk] == b"\x00" * 16

    assert sector_auth_from_keys({0: (b"123456", None), 1: (None, b"abcdef")}) == {
        0: (True, False),
        1: (False, True),
    }
    with pytest.raises(ValueError):
        reader.format_mifare_card(sectors=12, init_rf=False)


def test_cli_write_mifare_and_format_mifare_parsing_and_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dump_path = tmp_path / "test.dump"
    _make_valid_mini_dump().save(dump_path)

    key_file = tmp_path / "keys.txt"
    key_file.write_text("# Komentarz\n\nA0A1A2A3A4A5\nFFFFFFFFFFFF # fabryczny\n", encoding="utf-8")

    parser = build_parser()
    wm_args = parser.parse_args(
        ["write-mifare", str(dump_path), "--key", "112233445566", "--key-file", str(key_file), "--write-block0", "--no-trailers", "--yes"]
    )
    assert wm_args.command == "write-mifare"
    assert wm_args.write_block0 is True
    assert wm_args.no_trailers is True
    assert wm_args.yes is True

    fm_args = parser.parse_args(["format-mifare", "--sectors", "40", "--key-file", str(key_file), "--yes"])
    assert fm_args.command == "format-mifare"
    assert fm_args.sectors == 40
    assert fm_args.yes is True

    calls: list[tuple[str, dict[str, object]]] = []

    class DummyTransport:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("nfcplus.cli.open_reader", lambda path=None: (None, DummyTransport()))
    monkeypatch.setattr(NFCReader, "beep", lambda self, duration_ms=50: None)

    def fake_write(self, dump, keys=(), *, write_block0=False, write_trailers=True, init_rf=True, progress_cb=None):
        calls.append(
            ("write", {"blocks": dump.total_blocks, "keys": list(keys), "write_block0": write_block0, "write_trailers": write_trailers})
        )
        return MifareWriteReport([1, 2, 3], [0], {}, {0: (True, True)})

    def fake_format(self, sectors=16, keys=(), *, init_rf=True, progress_cb=None):
        calls.append(("format", {"sectors": sectors, "keys": list(keys)}))
        return MifareWriteReport([1, 2, 3], [0], {}, {0: (True, True)})

    monkeypatch.setattr(NFCReader, "write_mifare_dump", fake_write)
    monkeypatch.setattr(NFCReader, "format_mifare_card", fake_format)

    # write-mifare bez --write-block0 nie pyta o potwierdzenie
    assert cli_main(["write-mifare", str(dump_path)]) == 0
    assert calls[-1][0] == "write"
    assert calls[-1][1]["write_block0"] is False

    # write-mifare --write-block0 bez --yes przy odmowie przerywa bez wywołania write_mifare_dump
    before_count = len(calls)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert cli_main(["write-mifare", str(dump_path), "--write-block0"]) == 1
    assert len(calls) == before_count
    assert "Anulowano" in capsys.readouterr().out

    # write-mifare --write-block0 bez --yes przy akceptacji wykonuje zapis
    monkeypatch.setattr("builtins.input", lambda _prompt: "t")
    assert cli_main(["write-mifare", str(dump_path), "--write-block0", "--no-trailers"]) == 0
    assert calls[-1][1]["write_block0"] is True
    assert calls[-1][1]["write_trailers"] is False

    # write-mifare --write-block0 --yes omija prompt
    monkeypatch.setattr("builtins.input", lambda _prompt: (_ for _ in ()).throw(AssertionError("Prompt nie powinien się pojawić")))
    assert cli_main(["write-mifare", str(dump_path), "--write-block0", "--yes"]) == 0

    # format-mifare bez --yes przy odmowie anuluje operację
    before_count = len(calls)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert cli_main(["format-mifare", "--sectors", "16"]) == 1
    assert len(calls) == before_count

    # format-mifare --yes --key-file wczytuje klucze i wykonuje formatowanie
    monkeypatch.setattr("builtins.input", lambda _prompt: (_ for _ in ()).throw(AssertionError("Prompt nie powinien się pojawić")))
    assert cli_main(["format-mifare", "--sectors", "5", "--key-file", str(key_file), "--yes"]) == 0
    assert calls[-1] == (
        "format",
        {"sectors": 5, "keys": [bytes.fromhex("A0A1A2A3A4A5"), bytes.fromhex("FFFFFFFFFFFF")]},
    )


def test_ntag_pwd_auth_user_memory_and_write_ndef(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wariant z sufiksem 90 00 oraz bez 90 00
    t_pwd = MockHIDTransport(
        responses=[
            _pn532_reply(0x40, b"\x00\xab\xcd\x90\x00"),
            _pn532_reply(0x40, b"\x00\x12\x34"),
            _pn532_reply(0x40, b"\x14"),
        ]
    )
    reader_pwd = NFCReader(t_pwd)
    assert reader_pwd.ntag_pwd_auth(b"\x11\x22\x33\x44") == b"\xab\xcd"
    assert reader_pwd.ntag_pwd_auth(b"\x11\x22\x33\x44") == b"\x12\x34"
    with pytest.raises(ProtocolError, match="PWD_AUTH"):
        reader_pwd.ntag_pwd_auth(b"\x11\x22\x33\x44")

    _, _, sent_pwd = parse_frame(t_pwd.sent[0][1:])
    assert sent_pwd[6:] == bytes.fromhex("40011B11223344")

    # Zapis NDEF na NTAG213 (45 stron -> pamięć użytkownika 4..39 = 144 B)
    ver_213 = bytes.fromhex("0004040201000F03")
    ver_213_crc = _crc16_a(ver_213)
    tlv = build_ndef_uri_tlv("https://example.com")
    pages_needed = len(tlv) // 4

    monkeypatch.setattr(NFCReader, "init_rf", lambda self: None)
    responses = [
        _pn532_reply(0x4A, bytes.fromhex("01010044000704112233445566")),  # InListPassiveTarget NTAG
        _pn532_reply(0x4E, b""),
        _pn532_reply(0x06, b"\x80\x90\x00"),
        _pn532_reply(0x06, b"\x80\x90\x00"),
        _pn532_reply(0x06, b"\x00\x90\x00"),
        _pn532_reply(0x40, b"\x00\x50" + ver_213 + ver_213_crc + b"\x90\x00"),  # GET_VERSION
        _pn532_reply(0x40, b"\x00\xca\xfe\x90\x00"),  # PWD_AUTH
        *[_pn532_reply(0x40, b"\x00\x90\x00") for _ in range(pages_needed)],  # WRITE_PAGE
    ]
    t_write = MockHIDTransport(responses=responses)
    written = NFCReader(t_write).ntag_write_ndef(tlv, password=b"\x01\x02\x03\x04", init_rf=True)
    assert written == pages_needed

    a2_writes = []
    for frame in t_write.sent:
        _, _, pl = parse_frame(frame[1:])
        if len(pl) >= 14 and pl[5:9] == b"\xd4\x40\x01\xa2":
            a2_writes.append((pl[9], pl[10:14]))
    assert [p for p, _ in a2_writes] == list(range(4, 4 + pages_needed))
    assert b"".join(d for _, d in a2_writes) == tlv
    assert parse_ndef_tlv(b"".join(d for _, d in a2_writes))[0].uri == "https://example.com"

    # Przekroczenie pojemności NTAG213 (>144 B) rzuca ValueError PRZED wysłaniem 0xA2
    t_cap = MockHIDTransport(
        responses=[
            _pn532_reply(0x4A, bytes.fromhex("01010044000704112233445566")),
            _pn532_reply(0x4E, b""),
            _pn532_reply(0x06, b"\x80\x90\x00"),
            _pn532_reply(0x06, b"\x80\x90\x00"),
            _pn532_reply(0x06, b"\x00\x90\x00"),
            _pn532_reply(0x40, b"\x00\x50" + ver_213 + ver_213_crc + b"\x90\x00"),
        ]
    )
    with pytest.raises(ValueError, match="Za mała pojemność"):
        NFCReader(t_cap).ntag_write_user_memory(b"\xAA" * 148, start_page=4, init_rf=True)
    assert len(t_cap.sent) == 6


def test_transceive_apdu_and_parse_hex_bytes() -> None:
    assert parse_hex_bytes("0x00 A4:04-00 00") == bytes.fromhex("00A4040000")
    with pytest.raises(ValueError):
        parse_hex_bytes("XYZ")

    transport = MockHIDTransport(
        responses=[
            _pn532_reply(0x40, b"\x00HELLO\x90\x00"),
            _pn532_reply(0x40, b"\x00\x6a\x82"),
            _pn532_reply(0x40, b"\x14"),
        ]
    )
    reader = NFCReader(transport)
    r1 = reader.transceive_apdu(bytes.fromhex("00A4040000"))
    assert r1 == ApduResponse(data=b"HELLO", sw1=0x90, sw2=0x00)
    assert r1.status_word == "9000"
    assert r1.is_ok is True

    _, _, sent_apdu = parse_frame(transport.sent[0][1:])
    assert sent_apdu[6:] == bytes.fromhex("400100A4040000")

    r2 = reader.transceive_apdu(bytes.fromhex("00B0000004"))
    assert r2.data == b""
    assert r2.status_word == "6A82"
    assert r2.is_ok is False

    with pytest.raises(ProtocolError, match="APDU"):
        reader.transceive_apdu(bytes.fromhex("00B0000004"))


def test_convert_em4100_formats_bidirectional() -> None:
    # Wzorzec z dokumentacji: 4D0088BC89 <-> 0008961161 <-> 13648265 (FC=136, CN=48265)
    c_hex = convert_em4100_formats("4D0088BC89")
    assert c_hex.hex_id == "4D0088BC89"
    assert c_hex.decimal_10 == "0008961161"
    assert c_hex.wiegand_26 == "13648265"
    assert c_hex.wiegand_fc == 136
    assert c_hex.wiegand_cn == 48265

    c_dec10 = convert_em4100_formats("0008961161", version_byte=0x4D)
    assert c_dec10.hex_id == "4D0088BC89"
    assert c_dec10.wiegand_26 == "13648265"

    c_dec8 = convert_em4100_formats("13648265", version_byte=0x4D)
    assert c_dec8.hex_id == "4D0088BC89"
    assert c_dec8.decimal_10 == "0008961161"

    c_fccn = convert_em4100_formats("136,48265")
    assert c_fccn.wiegand_26 == "13648265"
    assert c_fccn.decimal_10 == "0008961161"


def test_write_em4100_and_hid_t5577(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NFCReader, "init_rf", lambda self: None)
    id5 = bytes.fromhex("4D0088BC89")
    b0, b1, b2 = encode_em4100_t5577_blocks(id5)
    assert b0 == bytes.fromhex("00148040")
    assert len(b1) == 4 and len(b2) == 4

    # 6 odpowiedzi FF 00 66 (reset, timing, blk1, blk2, blk0, reset) + 1 odpowiedź read_em4100
    t_em = MockHIDTransport(
        responses=[
            *[_make_response_frame(START_PN532, i * 2 + 1, b"\x05\x00\x00\x00\x00\x00") for i in range(6)],
            _make_response_frame(START_PN532, 13, b"\x05" + id5),
        ]
    )
    res_em = NFCReader(t_em).write_em4100_t5577(id5, verify=True, init_rf=True)
    assert res_em.raw == id5
    sent_payloads = [parse_frame(f[1:])[2] for f in t_em.sent]
    assert sent_payloads[0] == bytes.fromhex("FF0066001E48E801000014000000")
    assert sent_payloads[1] == bytes.fromhex("FF0066001E48E801001F1801EF009B008601")
    assert sent_payloads[2] == bytes.fromhex("FF0066001E48E80100120001") + b1
    assert sent_payloads[3] == bytes.fromhex("FF0066001E48E80100120002") + b2
    assert sent_payloads[4] == bytes.fromhex("FF0066001E48E80100120000") + b0
    assert sent_payloads[6] == bytes.fromhex("FF0065051E48E8010000000000")

    # HID Prox na T5577
    raw26 = _encode_hid_wiegand_raw6(26, (42 << 16) | 12345)
    hb0, hb1, hb2, hb3 = encode_hid_t5577_blocks(raw26)
    assert hb0 == bytes.fromhex("00107060")
    assert (hb1[0] & 0xFC) == 0x1C

    t_hid = MockHIDTransport(
        responses=[
            *[_make_response_frame(START_PN532, i * 2 + 1, b"\x05\x00\x00\x00\x00\x00") for i in range(7)],
            _make_response_frame(START_PN532, 15, b"\x07\x00" + raw26),
            _make_response_frame(START_PN532, 17, b"\x07\x00" + raw26),
        ]
    )
    res_hid = NFCReader(t_hid).write_hid_t5577(raw26, verify=True, init_rf=True)
    assert res_hid.raw == raw26
    assert res_hid.facility_code == 42
    assert res_hid.card_number == 12345


def test_cli_new_subcommands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    assert parser.parse_args(["read-ntag", "--password", "11223344"]).password == "11223344"
    assert parser.parse_args(["write-ntag", "--page", "4", "--data", "AABBCCDD", "--password", "11223344"]).password == "11223344"
    assert parser.parse_args(["read-ndef", "--password", "11223344"]).command == "read-ndef"
    assert parser.parse_args(["write-ndef", "--uri", "https://example.com"]).uri == "https://example.com"
    assert parser.parse_args(["apdu", "00A4040000", "--init-rf"]).init_rf is True
    assert parser.parse_args(["lf-convert", "4D0088BC89"]).command == "lf-convert"
    assert parser.parse_args(["dump-json", "card.dump"]).command == "dump-json"
    assert parser.parse_args(["write-t5577", "--em4100", "4D0088BC89", "--no-verify"]).no_verify is True

    # lf-convert (offline)
    assert cli_main(["lf-convert", "4D0088BC89"]) == 0
    out_lfc = capsys.readouterr().out
    assert "4D0088BC89" in out_lfc
    assert "0008961161" in out_lfc
    assert "13648265" in out_lfc

    # dump-json (offline)
    dump_path = tmp_path / "mini.dump"
    json_out = tmp_path / "mini.json"
    _make_valid_mini_dump().save(dump_path)
    assert cli_main(["dump-json", str(dump_path), "-o", str(json_out)]) == 0
    assert json_out.exists()
    capsys.readouterr()

    class DummyTransport:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("nfcplus.cli.open_reader", lambda path=None: (None, DummyTransport()))
    monkeypatch.setattr(NFCReader, "beep", lambda self, duration_ms=50: None)
    monkeypatch.setattr(
        NFCReader,
        "transceive_apdu",
        lambda self, apdu, *, init_rf=False: ApduResponse(b"\x01\x02", 0x90, 0x00),
    )
    assert cli_main(["apdu", "00A4040000"]) == 0
    out_apdu = capsys.readouterr().out
    assert "01 02" in out_apdu
    assert "90 00" in out_apdu

    monkeypatch.setattr(NFCReader, "ntag_write_ndef", lambda self, tlv, *, password=None, init_rf=True, progress_cb=None: len(tlv) // 4)
    assert cli_main(["write-ndef", "--text", "Test NFC", "--lang", "pl"]) == 0
    assert "Zapisano NDEF TLV" in capsys.readouterr().out

    monkeypatch.setattr(
        NFCReader,
        "write_em4100_t5577",
        lambda self, id5, freq_hz=125_000, *, verify=True, init_rf=True: convert_em4100_formats(id5.hex()),
    )
    assert cli_main(["write-t5577", "--em4100", "4D0088BC89"]) == 0
    assert "4D0088BC89" in capsys.readouterr().out
