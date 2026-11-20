"""Testy jednostkowe obsługi czytnika ACS ACR122U (072f:2200) — PC/SC, CCID USB, protokół i audyt."""

from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace

import pytest

from nfcplus.audit import audit_live_reader
from nfcplus.cli import main as cli_main
from nfcplus.protocol import NFCReader, ProtocolError
from nfcplus.transport import (
    _USBDEVFS_BULK,
    _USBDEVFS_CLAIMINTERFACE,
    _USBDEVFS_IOCTL,
    _USBDEVFS_RELEASEINTERFACE,
    DeviceInfo,
    HIDTransport,
    LinuxUsbCcidTransport,
    TransportError,
    WindowsPcscTransport,
    _build_ccid_frame,
    _enumerate_linux_usb_ccid,
    _parse_ccid_frame,
    _parse_pcsc_multi_string,
    format_reader_labels,
)


class MockAcr122uTransport(HIDTransport):
    """Atrapa transportu ACR122U rejestrująca komendy apdu_exchange."""

    def __init__(self, replies: list[bytes] | None = None) -> None:
        self._open = True
        self.sent_apdus: list[bytes] = []
        self.replies: list[bytes] = list(replies or [])

    @property
    def is_open(self) -> bool:
        return self._open

    @property
    def product(self) -> str:
        return "ACS ACR122U PICC Interface"

    @property
    def protocol_family(self) -> str:
        return "acr122u"

    @property
    def supports_lf(self) -> bool:
        return False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def write(self, data: bytes) -> int:
        raise AssertionError("ACR122U nie powinien wywoływać write()")

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        raise AssertionError("ACR122U nie powinien wywoływać read()")

    def apdu_exchange(self, apdu: bytes, timeout_ms: int = 2000) -> bytes:
        self.sent_apdus.append(apdu)
        if not self.replies:
            raise AssertionError(f"Brak odpowiedzi mocka dla APDU: {apdu.hex(' ')}")
        return self.replies.pop(0)


def test_windows_pcsc_transport_direct_control_and_cleanup() -> None:
    calls: list[str] = []

    class FakeWinscard:
        def SCardEstablishContext(self, _scope, _r1, _r2, ctx_ptr):
            calls.append("establish")
            ctypes.cast(ctx_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = 0x1001
            return 0

        def SCardConnectW(self, _ctx, name, share, proto, card_ptr, active_ptr):
            calls.append(f"connect:{name}:{share}:{proto}")
            ctypes.cast(card_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = 0x2002
            ctypes.cast(active_ptr, ctypes.POINTER(ctypes.c_uint32))[0] = 0
            return 0

        def SCardControl(self, _card, ioctl_code, _in_buf, in_len, out_buf, _out_len, ret_len_ptr):
            calls.append(f"control:0x{ioctl_code:08x}:{in_len}")
            reply = b"ACR122U214"
            out_arr = ctypes.cast(out_buf, ctypes.POINTER(ctypes.c_ubyte))
            for i, b in enumerate(reply):
                out_arr[i] = b
            ctypes.cast(ret_len_ptr, ctypes.POINTER(ctypes.c_uint32))[0] = len(reply)
            return 0

        def SCardDisconnect(self, _card, _disp):
            calls.append("disconnect")
            return 0

        def SCardReleaseContext(self, _ctx):
            calls.append("release")
            return 0

    t = WindowsPcscTransport("ACS ACR122U PICC Interface 0", dll=FakeWinscard())
    assert t.protocol_family == "acr122u"
    assert t.supports_lf is False

    with t:
        assert t.is_open is True
        resp = t.apdu_exchange(b"\xff\x00\x48\x00\x00")
        assert resp == b"ACR122U214"

    assert t.is_open is False
    assert calls == [
        "establish",
        "connect:ACS ACR122U PICC Interface 0:3:0",
        "control:0x003136b0:5",
        "disconnect",
        "release",
    ]

    multi = "ACS ACR122U 0\x00Inny Czytnik\x00\x00".encode("utf-16-le")
    assert _parse_pcsc_multi_string(multi, encoding="utf-16-le") == ["ACS ACR122U 0", "Inny Czytnik"]


def test_linux_usb_ccid_transport_framing_and_sysfs_enum(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Enumeracja sysfs dla 072f:2200
    dev_dir = tmp_path / "1-1"
    dev_dir.mkdir()
    (dev_dir / "idVendor").write_text("072f\n", encoding="utf-8")
    (dev_dir / "idProduct").write_text("2200\n", encoding="utf-8")
    (dev_dir / "busnum").write_text("1\n", encoding="utf-8")
    (dev_dir / "devnum").write_text("3\n", encoding="utf-8")
    (dev_dir / "product").write_text("ACR122U PICC Interface\n", encoding="utf-8")
    (dev_dir / "manufacturer").write_text("ACS\n", encoding="utf-8")

    found = _enumerate_linux_usb_ccid(sysfs_root=tmp_path)
    assert len(found) == 1
    assert found[0].path == "/dev/bus/usb/001/003"
    assert found[0].protocol_family == "acr122u"
    assert found[0].supports_lf is False
    assert format_reader_labels(found) == ["ACR122U PICC Interface (072f:2200)"]

    # Symulacja USBDEVFS ioctl + CCID 0x62 / 0x6F / 0x80 (w tym Time Extension 0x80)
    monkeypatch.setattr("nfcplus.transport.os.open", lambda _p, _f: 99)
    closed: list[int] = []
    monkeypatch.setattr("nfcplus.transport.os.close", lambda fd: closed.append(fd))

    in_queue: list[bytes] = [
        _build_ccid_frame(0x80, 0, b"", param0=0),  # odpowiedź na IccPowerOn (0x62)
        # Time extension (bmCommandStatus=2 -> 0x80) na 0x6F, potem właściwa odpowiedź
        bytes([0x80, 0, 0, 0, 0, 1, 0, 0x80, 0, 0]),
        bytes([0x80, 10, 0, 0, 0, 1, 0, 0x00, 0, 0]) + b"ACR122U214",
    ]
    out_packets: list[bytes] = []

    def fake_ioctl(_fd: int, req: int, arg: object) -> int:
        if req in (_USBDEVFS_IOCTL, _USBDEVFS_CLAIMINTERFACE, _USBDEVFS_RELEASEINTERFACE):
            return 0
        if req == _USBDEVFS_BULK:
            if arg.ep == 0x02:  # type: ignore[attr-defined]
                raw = ctypes.string_at(arg.data, arg.len)  # type: ignore[attr-defined]
                out_packets.append(raw)
                return len(raw)
            if arg.ep == 0x82:  # type: ignore[attr-defined]
                pkt = in_queue.pop(0)
                dst = (ctypes.c_ubyte * len(pkt)).from_address(arg.data)  # type: ignore[attr-defined]
                for i, b in enumerate(pkt):
                    dst[i] = b
                return len(pkt)
        raise AssertionError(f"Nieoczekiwany ioctl: {req}")

    transport = LinuxUsbCcidTransport("/dev/bus/usb/001/003", ioctl_fn=fake_ioctl)
    with transport:
        resp = transport.apdu_exchange(b"\xff\x00\x48\x00\x00")
        assert resp == b"ACR122U214"

    assert closed == [99]
    assert _parse_ccid_frame(out_packets[0])[0] == 0x62
    mtype, _seq, _st, _err, payload = _parse_ccid_frame(out_packets[1])
    assert mtype == 0x6F
    assert payload == b"\xff\x00\x48\x00\x00"

    # Błąd uprawnień przy otwarciu wskazuje regułę udev
    monkeypatch.setattr("nfcplus.transport.os.open", lambda _p, _f: (_ for _ in ()).throw(PermissionError("denied")))
    with pytest.raises(TransportError, match="99-nfcplus.rules"):
        LinuxUsbCcidTransport("/dev/bus/usb/001/003").open()


def test_nfc_reader_acr122u_ops_and_lf_rejection() -> None:
    uid = bytes.fromhex("12345678")
    t = MockAcr122uTransport(
        replies=[
            b"ACR122U214",  # get_firmware_version (FF 00 48 00 00)
            b"\x90\x02",  # beep (FF 00 40 00 04 05 00 01 01 -> 90 <LED_STATE>)
            # scan_card(init_rf=False): InListPassiveTarget, InPSL, ReadReg x3 (0x6302/03/0D -> już ustawione),
            bytes([0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x08, 0x04]) + uid + b"\x90\x00",
            b"\xd5\x4f\x90\x00",  # InPSL
            b"\xd5\x07\x80\x90\x00",  # ReadReg 0x6302 == 0x80
            b"\xd5\x07\x80\x90\x00",  # ReadReg 0x6303 == 0x80
            b"\xd5\x07\x00\x90\x00",  # ReadReg 0x630D == 0x00
            b"\xd5\x41\x00\x90\x00",  # mifare_auth OK
            b"\xd5\x41\x00" + (b"\xaa" * 16) + b"\x90\x00",  # mifare_read_block (17 B PN532)
            b"\xd5\x41\x00\x90\x00",  # mifare_write_block
            b"\xd5\x41\x00" + bytes.fromhex("0004040201000F03") + b"\x90\x00",  # ntag_get_version (0x60)
            b"\xd5\x41\x00NDEF\x90\x00",  # ntag_read_page
            b"\xd5\x41\x00\x90\x00",  # ntag_write_page
        ]
    )
    reader = NFCReader(t)
    assert reader.is_acr122u is True
    assert reader.supports_lf is False

    info = reader.get_device_info()
    assert info["firmware"] == "ACR122U214"
    assert info["model"] == "ACS ACR122U PICC Interface"
    reader.beep(50)
    assert t.sent_apdus[0] == bytes.fromhex("FF00480000")
    assert t.sent_apdus[1] == bytes.fromhex("FF0040000405000101")

    card = reader.scan_card(init_rf=False)
    assert card is not None and card.uid == uid and card.sak == 0x08
    assert reader.mifare_auth(4, bytes.fromhex("FFFFFFFFFFFF"), uid, "A") is True
    assert reader.mifare_read_block(4) == b"\xaa" * 16
    reader.mifare_write_block(4, b"\xbb" * 16)

    ver = reader.ntag_get_version()
    assert "NTAG213" in ver.name
    assert reader.ntag_read_page(4) == b"NDEF"
    reader.ntag_write_page(4, b"TEST")

    # Operacje 125 kHz są czytelnie blokowane na ACR122U
    with pytest.raises(ProtocolError, match="13,56 MHz"):
        reader.read_em4100()
    with pytest.raises(ProtocolError, match="13,56 MHz"):
        reader.read_hid_prox()
    with pytest.raises(ProtocolError, match="13,56 MHz"):
        reader.write_em4100_t5577(b"\x01\x02\x03\x04\x05")
    with pytest.raises(ProtocolError, match="13,56 MHz"):
        reader.write_hid_t5577(b"\x00\x20\x06\x54\x60\x73")


def test_audit_and_cli_scan_all_skip_lf_on_acr122u(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = MockAcr122uTransport(
        replies=[
            b"\xd5\x4b\x01\x01\x03\x44\x20\x04\x08\x11\x22\x33\x90\x00",  # scan_card (ISO 14443-4 Random UID)
            b"\xd5\x4f\x90\x00",
            b"\xd5\x07\x80\x90\x00",
            b"\xd5\x07\x80\x90\x00",
            b"\xd5\x07\x00\x90\x00",
        ]
    )
    reader = NFCReader(t)
    monkeypatch.setattr(reader, "init_rf", lambda: None)

    report = audit_live_reader(reader)
    assert report.risk_level == "NISKIE"
    assert report.card_metadata.get("supports_lf") is False

    # CLI `scan --all` nie rzuca błędu LF na ACR122U
    t_cli = MockAcr122uTransport(
        replies=[
            b"\xd5\x4b\x01\x01\x03\x44\x20\x04\x08\x11\x22\x33\x90\x00",
            b"\xd5\x4f\x90\x00",
            b"\xd5\x07\x80\x90\x00",
            b"\xd5\x07\x80\x90\x00",
            b"\xd5\x07\x00\x90\x00",
            b"\x90\x00",  # beep
        ]
    )
    monkeypatch.setattr(NFCReader, "init_rf", lambda self: None)
    monkeypatch.setattr(
        "nfcplus.cli.open_reader",
        lambda path=None: (
            DeviceInfo(vid=0x072F, pid=0x2200, path="/dev/bus/usb/001/003", product="ACS ACR122U", protocol_family="acr122u", supports_lf=False),
            t_cli,
        ),
    )
    assert cli_main(["scan", "--all"]) == 0
    out = capsys.readouterr().out
    assert "[13.56 MHz ISO14443A]" in out
    assert "08 11 22 33" in out

    # Reguła udev dla ACR122U obecna
    rules_text = (Path(__file__).resolve().parent.parent / "udev" / "99-nfcplus.rules").read_text(encoding="utf-8")
    assert 'ATTRS{idVendor}=="072f", ATTRS{idProduct}=="2200"' in rules_text
