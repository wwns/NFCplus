"""Testy jednostkowe modułu zrzutów (.dump) Mifare Classic i NTAG."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nfcplus.dump import (
    FACTORY_MIFARE_TRAILER,
    MifareDump,
    NtagDump,
    compare_buffers,
    decode_value_block,
    parse_access_bits,
    parse_key_file,
    validate_access_bits,
)


def test_parse_default_transport_access_bits() -> None:
    # Domyślne bity dostępu Mifare Classic: FF 07 80 69
    acc = parse_access_bits(bytes.fromhex("FF078069"))
    assert acc.valid is True
    assert acc.c_bits == (0, 0, 0, 1)  # bloki 0..2: 000, trailer: 001


def test_parse_invalid_access_bits() -> None:
    acc = parse_access_bits(bytes.fromhex("00000000"))
    assert acc.valid is False


def test_factory_trailer_and_validate_access_bits() -> None:
    assert len(FACTORY_MIFARE_TRAILER) == 16
    assert validate_access_bits(FACTORY_MIFARE_TRAILER) is True

    valid_ndef_trailer = bytes.fromhex("D3F7D3F7D3F7" + "7F078840" + "FFFFFFFFFFFF")
    assert validate_access_bits(valid_ndef_trailer) is True

    # Uszkodzony bit dopełnienia w bajcie 6..8 musi zostać wykryty
    bad_trailer = bytearray(FACTORY_MIFARE_TRAILER)
    bad_trailer[7] ^= 0x01
    assert validate_access_bits(bytes(bad_trailer)) is False
    assert validate_access_bits(bytes.fromhex("FFFFFFFFFFFF" + "00000000" + "FFFFFFFFFFFF")) is False
    assert validate_access_bits(b"\xff\x07\x80\x69") is False


def test_mifare_dump_set_block_and_sector_helpers() -> None:
    dump = MifareDump.empty(256)
    assert dump.sector_count == 40
    assert dump.sector_of_block(0) == 0
    assert dump.sector_of_block(7) == 1
    assert dump.sector_of_block(128) == 32
    assert dump.is_trailer_block(3) is True
    assert dump.is_trailer_block(2) is False
    assert dump.is_trailer_block(143) is True
    assert dump.is_trailer_block(142) is False

    returned = dump.set_block(1, b"\xAB" * 16)
    assert returned is dump
    assert dump.get_block(1) == b"\xAB" * 16

    bad_trailer = bytes.fromhex("FFFFFFFFFFFF" + "00000000" + "FFFFFFFFFFFF")
    with pytest.raises(ValueError, match="bity dostępu"):
        dump.set_block(3, bad_trailer, validate_trailer=True)
    assert dump.get_block(3) == b"\x00" * 16

    dump.set_block(3, FACTORY_MIFARE_TRAILER, validate_trailer=True)
    assert dump.get_block(3) == FACTORY_MIFARE_TRAILER

    dump.set_sector_auth(0, True, False)
    assert dump.sector_auth[0] == (True, False)


def test_mifare_dump_roundtrip_and_diff(tmp_path: Path) -> None:
    dump1 = MifareDump.empty(64)
    assert dump1.sector_count == 16
    assert dump1.total_blocks == 64

    dump1.set_block(3, bytes.fromhex("FFFFFFFFFFFF" + "FF078069" + "A0A1A2A3A4A5"))
    file_path = tmp_path / "card.dump"
    dump1.save(file_path)

    loaded = MifareDump.load(file_path)
    ka, acc, kb = loaded.get_sector_trailer(0)
    assert ka == bytes.fromhex("FFFFFFFFFFFF")
    assert acc.valid is True
    assert kb == bytes.fromhex("A0A1A2A3A4A5")

    dump2 = MifareDump(bytes(loaded.data))
    assert loaded.compare(dump2).identical is True

    dump2.set_block(4, b"A" * 16)
    diff = loaded.compare(dump2)
    assert diff.identical is False
    assert len(diff.differences) == 1
    assert diff.differences[0].index == 4


def test_ntag_dump_roundtrip_and_diff(tmp_path: Path) -> None:
    pages = [bytes([i, i + 1, i + 2, i + 3]) for i in range(45)]
    dump = NtagDump.from_pages(pages)
    assert dump.page_count == 45

    path = tmp_path / "ntag.dump"
    dump.save(path)
    loaded = NtagDump.load(path)
    assert loaded.get_page(10) == bytes([10, 11, 12, 13])

    other = NtagDump(bytes(loaded.data))
    other.set_page(4, b"TEST")
    diff = compare_buffers(bytes(loaded.data), bytes(other.data), block_size=4)
    assert not diff.identical
    assert [d.index for d in diff.differences] == [4]

    with pytest.raises(ValueError):
        NtagDump(b"\x01\x02")


def _make_value_block(value: int, addr: int) -> bytes:
    val_bytes = int(value).to_bytes(4, "little", signed=True)
    val_u32 = int.from_bytes(val_bytes, "little", signed=False)
    inv_bytes = ((~val_u32) & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
    addr_b = addr & 0xFF
    inv_addr_b = (~addr_b) & 0xFF
    return val_bytes + inv_bytes + val_bytes + bytes([addr_b, inv_addr_b, addr_b, inv_addr_b])


def test_parse_key_file_and_deduplication(tmp_path: Path) -> None:
    key_file = tmp_path / "keys.dic"
    key_file.write_text(
        "\n# Komentarz #1\n// Komentarz C++\n"
        "FF:FF:FF:FF:FF:FF # fabryczny\n"
        "A0 A1 A2 A3 A4 A5 // NDEF\n"
        "ffffffffffff\n"
        "D3-F7-D3-F7-D3-F7\n",
        encoding="utf-8",
    )
    keys = parse_key_file(key_file)
    assert keys == [
        bytes.fromhex("FFFFFFFFFFFF"),
        bytes.fromhex("A0A1A2A3A4A5"),
        bytes.fromhex("D3F7D3F7D3F7"),
    ]

    bad_file = tmp_path / "bad.txt"
    bad_file.write_text("FFFF\n", encoding="utf-8")
    with pytest.raises(ValueError, match="długość klucza"):
        parse_key_file(bad_file)


def test_decode_value_block_and_json_export(tmp_path: Path) -> None:
    vb_pos = _make_value_block(12345, addr=7)
    vb_neg = _make_value_block(-500, addr=2)
    assert decode_value_block(vb_pos) == 12345
    assert decode_value_block(vb_neg) == -500

    # Uszkodzenie dopełnienia wartości lub adresu -> None
    bad_vb = bytearray(vb_pos)
    bad_vb[4] ^= 0x01
    assert decode_value_block(bytes(bad_vb)) is None
    bad_addr = bytearray(vb_pos)
    bad_addr[13] ^= 0x01
    assert decode_value_block(bytes(bad_addr)) is None
    assert decode_value_block(b"\x00" * 16) is None

    dump = MifareDump.empty(20)  # 5 sektorów
    dump.set_block(1, _make_value_block(42, addr=1))
    dump.set_block(3, FACTORY_MIFARE_TRAILER)
    dump.set_sector_auth(0, True, True)

    json_path = tmp_path / "dump.json"
    dump.save_json(json_path, uid="3F 99 06 63", atqa="04 00", sak="08")
    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["format"] == "mifare-classic"
    assert parsed["sector_count"] == 5
    assert parsed["card"] == {"uid": "3F 99 06 63", "atqa": "04 00", "sak": "08"}
    s0 = parsed["sectors"][0]
    assert s0["access_bits"]["valid"] is True
    assert s0["auth"] == {"key_a": True, "key_b": True}
    assert s0["blocks"][1]["value_block"] == 42
    assert s0["blocks"][3]["is_trailer"] is True
    assert s0["blocks"][3]["value_block"] is None
