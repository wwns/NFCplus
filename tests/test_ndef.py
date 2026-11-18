"""Testy jednostkowe dekodowania i budowania rekordów NDEF TLV."""

from __future__ import annotations

import pytest

from nfcplus.ndef import (
    NdefRecord,
    build_ndef_text_tlv,
    build_ndef_uri_tlv,
    parse_ndef_tlv,
)


def test_build_and_parse_ndef_uri_prefixes() -> None:
    uris = [
        ("https://www.example.com/nfc", 0x02),
        ("https://example.org/path", 0x04),
        ("http://www.test.local", 0x01),
        ("http://test.local", 0x03),
        ("tel:+48123456789", 0x05),
        ("mailto:kontakt@example.com", 0x06),
        ("custom://app/item", 0x00),
    ]
    for uri, expected_prefix_code in uris:
        tlv = build_ndef_uri_tlv(uri)
        assert len(tlv) % 4 == 0
        assert tlv[0] == 0x03
        assert 0xFE in tlv

        records = parse_ndef_tlv(tlv)
        assert len(records) == 1
        rec = records[0]
        assert rec.tnf == 0x01
        assert rec.record_type == "U"
        assert rec.uri == uri
        assert rec.payload[0] == expected_prefix_code


def test_build_and_parse_ndef_text_utf8_utf16_and_long_tlv() -> None:
    tlv = build_ndef_text_tlv("Zażółć gęślą jaźń", lang="pl")
    assert len(tlv) % 4 == 0
    records = parse_ndef_tlv(tlv)
    assert len(records) == 1
    assert records[0].record_type == "T"
    assert records[0].language == "pl"
    assert records[0].text == "Zażółć gęślą jaźń"

    # Wariant UTF-16 (bit 7 bajtu statusu)
    utf16_text = "Cześć UTF-16".encode("utf-16")
    utf16_payload = bytes([0x80 | 2]) + b"pl" + utf16_text
    utf16_rec = bytes([0xD1, 1, len(utf16_payload)]) + b"T" + utf16_payload
    utf16_tlv = bytes([0x03, len(utf16_rec)]) + utf16_rec + b"\xfe"
    parsed_utf16 = parse_ndef_tlv(utf16_tlv)
    assert len(parsed_utf16) == 1
    assert parsed_utf16[0].text == "Cześć UTF-16"

    # Długi komunikat > 255 B (3-bajtowy nagłówek długości TLV 0xFF oraz rekord długi SR=0)
    long_text = "A" * 300
    long_tlv = build_ndef_text_tlv(long_text, lang="en")
    assert len(long_tlv) % 4 == 0
    assert long_tlv[0:2] == b"\x03\xff"
    parsed_long = parse_ndef_tlv(long_tlv)
    assert len(parsed_long) == 1
    assert parsed_long[0].text == long_text
    assert parsed_long[0].language == "en"


def test_parse_ndef_tlv_skips_null_and_lock_tlvs_and_decodes_mime() -> None:
    mime_type = b"text/plain"
    mime_payload = b"hello"
    mime_rec = bytes([0xD2, len(mime_type), len(mime_payload)]) + mime_type + mime_payload
    # NULL TLV (0x00) + Lock Control TLV (0x01, len 3) + NDEF TLV (0x03) + Terminator (0xFE) + śmieci
    raw = (
        b"\x00\x00"
        + b"\x01\x03\xa0\x0c\x34"
        + bytes([0x03, len(mime_rec)])
        + mime_rec
        + b"\xfe\xde\xad\xbe\xef"
    )
    records = parse_ndef_tlv(raw)
    assert len(records) == 1
    assert isinstance(records[0], NdefRecord)
    assert records[0].tnf == 0x02
    assert records[0].record_type == "text/plain"
    assert records[0].payload == b"hello"
    assert "text/plain" in records[0].summary

    with pytest.raises(ValueError):
        build_ndef_uri_tlv("")
    with pytest.raises(ValueError):
        build_ndef_text_tlv("abc", lang="pł")
    with pytest.raises(ValueError):
        build_ndef_text_tlv("abc", lang="a" * 64)
