"""Testy jednostkowe modułu Audytu Bezpieczeństwa Karty (src/nfcplus/audit.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nfcplus.audit import (
    audit_dump_file,
    audit_live_reader,
    audit_mifare_dump,
    audit_ntag_dump,
    mask_key_hex,
)
from nfcplus.cli import build_parser, main as cli_main
from nfcplus.dump import FACTORY_MIFARE_TRAILER, MifareDump, NtagDump
from nfcplus.protocol import (
    CardInfo,
    EM4100Card,
    HIDProxCard,
    NFCReader,
    NtagVersion,
    ProtocolError,
    decode_hid_prox,
)


def test_mask_key_hex() -> None:
    assert mask_key_hex("A0A1A2A3A4A5") == "A0A1****A4A5"
    assert mask_key_hex("ff ff ff ff ff ff") == "FFFF****FFFF"
    assert mask_key_hex("12") == "****"


def test_udev_rules_hardened_permissions() -> None:
    rules_path = Path(__file__).resolve().parent.parent / "udev" / "99-nfcplus.rules"
    text = rules_path.read_text(encoding="utf-8")
    assert 'MODE="0666"' not in text
    assert text.count('MODE="0660", GROUP="plugdev", TAG+="uaccess"') == 8


def test_audit_mifare_dump_default_keys_block0_bcc_sak_and_dual_lf() -> None:
    dump = MifareDump.empty(64)
    # Blok 0 z zepsutym BCC (3F^99^06^63 = C3, wpisujemy 00) i innym SAK (18 zamiast 08)
    dump.set_block(0, bytes.fromhex("3F9906630018040062639D61F0A86869"))
    dump.set_block(1, b"USER_SECRET_DATA")
    for s in range(16):
        dump.set_block(s * 4 + 3, bytes.fromhex("A0A1A2A3A4A5" + "FF078069" + "A0A1A2A3A4A5"))

    card = CardInfo(uid=bytes.fromhex("3F990663"), atqa=bytes.fromhex("0400"), sak=0x08, card_type="MIFARE Classic 1K")
    em = EM4100Card(raw=bytes.fromhex("4D0088BC89"))
    hid = decode_hid_prox(bytes.fromhex("002006546073"))
    assert isinstance(hid, HIDProxCard)

    report = audit_mifare_dump(
        dump,
        found_keys={(0, "A"): bytes.fromhex("A0A1A2A3A4A5"), (0, "B"): bytes.fromhex("A0A1A2A3A4A5")},
        card=card,
        em4100=em,
        hid_prox=hid,
    )
    assert report.risk_level == "KRYTYCZNE"
    assert report.risk_score >= 75
    codes = {f.code for f in report.findings}
    assert "LF_EM4100_PLAINTEXT" in codes
    assert "LF_HID_PROX_PLAINTEXT" in codes
    assert "MIFARE_CRYPTO1_LEGACY" in codes
    assert "MIFARE_DEFAULT_KEYS" in codes
    assert "MIFARE_KEY_REUSE_AB" in codes
    assert "MIFARE_TRANSPORT_ACCESS_BITS" in codes
    assert "MIFARE_BLOCK0_BCC_INVALID" in codes
    assert "MIFARE_BLOCK0_SAK_ATQA_ANOMALY" in codes

    # Domyślne maskowanie kluczy vs jawny widok
    masked_text = report.format_text(mask_sensitive=True)
    assert "A0A1****A4A5" in masked_text
    assert "A0A1A2A3A4A5" not in masked_text

    unmasked_text = report.format_text(mask_sensitive=False)
    assert "A0A1A2A3A4A5" in unmasked_text


def test_audit_ntag_dump_static_lock_and_auth0() -> None:
    pages = [b"\x00\x00\x00\x00" for _ in range(45)]
    pages[2] = b"\x11\x22\x00\x00"  # Static Lock == 00 00
    pages[41] = b"\x04\x00\x00\xff"  # CFG0 z AUTH0 == 0xFF
    dump = NtagDump.from_pages(pages)
    ver = NtagVersion(raw=bytes.fromhex("0004040201000F03"), name="NTAG213 (144 B user)", total_pages=45, total_bytes=180)
    card = CardInfo(uid=bytes.fromhex("04112233445566"), atqa=b"\x00\x44", sak=0x00, card_type="MIFARE Ultralight / NTAG")

    report = audit_ntag_dump(dump, version=ver, card=card)
    assert report.risk_level == "WYSOKIE"
    codes = {f.code for f in report.findings}
    assert "NTAG_STATIC_LOCK_OPEN" in codes
    assert "NTAG_AUTH0_DISABLED" in codes
    assert "NTAG_NO_CRYPTO_AUTH" in codes
    assert "NTAG 424 DNA" in report.migration_target


def test_audit_dump_file_and_exports(tmp_path: Path) -> None:
    mifare_path = tmp_path / "card.dump"
    dump = MifareDump.empty(20)
    for s in range(5):
        dump.set_block(s * 4 + 3, FACTORY_MIFARE_TRAILER)
    dump.save(mifare_path)

    rep_m = audit_dump_file(mifare_path)
    assert rep_m.risk_level == "KRYTYCZNE"

    ntag_path = tmp_path / "ntag.dump"
    NtagDump(b"\x00" * 180).save(ntag_path)
    rep_n = audit_dump_file(ntag_path)
    assert rep_n.card_metadata["pages"] == 45

    html_out = tmp_path / "report.html"
    md_out = tmp_path / "report.md"
    json_out = tmp_path / "report.json"

    rep_m.save_html(html_out, mask_sensitive=True)
    rep_m.save_markdown(md_out, mask_sensitive=True)
    rep_m.save_json(json_out, mask_sensitive=True)

    html_text = html_out.read_text(encoding="utf-8")
    assert "@media print" in html_text
    assert "FFFF****FFFF" in html_text
    assert "FFFFFFFFFFFF" not in html_text

    md_text = md_out.read_text(encoding="utf-8")
    assert "# Raport Audytu Bezpieczeństwa Karty RFID/NFC" in md_text
    assert "FFFF****FFFF" in md_text

    json_data = json.loads(json_out.read_text(encoding="utf-8"))
    assert json_data["masked"] is True
    assert json_data["risk_level"] == "KRYTYCZNE"


def test_audit_live_reader_readonly_and_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--dump", "card.dump", "-o", "out.html", "--unmask"])
    assert args.command == "audit"
    assert args.unmask is True

    # Weryfikacja, że audit_live_reader dla karty CPU z Random UID (0x08..) oraz dla LF-only działa czysto Read-Only
    class DummyTransport:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    reader = NFCReader(DummyTransport())  # type: ignore[arg-type]
    monkeypatch.setattr(
        reader,
        "scan_card",
        lambda init_rf=True: CardInfo(uid=bytes.fromhex("08112233"), atqa=b"\x03\x44", sak=0x20, card_type="ISO 14443-4 (CPU / DESFire / JC)"),
    )
    monkeypatch.setattr(reader, "read_em4100", lambda init_rf=True: None)
    monkeypatch.setattr(reader, "read_hid_prox", lambda init_rf=True: None)

    rep_cpu = audit_live_reader(reader)
    assert rep_cpu.risk_level == "NISKIE"
    assert {f.code for f in rep_cpu.findings} == {"ISO14443_RANDOM_UID", "ISO14443_4_CPU_CARD"}

    # Brak jakiejkolwiek karty -> ProtocolError
    monkeypatch.setattr(reader, "scan_card", lambda init_rf=True: None)
    with pytest.raises(ProtocolError, match="Nie wykryto żadnej karty"):
        audit_live_reader(reader)

    # CLI audit --dump -> HTML
    dump_path = tmp_path / "mini.dump"
    html_path = tmp_path / "audit.html"
    dump = MifareDump.empty(20)
    for s in range(5):
        dump.set_block(s * 4 + 3, bytes.fromhex("A0A1A2A3A4A5FF078069A0A1A2A3A4A5"))
    dump.save(dump_path)

    assert cli_main(["audit", "--dump", str(dump_path), "-o", str(html_path)]) == 0
    cli_out = capsys.readouterr().out
    assert "A0A1****A4A5" in cli_out
    assert "A0A1A2A3A4A5" not in cli_out
    assert html_path.exists()

    assert cli_main(["audit", "--dump", str(dump_path), "--unmask"]) == 0
    cli_unmasked = capsys.readouterr().out
    assert "A0A1A2A3A4A5" in cli_unmasked
