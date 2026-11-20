"""Nieinwazyjny moduł Audytu Bezpieczeństwa Kart RFID/NFC (Read-Only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import html
import json
from pathlib import Path
from typing import Any, Callable, Sequence

from .dump import MifareDump, NtagDump
from .protocol import (
    DEFAULT_MIFARE_KEYS,
    CardInfo,
    EM4100Card,
    HIDProxCard,
    NFCReader,
    NtagVersion,
    ProtocolError,
    sector_auth_from_keys,
)

SEVERITY_LEVELS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
RISK_LEVELS: tuple[str, ...] = ("KRYTYCZNE", "WYSOKIE", "ŚREDNIE", "NISKIE")

_SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 45,
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5,
    "INFO": 0,
}


def mask_key_hex(key_hex: str) -> str:
    """Maskuje środkowe znaki 6-bajtowego klucza HEX (np. 'A0A1A2A3A4A5' -> 'A0A1****A4A5')."""
    cleaned = key_hex.replace(" ", "").replace(":", "").replace("-", "").strip().upper()
    if len(cleaned) >= 8:
        return f"{cleaned[:4]}****{cleaned[-4:]}"
    if len(cleaned) >= 4:
        return f"{cleaned[:2]}****"
    return "****"


def _mask_text(text: str, sensitive_keys: Sequence[str], mask_sensitive: bool) -> str:
    if not mask_sensitive:
        return text
    out = text
    for raw_key in sensitive_keys:
        clean = raw_key.replace(" ", "").replace(":", "").replace("-", "").strip().upper()
        if len(clean) < 8:
            continue
        masked = mask_key_hex(clean)
        spaced = " ".join(clean[i : i + 2] for i in range(0, len(clean), 2))
        out = out.replace(clean, masked).replace(clean.lower(), masked)
        out = out.replace(spaced, masked).replace(spaced.lower(), masked)
    return out


def _mask_value(value: Any, sensitive_keys: Sequence[str], mask_sensitive: bool) -> Any:
    if not mask_sensitive:
        return value
    if isinstance(value, str):
        return _mask_text(value, sensitive_keys, True)
    if isinstance(value, list):
        return [_mask_value(item, sensitive_keys, True) for item in value]
    if isinstance(value, dict):
        return {k: _mask_value(v, sensitive_keys, True) for k, v in value.items()}
    return value


@dataclass(frozen=True)
class AuditFinding:
    """Pojedyncze znalezisko audytu bezpieczeństwa karty."""

    severity: str
    code: str
    title: str
    description: str
    recommendation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"Nieprawidłowy poziom istotności: {self.severity!r}")


@dataclass
class CardAuditReport:
    """Kompletny raport z nieinwazyjnego audytu bezpieczeństwa karty RFID/NFC."""

    risk_level: str
    risk_score: int
    summary: str
    card_metadata: dict[str, Any]
    findings: list[AuditFinding]
    recommendations: list[str]
    migration_target: str
    timestamp: str
    sensitive_keys: list[str] = field(default_factory=list)

    def to_dict(self, mask_sensitive: bool = True) -> dict[str, Any]:
        """Zwraca słownik gotowy do serializacji JSON z opcjonalnym maskowaniem kluczy."""
        keys = self.sensitive_keys
        return {
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "summary": _mask_text(self.summary, keys, mask_sensitive),
            "card_metadata": _mask_value(self.card_metadata, keys, mask_sensitive),
            "findings": [
                {
                    "severity": f.severity,
                    "code": f.code,
                    "title": _mask_text(f.title, keys, mask_sensitive),
                    "description": _mask_text(f.description, keys, mask_sensitive),
                    "recommendation": _mask_text(f.recommendation, keys, mask_sensitive),
                }
                for f in self.findings
            ],
            "recommendations": [_mask_text(r, keys, mask_sensitive) for r in self.recommendations],
            "migration_target": self.migration_target,
            "timestamp": self.timestamp,
            "masked": bool(mask_sensitive),
        }

    def save_json(self, path: Path | str, mask_sensitive: bool = True) -> None:
        """Zapisuje raport audytu w formacie JSON."""
        payload = json.dumps(self.to_dict(mask_sensitive=mask_sensitive), indent=2, ensure_ascii=False)
        Path(path).write_text(payload + "\n", encoding="utf-8")

    def format_text(self, mask_sensitive: bool = True) -> str:
        """Formatuje czytelny raport tekstowy dla CLI oraz podglądu GUI."""
        data = self.to_dict(mask_sensitive=mask_sensitive)
        lines = [
            "============================================================",
            f"AUDYT BEZPIECZEŃSTWA KARTY — RYZYKO: {data['risk_level']} ({data['risk_score']}/100)",
            "============================================================",
            f"Data audytu:      {data['timestamp']}",
            f"Podsumowanie:     {data['summary']}",
            f"Cel migracji:     {data['migration_target']}",
        ]
        meta = data["card_metadata"]
        if meta:
            lines.append("\n--- Metadane karty ---")
            for k, v in meta.items():
                if v is not None and v != "":
                    lines.append(f"  {k}: {v}")

        lines.append(f"\n--- Znaleziska ({len(data['findings'])}) ---")
        for idx, f in enumerate(data["findings"], start=1):
            lines.append(f"  [{idx}] [{f['severity']}] {f['code']}: {f['title']}")
            lines.append(f"      Opis:         {f['description']}")
            lines.append(f"      Rekomendacja: {f['recommendation']}")

        if data["recommendations"]:
            lines.append("\n--- Zalecenia wdrożeniowe ---")
            for rec in data["recommendations"]:
                lines.append(f"  * {rec}")
        return "\n".join(lines)

    def to_markdown(self, mask_sensitive: bool = True) -> str:
        """Generuje raport audytu w formacie Markdown."""
        data = self.to_dict(mask_sensitive=mask_sensitive)
        lines = [
            f"# Raport Audytu Bezpieczeństwa Karty RFID/NFC",
            "",
            f"- **Poziom ryzyka:** **{data['risk_level']}** (`{data['risk_score']}/100`)",
            f"- **Data badania:** `{data['timestamp']}`",
            f"- **Rekomendowana migracja:** `{data['migration_target']}`",
            f"- **Podsumowanie:** {data['summary']}",
            "",
            "## Metadane karty",
            "",
        ]
        for k, v in data["card_metadata"].items():
            if v is not None and v != "":
                lines.append(f"- **{k}:** `{v}`")

        lines.extend(["", "## Wykryte znaleziska", ""])
        for f in data["findings"]:
            lines.append(f"### [{f['severity']}] `{f['code']}` — {f['title']}")
            lines.append(f"- **Opis:** {f['description']}")
            lines.append(f"- **Rekomendacja:** {f['recommendation']}")
            lines.append("")

        lines.extend(["## Podsumowanie zaleceń", ""])
        for rec in data["recommendations"]:
            lines.append(f"- {rec}")
        return "\n".join(lines) + "\n"

    def save_markdown(self, path: Path | str, mask_sensitive: bool = True) -> None:
        """Zapisuje raport audytu w pliku Markdown (.md)."""
        Path(path).write_text(self.to_markdown(mask_sensitive=mask_sensitive), encoding="utf-8")

    def to_html(self, mask_sensitive: bool = True) -> str:
        """Generuje samowystarczalny raport HTML z kolorowymi odznakami i stylami @media print."""
        data = self.to_dict(mask_sensitive=mask_sensitive)
        risk_colors = {
            "KRYTYCZNE": "#dc2626",
            "WYSOKIE": "#ea580c",
            "ŚREDNIE": "#ca8a04",
            "NISKIE": "#16a34a",
        }
        sev_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#475569",
        }
        badge_bg = risk_colors.get(data["risk_level"], "#475569")

        meta_rows = "\n".join(
            f"<tr><th>{html.escape(str(k))}</th><td><code>{html.escape(str(v))}</code></td></tr>"
            for k, v in data["card_metadata"].items()
            if v is not None and v != ""
        )
        finding_cards = "\n".join(
            f"""<div class="finding">
  <div class="finding-header">
    <span class="badge" style="background:{sev_colors.get(f['severity'], '#475569')}">{html.escape(f['severity'])}</span>
    <strong>{html.escape(f['code'])} — {html.escape(f['title'])}</strong>
  </div>
  <p>{html.escape(f['description'])}</p>
  <p class="rec"><strong>Rekomendacja:</strong> {html.escape(f['recommendation'])}</p>
</div>"""
            for f in data["findings"]
        )
        rec_items = "\n".join(f"<li>{html.escape(r)}</li>" for r in data["recommendations"])

        return f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>Raport Audytu Bezpieczeństwa Karty — NFCplus</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; color: #1e293b; max-width: 900px; margin: 24px auto; padding: 0 16px; line-height: 1.5; }}
  header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }}
  .badge {{ color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.85rem; display: inline-block; }}
  .risk-banner {{ font-size: 1.1rem; padding: 8px 14px; border-radius: 8px; background: {badge_bg}; color: #fff; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
  th {{ width: 220px; color: #475569; }}
  .finding {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; page-break-inside: avoid; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
  .rec {{ color: #0f172a; margin-bottom: 0; }}
  @media print {{
    body {{ margin: 0; max-width: 100%; }}
    .badge, .risk-banner {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style>
</head>
<body>
<header>
  <div>
    <h1>Audyt Bezpieczeństwa Karty RFID/NFC</h1>
    <div>Data: <code>{html.escape(data['timestamp'])}</code> | Cel migracji: <strong>{html.escape(data['migration_target'])}</strong></div>
  </div>
  <div class="risk-banner">Ryzyko: {html.escape(data['risk_level'])} ({data['risk_score']}/100)</div>
</header>
<p><strong>Podsumowanie:</strong> {html.escape(data['summary'])}</p>
<h2>Metadane karty</h2>
<table>{meta_rows}</table>
<h2>Znaleziska ({len(data['findings'])})</h2>
{finding_cards}
<h2>Zalecenia wdrożeniowe</h2>
<ul>{rec_items}</ul>
</body>
</html>
"""

    def save_html(self, path: Path | str, mask_sensitive: bool = True) -> None:
        """Zapisuje samowystarczalny raport HTML."""
        Path(path).write_text(self.to_html(mask_sensitive=mask_sensitive), encoding="utf-8")


def _compute_risk_score_and_level(findings: Sequence[AuditFinding]) -> tuple[int, str]:
    score = min(100, sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))
    severities = {f.severity for f in findings}
    if "CRITICAL" in severities or score >= 70:
        return max(score, 75) if "CRITICAL" in severities else score, "KRYTYCZNE"
    if "HIGH" in severities or score >= 45:
        return max(score, 50) if "HIGH" in severities else score, "WYSOKIE"
    if "MEDIUM" in severities or score >= 20:
        return max(score, 25) if "MEDIUM" in severities else score, "ŚREDNIE"
    return score, "NISKIE"


def _add_lf_findings(
    findings: list[AuditFinding],
    metadata: dict[str, Any],
    em4100: EM4100Card | None,
    hid_prox: HIDProxCard | None,
) -> None:
    if em4100 is not None:
        metadata["lf_em4100_id"] = em4100.hex_id
        metadata["lf_em4100_dec10"] = em4100.decimal_10
        findings.append(
            AuditFinding(
                severity="CRITICAL",
                code="LF_EM4100_PLAINTEXT",
                title="Transponder 125 kHz EM4100 bez uwierzytelniania",
                description=(
                    f"Karta transmituje jawny, stały 40-bitowy identyfikator EM4100 ({em4100.hex_id}) "
                    "bez szyfrowania i bez mechanizmu challenge-response."
                ),
                recommendation=(
                    "Wycofaj pasmo 125 kHz EM4100 z systemów kontroli dostępu i migruj do MIFARE DESFire EV3 lub NTAG 424 DNA."
                ),
            )
        )
    if hid_prox is not None:
        metadata["lf_hid_prox"] = f"{hid_prox.format_name} ({hid_prox.raw_hex})"
        findings.append(
            AuditFinding(
                severity="CRITICAL",
                code="LF_HID_PROX_PLAINTEXT",
                title="Transponder 125 kHz HID Prox podatny na klonowanie T5577",
                description=(
                    f"Wykryto nieszyfrowany układ HID Prox ({hid_prox.format_name}, raw={hid_prox.raw_hex}), "
                    "który można skopiować na czysty układ T5577."
                ),
                recommendation=(
                    "Zastąp karty 125 kHz HID Prox kartami HF 13.56 MHz z uwierzytelnianiem AES-128 (DESFire EV3 / Seos)."
                ),
            )
        )


def _normalize_found_keys_map(
    dump: MifareDump,
    found_keys: dict[tuple[int, str], bytes] | dict[int, tuple[bytes | None, bytes | None]] | None,
) -> dict[int, tuple[bytes | None, bytes | None]]:
    result: dict[int, tuple[bytes | None, bytes | None]] = {}
    if found_keys:
        first_key = next(iter(found_keys.keys()))
        if isinstance(first_key, tuple):
            typed_map: dict[tuple[int, str], bytes] = found_keys  # type: ignore[assignment]
            for s in range(dump.sector_count):
                ka = typed_map.get((s, "A")) or typed_map.get((s, "a"))
                kb = typed_map.get((s, "B")) or typed_map.get((s, "b"))
                result[s] = (ka, kb)
            return result
        sector_map: dict[int, tuple[bytes | None, bytes | None]] = found_keys  # type: ignore[assignment]
        for s in range(dump.sector_count):
            result[s] = sector_map.get(s, (None, None))
        return result

    for s in range(dump.sector_count):
        ka, _acc, kb = dump.get_sector_trailer(s)
        result[s] = (ka, kb)
    return result


def audit_mifare_dump(
    dump: MifareDump,
    *,
    found_keys: dict[tuple[int, str], bytes] | dict[int, tuple[bytes | None, bytes | None]] | None = None,
    card: CardInfo | None = None,
    em4100: EM4100Card | None = None,
    hid_prox: HIDProxCard | None = None,
) -> CardAuditReport:
    """Wykonuje nieinwazyjny audyt zrzutu Mifare Classic (klucze, Crypto1, Access Bits, Blok 0, dual-tech LF)."""
    findings: list[AuditFinding] = []
    sensitive_keys: list[str] = []

    b0 = dump.get_block(0)
    uid_str = card.uid_hex if card is not None else (dump.uid or " ".join(f"{b:02X}" for b in b0[0:4]))
    atqa_str = card.atqa_hex if card is not None else (dump.atqa or f"{b0[6]:02X} {b0[7]:02X}")
    sak_str = f"{card.sak:02X}" if card is not None else (dump.sak or f"{b0[5]:02X}")

    metadata: dict[str, Any] = {
        "technology": card.card_type if card is not None else f"MIFARE Classic ({dump.sector_count} sektorów)",
        "uid": uid_str,
        "atqa": atqa_str,
        "sak": sak_str,
        "sectors": dump.sector_count,
        "total_blocks": dump.total_blocks,
    }

    _add_lf_findings(findings, metadata, em4100, hid_prox)

    findings.append(
        AuditFinding(
            severity="HIGH",
            code="MIFARE_CRYPTO1_LEGACY",
            title="Przestarzały algorytm kryptograficzny NXP Crypto1 (48-bit)",
            description=(
                "MIFARE Classic wykorzystuje 48-bitowy szyfr strumieniowy Crypto1 o znanych słabościach kryptograficznych."
            ),
            recommendation="Zaplanuj migrację do kart MIFARE DESFire EV3 lub MIFARE Plus EV2 w trybie SL3 (AES-128).",
        )
    )

    default_set = set(DEFAULT_MIFARE_KEYS)
    key_map = _normalize_found_keys_map(dump, found_keys)

    default_key_sectors: list[int] = []
    default_key_data_sectors: list[int] = []
    same_ab_sectors: list[int] = []
    invalid_access_sectors: list[int] = []
    transport_access_sectors: list[int] = []
    discovered_key_hexes: list[str] = []

    for s in range(dump.sector_count):
        ka, kb = key_map.get(s, (None, None))
        _t_ka, acc, _t_kb = dump.get_sector_trailer(s)
        for k_bytes in (ka, kb, _t_ka, _t_kb):
            if k_bytes is not None and k_bytes != b"\x00" * 6:
                k_hex = k_bytes.hex().upper()
                if k_hex not in sensitive_keys:
                    sensitive_keys.append(k_hex)

        ka_eff = ka if ka is not None else _t_ka
        kb_eff = kb if kb is not None else _t_kb
        is_def_a = ka_eff in default_set
        is_def_b = kb_eff in default_set
        if is_def_a or is_def_b:
            default_key_sectors.append(s)
            for k_eff, is_def in ((ka_eff, is_def_a), (kb_eff, is_def_b)):
                if is_def and k_eff is not None:
                    kh = k_eff.hex().upper()
                    if kh not in discovered_key_hexes:
                        discovered_key_hexes.append(kh)
            block_range = dump.sector_block_range(s)
            for blk in block_range[:-1]:
                if blk != 0 and dump.get_block(blk) != b"\x00" * 16:
                    default_key_data_sectors.append(s)
                    break

        if ka_eff is not None and kb_eff is not None and ka_eff == kb_eff and ka_eff != b"\x00" * 6:
            same_ab_sectors.append(s)

        if not acc.valid:
            invalid_access_sectors.append(s)
        elif acc.c_bits == (0, 0, 0, 1):
            transport_access_sectors.append(s)

    if default_key_sectors:
        keys_str = ", ".join(discovered_key_hexes)
        data_note = (
            f" (w tym sektory z danymi użytkownika: {', '.join(str(s) for s in default_key_data_sectors)})"
            if default_key_data_sectors
            else ""
        )
        findings.append(
            AuditFinding(
                severity="CRITICAL",
                code="MIFARE_DEFAULT_KEYS",
                title=f"Sektory zabezpieczone fabrycznymi/publicznymi kluczami ({len(default_key_sectors)}/{dump.sector_count})",
                description=(
                    f"Sektory {', '.join(str(s) for s in default_key_sectors)} używają powszechnie znanych kluczy ({keys_str}){data_note}."
                ),
                recommendation=(
                    "Zdywersyfikuj klucze per sektor i per UID karty lub migruj do MIFARE DESFire EV3 (AES-128)."
                ),
            )
        )

    if same_ab_sectors:
        findings.append(
            AuditFinding(
                severity="MEDIUM",
                code="MIFARE_KEY_REUSE_AB",
                title="Brak separacji uprawnień (Key A == Key B)",
                description=(
                    f"W sektorach {', '.join(str(s) for s in same_ab_sectors)} klucz A i klucz B są identyczne."
                ),
                recommendation="Ustaw osobny klucz tylko do odczytu (Key A) oraz klucz zapisu/administracji (Key B).",
            )
        )

    if invalid_access_sectors:
        findings.append(
            AuditFinding(
                severity="HIGH",
                code="MIFARE_INVALID_ACCESS_BITS",
                title="Nieprawidłowe bity dostępu C1/C2/C3 w trailerze sektora",
                description=(
                    f"Sektory {', '.join(str(s) for s in invalid_access_sectors)} mają uszkodzone dopełnienie bitów dostępu."
                ),
                recommendation="Zweryfikuj poprawność trailerów (np. przez validate_access_bits) przed zapisem na kartę.",
            )
        )
    elif transport_access_sectors:
        findings.append(
            AuditFinding(
                severity="MEDIUM",
                code="MIFARE_TRANSPORT_ACCESS_BITS",
                title="Fabryczna konfiguracja bitów dostępu (FF 07 80)",
                description=(
                    f"Sektory {', '.join(str(s) for s in transport_access_sectors)} używają konfiguracji transportowej (000/001), "
                    "w której Key A pozwala na pełny zapis danych i trailera."
                ),
                recommendation="Skonfiguruj bity dostępu tak, aby zapis bloków i trailera wymagał wyłącznie Key B.",
            )
        )

    # Weryfikacja Bloku 0 (BCC oraz SAK/ATQA)
    if b0 != b"\x00" * 16:
        if card is None or len(card.uid) == 4:
            expected_bcc = b0[0] ^ b0[1] ^ b0[2] ^ b0[3]
            actual_bcc = b0[4]
            if actual_bcc != expected_bcc:
                findings.append(
                    AuditFinding(
                        severity="HIGH",
                        code="MIFARE_BLOCK0_BCC_INVALID",
                        title="Niespójna suma kontrolna BCC w Bloku 0",
                        description=(
                            f"Bajt BCC w Bloku 0 wynosi 0x{actual_bcc:02X}, podczas gdy XOR pierwszych 4 bajtów UID daje 0x{expected_bcc:02X} "
                            "(wskazuje na niepoprawnie zapisaną kartę klonowalną CUID/Gen2)."
                        ),
                        recommendation="Zweryfikuj oryginalność karty i odrzucaj karty z niepoprawnym blokiem producenta.",
                    )
                )
        if card is not None:
            b0_sak = b0[5]
            b0_atqa = b0[6:8]
            if (len(card.uid) == 4 and b0[0:4] != card.uid) or b0_sak != card.sak or b0_atqa not in (card.atqa, card.atqa[::-1]):
                findings.append(
                    AuditFinding(
                        severity="HIGH",
                        code="MIFARE_BLOCK0_SAK_ATQA_ANOMALY",
                        title="Rozbieżność danych antykolizji (UID/SAK/ATQA) względem Bloku 0",
                        description=(
                            f"Odpowiedź radiowa ISO14443A (UID={card.uid_hex}, SAK={card.sak:02X}, ATQA={card.atqa_hex}) "
                            f"różni się od zawartości Bloku 0 (UID={b0[0:4].hex(' ').upper()}, SAK={b0_sak:02X}, ATQA={b0_atqa.hex(' ').upper()}). "
                            "Silny wskaźnik karty emulatora lub CUID/Gen1a/Gen2."
                        ),
                        recommendation="Wymagaj uwierzytelniania kryptograficznego warstwy aplikacji zamiast polegania na UID/Bloku 0.",
                    )
                )

    score, level = _compute_risk_score_and_level(findings)
    migration = "MIFARE DESFire EV3 / MIFARE Plus EV2 (SL3 AES-128)"
    recommendations = list(dict.fromkeys(f.recommendation for f in findings))
    summary = (
        f"Audyt MIFARE Classic ({dump.sector_count} sekt.): wykryto {len(default_key_sectors)} sekt. z domyślnymi kluczami; "
        f"poziom ryzyka {level} ({score}/100)."
    )
    return CardAuditReport(
        risk_level=level,
        risk_score=score,
        summary=summary,
        card_metadata=metadata,
        findings=findings,
        recommendations=recommendations,
        migration_target=migration,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        sensitive_keys=sensitive_keys,
    )


def audit_ntag_dump(
    dump: NtagDump,
    *,
    version: NtagVersion | None = None,
    card: CardInfo | None = None,
    em4100: EM4100Card | None = None,
    hid_prox: HIDProxCard | None = None,
) -> CardAuditReport:
    """Wykonuje nieinwazyjny audyt zrzutu NTAG / Ultralight (Static Lock, AUTH0/PWD_AUTH, brak AES)."""
    findings: list[AuditFinding] = []
    uid_str = card.uid_hex if card is not None else "nieznany"
    tag_name = version.name if version is not None else f"NTAG / Ultralight ({dump.page_count} stron)"

    metadata: dict[str, Any] = {
        "technology": tag_name,
        "uid": uid_str,
        "pages": dump.page_count,
        "size_bytes": len(dump.data),
    }

    _add_lf_findings(findings, metadata, em4100, hid_prox)

    if dump.page_count >= 3:
        p2 = dump.get_page(2)
        static_lock = p2[2:4]
        metadata["static_lock_hex"] = static_lock.hex().upper()
        if static_lock == b"\x00\x00":
            findings.append(
                AuditFinding(
                    severity="MEDIUM",
                    code="NTAG_STATIC_LOCK_OPEN",
                    title="Brak blokady zapisu Static Lock (strona 2 bajty 2..3 = 00 00)",
                    description=(
                        "Bajty Static Lock mają wartość 00 00 — początkowe strony pamięci użytkownika NTAG nie są "
                        "zablokowane przed nadpisaniem."
                    ),
                    recommendation="Zablokuj strony statyczne lub włącz ochronę hasłem PWD_AUTH dla stron od 04 wzwyż.",
                )
            )

    if dump.page_count >= 8:
        cfg0_idx = dump.page_count - 4
        cfg0 = dump.get_page(cfg0_idx)
        auth0 = cfg0[3]
        metadata["auth0_page"] = f"0x{auth0:02X}"
        if auth0 == 0xFF or auth0 >= dump.page_count:
            findings.append(
                AuditFinding(
                    severity="HIGH",
                    code="NTAG_AUTH0_DISABLED",
                    title="Ochrona hasłem PWD_AUTH wyłączona (AUTH0 = 0xFF)",
                    description=(
                        f"Bajt AUTH0 w stronie konfiguracyjnej CFG0 (strona {cfg0_idx}) wynosi 0x{auth0:02X}, "
                        "co oznacza brak ochrony hasłem dla całej pamięci tagu."
                    ),
                    recommendation="Ustaw unikalne 32-bitowe hasło PWD, 16-bitowy PACK oraz obniż AUTH0 do strony 04.",
                )
            )

    findings.append(
        AuditFinding(
            severity="MEDIUM",
            code="NTAG_NO_CRYPTO_AUTH",
            title="Brak kryptograficznego uwierzytelniania AES (tylko 32-bitowe PWD)",
            description=(
                "Standardowe układy NTAG21x / Ultralight EV1 używają statycznego 4-bajtowego hasła przesyłanego "
                "bez szyfrowania sesji, co nie chroni przed podsłuchem RF i klonowaniem."
            ),
            recommendation="W zastosowaniach wymagających ochrony przed klonowaniem migruj do NTAG 424 DNA (AES-128 / SUN).",
        )
    )

    score, level = _compute_risk_score_and_level(findings)
    recommendations = list(dict.fromkeys(f.recommendation for f in findings))
    summary = f"Audyt {tag_name}: poziom ryzyka {level} ({score}/100), znaleziska={len(findings)}."
    return CardAuditReport(
        risk_level=level,
        risk_score=score,
        summary=summary,
        card_metadata=metadata,
        findings=findings,
        recommendations=recommendations,
        migration_target="NTAG 424 DNA (AES-128 / SUN)",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def audit_dump_file(path: Path | str) -> CardAuditReport:
    """Automatycznie rozpoznaje plik zrzutu (.dump/.bin) Mifare Classic lub NTAG i wykonuje audyt offline."""
    raw = Path(path).read_bytes()
    if len(raw) in (320, 1024, 2048, 4096):
        return audit_mifare_dump(MifareDump(raw))
    if len(raw) > 0 and len(raw) % 4 == 0:
        return audit_ntag_dump(NtagDump(raw))
    raise ValueError(
        f"Nieobsługiwany rozmiar pliku zrzutu do audytu ({len(raw)} B). "
        "Oczekiwano 320/1024/2048/4096 B (Mifare) lub wielokrotności 4 B (NTAG)."
    )


def audit_live_reader(
    reader: NFCReader,
    keys: Sequence[bytes] = DEFAULT_MIFARE_KEYS,
    *,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> CardAuditReport:
    """Wykonuje w 100% nieinwazyjny (Read-Only) audyt karty umieszczonej na czytniku."""
    iso_card = reader.scan_card(init_rf=True)
    supports_lf = bool(getattr(reader, "supports_lf", True))
    if supports_lf:
        em_card = reader.read_em4100(init_rf=True)
        hid_card = reader.read_hid_prox(init_rf=True)
    else:
        em_card = None
        hid_card = None

    if iso_card is None and em_card is None and hid_card is None:
        if not supports_lf:
            raise ProtocolError("Nie wykryto żadnej karty 13,56 MHz na czytniku.")
        raise ProtocolError("Nie wykryto żadnej karty na czytniku (13.56 MHz / 125 kHz / HID).")

    if iso_card is not None:
        if iso_card.sak in (0x08, 0x18, 0x09, 0x28):
            sectors = 5 if iso_card.sak == 0x09 else (40 if iso_card.sak == 0x18 else 16)
            card_m, blocks, found = reader.mifare_read_sectors(
                keys=keys,
                sectors=sectors,
                progress_cb=progress_cb,
            )
            dump = MifareDump.from_blocks(
                blocks,
                sector_auth=sector_auth_from_keys(found),
                uid=card_m.uid_hex,
                atqa=card_m.atqa_hex,
                sak=f"{card_m.sak:02X}",
            )
            rep = audit_mifare_dump(
                dump,
                found_keys=found,
                card=card_m,
                em4100=em_card,
                hid_prox=hid_card,
            )
            if not supports_lf:
                rep.card_metadata["supports_lf"] = False
            return rep

        if iso_card.sak == 0x00:
            card_n, version, pages = reader.ntag_read_all()
            dump_n = NtagDump.from_pages(pages)
            rep = audit_ntag_dump(
                dump_n,
                version=version,
                card=card_n,
                em4100=em_card,
                hid_prox=hid_card,
            )
            if not supports_lf:
                rep.card_metadata["supports_lf"] = False
            return rep

        # Karta ISO 14443-4 (DESFire / CPU / Mifare Plus)
        findings: list[AuditFinding] = []
        metadata: dict[str, Any] = {
            "technology": iso_card.card_type,
            "uid": iso_card.uid_hex,
            "atqa": iso_card.atqa_hex,
            "sak": f"{iso_card.sak:02X}",
        }
        if not supports_lf:
            metadata["supports_lf"] = False
        _add_lf_findings(findings, metadata, em_card, hid_card)
        if len(iso_card.uid) == 4 and iso_card.uid[0] == 0x08:
            findings.append(
                AuditFinding(
                    severity="INFO",
                    code="ISO14443_RANDOM_UID",
                    title="Aktywny losowy identyfikator prywatności (Random UID 0x08..)",
                    description="Karta zwraca 4-bajtowy losowy UID zaczynający się od 0x08, co chroni przed śledzeniem radiowym.",
                    recommendation="Upewnij się, że identyfikacja odbywa się po uwierzytelnieniu aplikacji (np. AES), a nie po UID.",
                )
            )
        findings.append(
            AuditFinding(
                severity="INFO",
                code="ISO14443_4_CPU_CARD",
                title="Karta procesorowa ISO 14443-4 (CPU / DESFire)",
                description=f"Wykryto układ {iso_card.card_type} obsługujący warstwę APDU ISO 14443-4.",
                recommendation="Zweryfikuj wymuszanie wzajemnego uwierzytelniania AES-128 (EV2/EV3) w czytnikach dostępowych.",
            )
        )
        score, level = _compute_risk_score_and_level(findings)
        return CardAuditReport(
            risk_level=level,
            risk_score=score,
            summary=f"Audyt {iso_card.card_type}: poziom ryzyka {level} ({score}/100).",
            card_metadata=metadata,
            findings=findings,
            recommendations=list(dict.fromkeys(f.recommendation for f in findings)),
            migration_target="MIFARE DESFire EV3 (AES-128)",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    # Wykryto wyłącznie pasmo 125 kHz (EM4100 i/lub HID Prox)
    lf_findings: list[AuditFinding] = []
    lf_meta: dict[str, Any] = {"technology": "125 kHz LF (EM4100 / HID Prox)"}
    _add_lf_findings(lf_findings, lf_meta, em_card, hid_card)
    score, level = _compute_risk_score_and_level(lf_findings)
    return CardAuditReport(
        risk_level=level,
        risk_score=score,
        summary=f"Audyt karty 125 kHz LF: poziom ryzyka {level} ({score}/100).",
        card_metadata=lf_meta,
        findings=lf_findings,
        recommendations=list(dict.fromkeys(f.recommendation for f in lf_findings)),
        migration_target="MIFARE DESFire EV3 / NTAG 424 DNA",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
