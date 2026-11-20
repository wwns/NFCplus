"""Nowoczesny interfejs graficzny (CustomTkinter) dla czytników NFCplus."""

from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox
from typing import Any, Callable, Mapping, Sequence

import customtkinter as ctk

from nfcplus.audit import (
    CardAuditReport,
    audit_dump_file,
    audit_live_reader,
    audit_mifare_dump,
    audit_ntag_dump,
)
from nfcplus.dump import (
    FACTORY_MIFARE_TRAILER,
    MIFARE_BLOCK_SIZE,
    MifareDump,
    NtagDump,
    compare_buffers,
    decode_blocks_to_text,
    decode_value_block,
    encode_text_to_blocks,
    format_hex_ascii,
    is_mostly_printable_text,
    parse_key_file,
    validate_access_bits,
    writable_data_blocks,
)
from nfcplus.ndef import (
    NdefRecord,
    build_ndef_text_tlv,
    build_ndef_uri_tlv,
    parse_ndef_tlv,
)
from nfcplus.protocol import (
    DEFAULT_LF_FREQ_HZ,
    DEFAULT_MIFARE_KEYS,
    ApduResponse,
    CardInfo,
    EM4100Card,
    HIDProxCard,
    MifareWriteReport,
    NFCReader,
    NtagVersion,
    ProtocolError,
    convert_em4100_formats,
    parse_hex_bytes,
    sector_auth_from_keys,
)
from nfcplus.transport import (
    DeviceInfo,
    HIDTransport,
    TransportError,
    enumerate_readers,
    format_reader_labels,
    no_readers_hint,
    open_reader,
)

SECTOR_COLOR_OK = "#2E9E4B"
SECTOR_COLOR_FAIL = "#D94848"
SECTOR_COLOR_UNKNOWN = "#D0D4DA"
SECTOR_COLOR_UNKNOWN_DARK = "#4A505C"

APDU_TEMPLATES: dict[str, str] = {
    "SELECT MF (3F00)": "00 A4 00 00 02 3F 00",
    "GET CHALLENGE (8 B)": "00 84 00 00 08",
    "SELECT NDEF AID": "00 A4 04 00 07 D2 76 00 00 85 01 01 00",
    "SELECT PPSE (2PAY)": "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00",
}


def _enable_windows_dpi_awareness() -> None:
    """Włącza skalowanie HiDPI oraz AppUserModelID w systemie Windows przed inicjalizacją okna."""
    if sys.platform != "win32":
        return
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return
    try:
        if hasattr(windll, "shell32"):
            windll.shell32.SetCurrentProcessExplicitAppUserModelID("nfcplus.desktop.app")
    except (AttributeError, OSError):
        pass
    try:
        if hasattr(windll, "shcore"):
            windll.shcore.SetProcessDpiAwareness(1)
            return
    except (AttributeError, OSError):
        pass
    try:
        if hasattr(windll, "user32"):
            windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass


def _select_monospace_font(root: tk.Misc, platform: str | None = None) -> str:
    """Wybiera czytelny font o stałej szerokości dla danej platformy."""
    plat = sys.platform if platform is None else platform
    if plat == "win32":
        preferred = ("Consolas", "Courier New")
    elif plat.startswith("linux"):
        preferred = ("DejaVu Sans Mono", "Liberation Mono")
    else:
        preferred = ("Menlo", "DejaVu Sans Mono")

    try:
        available = set(tkfont.families(root))
    except tk.TclError:
        return "TkFixedFont"
    for name in preferred:
        if name in available:
            return name
    return "TkFixedFont"


def get_config_path(platform: str | None = None) -> Path:
    """Zwraca ścieżkę lokalnego pliku konfiguracyjnego użytkownika."""
    plat = sys.platform if platform is None else platform
    if plat == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else (Path.home() / "AppData" / "Roaming")
        return base / "NFCplus" / "config.json"
    return Path.home() / ".config" / "nfcplus" / "config.json"


def _normalize_theme(value: object) -> str:
    return "light" if str(value).strip().lower() == "light" else "dark"


def load_app_config(config_path: Path | None = None) -> dict[str, Any]:
    """Bezpiecznie wczytuje lokalną konfigurację aplikacji (auto_connect, theme)."""
    path = get_config_path() if config_path is None else config_path
    defaults: dict[str, Any] = {"auto_connect": True, "theme": "dark"}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return defaults
    if not isinstance(raw, dict):
        return defaults
    return {
        "auto_connect": bool(raw.get("auto_connect", True)),
        "theme": _normalize_theme(raw.get("theme", "dark")),
    }


def save_app_config(config: Mapping[str, Any], config_path: Path | None = None) -> bool:
    """Bezpiecznie zapisuje lokalną konfigurację użytkownika; zwraca False przy błędzie I/O."""
    path = get_config_path() if config_path is None else config_path
    payload = {
        "auto_connect": bool(config.get("auto_connect", True)),
        "theme": _normalize_theme(config.get("theme", "dark")),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return True
    except OSError:
        return False


def sector_indicator_colors(
    sector_count: int,
    sector_auth: Mapping[int, tuple[bool, bool]] | None = None,
    *,
    dark: bool = True,
) -> list[tuple[int, str, str]]:
    """Wyznacza kolory kontrolek Key A / Key B dla siatki sektorów Mifare Classic."""
    if sector_count <= 0:
        return []
    unknown_color = SECTOR_COLOR_UNKNOWN_DARK if dark else SECTOR_COLOR_UNKNOWN
    result: list[tuple[int, str, str]] = []
    for sector in range(sector_count):
        if sector_auth is None or sector not in sector_auth:
            result.append((sector, unknown_color, unknown_color))
            continue
        ok_a, ok_b = sector_auth[sector]
        result.append(
            (
                sector,
                SECTOR_COLOR_OK if ok_a else SECTOR_COLOR_FAIL,
                SECTOR_COLOR_OK if ok_b else SECTOR_COLOR_FAIL,
            )
        )
    return result


def sector_canvas_palette(dark: bool) -> dict[str, str]:
    """Paleta kolorów dla Canvas siatki kluczy w trybie ciemnym i jasnym."""
    if dark:
        return {
            "bg": "#1F2329",
            "cell_bg": "#2B3038",
            "cell_border": "#424955",
            "text": "#E8ECF2",
            "sq_border": "#111418",
            "sq_text": "#0F1216",
        }
    return {
        "bg": "#F2F4F7",
        "cell_bg": "#FFFFFF",
        "cell_border": "#C5CAD3",
        "text": "#22252A",
        "sq_border": "#555A64",
        "sq_text": "#111111",
    }


def merge_unique_keys(existing: Sequence[bytes], incoming: Sequence[bytes]) -> list[bytes]:
    """Scala listy kluczy 6 B bez duplikatów z zachowaniem kolejności."""
    merged: list[bytes] = []
    seen: set[bytes] = set()
    for key in (*existing, *incoming):
        if key not in seen:
            seen.add(key)
            merged.append(key)
    return merged


def validate_mifare_block_edit(dump: MifareDump, block: int, hex_value: str) -> tuple[bytes, bool]:
    """Waliduje edycję bloku w buforze MifareDump i blokuje błędne bity dostępu trailera."""
    if block < 0 or block >= dump.total_blocks:
        raise ValueError(f"Numer bloku musi być w zakresie 0..{dump.total_blocks - 1}.")
    cleaned = hex_value.strip().replace(" ", "").replace(":", "").replace("-", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("Dane bloku muszą być poprawnym ciągiem szesnastkowym (HEX).") from exc
    if len(raw) != MIFARE_BLOCK_SIZE:
        raise ValueError(f"Blok Mifare wymaga dokładnie {MIFARE_BLOCK_SIZE} bajtów (32 znaki HEX).")
    is_trailer = dump.is_trailer_block(block)
    if is_trailer and not validate_access_bits(raw):
        raise ValueError(
            f"Blok {block} jest trailerem sektora i ma nieprawidłowe bity dostępu (C1/C2/C3). "
            "Edycja została zablokowana."
        )
    return raw, is_trailer


def format_mifare_dump_text(
    dump: MifareDump,
    header: str = "",
    unavailable_blocks: set[int] | None = None,
) -> str:
    """Formatuje zawartość bufora MifareDump do widoku sektorów i bloków (HEX | ASCII)."""
    lines: list[str] = []
    if header:
        lines.append(header)
    missing = unavailable_blocks or set()
    for sector in range(dump.sector_count):
        ka, acc, kb = dump.get_sector_trailer(sector)
        auth = dump.sector_auth.get(sector)
        if auth is None:
            ka_s = ka.hex().upper()
            kb_s = kb.hex().upper()
        else:
            ka_s = ka.hex().upper() if auth[0] else "????????????"
            kb_s = kb.hex().upper() if auth[1] else "????????????"
        acc_warn = "" if acc.valid else " [BŁĘDNE BITY DOSTĘPU]"
        lines.append(f"=== Sektor {sector:02d} (KeyA={ka_s} | Access={acc.raw.hex().upper()}{acc_warn} | KeyB={kb_s}) ===")
        for blk in dump.sector_block_range(sector):
            txt = "<brak dostępu>" if blk in missing else format_hex_ascii(dump.get_block(blk))
            lines.append(f"  Blok {blk:03d}: {txt}")
        lines.append("")
    return "\n".join(lines)


def format_mifare_analysis(dump: MifareDump) -> str:
    """Generuje raport analizy bitów dostępu sektorów oraz bloków wartości (Value Block)."""
    lines = [
        f"Analiza bufora Mifare Classic ({len(dump.data)} B, {dump.sector_count} sektorów, {dump.total_blocks} bloków)",
        "",
    ]
    invalid_trailers = 0
    value_blocks_found = 0

    for sector in range(dump.sector_count):
        ka, acc, kb = dump.get_sector_trailer(sector)
        status = "OK" if acc.valid else "NIEPRAWIDŁOWE"
        if not acc.valid:
            invalid_trailers += 1
        c_str = ", ".join(f"B{idx}={val:03b}" for idx, val in enumerate(acc.c_bits))
        lines.append(
            f"Sektor {sector:02d}: Access={acc.raw.hex().upper()} [{status}] ({c_str}) | "
            f"KeyA={ka.hex().upper()} KeyB={kb.hex().upper()}"
        )
        block_range = dump.sector_block_range(sector)
        trailer_blk = block_range[-1]
        for blk in block_range:
            if blk == trailer_blk:
                continue
            val = decode_value_block(dump.get_block(blk))
            if val is not None:
                value_blocks_found += 1
                lines.append(f"  -> Blok {blk:03d}: Value Block = {val} (0x{val & 0xFFFFFFFF:08X})")

    lines.insert(
        1,
        f"Podsumowanie: nieprawidłowe trailery={invalid_trailers}, wykryte Value Block={value_blocks_found}",
    )
    return "\n".join(lines)


def format_write_report_summary(title: str, report: MifareWriteReport) -> str:
    """Buduje zwięzłe podsumowanie zapisu lub formatowania Mifare Classic."""
    lines = [
        f"{title}: zapisane={len(report.written_blocks)}, "
        f"pominięte={len(report.skipped_blocks)}, błędy={len(report.failed_blocks)}"
    ]
    for blk in sorted(report.failed_blocks):
        lines.append(f"  Blok {blk:03d}: {report.failed_blocks[blk]}")
    return "\n".join(lines)


def format_ndef_records_text(
    version: NtagVersion,
    card: CardInfo,
    records: Sequence[NdefRecord],
) -> str:
    """Formatuje zdekodowane rekordy NDEF i parametry pamięci użytkownika NTAG."""
    lines = [
        f"Tag: {version.name} | UID={card.uid_hex} | Pamięć użytkownika={version.user_pages * 4} B ({version.user_pages} stron)",
    ]
    if not records:
        lines.append("Brak rekordów NDEF w pamięci użytkownika (brak TLV 0x03).")
        return "\n".join(lines)
    for idx, rec in enumerate(records, start=1):
        lines.append(f"[{idx}] {rec.summary} (TNF={rec.tnf}, typ={rec.record_type}, {len(rec.payload)} B)")
    return "\n".join(lines)


def format_apdu_exchange_entry(apdu: bytes, resp: ApduResponse) -> str:
    """Formatuje pojedynczą wymianę APDU (wysłane bajty, odpowiedź HEX|ASCII i SW1 SW2)."""
    data_str = format_hex_ascii(resp.data) if resp.data else "<brak danych>"
    status_label = "OK" if resp.is_ok else "status nie-9000"
    return (
        f">> {apdu.hex(' ').upper()}\n"
        f"<< {data_str}\n"
        f"   SW={resp.sw1:02X} {resp.sw2:02X} ({status_label})"
    )


def format_em4100_conversion_text(card: EM4100Card) -> str:
    """Formatuje wszystkie reprezentacje identyfikatora EM4100 (40-bit HEX, DEC10, DEC8/WG26)."""
    return (
        f"40-bit HEX: {card.hex_id} ({card.hex_spaced}) | "
        f"DEC 10-cyfr.: {card.decimal_10} | "
        f"DEC 8-cyfr. (WG26): {card.wiegand_26} | "
        f"FC={card.wiegand_fc:03d}, CN={card.wiegand_cn:05d}"
    )


def _find_asset_path(filename: str) -> Path | None:
    """Lokalizuje plik zasobu w katalogu `assets/` (w trybie deweloperskim lub PyInstaller)."""
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(str(meipass)) / "assets" / filename)
    candidates.append(Path(__file__).resolve().parent.parent.parent / "assets" / filename)
    for path in candidates:
        if path.is_file():
            return path
    return None


def format_mifare_text_capacity(total_blocks: int, start_block: int, text: str) -> tuple[int, int, int, int]:
    """Zwraca (użyte_bajty, maks_bajty, użyte_bloki, maks_bloki) dla zapisu tekstu w Mifare."""
    blocks = writable_data_blocks(total_blocks, start_block=start_block)
    max_blocks = len(blocks)
    max_bytes = max_blocks * MIFARE_BLOCK_SIZE
    used_bytes = len(text.encode("utf-8"))
    used_blocks = (used_bytes + MIFARE_BLOCK_SIZE - 1) // MIFARE_BLOCK_SIZE if used_bytes > 0 else 0
    return used_bytes, max_bytes, used_blocks, max_blocks


def block_hex_to_utf8_text(hex_value: str) -> str:
    """Konwertuje 16-bajtowy zapis HEX pojedynczego bloku na tekst UTF-8 (ucina końcowe zera)."""
    cleaned = hex_value.strip().replace(" ", "").replace(":", "").replace("-", "")
    if len(cleaned) != MIFARE_BLOCK_SIZE * 2:
        raise ValueError("Blok HEX musi mieć dokładnie 32 znaki.")
    raw = bytes.fromhex(cleaned).rstrip(b"\x00")
    return raw.decode("utf-8", errors="replace")


def utf8_text_to_block_hex(text: str) -> str:
    """Konwertuje tekst UTF-8 (maks. 16 B) na 16-bajtowy ciąg HEX rozdzielony spacjami."""
    raw = text.encode("utf-8")
    if len(raw) > MIFARE_BLOCK_SIZE:
        raise ValueError(f"Tekst ({len(raw)} B) przekracza rozmiar jednego bloku (16 B).")
    return raw.ljust(MIFARE_BLOCK_SIZE, b"\x00").hex(" ").upper()


def format_mifare_text_block_preview(
    dump: MifareDump,
    text: str,
    start_block: int = 1,
    *,
    clear_remaining: bool = False,
) -> str:
    """Buduje podgląd podziału tekstu UTF-8 na 16-bajtowe bloki z zaznaczeniem pominiętych trailerów."""
    encoded_map = encode_text_to_blocks(
        text,
        dump.total_blocks,
        start_block=start_block,
        clear_remaining=clear_remaining,
    )
    if not encoded_map:
        return "<brak bloków do zapisu>"
    last_written = max(encoded_map)
    lines: list[str] = []
    for blk in range(start_block, last_written + 1):
        if blk == 0:
            lines.append("Blok 000: [UID / Producent — pominięty]")
        elif dump.is_trailer_block(blk):
            lines.append(f"Blok {blk:03d}: [TRAILER — pominięty]")
        elif blk in encoded_map:
            lines.append(f"Blok {blk:03d}: {format_hex_ascii(encoded_map[blk])}")
    return "\n".join(lines)


def format_audit_status_banner(report: CardAuditReport | None) -> tuple[str, str, str]:
    """Zwraca krotkę (poziom_ryzyka, wynik_pkt, cel_migracji) dla paska statusu audytu."""
    if report is None:
        return ("—", "—", "—")
    return (
        report.risk_level,
        f"{report.risk_score} / 100 pkt",
        report.migration_target,
    )


class NFCPlusApp(ctk.CTk):
    """Główne okno aplikacji desktopowej NFCplus (CustomTkinter)."""

    def __init__(self) -> None:
        _enable_windows_dpi_awareness()
        self._config: dict[str, Any] = load_app_config()
        self._theme: str = _normalize_theme(self._config.get("theme", "dark"))
        ctk.set_default_color_theme("blue")
        ctk.set_appearance_mode("Dark" if self._theme == "dark" else "Light")

        super().__init__()
        self.title("NFCplus — Czytelny klient czytnika NFC / Mifare")
        self.geometry("1120x780")
        self.minsize(920, 640)
        self._mono_font = _select_monospace_font(self)
        self._app_icon_img: tk.PhotoImage | None = None
        self._apply_window_icon()

        self._devices: list[DeviceInfo] = []
        self._device_labels: list[str] = []
        self._transport: HIDTransport | None = None
        self._reader: NFCReader | None = None
        self._last_mifare_dump: MifareDump | None = None
        self._last_mifare_card: CardInfo | None = None
        self._last_mifare_auth: dict[int, tuple[bool, bool]] | None = None
        self._last_mifare_header: str = ""
        self._last_mifare_missing: set[int] = set()
        self._last_ntag_dump: NtagDump | None = None
        self._last_audit_report: CardAuditReport | None = None
        self._busy = False

        self._build_ui()
        self._refresh_devices()
        self._draw_sector_grid()
        if self.auto_connect_var.get() and self._devices:
            self.after(100, self._try_auto_connect)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Budowa interfejsu
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self._bold_font = ctk.CTkFont(size=12, weight="bold")
        self._title_font = ctk.CTkFont(size=13, weight="bold")

        # Pasek połączenia
        conn_frame = ctk.CTkFrame(self)
        conn_frame.pack(fill="x", padx=12, pady=(12, 6))
        conn_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(conn_frame, text="Urządzenie:").grid(row=0, column=0, sticky="w", padx=(10, 6), pady=(10, 4))
        self.device_var = tk.StringVar(value="")
        self.device_combo = ctk.CTkComboBox(conn_frame, variable=self.device_var, values=[], state="readonly")
        self.device_combo.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=(10, 4))

        self.btn_refresh = ctk.CTkButton(conn_frame, text="Odśwież", width=95, command=self._refresh_devices)
        self.btn_refresh.grid(row=0, column=2, padx=4, pady=(10, 4))

        self.btn_connect = ctk.CTkButton(conn_frame, text="Połącz", width=95, command=self._toggle_connect)
        self.btn_connect.grid(row=0, column=3, padx=4, pady=(10, 4))

        self.btn_beep = ctk.CTkButton(
            conn_frame,
            text="Sygnał (Beep)",
            width=120,
            command=self._do_beep,
            state="disabled",
        )
        self.btn_beep.grid(row=0, column=4, padx=(4, 10), pady=(10, 4))

        self.conn_info_var = tk.StringVar(value="Status: Niepołączony")
        ctk.CTkLabel(conn_frame, textvariable=self.conn_info_var, anchor="w").grid(
            row=1, column=0, columnspan=5, sticky="ew", padx=10, pady=(2, 2)
        )

        id_bar = ctk.CTkFrame(conn_frame, fg_color="transparent")
        id_bar.grid(row=2, column=0, columnspan=5, sticky="ew", padx=10, pady=(2, 8))

        ctk.CTkLabel(id_bar, text="Device:").pack(side="left")
        self.device_fw_var = tk.StringVar(value="—")
        ctk.CTkLabel(id_bar, textvariable=self.device_fw_var, font=(self._mono_font, 13, "bold")).pack(
            side="left", padx=(4, 18)
        )
        ctk.CTkLabel(id_bar, text="SN:").pack(side="left")
        self.device_sn_var = tk.StringVar(value="—")
        ctk.CTkLabel(id_bar, textvariable=self.device_sn_var, font=(self._mono_font, 13, "bold")).pack(
            side="left", padx=(4, 18)
        )

        self.theme_var = tk.StringVar(value="Ciemna" if self._theme == "dark" else "Jasna")
        theme_box = ctk.CTkFrame(id_bar, fg_color="transparent")
        theme_box.pack(side="right")
        ctk.CTkLabel(theme_box, text="Skórka:").pack(side="left", padx=(0, 6))
        self.theme_seg = ctk.CTkSegmentedButton(
            theme_box,
            values=["Ciemna", "Jasna"],
            variable=self.theme_var,
            command=self._on_theme_changed,
        )
        self.theme_seg.pack(side="left")

        self.auto_connect_var = tk.BooleanVar(value=bool(self._config.get("auto_connect", True)))
        ctk.CTkCheckBox(
            id_bar,
            text="Auto-łącz przy starcie",
            variable=self.auto_connect_var,
            command=self._on_toggle_auto_connect,
        ).pack(side="right", padx=(0, 18))

        # Zakładki
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=4)

        self._build_scan_tab()
        self._build_mifare_tab()
        self._build_ntag_tab()
        self._build_dump_tab()
        self._build_lf_tab()
        self._build_apdu_tab()
        self._build_audit_tab()

        # Pasek statusu i postępu
        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=12, pady=(4, 10))
        self.status_var = tk.StringVar(value="Gotowy.")
        ctk.CTkLabel(bottom, textvariable=self.status_var, anchor="w").pack(side="left", padx=10, pady=6)
        self.progress = ctk.CTkProgressBar(bottom, width=260)
        self.progress.set(0.0)
        self.progress.pack(side="right", padx=10, pady=8)

    def _build_scan_tab(self) -> None:
        tab = self.tabs.add("1. Skanuj kartę")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 10))
        ctk.CTkButton(top, text="Skanuj kartę (UID / Typ)", command=self._do_scan).pack(side="left")
        ctk.CTkButton(
            top,
            text="Skanuj wszystko (13.56 MHz + 125 kHz / HID)",
            command=self._do_scan_all,
        ).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Kopiuj UID", width=110, command=self._copy_uid).pack(side="left")

        card_box = ctk.CTkFrame(tab)
        card_box.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(card_box, text="Dane wykrytej karty ISO 14443-A", font=self._title_font).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(8, 4)
        )

        self.uid_var = tk.StringVar(value="—")
        self.atqa_var = tk.StringVar(value="—")
        self.sak_var = tk.StringVar(value="—")
        self.card_type_var = tk.StringVar(value="—")

        for r_idx, (label, var) in enumerate(
            (
                ("UID:", self.uid_var),
                ("ATQA:", self.atqa_var),
                ("SAK:", self.sak_var),
                ("Rozpoznany typ:", self.card_type_var),
            ),
            start=1,
        ):
            ctk.CTkLabel(card_box, text=label, width=150, anchor="w").grid(
                row=r_idx, column=0, sticky="w", padx=10, pady=3
            )
            ctk.CTkLabel(card_box, textvariable=var, font=(self._mono_font, 14, "bold")).grid(
                row=r_idx, column=1, sticky="w", padx=(0, 10), pady=3
            )

        info_box = ctk.CTkFrame(tab)
        info_box.pack(fill="both", expand=True)
        ctk.CTkLabel(info_box, text="Dziennik operacji", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.log_text = ctk.CTkTextbox(info_box, font=(self._mono_font, 12), state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_mifare_tab(self) -> None:
        tab = self.tabs.add("2. Mifare Classic")

        left = ctk.CTkScrollableFrame(tab, width=320)
        left.pack(side="left", fill="y", padx=(0, 10), pady=4)

        keys_box = ctk.CTkFrame(left)
        keys_box.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(keys_box, text="Znane klucze (1 na linię, 12 hex)", font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 2)
        )
        self.keys_text = ctk.CTkTextbox(keys_box, height=96, font=(self._mono_font, 12))
        self.keys_text.insert("1.0", "\n".join(k.hex().upper() for k in DEFAULT_MIFARE_KEYS))
        self.keys_text.pack(fill="x", padx=8, pady=(0, 4))
        ctk.CTkButton(
            keys_box,
            text="Wczytaj klucze (.txt / .dic)",
            command=self._do_load_key_file,
        ).pack(fill="x", padx=8, pady=(0, 8))

        opts_box = ctk.CTkFrame(left)
        opts_box.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(opts_box, text="Odczyt i bufor (.dump)", font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 4)
        )
        sec_row = ctk.CTkFrame(opts_box, fg_color="transparent")
        sec_row.pack(fill="x", padx=8, pady=(0, 6))
        ctk.CTkLabel(sec_row, text="Sektory:").pack(side="left")
        self.sectors_var = tk.StringVar(value="16")
        self.sectors_combo = ctk.CTkComboBox(
            sec_row,
            variable=self.sectors_var,
            values=["5", "16", "32", "40"],
            state="readonly",
            width=90,
            command=lambda _val: self._on_sectors_changed(),
        )
        self.sectors_combo.pack(side="left", padx=(8, 0))

        buf_grid = ctk.CTkFrame(opts_box, fg_color="transparent")
        buf_grid.pack(fill="x", padx=8, pady=(0, 8))
        buf_grid.grid_columnconfigure(0, weight=1)
        buf_grid.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(buf_grid, text="Odczytaj sektory", command=self._do_read_mifare).grid(
            row=0, column=0, sticky="ew", padx=(0, 3), pady=2
        )
        ctk.CTkButton(buf_grid, text="Wczytaj .dump do bufora", command=self._do_load_mifare_dump).grid(
            row=0, column=1, sticky="ew", padx=(3, 0), pady=2
        )
        ctk.CTkButton(buf_grid, text="Zapisz .dump", command=self._save_mifare_dump).grid(
            row=1, column=0, sticky="ew", padx=(0, 3), pady=2
        )
        ctk.CTkButton(buf_grid, text="Eksportuj JSON", command=self._do_export_mifare_json).grid(
            row=1, column=1, sticky="ew", padx=(3, 0), pady=2
        )
        ctk.CTkButton(buf_grid, text="Edytuj blok w buforze…", command=self._do_edit_mifare_block).grid(
            row=2, column=0, sticky="ew", padx=(0, 3), pady=(2, 2)
        )
        ctk.CTkButton(buf_grid, text="Zapisz tekst do bufora…", command=self._do_write_text_to_mifare_buffer).grid(
            row=2, column=1, sticky="ew", padx=(3, 0), pady=(2, 2)
        )
        ctk.CTkButton(
            buf_grid,
            text="Analizuj uprawnienia i Value Block",
            command=self._do_analyze_mifare_dump,
        ).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 0))

        write_box = ctk.CTkFrame(left)
        write_box.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(write_box, text="Zapis pełnej karty i formatowanie", font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 4)
        )
        self.write_trailers_var = tk.BooleanVar(value=True)
        self.write_block0_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            write_box,
            text="Zapisz trailery sektorów",
            variable=self.write_trailers_var,
        ).pack(anchor="w", padx=8, pady=2)
        ctk.CTkCheckBox(
            write_box,
            text="Zapisz też Blok 0 (UID — tylko CUID / Gen2)",
            variable=self.write_block0_var,
        ).pack(anchor="w", padx=8, pady=(2, 6))
        wf = ctk.CTkFrame(write_box, fg_color="transparent")
        wf.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(wf, text="Zapisz zrzut na kartę", command=self._do_write_mifare_dump).pack(
            side="left", expand=True, fill="x", padx=(0, 3)
        )
        ctk.CTkButton(wf, text="Formatuj kartę", command=self._do_format_mifare).pack(
            side="left", expand=True, fill="x", padx=(3, 0)
        )

        blk_box = ctk.CTkFrame(left)
        blk_box.pack(fill="x")
        ctk.CTkLabel(blk_box, text="Pojedynczy blok (Odczyt / Zapis)", font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 4)
        )
        self.blk_num_var = tk.StringVar(value="4")
        self.blk_key_var = tk.StringVar(value="FFFFFFFFFFFF")
        self.blk_key_type_var = tk.StringVar(value="A")
        self.blk_data_var = tk.StringVar(value="00000000000000000000000000000000")

        btop = ctk.CTkFrame(blk_box, fg_color="transparent")
        btop.pack(fill="x", padx=8, pady=(0, 4))
        ctk.CTkLabel(btop, text="Blok:").pack(side="left")
        ctk.CTkEntry(btop, textvariable=self.blk_num_var, width=52).pack(side="left", padx=(4, 8))
        ctk.CTkLabel(btop, text="Klucz:").pack(side="left")
        ctk.CTkEntry(btop, textvariable=self.blk_key_var, width=120, font=(self._mono_font, 11)).pack(
            side="left", padx=(4, 4)
        )
        ctk.CTkComboBox(btop, variable=self.blk_key_type_var, values=["A", "B"], state="readonly", width=58).pack(
            side="left"
        )
        ctk.CTkLabel(blk_box, text="Dane bloku (32 hex):").pack(anchor="w", padx=8)
        ctk.CTkEntry(blk_box, textvariable=self.blk_data_var, font=(self._mono_font, 11)).pack(
            fill="x", padx=8, pady=(2, 6)
        )
        bf = ctk.CTkFrame(blk_box, fg_color="transparent")
        bf.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(bf, text="Odczytaj blok", command=self._do_read_single_block).pack(
            side="left", expand=True, fill="x", padx=(0, 3)
        )
        ctk.CTkButton(bf, text="Zapisz blok", command=self._do_write_single_block).pack(
            side="left", expand=True, fill="x", padx=(3, 0)
        )

        right_col = ctk.CTkFrame(tab, fg_color="transparent")
        right_col.pack(side="left", fill="both", expand=True, pady=4)

        grid_box = ctk.CTkFrame(right_col)
        grid_box.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(grid_box, text="Status kluczy sektorów (A / B)", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.sector_canvas = tk.Canvas(grid_box, height=74, highlightthickness=0)
        self.sector_canvas.pack(fill="x", padx=10)
        self.sector_canvas.bind("<Configure>", lambda _e: self._draw_sector_grid())

        legend = ctk.CTkFrame(grid_box, fg_color="transparent")
        legend.pack(fill="x", padx=10, pady=(4, 6))
        self._legend_swatches: list[tk.Canvas] = []
        for idx, label in enumerate(("Autoryzacja OK", "Brak klucza / błąd", "Niesprawdzono")):
            swatch = tk.Canvas(legend, width=12, height=12, highlightthickness=1, highlightbackground="#888888")
            swatch.pack(side="left", padx=(0, 4))
            self._legend_swatches.append(swatch)
            ctk.CTkLabel(legend, text=label).pack(side="left", padx=(0, 14 if idx < 2 else 0))

        right = ctk.CTkFrame(right_col)
        right.pack(fill="both", expand=True)
        ctk.CTkLabel(right, text="Podgląd sektorów i bloków (HEX | ASCII)", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.mifare_text = ctk.CTkTextbox(right, font=(self._mono_font, 12), state="disabled", wrap="none")
        self.mifare_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_ntag_tab(self) -> None:
        tab = self.tabs.add("3. NTAG / Ultralight")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 6))
        ctk.CTkButton(top, text="Info o tagu (Get Version)", command=self._do_ntag_version_info).pack(side="left")
        ctk.CTkButton(top, text="Odczytaj cały tag NTAG", command=self._do_read_ntag).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Zapisz zrzut NTAG (.dump)", command=self._save_ntag_dump).pack(side="left")

        pwd_row = ctk.CTkFrame(tab)
        pwd_row.pack(fill="x", pady=(0, 6))
        self.ntag_use_pwd_var = tk.BooleanVar(value=False)
        self.ntag_pwd_var = tk.StringVar(value="FFFFFFFF")
        ctk.CTkCheckBox(pwd_row, text="Użyj hasła (PWD_AUTH)", variable=self.ntag_use_pwd_var).pack(
            side="left", padx=(10, 8), pady=6
        )
        ctk.CTkLabel(pwd_row, text="Hasło (8 hex):").pack(side="left")
        ctk.CTkEntry(pwd_row, textvariable=self.ntag_pwd_var, width=120, font=(self._mono_font, 12)).pack(
            side="left", padx=(6, 16)
        )
        self.ntag_info_var = tk.StringVar(value="Wersja NTAG: —")
        ctk.CTkLabel(pwd_row, textvariable=self.ntag_info_var, font=self._bold_font).pack(
            side="left", padx=6
        )

        ndef_box = ctk.CTkFrame(tab)
        ndef_box.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(ndef_box, text="Zapisz rekord NDEF (od strony 4)", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 4)
        )
        ndef_row = ctk.CTkFrame(ndef_box, fg_color="transparent")
        ndef_row.pack(fill="x", padx=10, pady=(0, 8))
        self.ndef_kind_var = tk.StringVar(value="URL")
        ctk.CTkSegmentedButton(ndef_row, values=["URL", "Tekst"], variable=self.ndef_kind_var, width=130).pack(
            side="left"
        )
        self.ndef_value_var = tk.StringVar(value="https://example.com")
        ctk.CTkEntry(ndef_row, textvariable=self.ndef_value_var, placeholder_text="Treść URL lub tekstu").pack(
            side="left", fill="x", expand=True, padx=8
        )
        ctk.CTkLabel(ndef_row, text="Język:").pack(side="left")
        self.ndef_lang_var = tk.StringVar(value="pl")
        ctk.CTkEntry(ndef_row, textvariable=self.ndef_lang_var, width=50).pack(side="left", padx=(4, 8))
        ctk.CTkButton(ndef_row, text="Zapisz NDEF na tag", command=self._do_write_ndef).pack(side="left")

        wr_box = ctk.CTkFrame(tab)
        wr_box.pack(fill="x", pady=(0, 6))
        self.ntag_page_var = tk.StringVar(value="4")
        self.ntag_data_var = tk.StringVar(value="00000000")
        ctk.CTkLabel(wr_box, text="Zapis pojedynczej strony NTAG — Strona:").pack(side="left", padx=(10, 4), pady=6)
        ctk.CTkEntry(wr_box, textvariable=self.ntag_page_var, width=60).pack(side="left", padx=(0, 12))
        ctk.CTkLabel(wr_box, text="Dane (8 hex):").pack(side="left")
        ctk.CTkEntry(wr_box, textvariable=self.ntag_data_var, width=130, font=(self._mono_font, 12)).pack(
            side="left", padx=(6, 12)
        )
        ctk.CTkButton(wr_box, text="Zapisz stronę", command=self._do_write_ntag_page).pack(side="left")

        split = ctk.CTkFrame(tab, fg_color="transparent")
        split.pack(fill="both", expand=True)
        ndef_view = ctk.CTkFrame(split)
        ndef_view.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(ndef_view, text="Zdekodowane rekordy NDEF", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.ndef_text = ctk.CTkTextbox(ndef_view, height=90, font=(self._mono_font, 12), state="disabled")
        self.ndef_text.pack(fill="x", padx=10, pady=(0, 8))

        pages_view = ctk.CTkFrame(split)
        pages_view.pack(fill="both", expand=True)
        ctk.CTkLabel(pages_view, text="Zawartość stron (HEX | ASCII)", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.ntag_text = ctk.CTkTextbox(pages_view, font=(self._mono_font, 12), state="disabled", wrap="none")
        self.ntag_text.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    def _build_dump_tab(self) -> None:
        tab = self.tabs.add("4. Zrzuty (.dump)")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 6))
        ctk.CTkButton(top, text="Otwórz plik .dump / .bin", command=self._open_dump_file).pack(side="left")
        ctk.CTkButton(top, text="Otwórz lewy zrzut…", command=lambda: self._load_compare_side("left")).pack(
            side="left", padx=(12, 4)
        )
        ctk.CTkButton(top, text="Otwórz prawy zrzut…", command=lambda: self._load_compare_side("right")).pack(
            side="left", padx=4
        )
        ctk.CTkButton(top, text="Porównaj dwa zrzuty…", command=self._compare_dump_files).pack(side="left", padx=8)

        self.dump_left_path: Path | None = None
        self.dump_right_path: Path | None = None
        self.diff_summary_var = tk.StringVar(value="Wybierz plik do podglądu lub dwa pliki do porównania obok siebie.")
        ctk.CTkLabel(tab, textvariable=self.diff_summary_var, anchor="w").pack(fill="x", padx=4, pady=(0, 6))

        panes = ctk.CTkFrame(tab, fg_color="transparent")
        panes.pack(fill="both", expand=True)
        panes.grid_columnconfigure(0, weight=1)
        panes.grid_columnconfigure(1, weight=1)
        panes.grid_rowconfigure(0, weight=3)
        panes.grid_rowconfigure(1, weight=2)

        left_box = ctk.CTkFrame(panes)
        left_box.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=(0, 6))
        self.dump_left_title = tk.StringVar(value="Lewy bufor / plik")
        ctk.CTkLabel(left_box, textvariable=self.dump_left_title, font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 2)
        )
        self.dump_left_text = ctk.CTkTextbox(left_box, font=(self._mono_font, 11), state="disabled", wrap="none")
        self.dump_left_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        right_box = ctk.CTkFrame(panes)
        right_box.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=(0, 6))
        self.dump_right_title = tk.StringVar(value="Prawy bufor / plik")
        ctk.CTkLabel(right_box, textvariable=self.dump_right_title, font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 2)
        )
        self.dump_right_text = ctk.CTkTextbox(right_box, font=(self._mono_font, 11), state="disabled", wrap="none")
        self.dump_right_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        diff_box = ctk.CTkFrame(panes)
        diff_box.grid(row=1, column=0, columnspan=2, sticky="nsew")
        ctk.CTkLabel(diff_box, text="Różnice bloków / stron", font=self._bold_font).pack(
            anchor="w", padx=8, pady=(6, 2)
        )
        self.dump_text = ctk.CTkTextbox(diff_box, font=(self._mono_font, 12), state="disabled", wrap="none")
        self.dump_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _build_lf_tab(self) -> None:
        tab = self.tabs.add("5. 125 kHz / HID Prox")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 8))
        ctk.CTkButton(top, text="Odczytaj 125 kHz (EM4100)", command=self._do_read_em4100).pack(side="left")
        ctk.CTkButton(top, text="Odczytaj HID Prox", command=self._do_read_hid_prox).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Skanuj oba (125 kHz + HID)", command=self._do_scan_lf_both).pack(side="left")
        ctk.CTkLabel(top, text="Częstotliwość (Hz):").pack(side="left", padx=(16, 4))
        self.lf_freq_var = tk.StringVar(value=str(DEFAULT_LF_FREQ_HZ))
        ctk.CTkEntry(top, textvariable=self.lf_freq_var, width=90).pack(side="left")

        cards_row = ctk.CTkFrame(tab, fg_color="transparent")
        cards_row.pack(fill="x", pady=(0, 8))
        cards_row.grid_columnconfigure(0, weight=1)
        cards_row.grid_columnconfigure(1, weight=1)

        em_box = ctk.CTkFrame(cards_row)
        em_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ctk.CTkLabel(em_box, text="Karta 125 kHz (EM4100 / T5577)", font=self._bold_font).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(8, 4)
        )
        self.em_hex_var = tk.StringVar(value="—")
        self.em_dec_var = tk.StringVar(value="—")
        self.em_wg_var = tk.StringVar(value="—")
        for r_idx, (label, var) in enumerate(
            (
                ("ID (HEX 40-bit):", self.em_hex_var),
                ("ID (DEC 10-cyfr.):", self.em_dec_var),
                ("Wiegand 26:", self.em_wg_var),
            ),
            start=1,
        ):
            ctk.CTkLabel(em_box, text=label, width=140, anchor="w").grid(
                row=r_idx, column=0, sticky="w", padx=10, pady=2
            )
            ctk.CTkLabel(em_box, textvariable=var, font=(self._mono_font, 12, "bold")).grid(
                row=r_idx, column=1, sticky="w", padx=(0, 10), pady=2
            )
        ctk.CTkButton(em_box, text="Kopiuj ID EM4100", command=self._copy_em_id).grid(
            row=4, column=0, columnspan=2, sticky="w", padx=10, pady=(6, 10)
        )

        hid_box = ctk.CTkFrame(cards_row)
        hid_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ctk.CTkLabel(hid_box, text="Karta HID Prox (26–37 bitów)", font=self._bold_font).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(8, 4)
        )
        self.hid_format_var = tk.StringVar(value="—")
        self.hid_fc_var = tk.StringVar(value="—")
        self.hid_cn_var = tk.StringVar(value="—")
        self.hid_raw_var = tk.StringVar(value="—")
        self.hid_short_var = tk.StringVar(value="—")
        for r_idx, (label, var) in enumerate(
            (
                ("Format:", self.hid_format_var),
                ("Facility Code (FC):", self.hid_fc_var),
                ("Card Number (CN):", self.hid_cn_var),
                ("Surowe (6 B HEX):", self.hid_raw_var),
                ("Skrót 32-bit:", self.hid_short_var),
            ),
            start=1,
        ):
            ctk.CTkLabel(hid_box, text=label, width=140, anchor="w").grid(
                row=r_idx, column=0, sticky="w", padx=10, pady=2
            )
            ctk.CTkLabel(hid_box, textvariable=var, font=(self._mono_font, 12, "bold")).grid(
                row=r_idx, column=1, sticky="w", padx=(0, 10), pady=2
            )
        ctk.CTkButton(hid_box, text="Kopiuj ID HID", command=self._copy_hid_id).grid(
            row=6, column=0, columnspan=2, sticky="w", padx=10, pady=(6, 10)
        )

        t55_box = ctk.CTkFrame(tab)
        t55_box.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(
            t55_box,
            text="Zapis na czysty transponder T5577 i konwerter formatów 125 kHz",
            font=self._bold_font,
        ).pack(anchor="w", padx=10, pady=(6, 4))

        t55_row = ctk.CTkFrame(t55_box, fg_color="transparent")
        t55_row.pack(fill="x", padx=10, pady=(0, 6))
        self.t55_kind_var = tk.StringVar(value="EM4100 (HEX/DEC10/WG26)")
        ctk.CTkComboBox(
            t55_row,
            variable=self.t55_kind_var,
            values=["EM4100 (HEX/DEC10/WG26)", "HID Prox (6 B HEX)"],
            state="readonly",
            width=210,
        ).pack(side="left")
        self.t55_input_var = tk.StringVar(value="")
        ctk.CTkEntry(
            t55_row,
            textvariable=self.t55_input_var,
            placeholder_text="np. 4D0088BC89 lub 0008961161 albo 13648265",
            font=(self._mono_font, 12),
        ).pack(side="left", fill="x", expand=True, padx=8)
        self.t55_verify_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(t55_row, text="Weryfikuj odczytem", variable=self.t55_verify_var).pack(side="left", padx=(0, 8))
        ctk.CTkButton(t55_row, text="Zapisz na T5577", width=130, command=self._do_write_t5577).pack(side="left")

        conv_row = ctk.CTkFrame(t55_box, fg_color="transparent")
        conv_row.pack(fill="x", padx=10, pady=(0, 6))
        ctk.CTkLabel(conv_row, text="Konwerter EM4100:").pack(side="left")
        self.conv_input_var = tk.StringVar(value="4D0088BC89")
        ctk.CTkEntry(conv_row, textvariable=self.conv_input_var, width=180, font=(self._mono_font, 12)).pack(
            side="left", padx=6
        )
        self.conv_format_var = tk.StringVar(value="auto")
        ctk.CTkComboBox(
            conv_row,
            variable=self.conv_format_var,
            values=["auto", "hex", "dec10", "dec8", "fc_cn"],
            state="readonly",
            width=95,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(conv_row, text="Przelicz", width=95, command=self._do_convert_em4100).pack(side="left")
        self.conv_result_var = tk.StringVar(value="—")
        ctk.CTkLabel(conv_row, textvariable=self.conv_result_var, font=(self._mono_font, 11)).pack(
            side="left", padx=(10, 0)
        )

        log_box = ctk.CTkFrame(tab)
        log_box.pack(fill="both", expand=True)
        ctk.CTkLabel(log_box, text="Historia odczytów i zapisów 125 kHz / HID Prox", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.lf_log_text = ctk.CTkTextbox(log_box, font=(self._mono_font, 12), state="disabled", wrap="word")
        self.lf_log_text.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    def _build_apdu_tab(self) -> None:
        tab = self.tabs.add("6. CPU / APDU")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 8))
        ctk.CTkButton(top, text="Wykryj kartę ISO 14443-4", command=self._do_detect_apdu_card).pack(side="left")
        ctk.CTkLabel(top, text="Szablon APDU:").pack(side="left", padx=(14, 6))
        self.apdu_template_var = tk.StringVar(value="SELECT MF (3F00)")
        ctk.CTkComboBox(
            top,
            variable=self.apdu_template_var,
            values=list(APDU_TEMPLATES.keys()),
            state="readonly",
            width=220,
            command=self._on_apdu_template_selected,
        ).pack(side="left")
        self.apdu_init_rf_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(top, text="Inicjuj RF przed komendą", variable=self.apdu_init_rf_var).pack(
            side="left", padx=(12, 0)
        )

        cmd_row = ctk.CTkFrame(tab)
        cmd_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(cmd_row, text="APDU (HEX):").pack(side="left", padx=(10, 6), pady=8)
        self.apdu_cmd_var = tk.StringVar(value=APDU_TEMPLATES["SELECT MF (3F00)"])
        ctk.CTkEntry(cmd_row, textvariable=self.apdu_cmd_var, font=(self._mono_font, 13)).pack(
            side="left", fill="x", expand=True, padx=(0, 8), pady=8
        )
        ctk.CTkButton(cmd_row, text="Wyślij APDU", width=130, command=self._do_send_apdu).pack(
            side="left", padx=(0, 10), pady=8
        )

        hist_box = ctk.CTkFrame(tab)
        hist_box.pack(fill="both", expand=True)
        ctk.CTkLabel(hist_box, text="Historia wymiany APDU (Dane HEX | ASCII + SW1 SW2)", font=self._bold_font).pack(
            anchor="w", padx=10, pady=(6, 2)
        )
        self.apdu_text = ctk.CTkTextbox(hist_box, font=(self._mono_font, 12), state="disabled", wrap="none")
        self.apdu_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_audit_tab(self) -> None:
        tab = self.tabs.add("7. Audyt Bezpieczeństwa")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 8))
        ctk.CTkButton(
            top,
            text="Audytuj kartę na czytniku (Read-Only)",
            command=self._do_audit_live,
        ).pack(side="left")
        ctk.CTkButton(
            top,
            text="Audytuj plik .dump z dysku…",
            command=self._do_audit_file,
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            top,
            text="Audytuj obecny bufor",
            command=self._do_audit_current_buffer,
        ).pack(side="left")

        self.audit_mask_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            top,
            text="Maskuj wrażliwe dane (klucze) w raporcie",
            variable=self.audit_mask_var,
            command=self._on_audit_mask_changed,
        ).pack(side="right", padx=(12, 0))

        banner = ctk.CTkFrame(tab)
        banner.pack(fill="x", pady=(0, 8))
        self.audit_risk_var = tk.StringVar(value="—")
        self.audit_score_var = tk.StringVar(value="—")
        self.audit_migration_var = tk.StringVar(value="—")

        ctk.CTkLabel(banner, text="Poziom ryzyka:").pack(side="left", padx=(10, 4), pady=8)
        ctk.CTkLabel(banner, textvariable=self.audit_risk_var, font=(self._mono_font, 13, "bold")).pack(
            side="left", padx=(0, 18), pady=8
        )
        ctk.CTkLabel(banner, text="Wynik:").pack(side="left", padx=(0, 4), pady=8)
        ctk.CTkLabel(banner, textvariable=self.audit_score_var, font=(self._mono_font, 13, "bold")).pack(
            side="left", padx=(0, 18), pady=8
        )
        ctk.CTkLabel(banner, text="Rekomendowana migracja:").pack(side="left", padx=(0, 4), pady=8)
        ctk.CTkLabel(banner, textvariable=self.audit_migration_var, font=(self._mono_font, 12, "bold")).pack(
            side="left", padx=(0, 10), pady=8
        )

        export_row = ctk.CTkFrame(tab, fg_color="transparent")
        export_row.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(
            export_row,
            text="Eksportuj HTML (do druku / PDF)",
            command=self._do_export_audit_html,
        ).pack(side="left")
        ctk.CTkButton(
            export_row,
            text="Eksportuj Markdown (.md)",
            command=self._do_export_audit_markdown,
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            export_row,
            text="Eksportuj JSON",
            command=self._do_export_audit_json,
        ).pack(side="left")

        report_box = ctk.CTkFrame(tab)
        report_box.pack(fill="both", expand=True)
        ctk.CTkLabel(
            report_box,
            text="Raport Audytu Bezpieczeństwa Karty RFID/NFC (100% Read-Only)",
            font=self._bold_font,
        ).pack(anchor="w", padx=10, pady=(6, 2))
        self.audit_text = ctk.CTkTextbox(report_box, font=(self._mono_font, 12), state="disabled", wrap="word")
        self.audit_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # ------------------------------------------------------------------
    # Pomocnicze i motyw
    # ------------------------------------------------------------------

    def _apply_window_icon(self) -> None:
        self._apply_toplevel_icon(self, delays_ms=(50, 250, 600))

    def _apply_toplevel_icon(
        self,
        win: tk.Wm,
        *,
        delays_ms: tuple[int, ...] = (50, 250),
    ) -> None:
        png_path = _find_asset_path("nfcplus.png")
        if png_path is not None:
            try:
                if self._app_icon_img is None:
                    self._app_icon_img = tk.PhotoImage(file=str(png_path))
                win.iconphoto(True, self._app_icon_img)
            except (tk.TclError, OSError):
                pass
        if sys.platform == "win32":
            ico_path = _find_asset_path("nfcplus.ico")
            if ico_path is not None:
                ico_str = str(ico_path)
                self._set_win32_icon_safe(win, ico_str)
                for delay in delays_ms:
                    self.after(delay, lambda target=win, p=ico_str: self._set_win32_icon_safe(target, p))

    @staticmethod
    def _set_win32_icon_safe(win: tk.Wm, ico_str: str) -> None:
        try:
            win.wm_iconbitmap(ico_str)
            win.iconbitmap(default=ico_str)
        except (tk.TclError, OSError):
            pass

    def _is_dark(self) -> bool:
        return self._theme == "dark"

    def _on_theme_changed(self, selected: str) -> None:
        self._theme = "light" if selected == "Jasna" else "dark"
        ctk.set_appearance_mode("Dark" if self._theme == "dark" else "Light")
        self._config["theme"] = self._theme
        save_app_config(self._config)
        self._draw_sector_grid()

    def _log(self, msg: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _append_textbox(self, widget: ctk.CTkTextbox, msg: str) -> None:
        widget.configure(state="normal")
        widget.insert("end", msg + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def _set_text(self, widget: ctk.CTkTextbox, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _set_progress(self, done: int, total: int) -> None:
        ratio = min(1.0, max(0.0, done / max(1, total)))
        self.progress.set(ratio)

    def _require_reader(self) -> NFCReader | None:
        if self._reader is None:
            messagebox.showwarning("Brak połączenia", "Najpierw połącz się z czytnikiem USB HID.")
            return None
        return self._reader

    def _run_async(self, label: str, fn: Callable[[], None]) -> None:
        if self._busy:
            messagebox.showinfo("Zajęty", "Trwa poprzednia operacja na czytniku.")
            return
        self._busy = True
        self.status_var.set(label)

        def worker() -> None:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda err=exc: self._handle_error(err))
            finally:
                self.after(0, self._finish_async)

        threading.Thread(target=worker, daemon=True).start()

    def _finish_async(self) -> None:
        self._busy = False
        self.status_var.set("Gotowy.")

    def _handle_error(self, exc: Exception) -> None:
        self._log(f"[BŁĄD] {exc}")
        messagebox.showerror("Błąd", str(exc))

    # ------------------------------------------------------------------
    # Połączenie i skanowanie podstawowe
    # ------------------------------------------------------------------

    def _selected_device_path(self) -> str | None:
        current_label = self.device_var.get()
        if current_label in self._device_labels:
            idx = self._device_labels.index(current_label)
            return self._devices[idx].path
        return self._devices[0].path if self._devices else None

    def _refresh_devices(self) -> None:
        self._devices = enumerate_readers()
        self._device_labels = format_reader_labels(self._devices)
        self.device_combo.configure(values=self._device_labels)
        if self._device_labels:
            self.device_combo.set(self._device_labels[0])
            if self._reader is None:
                self.conn_info_var.set(f"Status: Wykryto urządzeń: {len(self._device_labels)} — kliknij Połącz")
            self._log(f"Wykryto urządzeń: {len(self._device_labels)}")
        else:
            self.device_combo.set("")
            hint = no_readers_hint()
            if self._reader is None:
                self.conn_info_var.set(f"Status: Brak czytnika — {hint}")
            self._log(
                f"Nie wykryto kompatybilnego czytnika USB HID (0416:b030/b031, 2518:6018/6022). {hint}"
            )

    def _on_toggle_auto_connect(self) -> None:
        self._config["auto_connect"] = bool(self.auto_connect_var.get())
        save_app_config(self._config)

    def _apply_connected_reader(
        self,
        dev_info: DeviceInfo,
        transport: HIDTransport,
        reader: NFCReader,
        info: dict[str, str],
    ) -> None:
        fw = info.get("firmware") or "—"
        sn = info.get("model") or "—"
        self._transport = transport
        self._reader = reader
        self.btn_connect.configure(text="Rozłącz")
        self.btn_beep.configure(state="normal")
        self.device_fw_var.set(fw)
        self.device_sn_var.set(sn)
        self.conn_info_var.set(
            f"Status: Połączono | {dev_info.vid_pid} ({dev_info.path}) | {info['display_name']}"
        )
        self._log(f"Połączono z: {info['display_name']} (Device: {fw}, SN: {sn})")

    def _try_auto_connect(self) -> None:
        if self._reader is not None or self._busy or not self._devices or not self.auto_connect_var.get():
            return
        path = self._devices[0].path
        self.conn_info_var.set(f"Status: Auto-łączenie z {self._devices[0].vid_pid}...")

        def worker() -> None:
            transport: HIDTransport | None = None
            try:
                dev_info, transport = open_reader(path=path)
                reader = NFCReader(transport)
                info = reader.get_device_info()
            except (TransportError, ProtocolError, TimeoutError, OSError) as exc:
                err_msg = str(exc)
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:  # noqa: BLE001
                        pass

                def on_fail(msg: str = err_msg) -> None:
                    if self._reader is None:
                        self.conn_info_var.set(f"Status: Auto-łączenie nieudane — kliknij Połącz ({msg})")
                    self._log(f"[Auto-łącz] Nie udało się połączyć automatycznie: {msg}")

                self.after(0, on_fail)
                return

            def finish() -> None:
                if self._reader is not None:
                    transport.close()
                    return
                self._apply_connected_reader(dev_info, transport, reader, info)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _toggle_connect(self) -> None:
        if self._reader is not None:
            self._disconnect()
            return
        path = self._selected_device_path()
        try:
            dev_info, transport = open_reader(path=path)
            reader = NFCReader(transport)
            info = reader.get_device_info()
        except (TransportError, ProtocolError, TimeoutError) as exc:
            messagebox.showerror("Błąd połączenia", str(exc))
            return
        self._apply_connected_reader(dev_info, transport, reader, info)

    def _disconnect(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            finally:
                self._transport = None
                self._reader = None
        self.btn_connect.configure(text="Połącz")
        self.btn_beep.configure(state="disabled")
        self.device_fw_var.set("—")
        self.device_sn_var.set("—")
        self.conn_info_var.set("Status: Niepołączony")
        self._log("Rozłączono czytnik.")

    def _do_beep(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        self._run_async("Wysyłanie sygnału...", lambda: reader.beep(60))

    def _apply_card_vars(self, card: CardInfo | None) -> None:
        if card is None:
            self.uid_var.set("—")
            self.atqa_var.set("—")
            self.sak_var.set("—")
            self.card_type_var.set("—")
            return
        self.uid_var.set(card.uid_hex)
        self.atqa_var.set(card.atqa_hex)
        self.sak_var.set(f"{card.sak:02X}")
        self.card_type_var.set(card.card_type)

    def _do_scan(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return

        def task() -> None:
            card = reader.scan_card(init_rf=True)
            if card is None:
                self.after(0, lambda: self._log("Nie wykryto karty na czytniku."))
                self.after(0, lambda: messagebox.showinfo("Brak karty", "Połóż kartę na czytniku i spróbuj ponownie."))
                return
            reader.beep(40)

            def update(found: CardInfo = card) -> None:
                self._apply_card_vars(found)
                self._log(
                    f"Wykryto kartę: UID={found.uid_hex}, ATQA={found.atqa_hex}, "
                    f"SAK={found.sak:02X} ({found.card_type})"
                )

            self.after(0, update)

        self._run_async("Skanowanie karty...", task)

    def _do_scan_all(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            freq = self._parse_lf_freq()
        except ValueError:
            freq = DEFAULT_LF_FREQ_HZ

        def task() -> None:
            iso_card = reader.scan_card(init_rf=True)
            em_card = reader.read_em4100(freq_hz=freq, init_rf=True)
            hid_card = reader.read_hid_prox(init_rf=True)

            if iso_card is None and em_card is None and hid_card is None:
                self.after(0, lambda: self._log("Brak karty na czytniku (13.56 MHz / 125 kHz / HID)."))
                self.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Brak karty", "Nie wykryto karty 13.56 MHz, 125 kHz (EM4100) ani HID Prox."
                    ),
                )
                return

            reader.beep(40)

            def update(
                c_iso: CardInfo | None = iso_card,
                c_em: EM4100Card | None = em_card,
                c_hid: HIDProxCard | None = hid_card,
            ) -> None:
                parts: list[str] = []
                self._apply_card_vars(c_iso)
                if c_iso is not None:
                    parts.append(f"13.56 MHz: UID={c_iso.uid_hex} ({c_iso.card_type})")
                if c_em is not None:
                    self._apply_em4100_result(c_em)
                    parts.append(f"125 kHz EM4100: {c_em.hex_id} (DEC={c_em.decimal_10})")
                if c_hid is not None:
                    self._apply_hid_result(c_hid)
                    parts.append(
                        f"HID Prox: {c_hid.format_name} FC={c_hid.facility_code} CN={c_hid.card_number}"
                    )
                self._log("[Skanowanie dualne] " + " | ".join(parts))

            self.after(0, update)

        self._run_async("Skanowanie 13.56 MHz + 125 kHz / HID...", task)

    def _copy_uid(self) -> None:
        uid = self.uid_var.get()
        if uid and uid != "—":
            self.clipboard_clear()
            self.clipboard_append(uid.replace(" ", ""))
            self.status_var.set("Skopiowano UID do schowka.")

    # ------------------------------------------------------------------
    # Mifare Classic
    # ------------------------------------------------------------------

    def _parse_key_list(self) -> list[bytes]:
        keys: list[bytes] = []
        for raw_line in self.keys_text.get("1.0", "end").splitlines():
            cleaned = raw_line.strip().replace(" ", "").replace(":", "").replace("-", "")
            if not cleaned:
                continue
            key = bytes.fromhex(cleaned)
            if len(key) != 6:
                raise ValueError(f"Klucz '{raw_line.strip()}' nie ma 6 bajtów (12 znaków hex).")
            keys.append(key)
        if not keys:
            raise ValueError("Podaj co najmniej jeden 6-bajtowy klucz.")
        return keys

    def _do_load_key_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Wczytaj klucze Mifare (.txt / .dic)",
            filetypes=[("Key Files", "*.txt *.dic *.keys"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            loaded = parse_key_file(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Błąd pliku kluczy", str(exc))
            return

        try:
            existing = self._parse_key_list()
        except ValueError:
            existing = []

        merged = merge_unique_keys(existing, loaded)
        self.keys_text.delete("1.0", "end")
        self.keys_text.insert("1.0", "\n".join(k.hex().upper() for k in merged))
        self._log(f"Wczytano {len(loaded)} kluczy z {path} (łącznie unikalnych: {len(merged)}).")

    def _on_sectors_changed(self) -> None:
        if self._last_mifare_dump is None:
            self._last_mifare_auth = None
        self._draw_sector_grid()

    def _draw_sector_grid(self) -> None:
        if not hasattr(self, "sector_canvas"):
            return
        canvas = self.sector_canvas
        dark = self._is_dark()
        pal = sector_canvas_palette(dark)
        canvas.configure(background=pal["bg"])

        for swatch, color in zip(
            getattr(self, "_legend_swatches", ()),
            (SECTOR_COLOR_OK, SECTOR_COLOR_FAIL, SECTOR_COLOR_UNKNOWN_DARK if dark else SECTOR_COLOR_UNKNOWN),
        ):
            swatch.configure(background=pal["bg"])
            swatch.delete("all")
            swatch.create_rectangle(1, 1, 11, 11, fill=color, outline="")

        sector_count = (
            self._last_mifare_dump.sector_count
            if self._last_mifare_dump is not None
            else int(self.sectors_var.get())
        )
        cols = 10 if sector_count > 32 else (5 if sector_count <= 5 else 8)
        rows = max(1, (sector_count + cols - 1) // cols)
        desired_h = max(44, rows * 32 + 8)
        if int(float(canvas.cget("height"))) != desired_h:
            canvas.configure(height=desired_h)

        canvas.delete("all")
        width = max(canvas.winfo_width(), 440)
        pad_x = 6
        pad_y = 4
        cell_w = max(42, (width - pad_x * 2) // cols)
        cell_h = 28

        for idx, (sector, color_a, color_b) in enumerate(
            sector_indicator_colors(sector_count, self._last_mifare_auth, dark=dark)
        ):
            r = idx // cols
            c = idx % cols
            x0 = pad_x + c * cell_w
            y0 = pad_y + r * (cell_h + 4)
            box_w = min(cell_w - 4, 72)
            canvas.create_rectangle(x0, y0, x0 + box_w, y0 + cell_h, fill=pal["cell_bg"], outline=pal["cell_border"])
            canvas.create_text(
                x0 + 13,
                y0 + cell_h // 2,
                text=f"{sector:02d}",
                font=(self._mono_font, 8, "bold"),
                fill=pal["text"],
            )
            sq = 12
            sy = y0 + (cell_h - sq) // 2
            ax0 = x0 + 25
            bx0 = ax0 + sq + 4
            canvas.create_rectangle(ax0, sy, ax0 + sq, sy + sq, fill=color_a, outline=pal["sq_border"])
            canvas.create_text(
                ax0 + sq // 2, sy + sq // 2, text="A", font=(self._mono_font, 7, "bold"), fill=pal["sq_text"]
            )
            canvas.create_rectangle(bx0, sy, bx0 + sq, sy + sq, fill=color_b, outline=pal["sq_border"])
            canvas.create_text(
                bx0 + sq // 2, sy + sq // 2, text="B", font=(self._mono_font, 7, "bold"), fill=pal["sq_text"]
            )

    def _refresh_mifare_preview(self) -> None:
        if self._last_mifare_dump is None:
            self._set_text(self.mifare_text, "")
            return
        text = format_mifare_dump_text(
            self._last_mifare_dump,
            header=self._last_mifare_header,
            unavailable_blocks=self._last_mifare_missing,
        )
        self._set_text(self.mifare_text, text)

    def _make_mifare_progress_cb(self) -> Callable[[int, int, str], None]:
        def on_progress(done: int, total: int, msg: str) -> None:
            self.after(0, lambda d=done, t=total: self._set_progress(d, t))
            self.after(0, lambda m=msg: self.status_var.set(m))

        return on_progress

    def _do_read_mifare(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            keys = self._parse_key_list()
        except ValueError as exc:
            messagebox.showerror("Błędny klucz", str(exc))
            return

        sectors = int(self.sectors_var.get())
        self._set_progress(0, sectors)
        on_progress = self._make_mifare_progress_cb()

        def task() -> None:
            card, blocks, found = reader.mifare_read_sectors(keys=keys, sectors=sectors, progress_cb=on_progress)
            reader.beep(50)
            auth_map = sector_auth_from_keys(found)
            dump = MifareDump.from_blocks(
                blocks,
                sector_auth=auth_map,
                uid=card.uid_hex,
                atqa=card.atqa_hex,
                sak=f"{card.sak:02X}",
            )
            missing = {idx for idx, blk in enumerate(blocks) if blk is None}
            header = f"Karta: {card.card_type} | UID={card.uid_hex} | ATQA={card.atqa_hex} | SAK={card.sak:02X}\n"

            def update(
                c: CardInfo = card,
                d: MifareDump = dump,
                am: dict[int, tuple[bool, bool]] = auth_map,
                hdr: str = header,
                miss: set[int] = missing,
            ) -> None:
                self._last_mifare_dump = d
                self._last_mifare_card = c
                self._last_mifare_auth = am
                self._last_mifare_header = hdr
                self._last_mifare_missing = miss
                self._apply_card_vars(c)
                self._draw_sector_grid()
                self._refresh_mifare_preview()
                self._log(f"Zakończono odczyt Mifare Classic ({sectors} sektorów).")

            self.after(0, update)

        self._run_async("Odczyt Mifare Classic...", task)

    def _do_load_mifare_dump(self) -> None:
        path = filedialog.askopenfilename(
            title="Wczytaj zrzut Mifare (.dump / .bin)",
            filetypes=[("Dump Files", "*.dump *.bin *.mfd"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            dump = MifareDump.load(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Błąd wczytywania zrzutu", str(exc))
            return

        self._last_mifare_dump = dump
        self._last_mifare_card = None
        self._last_mifare_auth = dict(dump.sector_auth) if dump.sector_auth else None
        self._last_mifare_header = f"Bufor z pliku: {path} ({len(dump.data)} B, {dump.sector_count} sektorów)\n"
        self._last_mifare_missing = set()
        if dump.sector_count in (5, 16, 32, 40):
            self.sectors_var.set(str(dump.sector_count))
        self._draw_sector_grid()
        self._refresh_mifare_preview()
        self._log(f"Wczytano zrzut Mifare do bufora: {path} ({dump.sector_count} sektorów)")

    def _do_export_mifare_json(self) -> None:
        if self._last_mifare_dump is None:
            messagebox.showinfo("Brak bufora", "Najpierw odczytaj kartę lub wczytaj plik .dump do bufora.")
            return
        path = filedialog.asksaveasfilename(
            title="Eksportuj zrzut Mifare do JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not path:
            return
        card = self._last_mifare_card
        self._last_mifare_dump.save_json(
            path,
            uid=card.uid_hex if card else self._last_mifare_dump.uid,
            atqa=card.atqa_hex if card else self._last_mifare_dump.atqa,
            sak=f"{card.sak:02X}" if card else self._last_mifare_dump.sak,
        )
        self._log(f"Wyeksportowano zrzut Mifare do JSON: {path}")

    def _do_analyze_mifare_dump(self) -> None:
        if self._last_mifare_dump is None:
            messagebox.showinfo("Brak bufora", "Najpierw odczytaj kartę lub wczytaj plik .dump do bufora.")
            return
        report = format_mifare_analysis(self._last_mifare_dump)
        win = ctk.CTkToplevel(self)
        win.title("Analiza uprawnień (Access Bits) i Value Block")
        win.geometry("760x520")
        win.transient(self)
        self._apply_toplevel_icon(win)
        txt = ctk.CTkTextbox(win, font=(self._mono_font, 12), wrap="word")
        txt.pack(fill="both", expand=True, padx=12, pady=12)
        txt.insert("1.0", report)
        txt.configure(state="disabled")

    def _do_edit_mifare_block(self) -> None:
        if self._last_mifare_dump is None:
            messagebox.showinfo(
                "Brak bufora",
                "Najpierw odczytaj kartę Mifare Classic lub wczytaj plik .dump do bufora.",
            )
            return

        dump = self._last_mifare_dump
        win = ctk.CTkToplevel(self)
        win.title("Edytuj blok w buforze Mifare")
        win.geometry("580x310")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)
        self._apply_toplevel_icon(win)

        frame = ctk.CTkFrame(win, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        block_var = tk.StringVar(value="4" if dump.total_blocks > 4 else "0")
        hex_var = tk.StringVar()
        text_var = tk.StringVar()
        role_var = tk.StringVar()
        syncing = {"active": False}

        def load_selected_block(*_: object) -> None:
            try:
                blk = int(block_var.get().strip())
                raw = dump.get_block(blk)
            except (ValueError, IndexError):
                role_var.set(f"Nieprawidłowy numer bloku (zakres 0..{dump.total_blocks - 1}).")
                return
            syncing["active"] = True
            try:
                hex_var.set(raw.hex(" ").upper())
                if is_mostly_printable_text(raw):
                    text_var.set(block_hex_to_utf8_text(raw.hex()))
                else:
                    text_var.set("")
            finally:
                syncing["active"] = False
            if dump.is_trailer_block(blk):
                status = "OK" if validate_access_bits(raw) else "BŁĘDNE"
                role_var.set(f"Sektor {dump.sector_of_block(blk):02d} — TRAILER (bity dostępu: {status})")
            elif blk == 0:
                role_var.set("Sektor 00 — Blok 0 producenta (UID)")
            else:
                role_var.set(f"Sektor {dump.sector_of_block(blk):02d} — Blok danych")

        def on_hex_changed(*_: object) -> None:
            if syncing["active"]:
                return
            syncing["active"] = True
            try:
                cleaned = hex_var.get().strip().replace(" ", "").replace(":", "").replace("-", "")
                if len(cleaned) == 32:
                    try:
                        raw = bytes.fromhex(cleaned)
                        text_var.set(raw.rstrip(b"\x00").decode("utf-8", errors="replace"))
                    except ValueError:
                        pass
            finally:
                syncing["active"] = False

            try:
                blk = int(block_var.get().strip())
                if not (0 <= blk < dump.total_blocks):
                    role_var.set(f"Zakres bloków: 0..{dump.total_blocks - 1}")
                    return
            except ValueError:
                role_var.set("Podaj poprawny numer bloku.")
                return
            if dump.is_trailer_block(blk):
                cleaned = hex_var.get().strip().replace(" ", "").replace(":", "").replace("-", "")
                if len(cleaned) == 32:
                    try:
                        raw = bytes.fromhex(cleaned)
                        acc_ok = validate_access_bits(raw)
                        role_var.set(
                            f"Sektor {dump.sector_of_block(blk):02d} — TRAILER (bity dostępu: {'OK' if acc_ok else 'NIEPRAWIDŁOWE!'})"
                        )
                        return
                    except ValueError:
                        pass
                role_var.set(f"Sektor {dump.sector_of_block(blk):02d} — TRAILER (wymaga poprawnych bitów dostępu)")

        def on_text_changed(*_: object) -> None:
            if syncing["active"]:
                return
            syncing["active"] = True
            try:
                txt = text_var.get()
                try:
                    hex_var.set(utf8_text_to_block_hex(txt))
                    role_var.set(f"Tekst UTF-8 ({len(txt.encode('utf-8'))}/16 B)")
                except ValueError as exc:
                    role_var.set(str(exc))
            finally:
                syncing["active"] = False

        row0 = ctk.CTkFrame(frame, fg_color="transparent")
        row0.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(row0, text=f"Numer bloku (0..{dump.total_blocks - 1}):").pack(side="left")
        ctk.CTkEntry(row0, textvariable=block_var, width=80).pack(side="left", padx=8)
        ctk.CTkButton(row0, text="Pobierz blok", width=110, command=load_selected_block).pack(side="left")

        ctk.CTkLabel(frame, textvariable=role_var).pack(anchor="w", pady=(0, 6))
        ctk.CTkLabel(frame, text="Dane bloku (32 znaki HEX):").pack(anchor="w")
        entry = ctk.CTkEntry(frame, textvariable=hex_var, font=(self._mono_font, 12))
        entry.pack(fill="x", pady=(4, 8))

        ctk.CTkLabel(frame, text="Tekst (UTF-8, maks. 16 B):").pack(anchor="w")
        text_entry = ctk.CTkEntry(frame, textvariable=text_var, font=(self._mono_font, 12))
        text_entry.pack(fill="x", pady=(4, 12))

        hex_var.trace_add("write", on_hex_changed)
        text_var.trace_add("write", on_text_changed)

        def save_edit() -> None:
            try:
                blk = int(block_var.get().strip())
            except ValueError:
                messagebox.showerror("Błędny blok", "Podaj poprawny numer bloku.", parent=win)
                return
            try:
                raw, is_trailer = validate_mifare_block_edit(dump, blk, hex_var.get())
            except ValueError as exc:
                messagebox.showerror("Nieprawidłowe dane bloku", str(exc), parent=win)
                return
            dump.set_block(blk, raw, validate_trailer=is_trailer)
            self._last_mifare_missing.discard(blk)
            self._refresh_mifare_preview()
            self._log(f"Zmieniono blok {blk:03d} w buforze: {raw.hex(' ').upper()}")
            win.destroy()

        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(fill="x")
        ctk.CTkButton(btns, text="Zapisz w buforze", command=save_edit).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btns, text="Anuluj", command=win.destroy).pack(side="right")

        load_selected_block()
        entry.focus_set()

    def _do_write_text_to_mifare_buffer(self) -> None:
        if self._last_mifare_dump is None:
            sectors = int(self.sectors_var.get()) if self.sectors_var.get() in ("5", "16", "32", "40") else 16
            self._last_mifare_dump = MifareDump.empty(sectors=sectors)
            self._last_mifare_header = f"Nowy czysty bufor Mifare ({sectors} sektorów)\n"
            self._last_mifare_missing = set()
            self._draw_sector_grid()
            self._refresh_mifare_preview()

        win = ctk.CTkToplevel(self)
        win.title("Zapisz tekst przez bloki Mifare Classic")
        win.geometry("740x560")
        win.minsize(640, 460)
        win.transient(self)
        win.grab_set()
        win.resizable(True, True)
        self._apply_toplevel_icon(win)

        frame = ctk.CTkFrame(win, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        start_var = tk.StringVar(value="1")
        clear_var = tk.BooleanVar(value=False)
        cap_var = tk.StringVar(value="")
        size_label_map = {"Mini (5 sekt.)": 5, "1K (16 sekt.)": 16, "2K (32 sekt.)": 32, "4K (40 sekt.)": 40}
        inv_size_map = {v: k for k, v in size_label_map.items()}
        size_var = tk.StringVar(value=inv_size_map.get(self._last_mifare_dump.sector_count, "1K (16 sekt.)"))

        top_row = ctk.CTkFrame(frame, fg_color="transparent")
        top_row.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(top_row, text="Rozmiar:").pack(side="left")
        ctk.CTkComboBox(
            top_row,
            variable=size_var,
            values=list(size_label_map.keys()),
            state="readonly",
            width=125,
            command=lambda val: on_size_changed(val),
        ).pack(side="left", padx=(6, 10))
        ctk.CTkLabel(top_row, text="Blok startowy:").pack(side="left")
        ctk.CTkEntry(top_row, textvariable=start_var, width=60).pack(side="left", padx=(6, 10))
        ctk.CTkCheckBox(
            top_row,
            text="Wyczyść pozostałe bloki (0x00)",
            variable=clear_var,
            command=lambda: update_capacity(),
        ).pack(side="left")

        ctk.CTkLabel(frame, textvariable=cap_var, anchor="w").pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(
            frame,
            text="Tekst UTF-8 (zapisywany automatycznie z pominięciem Bloku 0 i trailerów sektorów):",
            anchor="w",
        ).pack(fill="x")

        text_box = ctk.CTkTextbox(frame, height=160, font=(self._mono_font, 12), wrap="word")
        text_box.pack(fill="both", expand=True, pady=(4, 8))

        ctk.CTkLabel(frame, text="Podgląd podziału na bloki 16 B (na żywo):", anchor="w").pack(fill="x")
        preview_box = ctk.CTkTextbox(frame, height=150, font=(self._mono_font, 11), state="disabled", wrap="none")
        preview_box.pack(fill="both", expand=True, pady=(4, 10))

        def current_dump() -> MifareDump:
            assert self._last_mifare_dump is not None
            return self._last_mifare_dump

        def on_size_changed(choice: str) -> None:
            target_sectors = size_label_map.get(choice, 16)
            if current_dump().sector_count != target_sectors:
                self._last_mifare_dump = MifareDump.empty(sectors=target_sectors)
                self._last_mifare_header = f"Nowy czysty bufor Mifare ({target_sectors} sektorów)\n"
                self._last_mifare_missing = set()
                self.sectors_var.set(str(target_sectors))
                self._draw_sector_grid()
                self._refresh_mifare_preview()
            update_capacity()

        def load_decoded_text(*, force: bool = True) -> None:
            dump = current_dump()
            try:
                sb = int(start_var.get().strip())
                decoded = decode_blocks_to_text(dump, start_block=sb)
            except (ValueError, IndexError) as exc:
                if force:
                    messagebox.showerror("Błędny blok początkowy", str(exc), parent=win)
                return
            if force or is_mostly_printable_text(decoded):
                text_box.delete("1.0", "end")
                text_box.insert("1.0", decoded)
            update_capacity()

        def update_capacity(*_: object) -> None:
            dump = current_dump()
            try:
                sb = int(start_var.get().strip())
                txt = text_box.get("1.0", "end-1c")
                ub, mb, ublk, mblk = format_mifare_text_capacity(dump.total_blocks, sb, txt)
                status = "OK" if ub <= mb else "PRZEKROCZONO POJEMNOŚĆ!"
                cap_var.set(f"Pojemność od bloku {sb}: {ub} / {mb} B — zajmie {ublk} / {mblk} bloków danych ({status})")
                if ub <= mb:
                    preview = format_mifare_text_block_preview(
                        dump, txt, start_block=sb, clear_remaining=bool(clear_var.get())
                    )
                else:
                    preview = f"Tekst ({ub} B) przekracza dostępną pojemność ({mb} B)."
            except ValueError as exc:
                cap_var.set("Podaj poprawny numer bloku początkowego.")
                preview = str(exc)
            self._set_text(preview_box, preview)

        ctk.CTkButton(top_row, text="Odczytaj z bufora", width=120, command=lambda: load_decoded_text(force=True)).pack(
            side="right"
        )
        start_var.trace_add("write", update_capacity)
        text_box.bind("<KeyRelease>", lambda _e: update_capacity())

        def _commit_text_to_buffer() -> bool:
            dump = current_dump()
            try:
                sb = int(start_var.get().strip())
                txt = text_box.get("1.0", "end-1c")
                encode_text_to_blocks(
                    txt,
                    dump.total_blocks,
                    start_block=sb,
                    clear_remaining=bool(clear_var.get()),
                )
                updated = dump.write_text(txt, start_block=sb, clear_remaining=bool(clear_var.get()))
            except (ValueError, IndexError) as exc:
                messagebox.showerror("Błąd zapisu tekstu", str(exc), parent=win)
                return False
            for blk in updated:
                self._last_mifare_missing.discard(blk)
            self._refresh_mifare_preview()
            self._log(f"Zapisano tekst ({len(txt.encode('utf-8'))} B) do {len(updated)} bloków bufora od bloku {sb}.")
            return True

        def save_only() -> None:
            if _commit_text_to_buffer():
                win.destroy()

        def save_and_write_card() -> None:
            if _commit_text_to_buffer():
                win.destroy()
                self._do_write_mifare_dump()

        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(fill="x")
        ctk.CTkButton(btns, text="Zapisz i wgraj na kartę", command=save_and_write_card).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btns, text="Zapisz tekst w buforze", command=save_only).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btns, text="Anuluj", command=win.destroy).pack(side="right")

        load_decoded_text(force=False)
        text_box.focus_set()

    def _do_write_mifare_dump(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        if self._last_mifare_dump is None:
            messagebox.showinfo("Brak bufora", "Najpierw odczytaj kartę lub wczytaj plik .dump do bufora.")
            return
        try:
            keys = self._parse_key_list()
        except ValueError as exc:
            messagebox.showerror("Błędny klucz", str(exc))
            return

        dump = self._last_mifare_dump
        write_trailers = bool(self.write_trailers_var.get())
        write_block0 = bool(self.write_block0_var.get())

        if write_block0:
            if not messagebox.askyesno(
                "UWAGA: Zapis Bloku 0 (UID)",
                "Zaznaczono opcję zapisu Bloku 0 (UID / dane producenta).\n\n"
                "Zapis Bloku 0 działa wyłącznie na kartach CUID / Gen2 i na zwykłych kartach "
                "zakończy się błędem lub zablokowaniem bloku.\n\n"
                "Czy na pewno kontynuować zapis zrzutu na kartę?",
            ):
                return

        self._set_progress(0, dump.sector_count)
        on_progress = self._make_mifare_progress_cb()

        def task() -> None:
            report = reader.write_mifare_dump(
                dump,
                keys=keys,
                write_block0=write_block0,
                write_trailers=write_trailers,
                progress_cb=on_progress,
            )
            if not report.failed_blocks:
                reader.beep(50)
            summary = format_write_report_summary("Zapis zrzutu Mifare", report)

            def update(rep: MifareWriteReport = report, msg: str = summary) -> None:
                self._last_mifare_auth = dict(rep.sector_auth)
                self._apply_card_vars(rep.card)
                self._draw_sector_grid()
                self._log(msg)
                if rep.failed_blocks:
                    messagebox.showwarning("Zapis zakończony z błędami", msg)
                else:
                    messagebox.showinfo("Zapis zakończony", msg)

            self.after(0, update)

        self._run_async("Zapis zrzutu Mifare na kartę...", task)

    def _do_format_mifare(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            keys = self._parse_key_list()
        except ValueError as exc:
            messagebox.showerror("Błędny klucz", str(exc))
            return

        sectors = int(self.sectors_var.get())
        if not messagebox.askyesno(
            "Potwierdzenie formatowania karty",
            f"UWAGA: Formatowanie ({sectors} sektorów) wyzeruje wszystkie bloki danych (0x00, "
            "z pominięciem Bloku 0) oraz przywróci fabryczne trailery sektorów:\n"
            f"{FACTORY_MIFARE_TRAILER.hex(' ').upper()}\n\n"
            "Operacja jest nieodwracalna. Kontynuować?",
        ):
            return

        self._set_progress(0, sectors)
        on_progress = self._make_mifare_progress_cb()

        def task() -> None:
            report = reader.format_mifare_card(
                sectors=sectors,
                keys=keys,
                progress_cb=on_progress,
            )
            if not report.failed_blocks:
                reader.beep(50)
            summary = format_write_report_summary(f"Formatowanie karty ({sectors} sektorów)", report)

            def update(rep: MifareWriteReport = report, msg: str = summary) -> None:
                self._last_mifare_auth = dict(rep.sector_auth)
                self._apply_card_vars(rep.card)
                self._draw_sector_grid()
                self._log(msg)
                if rep.failed_blocks:
                    messagebox.showwarning("Formatowanie zakończone z błędami", msg)
                else:
                    messagebox.showinfo("Formatowanie zakończone", msg)

            self.after(0, update)

        self._run_async(f"Formatowanie karty Mifare ({sectors} sektorów)...", task)

    def _do_read_single_block(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            block = int(self.blk_num_var.get().strip())
            key = bytes.fromhex(self.blk_key_var.get().strip().replace(" ", ""))
            if len(key) != 6:
                raise ValueError("Klucz musi mieć 6 bajtów (12 znaków hex).")
            key_type = self.blk_key_type_var.get()
        except ValueError as exc:
            messagebox.showerror("Błędne dane", str(exc))
            return

        def task() -> None:
            card = reader.scan_card(init_rf=True)
            if card is None:
                raise ProtocolError("Brak karty na czytniku.")
            if not reader.mifare_auth(block, key, card.uid, key_type):
                raise ProtocolError(f"Autoryzacja bloku {block} kluczem {key_type} nie powiodła się.")
            data = reader.mifare_read_block(block)
            reader.beep(40)
            self.after(0, lambda d=data: self.blk_data_var.set(d.hex().upper()))
            self.after(0, lambda b=block, d=data: self._log(f"Odczytano blok {b}: {format_hex_ascii(d)}"))

        self._run_async(f"Odczyt bloku {block}...", task)

    def _do_write_single_block(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            block = int(self.blk_num_var.get().strip())
            key = bytes.fromhex(self.blk_key_var.get().strip().replace(" ", ""))
            data = bytes.fromhex(self.blk_data_var.get().strip().replace(" ", ""))
            if len(key) != 6:
                raise ValueError("Klucz musi mieć 6 bajtów (12 znaków hex).")
            if len(data) != 16:
                raise ValueError("Dane bloku muszą mieć 16 bajtów (32 znaki hex).")
            key_type = self.blk_key_type_var.get()
        except ValueError as exc:
            messagebox.showerror("Błędne dane", str(exc))
            return

        if block == 0 or (block < 128 and block % 4 == 3) or (block >= 128 and block % 16 == 15):
            if not messagebox.askyesno(
                "Potwierdzenie zapisu bloku systemowego",
                f"Blok {block} to blok producenta (0) lub trailer sektora (klucze i bity dostępu). "
                "Nieprawidłowy zapis może zablokować sektor. Kontynuować?",
            ):
                return

        def task() -> None:
            card = reader.scan_card(init_rf=True)
            if card is None:
                raise ProtocolError("Brak karty na czytniku.")
            if not reader.mifare_auth(block, key, card.uid, key_type):
                raise ProtocolError(f"Autoryzacja bloku {block} kluczem {key_type} nie powiodła się.")
            reader.mifare_write_block(block, data)
            reader.beep(50)
            self.after(0, lambda b=block, d=data: self._log(f"Zapisano blok {b}: {d.hex(' ').upper()}"))

        self._run_async(f"Zapis bloku {block}...", task)

    def _save_mifare_dump(self) -> None:
        if self._last_mifare_dump is None:
            messagebox.showinfo("Brak danych", "Najpierw odczytaj kartę Mifare Classic lub wczytaj bufor.")
            return
        path = filedialog.asksaveasfilename(
            title="Zapisz zrzut Mifare",
            defaultextension=".dump",
            filetypes=[("Dump Files", "*.dump *.bin"), ("All Files", "*.*")],
        )
        if path:
            self._last_mifare_dump.save(path)
            self._log(f"Zapisano zrzut Mifare: {path}")

    # ------------------------------------------------------------------
    # NTAG / Ultralight + NDEF + PWD_AUTH
    # ------------------------------------------------------------------

    def _get_ntag_password(self) -> bytes | None:
        if not self.ntag_use_pwd_var.get():
            return None
        pwd = parse_hex_bytes(self.ntag_pwd_var.get())
        if len(pwd) != 4:
            raise ValueError(f"Hasło NTAG musi mieć dokładnie 4 bajty (8 znaków HEX), podano {len(pwd)}.")
        return pwd

    def _do_ntag_version_info(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return

        def task() -> None:
            card = reader.scan_card(init_rf=True)
            if card is None:
                raise ProtocolError("Nie wykryto karty NTAG na czytniku.")
            version = reader.ntag_get_version()
            reader.beep(40)

            def update(c: CardInfo = card, v: NtagVersion = version) -> None:
                self._apply_card_vars(c)
                self.ntag_info_var.set(
                    f"Wersja NTAG: {v.name} ({v.total_pages} stron, użytkownik={v.user_pages * 4} B)"
                )
                self._log(
                    f"Info NTAG: {v.name} | UID={c.uid_hex} | Strony={v.total_pages} | "
                    f"Wersja={v.raw.hex(' ').upper()}"
                )

            self.after(0, update)

        self._run_async("Pobieranie wersji NTAG...", task)

    def _do_read_ntag(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            password = self._get_ntag_password()
        except ValueError as exc:
            messagebox.showerror("Błędne hasło NTAG", str(exc))
            return

        def on_progress(done: int, total: int) -> None:
            self.after(0, lambda d=done, t=total: self._set_progress(d, t))

        def task() -> None:
            card, version, pages = reader.ntag_read_all(progress_cb=on_progress, password=password)
            reader.beep(50)
            dump = NtagDump.from_pages(pages)
            user_mem = b"".join(pages[4 : version.user_end_page])
            records = parse_ndef_tlv(user_mem)
            ndef_summary = format_ndef_records_text(version, card, records)

            lines = [
                f"UID: {card.uid_hex} | ATQA={card.atqa_hex} | SAK={card.sak:02X}",
                f"Układ: {version.name} | Stron: {version.total_pages} | Wersja: {version.raw.hex(' ').upper()}\n",
            ]
            for idx, page in enumerate(pages):
                lines.append(f"  Strona {idx:03d} (0x{idx:02X}): {format_hex_ascii(page)}")

            def update(
                c: CardInfo = card,
                v: NtagVersion = version,
                d: NtagDump = dump,
                ns: str = ndef_summary,
                txt: str = "\n".join(lines),
            ) -> None:
                self._last_ntag_dump = d
                self._apply_card_vars(c)
                self.ntag_info_var.set(f"Wersja NTAG: {v.name} ({v.total_pages} stron)")
                self._set_text(self.ndef_text, ns)
                self._set_text(self.ntag_text, txt)
                self._log(f"Odczytano {v.name} ({v.total_pages} stron).")

            self.after(0, update)

        self._run_async("Odczyt NTAG...", task)

    def _do_write_ndef(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            password = self._get_ntag_password()
            value = self.ndef_value_var.get().strip()
            if self.ndef_kind_var.get() == "URL":
                tlv = build_ndef_uri_tlv(value)
            else:
                tlv = build_ndef_text_tlv(value, lang=self.ndef_lang_var.get().strip() or "pl")
        except ValueError as exc:
            messagebox.showerror("Błędne dane NDEF", str(exc))
            return

        def on_progress(done: int, total: int) -> None:
            self.after(0, lambda d=done, t=total: self._set_progress(d, t))

        def task() -> None:
            pages_written = reader.ntag_write_ndef(tlv, password=password, progress_cb=on_progress)
            reader.beep(50)
            msg = f"Zapisano rekord NDEF ({len(tlv)} B / {pages_written} stron od strony 4)."
            self.after(0, lambda m=msg: self._log(m))
            self.after(0, lambda m=msg: messagebox.showinfo("Zapis NDEF zakończony", m))

        self._run_async("Zapis NDEF na NTAG...", task)

    def _do_write_ntag_page(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            password = self._get_ntag_password()
            page = int(self.ntag_page_var.get().strip())
            data = bytes.fromhex(self.ntag_data_var.get().strip().replace(" ", ""))
            if len(data) != 4:
                raise ValueError("Strona NTAG musi mieć dokładnie 4 bajty (8 znaków hex).")
        except ValueError as exc:
            messagebox.showerror("Błędne dane", str(exc))
            return

        if page < 4:
            if not messagebox.askyesno(
                "Uwaga: strona systemowa NTAG",
                f"Strona {page} zawiera dane UID/Lock/CC. Nieprawidłowy zapis może nieodwracalnie zablokować tag. Kontynuować?",
            ):
                return

        def task() -> None:
            card = reader.scan_card(init_rf=True)
            if card is None:
                raise ProtocolError("Brak karty NTAG na czytniku.")
            reader.ntag_write_page(page, data, password=password)
            reader.beep(50)
            self.after(0, lambda p=page, d=data: self._log(f"Zapisano stronę NTAG {p}: {d.hex(' ').upper()}"))

        self._run_async(f"Zapis strony NTAG {page}...", task)

    def _save_ntag_dump(self) -> None:
        if self._last_ntag_dump is None:
            messagebox.showinfo("Brak danych", "Najpierw odczytaj tag NTAG.")
            return
        path = filedialog.asksaveasfilename(
            title="Zapisz zrzut NTAG",
            defaultextension=".dump",
            filetypes=[("Dump Files", "*.dump *.bin"), ("All Files", "*.*")],
        )
        if path:
            self._last_ntag_dump.save(path)
            self._log(f"Zapisano zrzut NTAG: {path}")

    # ------------------------------------------------------------------
    # Zrzuty (.dump) i porównywarka obok siebie
    # ------------------------------------------------------------------

    @staticmethod
    def _format_dump_for_viewer(path: Path, raw: bytes) -> str:
        lines = [f"Plik: {path} ({len(raw)} B)\n"]
        if len(raw) in (320, 1024, 2048, 4096):
            dump = MifareDump(raw)
            lines.append(format_mifare_dump_text(dump))
        else:
            dump_n = NtagDump(raw)
            for p in range(dump_n.page_count):
                lines.append(f"  Strona {p:03d} (0x{p:02X}): {format_hex_ascii(dump_n.get_page(p))}")
        return "\n".join(lines)

    def _open_dump_file(self) -> None:
        self._load_compare_side("left")

    def _load_compare_side(self, side: str) -> None:
        path_str = filedialog.askopenfilename(
            title=f"Otwórz plik zrzutu ({'lewy' if side == 'left' else 'prawy'})",
            filetypes=[("Dump Files", "*.dump *.bin *.mfd"), ("All Files", "*.*")],
        )
        if not path_str:
            return
        path = Path(path_str)
        raw = path.read_bytes()
        rendered = self._format_dump_for_viewer(path, raw)
        if side == "left":
            self.dump_left_path = path
            self.dump_left_title.set(f"Lewy: {path.name} ({len(raw)} B)")
            self._set_text(self.dump_left_text, rendered)
        else:
            self.dump_right_path = path
            self.dump_right_title.set(f"Prawy: {path.name} ({len(raw)} B)")
            self._set_text(self.dump_right_text, rendered)

        if self.dump_left_path is not None and self.dump_right_path is not None:
            self._run_side_by_side_diff(self.dump_left_path, self.dump_right_path)

    def _run_side_by_side_diff(self, left_path: Path, right_path: Path) -> None:
        left = left_path.read_bytes()
        right = right_path.read_bytes()
        block_size = 16 if len(left) in (320, 1024, 2048, 4096) else 4
        diff = compare_buffers(left, right, block_size=block_size)

        if diff.identical:
            self.diff_summary_var.set(f"Pliki identyczne ({diff.left_size} B).")
            self._set_text(self.dump_text, "Pliki są identyczne.")
            return

        summary = (
            f"Rozmiary: {diff.left_size} B vs {diff.right_size} B | "
            f"Różniących się bloków ({diff.block_size} B): {len(diff.differences)}"
        )
        self.diff_summary_var.set(summary)
        lines = [summary, ""]
        for item in diff.differences:
            lines.append(f"[{item.index:03d}] L: {format_hex_ascii(item.left)}")
            lines.append(f"      P: {format_hex_ascii(item.right)}\n")
        self._set_text(self.dump_text, "\n".join(lines))

    def _compare_dump_files(self) -> None:
        left_str = filedialog.askopenfilename(title="Wybierz pierwszy plik .dump")
        if not left_str:
            return
        right_str = filedialog.askopenfilename(title="Wybierz drugi plik .dump")
        if not right_str:
            return
        left_path = Path(left_str)
        right_path = Path(right_str)
        self.dump_left_path = left_path
        self.dump_right_path = right_path
        left_raw = left_path.read_bytes()
        right_raw = right_path.read_bytes()
        self.dump_left_title.set(f"Lewy: {left_path.name} ({len(left_raw)} B)")
        self.dump_right_title.set(f"Prawy: {right_path.name} ({len(right_raw)} B)")
        self._set_text(self.dump_left_text, self._format_dump_for_viewer(left_path, left_raw))
        self._set_text(self.dump_right_text, self._format_dump_for_viewer(right_path, right_raw))
        self._run_side_by_side_diff(left_path, right_path)

    # ------------------------------------------------------------------
    # 125 kHz (EM4100 / T5577) i HID Prox
    # ------------------------------------------------------------------

    def _append_lf_log(self, msg: str) -> None:
        self._append_textbox(self.lf_log_text, msg)
        self._log(msg)

    def _parse_lf_freq(self) -> int:
        freq = int(self.lf_freq_var.get().strip())
        if freq <= 0:
            raise ValueError("Częstotliwość musi być dodatnia.")
        return freq

    def _apply_em4100_result(self, card: EM4100Card) -> None:
        self.em_hex_var.set(f"{card.hex_spaced} ({card.hex_id})")
        self.em_dec_var.set(card.decimal_10)
        self.em_wg_var.set(f"FC={card.wiegand_fc:03d}, CN={card.wiegand_cn:05d} ({card.wiegand_26})")
        self._append_lf_log(
            f"[EM4100 {card.freq_hz // 1000} kHz] HEX={card.hex_id} | DEC={card.decimal_10} | "
            f"WG26 FC={card.wiegand_fc:03d} CN={card.wiegand_cn:05d}"
        )

    def _apply_hid_result(self, card: HIDProxCard) -> None:
        fc_str = str(card.facility_code) if card.facility_code is not None else "—"
        cn_str = str(card.card_number) if card.card_number is not None else "—"
        self.hid_format_var.set(card.format_name)
        self.hid_fc_var.set(fc_str)
        self.hid_cn_var.set(cn_str)
        self.hid_raw_var.set(card.raw_spaced)
        self.hid_short_var.set(f"{card.short_id:010d} (0x{card.short_id:08X})")
        self._append_lf_log(
            f"[{card.format_name}] FC={fc_str} | CN={cn_str} | HEX={card.raw_hex} | 32b={card.short_id:010d}"
        )

    def _do_read_em4100(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            freq = self._parse_lf_freq()
        except ValueError as exc:
            messagebox.showerror("Błędna częstotliwość", str(exc))
            return

        def task() -> None:
            card = reader.read_em4100(freq_hz=freq, init_rf=True)
            if card is None:
                self.after(0, lambda: self._append_lf_log("Nie wykryto karty 125 kHz (EM4100)."))
                self.after(0, lambda: messagebox.showinfo("Brak karty", "Połóż kartę 125 kHz i spróbuj ponownie."))
                return
            reader.beep(40)
            self.after(0, lambda c=card: self._apply_em4100_result(c))

        self._run_async("Odczyt 125 kHz (EM4100)...", task)

    def _do_read_hid_prox(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return

        def task() -> None:
            card = reader.read_hid_prox(init_rf=True)
            if card is None:
                self.after(0, lambda: self._append_lf_log("Nie wykryto karty HID Prox."))
                self.after(0, lambda: messagebox.showinfo("Brak karty", "Połóż kartę HID Prox i spróbuj ponownie."))
                return
            reader.beep(40)
            self.after(0, lambda c=card: self._apply_hid_result(c))

        self._run_async("Odczyt HID Prox...", task)

    def _do_scan_lf_both(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            freq = self._parse_lf_freq()
        except ValueError as exc:
            messagebox.showerror("Błędna częstotliwość", str(exc))
            return

        def task() -> None:
            em_card = reader.read_em4100(freq_hz=freq, init_rf=True)
            hid_card = reader.read_hid_prox(init_rf=True)
            if em_card is None and hid_card is None:
                self.after(0, lambda: self._append_lf_log("Brak karty 125 kHz (EM4100) ani HID Prox."))
                self.after(0, lambda: messagebox.showinfo("Brak karty", "Nie wykryto karty 125 kHz ani HID Prox."))
                return
            reader.beep(40)

            def update(c_em: EM4100Card | None = em_card, c_hid: HIDProxCard | None = hid_card) -> None:
                if c_em is not None:
                    self._apply_em4100_result(c_em)
                if c_hid is not None:
                    self._apply_hid_result(c_hid)

            self.after(0, update)

        self._run_async("Skanowanie 125 kHz + HID Prox...", task)

    def _do_convert_em4100(self) -> None:
        try:
            freq = self._parse_lf_freq()
        except ValueError:
            freq = DEFAULT_LF_FREQ_HZ
        try:
            card = convert_em4100_formats(
                self.conv_input_var.get(),
                source_format=self.conv_format_var.get(),
                freq_hz=freq,
            )
        except ValueError as exc:
            messagebox.showerror("Błędny format EM4100", str(exc))
            return
        self.conv_result_var.set(format_em4100_conversion_text(card))

    def _do_write_t5577(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            freq = self._parse_lf_freq()
            verify = bool(self.t55_verify_var.get())
            is_hid = self.t55_kind_var.get().startswith("HID")
            raw_input = self.t55_input_var.get().strip()
            if is_hid:
                raw6 = parse_hex_bytes(raw_input)
                if len(raw6) != 6:
                    raise ValueError(f"HID Prox wymaga dokładnie 6 bajtów (12 znaków HEX), podano {len(raw6)}.")
                target_label = f"HID Prox ({raw6.hex(' ').upper()})"
                em_card = None
            else:
                em_card = convert_em4100_formats(raw_input, source_format="auto", freq_hz=freq)
                raw6 = b""
                target_label = f"EM4100 ({em_card.hex_id}, DEC={em_card.decimal_10})"
        except ValueError as exc:
            messagebox.showerror("Błędne dane T5577", str(exc))
            return

        if not messagebox.askyesno(
            "Potwierdzenie zapisu na T5577",
            f"Zapisać {target_label} na czysty transponder T5577 ({freq} Hz)?\n"
            f"Weryfikacja odczytem: {'TAK' if verify else 'NIE'}.",
        ):
            return

        def task() -> None:
            if is_hid:
                res_hid = reader.write_hid_t5577(raw6, freq_hz=freq, verify=verify)
                reader.beep(50)
                self.after(0, lambda c=res_hid: self._apply_hid_result(c))
                self.after(0, lambda c=res_hid: self._append_lf_log(f"[Zapis T5577 OK] HID {c.raw_hex}"))
            else:
                assert em_card is not None
                res_em = reader.write_em4100_t5577(em_card.raw, freq_hz=freq, verify=verify)
                reader.beep(50)
                self.after(0, lambda c=res_em: self._apply_em4100_result(c))
                self.after(0, lambda c=res_em: self._append_lf_log(f"[Zapis T5577 OK] EM4100 {c.hex_id}"))

        self._run_async("Zapisywanie transpondera T5577...", task)

    def _copy_em_id(self) -> None:
        val = self.em_dec_var.get()
        if val and val != "—":
            self.clipboard_clear()
            self.clipboard_append(val)
            self.status_var.set("Skopiowano ID EM4100 (DEC) do schowka.")

    def _copy_hid_id(self) -> None:
        cn = self.hid_cn_var.get()
        raw = self.hid_raw_var.get()
        val = cn if cn and cn != "—" else raw.replace(" ", "")
        if val and val != "—":
            self.clipboard_clear()
            self.clipboard_append(val)
            self.status_var.set("Skopiowano numer karty HID do schowka.")

    # ------------------------------------------------------------------
    # CPU / ISO 7816-4 APDU
    # ------------------------------------------------------------------

    def _on_apdu_template_selected(self, choice: str) -> None:
        tpl = APDU_TEMPLATES.get(choice)
        if tpl:
            self.apdu_cmd_var.set(tpl)

    def _do_detect_apdu_card(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return

        def task() -> None:
            card = reader.scan_card(init_rf=True)
            if card is None:
                self.after(0, lambda: self._append_textbox(self.apdu_text, "[INFO] Brak karty w polu RF."))
                self.after(0, lambda: messagebox.showinfo("Brak karty", "Połóż kartę ISO 14443-4 i spróbuj ponownie."))
                return
            reader.beep(40)

            def update(c: CardInfo = card) -> None:
                self._apply_card_vars(c)
                self._append_textbox(
                    self.apdu_text,
                    f"[Karta] UID={c.uid_hex} | ATQA={c.atqa_hex} | SAK={c.sak:02X} ({c.card_type})",
                )

            self.after(0, update)

        self._run_async("Wykrywanie karty ISO 14443-4...", task)

    def _do_send_apdu(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            apdu = parse_hex_bytes(self.apdu_cmd_var.get())
            if len(apdu) < 4:
                raise ValueError("APDU musi mieć co najmniej 4 bajty (CLA INS P1 P2).")
        except ValueError as exc:
            messagebox.showerror("Błędne APDU", str(exc))
            return

        init_rf = bool(self.apdu_init_rf_var.get())

        def task() -> None:
            resp = reader.transceive_apdu(apdu, init_rf=init_rf)
            entry = format_apdu_exchange_entry(apdu, resp)
            self.after(0, lambda txt=entry: self._append_textbox(self.apdu_text, txt))

        self._run_async("Wysyłanie APDU...", task)

    # ------------------------------------------------------------------
    # Audyt Bezpieczeństwa (Read-Only)
    # ------------------------------------------------------------------

    def _apply_audit_report(self, report: CardAuditReport) -> None:
        self._last_audit_report = report
        risk_lbl, score_lbl, mig_lbl = format_audit_status_banner(report)
        self.audit_risk_var.set(risk_lbl)
        self.audit_score_var.set(score_lbl)
        self.audit_migration_var.set(mig_lbl)
        mask = bool(self.audit_mask_var.get())
        self._set_text(self.audit_text, report.format_text(mask_sensitive=mask))
        self._log(
            f"[Audyt] Ryzyko={report.risk_level} ({report.risk_score}/100) | "
            f"Znaleziska={len(report.findings)} | Migracja={report.migration_target}"
        )

    def _on_audit_mask_changed(self) -> None:
        if self._last_audit_report is None:
            return
        mask = bool(self.audit_mask_var.get())
        self._set_text(self.audit_text, self._last_audit_report.format_text(mask_sensitive=mask))

    def _do_audit_live(self) -> None:
        reader = self._require_reader()
        if reader is None:
            return
        try:
            keys = self._parse_key_list()
        except ValueError as exc:
            messagebox.showerror("Błędny klucz", str(exc))
            return

        self._set_progress(0, 16)
        on_progress = self._make_mifare_progress_cb()

        def task() -> None:
            report = audit_live_reader(reader, keys=keys, progress_cb=on_progress)
            reader.beep(40)
            self.after(0, lambda rep=report: self._apply_audit_report(rep))

        self._run_async("Wykonywanie audytu bezpieczeństwa karty (Read-Only)...", task)

    def _do_audit_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Wybierz plik zrzutu do audytu (.dump / .bin)",
            filetypes=[("Dump Files", "*.dump *.bin *.mfd"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            report = audit_dump_file(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Błąd audytu pliku", str(exc))
            return
        self._apply_audit_report(report)

    def _do_audit_current_buffer(self) -> None:
        if self._last_mifare_dump is not None:
            report = audit_mifare_dump(self._last_mifare_dump, card=self._last_mifare_card)
            self._apply_audit_report(report)
            return
        if self._last_ntag_dump is not None:
            report = audit_ntag_dump(self._last_ntag_dump)
            self._apply_audit_report(report)
            return
        messagebox.showinfo(
            "Brak bufora",
            "Najpierw odczytaj lub wczytaj do bufora kartę Mifare Classic albo NTAG.",
        )

    def _require_audit_report(self) -> CardAuditReport | None:
        if self._last_audit_report is None:
            messagebox.showinfo("Brak raportu", "Najpierw wykonaj audyt karty lub pliku .dump.")
            return None
        return self._last_audit_report

    def _do_export_audit_html(self) -> None:
        report = self._require_audit_report()
        if report is None:
            return
        path = filedialog.asksaveasfilename(
            title="Zapisz raport audytu HTML (do druku / PDF)",
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")],
        )
        if path:
            report.save_html(path, mask_sensitive=bool(self.audit_mask_var.get()))
            self._log(f"Zapisano raport audytu HTML: {path}")

    def _do_export_audit_markdown(self) -> None:
        report = self._require_audit_report()
        if report is None:
            return
        path = filedialog.asksaveasfilename(
            title="Zapisz raport audytu Markdown",
            defaultextension=".md",
            filetypes=[("Markdown Files", "*.md"), ("All Files", "*.*")],
        )
        if path:
            report.save_markdown(path, mask_sensitive=bool(self.audit_mask_var.get()))
            self._log(f"Zapisano raport audytu Markdown: {path}")

    def _do_export_audit_json(self) -> None:
        report = self._require_audit_report()
        if report is None:
            return
        path = filedialog.asksaveasfilename(
            title="Zapisz raport audytu JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if path:
            report.save_json(path, mask_sensitive=bool(self.audit_mask_var.get()))
            self._log(f"Zapisano raport audytu JSON: {path}")

    def _on_close(self) -> None:
        self._disconnect()
        self.destroy()


def main() -> int:
    _enable_windows_dpi_awareness()
    app = NFCPlusApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
