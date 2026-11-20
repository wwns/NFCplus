"""Testy jednostkowe helperów GUI (`nfcplus.app`) działające bez X11/DISPLAY."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from nfcplus import app as app_mod
from nfcplus.app import (
    SECTOR_COLOR_FAIL,
    SECTOR_COLOR_OK,
    SECTOR_COLOR_UNKNOWN,
    SECTOR_COLOR_UNKNOWN_DARK,
    NFCPlusApp,
    _find_asset_path,
    block_hex_to_utf8_text,
    format_apdu_exchange_entry,
    format_audit_status_banner,
    format_connection_status,
    format_em4100_conversion_text,
    format_mifare_analysis,
    format_mifare_dump_text,
    format_mifare_text_block_preview,
    format_mifare_text_capacity,
    utf8_text_to_block_hex,
    format_ndef_records_text,
    format_write_report_summary,
    get_config_path,
    load_app_config,
    merge_unique_keys,
    save_app_config,
    sector_canvas_palette,
    sector_indicator_colors,
    validate_mifare_block_edit,
)
from nfcplus.dump import FACTORY_MIFARE_TRAILER, MifareDump
from nfcplus.ndef import NdefRecord
from nfcplus.protocol import ApduResponse, CardInfo, EM4100Card, MifareWriteReport, NtagVersion
from nfcplus.transport import DeviceInfo, TransportError


def test_app_config_roundtrip_theme_and_error_handling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "nested" / "config.json"

    # Brak pliku -> domyślnie auto_connect=True, theme="dark"
    assert load_app_config(cfg_file) == {"auto_connect": True, "theme": "dark"}

    # Uszkodzony JSON / nieznany motyw -> bezpieczny fallback
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    cfg_file.write_text("{not-json", encoding="utf-8")
    assert load_app_config(cfg_file) == {"auto_connect": True, "theme": "dark"}
    cfg_file.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_app_config(cfg_file) == {"auto_connect": True, "theme": "dark"}
    cfg_file.write_text('{"auto_connect": false, "theme": "neon"}', encoding="utf-8")
    assert load_app_config(cfg_file) == {"auto_connect": False, "theme": "dark"}

    # Zapis i odczyt poprawnej konfiguracji dla trybu jasnego
    assert save_app_config({"auto_connect": False, "theme": "light"}, cfg_file) is True
    assert load_app_config(cfg_file) == {"auto_connect": False, "theme": "light"}

    # Błąd I/O przy zapisie -> zwraca False i nie rzuca wyjątku
    def _fail_write_text(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(Path, "write_text", _fail_write_text)
    assert save_app_config({"auto_connect": True, "theme": "dark"}, cfg_file) is False

    # Ścieżka konfiguracji dla Windows vs Linux
    monkeypatch.setenv("APPDATA", r"C:\Users\dev\AppData\Roaming")
    win_path = get_config_path(platform="win32")
    assert "NFCplus" in str(win_path)
    assert str(win_path).endswith("config.json")
    linux_path = get_config_path(platform="linux")
    assert linux_path.name == "config.json"
    assert ".config" in linux_path.parts


def test_sector_indicator_colors_dark_and_light_modes() -> None:
    unknown_dark = sector_indicator_colors(16, None, dark=True)
    assert len(unknown_dark) == 16
    assert all(ca == SECTOR_COLOR_UNKNOWN_DARK and cb == SECTOR_COLOR_UNKNOWN_DARK for _, ca, cb in unknown_dark)

    unknown_light = sector_indicator_colors(16, None, dark=False)
    assert len(unknown_light) == 16
    assert all(ca == SECTOR_COLOR_UNKNOWN and cb == SECTOR_COLOR_UNKNOWN for _, ca, cb in unknown_light)

    auth = {
        0: (True, True),
        1: (True, False),
        2: (False, True),
        3: (False, False),
    }
    colors = sector_indicator_colors(40, auth, dark=True)
    assert len(colors) == 40
    assert colors[0] == (0, SECTOR_COLOR_OK, SECTOR_COLOR_OK)
    assert colors[1] == (1, SECTOR_COLOR_OK, SECTOR_COLOR_FAIL)
    assert colors[2] == (2, SECTOR_COLOR_FAIL, SECTOR_COLOR_OK)
    assert colors[3] == (3, SECTOR_COLOR_FAIL, SECTOR_COLOR_FAIL)
    assert colors[4] == (4, SECTOR_COLOR_UNKNOWN_DARK, SECTOR_COLOR_UNKNOWN_DARK)
    assert colors[39] == (39, SECTOR_COLOR_UNKNOWN_DARK, SECTOR_COLOR_UNKNOWN_DARK)

    assert sector_canvas_palette(True)["bg"] != sector_canvas_palette(False)["bg"]


def test_validate_mifare_block_edit_and_merge_unique_keys() -> None:
    dump = MifareDump.empty(64)

    raw_data, is_trailer = validate_mifare_block_edit(
        dump,
        4,
        "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF",
    )
    assert is_trailer is False
    assert raw_data == bytes.fromhex("00112233445566778899AABBCCDDEEFF")

    with pytest.raises(ValueError, match="zakresie"):
        validate_mifare_block_edit(dump, 64, "00" * 16)
    with pytest.raises(ValueError, match="16 bajtów"):
        validate_mifare_block_edit(dump, 4, "AABBCC")
    with pytest.raises(ValueError, match="HEX"):
        validate_mifare_block_edit(dump, 4, "ZZZZ" * 8)

    raw_trailer, is_trailer_3 = validate_mifare_block_edit(dump, 3, FACTORY_MIFARE_TRAILER.hex())
    assert is_trailer_3 is True
    assert raw_trailer == FACTORY_MIFARE_TRAILER
    dump.set_block(3, raw_trailer, validate_trailer=True)
    assert dump.get_block(3) == FACTORY_MIFARE_TRAILER

    bad_trailer = bytearray(FACTORY_MIFARE_TRAILER)
    bad_trailer[6] = 0x00
    with pytest.raises(ValueError, match="bity dostępu"):
        validate_mifare_block_edit(dump, 3, bytes(bad_trailer).hex())

    k1 = bytes.fromhex("FFFFFFFFFFFF")
    k2 = bytes.fromhex("A0A1A2A3A4A5")
    k3 = bytes.fromhex("112233445566")
    assert merge_unique_keys([k1, k2], [k2, k3, k1]) == [k1, k2, k3]


def test_format_analysis_ndef_apdu_em4100_and_write_summary() -> None:
    # Value Block = 100 na bloku 4 (adres 4)
    val = 100
    inv_val = val ^ 0xFFFFFFFF
    vb = (
        val.to_bytes(4, "little", signed=True)
        + inv_val.to_bytes(4, "little", signed=False)
        + val.to_bytes(4, "little", signed=True)
        + bytes([4, 0xFF ^ 4, 4, 0xFF ^ 4])
    )
    dump = MifareDump.empty(20)  # Mifare Mini (5 sektorów)
    dump.set_block(3, FACTORY_MIFARE_TRAILER)
    dump.set_block(4, vb)
    dump.set_sector_auth(0, True, False)

    rendered = format_mifare_dump_text(dump, header="Nagłówek testowy", unavailable_blocks={1})
    assert "Nagłówek testowy" in rendered
    assert "Sektor 00 (KeyA=FFFFFFFFFFFF | Access=FF078069 | KeyB=????????????)" in rendered
    assert "Blok 001: <brak dostępu>" in rendered

    analysis = format_mifare_analysis(dump)
    assert "wykryte Value Block=1" in analysis
    assert "Blok 004: Value Block = 100" in analysis
    assert "Sektor 00: Access=FF078069 [OK]" in analysis

    report = MifareWriteReport(
        written_blocks=[1, 2, 3],
        skipped_blocks=[0],
        failed_blocks={7: "Błąd zapisu"},
        sector_auth={0: (True, True), 1: (False, False)},
    )
    summary = format_write_report_summary("Test zapisu", report)
    assert "zapisane=3, pominięte=1, błędy=1" in summary
    assert "Blok 007: Błąd zapisu" in summary

    card = CardInfo(uid=b"\x04\x11\x22\x33\x44\x55\x66", atqa=b"\x00\x44", sak=0x00, card_type="NTAG213")
    ver = NtagVersion(raw=b"\x00\x04\x04\x02\x01\x00\x0f\x03", name="NTAG213 (144 B user)", total_pages=45, total_bytes=180)
    ndef_txt = format_ndef_records_text(
        ver,
        card,
        [NdefRecord(tnf=1, record_type="U", summary="URI: https://example.com", payload=b"\x04example.com", uri="https://example.com")],
    )
    assert "NTAG213 (144 B user)" in ndef_txt
    assert "URI: https://example.com" in ndef_txt

    apdu_txt = format_apdu_exchange_entry(bytes.fromhex("0084000008"), ApduResponse(data=b"\x11\x22\x33\x44", sw1=0x90, sw2=0x00))
    assert ">> 00 84 00 00 08" in apdu_txt
    assert "SW=90 00 (OK)" in apdu_txt

    em_card = EM4100Card(raw=bytes.fromhex("4D0088BC89"))
    conv_txt = format_em4100_conversion_text(em_card)
    assert "4D0088BC89" in conv_txt
    assert "0008961161" in conv_txt
    assert "13648265" in conv_txt


def test_async_and_auto_connect_exception_binding_without_display(monkeypatch: pytest.MonkeyPatch) -> None:
    scheduled: list[object] = []

    class _DummyThread:
        def __init__(self, target, daemon=True) -> None:
            self._target = target

        def start(self) -> None:
            self._target()

    monkeypatch.setattr(app_mod.threading, "Thread", _DummyThread)

    errors: list[Exception] = []
    logs: list[str] = []
    fake_app = SimpleNamespace(
        _busy=False,
        _reader=None,
        _devices=[DeviceInfo(vid=0x0416, pid=0xB030, path="fake://1")],
        status_var=SimpleNamespace(set=lambda _v: None),
        conn_info_var=SimpleNamespace(set=lambda v: logs.append(v)),
        auto_connect_var=SimpleNamespace(get=lambda: True),
        after=lambda _ms, cb: scheduled.append(cb),
        _handle_error=lambda exc: errors.append(exc),
        _finish_async=lambda: None,
        _log=lambda msg: logs.append(msg),
    )

    def boom() -> None:
        raise RuntimeError("test boom")

    def fail_open(**_kw: object) -> object:
        raise TransportError("busy")

    NFCPlusApp._run_async(fake_app, "Test...", boom)  # type: ignore[arg-type]
    fake_app._busy = False
    monkeypatch.setattr(app_mod, "open_reader", fail_open)
    NFCPlusApp._try_auto_connect(fake_app)  # type: ignore[arg-type]

    for cb in scheduled:
        cb()  # type: ignore[operator]

    assert len(errors) == 1
    assert str(errors[0]) == "test boom"
    assert any("busy" in item for item in logs)


def test_audit_gui_banner_and_mask_toggle_without_display() -> None:
    from nfcplus.audit import audit_mifare_dump

    assert format_audit_status_banner(None) == ("—", "—", "—")

    dump = MifareDump.empty(64)
    for s in range(16):
        dump.set_block(dump.sector_block_range(s)[-1], FACTORY_MIFARE_TRAILER)
    dump.set_block(1, b"SECRET_USER_DATA")

    report = audit_mifare_dump(dump)
    risk_lbl, score_lbl, mig_lbl = format_audit_status_banner(report)
    assert risk_lbl == "KRYTYCZNE"
    assert "100 pkt" in score_lbl
    assert "DESFire" in mig_lbl

    rendered_texts: list[str] = []
    logs: list[str] = []
    mask_state = {"val": True}
    fake_app = SimpleNamespace(
        _last_audit_report=None,
        audit_risk_var=SimpleNamespace(set=lambda _v: None),
        audit_score_var=SimpleNamespace(set=lambda _v: None),
        audit_migration_var=SimpleNamespace(set=lambda _v: None),
        audit_mask_var=SimpleNamespace(get=lambda: mask_state["val"]),
        audit_text=object(),
        _set_text=lambda _w, txt: rendered_texts.append(txt),
        _log=lambda msg: logs.append(msg),
    )

    NFCPlusApp._apply_audit_report(fake_app, report)  # type: ignore[arg-type]
    assert "FFFF****FFFF" in rendered_texts[-1]
    assert "FFFFFFFFFFFF" not in rendered_texts[-1]

    # Wyłączenie maskowania w GUI odświeża widok z pełnym kluczem
    mask_state["val"] = False
    NFCPlusApp._on_audit_mask_changed(fake_app)  # type: ignore[arg-type]
    assert "FFFFFFFFFFFF" in rendered_texts[-1]


def test_assets_text_capacity_and_clean_reader_labels_in_gui(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _find_asset_path("nfcplus.ico") is not None
    assert _find_asset_path("nfcplus.png") is not None
    assert _find_asset_path("nonexistent_asset_xyz.ico") is None

    # Symulacja trybu PyInstaller (_MEIPASS)
    bundle_assets = tmp_path / "assets"
    bundle_assets.mkdir()
    fake_ico = bundle_assets / "nfcplus.ico"
    fake_ico.write_bytes(b"ICO")
    monkeypatch.setattr(app_mod.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert _find_asset_path("nfcplus.ico") == fake_ico

    # Pojemność zapisu tekstu UTF-8 dla Mifare Classic 1K (64 bloki -> 47 bloków danych od bloku 1 = 752 B)
    ub, mb, ublk, mblk = format_mifare_text_capacity(64, 1, "Ala ma kota")
    assert ub == 11
    assert mb == 752
    assert ublk == 1
    assert mblk == 47

    # _refresh_devices używa czytelnych etykiet bez \\?\hid#...
    win_dev = DeviceInfo(
        vid=0x0416,
        pid=0xB030,
        path=r"\\?\hid#vid_0416&pid_b030#6&1234&0&0000#{4d1e55b2}",
        product="NSCCN XIXEI Smart Reader",
        backend="win32",
    )
    monkeypatch.setattr(app_mod, "enumerate_readers", lambda: [win_dev])
    combo_values: list[list[str]] = []
    combo_selected: list[str] = []
    fake_app = SimpleNamespace(
        _devices=[],
        _device_labels=[],
        _reader=None,
        device_combo=SimpleNamespace(
            configure=lambda **kw: combo_values.append(kw["values"]),
            set=lambda val: combo_selected.append(val),
        ),
        conn_info_var=SimpleNamespace(set=lambda _v: None),
        _log=lambda _m: None,
    )
    NFCPlusApp._refresh_devices(fake_app)  # type: ignore[arg-type]
    assert combo_values == [["NSCCN XIXEI Smart Reader (0416:b030)"]]
    assert combo_selected == ["NSCCN XIXEI Smart Reader (0416:b030)"]
    assert r"\\?\hid#" not in combo_selected[0]


def test_block_hex_utf8_sync_and_live_block_preview() -> None:
    hex_str = utf8_text_to_block_hex("Witaj!")
    assert len(hex_str.replace(" ", "")) == 32
    assert block_hex_to_utf8_text(hex_str) == "Witaj!"

    with pytest.raises(ValueError, match="przekracza"):
        utf8_text_to_block_hex("A" * 17)

    dump = MifareDump.empty(sectors=16)
    preview = format_mifare_text_block_preview(
        dump,
        "1234567890123456" + "ABCDEFGHIJKLMNOP" + "XYZ",
        start_block=1,
    )
    assert "Blok 001:" in preview
    assert "Blok 002:" in preview
    assert "Blok 003: [TRAILER — pominięty]" in preview
    assert "Blok 004:" in preview


def test_acr122u_connection_status_lf_guard_and_scan_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acr_dev = DeviceInfo(
        vid=0x072F,
        pid=0x2200,
        path="/dev/bus/usb/001/003",
        product="ACR122U PICC Interface",
        backend="ccid_usb",
        protocol_family="acr122u",
        supports_lf=False,
    )
    status_acr = format_connection_status(acr_dev, "ACR122U PICC Interface", supports_lf=False)
    assert "(ccid_usb)" in status_acr
    assert "072f:2200" in status_acr
    assert "tylko 13,56 MHz" in status_acr

    wcopy_dev = DeviceInfo(
        vid=0x0416,
        pid=0xB030,
        path="/dev/hidraw0",
        product="wCopy",
        backend="hidraw",
        protocol_family="wcopy_hid",
        supports_lf=True,
    )
    status_wcopy = format_connection_status(wcopy_dev, "wCopy", supports_lf=True)
    assert "(hidraw)" in status_wcopy
    assert "tylko 13,56 MHz" not in status_wcopy

    # _require_lf_reader zwraca None i pokazuje messagebox.showinfo dla czytnika bez LF
    info_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        app_mod.messagebox,
        "showinfo",
        lambda title, msg: info_calls.append((title, msg)),
    )

    lf_calls: list[str] = []
    fake_iso_card = SimpleNamespace(uid_hex="3F 99 06 63", card_type="MIFARE Classic 1K")
    fake_reader = SimpleNamespace(
        supports_lf=False,
        scan_card=lambda init_rf=True: fake_iso_card,
        read_em4100=lambda **_kw: lf_calls.append("read_em4100"),
        read_hid_prox=lambda **_kw: lf_calls.append("read_hid_prox"),
        beep=lambda _ms: None,
    )

    def make_var(initial: str = "STARE") -> SimpleNamespace:
        state = {"val": initial}
        return SimpleNamespace(
            set=lambda v: state.__setitem__("val", v),
            get=lambda: state["val"],
        )

    scheduled: list[object] = []
    logs: list[str] = []
    applied_iso: list[object] = []
    fake_app = SimpleNamespace(
        _reader=fake_reader,
        _require_reader=lambda: fake_reader,
        _require_lf_reader=lambda: NFCPlusApp._require_lf_reader(fake_app),  # type: ignore[arg-type]
        _parse_lf_freq=lambda: 125_000,
        _clear_lf_vars=lambda: NFCPlusApp._clear_lf_vars(fake_app),  # type: ignore[arg-type]
        _apply_card_vars=lambda c: applied_iso.append(c),
        _log=lambda msg: logs.append(msg),
        after=lambda _ms, cb: scheduled.append(cb),
        _run_async=lambda _lbl, fn: fn(),
        em_hex_var=make_var(),
        em_dec_var=make_var(),
        em_wg_var=make_var(),
        hid_format_var=make_var(),
        hid_fc_var=make_var(),
        hid_cn_var=make_var(),
        hid_raw_var=make_var(),
        hid_short_var=make_var(),
    )

    assert NFCPlusApp._require_lf_reader(fake_app) is None  # type: ignore[arg-type]
    assert len(info_calls) == 1
    assert "13,56 MHz" in info_calls[0][1]

    for lf_method in (
        NFCPlusApp._do_read_em4100,
        NFCPlusApp._do_read_hid_prox,
        NFCPlusApp._do_scan_lf_both,
        NFCPlusApp._do_write_t5577,
    ):
        lf_method(fake_app)  # type: ignore[arg-type]
    assert lf_calls == []

    # _do_scan_all dla ACR122U pomija LF, czyści pola LF i loguje komunikat
    NFCPlusApp._do_scan_all(fake_app)  # type: ignore[arg-type]
    for cb in scheduled:
        cb()  # type: ignore[operator]

    assert lf_calls == []
    assert applied_iso == [fake_iso_card]
    assert any("wyłącznie pasmo 13,56 MHz" in msg for msg in logs)
    assert all(
        var.get() == "—"
        for var in (
            fake_app.em_hex_var,
            fake_app.em_dec_var,
            fake_app.em_wg_var,
            fake_app.hid_format_var,
            fake_app.hid_fc_var,
            fake_app.hid_cn_var,
            fake_app.hid_raw_var,
            fake_app.hid_short_var,
        )
    )


def test_toggle_connect_closes_transport_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    closed = {"count": 0}
    errors: list[tuple[str, str]] = []

    class BrokenReader:
        def __init__(self, _transport: object) -> None:
            pass

        def get_device_info(self) -> dict[str, str]:
            raise TransportError("nieudane info")

    fake_dev = DeviceInfo(vid=0x072F, pid=0x2200, path="ACS ACR122U 0", backend="winscard")
    fake_transport = SimpleNamespace(close=lambda: closed.__setitem__("count", closed["count"] + 1))

    monkeypatch.setattr(app_mod, "open_reader", lambda path=None: (fake_dev, fake_transport))
    monkeypatch.setattr(app_mod, "NFCReader", BrokenReader)
    monkeypatch.setattr(
        app_mod.messagebox,
        "showerror",
        lambda title, msg: errors.append((title, msg)),
    )

    fake_app = SimpleNamespace(
        _reader=None,
        _selected_device_path=lambda: "ACS ACR122U 0",
    )
    NFCPlusApp._toggle_connect(fake_app)  # type: ignore[arg-type]

    assert closed["count"] == 1
    assert len(errors) == 1
    assert "nieudane info" in errors[0][1]

