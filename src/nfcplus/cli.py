"""Interfejs wiersza poleceń (CLI) dla czytników NFCplus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import audit_dump_file, audit_live_reader
from .dump import MifareDump, NtagDump, compare_buffers, format_hex_ascii, parse_key_file
from .ndef import build_ndef_text_tlv, build_ndef_uri_tlv, parse_ndef_tlv
from .protocol import (
    DEFAULT_LF_FREQ_HZ,
    DEFAULT_MIFARE_KEYS,
    CardInfo,
    EM4100Card,
    HIDProxCard,
    MifareWriteReport,
    NFCReader,
    ProtocolError,
    convert_em4100_formats,
    parse_hex_bytes,
)
from .transport import TransportError, enumerate_readers, no_readers_hint, open_reader


def _parse_hex_bytes_value(value: str, expected_len: int, label: str) -> bytes:
    cleaned = value.replace(" ", "").replace(":", "").replace("-", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Nieprawidłowy zapis szesnastkowy dla {label}: {value}") from exc
    if len(raw) != expected_len:
        raise ValueError(
            f"{label} musi mieć dokładnie {expected_len} bajtów ({expected_len * 2} znaków hex), podano {len(raw)}."
        )
    return raw


def _parse_hex_bytes(value: str, expected_len: int, label: str) -> bytes:
    try:
        return _parse_hex_bytes_value(value, expected_len, label)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _load_mifare_keys(key_args: list[str] | None, key_file: str | None) -> list[bytes]:
    keys: list[bytes] = []
    if key_args:
        for item in key_args:
            keys.append(_parse_hex_bytes_value(item, 6, "klucz"))
    if key_file:
        for k in parse_key_file(key_file):
            if k not in keys:
                keys.append(k)
    return keys if keys else list(DEFAULT_MIFARE_KEYS)


def _confirm_action(prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [t/N]: ").strip().lower()
    except (EOFError, OSError):
        return False
    return answer in ("t", "tak", "y", "yes")


def _print_write_report(title: str, report: MifareWriteReport) -> None:
    print(f"=== {title} ===")
    if report.card is not None:
        print(
            f"Karta: {report.card.card_type} | UID={report.card.uid_hex} | "
            f"ATQA={report.card.atqa_hex} | SAK={report.card.sak:02X}"
        )
    print(
        f"Zapisano bloków: {len(report.written_blocks)} | "
        f"Pominięto bloków: {len(report.skipped_blocks)} | "
        f"Błędy: {len(report.failed_blocks)}"
    )
    if report.sector_auth:
        auth_parts = [
            f"S{s:02d}[{'A' if ka else '-'}{'B' if kb else '-'}]"
            for s, (ka, kb) in sorted(report.sector_auth.items())
        ]
        print("Autoryzacja sektorów: " + " ".join(auth_parts))
    if report.failed_blocks:
        print("Niepowodzenia:")
        for blk, reason in sorted(report.failed_blocks.items()):
            print(f"  Blok {blk:03d}: {reason}")


def _cmd_info(args: argparse.Namespace) -> int:
    devices = enumerate_readers()
    if not devices:
        print(f"Nie wykryto żadnego kompatybilnego czytnika USB HID. {no_readers_hint()}")
        return 1

    for idx, dev in enumerate(devices):
        print(f"[{idx}] {dev.vid_pid}  path={dev.path}  backend={dev.backend}  product={dev.product!r}")

    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        info = reader.get_device_info()
        print(f"Model:    {info['model']}")
        print(f"Firmware: {info['firmware']}")
        print(f"Wariant:  {info['display_name']}")
        if args.beep:
            reader.beep(60)
            print("Buzzer:   OK")
    return 0


def _print_iso14443a_card(card: CardInfo) -> None:
    print(f"UID:   {card.uid_hex}")
    print(f"ATQA:  {card.atqa_hex}")
    print(f"SAK:   {card.sak:02X}")
    print(f"Typ:   {card.card_type}")


def _print_em4100_card(card: EM4100Card) -> None:
    print(f"Typ:      EM4100 / T5577 ({card.freq_hz // 1000} kHz)")
    print(f"ID (HEX): {card.hex_spaced} ({card.hex_id})")
    print(f"ID (DEC): {card.decimal_10}")
    print(f"WG26:     FC={card.wiegand_fc:03d}  CN={card.wiegand_cn:05d} ({card.wiegand_26})")


def _print_hid_card(card: HIDProxCard) -> None:
    bits_label = f"{card.bit_length}" if card.bit_length is not None else "nieznana (surowe 48-bit)"
    fc_label = str(card.facility_code) if card.facility_code is not None else "—"
    cn_label = str(card.card_number) if card.card_number is not None else "—"
    print(f"Format:   {card.format_name}")
    print(f"Bity:     {bits_label}")
    print(f"FC:       {fc_label}")
    print(f"Card No:  {cn_label}")
    print(f"HEX (6B): {card.raw_spaced} ({card.raw_hex})")
    print(f"ID (32b): {card.short_id:010d} (0x{card.short_id:08X})")


def _cmd_scan(args: argparse.Namespace) -> int:
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        if not args.all:
            card = reader.scan_card(init_rf=True)
            if card is None:
                print("Brak karty na czytniku.")
                return 1
            reader.beep(40)
            _print_iso14443a_card(card)
            return 0

        iso_card = reader.scan_card(init_rf=True)
        em_card = reader.read_em4100(init_rf=True)
        hid_card = reader.read_hid_prox(init_rf=True)

        if iso_card is None and em_card is None and hid_card is None:
            print("Brak karty na czytniku (13.56 MHz / 125 kHz / HID).")
            return 1

        reader.beep(40)
        if iso_card is not None:
            print("[13.56 MHz ISO14443A]")
            _print_iso14443a_card(iso_card)
        if em_card is not None:
            if iso_card is not None:
                print()
            print("[125 kHz EM4100]")
            _print_em4100_card(em_card)
        if hid_card is not None:
            if iso_card is not None or em_card is not None:
                print()
            print("[125 kHz HID Prox]")
            _print_hid_card(hid_card)
    return 0


def _cmd_read_125k(args: argparse.Namespace) -> int:
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card = reader.read_em4100(freq_hz=args.freq, init_rf=True)
        if card is None:
            print("Brak karty 125 kHz (EM4100) na czytniku.")
            return 1
        reader.beep(40)
        _print_em4100_card(card)
    return 0


def _cmd_read_hid(args: argparse.Namespace) -> int:
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card = reader.read_hid_prox(init_rf=True)
        if card is None:
            print("Brak karty HID Prox na czytniku.")
            return 1
        reader.beep(40)
        _print_hid_card(card)
    return 0


def _cmd_read_mifare(args: argparse.Namespace) -> int:
    keys = [
        _parse_hex_bytes(k, 6, "klucz") for k in args.key
    ] if args.key else list(DEFAULT_MIFARE_KEYS)

    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card, blocks, found_keys = reader.mifare_read_sectors(keys=keys, sectors=args.sectors)
        reader.beep(50)
        print(f"Karta: {card.card_type} | UID={card.uid_hex} | ATQA={card.atqa_hex} | SAK={card.sak:02X}")
        for sector in range(args.sectors):
            ka, kb = found_keys[sector]
            ka_s = ka.hex().upper() if ka else "????????????"
            kb_s = kb.hex().upper() if kb else "????????????"
            print(f"\n--- Sektor {sector:02d} (KeyA={ka_s}, KeyB={kb_s}) ---")
            first = sector * 4 if sector < 32 else 128 + (sector - 32) * 16
            count = 4 if sector < 32 else 16
            for offset in range(count):
                blk = first + offset
                data = blocks[blk]
                text = format_hex_ascii(data) if data is not None else "<brak dostępu>"
                print(f"  Blok {blk:03d}: {text}")

        if args.output:
            dump = MifareDump.from_blocks(blocks)
            dump.save(args.output)
            print(f"\nZapisano zrzut do: {args.output}")
    return 0


def _cmd_write_block(args: argparse.Namespace) -> int:
    key = _parse_hex_bytes(args.key, 6, "klucz")
    data = _parse_hex_bytes(args.data, 16, "dane bloku")
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card = reader.scan_card(init_rf=True)
        if card is None:
            print("Brak karty na czytniku.")
            return 1
        if not reader.mifare_auth(args.block, key, card.uid, args.key_type):
            print(f"Błąd autoryzacji bloku {args.block} kluczem {args.key_type}.")
            return 1
        reader.mifare_write_block(args.block, data)
        reader.beep(50)
        print(f"Zapisano blok {args.block}: {data.hex(' ').upper()}")
    return 0


def _cmd_write_mifare(args: argparse.Namespace) -> int:
    dump = MifareDump.load(args.dump_file)
    keys = _load_mifare_keys(args.key, args.key_file)
    write_block0 = bool(args.write_block0)
    write_trailers = not bool(args.no_trailers)

    if write_block0 and not args.yes:
        if not _confirm_action(
            "UWAGA: Zapis bloku 0 (--write-block0) nadpisuje UID/dane producenta i wymaga karty CUID/Gen2. Kontynuować?"
        ):
            print("Anulowano zapis zrzutu Mifare.")
            return 1

    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        report = reader.write_mifare_dump(
            dump,
            keys=keys,
            write_block0=write_block0,
            write_trailers=write_trailers,
        )
        if not report.failed_blocks:
            reader.beep(50)
    _print_write_report(f"Zapis zrzutu Mifare ({args.dump_file})", report)
    return 1 if report.failed_blocks else 0


def _cmd_format_mifare(args: argparse.Namespace) -> int:
    keys = _load_mifare_keys(args.key, args.key_file)
    if not args.yes:
        if not _confirm_action(
            f"UWAGA: Formatowanie wyzeruje bloki danych ({args.sectors} sektorów, z pominięciem bloku 0) i przywróci fabryczne klucze FF..FF. Kontynuować?"
        ):
            print("Anulowano formatowanie karty Mifare.")
            return 1

    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        report = reader.format_mifare_card(sectors=args.sectors, keys=keys)
        if not report.failed_blocks:
            reader.beep(50)
    _print_write_report(f"Formatowanie karty Mifare ({args.sectors} sektorów)", report)
    return 1 if report.failed_blocks else 0


def _cmd_read_ntag(args: argparse.Namespace) -> int:
    password = _parse_hex_bytes_value(args.password, 4, "hasło NTAG") if args.password else None
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card, version, pages = reader.ntag_read_all(password=password)
        reader.beep(50)
        print(f"Karta:  {version.name} ({version.total_pages} stron, {version.total_bytes} B)")
        print(f"UID:    {card.uid_hex} | ATQA={card.atqa_hex} | SAK={card.sak:02X}")
        print(f"Wersja: {version.raw.hex(' ').upper()}\n")
        for idx, page_data in enumerate(pages):
            print(f"  Strona {idx:03d} (0x{idx:02X}): {format_hex_ascii(page_data)}")
        if args.output:
            dump = NtagDump.from_pages(pages)
            dump.save(args.output)
            print(f"\nZapisano zrzut NTAG do: {args.output}")
    return 0


def _cmd_write_ntag(args: argparse.Namespace) -> int:
    data = _parse_hex_bytes(args.data, 4, "dane strony")
    password = _parse_hex_bytes_value(args.password, 4, "hasło NTAG") if args.password else None
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card = reader.scan_card(init_rf=True)
        if card is None:
            print("Brak karty na czytniku.")
            return 1
        reader.ntag_write_page(args.page, data, password=password)
        reader.beep(50)
        print(f"Zapisano stronę {args.page} (0x{args.page:02X}): {data.hex(' ').upper()}")
    return 0


def _cmd_read_ndef(args: argparse.Namespace) -> int:
    password = _parse_hex_bytes_value(args.password, 4, "hasło NTAG") if args.password else None
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        card, version, user_mem = reader.ntag_read_user_memory(password=password)
        records = parse_ndef_tlv(user_mem)
        reader.beep(40)
    print(f"Karta: {version.name} | UID={card.uid_hex}")
    if not records:
        print("Brak rekordów NDEF w pamięci użytkownika.")
        return 0
    for idx, rec in enumerate(records, start=1):
        print(f"[{idx}] {rec.summary} (TNF={rec.tnf}, typ={rec.record_type})")
    return 0


def _cmd_write_ndef(args: argparse.Namespace) -> int:
    password = _parse_hex_bytes_value(args.password, 4, "hasło NTAG") if args.password else None
    if args.uri is not None:
        tlv = build_ndef_uri_tlv(args.uri)
    else:
        tlv = build_ndef_text_tlv(args.text, lang=args.lang)
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        pages_written = reader.ntag_write_ndef(tlv, password=password)
        reader.beep(50)
    print(f"Zapisano NDEF TLV ({len(tlv)} B / {pages_written} stron od strony 4).")
    return 0


def _cmd_apdu(args: argparse.Namespace) -> int:
    apdu = parse_hex_bytes(args.hex_apdu)
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        resp = reader.transceive_apdu(apdu, init_rf=bool(args.init_rf))
    data_hex = resp.data.hex(" ").upper() if resp.data else "<brak>"
    print(f"Dane ({len(resp.data)} B): {data_hex}")
    print(f"Status: {resp.sw1:02X} {resp.sw2:02X} ({'OK' if resp.is_ok else 'status nie-9000'})")
    return 0


def _cmd_lf_convert(args: argparse.Namespace) -> int:
    ver_byte = int(args.version_byte, 16) if args.version_byte.startswith("0x") or any(c in args.version_byte for c in "abcdefABCDEF") else int(args.version_byte, 0)
    card = convert_em4100_formats(args.value, source_format=args.format, version_byte=ver_byte)
    print(f"40-bit HEX:  {card.hex_id} ({card.hex_spaced})")
    print(f"DEC 10-cyfr: {card.decimal_10}")
    print(f"DEC 8-cyfr:  {card.wiegand_26}")
    print(f"Wiegand 26:  FC={card.wiegand_fc:03d}  CN={card.wiegand_cn:05d}")
    return 0


def _cmd_dump_json(args: argparse.Namespace) -> int:
    dump = MifareDump.load(args.dump_file)
    if args.output:
        dump.save_json(args.output)
        print(f"Zapisano JSON do: {args.output}")
    else:
        print(json.dumps(dump.to_json_dict(), indent=2, ensure_ascii=False))
    return 0


def _cmd_write_t5577(args: argparse.Namespace) -> int:
    verify = not bool(args.no_verify)
    _, transport = open_reader(path=args.path)
    with transport:
        reader = NFCReader(transport)
        if args.em4100 is not None:
            em_card = convert_em4100_formats(args.em4100, source_format="auto")
            result = reader.write_em4100_t5577(em_card.raw, freq_hz=args.freq, verify=verify)
            reader.beep(50)
            print("Zapisano EM4100 na T5577:")
            _print_em4100_card(result)
        else:
            raw6 = _parse_hex_bytes_value(args.hid, 6, "dane HID Prox")
            hid_card = reader.write_hid_t5577(raw6, freq_hz=args.freq, verify=verify)
            reader.beep(50)
            print("Zapisano HID Prox na T5577:")
            _print_hid_card(hid_card)
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    mask_sensitive = not bool(args.unmask)
    if args.dump:
        report = audit_dump_file(args.dump)
    else:
        keys = _load_mifare_keys(args.key, args.key_file)
        _, transport = open_reader(path=args.path)
        with transport:
            reader = NFCReader(transport)
            report = audit_live_reader(reader, keys=keys)
            reader.beep(40)

    print(report.format_text(mask_sensitive=mask_sensitive))
    if args.output:
        out_path = Path(args.output)
        suffix = out_path.suffix.lower()
        if suffix in (".html", ".htm"):
            report.save_html(out_path, mask_sensitive=mask_sensitive)
        elif suffix in (".md", ".markdown"):
            report.save_markdown(out_path, mask_sensitive=mask_sensitive)
        elif suffix == ".json":
            report.save_json(out_path, mask_sensitive=mask_sensitive)
        else:
            raise ValueError(
                f"Nieobsługiwane rozszerzenie raportu audytu: {out_path.suffix!r} (oczekiwano .html, .md lub .json)."
            )
        print(f"\nZapisano raport audytu do: {out_path}")
    return 0


def _cmd_dump_info(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    if len(raw) in (320, 1024, 2048, 4096):
        dump = MifareDump(raw)
        print(f"Plik Mifare Classic ({len(raw)} B, {dump.sector_count} sektorów, {dump.total_blocks} bloków)")
        for s in range(dump.sector_count):
            ka, acc, kb = dump.get_sector_trailer(s)
            print(f"\nSektor {s:02d} (KeyA={ka.hex().upper()}, Access={acc.raw.hex().upper()} valid={acc.valid}, KeyB={kb.hex().upper()})")
            for blk in dump.sector_block_range(s):
                print(f"  Blok {blk:03d}: {format_hex_ascii(dump.get_block(blk))}")
    else:
        dump_n = NtagDump(raw)
        print(f"Plik NTAG / Ultralight ({len(raw)} B, {dump_n.page_count} stron)")
        for p in range(dump_n.page_count):
            print(f"  Strona {p:03d} (0x{p:02X}): {format_hex_ascii(dump_n.get_page(p))}")
    return 0


def _cmd_dump_diff(args: argparse.Namespace) -> int:
    left = Path(args.left).read_bytes()
    right = Path(args.right).read_bytes()
    diff = compare_buffers(left, right, block_size=args.block_size)
    if diff.identical:
        print("Pliki zrzutów są identyczne.")
        return 0
    print(
        f"Rozmiary: {diff.left_size} B vs {diff.right_size} B | "
        f"Liczba różniących się bloków ({diff.block_size} B): {len(diff.differences)}"
    )
    for item in diff.differences:
        print(f"  [{item.index:03d}] L: {item.left.hex(' ').upper()}")
        print(f"        P: {item.right.hex(' ').upper()}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nfcplus",
        description="Czytelny klient USB HID dla czytników NFC/Mifare (wCopy / Xixei).",
    )
    path_example = r"\\?\hid#vid_0416&pid_b030#..." if sys.platform == "win32" else "/dev/hidraw0"
    parser.add_argument("--path", help=f"Opcjonalna ścieżka urządzenia (np. {path_example})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Wykrywa czytnik i pobiera model oraz wersję firmware")
    p_info.add_argument("--beep", action="store_true", help="Wydaj krótki sygnał dźwiękowy")
    p_info.set_defaults(func=_cmd_info)

    p_scan = sub.add_parser("scan", help="Odczytuje UID, ATQA, SAK oraz typ karty (opcjonalnie z 125 kHz / HID)")
    p_scan.add_argument(
        "--all",
        action="store_true",
        help="Skanuje kolejno 13.56 MHz (ISO14443A), 125 kHz (EM4100) oraz HID Prox",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_r125 = sub.add_parser("read-125k", help="Odczytuje kartę 125 kHz (EM4100 / T5577)")
    p_r125.add_argument(
        "--freq",
        type=int,
        default=DEFAULT_LF_FREQ_HZ,
        help=f"Częstotliwość odczytu w Hz (domyślnie {DEFAULT_LF_FREQ_HZ})",
    )
    p_r125.set_defaults(func=_cmd_read_125k)

    p_rhid = sub.add_parser("read-hid", help="Odczytuje kartę HID Prox (26–37 bitów)")
    p_rhid.set_defaults(func=_cmd_read_hid)

    p_rm = sub.add_parser("read-mifare", help="Odczytuje sektory Mifare Classic podanymi/domyślnymi kluczami")
    p_rm.add_argument("--key", action="append", help="6-bajtowy klucz hex (można podać wielokrotnie)")
    p_rm.add_argument("--sectors", type=int, default=16, choices=(5, 16, 40), help="Liczba sektorów")
    p_rm.add_argument("-o", "--output", help="Zapisz odczytany zrzut do pliku .dump")
    p_rm.set_defaults(func=_cmd_read_mifare)

    p_wb = sub.add_parser("write-block", help="Zapisuje 16-bajtowy blok Mifare Classic")
    p_wb.add_argument("--block", type=int, required=True, help="Numer bloku")
    p_wb.add_argument("--data", required=True, help="16 bajtów danych w hex (32 znaki)")
    p_wb.add_argument("--key", default="FFFFFFFFFFFF", help="6-bajtowy klucz hex")
    p_wb.add_argument("--key-type", default="A", choices=("A", "B"), help="Typ klucza (A/B)")
    p_wb.set_defaults(func=_cmd_write_block)

    p_wm = sub.add_parser("write-mifare", help="Zapisuje pełny zrzut .dump/.bin na kartę Mifare Classic")
    p_wm.add_argument("dump_file", help="Ścieżka do pliku zrzutu (.dump / .bin)")
    p_wm.add_argument("--key", action="append", help="6-bajtowy klucz hex (można podać wielokrotnie)")
    p_wm.add_argument("--key-file", help="Plik tekstowy z kluczami 6 B w hex (jeden klucz na linię)")
    p_wm.add_argument(
        "--write-block0",
        action="store_true",
        help="Zapisz także blok 0 producenta (wymaga karty CUID/Gen2 oraz potwierdzenia)",
    )
    p_wm.add_argument(
        "--no-trailers",
        action="store_true",
        help="Pomiń zapis bloków trailerów sektorów (zachowaj obecne klucze i bity dostępu)",
    )
    p_wm.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Pomiń interaktywne potwierdzenie podczas zapisu z --write-block0",
    )
    p_wm.set_defaults(func=_cmd_write_mifare)

    p_fm = sub.add_parser(
        "format-mifare",
        help="Formatuje kartę Mifare Classic (zeruje bloki danych bez bloku 0 i przywraca klucze FF..FF)",
    )
    p_fm.add_argument(
        "--sectors",
        type=int,
        default=16,
        choices=(5, 16, 32, 40),
        help="Liczba sektorów karty (domyślnie 16)",
    )
    p_fm.add_argument("--key", action="append", help="6-bajtowy klucz hex (można podać wielokrotnie)")
    p_fm.add_argument("--key-file", help="Plik tekstowy z kluczami 6 B w hex (jeden klucz na linię)")
    p_fm.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Pomiń interaktywne potwierdzenie formatowania",
    )
    p_fm.set_defaults(func=_cmd_format_mifare)

    p_rn = sub.add_parser("read-ntag", help="Odczytuje wersję i wszystkie strony karty NTAG/Ultralight")
    p_rn.add_argument("--password", help="Opcjonalne 4-bajtowe hasło NTAG (8 znaków hex)")
    p_rn.add_argument("-o", "--output", help="Zapisz odczytany zrzut do pliku .dump")
    p_rn.set_defaults(func=_cmd_read_ntag)

    p_wn = sub.add_parser("write-ntag", help="Zapisuje 4-bajtową stronę NTAG")
    p_wn.add_argument("--page", type=int, required=True, help="Numer strony")
    p_wn.add_argument("--data", required=True, help="4 bajty danych w hex (8 znaków)")
    p_wn.add_argument("--password", help="Opcjonalne 4-bajtowe hasło NTAG (8 znaków hex)")
    p_wn.set_defaults(func=_cmd_write_ntag)

    p_rndef = sub.add_parser("read-ndef", help="Odczytuje i dekoduje rekordy NDEF z pamięci użytkownika NTAG")
    p_rndef.add_argument("--password", help="Opcjonalne 4-bajtowe hasło NTAG (8 znaków hex)")
    p_rndef.set_defaults(func=_cmd_read_ndef)

    p_wndef = sub.add_parser("write-ndef", help="Zapisuje rekord NDEF (URI lub Text) na kartę NTAG")
    ndef_group = p_wndef.add_mutually_exclusive_group(required=True)
    ndef_group.add_argument("--uri", help="Adres URI/URL do zapisania (np. https://example.com)")
    ndef_group.add_argument("--text", help="Tekst UTF-8 do zapisania w rekordzie NDEF Text")
    p_wndef.add_argument("--lang", default="pl", help="Kod języka dla rekordu --text (domyślnie pl)")
    p_wndef.add_argument("--password", help="Opcjonalne 4-bajtowe hasło NTAG (8 znaków hex)")
    p_wndef.set_defaults(func=_cmd_write_ndef)

    p_apdu = sub.add_parser("apdu", help="Wysyła surowe polecenie ISO 7816-4 APDU przez InDataExchange")
    p_apdu.add_argument("hex_apdu", help="Bajty APDU w hex (np. 00A4040000)")
    p_apdu.add_argument("--init-rf", action="store_true", help="Zainicjuj pole RF i wykryj kartę przed wysłaniem APDU")
    p_apdu.set_defaults(func=_cmd_apdu)

    p_lfc = sub.add_parser("lf-convert", help="Konwertuje formaty identyfikatora 125 kHz EM4100 (HEX / DEC10 / DEC8)")
    p_lfc.add_argument("value", help="Wartość wejściowa (np. 4D0088BC89, 0008961161, 13648265 lub 136,48265)")
    p_lfc.add_argument(
        "--format",
        default="auto",
        choices=("auto", "hex", "dec10", "dec8", "fc_cn"),
        help="Jawny format wejścia (domyślnie auto)",
    )
    p_lfc.add_argument("--version-byte", default="0x00", help="Bajt wersji/prefiksu b0 przy konwersji z DEC (domyślnie 0x00)")
    p_lfc.set_defaults(func=_cmd_lf_convert)

    p_dj = sub.add_parser("dump-json", help="Eksportuje plik zrzutu Mifare Classic (.dump/.bin) do JSON")
    p_dj.add_argument("dump_file", help="Ścieżka do pliku zrzutu (.dump / .bin)")
    p_dj.add_argument("-o", "--output", help="Zapisz wynik JSON do pliku (domyślnie wypisuje na stdout)")
    p_dj.set_defaults(func=_cmd_dump_json)

    p_wt5 = sub.add_parser("write-t5577", help="Zapisuje ID 125 kHz (EM4100 lub HID Prox) na czysty transponder T5577")
    t5_group = p_wt5.add_mutually_exclusive_group(required=True)
    t5_group.add_argument("--em4100", help="ID EM4100 (40-bit HEX, DEC 10-cyfr. lub DEC 8-cyfr.)")
    t5_group.add_argument("--hid", help="Surowy 6-bajtowy ID HID Prox w hex (12 znaków)")
    p_wt5.add_argument(
        "--freq",
        type=int,
        default=DEFAULT_LF_FREQ_HZ,
        help=f"Częstotliwość zapisu w Hz (domyślnie {DEFAULT_LF_FREQ_HZ})",
    )
    p_wt5.add_argument("--no-verify", action="store_true", help="Pomiń weryfikację odczytem po zapisie")
    p_wt5.set_defaults(func=_cmd_write_t5577)

    p_aud = sub.add_parser("audit", help="Wykonuje nieinwazyjny Audyt Bezpieczeństwa Karty (z czytnika lub pliku .dump)")
    p_aud.add_argument("--dump", help="Opcjonalna ścieżka do pliku zrzutu (.dump / .bin) zamiast odczytu z czytnika")
    p_aud.add_argument("--key", action="append", help="6-bajtowy klucz hex dla kart Mifare (można podać wielokrotnie)")
    p_aud.add_argument("--key-file", help="Plik tekstowy (.txt/.dic) z kluczami 6 B w hex")
    p_aud.add_argument("-o", "--output", help="Zapisz raport audytu do pliku (.html, .md lub .json)")
    p_aud.add_argument("--unmask", action="store_true", help="Wyłącz domyślne maskowanie wykrytych kluczy w raporcie")
    p_aud.set_defaults(func=_cmd_audit)

    p_di = sub.add_parser("dump-info", help="Wyświetla zawartość pliku .dump/.bin")
    p_di.add_argument("file", help="Ścieżka do pliku zrzutu")
    p_di.set_defaults(func=_cmd_dump_info)

    p_dd = sub.add_parser("dump-diff", help="Porównuje dwa pliki zrzutów")
    p_dd.add_argument("left", help="Pierwszy plik .dump")
    p_dd.add_argument("right", help="Drugi plik .dump")
    p_dd.add_argument("--block-size", type=int, default=16, choices=(4, 16), help="Rozmiar bloku (16=Mifare, 4=NTAG)")
    p_dd.set_defaults(func=_cmd_dump_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (TransportError, ProtocolError, ValueError, FileNotFoundError) as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
