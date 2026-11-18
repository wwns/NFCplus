"""Dekodowanie i budowanie rekordów NDEF (URI / Text) w formacie TLV dla NTAG / Ultralight."""

from __future__ import annotations

from dataclasses import dataclass

NDEF_URI_PREFIXES: tuple[str, ...] = (
    "",
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cap://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:",
)

_URI_PREFIX_SEARCH_ORDER: tuple[tuple[int, str], ...] = tuple(
    sorted(
        ((idx, prefix) for idx, prefix in enumerate(NDEF_URI_PREFIXES) if idx > 0 and prefix),
        key=lambda item: len(item[1]),
        reverse=True,
    )
)


@dataclass(frozen=True)
class NdefRecord:
    """Pojedynczy zdekodowany rekord NDEF."""

    tnf: int
    record_type: str
    summary: str
    payload: bytes
    text: str | None = None
    uri: str | None = None
    language: str | None = None


def _decode_ndef_record(tnf: int, rec_type_bytes: bytes, payload: bytes) -> NdefRecord:
    if tnf == 0x01:
        record_type = rec_type_bytes.decode("ascii", errors="replace")
        if rec_type_bytes == b"U" and len(payload) >= 1:
            code = payload[0]
            prefix = NDEF_URI_PREFIXES[code] if code < len(NDEF_URI_PREFIXES) else ""
            uri_value = prefix + payload[1:].decode("utf-8", errors="replace")
            return NdefRecord(
                tnf=tnf,
                record_type=record_type,
                summary=f"URI: {uri_value}",
                payload=payload,
                uri=uri_value,
            )
        if rec_type_bytes == b"T" and len(payload) >= 1:
            status = payload[0]
            is_utf16 = bool(status & 0x80)
            lang_len = status & 0x3F
            lang_bytes = payload[1 : 1 + lang_len]
            text_bytes = payload[1 + lang_len :]
            language = lang_bytes.decode("ascii", errors="replace")
            encoding = "utf-16" if is_utf16 else "utf-8"
            text_value = text_bytes.decode(encoding, errors="replace")
            summary = f"Text ({language}): {text_value}" if language else f"Text: {text_value}"
            return NdefRecord(
                tnf=tnf,
                record_type=record_type,
                summary=summary,
                payload=payload,
                text=text_value,
                language=language,
            )
        hex_preview = payload.hex(" ").upper()
        return NdefRecord(
            tnf=tnf,
            record_type=record_type,
            summary=f"WKT {record_type} ({len(payload)} B): {hex_preview}" if hex_preview else f"WKT {record_type} (0 B)",
            payload=payload,
        )

    record_type = rec_type_bytes.decode("ascii", errors="replace") or f"TNF-{tnf}"
    hex_preview = payload.hex(" ").upper()
    summary = (
        f"TNF={tnf} {record_type} ({len(payload)} B): {hex_preview}"
        if hex_preview
        else f"TNF={tnf} {record_type} (0 B)"
    )
    return NdefRecord(
        tnf=tnf,
        record_type=record_type,
        summary=summary,
        payload=payload,
    )


def _parse_ndef_message(message: bytes) -> list[NdefRecord]:
    records: list[NdefRecord] = []
    pos = 0
    total = len(message)
    while pos < total:
        if pos + 2 > total:
            break
        hdr = message[pos]
        tnf = hdr & 0x07
        sr = bool(hdr & 0x10)
        il = bool(hdr & 0x08)
        me = bool(hdr & 0x40)
        type_len = message[pos + 1]
        cursor = pos + 2

        if sr:
            if cursor >= total:
                break
            payload_len = message[cursor]
            cursor += 1
        else:
            if cursor + 4 > total:
                break
            payload_len = int.from_bytes(message[cursor : cursor + 4], "big")
            cursor += 4

        if il:
            if cursor >= total:
                break
            id_len = message[cursor]
            cursor += 1
        else:
            id_len = 0

        if cursor + type_len + id_len + payload_len > total:
            break

        rec_type = bytes(message[cursor : cursor + type_len])
        cursor += type_len + id_len
        payload = bytes(message[cursor : cursor + payload_len])
        cursor += payload_len

        records.append(_decode_ndef_record(tnf, rec_type, payload))
        pos = cursor
        if me:
            break
    return records


def parse_ndef_tlv(user_memory: bytes) -> list[NdefRecord]:
    """Ekstrahuje i parsuje rekordy NDEF z bloków TLV (tag 0x03) pamięci użytkownika NTAG/Ultralight."""
    records: list[NdefRecord] = []
    pos = 0
    total = len(user_memory)

    while pos < total:
        tag = user_memory[pos]
        if tag == 0x00:
            pos += 1
            continue
        if tag == 0xFE:
            break
        if pos + 1 >= total:
            break

        length = user_memory[pos + 1]
        if length == 0xFF:
            if pos + 3 >= total:
                break
            length = (user_memory[pos + 2] << 8) | user_memory[pos + 3]
            val_start = pos + 4
        else:
            val_start = pos + 2

        val_end = val_start + length
        if val_end > total:
            break

        if tag == 0x03 and length > 0:
            records.extend(_parse_ndef_message(user_memory[val_start:val_end]))

        pos = val_end

    return records


def _build_single_wkt_record(record_type: bytes, payload: bytes) -> bytes:
    if len(payload) <= 0xFF:
        header = bytes([0xD1, len(record_type), len(payload)])  # MB=1, ME=1, SR=1, TNF=1
    else:
        header = bytes([0xC1, len(record_type)]) + len(payload).to_bytes(4, "big")
    return header + record_type + payload


def _wrap_ndef_tlv(ndef_message: bytes) -> bytes:
    msg_len = len(ndef_message)
    if msg_len < 0xFF:
        tlv_hdr = bytes([0x03, msg_len])
    else:
        tlv_hdr = b"\x03\xff" + msg_len.to_bytes(2, "big")
    raw = tlv_hdr + ndef_message + b"\xfe"
    pad_len = (-len(raw)) % 4
    return raw + (b"\x00" * pad_len)


def build_ndef_uri_tlv(uri: str) -> bytes:
    """Buduje kompletny bufor NDEF URI TLV (03 <len> ... FE) dopełniony zerami do wielokrotności 4 B."""
    if not uri:
        raise ValueError("URI nie może być puste.")
    prefix_code = 0x00
    remainder = uri
    for code, prefix in _URI_PREFIX_SEARCH_ORDER:
        if uri.startswith(prefix):
            prefix_code = code
            remainder = uri[len(prefix) :]
            break
    payload = bytes([prefix_code]) + remainder.encode("utf-8")
    return _wrap_ndef_tlv(_build_single_wkt_record(b"U", payload))


def build_ndef_text_tlv(text: str, lang: str = "pl") -> bytes:
    """Buduje kompletny bufor NDEF Text UTF-8 TLV (03 <len> ... FE) dopełniony zerami do wielokrotności 4 B."""
    try:
        lang_bytes = lang.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"Kod języka NDEF musi być w ASCII: {lang!r}") from exc
    if len(lang_bytes) > 0x3F:
        raise ValueError("Kod języka NDEF nie może przekraczać 63 znaków.")
    payload = bytes([len(lang_bytes)]) + lang_bytes + text.encode("utf-8")
    return _wrap_ndef_tlv(_build_single_wkt_record(b"T", payload))
