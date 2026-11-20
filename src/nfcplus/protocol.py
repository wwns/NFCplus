"""Implementacja protokołu USB HID czytników wCopy / Xixei / NFC Pro."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Sequence

from .dump import FACTORY_MIFARE_TRAILER, MifareDump, validate_access_bits
from .transport import HIDTransport, NoSmartCardError, TransportError

REPORT_SIZE = 64
MAX_PAYLOAD_SIZE = 48

START_NATIVE = 0x01
END_NATIVE = 0xFE

START_PN532 = 0x02
END_PN532 = 0xFD

PN532_HOST_TO_CHIP = 0xD4
PN532_CHIP_TO_HOST = 0xD5

DEFAULT_LF_FREQ_HZ = 125_000

DEFAULT_MIFARE_KEYS: tuple[bytes, ...] = (
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("4D3A99C351DD"),
    bytes.fromhex("1A982C7E459A"),
    bytes.fromhex("AABBCCDDEEFF"),
)

# Mapowanie nazw z firmware (FUN_140001da0) na nazwy czytelne dla użytkownika
MODEL_ALIASES: dict[str, str] = {
    "wCopy NSR106-HIDIC V805N": "NFC V5.5 IC&HID (NSR106-HIDIC V805N)",
    "wCopy NSR106-IC V801N1": "NFC V5.4.5 IC (NSR106-IC V801N1)",
    "wCopy NSR106-IDIC V801N1": "NFC V5.4.5 IC&ID (NSR106-IDIC V801N1)",
    "wCopy NSR106-IDIC V705N7": "NFC V5.3.7 IC&ID (NSR106-IDIC V705N7)",
    "wCopy WBW106-IDIC V705N7": "NFC V5.3.7 IC&ID (WBW106-IDIC V705N7)",
    "wCopy WBW106-IDIC V705N6": "NFC V5.3.6 IC&ID (WBW106-IDIC V705N6)",
    "wCopy NSR106-IDIC V705N6": "NFC V5.3.5 IC&ID (NSR106-IDIC V705N6)",
    "wCopy NSR106-IDIC V705N5": "NFC V5.3.4 IC&ID (NSR106-IDIC V705N5)",
    "wCopy NSR106-IDIC V705N3": "NFC V5.3.3 IC&ID (NSR106-IDIC V705N3)",
    "wCopy NSR106-IDIC V705N2": "NFC V5.3.2 IC&ID (NSR106-IDIC V705N2)",
    "wCopy NSR106-IDIC V705N1": "NFC V5.3.1 IC&ID (NSR106-IDIC V705N1)",
    "wCopy NSR106-IC V705N6": "NFC V5.3.4 IC (NSR106-IC V705N6)",
    "wCopy NSR106-IC V705N3": "NFC V5.3.3 IC (NSR106-IC V705N3)",
    "wCopy NSR106-IC V705N2": "NFC V5.3.2 IC (NSR106-IC V705N2)",
    "wCopy NSR106-IC V705N1": "NFC V5.3.1 IC (NSR106-IC V705N1)",
}

# Tabela wersji NTAG / Ultralight EV1 z FUN_1400563b0
NTAG_STORAGE_MAP: dict[int, tuple[str, int, int]] = {
    0x00: ("MF0UL11 (48 B user)", 20, 80),
    0x0B: ("MF0UL11 (48 B user)", 20, 80),
    0x0E: ("MF0UL21 (128 B user)", 41, 164),
    0x0F: ("NTAG213 (144 B user)", 45, 180),
    0x11: ("NTAG215 (504 B user)", 135, 540),
    0x13: ("NTAG216 (888 B user)", 231, 924),
}


class ProtocolError(RuntimeError):
    """Błąd ramki lub odpowiedzi protokołu czytnika."""


@dataclass(frozen=True)
class CardInfo:
    """Informacje o wykrytej karcie ISO14443A."""

    uid: bytes
    atqa: bytes
    sak: int
    card_type: str

    @property
    def uid_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.uid)

    @property
    def atqa_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.atqa)


@dataclass(frozen=True)
class NtagVersion:
    """Informacje o wersji układu NTAG / Mifare Ultralight EV1."""

    raw: bytes
    name: str
    total_pages: int
    total_bytes: int

    @property
    def user_pages(self) -> int:
        """Liczba stron pamięci użytkownika (od strony 4 w górę, z wyłączeniem stron konfiguracji/PWD)."""
        known = {20: 12, 41: 32, 45: 36, 135: 126, 231: 222}
        if self.total_pages in known:
            return known[self.total_pages]
        return max(0, self.total_pages - 9)

    @property
    def user_end_page(self) -> int:
        """Indeks pierwszej strony poza pamięcią użytkownika (wyłączny koniec zakresu)."""
        return 4 + self.user_pages


@dataclass(frozen=True)
class ApduResponse:
    """Odpowiedź karty ISO 7816-4 APDU (dane + SW1/SW2)."""

    data: bytes
    sw1: int
    sw2: int

    @property
    def status_word(self) -> str:
        return f"{self.sw1:02X}{self.sw2:02X}"

    @property
    def is_ok(self) -> bool:
        return self.sw1 == 0x90 and self.sw2 == 0x00


def parse_hex_bytes(text: str) -> bytes:
    """Parsuje ciąg szesnastkowy (z opcjonalnymi spacjami/dwukropkami/myślnikami) na bajty."""
    cleaned = text.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "").replace(":", "").replace("-", "")
    if not cleaned or len(cleaned) % 2 != 0:
        raise ValueError(f"Nieprawidłowa długość zapisu szesnastkowego: {text!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Nieprawidłowe znaki szesnastkowe: {text!r}") from exc


@dataclass
class MifareWriteReport:
    """Raport zbiorczy z zapisu zrzutu lub formatowania karty Mifare Classic."""

    written_blocks: list[int]
    skipped_blocks: list[int]
    failed_blocks: dict[int, str]
    sector_auth: dict[int, tuple[bool, bool]]
    card: CardInfo | None = None


def sector_auth_from_keys(
    found_keys: dict[int, tuple[bytes | None, bytes | None]],
) -> dict[int, tuple[bool, bool]]:
    """Konwertuje mapę znalezionych kluczy sektorów na słownik statusów (KeyA_ok, KeyB_ok)."""
    return {sector: (ka is not None, kb is not None) for sector, (ka, kb) in found_keys.items()}


def _normalize_mifare_keys(keys: Sequence[bytes]) -> list[bytes]:
    """Waliduje listę kluczy 6 B, usuwa duplikaty i dopisuje fabryczny klucz FF..FF jako fallback."""
    factory_key = bytes.fromhex("FFFFFFFFFFFF")
    normalized: list[bytes] = []
    for key in keys:
        if len(key) != 6:
            raise ValueError("Klucz Mifare Classic musi mieć dokładnie 6 bajtów.")
        if key not in normalized:
            normalized.append(key)
    if factory_key not in normalized:
        normalized.append(factory_key)
    return normalized


@dataclass(frozen=True)
class EM4100Card:
    """Informacje o wykrytej karcie 125 kHz (EM4100 / T5577)."""

    raw: bytes
    freq_hz: int = DEFAULT_LF_FREQ_HZ

    @property
    def hex_id(self) -> str:
        return self.raw.hex().upper()

    @property
    def hex_spaced(self) -> str:
        return " ".join(f"{b:02X}" for b in self.raw)

    @property
    def decimal_10(self) -> str:
        return f"{int.from_bytes(self.raw[1:5], 'big'):010d}"

    @property
    def wiegand_fc(self) -> int:
        return self.raw[2]

    @property
    def wiegand_cn(self) -> int:
        return (self.raw[3] << 8) | self.raw[4]

    @property
    def wiegand_26(self) -> str:
        return f"{self.wiegand_fc:03d}{self.wiegand_cn:05d}"

    @classmethod
    def from_decimal_10(
        cls,
        value: int | str,
        *,
        version_byte: int = 0x00,
        freq_hz: int = DEFAULT_LF_FREQ_HZ,
    ) -> EM4100Card:
        num = int(value, 10) if isinstance(value, str) else int(value)
        if not 0 <= num <= 0xFFFFFFFF:
            raise ValueError(f"Wartość 10-cyfrowa EM4100 musi mieścić się w 0..4294967295, podano {value!r}.")
        id5 = bytes([version_byte & 0xFF]) + num.to_bytes(4, "big")
        return cls(raw=id5, freq_hz=freq_hz)

    @classmethod
    def from_wiegand(
        cls,
        fc: int,
        cn: int,
        *,
        version_byte: int = 0x00,
        prefix_byte: int = 0x00,
        freq_hz: int = DEFAULT_LF_FREQ_HZ,
    ) -> EM4100Card:
        if not 0 <= fc <= 0xFF:
            raise ValueError(f"Facility Code (FC) musi wynosić 0..255, podano {fc}.")
        if not 0 <= cn <= 0xFFFF:
            raise ValueError(f"Card Number (CN) musi wynosić 0..65535, podano {cn}.")
        id5 = bytes([version_byte & 0xFF, prefix_byte & 0xFF, fc, (cn >> 8) & 0xFF, cn & 0xFF])
        return cls(raw=id5, freq_hz=freq_hz)


@dataclass(frozen=True)
class HIDProxCard:
    """Informacje o wykrytej karcie HID Prox (16 / 26–37 bitów / surowy 48-bit)."""

    raw: bytes
    bit_length: int | None
    facility_code: int | None
    card_number: int | None
    format_name: str
    short_id: int
    extra: int = 0
    parity_valid: bool | None = True

    @property
    def raw_hex(self) -> str:
        return self.raw.hex().upper()

    @property
    def raw_spaced(self) -> str:
        return " ".join(f"{b:02X}" for b in self.raw)


def decode_em4100(id5: bytes, freq_hz: int = DEFAULT_LF_FREQ_HZ) -> EM4100Card:
    """Buduje strukturę EM4100Card z 5-bajtowego identyfikatora [b0..b4]."""
    if len(id5) != 5:
        raise ValueError(f"Identyfikator EM4100 musi mieć dokładnie 5 bajtów, podano {len(id5)}.")
    return EM4100Card(raw=bytes(id5), freq_hz=freq_hz)


def convert_em4100_formats(
    value: str,
    *,
    source_format: str = "auto",
    version_byte: int = 0x00,
    freq_hz: int = DEFAULT_LF_FREQ_HZ,
) -> EM4100Card:
    """Konwertuje dwukierunkowo formaty EM4100: 40-bit HEX, DEC 10-cyfr., DEC 8-cyfr. (FC+CN) oraz (fc, cn)."""
    raw_text = value.strip()
    fmt = source_format.lower()
    if fmt not in ("auto", "hex", "dec10", "dec8", "fc_cn"):
        raise ValueError(f"Nieznany format wejściowy EM4100: {source_format!r}")

    if fmt == "auto":
        has_hex_hint = (
            raw_text.lower().startswith("0x")
            or any(ch in " -abcdefABCDEF" for ch in raw_text)
        )
        if "," in raw_text or ":" in raw_text and not has_hex_hint:
            # Jeśli po usunięciu dwukropków ma dokładnie 10 hex i zawiera dwukropki parami, to hex; inaczej FC:CN
            parts = raw_text.replace(":", ",").split(",")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                fmt = "fc_cn"
            else:
                fmt = "hex"
        elif has_hex_hint:
            fmt = "hex"
        elif raw_text.isdigit():
            if len(raw_text) == 8:
                fmt = "dec8"
            elif len(raw_text) == 10 and int(raw_text) <= 0xFFFFFFFF:
                fmt = "dec10"
            elif len(raw_text) == 10:
                fmt = "hex"
            elif int(raw_text) <= 0xFFFFFFFF:
                fmt = "dec10"
            else:
                raise ValueError(f"Nie można rozpoznać formatu EM4100 dla: {value!r}")
        else:
            raise ValueError(f"Nie można rozpoznać formatu EM4100 dla: {value!r}")

    if fmt == "hex":
        id5 = parse_hex_bytes(raw_text)
        return decode_em4100(id5, freq_hz=freq_hz)
    if fmt == "dec10":
        return EM4100Card.from_decimal_10(raw_text, version_byte=version_byte, freq_hz=freq_hz)
    if fmt == "dec8":
        if not raw_text.isdigit() or len(raw_text) != 8:
            raise ValueError(f"Format DEC 8-cyfrowy wymaga dokładnie 8 cyfr (FC3+CN5), podano {value!r}.")
        return EM4100Card.from_wiegand(
            int(raw_text[:3]),
            int(raw_text[3:]),
            version_byte=version_byte,
            freq_hz=freq_hz,
        )
    # fc_cn
    normalized = raw_text.replace(":", ",").replace("/", ",")
    parts = [p.strip() for p in normalized.split(",")]
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError(f"Format FC,CN wymaga dwóch liczb (np. 136,48265), podano {value!r}.")
    return EM4100Card.from_wiegand(
        int(parts[0]),
        int(parts[1]),
        version_byte=version_byte,
        freq_hz=freq_hz,
    )


def encode_em4100_t5577_blocks(id5: bytes) -> tuple[bytes, bytes, bytes]:
    """Koduje 5-bajtowy identyfikator EM4100 na bloki T5577 (block0_cfg, block1, block2) z FUN_140043710."""
    if len(id5) != 5:
        raise ValueError(f"Identyfikator EM4100 musi mieć dokładnie 5 bajtów, podano {len(id5)}.")
    bits: list[int] = [1] * 9
    col_parity = [0, 0, 0, 0]
    for byte in id5:
        for nibble in ((byte >> 4) & 0x0F, byte & 0x0F):
            nibble_bits = [(nibble >> shift) & 1 for shift in (3, 2, 1, 0)]
            bits.extend(nibble_bits)
            bits.append(sum(nibble_bits) & 1)
            for col in range(4):
                col_parity[col] ^= nibble_bits[col]
    bits.extend(col_parity)
    bits.append(0)  # stop bit

    em64 = bytearray(8)
    for idx, bit in enumerate(bits):
        if bit:
            em64[idx // 8] |= 1 << (7 - (idx % 8))

    block0 = bytes.fromhex("00148040")  # RF/64, Manchester, MaxBlk=2, bez hasła
    return block0, bytes(em64[0:4]), bytes(em64[4:8])


def encode_hid_t5577_blocks(raw6: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Koduje 6-bajtowy surowy HID Prox na bloki T5577 (block0_cfg, block1, block2, block3) z 0x1400111b0."""
    if len(raw6) != 6:
        raise ValueError(f"Surowe dane HID Prox muszą mieć dokładnie 6 bajtów, podano {len(raw6)}.")

    def _manchester_nibble(nibble: int) -> int:
        out = 0
        for shift in (3, 2, 1, 0):
            out = (out << 2) | (0b10 if ((nibble >> shift) & 1) else 0b01)
        return out

    encoded = bytearray(12)
    for idx, byte in enumerate(raw6):
        encoded[idx * 2] = _manchester_nibble((byte >> 4) & 0x0F)
        encoded[idx * 2 + 1] = _manchester_nibble(byte & 0x0F)
    encoded[0] = (encoded[0] & 0x03) | 0x1C

    block0 = bytes.fromhex("00107060")  # RF/50, FSK2a, MaxBlk=3
    return block0, bytes(encoded[0:4]), bytes(encoded[4:8]), bytes(encoded[8:12])


def _check_hid_parity(bits: int, bit_length: int) -> bool:
    """Weryfikuje parzystość Wiegand (even dla górnej połowy, odd dla dolnej) z FUN_140046f22."""
    if bit_length == 33:
        mask17 = (1 << 17) - 1
        upper = (bits >> 16) & mask17
        lower = bits & mask17
    elif bit_length % 2 == 0:
        half = bit_length // 2
        mask = (1 << half) - 1
        upper = (bits >> half) & mask
        lower = bits & mask
    else:
        half = bit_length // 2
        upper = (bits >> (half + 1)) & ((1 << half) - 1)
        lower = bits & ((1 << (half + 1)) - 1)
    return (upper.bit_count() % 2 == 0) and (lower.bit_count() % 2 == 1)


def decode_hid_prox(raw6: bytes, extra: int = 0) -> HIDProxCard | None:
    """Dekoduje 6-bajtową odpowiedź HID Prox (16-bit, 26–37 bitów z parzystością lub surowy 48-bit)."""
    if len(raw6) != 6:
        raise ValueError(f"Dane HID Prox muszą mieć dokładnie 6 bajtów, podano {len(raw6)}.")

    raw6 = bytes(raw6)
    b0, b1 = raw6[0], raw6[1]
    w = int.from_bytes(raw6, "big")
    short_id = int.from_bytes(raw6[2:6], "big")

    if b0 == 0x09 and b1 == 0x01:
        return HIDProxCard(
            raw=raw6,
            bit_length=16,
            facility_code=None,
            card_number=(raw6[2] << 8) | raw6[3],
            format_name="HID 16-bit",
            short_id=short_id,
            extra=extra,
            parity_valid=True,
        )

    if b0 != 0x00:
        return HIDProxCard(
            raw=raw6,
            bit_length=None,
            facility_code=None,
            card_number=None,
            format_name="HID Raw (48-bit)",
            short_id=short_id,
            extra=extra,
            parity_valid=None,
        )

    bit_length: int | None = None
    for candidate in range(26, 37):
        if (w >> candidate) == ((1 << (37 - candidate)) | 1):
            bit_length = candidate
            break
    if bit_length is None and (b1 & 0xE0) == 0x00:
        bit_length = 37
    if bit_length is None:
        return None

    bits = w & ((1 << bit_length) - 1)
    if not _check_hid_parity(bits, bit_length):
        return None

    if bit_length == 26:
        facility_code: int | None = (bits >> 17) & 0xFF
        card_number = (bits >> 1) & 0xFFFF
        format_name = "HID 26-bit (H10301)"
    elif bit_length == 37:
        facility_code = (bits >> 20) & 0xFFFF
        card_number = (bits >> 1) & 0x7FFFF
        format_name = "HID 37-bit (H10304)"
    else:
        facility_code = None
        card_number = (bits >> 1) & ((1 << (bit_length - 2)) - 1)
        format_name = f"HID {bit_length}-bit"

    return HIDProxCard(
        raw=raw6,
        bit_length=bit_length,
        facility_code=facility_code,
        card_number=card_number,
        format_name=format_name,
        short_id=short_id,
        extra=extra,
        parity_valid=True,
    )


def classify_iso14443a_card(atqa: bytes, sak: int) -> str:
    """Rozpoznaje przybliżony typ karty ISO14443A na podstawie ATQA i SAK."""
    if sak == 0x08:
        return "MIFARE Classic 1K"
    if sak == 0x18:
        return "MIFARE Classic 4K"
    if sak == 0x09:
        return "MIFARE Classic Mini"
    if sak == 0x10:
        return "MIFARE Plus 2K (SL2)"
    if sak == 0x11:
        return "MIFARE Plus 4K (SL2)"
    if sak == 0x00 and atqa == b"\x00\x44":
        return "MIFARE Ultralight / NTAG"
    if sak == 0x20:
        return "ISO 14443-4 (CPU / DESFire / JC)"
    if sak == 0x28:
        return "MIFARE Classic 1K + ISO 14443-4"
    return f"Nieznana ISO14443A (ATQA={atqa.hex().upper()}, SAK={sak:02X})"


def compute_checksum(frame_without_trailer: bytes) -> int:
    """Oblicza 8-bitową sumę kontrolną: ~sum(bytes) & 0xFF."""
    return (~sum(frame_without_trailer)) & 0xFF


def build_frame(payload: bytes, seq: int) -> bytes:
    """Buduje 64-bajtowy raport HID z nagłówkiem Report ID 0x00 (zgodnie z FUN_1400453f0)."""
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Ładunek przekracza maks. długość {MAX_PAYLOAD_SIZE} B: {len(payload)}")

    total_len = len(payload) + 6
    body = bytes([START_NATIVE, total_len, seq & 0xFF, (seq >> 8) & 0xFF]) + payload
    csum = compute_checksum(body)
    report = bytes([0x00]) + body + bytes([csum, END_NATIVE])
    return report.ljust(REPORT_SIZE, b"\x00")


def parse_frame(raw: bytes) -> tuple[int, int, bytes]:
    """Dekoduje i weryfikuje przychodzącą ramkę 64 B z czytnika."""
    if len(raw) == REPORT_SIZE + 1 and raw[0] == 0x00 and raw[1] in (START_NATIVE, START_PN532):
        raw = raw[1:]

    if len(raw) < 6:
        raise ProtocolError(f"Za krótka odpowiedź z czytnika ({len(raw)} B).")

    start = raw[0]
    if start not in (START_NATIVE, START_PN532):
        raise ProtocolError(f"Nieprawidłowy bajt startowy odpowiedzi: 0x{start:02X}")

    total_len = raw[1]
    if total_len < 6 or total_len > len(raw):
        raise ProtocolError(f"Nieprawidłowa długość ramki: {total_len} (odebrano {len(raw)} B)")

    expected_end = END_NATIVE if start == START_NATIVE else END_PN532
    end_byte = raw[total_len - 1]
    if end_byte != expected_end:
        raise ProtocolError(
            f"Nieprawidłowy bajt końca ramki: 0x{end_byte:02X} (oczekiwano 0x{expected_end:02X})"
        )

    expected_csum = compute_checksum(raw[: total_len - 2])
    actual_csum = raw[total_len - 2]
    if actual_csum != expected_csum:
        raise ProtocolError(
            f"Błąd sumy kontrolnej: odebrano 0x{actual_csum:02X}, obliczono 0x{expected_csum:02X}"
        )

    seq = raw[2] | (raw[3] << 8)
    payload = bytes(raw[4 : total_len - 2])
    return start, seq, payload


def _crc16_a(data: bytes) -> bytes:
    """CRC-16/ISO-IEC-14443-A (start 0x6363) zgodne z FUN_14004a920."""
    crc = 0x6363
    for byte in data:
        b = byte ^ (crc & 0xFF)
        b = (b ^ (b << 4)) & 0xFF
        crc = (crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)
        crc &= 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def _is_pcsc_escape_blocked(exc: Exception) -> bool:
    """Sprawdza, czy błąd wynika z zablokowanego IOCTL_CCID_ESCAPE w sterowniku PC/SC."""
    if isinstance(exc, NoSmartCardError):
        return False
    if isinstance(exc, TransportError):
        return True
    if isinstance(exc, ProtocolError):
        msg = str(exc).upper()
        return any(code in msg for code in ("6D 00", "6E 00", "6F 00", "68 00"))
    return False


def _card_info_from_pcsc_atr(uid: bytes, atr: bytes | None) -> CardInfo:
    """Buduje CardInfo na podstawie UID (FF CA) i opcjonalnego ATR PC/SC 2.01."""
    atqa = b"\x04\x00"
    sak = 0x08
    if atr:
        marker = b"\xa0\x00\x00\x03\x06"
        idx = atr.find(marker)
        if idx != -1 and len(atr) >= idx + 8:
            card_name = (atr[idx + 6], atr[idx + 7])
            if card_name == (0x00, 0x01):
                atqa, sak = b"\x04\x00", 0x08
            elif card_name == (0x00, 0x02):
                atqa, sak = b"\x02\x00", 0x18
            elif card_name == (0x00, 0x03):
                atqa, sak = b"\x44\x00", 0x00
            elif card_name == (0x00, 0x26):
                atqa, sak = b"\x04\x00", 0x09
    elif len(uid) == 7:
        atqa, sak = b"\x44\x00", 0x00
    return CardInfo(
        uid=uid,
        atqa=atqa,
        sak=sak,
        card_type=classify_iso14443a_card(atqa, sak),
    )


class NFCReader:
    """Wysokopoziomowy sterownik czytników wCopy / Xixei / NFC Pro."""

    def __init__(self, transport: HIDTransport, timeout_ms: int = 2000) -> None:
        self._transport = transport
        self._timeout_ms = timeout_ms
        self._seq = 0
        self._set_params_flags = 0x00
        self._pcsc_fallback = False
        self.last_sector_auth: dict[int, tuple[bool, bool]] = {}

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 2) & 0xFFFF
        return seq

    def exchange_raw(
        self,
        payload: bytes,
        expected_start: int | Sequence[int] | None = None,
    ) -> bytes:
        """Wysyła komendę w ramce 64 B i zwraca ładunek odpowiedzi."""
        report = build_frame(payload, self._next_seq())
        self._transport.write(report)
        raw = self._transport.read(REPORT_SIZE + 1, self._timeout_ms)
        start, _seq, resp_payload = parse_frame(raw)
        if expected_start is not None:
            allowed = (expected_start,) if isinstance(expected_start, int) else tuple(expected_start)
            if start not in allowed:
                expected_fmt = "/".join(f"0x{val:02X}" for val in allowed)
                raise ProtocolError(
                    f"Nieoczekiwany typ ramki: 0x{start:02X} (oczekiwano {expected_fmt})"
                )
        return resp_payload

    # ------------------------------------------------------------------
    # Komendy natywne czytnika
    # ------------------------------------------------------------------

    @property
    def transport(self) -> HIDTransport:
        return self._transport

    @property
    def protocol_family(self) -> str:
        return str(getattr(self._transport, "protocol_family", "wcopy_hid"))

    @property
    def is_acr122u(self) -> bool:
        return self.protocol_family == "acr122u"

    @property
    def supports_lf(self) -> bool:
        return bool(getattr(self._transport, "supports_lf", True))

    def _require_lf_support(self) -> None:
        if not self.supports_lf:
            raise ProtocolError("Czytnik ACR122U obsługuje wyłącznie pasmo 13,56 MHz (brak cewki 125 kHz).")

    def get_firmware_version(self) -> str:
        """Pobiera wersję firmware (FF 00 68 dla wCopy lub FF 00 48 00 00 dla ACR122U)."""
        if self.is_acr122u:
            if self._pcsc_fallback:
                return "ACS ACR122U (PC/SC)"
            try:
                resp = self._transport.apdu_exchange(b"\xff\x00\x48\x00\x00", timeout_ms=self._timeout_ms)
                return resp.rstrip(b"\x00").decode("ascii", errors="replace").strip()
            except (TransportError, ProtocolError) as exc:
                if _is_pcsc_escape_blocked(exc):
                    self._pcsc_fallback = True
                return "ACS ACR122U (PC/SC)"
        # Nowsze warianty firmware (np. NSR122-HID V901N1) zwracają ramki 0x02...0xFD także dla komend natywnych.
        resp = self.exchange_raw(b"\xff\x00\x68", expected_start=(START_NATIVE, START_PN532))
        return resp.rstrip(b"\x00").decode("ascii", errors="replace").strip()

    def get_model_name(self) -> str:
        """Pobiera nazwę modelu (FF 00 69 dla wCopy lub nazwę produktu dla ACR122U)."""
        if self.is_acr122u:
            return str(getattr(self._transport, "product", "") or "ACS ACR122U PICC Interface")
        resp = self.exchange_raw(b"\xff\x00\x69", expected_start=(START_NATIVE, START_PN532))
        return resp.rstrip(b"\x00").decode("ascii", errors="replace").strip()

    def get_device_info(self) -> dict[str, str]:
        """Pobiera model, firmware oraz czytelną nazwę wariantu czytnika."""
        fw = self.get_firmware_version()
        model = self.get_model_name()
        combined = f"{fw} - {model}".strip(" -")
        alias = next((label for key, label in MODEL_ALIASES.items() if key in combined), combined)
        return {"firmware": fw, "model": model, "display_name": alias}

    def beep(self, duration_ms: int = 50) -> None:
        """Uruchamia brzęczyk czytnika na podany czas (w ms)."""
        dur = max(1, (duration_ms // 10) & 0xFF)
        if self.is_acr122u:
            if self._pcsc_fallback:
                return
            try:
                resp = self._transport.apdu_exchange(
                    bytes([0xFF, 0x00, 0x40, 0x00, 0x04, dur, 0x00, 0x01, 0x01]),
                    timeout_ms=self._timeout_ms,
                )
            except (TransportError, ProtocolError) as exc:
                if _is_pcsc_escape_blocked(exc):
                    self._pcsc_fallback = True
                return
            # ACR122U zwraca 90 <LED_STATE> (bit 0 = czerwony, bit 1 = zielony), np. 90 00..90 03.
            if len(resp) < 2 or resp[-2] != 0x90:
                raise ProtocolError(f"Błąd brzęczyka ACR122U: {resp.hex(' ')}")
            return
        self.exchange_raw(bytes([0xFF, 0x00, 0x40, 0x50, 0x04, dur, 0x01, 0x01, 0x01]))

    # ------------------------------------------------------------------
    # Tunel PN532-over-HID / PN532-over-ACR122U
    # ------------------------------------------------------------------

    def pn532_command(self, cmd: bytes) -> bytes:
        """Wysyła komendę PN532 przez tunel FF 00 00 00 <len> D4 <cmd>."""
        if not cmd:
            raise ValueError("Komenda PN532 nie może być pusta.")
        tunnel_payload = bytes([0xFF, 0x00, 0x00, 0x00, len(cmd) + 1, PN532_HOST_TO_CHIP]) + cmd
        if self.is_acr122u:
            resp = self._transport.apdu_exchange(tunnel_payload, timeout_ms=self._timeout_ms)
            if len(resp) < 2:
                raise ProtocolError(f"Za krótka odpowiedź tunelu ACR122U: {resp.hex(' ')}")
            if resp[-2:] != b"\x90\x00":
                raise ProtocolError(f"Błąd statusu ACR122U: {resp[-2:].hex(' ').upper()}")
            inner = resp[:-2]
            if len(inner) < 2 or inner[0] != PN532_CHIP_TO_HOST or inner[1] != ((cmd[0] + 1) & 0xFF):
                raise ProtocolError(f"Nieprawidłowa odpowiedź PN532 z ACR122U: {resp.hex(' ')}")
            return inner[2:]

        resp = self.exchange_raw(tunnel_payload, expected_start=START_PN532)
        if len(resp) < 2 or resp[0] != PN532_CHIP_TO_HOST or resp[1] != ((cmd[0] + 1) & 0xFF):
            raise ProtocolError(f"Nieprawidłowa odpowiedź tunelu PN532: {resp.hex(' ')}")
        return resp[2:]

    def read_register(self, reg: int) -> int:
        """Odczytuje pojedynczy rejestr PN532 (komenda 0x06)."""
        resp = self.pn532_command(bytes([0x06, (reg >> 8) & 0xFF, reg & 0xFF]))
        if self.is_acr122u:
            if len(resp) == 1 or (len(resp) == 3 and resp[1:] == b"\x90\x00"):
                return resp[0]
            raise ProtocolError(f"Błąd odczytu rejestru 0x{reg:04X}: {resp.hex(' ')}")
        if len(resp) != 3 or resp[1:] != b"\x90\x00":
            raise ProtocolError(f"Błąd odczytu rejestru 0x{reg:04X}: {resp.hex(' ')}")
        return resp[0]

    def write_register(self, reg: int, mask: int, value: int) -> None:
        """Zapisuje rejestr PN532 z opcjonalną maską bitową (komenda 0x08)."""
        if mask != 0xFF:
            current = self.read_register(reg)
            new_val = ((~mask) & current) | (value & mask)
            if new_val == current:
                return
        else:
            new_val = value & 0xFF

        resp = self.pn532_command(bytes([0x08, (reg >> 8) & 0xFF, reg & 0xFF, new_val]))
        valid = (b"", b"\x90\x00") if self.is_acr122u else (b"\x90\x00",)
        if resp not in valid:
            raise ProtocolError(f"Błąd zapisu rejestru 0x{reg:04X}: {resp.hex(' ')}")

    def set_rf_field(self, enabled: bool) -> None:
        """Włącza lub wyłącza pole anteny RF (RFConfiguration 0x32 0x01)."""
        self.pn532_command(bytes([0x32, 0x01, 0x01 if enabled else 0x00]))

    def set_crc(self, enabled: bool) -> None:
        """Włącza lub wyłącza sprzętowe CRC Tx/Rx (rejestry 0x6302 / 0x6303)."""
        val = 0x80 if enabled else 0x00
        self.write_register(0x6302, 0x80, val)
        self.write_register(0x6303, 0x80, val)

    def set_parity(self, enabled: bool) -> None:
        """Włącza lub wyłącza sprzętową parzystość ISO14443A (rejestr 0x630D)."""
        val = 0x00 if enabled else 0x10
        self.write_register(0x630D, 0x10, val)

    def init_rf(self) -> None:
        """Resetuje i konfiguruje układ RF do pracy z kartami ISO14443A (FUN_14004ae20 + FUN_140042440)."""
        self.set_rf_field(False)
        time.sleep(0.01)
        self.set_rf_field(True)
        # MaxRetries: MxRtyATR=0x00, MxRtyPSL=0x01, MxRtyPassiveActivation=0x02
        self.pn532_command(bytes([0x32, 0x05, 0x00, 0x01, 0x02]))
        # SetParameters: fAutomaticATR_RES (0x10)
        self._set_params_flags = 0x10
        self.pn532_command(bytes([0x12, self._set_params_flags]))
        # Konfiguracja modulacji i szybkości 106 kbps Type A
        self.write_register(0x6302, 0x03, 0x00)
        self.write_register(0x6303, 0x03, 0x00)
        self.write_register(0x6305, 0x40, 0x40)
        self.write_register(0x6302, 0x70, 0x00)
        self.write_register(0x6303, 0x70, 0x00)
        self.write_register(0x6303, 0x08, 0x00)
        self.write_register(0x6303, 0x04, 0x00)
        self.set_crc(True)
        self.set_parity(True)

    # ------------------------------------------------------------------
    # Wykrywanie kart
    # ------------------------------------------------------------------

    def _pcsc_scan_card(self) -> CardInfo | None:
        try:
            resp = self._transport.apdu_exchange(b"\xff\xca\x00\x00\x00", timeout_ms=self._timeout_ms)
        except NoSmartCardError:
            return None
        if len(resp) < 2:
            raise ProtocolError(f"Za krótka odpowiedź PC/SC Get UID: {resp.hex(' ')}")
        sw = resp[-2:]
        if sw in (b"\x6a\x81", b"\x63\x00"):
            return None
        if sw != b"\x90\x00":
            raise ProtocolError(f"Błąd PC/SC Get UID (FF CA): {sw.hex(' ').upper()}")
        uid = resp[:-2]
        atr = self._transport.get_atr() if hasattr(self._transport, "get_atr") else None
        return _card_info_from_pcsc_atr(uid, atr)

    def _pcsc_mifare_auth(self, block: int, key: bytes, kt: str) -> bool:
        load_resp = self._transport.apdu_exchange(b"\xff\x82\x00\x00\x06" + key, timeout_ms=self._timeout_ms)
        if len(load_resp) < 2 or load_resp[-2:] != b"\x90\x00":
            return False
        key_type_byte = 0x60 if kt == "A" else 0x61
        auth_apdu = bytes([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block & 0xFF, key_type_byte, 0x00])
        auth_resp = self._transport.apdu_exchange(auth_apdu, timeout_ms=self._timeout_ms)
        return len(auth_resp) >= 2 and auth_resp[-2:] == b"\x90\x00"

    def _pcsc_read_binary(self, block_or_page: int, length: int) -> bytes:
        apdu = bytes([0xFF, 0xB0, 0x00, block_or_page & 0xFF, length & 0xFF])
        resp = self._transport.apdu_exchange(apdu, timeout_ms=self._timeout_ms)
        if len(resp) < 2 + length or resp[-2:] != b"\x90\x00":
            raise ProtocolError(f"Błąd odczytu PC/SC (FF B0 {block_or_page}): {resp.hex(' ')}")
        return resp[:length]

    def _pcsc_update_binary(self, block_or_page: int, data: bytes) -> None:
        apdu = bytes([0xFF, 0xD6, 0x00, block_or_page & 0xFF, len(data) & 0xFF]) + data
        resp = self._transport.apdu_exchange(apdu, timeout_ms=self._timeout_ms)
        if len(resp) < 2 or resp[-2:] != b"\x90\x00":
            raise ProtocolError(f"Błąd zapisu PC/SC (FF D6 {block_or_page}): {resp.hex(' ')}")

    def scan_card(self, init_rf: bool = True) -> CardInfo | None:
        """Skanuje pojedynczą kartę ISO14443A przez InListPassiveTarget (0x4A) lub PC/SC FF CA."""
        if self.is_acr122u and self._pcsc_fallback:
            return self._pcsc_scan_card()
        try:
            if init_rf:
                self.init_rf()

            resp = self.pn532_command(b"\x4a\x01\x00")
            # Część czytników (np. NSR122-HID V901N1) sygnalizuje brak karty statusem 63 00 zamiast NbTg=0.
            if not resp or resp[0] == 0 or resp == b"\x63\x00":
                return None

            if len(resp) < 6:
                raise ProtocolError(f"Niekompletna odpowiedź InListPassiveTarget: {resp.hex(' ')}")

            atqa = bytes([resp[3], resp[2]])
            sak = resp[4]
            uid_len = resp[5]
            uid = resp[6 : 6 + uid_len]
            if len(uid) != uid_len:
                raise ProtocolError(f"Skrócony UID w odpowiedzi: oczekiwano {uid_len} B, jest {len(uid)} B")

            # Wybór domyślnego 106 kbps (InPSL 0x4E) jak w FUN_14004bda0
            self.pn532_command(b"\x4e\x01\x00\x00")
            self.set_crc(True)
            self.set_parity(True)

            return CardInfo(
                uid=uid,
                atqa=atqa,
                sak=sak,
                card_type=classify_iso14443a_card(atqa, sak),
            )
        except (TransportError, ProtocolError) as exc:
            if isinstance(exc, NoSmartCardError):
                return None
            if self.is_acr122u and _is_pcsc_escape_blocked(exc):
                self._pcsc_fallback = True
                return self._pcsc_scan_card()
            raise

    def high_level_scan(self) -> CardInfo | None:
        """Alternatywne skanowanie wysokopoziomowe komendą FF 00 6B 30 (FUN_140046110)."""
        resp = self.exchange_raw(b"\xff\x00\x6b\x30", expected_start=(START_NATIVE, START_PN532))
        if len(resp) < 7 or resp[-2:] != b"\x90\x00":
            return None
        atqa = bytes([resp[2], resp[1]])
        sak = resp[3]
        uid_len = resp[4]
        uid = resp[5 : 5 + uid_len]
        if uid_len not in (4, 7, 10) or len(uid) != uid_len:
            return None
        return CardInfo(
            uid=uid,
            atqa=atqa,
            sak=sak,
            card_type=classify_iso14443a_card(atqa, sak),
        )

    # ------------------------------------------------------------------
    # MIFARE Classic (wyłącznie znane / podane klucze)
    # ------------------------------------------------------------------

    def mifare_auth(self, block: int, key: bytes, uid: bytes, key_type: str = "A") -> bool:
        """Autoryzuje blok Mifare Classic znanym kluczem A lub B (0x60 / 0x61)."""
        if len(key) != 6:
            raise ValueError("Klucz Mifare Classic musi mieć dokładnie 6 bajtów.")
        if len(uid) < 4:
            raise ValueError("UID musi mieć co najmniej 4 bajty.")
        kt = key_type.upper()
        if kt not in ("A", "B"):
            raise ValueError("Typ klucza musi wynosić 'A' lub 'B'.")

        cmd_code = 0x60 if kt == "A" else 0x61
        if self.is_acr122u and self._pcsc_fallback:
            return self._pcsc_mifare_auth(block, key, kt)
        # Dla 7-bajtowych UID autoryzacja używa ostatnich 4 bajtów lub pierwszych 4 bajtów zależnie od kaskady;
        # zgodnie z FUN_1400426d0 używamy 4 bajtów UID przekazanych w parametrze (dla 7B zwykle uid[-4:]).
        uid4 = uid[-4:] if len(uid) > 4 else uid[:4]
        try:
            resp = self.pn532_command(bytes([0x40, 0x01, cmd_code, block & 0xFF]) + key + uid4)
        except (TransportError, ProtocolError) as exc:
            if self.is_acr122u and _is_pcsc_escape_blocked(exc):
                self._pcsc_fallback = True
                return self._pcsc_mifare_auth(block, key, kt)
            raise
        return len(resp) >= 1 and resp[0] == 0x00

    def mifare_read_block(self, block: int) -> bytes:
        """Odczytuje 16-bajtowy blok Mifare Classic (0x30 lub PC/SC FF B0)."""
        if self.is_acr122u and self._pcsc_fallback:
            return self._pcsc_read_binary(block, 16)
        try:
            resp = self.pn532_command(bytes([0x40, 0x01, 0x30, block & 0xFF]))
        except (TransportError, ProtocolError) as exc:
            if self.is_acr122u and _is_pcsc_escape_blocked(exc):
                self._pcsc_fallback = True
                return self._pcsc_read_binary(block, 16)
            raise
        if self.is_acr122u:
            if len(resp) == 17 and resp[0] == 0x00:
                return resp[1:17]
            if len(resp) == 19 and resp[0] == 0x00 and resp[-2:] == b"\x90\x00":
                return resp[1:17]
            raise ProtocolError(f"Błąd odczytu bloku {block}: {resp.hex(' ')}")
        if len(resp) != 19 or resp[0] != 0x00 or resp[-2:] != b"\x90\x00":
            raise ProtocolError(f"Błąd odczytu bloku {block}: {resp.hex(' ')}")
        return resp[1:17]

    def mifare_write_block(self, block: int, data: bytes) -> None:
        """Zapisuje 16-bajtowy blok Mifare Classic (0xA0 lub PC/SC FF D6)."""
        if len(data) != 16:
            raise ValueError("Blok Mifare Classic musi mieć dokładnie 16 bajtów.")
        if self.is_acr122u and self._pcsc_fallback:
            self._pcsc_update_binary(block, data)
            return
        try:
            resp = self.pn532_command(bytes([0x40, 0x01, 0xA0, block & 0xFF]) + data)
        except (TransportError, ProtocolError) as exc:
            if self.is_acr122u and _is_pcsc_escape_blocked(exc):
                self._pcsc_fallback = True
                self._pcsc_update_binary(block, data)
                return
            raise
        valid = (b"\x00", b"\x00\x90\x00") if self.is_acr122u else (b"\x00\x90\x00",)
        if resp not in valid:
            raise ProtocolError(f"Błąd zapisu bloku {block}: {resp.hex(' ')}")

    def _authenticate_mifare_sector(
        self,
        first_block: int,
        uid: bytes,
        keys: Sequence[bytes],
    ) -> tuple[bytes | None, bytes | None]:
        """Próbuje autoryzować sektor znanymi kluczami z listy i zwraca (key_a, key_b)."""
        key_a: bytes | None = None
        key_b: bytes | None = None
        needs_reselect = False
        for candidate in keys:
            for key_type in ("A", "B"):
                if (key_type == "A" and key_a is not None) or (key_type == "B" and key_b is not None):
                    continue
                if needs_reselect:
                    try:
                        if self.scan_card(init_rf=False) is None:
                            return key_a, key_b
                    except ProtocolError:
                        return key_a, key_b
                    needs_reselect = False
                try:
                    ok = self.mifare_auth(first_block, candidate, uid, key_type)
                except ProtocolError:
                    ok = False
                if ok:
                    if key_type == "A":
                        key_a = candidate
                    else:
                        key_b = candidate
                else:
                    needs_reselect = True
            if key_a is not None and key_b is not None:
                break
        return key_a, key_b

    def _reselect_and_auth(self, block: int, key: bytes, uid: bytes, key_type: str) -> bool:
        """Ponownie wybiera kartę w polu RF i autoryzuje wskazany blok."""
        try:
            if self.scan_card(init_rf=False) is None:
                return False
            return self.mifare_auth(block, key, uid, key_type)
        except ProtocolError:
            return False

    def mifare_read_sectors(
        self,
        keys: Sequence[bytes],
        sectors: int = 16,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> tuple[CardInfo, list[bytes | None], dict[int, tuple[bytes | None, bytes | None]]]:
        """Odczytuje wszystkie dostępne sektory Mifare Classic przy użyciu listy znanych kluczy."""
        card = self.scan_card(init_rf=True)
        if card is None:
            raise ProtocolError("Nie wykryto karty na czytniku.")

        total_blocks = 20 if sectors <= 5 else (64 if sectors <= 16 else (128 if sectors <= 32 else 256))
        blocks: list[bytes | None] = [None] * total_blocks
        found_keys: dict[int, tuple[bytes | None, bytes | None]] = {}

        for sector in range(sectors):
            first_block = sector * 4 if sector < 32 else 128 + (sector - 32) * 16
            block_count = 4 if sector < 32 else 16
            key_a, key_b = self._authenticate_mifare_sector(first_block, card.uid, keys)

            found_keys[sector] = (key_a, key_b)
            active_key = key_a or key_b
            active_type = "A" if key_a is not None else "B"

            if active_key is None:
                if progress_cb:
                    progress_cb(sector + 1, sectors, f"Sektor {sector:02d}: brak pasującego klucza")
                # Ponowna selekcja karty po nieudanej autoryzacji
                self.scan_card(init_rf=False)
                continue

            # Autoryzujemy wybranym kluczem i czytamy bloki sektora
            if not self.mifare_auth(first_block, active_key, card.uid, active_type):
                self._reselect_and_auth(first_block, active_key, card.uid, active_type)
            for offset in range(block_count):
                blk = first_block + offset
                try:
                    data = bytearray(self.mifare_read_block(blk))
                    # Jeśli to trailer sektora, uzupełniamy znane klucze A/B w zrzucie
                    if offset == block_count - 1:
                        if key_a is not None:
                            data[0:6] = key_a
                        if key_b is not None:
                            data[10:16] = key_b
                    blocks[blk] = bytes(data)
                except ProtocolError:
                    blocks[blk] = None

            if progress_cb:
                progress_cb(sector + 1, sectors, f"Sektor {sector:02d}: odczytano")

        self.last_sector_auth = sector_auth_from_keys(found_keys)
        return card, blocks, found_keys

    def write_mifare_dump(
        self,
        dump: MifareDump,
        keys: Sequence[bytes] = DEFAULT_MIFARE_KEYS,
        *,
        write_block0: bool = False,
        write_trailers: bool = True,
        init_rf: bool = True,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> MifareWriteReport:
        """Zapisuje zrzut MifareDump na kartę z bezpiecznymi blokadami (blok 0 oraz weryfikacja trailerów)."""
        candidate_keys = _normalize_mifare_keys(keys)
        card = self.scan_card(init_rf=init_rf)
        if card is None:
            raise ProtocolError("Nie wykryto karty na czytniku.")

        written_blocks: list[int] = []
        skipped_blocks: list[int] = []
        failed_blocks: dict[int, str] = {}
        sector_auth: dict[int, tuple[bool, bool]] = {}
        total_sectors = dump.sector_count

        for sector in range(total_sectors):
            block_range = dump.sector_block_range(sector)
            first_block = block_range.start
            trailer_block = block_range[-1]

            key_a, key_b = self._authenticate_mifare_sector(first_block, card.uid, candidate_keys)
            sector_auth[sector] = (key_a is not None, key_b is not None)

            active_key = key_a if key_a is not None else key_b
            active_type = "A" if key_a is not None else "B"

            if active_key is None:
                for blk in block_range:
                    if (blk == 0 and not write_block0) or (blk == trailer_block and not write_trailers):
                        skipped_blocks.append(blk)
                    else:
                        failed_blocks[blk] = "Brak pasującego klucza autoryzacji"
                if progress_cb:
                    progress_cb(sector + 1, total_sectors, f"Sektor {sector:02d}: brak pasującego klucza")
                try:
                    self.scan_card(init_rf=False)
                except ProtocolError:
                    pass
                continue

            if not self.mifare_auth(first_block, active_key, card.uid, active_type):
                self._reselect_and_auth(first_block, active_key, card.uid, active_type)

            sector_written = 0
            sector_failed = 0
            for blk in block_range:
                if blk == 0 and not write_block0:
                    skipped_blocks.append(blk)
                    continue
                if blk == trailer_block and not write_trailers:
                    skipped_blocks.append(blk)
                    continue

                block_data = dump.get_block(blk)
                if blk == trailer_block and not validate_access_bits(block_data):
                    failed_blocks[blk] = (
                        "Nieprawidłowe bity dostępu w bloku trailera (zapis zablokowany przed komendą A0)"
                    )
                    sector_failed += 1
                    continue

                try:
                    self.mifare_write_block(blk, block_data)
                    written_blocks.append(blk)
                    sector_written += 1
                except ProtocolError as exc:
                    recovered = False
                    if active_type == "A" and key_b is not None:
                        if self._reselect_and_auth(first_block, key_b, card.uid, "B"):
                            try:
                                self.mifare_write_block(blk, block_data)
                                written_blocks.append(blk)
                                sector_written += 1
                                active_key = key_b
                                active_type = "B"
                                recovered = True
                            except ProtocolError as exc_b:
                                exc = exc_b

                    if not recovered:
                        failed_blocks[blk] = str(exc)
                        sector_failed += 1
                        if blk != trailer_block:
                            self._reselect_and_auth(first_block, active_key, card.uid, active_type)
                        else:
                            try:
                                self.scan_card(init_rf=False)
                            except ProtocolError:
                                pass

            if progress_cb:
                progress_cb(
                    sector + 1,
                    total_sectors,
                    f"Sektor {sector:02d}: zapisano={sector_written}, błędy={sector_failed}",
                )

        self.last_sector_auth = dict(sector_auth)
        return MifareWriteReport(
            written_blocks=written_blocks,
            skipped_blocks=skipped_blocks,
            failed_blocks=failed_blocks,
            sector_auth=sector_auth,
            card=card,
        )

    def format_mifare_card(
        self,
        sectors: int = 16,
        keys: Sequence[bytes] = DEFAULT_MIFARE_KEYS,
        *,
        init_rf: bool = True,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> MifareWriteReport:
        """Formatuje kartę Mifare Classic (zeruje bloki danych z pominięciem bloku 0 i przywraca fabryczny trailer)."""
        blocks_by_sectors = {5: 20, 16: 64, 32: 128, 40: 256}
        if sectors not in blocks_by_sectors:
            raise ValueError(
                f"Nieobsługiwana liczba sektorów: {sectors}. Oczekiwano jednej z wartości: 5, 16, 32, 40."
            )
        dump = MifareDump.empty(blocks_by_sectors[sectors])
        for sector in range(sectors):
            trailer_blk = dump.sector_block_range(sector)[-1]
            dump.set_block(trailer_blk, FACTORY_MIFARE_TRAILER)
        return self.write_mifare_dump(
            dump,
            keys=keys,
            write_block0=False,
            write_trailers=True,
            init_rf=init_rf,
            progress_cb=progress_cb,
        )

    # ------------------------------------------------------------------
    # NTAG / MIFARE Ultralight EV1
    # ------------------------------------------------------------------

    def _pcsc_infer_ntag_version(self) -> NtagVersion:
        """Wnioskuje wariant NTAG z bloku CC (strona 3) w trybie PC/SC."""
        cc = self._pcsc_read_binary(3, 4)
        size_code = cc[2]
        if size_code == 0x12:
            return NtagVersion(raw=b"\x00" * 8, name="NTAG213 (PC/SC)", total_pages=45, total_bytes=180)
        if size_code == 0x3E:
            return NtagVersion(raw=b"\x00" * 8, name="NTAG215 (PC/SC)", total_pages=135, total_bytes=540)
        if size_code == 0x6D:
            return NtagVersion(raw=b"\x00" * 8, name="NTAG216 (PC/SC)", total_pages=231, total_bytes=924)
        pages = max(45, (size_code * 8) // 4 + 9) if size_code else 45
        return NtagVersion(raw=b"\x00" * 8, name="NTAG/Ultralight (PC/SC)", total_pages=pages, total_bytes=pages * 4)

    def ntag_get_version(self) -> NtagVersion:
        """Odczytuje wersję układu NTAG / Ultralight EV1 (0x60 na ACR122U lub 0x62 w wCopy)."""
        if self.is_acr122u:
            if self._pcsc_fallback:
                return self._pcsc_infer_ntag_version()
            try:
                resp = self.pn532_command(b"\x40\x01\x60")
            except (TransportError, ProtocolError) as exc:
                if _is_pcsc_escape_blocked(exc):
                    self._pcsc_fallback = True
                    return self._pcsc_infer_ntag_version()
                raise
            if len(resp) == 9 and resp[0] == 0x00:
                ver = resp[1:9]
            elif len(resp) in (12, 14) and resp[0] == 0x00 and resp[1] == 0x50 and resp[-2:] == b"\x90\x00":
                ver = resp[2:10]
            else:
                raise ProtocolError(f"Karta nie obsługuje polecenia GET_VERSION NTAG: {resp.hex(' ')}")
        else:
            resp = self.pn532_command(b"\x40\x01\x62")
            if len(resp) not in (12, 14) or resp[0] != 0x00 or resp[1] != 0x50 or resp[-2:] != b"\x90\x00":
                raise ProtocolError(f"Karta nie obsługuje polecenia GET_VERSION NTAG: {resp.hex(' ')}")
            ver = resp[2:10]
        storage_code = ver[6]
        name, pages, total_bytes = NTAG_STORAGE_MAP.get(
            storage_code, (f"Nieznany NTAG/UL (0x{storage_code:02X})", 45, 180)
        )
        return NtagVersion(raw=ver, name=name, total_pages=pages, total_bytes=total_bytes)

    def ntag_read_page(self, page: int) -> bytes:
        """Odczytuje pojedynczą 4-bajtową stronę NTAG przez FAST_READ (0x3A) lub PC/SC FF B0."""
        if self.is_acr122u and self._pcsc_fallback:
            return self._pcsc_read_binary(page, 4)
        try:
            resp = self.pn532_command(bytes([0x40, 0x01, 0x3A, page & 0xFF, page & 0xFF]))
        except (TransportError, ProtocolError) as exc:
            if self.is_acr122u and _is_pcsc_escape_blocked(exc):
                self._pcsc_fallback = True
                return self._pcsc_read_binary(page, 4)
            raise
        if self.is_acr122u:
            if len(resp) < 5 or resp[0] != 0x00:
                raise ProtocolError(f"Błąd odczytu strony {page}: {resp.hex(' ')}")
            return resp[1:5]
        if len(resp) < 7 or resp[0] != 0x00 or resp[-2:] != b"\x90\x00":
            raise ProtocolError(f"Błąd odczytu strony {page}: {resp.hex(' ')}")
        page_data = resp[1:5]
        # Weryfikacja CRC-16-A jeśli obecne w odpowiedzi (FUN_14004c350)
        if len(resp) >= 9 and resp[-4:-2] == b"\x30\x00":
            expected_crc = _crc16_a(page_data)
            if resp[5:7] != expected_crc:
                raise ProtocolError(f"Błąd CRC strony {page}: {resp[5:7].hex()} != {expected_crc.hex()}")
        return page_data

    def ntag_pwd_auth(self, password: bytes) -> bytes:
        """Autoryzuje kartę NTAG21x 4-bajtowym hasłem (PWD_AUTH 0x1B) i zwraca 2-bajtowy PACK."""
        if len(password) != 4:
            raise ValueError(f"Hasło NTAG musi mieć dokładnie 4 bajty, podano {len(password)}.")
        resp = self.pn532_command(b"\x40\x01\x1b" + bytes(password))
        if len(resp) == 5 and resp[0] == 0x00 and resp[3:5] == b"\x90\x00":
            return resp[1:3]
        if len(resp) == 3 and resp[0] == 0x00:
            return resp[1:3]
        raise ProtocolError(f"Błąd autoryzacji PWD_AUTH NTAG: {resp.hex(' ')}")

    def ntag_read_all(
        self,
        progress_cb: Callable[[int, int], None] | None = None,
        *,
        password: bytes | None = None,
    ) -> tuple[CardInfo, NtagVersion, list[bytes]]:
        """Wykrywa NTAG, pobiera jego wersję i odczytuje wszystkie strony."""
        card = self.scan_card(init_rf=True)
        if card is None:
            raise ProtocolError("Nie wykryto karty NTAG na czytniku.")
        version = self.ntag_get_version()
        if password is not None:
            self.ntag_pwd_auth(password)
        pages: list[bytes] = []
        for p in range(version.total_pages):
            pages.append(self.ntag_read_page(p))
            if progress_cb:
                progress_cb(p + 1, version.total_pages)
        return card, version, pages

    def ntag_read_user_memory(
        self,
        *,
        password: bytes | None = None,
        init_rf: bool = True,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> tuple[CardInfo, NtagVersion, bytes]:
        """Odczytuje strony pamięci użytkownika NTAG/Ultralight (od strony 4 do końca pamięci użytkownika)."""
        card = self.scan_card(init_rf=init_rf)
        if card is None:
            raise ProtocolError("Nie wykryto karty NTAG na czytniku.")
        version = self.ntag_get_version()
        if password is not None:
            self.ntag_pwd_auth(password)
        end_page = version.user_end_page
        total_user = max(0, end_page - 4)
        buf = bytearray()
        for idx, page in enumerate(range(4, end_page)):
            buf.extend(self.ntag_read_page(page))
            if progress_cb:
                progress_cb(idx + 1, total_user)
        return card, version, bytes(buf)

    def ntag_write_page(
        self,
        page: int,
        data: bytes,
        *,
        password: bytes | None = None,
    ) -> None:
        """Zapisuje 4-bajtową stronę NTAG (komenda 0xA2 lub PC/SC FF D6)."""
        if len(data) != 4:
            raise ValueError("Strona NTAG musi mieć dokładnie 4 bajty.")
        if self.is_acr122u and self._pcsc_fallback:
            if password is not None:
                raise ProtocolError("Autoryzacja hasłem NTAG (PWD_AUTH) wymaga włączonego EscapeCommandEnable.")
            self._pcsc_update_binary(page, data)
            return
        if password is not None:
            self.ntag_pwd_auth(password)
        try:
            resp = self.pn532_command(bytes([0x40, 0x01, 0xA2, page & 0xFF]) + data)
        except (TransportError, ProtocolError) as exc:
            if self.is_acr122u and _is_pcsc_escape_blocked(exc):
                self._pcsc_fallback = True
                if password is not None:
                    raise ProtocolError("Autoryzacja hasłem NTAG (PWD_AUTH) wymaga włączonego EscapeCommandEnable.") from exc
                self._pcsc_update_binary(page, data)
                return
            raise
        valid = (b"\x00", b"\x00\x90\x00") if self.is_acr122u else (b"\x00\x90\x00",)
        if resp not in valid:
            raise ProtocolError(f"Błąd zapisu strony {page}: {resp.hex(' ')}")

    def ntag_write_user_memory(
        self,
        data: bytes,
        start_page: int = 4,
        *,
        password: bytes | None = None,
        init_rf: bool = True,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> int:
        """Zapisuje dane do pamięci użytkownika NTAG po sprawdzeniu pojemności z GET_VERSION."""
        if not data:
            raise ValueError("Dane do zapisu na NTAG nie mogą być puste.")
        if start_page < 4:
            raise ValueError("Zapis pamięci użytkownika NTAG musi zaczynać się co najmniej od strony 4.")
        padded = bytes(data) + (b"\x00" * ((-len(data)) % 4))
        pages_needed = len(padded) // 4

        card = self.scan_card(init_rf=init_rf)
        if card is None:
            raise ProtocolError("Nie wykryto karty NTAG na czytniku.")
        version = self.ntag_get_version()
        if start_page + pages_needed > version.user_end_page:
            available_bytes = max(0, (version.user_end_page - start_page) * 4)
            raise ValueError(
                f"Za mała pojemność {version.name}: potrzeba {len(padded)} B, dostępne {available_bytes} B od strony {start_page}."
            )
        if password is not None:
            self.ntag_pwd_auth(password)

        for idx in range(pages_needed):
            chunk = padded[idx * 4 : (idx + 1) * 4]
            self.ntag_write_page(start_page + idx, chunk)
            if progress_cb:
                progress_cb(idx + 1, pages_needed)
        return pages_needed

    def ntag_write_ndef(
        self,
        tlv_bytes: bytes,
        *,
        password: bytes | None = None,
        init_rf: bool = True,
        progress_cb: Callable[[int, int], None] | None = None,
    ) -> int:
        """Zapisuje bufor NDEF TLV od strony 4 karty NTAG/Ultralight po weryfikacji pojemności."""
        return self.ntag_write_user_memory(
            tlv_bytes,
            start_page=4,
            password=password,
            init_rf=init_rf,
            progress_cb=progress_cb,
        )

    # ------------------------------------------------------------------
    # ISO 7816-4 APDU (ISO14443-4)
    # ------------------------------------------------------------------

    def transceive_apdu(self, apdu: bytes, *, init_rf: bool = False) -> ApduResponse:
        """Wysyła surowe polecenie APDU przez InDataExchange (40 01 <apdu>) i zwraca ApduResponse."""
        if len(apdu) < 4:
            raise ValueError(f"APDU musi mieć co najmniej 4 bajty (CLA INS P1 P2), podano {len(apdu)}.")
        if init_rf:
            card = self.scan_card(init_rf=True)
            if card is None:
                raise ProtocolError("Nie wykryto karty ISO14443A/ISO14443-4 na czytniku.")
        resp = self.pn532_command(b"\x40\x01" + bytes(apdu))
        if len(resp) < 3 or resp[0] != 0x00:
            raise ProtocolError(f"Błąd wymiany APDU: {resp.hex(' ')}")
        return ApduResponse(data=resp[1:-2], sw1=resp[-2], sw2=resp[-1])

    # ------------------------------------------------------------------
    # Karty 125 kHz (EM4100 / T5577) oraz HID Prox
    # ------------------------------------------------------------------

    def _t5577_command(self, freq_hz: int, body: bytes) -> bytes:
        if freq_hz <= 0 or freq_hz > 0xFFFFFFFF:
            raise ValueError(f"Nieprawidłowa częstotliwość 125 kHz: {freq_hz}")
        payload = b"\xff\x00\x66\x00\x1e" + freq_hz.to_bytes(4, "little") + body
        resp = self.exchange_raw(payload, expected_start=(START_NATIVE, START_PN532))
        if not ((len(resp) >= 1 and resp[0] == 0x05) or resp == b"\x90\x00"):
            raise ProtocolError(f"Błąd komendy zapisu T5577 (FF 00 66): {resp.hex(' ')}")
        return resp

    def write_em4100_t5577(
        self,
        id5: bytes,
        freq_hz: int = DEFAULT_LF_FREQ_HZ,
        *,
        verify: bool = True,
        init_rf: bool = True,
    ) -> EM4100Card:
        """Zapisuje 5-bajtowy identyfikator EM4100 na czysty transponder T5577 (FF 00 66 00 1E ...)."""
        self._require_lf_support()
        block0, block1, block2 = encode_em4100_t5577_blocks(id5)
        if init_rf:
            self.init_rf()
        self._t5577_command(freq_hz, b"\x00\x14\x00\x00\x00")
        self._t5577_command(freq_hz, bytes.fromhex("1F1801EF009B008601"))
        self._t5577_command(freq_hz, b"\x12\x00\x01" + block1)
        self._t5577_command(freq_hz, b"\x12\x00\x02" + block2)
        self._t5577_command(freq_hz, b"\x12\x00\x00" + block0)
        self._t5577_command(freq_hz, b"\x00\x64\x00\x00\x00")

        if not verify:
            return decode_em4100(id5, freq_hz=freq_hz)
        read_back = self.read_em4100(freq_hz=freq_hz, init_rf=False)
        if read_back is None or read_back.raw != bytes(id5):
            got = read_back.hex_id if read_back is not None else "<brak odpowiedzi>"
            raise ProtocolError(f"Weryfikacja zapisu EM4100 na T5577 nie powiodła się (odczytano: {got}).")
        return read_back

    def write_hid_t5577(
        self,
        raw6: bytes,
        freq_hz: int = DEFAULT_LF_FREQ_HZ,
        *,
        verify: bool = True,
        init_rf: bool = True,
    ) -> HIDProxCard:
        """Zapisuje 6-bajtowy identyfikator HID Prox na czysty transponder T5577 (FF 00 66 00 1E ...)."""
        self._require_lf_support()
        block0, block1, block2, block3 = encode_hid_t5577_blocks(raw6)
        if init_rf:
            self.init_rf()
        self._t5577_command(freq_hz, b"\x00\x14\x00\x00\x00")
        self._t5577_command(freq_hz, bytes.fromhex("1F1801EF009B008601"))
        self._t5577_command(freq_hz, b"\x12\x00\x01" + block1)
        self._t5577_command(freq_hz, b"\x12\x00\x02" + block2)
        self._t5577_command(freq_hz, b"\x12\x00\x03" + block3)
        self._t5577_command(freq_hz, b"\x12\x00\x00" + block0)
        self._t5577_command(freq_hz, b"\x00\x64\x00\x00\x00")

        if verify:
            read_back = self.read_hid_prox(init_rf=False)
            if read_back is None or read_back.raw != bytes(raw6):
                got = read_back.raw_hex if read_back is not None else "<brak odpowiedzi>"
                raise ProtocolError(f"Weryfikacja zapisu HID Prox na T5577 nie powiodła się (odczytano: {got}).")
            return read_back
        decoded = decode_hid_prox(raw6)
        if decoded is not None:
            return decoded
        return HIDProxCard(
            raw=bytes(raw6),
            bit_length=None,
            facility_code=None,
            card_number=None,
            format_name="HID Raw (48-bit)",
            short_id=int.from_bytes(raw6[2:6], "big"),
            parity_valid=None,
        )

    def read_em4100(self, freq_hz: int = DEFAULT_LF_FREQ_HZ, init_rf: bool = True) -> EM4100Card | None:
        """Odczytuje kartę 125 kHz EM4100 / T5577 komendą FF 00 65 05 1E <freq_le32> 00 00 00 00."""
        self._require_lf_support()
        if freq_hz <= 0 or freq_hz > 0xFFFFFFFF:
            raise ValueError(f"Nieprawidłowa częstotliwość 125 kHz: {freq_hz}")
        if init_rf:
            self.init_rf()
        payload = b"\xff\x00\x65\x05\x1e" + freq_hz.to_bytes(4, "little") + b"\x00\x00\x00\x00"
        resp = self.exchange_raw(payload, expected_start=(START_NATIVE, START_PN532))
        if len(resp) != 6 or resp[0] != 0x05:
            return None
        return decode_em4100(resp[1:6], freq_hz=freq_hz)

    def _read_hid_prox_once(self, retries: int = 5, retry_delay_s: float = 0.01) -> HIDProxCard | None:
        attempts = max(1, retries)
        for attempt in range(attempts):
            resp = self.exchange_raw(
                b"\xff\x00\x6a\x01\x00\x08",
                expected_start=(START_NATIVE, START_PN532),
            )
            if len(resp) == 8 and resp[0] == 0x07:
                card = decode_hid_prox(resp[2:8], extra=resp[1])
                if card is not None:
                    return card
            if attempt + 1 < attempts:
                time.sleep(retry_delay_s)
        return None

    def read_hid_prox(
        self,
        init_rf: bool = True,
        retries: int = 5,
        confirm_reads: int = 2,
        retry_delay_s: float = 0.01,
    ) -> HIDProxCard | None:
        """Odczytuje kartę HID Prox (26–37 bitów) komendą FF 00 6A 01 00 08 z weryfikacją powtórną."""
        self._require_lf_support()
        if init_rf:
            self.init_rf()
        first = self._read_hid_prox_once(retries=retries, retry_delay_s=retry_delay_s)
        if first is None:
            return None
        for _ in range(max(0, confirm_reads - 1)):
            nxt = self._read_hid_prox_once(retries=retries, retry_delay_s=retry_delay_s)
            if nxt is None or nxt.raw != first.raw or nxt.bit_length != first.bit_length:
                return None
        return first
