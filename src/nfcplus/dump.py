"""Obsługa plików zrzutów (.dump / .bin) Mifare Classic oraz NTAG."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Sequence

MIFARE_BLOCK_SIZE = 16
NTAG_PAGE_SIZE = 4
FACTORY_MIFARE_TRAILER = bytes.fromhex("FFFFFFFFFFFFFF078069FFFFFFFFFFFF")


@dataclass(frozen=True)
class SectorAccess:
    """Zdekodowane bity dostępu (C1/C2/C3) z bloku trailera Mifare Classic."""

    valid: bool
    c_bits: tuple[int, int, int, int]
    raw: bytes


def parse_access_bits(access_bytes: bytes) -> SectorAccess:
    """Dekoduje i weryfikuje 3/4 bajty bitów dostępu Mifare Classic (bajty 6..9 trailera)."""
    if len(access_bytes) < 3:
        raise ValueError("Bity dostępu wymagają co najmniej 3 bajtów.")

    b6, b7, b8 = access_bytes[0], access_bytes[1], access_bytes[2]
    c1_inv = b6 & 0x0F
    c2_inv = (b6 >> 4) & 0x0F
    c3_inv = b7 & 0x0F
    c1 = (b7 >> 4) & 0x0F
    c2 = b8 & 0x0F
    c3 = (b8 >> 4) & 0x0F

    valid = (c1 ^ c1_inv) == 0x0F and (c2 ^ c2_inv) == 0x0F and (c3 ^ c3_inv) == 0x0F
    c_vals = tuple(
        (((c1 >> i) & 1) << 2) | (((c2 >> i) & 1) << 1) | ((c3 >> i) & 1)
        for i in range(4)
    )
    return SectorAccess(valid=valid, c_bits=c_vals, raw=bytes(access_bytes[:4]))  # type: ignore[arg-type]


def validate_access_bits(trailer: bytes) -> bool:
    """Weryfikuje bity dostępu C1/C2/C3 (bajty 6..8) w 16-bajtowym bloku trailera Mifare Classic."""
    if len(trailer) != MIFARE_BLOCK_SIZE:
        return False
    return parse_access_bits(bytes(trailer[6:10])).valid


def format_hex_ascii(data: bytes) -> str:
    """Formatuje blok bajtów do postaci HEX + ASCII."""
    hex_part = " ".join(f"{b:02X}" for b in data)
    ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)
    return f"{hex_part}  |  {ascii_part}"


def parse_key_file(path: Path | str) -> list[bytes]:
    """Wczytuje plik tekstowy (.txt/.dic) ze znanymi kluczami 6 B (12 znaków HEX na linię)."""
    content = Path(path).read_text(encoding="utf-8")
    keys: list[bytes] = []
    seen: set[bytes] = set()
    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].split("//", 1)[0].strip()
        if not line:
            continue
        cleaned = line.replace(" ", "").replace(":", "").replace("-", "")
        if len(cleaned) != 12:
            raise ValueError(
                f"Nieprawidłowa długość klucza w {path}:{line_no} (oczekiwano 12 znaków HEX, jest {len(cleaned)})."
            )
        try:
            key = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"Nieprawidłowy zapis HEX w {path}:{line_no}: {line!r}") from exc
        if key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def decode_value_block(block: bytes) -> int | None:
    """Dekoduje 16-bajtowy blok wartości Mifare Value Block (zwraca int32 ze znakiem lub None)."""
    if len(block) != MIFARE_BLOCK_SIZE:
        return None
    val_u32 = int.from_bytes(block[0:4], "little", signed=False)
    inv_val = int.from_bytes(block[4:8], "little", signed=False)
    val2 = int.from_bytes(block[8:12], "little", signed=False)
    if val_u32 != val2 or (val_u32 ^ inv_val) != 0xFFFFFFFF:
        return None
    addr, inv_addr, addr2, inv_addr2 = block[12], block[13], block[14], block[15]
    if addr != addr2 or inv_addr != inv_addr2 or (addr ^ inv_addr) != 0xFF:
        return None
    return int.from_bytes(block[0:4], "little", signed=True)


@dataclass(frozen=True)
class BlockDiff:
    """Różnica pojedynczego bloku/strony między dwoma zrzutami."""

    index: int
    left: bytes
    right: bytes


@dataclass(frozen=True)
class DumpDiff:
    """Wynik porównania dwóch zrzutów binarnych."""

    left_size: int
    right_size: int
    block_size: int
    differences: tuple[BlockDiff, ...]

    @property
    def identical(self) -> bool:
        return self.left_size == self.right_size and len(self.differences) == 0


def compare_buffers(left: bytes, right: bytes, block_size: int = MIFARE_BLOCK_SIZE) -> DumpDiff:
    """Porównuje dwa zrzuty binarne blok po bloku."""
    max_len = max(len(left), len(right))
    diffs: list[BlockDiff] = []
    for idx, offset in enumerate(range(0, max_len, block_size)):
        chunk_l = left[offset : offset + block_size]
        chunk_r = right[offset : offset + block_size]
        if chunk_l != chunk_r:
            diffs.append(BlockDiff(index=idx, left=chunk_l, right=chunk_r))
    return DumpDiff(
        left_size=len(left),
        right_size=len(right),
        block_size=block_size,
        differences=tuple(diffs),
    )


class MifareDump:
    """Reprezentacja zrzutu pamięci karty Mifare Classic (Mini / 1K / 4K)."""

    def __init__(
        self,
        data: bytes,
        *,
        sector_auth: dict[int, tuple[bool, bool]] | None = None,
        uid: str | None = None,
        atqa: str | None = None,
        sak: str | None = None,
    ) -> None:
        if len(data) not in (320, 1024, 2048, 4096) or len(data) % MIFARE_BLOCK_SIZE != 0:
            raise ValueError(
                f"Nieprawidłowy rozmiar zrzutu Mifare ({len(data)} B). Oczekiwano 320, 1024, 2048 lub 4096 B."
            )
        self.data = bytearray(data)
        self.sector_auth: dict[int, tuple[bool, bool]] = dict(sector_auth) if sector_auth is not None else {}
        self.uid = uid
        self.atqa = atqa
        self.sak = sak

    @classmethod
    def empty(cls, blocks: int = 64) -> MifareDump:
        return cls(bytes([0x00] * (blocks * MIFARE_BLOCK_SIZE)))

    @classmethod
    def from_blocks(
        cls,
        blocks: Sequence[bytes | None],
        fill: bytes = b"\x00" * 16,
        *,
        sector_auth: dict[int, tuple[bool, bool]] | None = None,
        uid: str | None = None,
        atqa: str | None = None,
        sak: str | None = None,
    ) -> MifareDump:
        buf = bytearray()
        for blk in blocks:
            if blk is None:
                buf.extend(fill)
            else:
                if len(blk) != MIFARE_BLOCK_SIZE:
                    raise ValueError("Każdy blok musi mieć 16 bajtów.")
                buf.extend(blk)
        return cls(bytes(buf), sector_auth=sector_auth, uid=uid, atqa=atqa, sak=sak)

    @classmethod
    def load(cls, path: str | Path) -> MifareDump:
        return cls(Path(path).read_bytes())

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(bytes(self.data))

    @property
    def total_blocks(self) -> int:
        return len(self.data) // MIFARE_BLOCK_SIZE

    @property
    def sector_count(self) -> int:
        if self.total_blocks <= 128:
            return self.total_blocks // 4
        return 32 + (self.total_blocks - 128) // 16

    def sector_block_range(self, sector: int) -> range:
        if sector < 0 or sector >= self.sector_count:
            raise IndexError(f"Nieprawidłowy numer sektora: {sector}")
        if sector < 32:
            start = sector * 4
            return range(start, start + 4)
        start = 128 + (sector - 32) * 16
        return range(start, start + 16)

    def sector_of_block(self, block: int) -> int:
        """Zwraca numer sektora dla podanego indeksu bloku."""
        if block < 0 or block >= self.total_blocks:
            raise IndexError(f"Nieprawidłowy numer bloku: {block}")
        if block < 128:
            return block // 4
        return 32 + (block - 128) // 16

    def is_trailer_block(self, block: int) -> bool:
        """Sprawdza, czy podany blok jest blokiem trailera sektora."""
        sector = self.sector_of_block(block)
        return block == self.sector_block_range(sector)[-1]

    def get_block(self, block: int) -> bytes:
        if block < 0 or block >= self.total_blocks:
            raise IndexError(f"Nieprawidłowy numer bloku: {block}")
        off = block * MIFARE_BLOCK_SIZE
        return bytes(self.data[off : off + MIFARE_BLOCK_SIZE])

    def set_block(
        self,
        block: int,
        value: bytes,
        *,
        validate_trailer: bool = False,
    ) -> MifareDump:
        """Aktualizuje zawartość wskazanego bloku (opcjonalnie weryfikując bity dostępu trailera) i zwraca self."""
        if len(value) != MIFARE_BLOCK_SIZE:
            raise ValueError("Blok musi mieć dokładnie 16 bajtów.")
        if block < 0 or block >= self.total_blocks:
            raise IndexError(f"Nieprawidłowy numer bloku: {block}")
        if validate_trailer and self.is_trailer_block(block) and not validate_access_bits(value):
            raise ValueError(f"Nieprawidłowe bity dostępu w bloku trailera {block}.")
        off = block * MIFARE_BLOCK_SIZE
        self.data[off : off + MIFARE_BLOCK_SIZE] = value
        return self

    def set_sector_auth(self, sector: int, key_a: bool, key_b: bool) -> MifareDump:
        """Zapisuje wynik autoryzacji Key A / Key B dla sektora i zwraca self."""
        if sector < 0 or sector >= self.sector_count:
            raise IndexError(f"Nieprawidłowy numer sektora: {sector}")
        self.sector_auth[sector] = (bool(key_a), bool(key_b))
        return self

    def get_sector_trailer(self, sector: int) -> tuple[bytes, SectorAccess, bytes]:
        trailer_blk = self.sector_block_range(sector)[-1]
        raw = self.get_block(trailer_blk)
        return raw[0:6], parse_access_bits(raw[6:10]), raw[10:16]

    def compare(self, other: MifareDump) -> DumpDiff:
        return compare_buffers(bytes(self.data), bytes(other.data), MIFARE_BLOCK_SIZE)

    def write_text(
        self,
        text: str,
        start_block: int = 1,
        *,
        encoding: str = "utf-8",
        clear_remaining: bool = False,
    ) -> list[int]:
        """Koduje tekst przez kolejne bloki danych (z pominięciem Bloku 0 i trailerów) i zwraca listę zapisanych bloków."""
        block_map = encode_text_to_blocks(
            text,
            self.total_blocks,
            start_block=start_block,
            encoding=encoding,
            clear_remaining=clear_remaining,
        )
        for blk, payload in block_map.items():
            self.set_block(blk, payload)
        return sorted(block_map.keys())

    def to_json_dict(
        self,
        *,
        uid: str | None = None,
        atqa: str | None = None,
        sak: str | None = None,
    ) -> dict[str, Any]:
        """Eksportuje zrzut do ustrukturyzowanego słownika JSON (sektory, bloki, access bits, Value Block)."""
        sectors_out: list[dict[str, Any]] = []
        for s in range(self.sector_count):
            ka, acc, kb = self.get_sector_trailer(s)
            block_range = self.sector_block_range(s)
            trailer_blk = block_range[-1]
            blocks_out: list[dict[str, Any]] = []
            for blk in block_range:
                raw_blk = self.get_block(blk)
                is_trailer = blk == trailer_blk
                val = None if is_trailer else decode_value_block(raw_blk)
                blocks_out.append(
                    {
                        "block": blk,
                        "hex": raw_blk.hex().upper(),
                        "is_trailer": is_trailer,
                        "value_block": val,
                    }
                )
            sector_entry: dict[str, Any] = {
                "sector": s,
                "key_a": ka.hex().upper(),
                "key_b": kb.hex().upper(),
                "access_bits": {
                    "raw": acc.raw.hex().upper(),
                    "valid": acc.valid,
                    "c_bits": list(acc.c_bits),
                },
                "blocks": blocks_out,
            }
            if s in self.sector_auth:
                auth_a, auth_b = self.sector_auth[s]
                sector_entry["auth"] = {"key_a": auth_a, "key_b": auth_b}
            sectors_out.append(sector_entry)

        return {
            "format": "mifare-classic",
            "size_bytes": len(self.data),
            "total_blocks": self.total_blocks,
            "sector_count": self.sector_count,
            "card": {
                "uid": uid if uid is not None else self.uid,
                "atqa": atqa if atqa is not None else self.atqa,
                "sak": sak if sak is not None else self.sak,
            },
            "sectors": sectors_out,
        }

    def save_json(
        self,
        path: str | Path,
        *,
        uid: str | None = None,
        atqa: str | None = None,
        sak: str | None = None,
    ) -> None:
        """Zapisuje reprezentację JSON zrzutu do wskazanego pliku."""
        payload = json.dumps(self.to_json_dict(uid=uid, atqa=atqa, sak=sak), indent=2, ensure_ascii=False)
        Path(path).write_text(payload + "\n", encoding="utf-8")


class NtagDump:
    """Reprezentacja zrzutu pamięci NTAG / Mifare Ultralight (4 B na stronę)."""

    def __init__(self, data: bytes) -> None:
        if len(data) == 0 or len(data) % NTAG_PAGE_SIZE != 0:
            raise ValueError(f"Rozmiar zrzutu NTAG ({len(data)} B) musi być wielokrotnością 4 bajtów.")
        self.data = bytearray(data)

    @classmethod
    def from_pages(cls, pages: Iterable[bytes]) -> NtagDump:
        buf = bytearray()
        for page in pages:
            if len(page) != NTAG_PAGE_SIZE:
                raise ValueError("Każda strona NTAG musi mieć 4 bajty.")
            buf.extend(page)
        return cls(bytes(buf))

    @classmethod
    def load(cls, path: str | Path) -> NtagDump:
        return cls(Path(path).read_bytes())

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(bytes(self.data))

    @property
    def page_count(self) -> int:
        return len(self.data) // NTAG_PAGE_SIZE

    def get_page(self, page: int) -> bytes:
        if page < 0 or page >= self.page_count:
            raise IndexError(f"Nieprawidłowy numer strony: {page}")
        off = page * NTAG_PAGE_SIZE
        return bytes(self.data[off : off + NTAG_PAGE_SIZE])

    def set_page(self, page: int, value: bytes) -> None:
        if len(value) != NTAG_PAGE_SIZE:
            raise ValueError("Strona NTAG musi mieć dokładnie 4 bajty.")
        if page < 0 or page >= self.page_count:
            raise IndexError(f"Nieprawidłowy numer strony: {page}")
        off = page * NTAG_PAGE_SIZE
        self.data[off : off + NTAG_PAGE_SIZE] = value

    def compare(self, other: NtagDump) -> DumpDiff:
        return compare_buffers(bytes(self.data), bytes(other.data), NTAG_PAGE_SIZE)


def _is_mifare_trailer_index(block: int) -> bool:
    if block < 128:
        return block % 4 == 3
    return (block - 128) % 16 == 15


def writable_data_blocks(total_blocks: int, start_block: int = 1) -> list[int]:
    """Zwraca listę indeksów bloków danych >= start_block z pominięciem Bloku 0 i trailerów sektorów."""
    if total_blocks <= 0:
        raise ValueError(f"Liczba bloków musi być dodatnia, podano {total_blocks}.")
    if start_block < 0 or start_block >= total_blocks:
        raise IndexError(f"Nieprawidłowy blok początkowy: {start_block}")
    return [
        blk
        for blk in range(max(1, start_block), total_blocks)
        if not _is_mifare_trailer_index(blk)
    ]


def encode_text_to_blocks(
    text: str,
    total_blocks: int,
    start_block: int = 1,
    *,
    encoding: str = "utf-8",
    pad_byte: int = 0x00,
    clear_remaining: bool = False,
) -> dict[int, bytes]:
    """Koduje tekst na 16-bajtowe bloki danych Mifare Classic (bez Bloku 0 i trailerów)."""
    if not 0 <= pad_byte <= 0xFF:
        raise ValueError(f"Bajt dopełnienia musi być z zakresu 0..255, podano {pad_byte}.")
    target_blocks = writable_data_blocks(total_blocks, start_block=start_block)
    raw = text.encode(encoding)
    capacity = len(target_blocks) * MIFARE_BLOCK_SIZE
    if len(raw) > capacity:
        raise ValueError(
            f"Tekst ({len(raw)} B) przekracza pojemność dostępnych bloków danych ({capacity} B)."
        )

    pad_b = bytes([pad_byte])
    chunks: list[bytes] = []
    if raw:
        for off in range(0, len(raw), MIFARE_BLOCK_SIZE):
            chunk = raw[off : off + MIFARE_BLOCK_SIZE]
            if len(chunk) < MIFARE_BLOCK_SIZE:
                chunk = chunk + (pad_b * (MIFARE_BLOCK_SIZE - len(chunk)))
            chunks.append(chunk)
    elif target_blocks:
        chunks.append(pad_b * MIFARE_BLOCK_SIZE)

    result: dict[int, bytes] = {
        target_blocks[idx]: chunk for idx, chunk in enumerate(chunks)
    }
    if clear_remaining:
        zero_block = b"\x00" * MIFARE_BLOCK_SIZE
        for blk in target_blocks[len(chunks) :]:
            result[blk] = zero_block
    return result


def decode_blocks_to_text(
    dump: MifareDump,
    start_block: int = 1,
    end_block: int | None = None,
    *,
    encoding: str = "utf-8",
) -> str:
    """Dekoduje tekst z kolejnych bloków danych Mifare Classic (pomijając Blok 0 i trailery)."""
    blocks = writable_data_blocks(dump.total_blocks, start_block=start_block)
    if end_block is not None:
        blocks = [blk for blk in blocks if blk <= end_block]
    raw = b"".join(dump.get_block(blk) for blk in blocks).rstrip(b"\x00")
    return raw.decode(encoding, errors="replace")
