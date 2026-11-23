"""Warstwa transportowa USB HID dla czytników wCopy / Xixei / NFC Pro."""

from __future__ import annotations

import ctypes
import os
import select
import struct
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

SUPPORTED_USB_IDS: tuple[tuple[int, int], ...] = (
    (0x0416, 0xB030),
    (0x0416, 0xB031),
    (0x2518, 0x6022),
    (0x2518, 0x6018),
)

SUPPORTED_CCID_IDS: dict[tuple[int, int], str] = {
    (0x072F, 0x2200): "ACS ACR122U PICC Interface",
}


class TransportError(RuntimeError):
    """Błąd komunikacji z urządzeniem USB HID."""


class NoSmartCardError(TransportError):
    """Brak karty lub tagu na czytniku PC/SC (SCARD_E_NO_SMARTCARD / SCARD_W_REMOVED_CARD)."""


@dataclass(frozen=True)
class DeviceInfo:
    """Metadane wykrytego czytnika USB HID lub CCID (ACR122U)."""

    vid: int
    pid: int
    path: str
    product: str = ""
    manufacturer: str = ""
    serial: str = ""
    backend: str = ""
    protocol_family: str = "wcopy_hid"
    supports_lf: bool = True

    @property
    def vid_pid(self) -> str:
        return f"{self.vid:04x}:{self.pid:04x}"


def format_reader_label(dev: DeviceInfo, *, duplicate_index: int | None = None) -> str:
    """Formatuje czytelną nazwę czytnika dla UI bez surowej ścieżki \\\\?\\hid#..."""
    product = dev.product.strip() if dev.product else ""
    if not product:
        if (dev.vid, dev.pid) in SUPPORTED_CCID_IDS:
            product = SUPPORTED_CCID_IDS[(dev.vid, dev.pid)]
        elif dev.vid == 0x0416 and dev.pid in (0xB030, 0xB031):
            product = "XIXEI Smart Reader"
        elif dev.vid == 0x2518:
            product = "wCopy NFC Reader"
        else:
            product = "Czytnik USB HID"
    label = f"{product} ({dev.vid_pid})"
    if duplicate_index is not None and duplicate_index > 1:
        return f"{label} #{duplicate_index}"
    return label


def format_reader_labels(devices: Sequence[DeviceInfo]) -> list[str]:
    """Buduje listę unikalnych, czytelnych etykiet czytników (dopisując #2, #3 przy duplikatach)."""
    counts: dict[str, int] = {}
    labels: list[str] = []
    for dev in devices:
        base = format_reader_label(dev)
        idx = counts.get(base, 0) + 1
        counts[base] = idx
        labels.append(format_reader_label(dev, duplicate_index=idx if idx > 1 else None))
    return labels


class HIDTransport(ABC):
    """Abstrakcyjny interfejs transportu 64-bajtowych raportów HID."""

    @abstractmethod
    def open(self) -> None:
        """Otwiera połączenie z urządzeniem."""

    @abstractmethod
    def close(self) -> None:
        """Zamyka połączenie z urządzeniem."""

    @abstractmethod
    def write(self, data: bytes) -> int:
        """Wysyła raport HID (64 bajty z wiodącym Report ID 0x00)."""

    @abstractmethod
    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        """Odbiera raport HID z podanym limitem czasu."""

    @property
    @abstractmethod
    def is_open(self) -> bool:
        """Zwraca True, jeśli urządzenie jest otwarte."""

    @property
    def protocol_family(self) -> str:
        """Rodzina protokołu czytnika ('wcopy_hid' lub 'acr122u')."""
        return "wcopy_hid"

    @property
    def supports_lf(self) -> bool:
        """Czy czytnik obsługuje pasmo 125 kHz LF (EM4100 / HID Prox / T5577)."""
        return True

    def apdu_exchange(self, apdu: bytes, timeout_ms: int = 2000) -> bytes:
        """Wysyła komendę APDU/pseudo-APDU (dla czytników CCID/PC-SC takich jak ACR122U)."""
        raise NotImplementedError("Ten transport nie obsługuje bezpośredniej wymiany APDU CCID/PC/SC.")

    def __enter__(self) -> HIDTransport:
        self.open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class HidApiTransport(HIDTransport):
    """Backend oparty o bibliotekę `hidapi` (moduł `hid`, wieloplatformowy)."""

    def __init__(self, path: str | bytes) -> None:
        self._path = path.encode("utf-8") if isinstance(path, str) else path
        self._dev: object | None = None

    @property
    def is_open(self) -> bool:
        return self._dev is not None

    def open(self) -> None:
        try:
            import hid  # type: ignore[import-not-found]
        except ImportError as exc:
            raise TransportError("Brak modułu 'hid' (zainstaluj pakiet 'hidapi').") from exc

        dev = hid.device()
        try:
            dev.open_path(self._path)
        except OSError as exc:
            raise TransportError(f"Nie można otworzyć urządzenia HID ({self._path!r}): {exc}") from exc
        self._dev = dev

    def close(self) -> None:
        if self._dev is not None:
            try:
                self._dev.close()  # type: ignore[attr-defined]
            finally:
                self._dev = None

    def write(self, data: bytes) -> int:
        if self._dev is None:
            raise TransportError("Urządzenie HID nie jest otwarte.")
        try:
            written = self._dev.write(list(data))  # type: ignore[attr-defined]
        except OSError as exc:
            raise TransportError(f"Błąd zapisu HID: {exc}") from exc
        if written < 0:
            raise TransportError("Błąd zapisu HID (hid_write zwrócił wartość ujemną).")
        return int(written)

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        if self._dev is None:
            raise TransportError("Urządzenie HID nie jest otwarte.")
        try:
            raw = self._dev.read(size, timeout_ms)  # type: ignore[attr-defined]
        except OSError as exc:
            raise TransportError(f"Błąd odczytu HID: {exc}") from exc
        if not raw:
            raise TimeoutError(f"Upłynął limit czasu odczytu HID ({timeout_ms} ms).")
        return bytes(raw)


class LinuxHidrawTransport(HIDTransport):
    """Natywny backend `/dev/hidraw*` dla Linuksa (bez zewnętrznych zależności)."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._fd: int | None = None

    @property
    def is_open(self) -> bool:
        return self._fd is not None

    def open(self) -> None:
        if self._fd is not None:
            return
        try:
            self._fd = os.open(self._path, os.O_RDWR | os.O_NONBLOCK)
        except PermissionError as exc:
            raise TransportError(
                f"Brak uprawnień do {self._path}. Zainstaluj regułę udev z pliku udev/99-nfcplus.rules."
            ) from exc
        except OSError as exc:
            raise TransportError(f"Nie można otworzyć {self._path}: {exc}") from exc

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def write(self, data: bytes) -> int:
        if self._fd is None:
            raise TransportError("Urządzenie hidraw nie jest otwarte.")
        try:
            return os.write(self._fd, data)
        except OSError as exc:
            raise TransportError(f"Błąd zapisu do {self._path}: {exc}") from exc

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        if self._fd is None:
            raise TransportError("Urządzenie hidraw nie jest otwarte.")
        timeout_s = max(0.0, timeout_ms / 1000.0)
        ready, _, _ = select.select([self._fd], [], [], timeout_s)
        if not ready:
            raise TimeoutError(f"Upłynął limit czasu odczytu z {self._path} ({timeout_ms} ms).")
        try:
            data = os.read(self._fd, size)
        except OSError as exc:
            raise TransportError(f"Błąd odczytu z {self._path}: {exc}") from exc
        if not data:
            raise TimeoutError(f"Pusty odczyt z {self._path}.")
        return data


def no_readers_hint(platform: str | None = None) -> str:
    """Zwraca wskazówkę diagnostyczną dopasowaną do systemu operacyjnego."""
    plat = sys.platform if platform is None else platform
    if plat == "win32":
        return (
            "Sprawdź połączenie USB oraz Menedżer urządzeń (Urządzenia interfejsu HID). "
            "Jeśli czytnik jest zajęty, zamknij wCopy lub nfcPro_x64.exe."
        )
    if plat.startswith("linux"):
        return (
            "Sprawdź połączenie USB, /dev/hidraw* oraz uprawnienia udev (udev/99-nfcplus.rules)."
        )
    return "Sprawdź połączenie USB z czytnikiem HID."


# ---------------------------------------------------------------------------
# Natywny backend Windows HID (setupapi.dll + hid.dll + kernel32.dll via ctypes)
# ---------------------------------------------------------------------------

_DIGCF_PRESENT = 0x00000002
_DIGCF_DEVICEINTERFACE = 0x00000010
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_FLAG_OVERLAPPED = 0x40000000
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32
_ERROR_IO_PENDING = 997

_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF
_HIDP_STATUS_SUCCESS = 0x00110000


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]


class _SPDeviceInterfaceData(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("InterfaceClassGuid", _GUID),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_size_t),
    ]


class _HiddAttributes(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint32),
        ("VendorID", ctypes.c_uint16),
        ("ProductID", ctypes.c_uint16),
        ("VersionNumber", ctypes.c_uint16),
    ]


class _HidpCaps(ctypes.Structure):
    _fields_ = [
        ("Usage", ctypes.c_uint16),
        ("UsagePage", ctypes.c_uint16),
        ("InputReportByteLength", ctypes.c_uint16),
        ("OutputReportByteLength", ctypes.c_uint16),
        ("FeatureReportByteLength", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16 * 17),
        ("NumberLinkCollectionNodes", ctypes.c_uint16),
        ("NumberInputButtonCaps", ctypes.c_uint16),
        ("NumberInputValueCaps", ctypes.c_uint16),
        ("NumberInputDataIndices", ctypes.c_uint16),
        ("NumberOutputButtonCaps", ctypes.c_uint16),
        ("NumberOutputValueCaps", ctypes.c_uint16),
        ("NumberOutputDataIndices", ctypes.c_uint16),
        ("NumberFeatureButtonCaps", ctypes.c_uint16),
        ("NumberFeatureValueCaps", ctypes.c_uint16),
        ("NumberFeatureDataIndices", ctypes.c_uint16),
    ]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]


@dataclass
class _Win32HidApi:
    """Kontener uchwytów bibliotek Win32 używanych do komunikacji HID."""

    setupapi: Any
    hid: Any
    kernel32: Any


def _configure_win32_dlls(setupapi: Any, hid: Any, kernel32: Any) -> None:
    """Konfiguruje argtypes/restype dla bezpiecznych wywołań Win32 na x64."""
    hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(_GUID)]
    hid.HidD_GetHidGuid.restype = None
    hid.HidD_GetAttributes.argtypes = [ctypes.c_void_p, ctypes.POINTER(_HiddAttributes)]
    hid.HidD_GetAttributes.restype = ctypes.c_ubyte
    hid.HidD_GetPreparsedData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    hid.HidD_GetPreparsedData.restype = ctypes.c_ubyte
    hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
    hid.HidD_FreePreparsedData.restype = ctypes.c_ubyte
    hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(_HidpCaps)]
    hid.HidP_GetCaps.restype = ctypes.c_int32
    hid.HidD_GetProductString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    hid.HidD_GetProductString.restype = ctypes.c_ubyte
    hid.HidD_GetManufacturerString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    hid.HidD_GetManufacturerString.restype = ctypes.c_ubyte
    hid.HidD_GetSerialNumberString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    hid.HidD_GetSerialNumberString.restype = ctypes.c_ubyte
    if hasattr(hid, "HidD_SetNumInputBuffers"):
        hid.HidD_SetNumInputBuffers.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        hid.HidD_SetNumInputBuffers.restype = ctypes.c_ubyte

    setupapi.SetupDiGetClassDevsW.argtypes = [
        ctypes.POINTER(_GUID),
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
    setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(_GUID),
        ctypes.c_uint32,
        ctypes.POINTER(_SPDeviceInterfaceData),
    ]
    setupapi.SetupDiEnumDeviceInterfaces.restype = ctypes.c_int32
    setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_SPDeviceInterfaceData),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    setupapi.SetupDiGetDeviceInterfaceDetailW.restype = ctypes.c_int32
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    setupapi.SetupDiDestroyDeviceInfoList.restype = ctypes.c_int32

    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int32
    kernel32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_int32, ctypes.c_wchar_p]
    kernel32.CreateEventW.restype = ctypes.c_void_p
    kernel32.ResetEvent.argtypes = [ctypes.c_void_p]
    kernel32.ResetEvent.restype = ctypes.c_int32
    kernel32.ReadFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.ReadFile.restype = ctypes.c_int32
    kernel32.WriteFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.WriteFile.restype = ctypes.c_int32
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.GetOverlappedResult.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_Overlapped),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int32,
    ]
    kernel32.GetOverlappedResult.restype = ctypes.c_int32
    kernel32.CancelIo.argtypes = [ctypes.c_void_p]
    kernel32.CancelIo.restype = ctypes.c_int32


def _load_win32_api() -> _Win32HidApi:
    """Ładuje biblioteki Win32 HID (`setupapi`, `hid`, `kernel32`) bez zależności pip."""
    if sys.platform != "win32":
        raise TransportError("Natywny transport Windows HID działa wyłącznie w systemie Windows.")
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise TransportError("Brak obsługi ctypes.WinDLL w tym środowisku Pythona.")
    setupapi = win_dll("setupapi.dll", use_last_error=True)
    hid = win_dll("hid.dll", use_last_error=True)
    kernel32 = win_dll("kernel32.dll", use_last_error=True)
    _configure_win32_dlls(setupapi, hid, kernel32)
    return _Win32HidApi(setupapi=setupapi, hid=hid, kernel32=kernel32)


def _is_invalid_handle(handle: Any) -> bool:
    return handle in (None, 0, -1, _INVALID_HANDLE_VALUE)


def _win32_last_error(api: _Win32HidApi) -> int:
    getter = getattr(api, "get_last_error", None)
    if callable(getter):
        return int(getter())
    err = int(ctypes.get_last_error())
    if err == 0 and hasattr(api.kernel32, "GetLastError"):
        try:
            err = int(api.kernel32.GetLastError())
        except Exception:
            pass
    return err


def _read_hid_string(fn: Any, handle: Any) -> str:
    buf = ctypes.create_string_buffer(256)
    try:
        ok = fn(handle, buf, ctypes.sizeof(buf))
    except Exception:
        return ""
    if not ok:
        return ""
    return buf.raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0].strip()


def _format_win32_open_error(path: str, err: int) -> str:
    if err in (_ERROR_ACCESS_DENIED, _ERROR_SHARING_VIOLATION):
        return (
            f"Nie można otworzyć urządzenia HID ({path}): odmowa dostępu lub czytnik jest zajęty "
            "(błąd Win32 "
            f"{err}). Zamknij programy wCopy / nfcPro_x64.exe i spróbuj ponownie, "
            "lub sprawdź Menedżer urządzeń (Urządzenia interfejsu HID)."
        )
    if err in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
        return (
            f"Nie znaleziono urządzenia HID pod ścieżką {path} (błąd Win32 {err}). "
            "Sprawdź połączenie USB oraz Menedżer urządzeń (Urządzenia interfejsu HID)."
        )
    return (
        f"Nie można otworzyć urządzenia HID ({path}): błąd Win32 {err}. "
        "Sprawdź Menedżer urządzeń (Urządzenia interfejsu HID) i zamknij wCopy / nfcPro_x64.exe."
    )


class WindowsHidTransport(HIDTransport):
    """Natywny, bezpudełkowy backend Windows HID (`setupapi`/`hid`/`kernel32` przez `ctypes`)."""

    def __init__(self, path: str, api: _Win32HidApi | None = None) -> None:
        self._path = path
        self._api = api
        self._handle: Any = None
        self._read_event: Any = None
        self._write_event: Any = None
        self._input_report_len: int = 65
        self._output_report_len: int = 65
        self._read_buf: Any = None
        self._read_overlapped: _Overlapped | None = None

    @property
    def is_open(self) -> bool:
        return self._handle is not None

    @property
    def input_report_length(self) -> int:
        return self._input_report_len

    @property
    def output_report_length(self) -> int:
        return self._output_report_len

    def _get_api(self) -> _Win32HidApi:
        if self._api is None:
            self._api = _load_win32_api()
        return self._api

    def open(self) -> None:
        if self._handle is not None:
            return
        api = self._get_api()
        handle = api.kernel32.CreateFileW(
            self._path,
            _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OVERLAPPED,
            None,
        )
        if _is_invalid_handle(handle):
            err = _win32_last_error(api)
            raise TransportError(_format_win32_open_error(self._path, err))

        self._handle = handle
        try:
            if hasattr(api.hid, "HidD_SetNumInputBuffers"):
                api.hid.HidD_SetNumInputBuffers(handle, 64)

            preparsed = ctypes.c_void_p()
            if not api.hid.HidD_GetPreparsedData(handle, ctypes.byref(preparsed)) or not preparsed.value:
                raise TransportError(f"Nie udało się pobrać deskryptora HID dla {self._path}.")
            try:
                caps = _HidpCaps()
                status = api.hid.HidP_GetCaps(preparsed, ctypes.byref(caps))
                if status != _HIDP_STATUS_SUCCESS:
                    raise TransportError(
                        f"Nie udało się odczytać możliwości raportów HID (status=0x{status & 0xFFFFFFFF:08X})."
                    )
                self._input_report_len = int(caps.InputReportByteLength) or 65
                self._output_report_len = int(caps.OutputReportByteLength) or 65
            finally:
                api.hid.HidD_FreePreparsedData(preparsed)

            self._read_event = api.kernel32.CreateEventW(None, 1, 0, None)
            self._write_event = api.kernel32.CreateEventW(None, 1, 0, None)
            if _is_invalid_handle(self._read_event) or _is_invalid_handle(self._write_event):
                raise TransportError("Nie udało się utworzyć obiektu zdarzenia Win32 dla operacji HID.")
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        api = self._api
        if api is None:
            self._handle = None
            self._read_event = None
            self._write_event = None
            return
        try:
            if not _is_invalid_handle(self._read_event):
                api.kernel32.CloseHandle(self._read_event)
        finally:
            self._read_event = None
            try:
                if not _is_invalid_handle(self._write_event):
                    api.kernel32.CloseHandle(self._write_event)
            finally:
                self._write_event = None
                try:
                    if not _is_invalid_handle(self._handle):
                        api.kernel32.CloseHandle(self._handle)
                finally:
                    self._handle = None

    def _prepare_output_report(self, data: bytes) -> bytes:
        out_len = self._output_report_len
        if out_len <= 0 or len(data) == out_len:
            return data
        if len(data) < out_len:
            if out_len == 65 and len(data) == 64 and data[:1] != b"\x00":
                return b"\x00" + data
            return data.ljust(out_len, b"\x00")
        return data

    def write(self, data: bytes) -> int:
        if self._handle is None:
            raise TransportError("Urządzenie HID nie jest otwarte.")
        api = self._get_api()
        payload = self._prepare_output_report(bytes(data))
        buf = ctypes.create_string_buffer(payload, len(payload))
        written = ctypes.c_uint32(0)
        ov = _Overlapped(hEvent=self._write_event)
        api.kernel32.ResetEvent(self._write_event)

        ok = api.kernel32.WriteFile(
            self._handle,
            buf,
            len(payload),
            ctypes.byref(written),
            ctypes.byref(ov),
        )
        if not ok:
            err = _win32_last_error(api)
            if err != _ERROR_IO_PENDING:
                raise TransportError(f"Błąd zapisu HID (Win32 {err}) dla {self._path}.")
            if not api.kernel32.GetOverlappedResult(self._handle, ctypes.byref(ov), ctypes.byref(written), 1):
                err2 = _win32_last_error(api)
                raise TransportError(f"Błąd zakończenia zapisu HID (Win32 {err2}) dla {self._path}.")
        elif written.value == 0:
            api.kernel32.GetOverlappedResult(self._handle, ctypes.byref(ov), ctypes.byref(written), 1)

        return int(written.value) if written.value else len(payload)

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        if self._handle is None:
            raise TransportError("Urządzenie HID nie jest otwarte.")
        api = self._get_api()
        read_len = self._input_report_len if self._input_report_len > 0 else size
        self._read_buf = ctypes.create_string_buffer(read_len)
        bytes_read = ctypes.c_uint32(0)
        self._read_overlapped = _Overlapped(hEvent=self._read_event)
        api.kernel32.ResetEvent(self._read_event)

        ok = api.kernel32.ReadFile(
            self._handle,
            self._read_buf,
            read_len,
            ctypes.byref(bytes_read),
            ctypes.byref(self._read_overlapped),
        )
        if not ok:
            err = _win32_last_error(api)
            if err != _ERROR_IO_PENDING:
                api.kernel32.CancelIo(self._handle)
                raise TransportError(f"Błąd odczytu HID (Win32 {err}) dla {self._path}.")

            wait_ms = _INFINITE if timeout_ms < 0 else int(timeout_ms)
            wait_res = api.kernel32.WaitForSingleObject(self._read_event, wait_ms)
            if wait_res == _WAIT_TIMEOUT:
                api.kernel32.CancelIo(self._handle)
                drained = ctypes.c_uint32(0)
                if (
                    api.kernel32.GetOverlappedResult(
                        self._handle, ctypes.byref(self._read_overlapped), ctypes.byref(drained), 1
                    )
                    and drained.value > 0
                ):
                    bytes_read = drained
                else:
                    raise TimeoutError(f"Upłynął limit czasu odczytu HID ({timeout_ms} ms).")
            elif wait_res != _WAIT_OBJECT_0:
                err_w = _win32_last_error(api)
                api.kernel32.CancelIo(self._handle)
                drained = ctypes.c_uint32(0)
                api.kernel32.GetOverlappedResult(
                    self._handle, ctypes.byref(self._read_overlapped), ctypes.byref(drained), 1
                )
                raise TransportError(
                    f"Błąd oczekiwania na odczyt HID (status={wait_res}, Win32 {err_w})."
                )
            elif not api.kernel32.GetOverlappedResult(
                self._handle, ctypes.byref(self._read_overlapped), ctypes.byref(bytes_read), 1
            ):
                err2 = _win32_last_error(api)
                raise TransportError(f"Błąd zakończenia odczytu HID (Win32 {err2}) dla {self._path}.")
        elif bytes_read.value == 0:
            if not api.kernel32.GetOverlappedResult(
                self._handle, ctypes.byref(self._read_overlapped), ctypes.byref(bytes_read), 1
            ):
                err2 = _win32_last_error(api)
                raise TransportError(f"Błąd odczytu HID (Win32 {err2}) dla {self._path}.")

        count = int(bytes_read.value)
        if count == 0:
            raise TimeoutError(f"Pusty odczyt HID ({self._path}).")

        raw = bytes(self._read_buf.raw[:count])
        if (self._input_report_len > 64 or len(raw) > 64) and raw[:1] == b"\x00":
            raw = raw[1:]
        return raw[:size]


def _enumerate_windows_hid(
    usb_ids: Iterable[tuple[int, int]],
    api: _Win32HidApi | None = None,
) -> list[DeviceInfo]:
    """Wykrywa kompatybilne czytniki w Windows przez natywne Win32 HID API."""
    if api is None:
        if sys.platform != "win32":
            return []
        try:
            api = _load_win32_api()
        except TransportError:
            return []

    allowed = set(usb_ids)
    found: list[DeviceInfo] = []
    hid_guid = _GUID()
    api.hid.HidD_GetHidGuid(ctypes.byref(hid_guid))

    dev_info = api.setupapi.SetupDiGetClassDevsW(
        ctypes.byref(hid_guid),
        None,
        None,
        _DIGCF_PRESENT | _DIGCF_DEVICEINTERFACE,
    )
    if _is_invalid_handle(dev_info):
        return found

    cb_size = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
    try:
        member_index = 0
        while True:
            if_data = _SPDeviceInterfaceData(cbSize=ctypes.sizeof(_SPDeviceInterfaceData))
            ok = api.setupapi.SetupDiEnumDeviceInterfaces(
                dev_info,
                None,
                ctypes.byref(hid_guid),
                member_index,
                ctypes.byref(if_data),
            )
            if not ok:
                break
            member_index += 1

            required_size = ctypes.c_uint32(0)
            api.setupapi.SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                ctypes.byref(if_data),
                None,
                0,
                ctypes.byref(required_size),
                None,
            )
            if required_size.value <= 4:
                continue

            detail_buf = ctypes.create_string_buffer(required_size.value)
            ctypes.c_uint32.from_buffer(detail_buf).value = cb_size
            ok_detail = api.setupapi.SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                ctypes.byref(if_data),
                detail_buf,
                required_size.value,
                None,
                None,
            )
            if not ok_detail:
                continue

            device_path = (
                bytes(detail_buf.raw[4:])
                .decode("utf-16-le", errors="replace")
                .split("\x00", 1)[0]
            )
            if not device_path:
                continue

            handle = api.kernel32.CreateFileW(
                device_path,
                0,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_OVERLAPPED,
                None,
            )
            if _is_invalid_handle(handle):
                continue

            try:
                attrs = _HiddAttributes(Size=ctypes.sizeof(_HiddAttributes))
                if not api.hid.HidD_GetAttributes(handle, ctypes.byref(attrs)):
                    continue
                vid = int(attrs.VendorID)
                pid = int(attrs.ProductID)
                if (vid, pid) not in allowed:
                    continue

                preparsed = ctypes.c_void_p()
                if api.hid.HidD_GetPreparsedData(handle, ctypes.byref(preparsed)) and preparsed.value:
                    try:
                        caps = _HidpCaps()
                        if api.hid.HidP_GetCaps(preparsed, ctypes.byref(caps)) == _HIDP_STATUS_SUCCESS:
                            if caps.InputReportByteLength == 0 and caps.OutputReportByteLength == 0:
                                continue
                    finally:
                        api.hid.HidD_FreePreparsedData(preparsed)

                product = _read_hid_string(api.hid.HidD_GetProductString, handle)
                manufacturer = _read_hid_string(api.hid.HidD_GetManufacturerString, handle)
                serial = _read_hid_string(api.hid.HidD_GetSerialNumberString, handle)

                found.append(
                    DeviceInfo(
                        vid=vid,
                        pid=pid,
                        path=device_path,
                        product=product,
                        manufacturer=manufacturer,
                        serial=serial,
                        backend="win32",
                    )
                )
            finally:
                api.kernel32.CloseHandle(handle)
    finally:
        api.setupapi.SetupDiDestroyDeviceInfoList(dev_info)

    return found


def _parse_hidraw_uevent(uevent_text: str) -> tuple[int, int, str, str] | None:
    """Parsuje VID, PID, nazwę produktu i serial z sysfs uevent dla hidraw."""
    vid = pid = None
    name = ""
    serial = ""
    for line in uevent_text.splitlines():
        if line.startswith("HID_ID="):
            parts = line.split("=", 1)[1].split(":")
            if len(parts) == 3:
                vid = int(parts[1], 16)
                pid = int(parts[2], 16)
        elif line.startswith("HID_NAME="):
            name = line.split("=", 1)[1].strip()
        elif line.startswith("HID_UNIQ="):
            serial = line.split("=", 1)[1].strip()
    if vid is None or pid is None:
        return None
    return vid, pid, name, serial


def _enumerate_linux_hidraw(
    usb_ids: Iterable[tuple[int, int]],
    sysfs_root: Path = Path("/sys/class/hidraw"),
) -> list[DeviceInfo]:
    """Wykrywa kompatybilne czytniki przez Linux sysfs (`/sys/class/hidraw`)."""
    allowed = set(usb_ids)
    found: list[DeviceInfo] = []
    if not sysfs_root.exists():
        return found

    for entry in sorted(sysfs_root.iterdir()):
        uevent_path = entry / "device" / "uevent"
        if not uevent_path.is_file():
            continue
        try:
            parsed = _parse_hidraw_uevent(uevent_path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if parsed is None:
            continue
        vid, pid, name, serial = parsed
        if (vid, pid) in allowed:
            found.append(
                DeviceInfo(
                    vid=vid,
                    pid=pid,
                    path=f"/dev/{entry.name}",
                    product=name,
                    serial=serial,
                    backend="hidraw",
                )
            )
    return found


def _enumerate_hidapi(usb_ids: Iterable[tuple[int, int]]) -> list[DeviceInfo]:
    """Wykrywa kompatybilne czytniki przez `hidapi` (jeśli zainstalowane)."""
    try:
        import hid  # type: ignore[import-not-found]
    except ImportError:
        return []

    allowed = set(usb_ids)
    found: list[DeviceInfo] = []
    for item in hid.enumerate():
        vid = int(item.get("vendor_id", 0))
        pid = int(item.get("product_id", 0))
        if (vid, pid) not in allowed:
            continue
        raw_path = item.get("path", b"")
        path = raw_path.decode("utf-8", errors="replace") if isinstance(raw_path, bytes) else str(raw_path)
        found.append(
            DeviceInfo(
                vid=vid,
                pid=pid,
                path=path,
                product=str(item.get("product_string") or ""),
                manufacturer=str(item.get("manufacturer_string") or ""),
                serial=str(item.get("serial_number") or ""),
                backend="hidapi",
            )
        )
    return found


def enumerate_readers(usb_ids: Iterable[tuple[int, int]] = SUPPORTED_USB_IDS) -> list[DeviceInfo]:
    """Zwraca listę wykrytych czytników NFC (wCopy/Xixei HID oraz ACS ACR122U CCID/PC-SC)."""
    ids = tuple(usb_ids)
    devices = _enumerate_hidapi(ids)
    if sys.platform == "win32":
        seen = {dev.path.casefold() for dev in devices}
        for win_dev in _enumerate_windows_hid(ids):
            key = win_dev.path.casefold()
            if key not in seen:
                seen.add(key)
                devices.append(win_dev)
        for pcsc_dev in _enumerate_windows_pcsc():
            key = pcsc_dev.path.casefold()
            if key not in seen:
                seen.add(key)
                devices.append(pcsc_dev)
        return devices

    if not devices and sys.platform.startswith("linux"):
        devices = _enumerate_linux_hidraw(ids)

    if sys.platform.startswith("linux"):
        pcsc_devs = _enumerate_linux_pcsc()
        if pcsc_devs:
            devices.extend(pcsc_devs)
        else:
            devices.extend(_enumerate_linux_usb_ccid())
    return devices


def _create_transport_for_device(dev: DeviceInfo) -> HIDTransport:
    if dev.backend == "hidraw":
        return LinuxHidrawTransport(dev.path)
    if dev.backend == "win32":
        return WindowsHidTransport(dev.path)
    if dev.backend == "winscard":
        return WindowsPcscTransport(dev.path)
    if dev.backend == "pcsc":
        return LinuxPcscTransport(dev.path)
    if dev.backend == "ccid_usb":
        return LinuxUsbCcidTransport(dev.path, product=dev.product or "ACS ACR122U PICC Interface")
    return HidApiTransport(dev.path)


def open_reader(
    vid: int | None = None,
    pid: int | None = None,
    path: str | None = None,
) -> tuple[DeviceInfo, HIDTransport]:
    """Wyszukuje i otwiera pierwszy pasujący czytnik USB HID lub ACR122U."""
    if path is not None:
        matched = next(
            (
                dev
                for dev in enumerate_readers()
                if (dev.path.casefold() == path.casefold() if sys.platform == "win32" else dev.path == path)
            ),
            None,
        )
        if matched is not None:
            transport = _create_transport_for_device(matched)
            transport.open()
            return matched, transport

        if path.startswith("/dev/hidraw"):
            info = DeviceInfo(vid=vid or 0, pid=pid or 0, path=path, backend="hidraw")
            transport = LinuxHidrawTransport(path)
        elif path.startswith("/dev/bus/usb/"):
            info = DeviceInfo(
                vid=vid or 0x072F,
                pid=pid or 0x2200,
                path=path,
                product="ACS ACR122U PICC Interface",
                backend="ccid_usb",
                protocol_family="acr122u",
                supports_lf=False,
            )
            transport = LinuxUsbCcidTransport(path)
        elif sys.platform == "win32" and _is_acr122_reader_name(path):
            info = DeviceInfo(
                vid=vid or 0x072F,
                pid=pid or 0x2200,
                path=path,
                product=path,
                backend="winscard",
                protocol_family="acr122u",
                supports_lf=False,
            )
            transport = WindowsPcscTransport(path)
        elif sys.platform == "win32":
            info = DeviceInfo(vid=vid or 0, pid=pid or 0, path=path, backend="win32")
            transport = WindowsHidTransport(path)
        elif sys.platform.startswith("linux") and _is_acr122_reader_name(path):
            info = DeviceInfo(
                vid=vid or 0x072F,
                pid=pid or 0x2200,
                path=path,
                product=path,
                backend="pcsc",
                protocol_family="acr122u",
                supports_lf=False,
            )
            transport = LinuxPcscTransport(path)
        else:
            info = DeviceInfo(vid=vid or 0, pid=pid or 0, path=path, backend="manual")
            transport = HidApiTransport(path)
        transport.open()
        return info, transport

    candidates = enumerate_readers()
    for dev in candidates:
        if vid is not None and dev.vid != vid:
            continue
        if pid is not None and dev.pid != pid:
            continue
        transport = _create_transport_for_device(dev)
        transport.open()
        return dev, transport

    if not candidates:
        all_ids = SUPPORTED_USB_IDS + tuple(SUPPORTED_CCID_IDS.keys())
        supported_str = ", ".join(f"{v:04x}:{p:04x}" for v, p in all_ids)
        raise TransportError(
            f"Nie znaleziono żadnego kompatybilnego czytnika USB HID/CCID ({supported_str}). "
            f"{no_readers_hint()}"
        )
    raise TransportError(
        f"Nie znaleziono czytnika pasującego do filtru VID={vid} PID={pid}. {no_readers_hint()}"
    )


# ------------------------------------------------------------------
# Obsługa ACS ACR122U (072f:2200) — PC/SC (Windows/Linux) + Linux USB CCID
# ------------------------------------------------------------------

_SCARD_SCOPE_USER = 0
_SCARD_SHARE_SHARED = 2
_SCARD_SHARE_DIRECT = 3
_SCARD_LEAVE_CARD = 0
_SCARD_PROTOCOL_TX = 0x0003
_SCARD_E_SHARING_VIOLATION = 0x8010000B
_SCARD_E_NO_SMARTCARD = 0x8010000C
_SCARD_W_RESET_CARD = 0x80100068
_SCARD_W_REMOVED_CARD = 0x80100069
_SCARD_NO_CARD_ERRORS = (_SCARD_E_NO_SMARTCARD, _SCARD_W_REMOVED_CARD)
_CM_IOCTL_GET_FEATURE_REQUEST = 0x00313520
_FEATURE_CCID_ESC_COMMAND = 0x13
_IOCTL_CCID_ESCAPE_WIN = 0x003136B0
_IOCTL_CCID_ESCAPE_LINUX = 0x42000DAC
_IOCTL_CCID_ALT_LINUX = 0x42000D48


def _parse_pcsc_multi_string(raw: bytes, *, encoding: str) -> list[str]:
    text = raw.decode(encoding, errors="replace")
    names: list[str] = []
    for part in text.split("\x00"):
        cleaned = part.strip()
        if not cleaned:
            if names:
                break
            continue
        names.append(cleaned)
    return names


def _is_acr122_reader_name(name: str) -> bool:
    return "acr122" in name.lower()


def _load_winscard_dll() -> Any:
    if sys.platform != "win32":
        raise TransportError("winscard.dll jest dostępny wyłącznie w systemie Windows.")
    try:
        return ctypes.WinDLL("winscard")  # type: ignore[attr-defined]
    except (OSError, AttributeError) as exc:
        raise TransportError(f"Nie można załadować winscard.dll: {exc}") from exc


def _load_pcsclite_lib() -> Any:
    for lib_name in ("libpcsclite.so.1", "libpcsclite.so"):
        try:
            return ctypes.CDLL(lib_name)
        except OSError:
            continue
    raise TransportError("Brak biblioteki libpcsclite.so.1 w systemie.")


class _BasePcscTransport(HIDTransport):
    """Wspólna baza PC/SC dla Windows (`winscard.dll`) i Linuksa (`libpcsclite`)."""

    def __init__(self, reader_name: str) -> None:
        self._reader_name = reader_name
        self._ctx: Any = None
        self._card: Any = None
        self._active_protocol: int = 0

    @property
    def product(self) -> str:
        return self._reader_name

    @property
    def protocol_family(self) -> str:
        return "acr122u"

    @property
    def supports_lf(self) -> bool:
        return False

    @property
    def is_open(self) -> bool:
        return self._card is not None

    @property
    def pcsc_card_present(self) -> bool:
        """True, gdy połączenie PC/SC ma aktywny protokół karty (T=0/T=1)."""
        return self._card is not None and self._active_protocol != 0

    def get_atr(self) -> bytes | None:
        """Zwraca ATR obecnej karty w trybie PC/SC lub None."""
        return None

    def write(self, data: bytes) -> int:
        raise TransportError("Czytnik ACR122U używa apdu_exchange(), nie surowych raportów HID 64 B.")

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        raise TransportError("Czytnik ACR122U używa apdu_exchange(), nie surowych raportów HID 64 B.")


class WindowsPcscTransport(_BasePcscTransport):
    """Natywny backend PC/SC dla Windowsa (`winscard.dll`, zero zależności pip)."""

    def __init__(self, reader_name: str, *, dll: Any | None = None) -> None:
        super().__init__(reader_name)
        self._dll = dll
        self._escape_ioctl: int = _IOCTL_CCID_ESCAPE_WIN
        self._escape_ioctl_probed: bool = False

    def _api(self) -> Any:
        if self._dll is None:
            self._dll = _load_winscard_dll()
        return self._dll

    def open(self) -> None:
        if self._card is not None:
            return
        api = self._api()
        ctx = ctypes.c_void_p()
        rc = int(api.SCardEstablishContext(_SCARD_SCOPE_USER, None, None, ctypes.byref(ctx)))
        if rc != 0:
            raise TransportError(f"SCardEstablishContext nie powiodło się (0x{rc & 0xFFFFFFFF:08X}).")

        card = ctypes.c_void_p()
        proto = ctypes.c_uint32(0)
        rc = int(
            api.SCardConnectW(
                ctx,
                self._reader_name,
                _SCARD_SHARE_SHARED,
                _SCARD_PROTOCOL_TX,
                ctypes.byref(card),
                ctypes.byref(proto),
            )
        )
        if rc != 0:
            rc_u32 = rc & 0xFFFFFFFF
            if rc_u32 != _SCARD_E_SHARING_VIOLATION:
                rc = int(
                    api.SCardConnectW(
                        ctx,
                        self._reader_name,
                        _SCARD_SHARE_DIRECT,
                        0,
                        ctypes.byref(card),
                        ctypes.byref(proto),
                    )
                )
        if rc != 0:
            rc_u32 = rc & 0xFFFFFFFF
            try:
                api.SCardReleaseContext(ctx)
            except Exception:
                pass
            if rc_u32 == _SCARD_E_SHARING_VIOLATION:
                raise TransportError(
                    f"Czytnik '{self._reader_name}' jest zajęty przez inny proces (0x8010000B). "
                    "Zamknij inne aplikacje NFC i spróbuj ponownie."
                )
            raise TransportError(
                f"SCardConnectW('{self._reader_name}') nie powiodło się (0x{rc_u32:08X})."
            )
        self._ctx = ctx
        self._card = card
        self._active_protocol = int(proto.value)

    def close(self) -> None:
        try:
            if self._dll is not None:
                if self._card is not None:
                    try:
                        self._dll.SCardDisconnect(self._card, _SCARD_LEAVE_CARD)
                    except Exception:
                        pass
                if self._ctx is not None:
                    try:
                        self._dll.SCardReleaseContext(self._ctx)
                    except Exception:
                        pass
        finally:
            self._card = None
            self._ctx = None
            self._active_protocol = 0
            self._escape_ioctl = _IOCTL_CCID_ESCAPE_WIN
            self._escape_ioctl_probed = False

    def get_atr(self) -> bytes | None:
        if self._card is None:
            return None
        api = self._api()
        status_fn = getattr(api, "SCardStatusW", None)
        if status_fn is None:
            return None
        reader_buf = (ctypes.c_wchar * 256)()
        reader_len = ctypes.c_uint32(256)
        state = ctypes.c_uint32(0)
        proto = ctypes.c_uint32(0)
        atr_buf = (ctypes.c_ubyte * 64)()
        atr_len = ctypes.c_uint32(64)
        rc = int(
            status_fn(
                self._card,
                reader_buf,
                ctypes.byref(reader_len),
                ctypes.byref(state),
                ctypes.byref(proto),
                atr_buf,
                ctypes.byref(atr_len),
            )
        )
        if rc != 0 or int(atr_len.value) <= 0:
            return None
        return bytes(atr_buf[: int(atr_len.value)])

    def _reconnect_shared(self, api: Any) -> None:
        """Przełącza uchwyt karty do SCARD_SHARE_SHARED (T=0/T=1), gdy karta jest obecna."""
        proto = ctypes.c_uint32(0)
        reconnect_fn = getattr(api, "SCardReconnect", None)
        if reconnect_fn is not None:
            rc = int(
                reconnect_fn(
                    self._card,
                    _SCARD_SHARE_SHARED,
                    _SCARD_PROTOCOL_TX,
                    _SCARD_LEAVE_CARD,
                    ctypes.byref(proto),
                )
            )
            if rc == 0 and int(proto.value) != 0:
                self._active_protocol = int(proto.value)
                return
            rc_u32 = rc & 0xFFFFFFFF
            if rc_u32 in _SCARD_NO_CARD_ERRORS:
                raise NoSmartCardError("Brak karty lub tagu na czytniku ACR122U.")

        if self._card is not None:
            try:
                api.SCardDisconnect(self._card, _SCARD_LEAVE_CARD)
            except Exception:
                pass
            self._card = None
            self._active_protocol = 0

        card = ctypes.c_void_p()
        rc = int(
            api.SCardConnectW(
                self._ctx,
                self._reader_name,
                _SCARD_SHARE_SHARED,
                _SCARD_PROTOCOL_TX,
                ctypes.byref(card),
                ctypes.byref(proto),
            )
        )
        if rc == 0:
            self._card = card
            self._active_protocol = int(proto.value)
            return

        rc_u32 = rc & 0xFFFFFFFF
        direct_card = ctypes.c_void_p()
        direct_proto = ctypes.c_uint32(0)
        if (
            int(
                api.SCardConnectW(
                    self._ctx,
                    self._reader_name,
                    _SCARD_SHARE_DIRECT,
                    0,
                    ctypes.byref(direct_card),
                    ctypes.byref(direct_proto),
                )
            )
            == 0
        ):
            self._card = direct_card
            self._active_protocol = int(direct_proto.value)
        if rc_u32 in _SCARD_NO_CARD_ERRORS:
            raise NoSmartCardError("Brak karty lub tagu na czytniku ACR122U.")
        raise TransportError(f"SCardReconnect/SCardConnectW(SHARED) nie powiodło się (0x{rc_u32:08X}).")

    def _resolve_escape_ioctl(self, api: Any) -> int:
        """Odpytuje CM_IOCTL_GET_FEATURE_REQUEST (0x00313520) o FEATURE_CCID_ESC_COMMAND (0x13)."""
        if self._escape_ioctl_probed:
            return self._escape_ioctl
        self._escape_ioctl_probed = True
        recv_buf = (ctypes.c_ubyte * 256)()
        recv_len = ctypes.c_uint32(256)
        try:
            rc = int(
                api.SCardControl(
                    self._card,
                    _CM_IOCTL_GET_FEATURE_REQUEST,
                    None,
                    0,
                    recv_buf,
                    len(recv_buf),
                    ctypes.byref(recv_len),
                )
            )
        except Exception:
            return self._escape_ioctl
        if rc != 0:
            return self._escape_ioctl
        raw = bytes(recv_buf[: int(recv_len.value)])
        idx = 0
        while idx + 2 <= len(raw):
            tag = raw[idx]
            length = raw[idx + 1]
            if idx + 2 + length > len(raw):
                break
            if tag == _FEATURE_CCID_ESC_COMMAND and length == 4:
                ioctl = int.from_bytes(raw[idx + 2 : idx + 6], "big")
                if ioctl != 0:
                    self._escape_ioctl = ioctl
                break
            idx += 2 + length
        return self._escape_ioctl

    def apdu_exchange(self, apdu: bytes, timeout_ms: int = 2000) -> bytes:
        if self._card is None:
            raise TransportError("Czytnik ACR122U (PC/SC) nie jest otwarty.")
        api = self._api()
        send_buf = (ctypes.c_ubyte * len(apdu))(*apdu)
        recv_buf = (ctypes.c_ubyte * 512)()
        recv_len = ctypes.c_uint32(512)

        if self._active_protocol == 0 or apdu[:2] == b"\xff\x00":
            escape_ioctl = self._resolve_escape_ioctl(api)
            rc = int(
                api.SCardControl(
                    self._card,
                    escape_ioctl,
                    send_buf,
                    len(apdu),
                    recv_buf,
                    len(recv_buf),
                    ctypes.byref(recv_len),
                )
            )
            if rc == 0:
                return bytes(recv_buf[: int(recv_len.value)])
            if self._active_protocol == 0:
                self._reconnect_shared(api)

        class _SCardIoRequest(ctypes.Structure):
            _fields_ = [("dwProtocol", ctypes.c_uint32), ("cbPciLength", ctypes.c_uint32)]

        for attempt in range(2):
            pci = _SCardIoRequest(self._active_protocol or 2, ctypes.sizeof(_SCardIoRequest))
            recv_len = ctypes.c_uint32(512)
            rc = int(
                api.SCardTransmit(
                    self._card,
                    ctypes.byref(pci),
                    send_buf,
                    len(apdu),
                    None,
                    recv_buf,
                    ctypes.byref(recv_len),
                )
            )
            if rc == 0:
                return bytes(recv_buf[: int(recv_len.value)])
            rc_u32 = rc & 0xFFFFFFFF
            if rc_u32 in _SCARD_NO_CARD_ERRORS:
                raise NoSmartCardError("Brak karty lub tagu na czytniku ACR122U.")
            if rc_u32 == _SCARD_W_RESET_CARD and attempt == 0:
                self._reconnect_shared(api)
                continue
            raise TransportError(f"SCardTransmit(ACR122U) nie powiodło się (0x{rc_u32:08X}).")
        raise TransportError("SCardTransmit(ACR122U) nie powiodło się.")


class LinuxPcscTransport(_BasePcscTransport):
    """Backend PC/SC dla Linuksa (`libpcsclite.so.1`, jeśli `pcscd` działa)."""

    def __init__(self, reader_name: str, *, lib: Any | None = None) -> None:
        super().__init__(reader_name)
        self._lib = lib

    def _api(self) -> Any:
        if self._lib is None:
            self._lib = _load_pcsclite_lib()
        return self._lib

    def open(self) -> None:
        if self._card is not None:
            return
        api = self._api()
        ctx = ctypes.c_long(0)
        rc = int(api.SCardEstablishContext(_SCARD_SCOPE_USER, None, None, ctypes.byref(ctx)))
        if rc != 0:
            raise TransportError(f"SCardEstablishContext (pcsclite) błąd 0x{rc & 0xFFFFFFFF:08X}.")

        card = ctypes.c_long(0)
        proto = ctypes.c_ulong(0)
        name_bytes = self._reader_name.encode("utf-8")
        rc = int(
            api.SCardConnect(
                ctx,
                name_bytes,
                _SCARD_SHARE_DIRECT,
                0,
                ctypes.byref(card),
                ctypes.byref(proto),
            )
        )
        if rc != 0:
            rc = int(
                api.SCardConnect(
                    ctx,
                    name_bytes,
                    _SCARD_SHARE_SHARED,
                    _SCARD_PROTOCOL_TX,
                    ctypes.byref(card),
                    ctypes.byref(proto),
                )
            )
        if rc != 0:
            api.SCardReleaseContext(ctx)
            raise TransportError(f"SCardConnect('{self._reader_name}') błąd 0x{rc & 0xFFFFFFFF:08X}.")
        self._ctx = ctx
        self._card = card
        self._active_protocol = int(proto.value)

    def close(self) -> None:
        if self._lib is not None:
            if self._card is not None:
                try:
                    self._lib.SCardDisconnect(self._card, _SCARD_LEAVE_CARD)
                except Exception:
                    pass
                self._card = None
            if self._ctx is not None:
                try:
                    self._lib.SCardReleaseContext(self._ctx)
                except Exception:
                    pass
                self._ctx = None
        self._active_protocol = 0

    def apdu_exchange(self, apdu: bytes, timeout_ms: int = 2000) -> bytes:
        if self._card is None:
            raise TransportError("Czytnik ACR122U (PC/SC) nie jest otwarty.")
        api = self._api()
        send_buf = (ctypes.c_ubyte * len(apdu))(*apdu)
        recv_buf = (ctypes.c_ubyte * 512)()
        recv_len = ctypes.c_ulong(0)

        if self._active_protocol == 0 or apdu[:2] == b"\xff\x00":
            for ctl in (_IOCTL_CCID_ESCAPE_LINUX, _IOCTL_CCID_ALT_LINUX):
                recv_len = ctypes.c_ulong(0)
                rc = int(
                    api.SCardControl(
                        self._card,
                        ctl,
                        send_buf,
                        len(apdu),
                        recv_buf,
                        len(recv_buf),
                        ctypes.byref(recv_len),
                    )
                )
                if rc == 0:
                    return bytes(recv_buf[: int(recv_len.value)])
            if self._active_protocol == 0:
                raise TransportError(f"SCardControl (pcsclite) błąd 0x{rc & 0xFFFFFFFF:08X}.")

        class _PcscIoRequest(ctypes.Structure):
            _fields_ = [("dwProtocol", ctypes.c_ulong), ("cbPciLength", ctypes.c_ulong)]

        pci = _PcscIoRequest(self._active_protocol or 2, ctypes.sizeof(_PcscIoRequest))
        recv_len = ctypes.c_ulong(len(recv_buf))
        rc = int(
            api.SCardTransmit(
                self._card,
                ctypes.byref(pci),
                send_buf,
                len(apdu),
                None,
                recv_buf,
                ctypes.byref(recv_len),
            )
        )
        if rc != 0:
            raise TransportError(f"SCardTransmit (pcsclite) błąd 0x{rc & 0xFFFFFFFF:08X}.")
        return bytes(recv_buf[: int(recv_len.value)])


class _UsbdevfsBulkTransfer(ctypes.Structure):
    _fields_ = [
        ("ep", ctypes.c_uint),
        ("len", ctypes.c_uint),
        ("timeout", ctypes.c_uint),
        ("data", ctypes.c_void_p),
    ]


class _UsbdevfsIoctl(ctypes.Structure):
    _fields_ = [
        ("ifno", ctypes.c_int),
        ("ioctl_code", ctypes.c_int),
        ("data", ctypes.c_void_p),
    ]


def _iowr(kind: str, nr: int, size: int) -> int:
    return (3 << 30) | (size << 16) | (ord(kind) << 8) | nr


def _ior(kind: str, nr: int, size: int) -> int:
    return (2 << 30) | (size << 16) | (ord(kind) << 8) | nr


_USBDEVFS_BULK = _iowr("U", 2, ctypes.sizeof(_UsbdevfsBulkTransfer))
_USBDEVFS_CLAIMINTERFACE = _ior("U", 15, ctypes.sizeof(ctypes.c_uint))
_USBDEVFS_RELEASEINTERFACE = _ior("U", 16, ctypes.sizeof(ctypes.c_uint))
_USBDEVFS_IOCTL = _iowr("U", 18, ctypes.sizeof(_UsbdevfsIoctl))
_USBDEVFS_DISCONNECT = (ord("U") << 8) | 22


def _build_ccid_frame(msg_type: int, seq: int, payload: bytes = b"", param0: int = 0, param1: int = 0) -> bytes:
    """Buduje 10-bajtowy nagłówek CCID + ładunek."""
    return struct.pack("<BIBBBH", msg_type & 0xFF, len(payload), 0, seq & 0xFF, param0 & 0xFF, param1 & 0xFFFF) + payload


def _parse_ccid_frame(raw: bytes) -> tuple[int, int, int, int, bytes]:
    """Dekoduje 10-bajtową odpowiedź CCID: (msg_type, seq, status, error, payload)."""
    if len(raw) < 10:
        raise TransportError(f"Za krótka odpowiedź CCID ({len(raw)} B).")
    msg_type, dw_len, _slot, seq, b_status, b_error, _param = struct.unpack("<BIBBBBB", raw[:10])
    payload = raw[10 : 10 + dw_len]
    return msg_type, seq, b_status, b_error, payload


class LinuxUsbCcidTransport(HIDTransport):
    """Bezpośredni backend Linux USB CCID (`USBDEVFS_*` na `/dev/bus/usb/BBB/DDD`, bez pyusb/libusb)."""

    def __init__(
        self,
        path: str,
        *,
        ep_out: int = 0x02,
        ep_in: int = 0x82,
        interface_num: int = 0,
        product: str = "ACS ACR122U PICC Interface",
        ioctl_fn: Any | None = None,
    ) -> None:
        self._path = path
        self._ep_out = ep_out
        self._ep_in = ep_in
        self._interface_num = interface_num
        self._product = product
        self._fd: int | None = None
        self._seq = 0
        self._ioctl_fn = ioctl_fn

    @property
    def product(self) -> str:
        return self._product

    @property
    def protocol_family(self) -> str:
        return "acr122u"

    @property
    def supports_lf(self) -> bool:
        return False

    @property
    def is_open(self) -> bool:
        return self._fd is not None

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) & 0xFF
        return seq

    def _do_ioctl(self, fd: int, request: int, arg: Any) -> int:
        if self._ioctl_fn is not None:
            return int(self._ioctl_fn(fd, request, arg))
        import fcntl

        return int(fcntl.ioctl(fd, request, arg))

    def _bulk_transfer(self, ep: int, data: bytes | int, timeout_ms: int) -> bytes:
        if self._fd is None:
            raise TransportError("Urządzenie USB CCID nie jest otwarte.")
        if isinstance(data, int):
            buf = (ctypes.c_ubyte * data)()
            length = data
        else:
            buf = (ctypes.c_ubyte * len(data))(*data)
            length = len(data)
        xfer = _UsbdevfsBulkTransfer(
            ep=ep,
            len=length,
            timeout=max(100, timeout_ms),
            data=ctypes.cast(buf, ctypes.c_void_p).value,
        )
        nbytes = self._do_ioctl(self._fd, _USBDEVFS_BULK, xfer)
        if isinstance(data, int):
            return bytes(buf[:nbytes])
        return data[:nbytes]

    def open(self) -> None:
        if self._fd is not None:
            return
        try:
            fd = os.open(self._path, os.O_RDWR)
        except PermissionError as exc:
            raise TransportError(
                f"Brak uprawnień zapisu do {self._path}. Zainstaluj regułę udev z pliku udev/99-nfcplus.rules."
            ) from exc
        except OSError as exc:
            raise TransportError(f"Nie można otworzyć {self._path}: {exc}") from exc

        self._fd = fd
        try:
            # Odłącz sterownik jądra (np. pn533_usb) od interfejsu 0, jeśli jest podpięty.
            disc = _UsbdevfsIoctl(ifno=self._interface_num, ioctl_code=_USBDEVFS_DISCONNECT, data=0)
            try:
                self._do_ioctl(fd, _USBDEVFS_IOCTL, disc)
            except OSError:
                pass

            iface = ctypes.c_uint(self._interface_num)
            try:
                self._do_ioctl(fd, _USBDEVFS_CLAIMINTERFACE, iface)
            except OSError as exc:
                if getattr(exc, "errno", None) == 16:  # EBUSY
                    raise TransportError(
                        f"Interfejs USB {self._path} jest zajęty (np. przez sterownik jądra pn533_usb lub pcscd): {exc}"
                    ) from exc
                raise TransportError(f"Nie można zająć interfejsu USB CCID ({self._path}): {exc}") from exc

            # PC_to_RDR_IccPowerOn (0x62): inicjalizacja slotu CCID (ignorujemy błąd braku karty).
            try:
                self._ccid_exchange(0x62, b"", timeout_ms=500, ignore_card_absent=True)
            except TransportError:
                pass
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._fd is not None:
            try:
                iface = ctypes.c_uint(self._interface_num)
                self._do_ioctl(self._fd, _USBDEVFS_RELEASEINTERFACE, iface)
            except Exception:
                pass
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def _ccid_exchange(
        self,
        msg_type: int,
        payload: bytes,
        *,
        timeout_ms: int = 2000,
        ignore_card_absent: bool = False,
    ) -> bytes:
        seq = self._next_seq()
        packet = _build_ccid_frame(msg_type, seq, payload)
        self._bulk_transfer(self._ep_out, packet, timeout_ms)

        while True:
            raw = self._bulk_transfer(self._ep_in, 512, timeout_ms)
            _r_type, _r_seq, b_status, b_error, resp_payload = _parse_ccid_frame(raw)
            cmd_status = (b_status >> 6) & 0x03
            if cmd_status == 0x02:  # CCID Time Extension
                continue
            if cmd_status != 0x00:
                if ignore_card_absent and b_error in (0xFE, 0xFF):
                    return b""
                raise TransportError(f"Błąd CCID ACR122U (status=0x{b_status:02X}, error=0x{b_error:02X}).")
            return resp_payload

    def apdu_exchange(self, apdu: bytes, timeout_ms: int = 2000) -> bytes:
        return self._ccid_exchange(0x6F, apdu, timeout_ms=timeout_ms)

    def write(self, data: bytes) -> int:
        raise TransportError("Czytnik ACR122U używa apdu_exchange(), nie surowych raportów HID 64 B.")

    def read(self, size: int = 64, timeout_ms: int = 2000) -> bytes:
        raise TransportError("Czytnik ACR122U używa apdu_exchange(), nie surowych raportów HID 64 B.")


def _enumerate_windows_pcsc() -> list[DeviceInfo]:
    if sys.platform != "win32":
        return []
    try:
        api = _load_winscard_dll()
    except TransportError:
        return []

    ctx = ctypes.c_void_p()
    if int(api.SCardEstablishContext(_SCARD_SCOPE_USER, None, None, ctypes.byref(ctx))) != 0:
        return []
    try:
        ch_len = ctypes.c_uint32(0)
        rc = int(api.SCardListReadersW(ctx, None, None, ctypes.byref(ch_len)))
        if rc != 0 or ch_len.value == 0:
            return []
        buf = (ctypes.c_wchar * int(ch_len.value))()
        if int(api.SCardListReadersW(ctx, None, buf, ctypes.byref(ch_len))) != 0:
            return []
        names = _parse_pcsc_multi_string(bytes(buf), encoding="utf-16-le")
    finally:
        api.SCardReleaseContext(ctx)

    return [
        DeviceInfo(
            vid=0x072F,
            pid=0x2200,
            path=name,
            product=name,
            manufacturer="ACS",
            backend="winscard",
            protocol_family="acr122u",
            supports_lf=False,
        )
        for name in names
        if _is_acr122_reader_name(name)
    ]


def _enumerate_linux_pcsc() -> list[DeviceInfo]:
    if not sys.platform.startswith("linux"):
        return []
    try:
        api = _load_pcsclite_lib()
    except TransportError:
        return []

    ctx = ctypes.c_long(0)
    if int(api.SCardEstablishContext(_SCARD_SCOPE_USER, None, None, ctypes.byref(ctx))) != 0:
        return []
    try:
        ch_len = ctypes.c_ulong(0)
        rc = int(api.SCardListReaders(ctx, None, None, ctypes.byref(ch_len)))
        if rc != 0 or ch_len.value == 0:
            return []
        buf = ctypes.create_string_buffer(int(ch_len.value))
        if int(api.SCardListReaders(ctx, None, buf, ctypes.byref(ch_len))) != 0:
            return []
        names = _parse_pcsc_multi_string(buf.raw, encoding="utf-8")
    finally:
        api.SCardReleaseContext(ctx)

    return [
        DeviceInfo(
            vid=0x072F,
            pid=0x2200,
            path=name,
            product=name,
            manufacturer="ACS",
            backend="pcsc",
            protocol_family="acr122u",
            supports_lf=False,
        )
        for name in names
        if _is_acr122_reader_name(name)
    ]


def _enumerate_linux_usb_ccid(
    ccid_ids: dict[tuple[int, int], str] | None = None,
    sysfs_root: Path = Path("/sys/bus/usb/devices"),
) -> list[DeviceInfo]:
    """Wykrywa czytniki CCID (np. ACS ACR122U 072f:2200) przez Linux sysfs (`/sys/bus/usb/devices`)."""
    allowed = ccid_ids if ccid_ids is not None else SUPPORTED_CCID_IDS
    found: list[DeviceInfo] = []
    if not sysfs_root.exists():
        return found

    for entry in sorted(sysfs_root.iterdir()):
        if ":" in entry.name:
            continue
        vid_file = entry / "idVendor"
        pid_file = entry / "idProduct"
        bus_file = entry / "busnum"
        dev_file = entry / "devnum"
        if not (vid_file.is_file() and pid_file.is_file() and bus_file.is_file() and dev_file.is_file()):
            continue
        try:
            vid = int(vid_file.read_text(encoding="utf-8").strip(), 16)
            pid = int(pid_file.read_text(encoding="utf-8").strip(), 16)
            busnum = int(bus_file.read_text(encoding="utf-8").strip(), 10)
            devnum = int(dev_file.read_text(encoding="utf-8").strip(), 10)
        except (OSError, ValueError):
            continue
        if (vid, pid) not in allowed:
            continue

        def _read_opt(name: str) -> str:
            p = entry / name
            if p.is_file():
                try:
                    return p.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    return ""
            return ""

        product = _read_opt("product") or allowed[(vid, pid)]
        manufacturer = _read_opt("manufacturer")
        serial = _read_opt("serial")
        found.append(
            DeviceInfo(
                vid=vid,
                pid=pid,
                path=f"/dev/bus/usb/{busnum:03d}/{devnum:03d}",
                product=product,
                manufacturer=manufacturer,
                serial=serial,
                backend="ccid_usb",
                protocol_family="acr122u",
                supports_lf=False,
            )
        )
    return found
