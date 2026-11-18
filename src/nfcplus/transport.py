"""Warstwa transportowa USB HID dla czytników wCopy / Xixei / NFC Pro."""

from __future__ import annotations

import ctypes
import os
import select
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SUPPORTED_USB_IDS: tuple[tuple[int, int], ...] = (
    (0x0416, 0xB030),
    (0x0416, 0xB031),
    (0x2518, 0x6022),
    (0x2518, 0x6018),
)


class TransportError(RuntimeError):
    """Błąd komunikacji z urządzeniem USB HID."""


@dataclass(frozen=True)
class DeviceInfo:
    """Metadane wykrytego czytnika USB HID."""

    vid: int
    pid: int
    path: str
    product: str = ""
    manufacturer: str = ""
    serial: str = ""
    backend: str = ""

    @property
    def vid_pid(self) -> str:
        return f"{self.vid:04x}:{self.pid:04x}"


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
    """Zwraca listę wykrytych czytników NFC kompatybilnych z protokołem wCopy/Xixei."""
    ids = tuple(usb_ids)
    devices = _enumerate_hidapi(ids)
    if sys.platform == "win32":
        seen = {dev.path.casefold() for dev in devices}
        for win_dev in _enumerate_windows_hid(ids):
            key = win_dev.path.casefold()
            if key not in seen:
                seen.add(key)
                devices.append(win_dev)
        return devices
    if devices:
        return devices
    if sys.platform.startswith("linux"):
        return _enumerate_linux_hidraw(ids)
    return []


def _create_transport_for_device(dev: DeviceInfo) -> HIDTransport:
    if dev.backend == "hidraw":
        return LinuxHidrawTransport(dev.path)
    if dev.backend == "win32":
        return WindowsHidTransport(dev.path)
    return HidApiTransport(dev.path)


def open_reader(
    vid: int | None = None,
    pid: int | None = None,
    path: str | None = None,
) -> tuple[DeviceInfo, HIDTransport]:
    """Wyszukuje i otwiera pierwszy pasujący czytnik USB HID."""
    if path is not None:
        matched = next(
            (
                dev
                for dev in enumerate_readers()
                if (dev.path.casefold() == path.casefold() if sys.platform == "win32" else dev.path == path)
            ),
            None,
        )
        if path.startswith("/dev/hidraw"):
            info = matched or DeviceInfo(vid=vid or 0, pid=pid or 0, path=path, backend="hidraw")
            transport: HIDTransport = LinuxHidrawTransport(path)
        elif sys.platform == "win32":
            info = matched or DeviceInfo(vid=vid or 0, pid=pid or 0, path=path, backend="win32")
            transport = (
                HidApiTransport(path)
                if matched is not None and matched.backend == "hidapi"
                else WindowsHidTransport(path)
            )
        else:
            info = matched or DeviceInfo(vid=vid or 0, pid=pid or 0, path=path, backend="manual")
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
        supported_str = ", ".join(f"{v:04x}:{p:04x}" for v, p in SUPPORTED_USB_IDS)
        raise TransportError(
            f"Nie znaleziono żadnego kompatybilnego czytnika USB HID ({supported_str}). "
            f"{no_readers_hint()}"
        )
    raise TransportError(
        f"Nie znaleziono czytnika pasującego do filtru VID={vid} PID={pid}. {no_readers_hint()}"
    )
