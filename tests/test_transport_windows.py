"""Testy jednostkowe warstwy Windows HID (`WindowsHidTransport`) z mockami Win32 API."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nfcplus import app as app_mod
from nfcplus import transport as transport_mod
from nfcplus.protocol import START_NATIVE, START_PN532, NFCReader, build_frame, compute_checksum
from nfcplus.transport import (
    _ERROR_ACCESS_DENIED,
    _ERROR_FILE_NOT_FOUND,
    _ERROR_IO_PENDING,
    _HIDP_STATUS_SUCCESS,
    _INVALID_HANDLE_VALUE,
    _WAIT_OBJECT_0,
    _WAIT_TIMEOUT,
    DeviceInfo,
    TransportError,
    WindowsHidTransport,
    _enumerate_windows_hid,
    _GUID,
    _HiddAttributes,
    _HidpCaps,
    _Overlapped,
    _SPDeviceInterfaceData,
    _Win32HidApi,
    enumerate_readers,
    no_readers_hint,
    open_reader,
)


def _make_frame(start: int, seq: int, payload: bytes) -> bytes:
    end = 0xFE if start == START_NATIVE else 0xFD
    body = bytes([start, len(payload) + 6, seq & 0xFF, (seq >> 8) & 0xFF]) + payload
    csum = compute_checksum(body)
    return (body + bytes([csum, end])).ljust(64, b"\x00")


class _FakeWin32Harness:
    """Symulator wywołań setupapi.dll / hid.dll / kernel32.dll dla testów bez Windows."""

    def __init__(
        self,
        devices: list[dict[str, object]] | None = None,
        input_report_len: int = 65,
        output_report_len: int = 65,
    ) -> None:
        self.devices = devices or []
        self.input_report_len = input_report_len
        self.output_report_len = output_report_len
        self.last_error = 0
        self.open_error: int | None = None
        self.written_packets: list[bytes] = []
        self.read_queue: list[bytes] = []
        self.read_pending = False
        self.write_pending = False
        self.wait_result = _WAIT_OBJECT_0
        self.closed_handles: list[int] = []
        self.freed_preparsed: list[int] = []
        self.destroyed_dev_info: list[int] = []
        self.cancel_calls: list[int] = []
        self.wait_timeouts: list[int] = []

        self._handle_to_dev: dict[int, dict[str, object]] = {}
        self._next_handle = 0x1000
        self._pending_read_buf_ptr: int | None = None
        self._pending_read_data: bytes = b""
        self._read_cancelled = False

        self.setupapi = SimpleNamespace(
            SetupDiGetClassDevsW=MagicMock(side_effect=self._setup_di_get_class_devs),
            SetupDiEnumDeviceInterfaces=MagicMock(side_effect=self._setup_di_enum_interfaces),
            SetupDiGetDeviceInterfaceDetailW=MagicMock(side_effect=self._setup_di_get_detail),
            SetupDiDestroyDeviceInfoList=MagicMock(side_effect=self._setup_di_destroy),
        )
        self.hid = SimpleNamespace(
            HidD_GetHidGuid=MagicMock(side_effect=self._hidd_get_guid),
            HidD_GetAttributes=MagicMock(side_effect=self._hidd_get_attributes),
            HidD_GetPreparsedData=MagicMock(side_effect=self._hidd_get_preparsed),
            HidD_FreePreparsedData=MagicMock(side_effect=self._hidd_free_preparsed),
            HidP_GetCaps=MagicMock(side_effect=self._hidp_get_caps),
            HidD_GetProductString=MagicMock(side_effect=self._hidd_get_product),
            HidD_GetManufacturerString=MagicMock(side_effect=self._hidd_get_manufacturer),
            HidD_GetSerialNumberString=MagicMock(side_effect=self._hidd_get_serial),
            HidD_SetNumInputBuffers=MagicMock(return_value=1),
        )
        self.kernel32 = SimpleNamespace(
            CreateFileW=MagicMock(side_effect=self._create_file),
            CloseHandle=MagicMock(side_effect=self._close_handle),
            CreateEventW=MagicMock(side_effect=self._create_event),
            ResetEvent=MagicMock(return_value=1),
            ReadFile=MagicMock(side_effect=self._read_file),
            WriteFile=MagicMock(side_effect=self._write_file),
            WaitForSingleObject=MagicMock(side_effect=self._wait_for_single_object),
            GetOverlappedResult=MagicMock(side_effect=self._get_overlapped_result),
            CancelIo=MagicMock(side_effect=self._cancel_io),
        )
        self.api = _Win32HidApi(
            setupapi=self.setupapi,
            hid=self.hid,
            kernel32=self.kernel32,
        )
        self.api.get_last_error = lambda: self.last_error  # type: ignore[attr-defined]

    @staticmethod
    def _deref_ptr(arg: object) -> int:
        # ctypes.byref(x) tworzy obiekt CArgObject z atrybutem _obj, a cast do c_void_p daje adres
        obj = getattr(arg, "_obj", None)
        if obj is not None:
            return ctypes.addressof(obj)
        if isinstance(arg, int):
            return arg
        return ctypes.addressof(arg)  # type: ignore[arg-type]

    def _hidd_get_guid(self, guid_ptr: object) -> None:
        guid = _GUID.from_address(self._deref_ptr(guid_ptr))
        guid.Data1 = 0x4D1E55B2

    def _setup_di_get_class_devs(self, *_args: object) -> int:
        return 0x2000

    def _setup_di_destroy(self, dev_info: int) -> int:
        self.destroyed_dev_info.append(dev_info)
        return 1

    def _setup_di_enum_interfaces(self, _dev_info: int, _dev_data: object, _guid: object, idx: int, _if_data: object) -> int:
        return 1 if 0 <= idx < len(self.devices) else 0

    def _setup_di_get_detail(
        self,
        _dev_info: int,
        if_data_ptr: object,
        detail_buf: object,
        buf_size: int,
        required_size_ptr: object,
        _dev_info_data: object,
    ) -> int:
        # Odtwarzamy indeks z kolejności wywołań SetupDiEnumDeviceInterfaces
        idx = self.setupapi.SetupDiEnumDeviceInterfaces.call_count - 1
        path = str(self.devices[idx]["path"])
        encoded = (path + "\x00").encode("utf-16-le")
        needed = 4 + len(encoded)
        if detail_buf is None:
            req = ctypes.c_uint32.from_address(self._deref_ptr(required_size_ptr))
            req.value = needed
            return 0
        assert buf_size >= needed
        dest = ctypes.addressof(detail_buf) + 4  # type: ignore[arg-type]
        ctypes.memmove(dest, encoded, len(encoded))
        return 1

    def _create_file(self, path: str, *_args: object) -> int:
        if self.open_error is not None:
            self.last_error = self.open_error
            return _INVALID_HANDLE_VALUE
        matched = next((d for d in self.devices if str(d["path"]).casefold() == path.casefold()), None)
        if matched is None and self.devices:
            self.last_error = _ERROR_FILE_NOT_FOUND
            return _INVALID_HANDLE_VALUE
        self._next_handle += 1
        handle = self._next_handle
        self._handle_to_dev[handle] = matched or {
            "path": path,
            "vid": 0x0416,
            "pid": 0xB030,
            "in_len": self.input_report_len,
            "out_len": self.output_report_len,
        }
        return handle

    def _close_handle(self, handle: int) -> int:
        self.closed_handles.append(handle)
        return 1

    def _create_event(self, *_args: object) -> int:
        self._next_handle += 1
        return self._next_handle

    def _hidd_get_attributes(self, handle: int, attrs_ptr: object) -> int:
        dev = self._handle_to_dev[handle]
        attrs = _HiddAttributes.from_address(self._deref_ptr(attrs_ptr))
        attrs.VendorID = int(dev["vid"])  # type: ignore[arg-type]
        attrs.ProductID = int(dev["pid"])  # type: ignore[arg-type]
        return 1

    def _hidd_get_preparsed(self, handle: int, preparsed_ptr: object) -> int:
        ptr = ctypes.c_void_p.from_address(self._deref_ptr(preparsed_ptr))
        ptr.value = handle + 0x5000
        return 1

    def _hidd_free_preparsed(self, preparsed: int) -> int:
        self.freed_preparsed.append(preparsed)
        return 1

    def _hidp_get_caps(self, preparsed: object, caps_ptr: object) -> int:
        preparsed_val = preparsed.value if isinstance(preparsed, ctypes.c_void_p) else int(preparsed)  # type: ignore[arg-type]
        handle = int(preparsed_val) - 0x5000
        dev = self._handle_to_dev[handle]
        caps = _HidpCaps.from_address(self._deref_ptr(caps_ptr))
        caps.InputReportByteLength = int(dev.get("in_len", self.input_report_len))  # type: ignore[arg-type]
        caps.OutputReportByteLength = int(dev.get("out_len", self.output_report_len))  # type: ignore[arg-type]
        return _HIDP_STATUS_SUCCESS

    def _write_wstr(self, buf: object, value: str) -> int:
        if not value:
            return 0
        encoded = (value + "\x00").encode("utf-16-le")
        ctypes.memmove(ctypes.addressof(buf), encoded, len(encoded))  # type: ignore[arg-type]
        return 1

    def _hidd_get_product(self, handle: int, buf: object, _size: int) -> int:
        return self._write_wstr(buf, str(self._handle_to_dev[handle].get("product", "")))

    def _hidd_get_manufacturer(self, handle: int, buf: object, _size: int) -> int:
        return self._write_wstr(buf, str(self._handle_to_dev[handle].get("manufacturer", "")))

    def _hidd_get_serial(self, handle: int, buf: object, _size: int) -> int:
        return self._write_wstr(buf, str(self._handle_to_dev[handle].get("serial", "")))

    def _write_file(self, _handle: int, buf: object, length: int, written_ptr: object, _ov: object) -> int:
        raw = ctypes.string_at(ctypes.addressof(buf), length)  # type: ignore[arg-type]
        self.written_packets.append(raw)
        if self.write_pending:
            self.last_error = _ERROR_IO_PENDING
            self._pending_written = length
            return 0
        written = ctypes.c_uint32.from_address(self._deref_ptr(written_ptr))
        written.value = length
        return 1

    def _read_file(self, _handle: int, buf: object, length: int, read_ptr: object, _ov: object) -> int:
        data = self.read_queue.pop(0) if self.read_queue else b""
        data = data[:length]
        self._pending_read_buf_ptr = ctypes.addressof(buf)  # type: ignore[arg-type]
        self._pending_read_data = data
        if self.read_pending:
            self.last_error = _ERROR_IO_PENDING
            return 0
        if data:
            ctypes.memmove(self._pending_read_buf_ptr, data, len(data))
        cnt = ctypes.c_uint32.from_address(self._deref_ptr(read_ptr))
        cnt.value = len(data)
        return 1

    def _wait_for_single_object(self, _event: int, timeout_ms: int) -> int:
        self.wait_timeouts.append(timeout_ms)
        return self.wait_result

    def _get_overlapped_result(self, _handle: int, _ov: object, transferred_ptr: object, _wait: int) -> int:
        cnt = ctypes.c_uint32.from_address(self._deref_ptr(transferred_ptr))
        if self._read_cancelled:
            self._read_cancelled = False
            self._pending_read_buf_ptr = None
            cnt.value = 0
            self.last_error = 995  # ERROR_OPERATION_ABORTED
            return 0
        if self._pending_read_buf_ptr is not None:
            if self._pending_read_data:
                ctypes.memmove(self._pending_read_buf_ptr, self._pending_read_data, len(self._pending_read_data))
            cnt.value = len(self._pending_read_data)
            self._pending_read_buf_ptr = None
        else:
            cnt.value = getattr(self, "_pending_written", 0)
        return 1

    def _cancel_io(self, handle: int) -> int:
        self.cancel_calls.append(handle)
        self._read_cancelled = True
        return 1


def test_enumerate_windows_hid_filters_usb_ids_and_cleans_handles() -> None:
    harness = _FakeWin32Harness(
        devices=[
            {
                "path": r"\\?\hid#vid_046d&pid_c31c#kbd",
                "vid": 0x046D,
                "pid": 0xC31C,
                "product": "Keyboard",
            },
            {
                "path": r"\\?\hid#vid_0416&pid_b030#reader1",
                "vid": 0x0416,
                "pid": 0xB030,
                "product": "wCopy HID Reader",
                "manufacturer": "Nuvoton",
                "serial": "SN12345",
                "in_len": 65,
                "out_len": 65,
            },
            {
                "path": r"\\?\hid#vid_2518&pid_6022#empty_caps",
                "vid": 0x2518,
                "pid": 0x6022,
                "in_len": 0,
                "out_len": 0,
            },
        ]
    )

    found = _enumerate_windows_hid(((0x0416, 0xB030), (0x2518, 0x6022)), api=harness.api)
    assert len(found) == 1
    assert found[0] == DeviceInfo(
        vid=0x0416,
        pid=0xB030,
        path=r"\\?\hid#vid_0416&pid_b030#reader1",
        product="wCopy HID Reader",
        manufacturer="Nuvoton",
        serial="SN12345",
        backend="win32",
    )
    assert len(harness.destroyed_dev_info) == 1
    assert len(harness.freed_preparsed) == 2  # oba dopasowane VID:PID zwolniły preparsed data
    assert len(harness.closed_handles) == 3


def test_enumerate_readers_on_win32_zero_dep_and_deduplication(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_mod.sys, "platform", "win32")
    monkeypatch.setattr(transport_mod, "_enumerate_hidapi", lambda _ids: [])
    win_dev = DeviceInfo(vid=0x0416, pid=0xB030, path=r"\\?\HID#VID_0416&PID_B030#1", backend="win32")
    monkeypatch.setattr(transport_mod, "_enumerate_windows_hid", lambda _ids: [win_dev])

    assert enumerate_readers() == [win_dev]

    # Gdy hidapi zwróci tę samą ścieżkę (w innej wielkości liter), nie duplikujemy wpisu
    hidapi_dev = DeviceInfo(vid=0x0416, pid=0xB030, path=r"\\?\hid#vid_0416&pid_b030#1", backend="hidapi")
    monkeypatch.setattr(transport_mod, "_enumerate_hidapi", lambda _ids: [hidapi_dev])
    assert enumerate_readers() == [hidapi_dev]


def test_windows_hid_write_handles_65_and_64_byte_reports() -> None:
    path = r"\\?\hid#vid_0416&pid_b030#1"
    # Przypadek 1: OutputReportByteLength == 65, ramka z build_frame() ma już wiodące 0x00 (64 B)
    harness_65 = _FakeWin32Harness(
        devices=[{"path": path, "vid": 0x0416, "pid": 0xB030, "in_len": 65, "out_len": 65}],
        input_report_len=65,
        output_report_len=65,
    )
    harness_65.write_pending = True
    t65 = WindowsHidTransport(path, api=harness_65.api)
    with t65:
        frame_with_rid = build_frame(b"\xff\x00\x68", seq=0)
        assert len(frame_with_rid) == 64
        assert frame_with_rid[0] == 0x00
        written = t65.write(frame_with_rid)
        assert written == 65
        assert len(harness_65.written_packets[0]) == 65
        assert harness_65.written_packets[0][0] == 0x00
        assert harness_65.written_packets[0][1] == START_NATIVE

        # Ramka 64 B bez wiodącego 0x00 powinna otrzymać prefiks Report ID 0x00
        raw_no_rid = _make_frame(START_NATIVE, 0, b"\xff\x00\x68")
        assert raw_no_rid[0] == START_NATIVE
        t65.write(raw_no_rid)
        assert len(harness_65.written_packets[1]) == 65
        assert harness_65.written_packets[1] == b"\x00" + raw_no_rid

    # Przypadek 2: OutputReportByteLength == 64 -> dokładnie 64 bajty bez powielania
    harness_64 = _FakeWin32Harness(
        devices=[{"path": path, "vid": 0x0416, "pid": 0xB030, "in_len": 64, "out_len": 64}],
        input_report_len=64,
        output_report_len=64,
    )
    t64 = WindowsHidTransport(path, api=harness_64.api)
    with t64:
        frame = build_frame(b"\xff\x00\x68", seq=0)
        written = t64.write(frame)
        assert written == 64
        assert harness_64.written_packets[0] == frame


def test_windows_hid_read_strips_report_id_and_handles_overlapped_timeout() -> None:
    path = r"\\?\hid#vid_0416&pid_b030#1"
    fw_frame = _make_frame(START_PN532, 1, b"wCopy NSR122-HID V901N1")
    sn_frame = _make_frame(START_PN532, 3, b"P37354833679")

    harness = _FakeWin32Harness(
        devices=[{"path": path, "vid": 0x0416, "pid": 0xB030, "in_len": 65, "out_len": 65}],
        input_report_len=65,
        output_report_len=65,
    )
    harness.read_pending = True
    harness.read_queue = [b"\x00" + fw_frame, b"\x00" + sn_frame]

    t = WindowsHidTransport(path, api=harness.api)
    with t:
        reader = NFCReader(t, timeout_ms=1500)
        info = reader.get_device_info()
        assert info["firmware"] == "wCopy NSR122-HID V901N1"
        assert info["model"] == "P37354833679"
        assert harness.wait_timeouts == [1500, 1500]

        # Test przekroczenia czasu (WAIT_TIMEOUT -> CancelIo -> GetOverlappedResult(..., 1) -> TimeoutError)
        harness.wait_result = _WAIT_TIMEOUT
        ov_calls_before = harness.kernel32.GetOverlappedResult.call_count
        with pytest.raises(TimeoutError, match="1234 ms"):
            t.read(64, timeout_ms=1234)
        assert len(harness.cancel_calls) == 1
        assert harness.kernel32.GetOverlappedResult.call_count == ov_calls_before + 1
        assert harness.kernel32.GetOverlappedResult.call_args.args[3] == 1

        # Test błędu oczekiwania (WAIT_FAILED -> CancelIo -> GetOverlappedResult(..., 1) -> TransportError)
        harness.wait_result = 0xFFFFFFFF
        harness.last_error = 6  # ERROR_INVALID_HANDLE
        with pytest.raises(TransportError, match="oczekiwania na odczyt"):
            t.read(64, timeout_ms=500)
        assert len(harness.cancel_calls) == 2
        assert harness.kernel32.GetOverlappedResult.call_count == ov_calls_before + 2
        assert harness.kernel32.GetOverlappedResult.call_args.args[3] == 1

    # Gdy InputReportByteLength == 64, nie usuwamy pierwszego bajtu ramki (np. 0x01/0x02)
    harness_64 = _FakeWin32Harness(
        devices=[{"path": path, "vid": 0x0416, "pid": 0xB030, "in_len": 64, "out_len": 64}],
        input_report_len=64,
        output_report_len=64,
    )
    harness_64.read_queue = [fw_frame]
    t64 = WindowsHidTransport(path, api=harness_64.api)
    with t64:
        got = t64.read(65, timeout_ms=500)
        assert len(got) == 64
        assert got == fw_frame


def test_windows_error_hints_and_open_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    win_hint = no_readers_hint("win32")
    assert "Menedżer urządzeń" in win_hint
    assert "wCopy" in win_hint
    assert "udev" not in win_hint.lower()
    assert "hidraw" not in win_hint.lower()

    linux_hint = no_readers_hint("linux")
    assert "udev" in linux_hint.lower()
    assert "hidraw" in linux_hint.lower()

    path = r"\\?\hid#vid_0416&pid_b030#busy"
    harness = _FakeWin32Harness(devices=[{"path": path, "vid": 0x0416, "pid": 0xB030}])
    harness.open_error = _ERROR_ACCESS_DENIED
    t = WindowsHidTransport(path, api=harness.api)
    with pytest.raises(TransportError) as exc_info:
        t.open()
    msg = str(exc_info.value)
    assert "wCopy" in msg
    assert "Menedżer urządzeń" in msg
    assert "udev" not in msg.lower()

    monkeypatch.setattr(transport_mod.sys, "platform", "win32")
    monkeypatch.setattr(transport_mod, "enumerate_readers", lambda: [])
    with pytest.raises(TransportError) as no_dev_exc:
        open_reader()
    no_dev_msg = str(no_dev_exc.value)
    assert "Menedżer urządzeń" in no_dev_msg
    assert "udev" not in no_dev_msg.lower()


def test_app_helpers_dpi_and_monospace_font(monkeypatch: pytest.MonkeyPatch) -> None:
    # Na Linuksie wywołanie DPI jest bezpieczne (no-op)
    monkeypatch.setattr(app_mod.sys, "platform", "linux")
    app_mod._enable_windows_dpi_awareness()

    # Na Windowsie preferuje shcore.SetProcessDpiAwareness(1), a przy błędzie spada do user32.SetProcessDPIAware()
    shcore_mock = MagicMock()
    user32_mock = MagicMock()
    fake_windll = SimpleNamespace(shcore=shcore_mock, user32=user32_mock)
    monkeypatch.setattr(app_mod.sys, "platform", "win32")
    monkeypatch.setattr(app_mod.ctypes, "windll", fake_windll, raising=False)
    app_mod._enable_windows_dpi_awareness()
    shcore_mock.SetProcessDpiAwareness.assert_called_once_with(1)
    user32_mock.SetProcessDPIAware.assert_not_called()

    shcore_mock.SetProcessDpiAwareness.side_effect = OSError("unsupported")
    app_mod._enable_windows_dpi_awareness()
    user32_mock.SetProcessDPIAware.assert_called_once_with()

    # Dobór czcionki stałej szerokości dla win32 / linux / fallback
    monkeypatch.setattr(app_mod.tkfont, "families", lambda _root: ["Arial", "Consolas", "DejaVu Sans Mono"])
    assert app_mod._select_monospace_font(object(), platform="win32") == "Consolas"  # type: ignore[arg-type]
    assert app_mod._select_monospace_font(object(), platform="linux") == "DejaVu Sans Mono"  # type: ignore[arg-type]

    monkeypatch.setattr(app_mod.tkfont, "families", lambda _root: ["Arial"])
    assert app_mod._select_monospace_font(object(), platform="win32") == "TkFixedFont"  # type: ignore[arg-type]
