@echo off
setlocal EnableExtensions

cd /d "%~dp0"

set "PYTHON_CMD="
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py -3"
) else (
    python --version >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_CMD=python"
    )
)

if "%PYTHON_CMD%"=="" (
    echo [NFCplus] Nie znaleziono interpretera Python 3.10+ w systemie Windows.
    echo Zainstaluj Pythona z https://www.python.org/downloads/ (zaznacz "Add Python to PATH").
    pause
    exit /b 1
)

if defined PYTHONPATH (
    set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%~dp0src"
)

if not "%~1"=="" (
    %PYTHON_CMD% -m nfcplus.cli %*
    set "EXIT_CODE=%errorlevel%"
    echo.
    if not "%EXIT_CODE%"=="0" (
        echo [NFCplus] Polecenie zakonczone z kodem %EXIT_CODE%.
    ) else (
        echo [NFCplus] Polecenie zakonczone pomyslnie.
    )
    pause
    exit /b %EXIT_CODE%
)

echo ============================================================
echo   NFCplus — Diagnostyka USB HID (Windows)
echo ============================================================
echo.
echo [1/3] Wykrywanie podlaczonych czytnikow USB HID...
%PYTHON_CMD% -c "from nfcplus.transport import enumerate_readers, no_readers_hint; devs = enumerate_readers(); print('\n'.join(f'  [{i}] {d.vid_pid} backend={d.backend} product={d.product!r} serial={d.serial!r} path={d.path}' for i, d in enumerate(devs)) if devs else f'  Brak czytnikow. {no_readers_hint()}')"
echo.

echo [2/3] Test komunikacji i sygnalu dzwiekowego (info --beep)...
%PYTHON_CMD% -m nfcplus.cli info --beep
set "INFO_RC=%errorlevel%"
echo.

echo [3/3] Skanowanie wszystkich czestotliwosci (scan --all)...
%PYTHON_CMD% -m nfcplus.cli scan --all
set "SCAN_RC=%errorlevel%"
echo.

if "%INFO_RC%"=="0" (
    echo [NFCplus] Diagnostyka zakonczona. Czytnik odpowiada poprawnie ^(scan=%SCAN_RC%^).
) else (
    echo [NFCplus] Diagnostyka zakonczona z bledem komunikacji ^(info=%INFO_RC%, scan=%SCAN_RC%^).
)
pause
exit /b %INFO_RC%
