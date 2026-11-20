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
    echo [NFCplus] Nie znaleziono Pythona 3.10+. Zainstaluj Pythona z https://www.python.org/downloads/.
    pause
    exit /b 1
)

%PYTHON_CMD% -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [NFCplus] Brak pakietu PyInstaller.
    echo Zainstaluj go poleceniem:
    echo   %PYTHON_CMD% -m pip install pyinstaller
    echo lub:
    echo   %PYTHON_CMD% -m pip install -e ".[build]"
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo [NFCplus] Brak biblioteki customtkinter.
    echo Zainstaluj zaleznosci projektu poleceniem:
    echo   %PYTHON_CMD% -m pip install -e .
    pause
    exit /b 1
)

echo [NFCplus] Budowanie pliku wykonywalnego dist\NFCplus.exe ...
%PYTHON_CMD% -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --icon assets\nfcplus.ico ^
    --add-data "assets\nfcplus.ico;assets" ^
    --add-data "assets\nfcplus.png;assets" ^
    --collect-all customtkinter ^
    --name NFCplus ^
    --paths src ^
    src\nfcplus\app.py

if errorlevel 1 (
    echo [NFCplus] Budowanie nie powiodlo sie.
    pause
    exit /b %errorlevel%
)

where makensis >nul 2>&1
if not errorlevel 1 (
    echo [NFCplus] Budowanie instalatora NSIS ^(dist\NFCplus-Setup-v0.1.2.exe^)...
    makensis installer\nfcplus.nsi
    if errorlevel 1 (
        echo [NFCplus] Ostrzezenie: budowanie instalatora NSIS nie powiodlo sie.
    )
)

echo.
echo [NFCplus] Gotowe! Plik wykonywalny znajduje sie w: %~dp0dist\NFCplus.exe
pause
