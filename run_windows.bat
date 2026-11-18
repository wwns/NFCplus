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
    echo Zainstaluj Pythona z https://www.python.org/downloads/ (zaznacz "Add Python to PATH" oraz "tcl/tk and IDLE").
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo [NFCplus] Wykryto Pythona (%PYTHON_CMD%), ale brak modulu Tkinter (tcl/tk).
    echo Uruchom instalator Pythona ponownie, wybierz "Modify" i zaznacz "tcl/tk and IDLE".
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo [NFCplus] Brak wymaganej biblioteki interfejsu "customtkinter".
    echo Instalowanie pakietu i zaleznosci ^(%PYTHON_CMD% -m pip install -e .^)...
    %PYTHON_CMD% -m pip install -e .
    if errorlevel 1 (
        echo [NFCplus] Nie udalo sie zainstalowac customtkinter.
        echo Sprobuj recznie: %PYTHON_CMD% -m pip install "customtkinter>=5.2"
        pause
        exit /b 1
    )
)

if defined PYTHONPATH (
    set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%~dp0src"
)

%PYTHON_CMD% -m nfcplus.app %*
if errorlevel 1 (
    echo.
    echo [NFCplus] Aplikacja zakonczyla dzialanie z kodem bledu %errorlevel%.
    pause
    exit /b %errorlevel%
)
