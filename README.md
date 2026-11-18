# NFCplus

Czytelny, działający w pełni lokalnie (offline) sterownik oraz klient GUI + CLI dla czytników USB HID z rodziny **wCopy / Xixei / NFC Pro** (obsługiwane VID:PID: `0416:b030`, `0416:b031`, `2518:6022`, `2518:6018`).

Protokół został wyodrębniony z oryginalnej binarki [nfcPro_x64.exe](nfcPro_x64.exe) i opisany w [docs/protocol.md](docs/protocol.md). Program obsługuje wyłącznie standardową komunikację z czytnikiem (bez funkcji sieciowych i bez modułów ataków kryptograficznych).

## Uruchomienie na Linuksie

Na Linuksie aplikacja korzysta z wbudowanego backendu `/dev/hidraw*` (nie wymaga zewnętrznych bibliotek do komunikacji z czytnikiem).

1. (Jednorazowo) nadaj bezpieczne uprawnienia dla zalogowanego użytkownika lokalnego (`MODE="0660", GROUP="plugdev", TAG+="uaccess"`) przez `udev`:
   ```bash
   sudo cp udev/99-nfcplus.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules && sudo udevadm trigger
   ```
   Po skopiowaniu reguł odepnij i podepnij czytnik ponownie.

2. Uruchom środowisko wirtualne i zainstaluj pakiet:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -e .
   ```

3. Uruchom aplikację okienkową (GUI, opartą o `customtkinter`) lub konsolową (CLI):
   ```bash
   .venv/bin/nfcplus-gui
   # lub CLI:
   .venv/bin/nfcplus info --beep
   .venv/bin/nfcplus scan --all
   .venv/bin/nfcplus read-mifare -o karta.dump
   .venv/bin/nfcplus write-mifare karta.dump
   .venv/bin/nfcplus format-mifare --sectors 16
   .venv/bin/nfcplus dump-json karta.dump -o karta.json
   .venv/bin/nfcplus read-ntag -o tag.dump
   .venv/bin/nfcplus read-ndef
   .venv/bin/nfcplus write-ndef --uri "https://example.com"
   .venv/bin/nfcplus apdu "00 A4 00 00 02 3F 00" --init-rf
   .venv/bin/nfcplus lf-convert 4D0088BC89
   .venv/bin/nfcplus write-t5577 --em4100 4D0088BC89
   .venv/bin/nfcplus audit -o raport.html
   .venv/bin/nfcplus audit --dump karta.dump -o raport.md
   ```

## Funkcje aplikacji GUI (`nfcplus-gui`)

- **Nowoczesny interfejs `customtkinter` z dwiema skórkami (`Ciemna` / `Jasna`):** przełącznik motywu na żywo w górnym pasku połączenia (wybór zapisywany lokalnie w `config.json`), obsługa HiDPI na Windowsie oraz opcjonalne **auto-łączenie przy starcie**.
- **Zakładka `1. Skanuj kartę`:** skanowanie ISO 14443-A oraz przycisk **„Skanuj wszystko (13.56 MHz + 125 kHz / HID)”** łączący odczyt 13.56 MHz, EM4100 i HID Prox.
- **Zakładka `2. Mifare Classic`:**
  - import własnych list kluczy **`.txt` / `.dic`** (`parse_key_file`) ze scalaniem bez duplikatów,
  - wizualna **siatka statusu kluczy A / B per sektor** (dopasowana do trybu ciemnego i jasnego: zielony = OK, czerwony = błąd / brak klucza, szary = niesprawdzono),
  - wczytywanie `.dump` / `.bin` do bufora, eksport do **JSON** (`save_json`), **analizator uprawnień (`Access Bits`) i bloków `Value Block`**, **edycja bloków w buforze** z walidacją `C1/C2/C3`,
  - **zapis całego zrzutu na kartę** (domyślnie bez Bloku 0; zapis Bloku 0 wymaga potwierdzenia dla kart CUID/Gen2) oraz **bezpieczne formatowanie karty** (zerowanie danych bez Bloku 0 i przywrócenie `FFFFFFFFFFFF / FF078069 / FFFFFFFFFFFF`).
- **Zakładka `3. NTAG / Ultralight`:** `Info o tagu (Get Version)`, opcjonalna autoryzacja hasłem **`PWD_AUTH`** (`4 B` hex), odczyt i zapis stron/zrzutów, automatyczne dekodowanie **NDEF** (`URI` / `Text`) oraz formularz zapisu rekordów **NDEF** od strony 4.
- **Zakładka `4. Zrzuty (.dump)`:** podgląd plików `.dump` / `.bin` oraz **porównywarka dwóch zrzutów obok siebie** (lewy + prawy panel i lista różnic `compare_buffers`).
- **Zakładka `5. 125 kHz / HID Prox`:** odczyt EM4100 i HID Prox, **zapis na czysty transponder T5577** (EM4100 lub HID Prox z weryfikacją odczytem) oraz **dwukierunkowy konwerter formatów 125 kHz** (`40-bit HEX` ↔ `DEC 10-cyfr.` ↔ `DEC 8-cyfr. / WG26` ↔ `FC + CN`).
- **Zakładka `6. CPU / APDU`:** wykrywanie kart ISO 14443-4, szablony APDU (`SELECT MF`, `GET CHALLENGE`, `SELECT NDEF AID`) i ręczna wymiana ramek APDU z podglądem `HEX | ASCII` oraz `SW1 SW2`.
- **Zakładka `7. Audyt Bezpieczeństwa`:** w 100% nieinwazyjny (**Read-Only**) audyt bezpieczeństwa karty na czytniku, pliku `.dump` z dysku lub obecnego bufora (ocena 125 kHz EM4100/HID, Crypto1, kluczy domyślnych, `Key A == Key B`, `Access Bits`, anomalii `BCC`/`SAK`/`ATQA` w Bloku 0, `Static Lock` i `AUTH0` w NTAG21x), przełącznik maskowania kluczy (`A0A1****A4A5`) oraz eksport raportu do **HTML (do druku / PDF)**, **Markdown (`.md`)** i **JSON**.

## Uruchomienie na Windowsie

Na Windowsie komunikacja z czytnikiem działa **bez dodatkowych sterowników USB** (wbudowany `WindowsHidTransport` korzysta bezpośrednio z Win32 API `setupapi.dll`, `hid.dll`, `kernel32.dll` przez `ctypes`). Jedyną wymaganą zależnością interfejsu graficznego jest `customtkinter>=5.2` (instalowana automatycznie przez `pip install -e .` lub skrypt `run_windows.bat`).

### Szybkie uruchomienie i diagnostyka

1. Zainstaluj Python 3.10+ ze strony [python.org](https://www.python.org/downloads/) (zaznacz **Add Python to PATH** oraz **tcl/tk and IDLE**).
2. Kliknij dwukrotnie **`run_windows.bat`** (sprawdza/instaluje `customtkinter` i uruchamia GUI) lub **`diag_windows.bat`** (wykrywa czytnik HID, uruchamia `info --beep` i `scan --all`):
   ```bat
   run_windows.bat
   diag_windows.bat
   diag_windows.bat read-mifare -o karta.dump
   ```

### Instalacja w środowisku wirtualnym (GUI + CLI)

```powershell
python -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\nfcplus-gui
```

Dostępne są także polecenia CLI:
```powershell
.venv\Scripts\nfcplus info --beep
.venv\Scripts\nfcplus scan --all
.venv\Scripts\nfcplus read-mifare -o karta.dump
.venv\Scripts\nfcplus write-mifare karta.dump
.venv\Scripts\nfcplus format-mifare --sectors 16
.venv\Scripts\nfcplus dump-json karta.dump -o karta.json
.venv\Scripts\nfcplus read-ntag -o tag.dump --password FFFFFFFF
.venv\Scripts\nfcplus read-ndef
.venv\Scripts\nfcplus write-ndef --uri "https://example.com"
.venv\Scripts\nfcplus apdu "00 A4 00 00 02 3F 00" --init-rf
.venv\Scripts\nfcplus lf-convert 4D0088BC89
.venv\Scripts\nfcplus write-t5577 --em4100 4D0088BC89
.venv\Scripts\nfcplus audit -o raport.html
```

*(Opcjonalnie)* Jeśli chcesz używać biblioteki `hidapi` zamiast wbudowanego backendu Win32:
```powershell
.venv\Scripts\pip install -e ".[hid]"
```

### Budowanie samodzielnego pliku `NFCplus.exe` (lokalnie lub przez GitHub Actions)

Lokalnie na Windowsie:
```bat
py -3 -m pip install -e ".[build]"
build_windows.bat
```
Gotowy plik powstanie w `dist\NFCplus.exe`.

Automatycznie w chmurze (**GitHub Actions**):
- Workflow [`.github/workflows/build-windows.yml`](.github/workflows/build-windows.yml) na maszynie `windows-latest` uruchamia zestaw testów `pytest -v`, buduje jednoplikowy `dist\NFCplus.exe` przez PyInstaller (`--onefile --windowed --collect-all customtkinter`) i publikuje go jako artefakt **`NFCplus-Windows-x64`** przy każdym `push`, `pull_request` lub ręcznym uruchomieniu (`workflow_dispatch`).

> **Wskazówka (Windows):** Jeśli program zgłasza błąd otwarcia czytnika (`odmowa dostępu` / `zajęty`), zamknij inne otwarte narzędzia korzystające z czytnika (np. `wCopy` lub `nfcPro_x64.exe`) i sprawdź obecność urządzenia w **Menedżerze urządzeń → Urządzenia interfejsu HID**.

## Testy

```bash
.venv/bin/pytest
```
