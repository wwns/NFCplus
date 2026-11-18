# Specyfikacja protokołu czytnika wCopy / Xixei / NFC Pro

Dokumentacja wyodrębniona na podstawie analizy statycznej binarki `nfcPro_x64.exe` (C++/MFC x64, `hidapi`).

---

## 1. Warstwa transportowa (USB HID)

Czytnik komunikuje się jako urządzenie **USB HID** (brak osobnego protokołu szeregowego — wymiana odbywa się przez 64-bajtowe raporty HID Interrupt OUT / IN).

### Obsługiwane identyfikatory USB (`VID:PID`)

Z funkcji `FUN_14004a5d0` i `FUN_14004c060`:

| Vendor ID | Product ID | Uwagi |
|---|---|---|
| `0x0416` | `0xB030` | Winbond / Nuvoton HID NFC |
| `0x0416` | `0xB031` | Winbond / Nuvoton HID NFC |
| `0x2518` | `0x6022` | wCopy / Xixei HID NFC |
| `0x2518` | `0x6018` | wCopy / Xixei HID NFC |

### Obsługiwane warianty firmware (z `FUN_140001da0`)

- `wCopy NSR106-IC V705N1`..`V705N6`, `V801N1`
- `wCopy NSR106-IDIC V705N1`..`V705N7`, `V801N1`
- `wCopy WBW106-IDIC V705N6`, `V705N7`
- `wCopy NSR106-HIDIC V805N` (mapowane w GUI na `NFC V5.5 IC&HID`)
- `wCopy NSR122-HID V901N1` (zaobserwowane na urządzeniu `0416:b030`)

---

## 2. Format ramek (64 bajty)

### Ramka wychodząca (Host → Czytnik) — `FUN_1400453f0`

Przy zapisie przez `hid_write` wysyłane są zawsze **64 bajty** (`0x40`), gdzie bajt `0` to HID Report ID `0x00`:

| Offset | Rozmiar | Opis |
|---|---|---|
| `0` | 1 | HID Report ID = `0x00` |
| `1` | 1 | Bajt startowy = `0x01` |
| `2` | 1 | Długość ramki `L = len(payload) + 6` (maks. `len(payload) <= 48`) |
| `3..4` | 2 | Licznik sekwencji `seq` (little-endian `uint16`, inkrementowany o `+2` po każdej ramce) |
| `5..5+N-1` | `N` | Ładunek komendy (`payload`) |
| `5+N` | 1 | Suma kontrolna `csum = (~sum(packet[1 : 5+N])) & 0xFF` |
| `6+N` | 1 | Bajt końcowy = `0xFE` |
| `7+N..63` | padding | Wypełnienie zerami `0x00` do 64 bajtów |

### Ramka przychodząca (Czytnik → Host)

Odbierane jest **64 bajty** (bez prefiksu Report ID `0x00`, choć na niektórych systemach sterownik może dodać `0x00` na początku — należy to bezpiecznie obsłużyć):

| Offset | Rozmiar | Opis |
|---|---|---|
| `0` | 1 | Bajt startowy: `0x01` (odpowiedź natywna `FF 00 ...`) lub `0x02` (odpowiedź tunelu PN532; w części firmware, np. `wCopy NSR122-HID V901N1`, również odpowiedzi na komendy natywne `FF 00 ...` używają `0x02 ... 0xFD`) |
| `1` | 1 | Długość ramki `L` |
| `2..3` | 2 | Echo licznika sekwencji (w części firmware inkrementowane o `+1`, np. `seq + 1`) |
| `4..L-3` | `L-6` | Dane odpowiedzi (`payload`) |
| `L-2` | 1 | Suma kontrolna `(~sum(frame[0 : L-2])) & 0xFF` |
| `L-1` | 1 | Bajt końcowy: `0xFE` (dla startu `0x01`) lub `0xFD` (dla startu `0x02`) |

---

## 3. Komendy natywne czytnika (`FF 00 ...`)

### 3.1. Identyfikacja urządzenia (`FUN_140045750`, `FUN_140045980`, `FUN_140045a90`)

- **Pobranie wersji firmware:** `FF 00 68` → odpowiedź ASCII w payloadzie (`L - 6` bajtów, np. `wCopy NSR122-HID V901N1`).
- **Pobranie modelu czytnika:** `FF 00 69` → odpowiedź ASCII w payloadzie (np. `wCopy NSR106-HIDIC V805N` lub identyfikator/numer seryjny jak `P37354833679` w `NSR122-HID V901N1`).

### 3.2. Sygnał dźwiękowy / Buzzer (`FUN_140045ba0`)

- **Payload (9 bajtów):** `FF 00 40 50 04 <dur> 01 01 01` (odpowiedź np. `90 00` lub `90 01`)
  - `<dur>` = `max(1, (duration_ms // 10) & 0xFF)` (czas w jednostkach 10 ms).

### 3.3. Skanowanie wysokopoziomowe (`FUN_140046110`)

- **Payload (4 bajty):** `FF 00 6B 30`
- **Odpowiedź (`frame[1] == 0x19`, `payload[0] == 0x12`, końcówka `90 00`):**
  - `payload[1:3]`: `ATQA` (2 bajty)
  - `payload[3]`: `SAK` (1 bajt)
  - `payload[4]`: `uid_len` (`4`, `7` lub `10`)
  - `payload[5 : 5+uid_len]`: `UID`

---

## 4. Tunel PN532-over-HID (`FF 00 00 00 ...`)

Wszystkie operacje niskopoziomowe na kartach ISO14443A (Mifare Classic, Ultralight, NTAG) są przesyłane przez tunel PN532 zaimplementowany w `FUN_14004a6c0`:

- **Żądanie (payload w ramce `0x01`):**
  `FF 00 00 00 <len(cmd)+1> D4 <cmd...>`
- **Odpowiedź (ramka `0x02 ... FD`):**
  - `frame[4] == 0xD5`
  - `frame[5] == cmd[0] + 1`
  - `data = frame[6 : L-2]` (długość `L - 8`)

### 4.1. Inicjalizacja pola RF (`FUN_14004ae20`, `FUN_14004ab60`, `FUN_140042440`)

1. `RFConfiguration`: `32 01 00` (wyłączenie RF), pauza 10 ms
2. `RFConfiguration`: `32 01 01` (włączenie RF)
3. `RFConfiguration`: `32 05 00 01 02` (konfiguracja retry)
4. `SetParameters`: `12 10` (`fAutomaticATR_RES`)
5. `WriteRegister` (`08 <reg_hi> <reg_lo> <val>`):
   - `0x6302` (`CIU_TxMode`), maska `0x03` → `0x00` (106 kbps Tx)
   - `0x6303` (`CIU_RxMode`), maska `0x03` → `0x00` (106 kbps Rx)
   - `0x6305` (`CIU_TxAuto`), maska `0x40` → `0x40` (Force 100% ASK)
   - `0x6302` maska `0x70` → `0x00`, `0x6303` maska `0x70` → `0x00` (ISO14443A)
   - `0x6303` maska `0x08` → `0x00`, `0x6303` maska `0x04` → `0x00`
   - Włączenie sprzętowego CRC (`0x6302` i `0x6303` bit `0x80` = `1`) oraz parzystości (`0x630D` bit `0x10` = `0`).

### 4.2. Wykrycie karty ISO14443A (`FUN_14004bda0` / `FUN_140033a50`)

- **Komenda:** `4A 01 00` (`InListPassiveTarget`, MaxTg=1, BrTy=106kbps Type A)
- **Odpowiedź (`D5 4B`):**
  - Wariant bez karty na części firmware (np. `wCopy NSR122-HID V901N1`): `data = 63 00` (status `63 00` oznacza brak karty zamiast `NbTg = 0`).
  - `data[0]`: `NbTg` (`0` = brak karty, `1` = karta obecna)
  - `data[1]`: `Tg` (`0x01`)
  - `data[2:4]`: `ATQA` (SENS_RES, 2 bajty)
  - `data[4]`: `SAK` (SEL_RES, 1 bajt)
  - `data[5]`: `uid_len` (`4`, `7` lub `10`)
  - `data[6 : 6+uid_len]`: `UID`
- Po wykryciu: `4E 01 00 00` (`InPSL`).

### 4.3. Operacje Mifare Classic (`FUN_140041c30`, `FUN_1400426d0`, `FUN_140042710`, `FUN_1400427b0`)

Wszystkie komendy idą przez `InDataExchange` (`40 01 ...`):

| Operacja | Bajty komendy PN532 (`D4 ...`) | Oczekiwana odpowiedź (`D5 41 ...`) |
|---|---|---|
| **Auth Key A / B** | `40 01 <0x60\|0x61> <block> <key[6]> <uid4[4]>` | `00` (sukces; kod różny od 0 = błąd autoryzacji) |
| **Read Block** | `40 01 30 <block>` | `00 <data[16]> 90 00` (19 bajtów) |
| **Write Block** | `40 01 A0 <block> <data[16]>` | `00 90 00` (3 bajty) |

### 4.4. Operacje NTAG / Mifare Ultralight (`FUN_14004c220`, `FUN_14004c350`, `FUN_14004c7a0`)

| Operacja | Bajty komendy PN532 (`D4 ...`) | Oczekiwana odpowiedź (`D5 41 ...`) |
|---|---|---|
| **GET_VERSION** | `40 01 62` | `00 50 <version[8]> 90 00` (14 bajtów) |
| **FAST_READ** | `40 01 3A <start_page> <end_page>` | `00 <pages_data...> <crc2> 90 00` |
| **WRITE_PAGE** | `40 01 A2 <page> <data[4]>` | `00 90 00` (3 bajty) |

Wartość `version[6]` (bajt rozmiaru pamięci) identyfikuje układ (`FUN_1400563b0`):
- `0x00` / `0x0B`: Mifare Ultralight EV1 MF0UL11 (48 B user, 20 stron)
- `0x0E`: Mifare Ultralight EV1 MF0UL21 (128 B user, 41 stron)
- `0x0F`: NTAG213 (144 B user, 45 stron)
- `0x11`: NTAG215 (504 B user, 135 stron)
- `0x13`: NTAG216 (888 B user, 231 stron)

---

## 5. Karty niskiej częstotliwości: 125 kHz (EM4100 / T5577) i HID Prox

Zarówno `wCopy NSR122-HID V901N1`, jak i `NSR106-HIDIC` korzystają z tych samych komend natywnych do odczytu kart niskiej częstotliwości (brak rozgałęzienia po modelu w `nfcPro_x64.exe`). Na `NSR122-HID V901N1` ramka odpowiedzi może używać nagłówka `0x02 ... 0xFD` zamiast `0x01 ... 0xFE`.

### 5.1. Inicjalizacja przed odczytem (`FUN_140043500`)

Przed odczytem 125 kHz lub HID Prox aplikacja wykonuje pełną inicjalizację układu PN532/RF (`init_rf`: `RFConfiguration 32 01 00` → pauza 10 ms → `32 01 01` → `32 05 00 01 02` → `SetParameters 12 10` → konfiguracja rejestrów `0x6302`, `0x6303`, `0x6305`, `0x630D`).

### 5.2. Odczyt 125 kHz EM4100 / T5577 (`FUN_1400435f0` → `FUN_140046b40`)

- **Żądanie (payload 13 bajtów):**
  `FF 00 65 05 1E <freq_le32> 00 00 00 00`
  - Domyślnie `freq = 125000` (`0x0001E848`, little-endian `48 E8 01 00`):
    `FF 00 65 05 1E 48 E8 01 00 00 00 00 00`
  - *(Komendy `FF 00 66 00 1E ...` i `FF 00 66 05 1E ...` służą do operacji blokowych/zapisu/hasła T5577 i EM4305.)*
- **Odpowiedź (ramka `0x01 ... 0xFE` lub `0x02 ... 0xFD`):**
  - Sukces: `L == 0x0C` (`len(payload) == 6`) oraz `payload[0] == 0x05`; inny payload oznacza brak karty lub błąd.
  - `id5 = payload[1:6]` (5 bajtów `[b0, b1, b2, b3, b4]`).
- **Dekodowanie (`FUN_140010d0b`, `FUN_1400643e4`):**
  - **40-bit HEX:** `b0..b4` (10 znaków hex)
  - **10-cyfrowy DEC (`%10.10u`):** `int.from_bytes(id5[1:5], "big")` (`(b1 << 24) | (b2 << 16) | (b3 << 8) | b4`)
  - **Wiegand 26 (`%3.3u%5.5u`):** `FC = b2`, `CN = (b3 << 8) | b4`

### 5.3. Odczyt HID Prox 26–37 bitów (`FUN_140043620` → `FUN_140046d90`)

- **Żądanie (payload 6 bajtów):**
  `FF 00 6A 01 00 08` (parametr `0x0800` little-endian)
  - `FUN_140046d90` ponawia próbę do 5 razy (co 10 ms), aż ramka i parzystość Wiegand przejdą walidację; `FUN_140043620` wykonuje 2 kolejne odczyty i wymaga identycznej liczby bitów oraz 6 bajtów `raw6`.
- **Odpowiedź (ramka `0x01 ... 0xFE` lub `0x02 ... 0xFD`):**
  - Sukces: `L == 0x0E` (`len(payload) == 8`) oraz `payload[0] == 0x07`.
  - `extra = payload[1]`, `raw6 = payload[2:8]` (6 bajtów `[b0, b1, b2, b3, b4, b5]`).
- **Rozpoznawanie długości bitowej i weryfikacja parzystości (`FUN_140046f22`..`FUN_140047e39`):**
  Niech `w = int.from_bytes(raw6, "big")`:
  - `b0 == 0x09` i `b1 == 0x01`: wariant specjalny 16-bit, wartość `(b2 << 8) | b3`.
  - `b0 != 0x00`: surowy wynik 48-bitowy HID (6 bajtów hex, bez wyznaczonej liczby bitów).
  - `b0 == 0x00`:
    - `N ∈ 26..36`: wymagany sentinel `(w >> N) == ((1 << (37 - N)) | 1)` (bit 37 = `1`, bity `36..N+1` = `0`, bit `N` = `1`).
    - `N == 37`: wymagane `(b1 & 0xE0) == 0x00` (bity `39..37` = `0`).
    - Kontrola parzystości na dolnych `N` bitach (`bits = w & ((1 << N) - 1)`):
      - `N` parzyste (`26, 28, 30, 32, 34, 36`): górne `N/2` bitów = parzystość parzysta (`even`), dolne `N/2` bitów = nieparzysta (`odd`).
      - `N ∈ {27, 29, 31, 35, 37}`: górne `N//2` bitów (`N-1..N//2+1`) = `even`, dolne `N//2+1` bitów (`N//2..0`) = `odd`.
      - `N == 33`: górne 17 bitów (`32..16`) = `even`, dolne 17 bitów (`16..0`) = `odd` (bit `16` współdzielony).
- **Dekodowanie pól (`FUN_14006ac50`..`FUN_14006b827`):**
  - **26 bitów (H10301):** `FC = (w >> 17) & 0xFF`, `CN = (w >> 1) & 0xFFFF`
  - **27–36 bitów:** brak osobnego `FC`; `CN = (w >> 1) & ((1 << (N - 2)) - 1)`
  - **37 bitów (H10304):** `FC = (w >> 20) & 0xFFFF`, `CN = (w >> 1) & 0x7FFFF`
  - **Skrót 32-bit:** `int.from_bytes(raw6[2:6], "big")`

### 5.4. Zapis na czyste transpondery T5577 (`FF 00 66 00 1E ...`)

Zapis kart 125 kHz EM4100 oraz HID Prox na czyste układy **T5577** (odtworzone z funkcji `FUN_140010fc0`, `FUN_140046a40`, `FUN_140047e40`, `FUN_140047f70`, `FUN_1400480a0` oraz `FUN_140043710`):

1. **Reset / pauza pola LF (`FUN_140046a40`, 13 bajtów):**
   `FF 00 66 00 1E <freq_le32> 00 <delay_le16> 00 00`
   (np. `delay = 0x0014` przed zapisem lub `0x0064` po zapisie przed weryfikacją).
2. **Konfiguracja timingu T5577 (`FUN_140047e40`, 18 bajtów):**
   `FF 00 66 00 1E <freq_le32> 1F 18 01 EF 00 9B 00 86 01`
3. **Zapis bloku T5577 bez hasła (`FUN_140047f70`, 16 bajtów):**
   `FF 00 66 00 1E <freq_le32> 12 <page> <block> <data4[4]>`
   *(Wariant z 4-bajtowym hasłem `FUN_1400480a0`, 20 bajtów: zamiana `0x12` na `0x13` i dopisanie `<pwd4[4]>` na końcu.)*
4. **Odpowiedź z czytnika na komendy `FF 00 66`:**
   Ramka `0x01 ... 0xFE` (lub `0x02 ... 0xFD` na `NSR122-HID`) o długości `L == 0x0C` (`len(payload) == 6`) z `payload[0] == 0x05`.
5. **Kodowanie bloków T5577 (Page 0):**
   - **EM4100 (`FUN_140043710`):** 5-bajtowy identyfikator `id5` kodowany jest do 64-bitowej ramki EM4100 (9 bitów nagłówka `111111111`, 10 wierszy po 4 bity + bit parzystości parzystej, 4 bity parzystości kolumn + bit stopu `0`):
     - `Block 1 = em64[0:4]`, `Block 2 = em64[4:8]`
     - `Block 0 = 00 14 80 40` (RF/64, modulacja Manchester, `MaxBlk = 2`, bez hasła)
   - **HID Prox (`FUN_140010fc0`):** 6-bajtowy identyfikator `raw6` kodowany jest w kodzie Manchester (`0 -> 01`, `1 -> 10` na każdy bit, 96 bitów = 12 bajtów) z preambułą `0x1C` w najstarszych 6 bitach bajtu 0 (`out[0] = (manchester(raw6[0] >> 4) & 0x03) | 0x1C`):
     - `Block 1 = out[0:4]`, `Block 2 = out[4:8]`, `Block 3 = out[8:12]`
     - `Block 0 = 00 10 70 60` (RF/50, modulacja FSK2a, `MaxBlk = 3`)
6. **Weryfikacja:** po zapisie bloku 0 aplikacja odczekuje ok. 50–100 ms i wykonuje ponowny odczyt (`FF 00 65 05 1E ...` dla EM4100 lub `FF 00 6A 01 00 08` dla HID Prox), porównując odczytane bajty z zapisanym identyfikatorem.
