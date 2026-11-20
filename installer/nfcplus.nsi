; NFCplus Windows Installer (NSIS MUI2)
Unicode True

!ifndef VERSION
  !define VERSION "0.1.1"
!endif

!define APP_NAME "NFCplus"
!define APP_PUBLISHER "NFCplus"
!define APP_URL "https://github.com/wwns/NFCplus"
!define APP_EXE "NFCplus.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

!include "MUI2.nsh"
!include "x64.nsh"

Name "${APP_NAME} ${VERSION}"
OutFile "..\dist\NFCplus-Setup-v${VERSION}.exe"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "Software\${APP_NAME}" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; Ikony instalatora i deinstalatora
!define MUI_ICON "..\assets\nfcplus.ico"
!define MUI_UNICON "..\assets\nfcplus.ico"
!define MUI_ABORTWARNING

; Strony instalatora
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!insertmacro MUI_PAGE_FINISH

; Strony deinstalatora
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Języki (Polski domyślny + Angielski)
!insertmacro MUI_LANGUAGE "Polish"
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Section "NFCplus (wymagane)" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"

  File "..\dist\${APP_EXE}"
  File "..\README.md"
  File "..\run_windows.bat"
  File "..\diag_windows.bat"

  SetOutPath "$INSTDIR\assets"
  File "..\assets\nfcplus.ico"

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Wpis w rejestrze (64-bit) i "Dodaj lub usuń programy"
  SetRegView 64
  WriteRegStr HKLM "Software\${APP_NAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME} ${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "${APP_URL}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\assets\nfcplus.ico"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1

  ; Skróty w Menu Start
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\assets\nfcplus.ico" 0
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Diagnostyka HID.lnk" "$INSTDIR\diag_windows.bat" "" "$INSTDIR\assets\nfcplus.ico" 0
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Odinstaluj ${APP_NAME}.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\assets\nfcplus.ico" 0
SectionEnd

Section "Skrót na Pulpicie" SecDesktop
  CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\assets\nfcplus.ico" 0
SectionEnd

LangString DESC_SecMain ${LANG_POLISH} "Główne pliki programu NFCplus, dokumentacja oraz skrypty diagnostyczne."
LangString DESC_SecMain ${LANG_ENGLISH} "Core NFCplus application, documentation, and diagnostic scripts."
LangString DESC_SecDesktop ${LANG_POLISH} "Tworzy skrót NFCplus na Pulpicie."
LangString DESC_SecDesktop ${LANG_ENGLISH} "Creates an NFCplus shortcut on the Desktop."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} $(DESC_SecDesktop)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  SetRegView 64
  Delete "$DESKTOP\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Diagnostyka HID.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Odinstaluj ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"

  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\run_windows.bat"
  Delete "$INSTDIR\diag_windows.bat"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$INSTDIR\assets\nfcplus.ico"
  RMDir "$INSTDIR\assets"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\${APP_NAME}"
SectionEnd
