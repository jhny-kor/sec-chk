#ifndef MyAppVersion
#define MyAppVersion "0.1.0"
#endif

#define MyAppName "KODA"
#define MyAppPublisher "jhny-kor"
#define MyAppExeName "KODA.exe"
#define SourceDir "..\..\dist\KODA"
#define MyAppIcon "assets\KODA.ico"

[Setup]
AppId={{2A235674-97E5-4B71-A57C-32BE33DC960C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/jhny-kor/sec-chk
AppSupportURL=https://github.com/jhny-kor/sec-chk
AppUpdatesURL=https://github.com/jhny-kor/sec-chk
DefaultDirName={localappdata}\KODA
DefaultGroupName=KODA
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\..\dist\Windows
OutputBaseFilename=KODASetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppExeName}

[Tasks]
Name: "desktopicon"; Description: "바탕 화면에 KODA 바로가기 만들기"; GroupDescription: "추가 바로가기:"; Flags: unchecked

[InstallDelete]
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\.venv"
Type: files; Name: "{app}\SecChk.bat"
Type: files; Name: "{app}\SecChk-CLI.bat"
Type: files; Name: "{app}\Uninstall-SecChk.ps1"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\KODA"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{userdocs}"; Comment: "KODA local security dashboard"
Name: "{userdesktop}\KODA"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{userdocs}"; Comment: "KODA local security dashboard"; Tasks: desktopicon
Name: "{group}\KODA 제거"; Filename: "{uninstallexe}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "KODA 지금 실행"; Flags: nowait postinstall skipifsilent
