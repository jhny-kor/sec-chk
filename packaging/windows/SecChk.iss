#ifndef MyAppVersion
#define MyAppVersion "0.1.0"
#endif

#define MyAppName "SecChk"
#define MyAppPublisher "jhny-kor"
#define MyAppExeName "SecChk.exe"
#define SourceDir "..\..\dist\SecChk"

[Setup]
AppId={{61C3DF7E-8694-4ED6-9AA8-2E4E8C68F92E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/jhny-kor/sec-chk
AppSupportURL=https://github.com/jhny-kor/sec-chk
AppUpdatesURL=https://github.com/jhny-kor/sec-chk
DefaultDirName={localappdata}\SecChk
DefaultGroupName=SecChk
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\..\dist\Windows
OutputBaseFilename=SecChkSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Tasks]
Name: "desktopicon"; Description: "바탕 화면에 SecChk 바로가기 만들기"; GroupDescription: "추가 바로가기:"; Flags: unchecked

[InstallDelete]
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\.venv"
Type: files; Name: "{app}\SecChk.bat"
Type: files; Name: "{app}\SecChk-CLI.bat"
Type: files; Name: "{app}\Uninstall-SecChk.ps1"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SecChk"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{userdocs}"; Comment: "SecChk local security dashboard"
Name: "{userdesktop}\SecChk"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{userdocs}"; Comment: "SecChk local security dashboard"; Tasks: desktopicon
Name: "{group}\SecChk 제거"; Filename: "{uninstallexe}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "SecChk 지금 실행"; Flags: nowait postinstall skipifsilent
