; Inno Setup script for RootreX.
; Build:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\rootrex.iss
; Produces installer\Output\RootreX-Setup.exe
; Prereq: run PyInstaller first so dist\RootreX\ exists.

#define MyAppName "RootreX"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "RootreX Lab"
#define MyAppExeName "RootreX.exe"

[Setup]
AppId={{8F3A1C2E-4B5D-4E6F-9A0B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=Output
OutputBaseFilename=RootreX-Setup
SetupIconFile=..\assets\rootrex.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\dist\RootreX\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Launch via "cmd start" so it detaches immediately (no installer hang) and the
; app's own admin manifest triggers one UAC prompt (avoids CreateProcess 740).
Filename: "{cmd}"; Parameters: "/C start """" ""{app}\{#MyAppExeName}"""; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent runhidden

[Code]
function NpcapInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'))
         or FileExists(ExpandConstant('{sys}\wpcap.dll'))
         or DirExists(ExpandConstant('{pf}\Npcap'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var ErrorCode: Integer;
begin
  if (CurStep = ssPostInstall) and (not NpcapInstalled()) then
  begin
    if MsgBox('RootreX needs the Npcap packet driver to capture traffic, and it was not detected.'
      + #13#10#13#10 + 'Open the Npcap download page now? (Install it with "WinPcap API-compatible mode" ticked.)',
      mbConfirmation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOW, ewNoWait, ErrorCode);
  end;
end;
