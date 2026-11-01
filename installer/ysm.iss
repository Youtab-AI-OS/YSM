; -----------------------------------------------------------------------------
; YSM — Youtab Security Message
; Inno Setup 6 script
;
; Builds a per-user installer around the electron-builder output in
; release/win-unpacked. Per-user (HKCU / %LOCALAPPDATA%) rather than machine-wide
; so installation needs no administrator rights and the encrypted vault lives in
; the user's own profile where it belongs.
;
; Security-relevant choices:
;   - No "run at startup" entry: the app has no background component and adding
;     one would be a persistence mechanism we do not need.
;   - No automatic update check.
;   - No network access during install.
;   - Uninstall optionally removes app data, and says plainly what that deletes.
; -----------------------------------------------------------------------------

#define AppName        "YSM"
#define AppFullName    "YSM — Youtab Security Message"
#define AppVersion     "1.0.0"
#define AppPublisher   "Youtab"
#define AppExeName     "YSM.exe"
#define AppId          "{{8F3C2A61-7D4E-4B95-9C3A-1E6B5D8A7F20}"

[Setup]
AppId={#AppId}
AppName={#AppFullName}
AppVersion={#AppVersion}
AppVerName={#AppFullName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppFullName} Setup

; Per-user install: no admin prompt, vault stays in the user's profile.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\YSM
DefaultGroupName={#AppName}

; Our own icon for the installer and the uninstall entry.
SetupIconFile=..\assets\ysm.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppFullName}

OutputDir=..\release\installer
OutputBaseFilename=YSM-Setup-{#AppVersion}-x64
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
DisableProgramGroupPage=yes
DisableWelcomePage=no
AllowNoIcons=yes
CloseApplications=yes
RestartApplications=no
LicenseFile=..\docs\LICENSE.txt
InfoBeforeFile=..\docs\INSTALL-NOTICE.txt
MinVersion=10.0.17763

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "dutch";   MessagesFile: "compiler:Languages\Dutch.isl"
; Farsi: Inno ships no Persian translation, so the installer UI is English/Dutch
; while the application itself is fully localised in Farsi (see docs/README).

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main application payload from electron-builder.
Source: "..\release\win-unpacked\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppFullName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppFullName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Offer to launch at the end. No silent first-run actions beyond this.
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppFullName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove application files that the installer itself created at runtime.
Type: filesandordirs; Name: "{app}\resources"
Type: dirifempty; Name: "{app}"

[Code]
// -----------------------------------------------------------------------------
// Uninstall: make the data-deletion choice explicit rather than silent.
//
// The encrypted vault lives in %APPDATA%\YSM. Deleting it destroys every message
// permanently — the app cannot recover it, by design (no server, no backup). So
// the uninstaller asks, defaults to KEEPING the data, and explains the
// consequence either way.
//
// There is deliberately no install-time data deletion: installing must never
// destroy a user's existing vault.
// -----------------------------------------------------------------------------

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{userappdata}\YSM');
    if DirExists(DataDir) then
    begin
      if MsgBox('Also delete your encrypted YSM data?' + #13#10 + #13#10 +
                'Location: ' + DataDir + #13#10 + #13#10 +
                'This permanently deletes all messages, contacts and keys. ' +
                'It cannot be undone. Choose No to keep your data for a future install.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;
  end;
end;
