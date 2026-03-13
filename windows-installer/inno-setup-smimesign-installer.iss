#define MyAppName "smimesign"

#define MyGitVersion GetEnv("GIT_VERSION")
#define MyBareGitVersion GetEnv("BARE_GIT_VERSION")

#define PathToX64Binary "../build/amd64/smimesign.exe"
#ifnexist PathToX64Binary
  #pragma error PathToX64Binary + " does not exist, please build it first."
#endif

#define PathToX64Helper "../build/amd64/git-x509-cert.exe"
#ifnexist PathToX64Helper
  #pragma error PathToX64Helper + " does not exist, please build it first."
#endif

#define PathToReadme "../README.md"
#ifnexist PathToReadme
  #pragma error PathToReadme + " does not exist."
#endif

#define PathToLicense "../LICENSE.md"
#ifnexist PathToLicense
  #pragma error PathToLicense + " does not exist."
#endif

#define PathToSmimesignHelp "../build/amd64/docs/smimesign-help.txt"
#ifnexist PathToSmimesignHelp
  #pragma error PathToSmimesignHelp + " does not exist, please build docs first."
#endif

#define PathToGitX509CertHelp "../build/amd64/docs/git-x509-cert-help.txt"
#ifnexist PathToGitX509CertHelp
  #pragma error PathToGitX509CertHelp + " does not exist, please build docs first."
#endif

#define MyAppPublisher "GitHub, Inc."
#define MyAppURL "https://github.com/droren/smimesign"
#define MyAppFilePrefix "smimesign-windows"

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppCopyright=GitHub, Inc.
AppId={{4F942266-232E-4F47-8D44-A6BEE366A2A0}
AppName={#MyAppName}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppVerName={#MyBareGitVersion}
ArchitecturesInstallIn64BitMode=x64
ChangesEnvironment=yes
Compression=lzma
DefaultDirName={code:GetDefaultDirName}
DirExistsWarning=no
DisableReadyPage=True
LicenseFile=..\LICENSE.md
OutputBaseFilename={#MyAppFilePrefix}-{#MyGitVersion}
OutputDir=..\build\installer\
PrivilegesRequired=none
SolidCompression=yes
UsePreviousAppDir=no
VersionInfoVersion={#MyBareGitVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: {#PathToX64Binary}; DestDir: "{app}"; Flags: ignoreversion; DestName: "smimesign.exe"
Source: {#PathToX64Helper}; DestDir: "{app}"; Flags: ignoreversion; DestName: "git-x509-cert.exe"
Source: {#PathToReadme}; DestDir: "{app}\docs"; Flags: ignoreversion; DestName: "README.md"
Source: {#PathToLicense}; DestDir: "{app}\docs"; Flags: ignoreversion; DestName: "LICENSE.md"
Source: {#PathToSmimesignHelp}; DestDir: "{app}\docs"; Flags: ignoreversion; DestName: "smimesign-help.txt"
Source: {#PathToGitX509CertHelp}; DestDir: "{app}\docs"; Flags: ignoreversion; DestName: "git-x509-cert-help.txt"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: IsAdminLoggedOn and NeedsAddPath('{app}')
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: (not IsAdminLoggedOn) and NeedsAddPath('{app}')

[Code]
function GetDefaultDirName(Dummy: string): string;
begin
  if IsAdminInstallMode then begin
    Result:=ExpandConstant('{pf}\{#MyAppName}');
  end else begin
    Result:=ExpandConstant('{userpf}\{#MyAppName}');
  end;
end;

// Checks to see if we need to add the dir to the env PATH variable.
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
  ParamExpanded: string;
begin
  //expand the setup constants like {app} from Param
  ParamExpanded := ExpandConstant(Param);
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  // look for the path with leading and trailing semicolon and with or without \ ending
  // Pos() returns 0 if not found
  Result := Pos(';' + UpperCase(ParamExpanded) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
  if Result = True then
    Result := Pos(';' + UpperCase(ParamExpanded) + '\;', ';' + UpperCase(OrigPath) + ';') = 0;
end;
