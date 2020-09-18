@ECHO OFF &SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
title Felipe.#8581 ~ Donate: bit.ly/3goAOyc 
cd /D "%~dp0"

ECHO.
ECHO  Tweaking improves latency, input lag, system responsiveness, not FPS
ECHO  Do not expect your computer to hit higher fps unless you did shit before 
ECHO  This is not realistic and that's why it's called optimization, not a miracle
ECHO.
ECHO.
ECHO  Automatization is never the best way to do things, please learn tweaking
ECHO  You can start reading all guides on Revision discord (revi.cc)
ECHO.

:: Resync time based on your timezone
w32tm /config /manualpeerlist:time.windows.com >NUL 2>&1
w32tm /resync /rediscover >NUL 2>&1

:: Automatically set static ip while Dhcp is enabled, thanks to Phlegm
if "%INTERFACE%"=="" for /f "tokens=3,*" %%i in ('netsh int show interface^|find "Connected"') do set INTERFACE=%%j
if "%IP%"=="" for /f "tokens=3 delims=: " %%i in ('netsh int ip show config name^="%INTERFACE%" ^| findstr "IP Address" ^| findstr [0-9]') do set IP=%%i
if "%MASK%"=="" for /f "tokens=2 delims=()" %%i in ('netsh int ip show config name^="%INTERFACE%" ^| findstr /r "(.*)"') do for %%j in (%%i) do set MASK=%%j
if "%GATEWAY%"=="" for /f "tokens=3 delims=: " %%i in ('netsh int ip show config name^="%INTERFACE%" ^| findstr "Default" ^| findstr [0-9]') do set GATEWAY=%%i
set DNS1=156.154.70.22
set DNS2=8.8.4.4
netsh int ipv4 set address name="%INTERFACE%" static %IP% %MASK% %GATEWAY% >NUL 2>&1
netsh int ipv4 set dns name="%INTERFACE%" static %DNS1% primary >NUL 2>&1
netsh int ipv4 add dns name="%INTERFACE%" %DNS2% index=2 >NUL 2>&1
netsh int set interface name="%INTERFACE%" admin="disabled" && netsh int set interface name="%INTERFACE%" admin="enabled" >NUL 2>&1

:: Removing Image File Execution Options...
POWERSHELL "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" >NUL 2>&1

:: Removing ThreadPrioritys...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "ThreadPriority"^| FINDSTR /V "ThreadPriority"') DO (
REG DELETE "%%a" /F /V "ThreadPriority" >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\=!
SET STR=!STR:\Parameters=!
)
)

ECHO  Execution Policy to Unrestricted...
POWERSHELL "Set-ExecutionPolicy -ExecutionPolicy Unrestricted" >NUL 2>&1

ECHO  Enabling Windows Components...
dism /online /enable-feature /featurename:DesktopExperience /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:LegacyComponents /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:DirectPlay /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:NetFx4-AdvSrvs /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:NetFx3 /all /norestart >NUL 2>&1

ECHO  Enabling MSI for GPU...
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >NUL 2>&1
)

ECHO  Disabling Mitigations...
POWERSHELL "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"  >NUL 2>&1

ECHO  Disabling RAM compression...
POWERSHELL Disable-MMAgent -MemoryCompression -ApplicationPreLaunch -ErrorAction SilentlyContinue >NUL 2>&1

ECHO  Disabling Hibernation...
powercfg -h OFF >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

ECHO  Disabling User Account Control...
REG ADD "HKLM\System\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >NUL 2>&1

ECHO  Disabling Windows Defender...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >NUL 2>&1
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /f >NUL 2>&1

ECHO  Disabling Windows Update...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "BranchReadinessLevel" /t REG_SZ /d "CB" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "DeferQualityUpdates" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "ExcludeWUDrivers" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "FeatureUpdatesDeferralInDays" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsDeferralIsActive" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsWUfBConfigured" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsWUfBDualScanActive" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "PolicySources" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "BranchReadinessLevel" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "PauseFeatureUpdatesStartTime" /t REG_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequency" /t REG_DWORD /d "20" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequencyEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "EnableFeaturedSoftware" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >NUL 2>&1

ECHO  Disabling OneDrive...
taskkill /f /im OneDrive.exe >NUL 2>&1
if exist %SystemRoot%\System32\OneDriveSetup.exe start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall >NUL 2>&1
rd "%UserProfile%\OneDrive" /q /s >NUL 2>&1
rd "%SystemDrive%\OneDriveTemp" /q /s >NUL 2>&1
rd "%LocalAppData%\Microsoft\OneDrive" /q /s >NUL 2>&1
rd "%ProgramData%\Microsoft OneDrive" /q /s >NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d "1" /f >NUL 2>&1

ECHO  Disabling IoLatencyCap...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
REG ADD "%%a" /v "IoLatencyCap" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\services\=!
SET STR=!STR:\Parameters=!
)
)
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\DriverDatabase\DriverPackages" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
REG ADD "%%a" /v "IoLatencyCap" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\SYSTEM\DriverDatabase\DriverPackages\=!
SET STR=!STR:\Configurations\msahci_Inst\Services\storahci\Parameters=!
)
)

ECHO  Disabling HIPM and DIPM...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
REG ADD "%%a" /v "EnableHIPM" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "%%a" /v "EnableDIPM" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Services\=!
)
)

ECHO  Disabling CdpUserSvcs...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /F "cdpusersvc"') DO (
REG ADD "%%a" /F /V "Start" /T REG_DWORD /d 4 >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\services\=!
)
)

ECHO  Disabling QoS and NdisCap...
FOR /F %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services\Psched\Parameters\Adapters"') DO ( 
REG DELETE %%a /F >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Services\Psched\Parameters\Adapters\=!
)
)
FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^| FINDSTR /I /L "ServiceName"') DO (
FOR /F %%a IN ('REG QUERY "HKLM\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /F "%%I" /D /E /S^| FINDSTR /I /L "\\Class\\"') DO SET "REGPATH=%%a"
FOR /F "tokens=3*" %%n in ('REG QUERY "!REGPATH!" /V "FilterList"') DO SET newFilterList=%%n
SET newFilterList=!newFilterList:-{B5F4D659-7DAA-4565-8E41-BE220ED60542}=!
SET newFilterList=!newFilterList:-{430BDADD-BAB0-41AB-A369-94B67FA5BE0A}=!
REG QUERY !REGPATH! /V "FilterList" | FINDSTR /I "{B5F4D659-7DAA-4565-8E41-BE220ED60542} {430BDADD-BAB0-41AB-A369-94B67FA5BE0A}" >NUL 2>&1
IF NOT ERRORLEVEL 1 (
REG ADD !REGPATH! /F /V "FilterList" /T REG_MULTI_SZ /d "!newFilterList!" >NUL 2>&1
)
)

ECHO  Disabling USB Hub and StorPort idle...
FOR /F %%a in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') DO (
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >NUL 2>&1	
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1	
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >NUL 2>&1	
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\usbflags" /v "fid_D1Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\usbflags" /v "fid_D2Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\usbflags" /v "fid_D3Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
)
FOR /F "tokens=*" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort"^| FINDSTR /E "StorPort"') DO (
REG ADD "%%a" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Enum\=!
SET STR=!STR:\Device Parameters\StorPort=!
)
)

IF EXIST "%WinDir%\Resources\Themes\aero\aerolite.msstyles" (
powershell "$content = [System.IO.File]::ReadAllText('%WinDir%\Resources\Themes\aero.theme').Replace('%ResourceDir%\Themes\Aero\Aero.msstyles','%ResourceDir%\Themes\Aero\Aerolite.msstyles'); [System.IO.File]::WriteAllText('%WinDir%\Resources\Themes\aerolite.theme', $content)" >NUL 2>&1
ECHO  Installing Aero Lite Theme
IF EXIST "%WinDir%\Resources\Themes\light.theme" (
powershell "$content = [System.IO.File]::ReadAllText('%WinDir%\Resources\Themes\light.theme').Replace('%ResourceDir%\Themes\Aero\Aero.msstyles','%ResourceDir%\Themes\Aero\Aerolite.msstyles'); [System.IO.File]::WriteAllText('%WinDir%\Resources\Themes\lightlite.theme', $content)" >NUL 2>&1 
ECHO  Installing Light Lite Theme
)
)

ECHO  Installing Process Explorer...
IF EXIST "%WINDIR%\procexp64.exe" REG ADD "HKLM\System\CurrentControlSet\Services\PCW" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
IF EXIST "%WINDIR%\procexp64.exe" REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\procexp64.exe" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "EulaAccepted" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "Windowplacement" /t REG_BINARY /d "2c0000000200000003000000ffffffffffffffffffffffffffffffff75030000110000009506000069020000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "FindWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000096000000960000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SysinfoWindowplacement" /t REG_BINARY /d "2c00000000000000010000000000000000000000ffffffffffffffff28000000280000002b0300002b020000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "PropWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000028000000280000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllPropWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000028000000280000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "UnicodeFont" /t REG_BINARY /d "080000000000000000000000000000009001000000000000000000004d00530020005300680065006c006c00200044006c00670000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "Divider" /t REG_BINARY /d "531f0e151662ea3f" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SavedDivider" /t REG_BINARY /d "531f0e151662ea3f" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ProcessImageColumnWidth" /t REG_DWORD /d "261" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowUnnamedHandles" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowDllView" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HandleSortColumn" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HandleSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllSortColumn" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ProcessSortColumn" /t REG_DWORD /d "4294967295" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ProcessSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightServices" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightOwnProcesses" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightRelocatedDlls" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightJobs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightNewProc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightDelProc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightImmersive" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightProtected" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightPacked" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightNetProcess" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightSuspend" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightDuration" /t REG_DWORD /d "1000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowCpuFractions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowLowerpane" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowAllUsers" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowProcessTree" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SymbolWarningShown" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HideWhenMinimized" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "AlwaysOntop" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "OneInstance" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "NumColumnSets" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ConfirmKill" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "RefreshRate" /t REG_DWORD /d "1000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "PrcessColumnCount" /t REG_DWORD /d "17" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllColumnCount" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HandleColumnCount" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DefaultProcPropPage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DefaultSysInfoPage" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DefaultDllPropPage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DbgHelpPath" /t REG_SZ /d "C:\Windows\SYSTEM32\dbghelp.dll" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SymbolPath" /t REG_SZ /d "" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorPacked" /t REG_DWORD /d "16711808" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorImmersive" /t REG_DWORD /d "15395328" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorOwn" /t REG_DWORD /d "16765136" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorServices" /t REG_DWORD /d "13684991" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorRelocatedDlls" /t REG_DWORD /d "10551295" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorGraphBk" /t REG_DWORD /d "15790320" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorJobs" /t REG_DWORD /d "27856" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorDelProc" /t REG_DWORD /d "4605695" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorNewProc" /t REG_DWORD /d "4652870" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorNet" /t REG_DWORD /d "10551295" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorProtected" /t REG_DWORD /d "8388863" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowHeatmaps" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorSuspend" /t REG_DWORD /d "8421504" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "StatusBarColumns" /t REG_DWORD /d "13589" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowAllCpus" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowAllGpus" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "Opacity" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "GpuNodeUsageMask" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "GpuNodeUsageMask1" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "VerifySignatures" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "VirusTotalCheck" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "VirusTotalSubmitUnknown" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ToolbarBands" /t REG_BINARY /d "0601000000000000000000004b00000001000000000000004b00000002000000000000004b00000003000000000000004b0000000400000000000000400000000500000000000000500000000600000000000000930400000700000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "UseGoogle" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowNewProcesses" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "TrayCPUHistory" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowIoTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowNetTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowDiskTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowPhysTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowCommitTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowGpuTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "FormatIoBytes" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "StackWindowPlacement" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ETWstandardUserWarning" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "0" /t REG_DWORD /d "26" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "1" /t REG_DWORD /d "42" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "2" /t REG_DWORD /d "1033" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "3" /t REG_DWORD /d "1111" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "4" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "0" /t REG_DWORD /d "110" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "1" /t REG_DWORD /d "180" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "2" /t REG_DWORD /d "140" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "3" /t REG_DWORD /d "300" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "4" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumnMap" /v "0" /t REG_DWORD /d "21" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumnMap" /v "1" /t REG_DWORD /d "22" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumns" /v "0" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumns" /v "1" /t REG_DWORD /d "450" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "0" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "1" /t REG_DWORD /d "1055" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "2" /t REG_DWORD /d "1650" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "3" /t REG_DWORD /d "1065" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "4" /t REG_DWORD /d "1200" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "5" /t REG_DWORD /d "1092" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "6" /t REG_DWORD /d "1340" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "7" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "8" /t REG_DWORD /d "1339" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "9" /t REG_DWORD /d "1333" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "10" /t REG_DWORD /d "1622" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "11" /t REG_DWORD /d "1636" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "12" /t REG_DWORD /d "1179" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "13" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "14" /t REG_DWORD /d "1060" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "15" /t REG_DWORD /d "1063" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "16" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "17" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "18" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "19" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "0" /t REG_DWORD /d "261" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "1" /t REG_DWORD /d "35" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "2" /t REG_DWORD /d "37" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "3" /t REG_DWORD /d "52" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "4" /t REG_DWORD /d "85" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "5" /t REG_DWORD /d "80" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "6" /t REG_DWORD /d "60" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "7" /t REG_DWORD /d "39" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "8" /t REG_DWORD /d "79" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "9" /t REG_DWORD /d "65" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "10" /t REG_DWORD /d "93" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "11" /t REG_DWORD /d "76" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "12" /t REG_DWORD /d "55" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "13" /t REG_DWORD /d "31" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "14" /t REG_DWORD /d "70" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "15" /t REG_DWORD /d "70" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "16" /t REG_DWORD /d "44" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\VirusTotal" /v "VirusTotalTermsAccepted" /t REG_DWORD /d "1" /f >NUL 2>&1

ECHO  Network tweaks, takes time...
NETSH winsock reset >NUL 2>&1
NETSH interface teredo set state disabled >NUL 2>&1
NETSH interface 6to4 set state disabled >NUL 2>&1
NETSH int isatap set state disable >NUL 2>&1
NETSH int ip set global neighborcachelimit=4096 >NUL 2>&1
NETSH int ip set global taskoffload=disabled >NUL 2>&1
NETSH int ip set global loopbackworkercount = %NUMBER_OF_PROCESSORS% >NUL 2>&1
NETSH int tcp set global autotuninglevel=disable >NUL 2>&1
NETSH int tcp set global chimney=disabled >NUL 2>&1
NETSH int tcp set global dca=enabled >NUL 2>&1
NETSH int tcp set global ecncapability=disabled >NUL 2>&1
NETSH int tcp set global netdma=enabled >NUL 2>&1
NETSH int tcp set global nonsackrttresiliency=disabled >NUL 2>&1
NETSH int tcp set global rsc=disabled >NUL 2>&1
NETSH int tcp set global rss=enabled >NUL 2>&1
NETSH int tcp set global timestamps=disabled >NUL 2>&1
NETSH int tcp set heuristics disabled >NUL 2>&1
NETSH int tcp set security mpp=disabled >NUL 2>&1
NETSH int tcp set security profiles=disabled >NUL 2>&1
NETSH int tcp set global initialRto=3000 >NUL 2>&1
NETSH int tcp set global maxsynretransmissions=2 >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "5840" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "5840" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f >NUL 2>&1
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >NUL 2>&1
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >NUL 2>&1
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Adapter
for /f %%r in ('reg query "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /f "PCI\VEN" /d /s^|Findstr HKEY') do (
REG ADD "%%r" /v "*EEE" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*FlowControl" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*InterruptModeration" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*JumboPacket" /t REG_SZ /d "1415" /f >NUL 2>&1
REG ADD "%%r" /v "*LsoV1IPv4" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*LsoV2IPv4" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*LsoV2IPv6" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*NumRssQueues" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*PMARPOffload" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*PMNSOffload" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*PriorityVLANTag" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*ReceiveBuffers" /t REG_SZ /d "80" /f >NUL 2>&1
REG ADD "%%r" /v "*RSS" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*RssBaseProcNumber" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*RssMaxProcNumber" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*SpeedDuplex" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TransmitBuffers" /t REG_SZ /d "80" /f >NUL 2>&1
REG ADD "%%r" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "AdvancedEEE" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EnablePME" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EnableTss" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "GigaLite" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "ITR" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "LogLinkStateEvent" /t REG_SZ /d "51" /f >NUL 2>&1
REG ADD "%%r" /v "MasterSlave" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "PowerSavingMode" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "TxIntDelay" /t REG_SZ /d "5" /f >NUL 2>&1
REG ADD "%%r" /v "ULPMode" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WaitAutoNegComplete" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WakeOnLink" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WakeOnSlot" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >NUL 2>&1
)

:: Core 2 Affinity
for /f %%n in ('wmic path win32_networkadapter get PNPDeviceID ^| findstr /L "VEN_"') do (
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MessageNumberLimit" /t REG_DWORD /d "256" /f >NUL 2>&1
)

POWERSHELL Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled -ErrorAction SilentlyContinue
POWERSHELL Set-NetTCPSetting -SettingName internet -MinRto 300 -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterEncapsulatedPacketTaskOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterIPsecOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterChecksumOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterLso -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterRsc -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterIPsecOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterPowerManagement -Name "*" -ErrorAction SilentlyContinue

:: Adapter bindings
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp -ErrorAction SilentlyContinue
:: Link-Layer Topology Discovery Mapper I/O Driver
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio -ErrorAction SilentlyContinue
:: Client for Microsoft Networks
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient -ErrorAction SilentlyContinue
:: Microsoft LLDP Protocol Driver
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr -ErrorAction SilentlyContinue
:: File and Printer Sharing for Microsoft Networks
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_server -ErrorAction SilentlyContinue
:: Microsoft Network Adapter Multiplexor Protocol
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat -ErrorAction SilentlyContinue

:: QoS Packet Scheduler
POWERSHELL Disable-NetAdapterQos -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer -ErrorAction SilentlyContinue

:: Bindings that are not common
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_pppoe -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_rdma_ndk -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_ndisuio -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_wfplwf_upper -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_wfplwf_lower -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_netbt -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_netbios -ErrorAction SilentlyContinue

:: Restarting Adapter
POWERSHELL Restart-NetAdapter -Name "Ethernet" -ErrorAction SilentlyContinue

ECHO  Disabling Drivers...
:: Preventing Errors
REG ADD "HKLM\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\hidserv" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\fvevol" /v "ErrorControl" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1

:: ACPI Devices driver
REG ADD "HKLM\System\CurrentControlSet\Services\AcpiDev" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Charge Arbitration Driver
REG ADD "HKLM\System\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Cloud Files Filter Driver
REG ADD "HKLM\System\CurrentControlSet\Services\CldFlt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows sandboxing and encryption filter
REG ADD "HKLM\System\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: GPU Energy Driver
REG ADD "HKLM\System\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (PPTP)
REG ADD "HKLM\System\CurrentControlSet\Services\PptpMiniport" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Application Programming Interface (RAPI)
REG ADD "HKLM\System\CurrentControlSet\Services\RapiMgr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (IKEv2)
REG ADD "HKLM\System\CurrentControlSet\Services\RasAgileVpn" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (L2TP)
REG ADD "HKLM\System\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (SSTP)
REG ADD "HKLM\System\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access IP ARP Driver
REG ADD "HKLM\System\CurrentControlSet\Services\Wanarp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access IPv6 ARP Driver
REG ADD "HKLM\System\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender
REG ADD "HKLM\System\CurrentControlSet\Services\Wdnsfltr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CTF Loader
REG ADD "HKLM\System\CurrentControlSet\Services\WcesComm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Container Isolation
REG ADD "HKLM\System\CurrentControlSet\Services\Wcifs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Container Name Virtualization
REG ADD "HKLM\System\CurrentControlSet\Services\Wcnfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Trusted Execution Environment Class Extension
REG ADD "HKLM\System\CurrentControlSet\Services\WindowsTrustedRT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Microsoft Windows Trusted Runtime Secure Service
REG ADD "HKLM\System\CurrentControlSet\Services\WindowsTrustedRTProxy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

:: Background Activity Moderator Driver (W10Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CNG Hardware Assist algorithm provider (W10Default=4) (W8Default=Empty)
REG ADD "HKLM\System\CurrentControlSet\Services\cnghwassist" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Disk I/O Rate Filter Driver (W10Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\iorate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Security Events Component Minifilter (W10Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\mssecflt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Tunnel Miniport Adapter Driver (W10Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\tunnel" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual WiFi Filter Driver (W10Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: ACPI Processor Aggregator Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: ACPI Power Meter Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: ACPI Wake Alarm Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Acpitime" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Most useless driver to exist (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NT Lan Manager Datagram Receiver Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\bowser" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CD/DVD File System Reader (W8Default=4)
REG ADD "HKLM\System\CurrentControlSet\Services\cdfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CD-ROM Driver / Cannot use programs like rufus (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Common Log / General-purpose logging service (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\CLFS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: (Compbatt for W7) (For laptops) - Microsoft ACPI Control Method Battery Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\CmBatt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Composite Bus Enumerator Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\CompositeBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Console Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\condrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Offline Files Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Desktop Activity Moderator Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: DFS Namespace Client Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\dfsc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Enhanced Storage Filter Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\EhStorClass" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: FAT12/16/32 File System Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\fastfat" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: File Information FS MiniFilter (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\FileInfo" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: BitLocker Drive Encryption Filter Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\fvevol" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Kernel Debug Network Miniport NDIS 6.20 (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\kdnic" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Kernel Security Support Provider Interface Packages (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\KSecPkg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Link-Layer Topology Discovery Mapper I/O Driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\lltdio" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: UAC File Virtualization (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Modem Device Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Modem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: The Networking-MPSSVC-Svc component is part of Windows Firewall (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Defender Firewall Authorization Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\mpsdrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: SMB MiniRedirector Wrapper and Engine (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: SMB 1.x MiniRedirector (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\Mrxsmb10" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: SMB 2.0 MiniRedirector (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Disabling breaks laptop keyboards and PS2 keyboards (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\msisadrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Link-Layer Discovery Protocol (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\MsLldp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: System Management BIOS Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\mssmbios" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NDIS Capture (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisCap" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access NDIS TAPI Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisTapi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual Network Adapter Enumerator (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access NDIS WAN Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisWan" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NDIS Proxy Driver  (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Ndproxy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Network Data Usage Monitoring Driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\Ndu" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NetBIOS interface driver (W8Default=1) 
REG ADD "HKLM\System\CurrentControlSet\Services\NetBIOS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Implements NetBios over TCP/IP (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Named pipe service trigger provider (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Npsvctrig" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Protected Environment Authentication and Authorization Export Driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: QoS Packet Scheduler (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Psched" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: QWAVE enhances AV streaming performance and reliability by ensuring network QoS for AV apps (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access Auto Connection Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\RasAcd" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access PPPOE Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Redirected Buffering Sub System (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Desktop Device Redirector Bus Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\rdpbus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Usually already stripped in custom isos (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\rdyboost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Link-Layer Topology Discovery Responder (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\rspndr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Serial Mouse Driver / Needed for ps2 mice (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\sermouse" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Storage Spaces Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\spaceport" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Server SMB 2.xxx Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\srv2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Server network driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Srvnet" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Central repository of Telephony data (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: IPv6 Protocol Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: TCP/IP registry compatibility driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: TDI translation driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\tdx" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Trusted Platform Module (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\TPM" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Reads/Writes UDF 1.02,1.5,2.0x,2.5 disc formats, usually found on C/DVD discs (W8Default=4)
REG ADD "HKLM\System\CurrentControlSet\Services\udfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Can be disabled on UEFI. Bricks some systems (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\UEFI" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: UMBus Enumerator Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\umbus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual Drive Root Enumerator file (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\vdrvroot" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Hyper-V Virtualization Infrastructure Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Vid" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Volume Manager Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\Volmgrx" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual Wireless Bus Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\vwifibus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\Wdboot" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows defender (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Microsoft Windows Management Interface for ACPI (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\WmiAcpi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Winsock IFS Driver (W8Default=4)
REG ADD "HKLM\System\CurrentControlSet\Services\ws2ifsl" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: This can be disabled, but it breaks some functionality of the kernel. Null is required for piping thus for some programs to work, like wget and wsusoffline (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Null" /v "Start" /t REG_DWORD /d "1" /f >NUL 2>&1
:: This will make the necessary use of static ip
REG ADD "HKLM\System\CurrentControlSet\Services\AFD" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Dhcp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

ECHO  Importing main tweaks...
:: Disable Meltdown/Spectre patches
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Disable DMA memory protection and cores isolation
REG ADD "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Power settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Power settings (Questionable)
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
::Testing more agressive setting atm
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceIdleResiliency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Kernel settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Kernel settings (Questionable)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdealDpcRate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "AdjustDpcThreshold" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Cursor tweaks (Questionable)
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Display tweaks (Questionable)
FOR /F "DELIMS=DesktopMonitor, " %%i in ('WMIC PATH Win32_DesktopMonitor GET DeviceID^| FINDSTR /L "DesktopMonitor"') DO (
SET MonitorAmount=%%i
)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v Display%MonitorAmount%_PipeOptimizationEnable /t REG_DWORD /d "1" /f >NUL 2>&1

:: Force contiguous memory allocation in the DirectX Graphics Kernel
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Force contiguous memory allocation in the NVIDIA driver
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1

:: GPU tweaks (Questionable)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "D3PCLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchedMode" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "UseGpuTimer" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "D3PCLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "UseGpuTimer" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "BuffersInFlight" /t REG_DWORD /d "128" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "D3PCLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableGDIAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePFonDP" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmFbsrPagedDMA" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "UseGpuTimer" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Gpu tweaks (Questionable) Melody Basic Tweaks
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TransitionLatency" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Avalon tweaks (Questionable)
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "ClearTypeLevel" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "EnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "GammaLevel" /t REG_DWORD /d "1600" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "GrayscaleEnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "PixelStructure" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "TextContrastLevel" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "ClearTypeLevel" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "EnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "GammaLevel" /t REG_DWORD /d "1600" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "GrayscaleEnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "PixelStructure" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "TextContrastLevel" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "ClearTypeLevel" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "EnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "GammaLevel" /t REG_DWORD /d "1600" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "GrayscaleEnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "PixelStructure" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "TextContrastLevel" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Direct3d tweaks (Questionable)
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Unlock Silk Smoothness
REG ADD "HKLM\System\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Removing Kernel Blacklist
REG DELETE "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\BlockList\Kernel" /va /reg:64 /f >NUL 2>&1

:: Enabling AL HRTF
ECHO hrtf ^= true > "%appdata%\alsoft.ini"
ECHO hrtf ^= true > "C:\ProgramData\alsoft.ini"

:: Disable additional NTFS/ReFS mitigations
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Drivers and the kernel can be paged to disk as needed
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Using big system memory caching to improve microstuttering
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Using big page file size to improve microstuttering but only if you have 16gb
for /f "skip=1" %%A in ('wmic os get TotalVisibleMemorySize') do ( 
set system_ram=%%A
goto :ramchecker
)
:ramchecker
if %system_ram% GEQ 16277216 if %system_ram% LEQ 17277216 goto 16gb
goto no16gb
:16gb
WMIC computersystem where name="%computername%" set AutomaticManagedPagefile=False >NUL 2>&1
WMIC pagefileset where name="C:\\pagefile.sys" set InitialSize=32768,MaximumSize=32768 >NUL 2>&1
:no16gb

:: Multimedia Profile
REG ADD "HKLM\System\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >NUL 2>&1

:: Process Scheduling
REG ADD "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >NUL 2>&1

:: Minimizing the number of times the CPU is forced to perform the relatively power-costly operation of entering and exiting idle states
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Revision Powerplan Disable Idle
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b" /v "Description" /t REG_EXPAND_SZ /d "(v2.8) Promotes low latency and high performance while eliminating sleeping features." /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b" /v "FriendlyName" /t REG_EXPAND_SZ /d "Revision™ Extreme Performance" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\80e3c60e-bb94-4ad8-bbe0-0d3195efc663" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\d3d55efd-c1ff-424e-9dc3-441be7833010" /v "DCSettingIndex" /t REG_DWORD /d "2000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\d639518a-e56d-4345-8af2-b9f32fb26109" /v "DCSettingIndex" /t REG_DWORD /d "200" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\dab60367-53fe-4fbc-825e-521d069d2456" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\dbc9e238-6de9-49e3-92cd-8c2b4946b472" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0012ee47-9041-4b5d-9b77-535fba8b1442\fc95af4d-40e7-4b6d-835a-56d131dbc80e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\02f815b5-a5cf-4c84-bf20-649d1f75d3d8\4c793e7d-a264-42e1-87d3-7a0d2f523ccd" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\0d7dbae2-4294-402a-ba8e-26777e8488cd\309dce9b-bef4-4119-9921-a851fb12f0f4" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\19cbb8fa-5279-450e-9fac-8a3d5fedd0c1\12bbebe6-58d6-4636-95bb-3217ef867c1a" /v "DCSettingIndex" /t REG_BINARY /d "00000000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\1a34bdc3-7e6b-442e-a9d0-64b6ef378e84" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\25dfa149-5dd1-4736-b5ab-e8a37b5b8187" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\9d7815a6-7ee4-497e-8888-515a05f02364" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\9d7815a6-7ee4-497e-8888-515a05f02364" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\238c9fa8-0aad-41ed-83f4-97be242c8f20\d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\245d8541-3943-4422-b025-13a784f679b7" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\245d8541-3943-4422-b025-13a784f679b7" /v "DCSettingIndex" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683" /v "DCSettingIndex" /t REG_DWORD /d "100000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683" /v "ACSettingIndex" /t REG_DWORD /d "50" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\498c044a-201b-4631-a522-5c744ed4e678" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2e601130-5351-4d9d-8e04-252966bad054\3166bc41-7e98-4e03-b34e-ec0f5f2b218e" /v "ACSettingIndex" /t REG_DWORD /d "4294967295" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2e601130-5351-4d9d-8e04-252966bad054\3166bc41-7e98-4e03-b34e-ec0f5f2b218e" /v "DCSettingIndex" /t REG_DWORD /d "4294967295" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2e601130-5351-4d9d-8e04-252966bad054\c36f0eb4-2988-4a70-8eee-0884fc2c2433" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2e601130-5351-4d9d-8e04-252966bad054\d502f7ee-1dc7-4efd-a55d-f04b6f5c0545" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\2e601130-5351-4d9d-8e04-252966bad054\d502f7ee-1dc7-4efd-a55d-f04b6f5c0545" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\44f3beca-a7c0-460e-9df2-bb8b99e0cba6\3619c3f2-afb2-4afc-b0e9-e7fef372de36" /v "DCSettingIndex" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\48672f38-7a9a-4bb2-8bf8-3d85be19de4e\73cde64d-d720-4bb2-a860-c755afe77ef2" /v "DCSettingIndex" /t REG_DWORD /d "10000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\48672f38-7a9a-4bb2-8bf8-3d85be19de4e\73cde64d-d720-4bb2-a860-c755afe77ef2" /v "ACSettingIndex" /t REG_DWORD /d "10000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\48672f38-7a9a-4bb2-8bf8-3d85be19de4e\d6ba4903-386f-4c2c-8adb-5c21b3328d25" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\48672f38-7a9a-4bb2-8bf8-3d85be19de4e\d6ba4903-386f-4c2c-8adb-5c21b3328d25" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\4f971e89-eebd-4455-a8de-9e59040e7347\5ca83367-6e45-459f-a27b-476b1d01c936" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\4f971e89-eebd-4455-a8de-9e59040e7347\96996bc0-ad50-47ec-923b-6f41874dd9eb" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\4f971e89-eebd-4455-a8de-9e59040e7347\96996bc0-ad50-47ec-923b-6f41874dd9eb" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\4faab71a-92e5-4726-b531-224559672d19" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\501a4d13-42af-4429-9fd1-a8218c268e20\ee12f906-d277-404b-b6da-e5fa1a576df5" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35d" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35d" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35e" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35e" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318584" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318584" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a7" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a7" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\36687f9e-e3a5-4dbf-b1dc-15eb381c6863" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\36687f9e-e3a5-4dbf-b1dc-15eb381c6864" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac7" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac7" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2c" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc418" /v "DCSettingIndex" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc419" /v "ACSettingIndex" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\4bdaf4e9-d103-46d7-a5f0-6280121616ef" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\4bdaf4e9-d103-46d7-a5f0-6280121616ef" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5" /v "DCSettingIndex" /t REG_DWORD /d "5000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5" /v "ACSettingIndex" /t REG_DWORD /d "5000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\616cdaa5-695e-4545-97ad-97dc2d1bdd88" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\616cdaa5-695e-4545-97ad-97dc2d1bdd88" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\616cdaa5-695e-4545-97ad-97dc2d1bdd89" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\616cdaa5-695e-4545-97ad-97dc2d1bdd89" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300971" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300971" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300972" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300972" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\68dd2f27-a4ce-4e11-8487-3794e4135dfa" /v "ACSettingIndex" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\71021b41-c749-4d21-be74-a00f335d582b" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7d24baa7-0b84-480f-840c-1b0743c00f5f" /v "ACSettingIndex" /t REG_DWORD /d "128" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7d24baa7-0b84-480f-840c-1b0743c00f5f" /v "DCSettingIndex" /t REG_DWORD /d "128" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7d24baa7-0b84-480f-840c-1b0743c00f60" /v "ACSettingIndex" /t REG_DWORD /d "128" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7d24baa7-0b84-480f-840c-1b0743c00f60" /v "DCSettingIndex" /t REG_DWORD /d "128" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7f2492b6-60b1-45e5-ae55-773f8cd5caec" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\7f2492b6-60b1-45e5-ae55-773f8cd5caec" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964d" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\8baa4a8a-14c6-4451-8e8b-14bdbd197537" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\8baa4a8a-14c6-4451-8e8b-14bdbd197537" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\93b8b6dc-0698-4d1c-9ee4-0644e900c85d" /v "DCSettingIndex" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\93b8b6dc-0698-4d1c-9ee4-0644e900c85d" /v "ACSettingIndex" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\94d3a615-a899-4ac5-ae2b-e4d8f634367f" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5ab" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5ab" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\bae08b81-2d5e-4688-ad6a-13243356654b" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\bae08b81-2d5e-4688-ad6a-13243356654b" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b" /v "ACSettingIndex" /t REG_DWORD /d "200000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b" /v "DCSettingIndex" /t REG_DWORD /d "200000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6" /v "ACSettingIndex" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6" /v "DCSettingIndex" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\cfeda3d0-7697-4566-a922-a9086cd49dfa" /v "DCSettingIndex" /t REG_DWORD /d "45000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\cfeda3d0-7697-4566-a922-a9086cd49dfa" /v "ACSettingIndex" /t REG_DWORD /d "45000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c9" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c9" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\df142941-20f3-4edf-9a4a-9c83d3d717d1" /v "ACSettingIndex" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\54533251-82be-4824-96c1-47b60b740d00\f735a673-2066-4f80-a0c5-ddee0cf1bf5d" /v "ACSettingIndex" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\68afb2d9-ee95-47a8-8f50-4115088073b1" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\17aaa29b-8b43-4b94-aafe-35f64daaf1ee" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\17aaa29b-8b43-4b94-aafe-35f64daaf1ee" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\684c3e69-a4f7-4014-8754-d45179a56167" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb" /v "ACSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\60c07fe1-0556-45cf-9903-d56e32210242" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\60c07fe1-0556-45cf-9903-d56e32210242" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\82011705-fb95-4d46-8d35-4042b1d20def" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\82011705-fb95-4d46-8d35-4042b1d20def" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\9fe527be-1b70-48da-930d-7bcf17b44990" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\9fe527be-1b70-48da-930d-7bcf17b44990" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\c763ee92-71e8-4127-84eb-f6ed043a3e3d" /v "ACSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\8619b916-e004-4dd8-9b66-dae86f806698\c763ee92-71e8-4127-84eb-f6ed043a3e3d" /v "DCSettingIndex" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\9596fb26-9850-41fd-ac3e-f7c3c00afd4b\10778347-1370-4ee0-8bbd-33bdacaade49" /v "ACSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\9596fb26-9850-41fd-ac3e-f7c3c00afd4b\10778347-1370-4ee0-8bbd-33bdacaade49" /v "DCSettingIndex" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\9596fb26-9850-41fd-ac3e-f7c3c00afd4b\34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4" /v "ACSettingIndex" /t REG_BINARY /d "00000000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\9596fb26-9850-41fd-ac3e-f7c3c00afd4b\34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4" /v "DCSettingIndex" /t REG_BINARY /d "00000000" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\f3193aa7-d9d0-421a-90dc-845e70eff72b\de830923-a562-41af-a086-e3a2c6bad2da\13d09884-f74e-474a-a852-b6bde8ad03a8" /v "DCSettingIndex" /t REG_DWORD /d "100" /f >NUL 2>&1
powercfg -setactive f3193aa7-d9d0-421a-90dc-845e70eff72b >NUL 2>&1
powercfg -attributes sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1 >NUL 2>&1

:: Settings based on current Windows Version
for /f "tokens=3*" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "ProductName"') do set "WinVersion=%%A %%B"
ECHO %WinVersion% | find "Windows 7" > nul
if %errorlevel% equ 0 (
:: Timestamp to 0 cause no problems at all in w7
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
:: Mouse fix (Windows 7)
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000703d0a0000000000e07a14000000000050b81e0000000000c0f5280000000000" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f >NUL 2>&1
)
ECHO %WinVersion% | find "Windows 8.1" > nul
if %errorlevel% equ 0 (
:: Timestamp to 0 cause no problems at all in w8
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
:: Mouse fix (Windows 8.1)
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f >NUL 2>&1
REG ADD add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f >NUL 2>&1
:: Disabling mitigation (Windows 8.1)
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "00000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "00000000000000000000000000000000" /f >NUL 2>&1
:: Manages power policy and power policy notification delivery and IDE Channel / Bricks Windows 7
REG ADD "HKLM\System\CurrentControlSet\Services\Power" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\atapi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
)
ECHO %WinVersion% | find "Windows 10" > nul
if %errorlevel% equ 0 (
:: Timestamp to 1 cause it will force timer to 0.48 while hpet off bios in some w10 versions
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f >NUL 2>&1
:: Mouse fix (Windows 10)
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f >NUL 2>&1
:: Disabling mitigation (Windows 10)
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "22222222222222222002000000200000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "20000020202022220000000000000000" /f >NUL 2>&1
:: Manages power policy and power policy notification delivery and IDE Channel / Bricks Windows 7
REG ADD "HKLM\System\CurrentControlSet\Services\Power" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\atapi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
)

ECHO  Importing minimal tweaks...
:: Disable SmartScreen
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > NUL 2>&1

:: Disable Content Evaluation
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v ContentEvaluation /t REG_DWORD /d "0" /f > NUL 2>&1

:: Disable Timeline
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f > NUL 2>&1

:: Disabling DWM (Windows 7)
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Seens like this reg improves dwm performance
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable power throttling (Windows 10)
REG ADD "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable FSO Globally and GameDVR (Windows 10)
REG ADD "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG DELETE "HKCU\System\GameConfigStore\Children" /f >NUL 2>&1
REG DELETE "HKCU\System\GameConfigStore\Parents" /f >NUL 2>&1

:: Hide Language Bar
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "ShowStatus" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "ExtraIconsOnMinimized" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "Transparency" /t REG_DWORD /d "255" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "Label" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn Off Enhance Pointer Precision
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >NUL 2>&1

:: Control Panel tweaks
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Sound" /v "ExtendedSounds" /t REG_SZ /d "no" /f >NUL 2>&1

:: Disable Acessibility keys
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1

:: Enable All Folders in Explorer Navigation Panel
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable automatic folder type discovery
REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f >NUL 2>&1
REG DELETE "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >NUL 2>&1

:: Disable shortcut text for shortcuts
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f >NUL 2>&1

:: Disable Mouse Keys Keyboard Shortcut
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "186" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "40" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f >NUL 2>&1

:: Disable Data Execution Prevention
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable automatic maintenance
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable fast startup
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Sleep study
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable aero shake
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable downloads blocking
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable malicious software removal tool from installing
REG ADD "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Windows update never notify and never install
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Disable error reporting
REG ADD "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Menu show delay
REG ADD "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >NUL 2>&1

:: Show BSOD details instead of the sad smiley
REG ADD "HKLM\System\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable action center
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable jump lists
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable search history
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable administrative shares
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Keyboard Hotkeys
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d "3" /f >NUL 2>&1
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d "3" /f >NUL 2>&1
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d "3" /f >NUL 2>&1

:: Turn Off Sleep And Lock In Power Options
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Sound Communications Do Nothing
REG ADD "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Disable Store And Display Recently Opened Programs In The Start Menu
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Speed Up Start Time
REG ADD "HKCU\AppEvents\Schemes" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Network Notification Icon
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d "1" /f >NUL 2>&1
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /f >NUL 2>&1

:: Disable Startup Sound
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Small Start Menu Icons
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_LargeMFUIcons" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Black Background
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" /v "OEMBackground" /t REG_DWORD /d "1" /f >NUL 2>&1

:: System properties - performance options - adjust for best performance
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Disable KB4524752 Support Notifications
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Gwx" /v "DisableGwx" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable KB4524752 Support Notifications
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Maintenance
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Prefetcher and Superfetch
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Show all icons and notifications on the taskbar
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Consumer experiences from Microsoft
REG ADD "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable WPP Software Tracing Logs
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn off Microsoft Peer-to-Peer Networking Services
REG ADD "HKLM\Software\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn off Data Execution Prevention
REG ADD "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Display highly detailed status messages
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Trick to make system Startup faster
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn off Pen feedback
REG ADD "HKLM\Software\Policies\Microsoft\TabletPC" /v "TurnOffPenFeedback" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Making menu more responsive
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >NUL 2>&1

:: Disable Remote Assistance Connections
REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Telemetry
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f > NUL 2>&1
ECHO "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl >NUL 2>&1

:: Disable Firewall
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable SettingSync
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t Reg_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t Reg_DWORD /d "2" /f  >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1

:: Disable Windows Search
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Remove Metadata Tracking
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /f > NUL 2>&1

:: Remove Storage Sense
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense" /f > NUL 2>&1

:: Remove Firewall Rules
REG DELETE "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >NUL 2>&1

ECHO  BCD Params...
:: Disable synthetic timer
BCDEDIT /deletevalue useplatformclock >NUL 2>&1
:: Constantly pool interrupts, dynamic tick was implemented as a power saving feature for laptops
BCDEDIT /set disabledynamictick yes >NUL 2>&1
:: Disable synthetic tick
BCDEDIT /set useplatformtick Yes >NUL 2>&1
:: Sync Policy
BCDEDIT /set tscsyncpolicy Enhanced >NUL 2>&1
:: Disable Data Execution Prevention Security Feature
BCDEDIT /set nx AlwaysOff >NUL 2>&1
:: Disable Emergency Management Services
BCDEDIT /set ems No >NUL 2>&1
BCDEDIT /set bootems No >NUL 2>&1
:: Disable code integrity services
BCDEDIT /set integrityservices disable >NUL 2>&1
:: Disable TPM Boot Entropy policy Security Feature
BCDEDIT /set tpmbootentropy ForceDisable >NUL 2>&1
:: Change bootmenupolicy to be able to F8
BCDEDIT /set bootmenupolicy Legacy >NUL 2>&1
:: Disable kernel debugger
BCDEDIT /set debug No >NUL 2>&1
:: Disable Virtual Secure Mode from Hyper-V
BCDEDIT /set hypervisorlaunchtype Off >NUL 2>&1
:: Disable the Controls the loading of Early Launch Antimalware (ELAM) drivers
BCDEDIT /set disableelamdrivers Yes >NUL 2>&1
:: Disable some of the kernel memory mitigations, gamers dont use SGX under any possible circumstance
BCDEDIT /set isolatedcontext No >NUL 2>&1
BCDEDIT /set allowedinmemorysettings 0x0 >NUL 2>&1
:: Disable DMA memory protection and cores isolation
BCDEDIT /set vm No >NUL 2>&1
BCDEDIT /set vsmlaunchtype Off >NUL 2>&1
:: Enable X2Apic and enable Memory Mapping for PCI-E devices
:: (for best results, further more enable MSI mode for all devices using MSI utility or manually)
BCDEDIT /set x2apicpolicy Enable >NUL 2>&1
BCDEDIT /set configaccesspolicy Default >NUL 2>&1
BCDEDIT /set MSI Default >NUL 2>&1
BCDEDIT /set usephysicaldestination No >NUL 2>&1
BCDEDIT /set usefirmwarepcisettings No >NUL 2>&1
:: Questionable
BCDEDIT /set linearaddress57 OptOut >NUL 2>&1
BCDEDIT /set increaseuserva 268435328 >NUL 2>&1
BCDEDIT /set firstmegabytepolicy UseAll >NUL 2>&1
BCDEDIT /set avoidlowmemory 0x8000000 >NUL 2>&1
BCDEDIT /set nolowmem Yes >NUL 2>&1

ECHO  Debloating softwares...
:: Google Chrome
taskkill /f /im chrome.exe >NUL 2>&1
schtasks.exe /change /TN "\GoogleUpdateTaskMachineCore" /Disable >NUL 2>&1
schtasks.exe /change /TN "\GoogleUpdateTaskMachineUA" /Disable >NUL 2>&1
del "c:\program files\google\chrome\application\85.0.4183.102\installer\chrmstp.exe" >NUL 2>&1
sc delete gupdate >NUL 2>&1
sc delete gupdatem >NUL 2>&1
sc delete GoogleChromeElevationService >NUL 2>&1
:: Notepad++
taskkill /f /im notepad++.exe >NUL 2>&1
del /F /Q "%ProgramFiles%\Notepad++\updater" >NUL 2>&1
:: Easy7zip
taskkill /f /im 7zFM.exe >NUL 2>&1
REG ADD "HKCU\Software\7-Zip\Options" /v "CascadedMenu" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\7-Zip\Options" /v "MenuIcons" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\7-Zip\Options" /v "ContextMenu" /t REG_DWORD /d "4132" /f >NUL 2>&1
REG ADD "HKCU\Software\7-Zip\FM\Columns" /v "RootFolder" /t REG_BINARY /d "0100000000000000010000000400000001000000A0000000" /f >NUL 2>&1
del "C:\Users\Public\Desktop\7-Zip File Manager.lnk" >NUL 2>&1
:: Discord (Thanks Chromestastic and Velo)
taskkill /f /im discord.exe >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_modules\397863cd8f\2\discord_game_sdk_x64.dll" /F /Q >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_modules\397863cd8f\2\discord_game_sdk_x64.dll" /F /Q >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_modules\397863cd8f\2\discord_game_sdk_x64.dll" /F /Q >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_modules\397863cd8f\2\discord_game_sdk_x86.dll" /F /Q >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_modules\397863cd8f\2\discord_game_sdk_x86.dll" /F /Q >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_modules\397863cd8f\2\discord_game_sdk_x86.dll" /F /Q >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_cloudsync" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_cloudsync" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_cloudsync" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_dispatch" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_dispatch" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_dispatch" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_erlpack" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_erlpack" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_erlpack" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_game_utils" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_game_utils" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_game_utils" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_krisp" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_krisp" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_krisp" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_media" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_media" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_media" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_overlay2" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_overlay2" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_overlay2" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_rpc" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_rpc" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_rpc" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_Spellcheck" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.307\modules\discord_Spellcheck" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.306\modules\discord_Spellcheck" >NUL 2>&1
attrib +r "%localappdata%\Discord\Update.exe" >NUL 2>&1
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Discord" /f >NUL 2>&1
:: Spotify
taskkill /f /im spotify.exe >NUL 2>&1
del /f/s/q "%appdata%\Spotify\SpotifyMigrator.exe" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\SpotifyStartupTask.exe" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Buddy-list.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Concert.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Concerts.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Error.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Findfriends.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Legacy-lyrics.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Lyrics.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Show.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\Apps\Buddy-list.spa" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\am.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ar.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ar.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\bg.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\bn.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ca.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\cs.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\cs.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\da.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\de.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\de.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\el.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\el.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\en-GB.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\es.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\es.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\es-419.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\es-419.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\et.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fa.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fi.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fi.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fil.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fr.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fr.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\fr-CA.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\gu.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\he.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\he.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\hi.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\hr.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\hu.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\hu.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\id.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\id.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\it.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\it.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ja.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ja.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\kn.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ko.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ko.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\lt.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\lv.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ml.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\mr.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ms.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ms.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\nb.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\nl.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\nl.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\pl.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\pl.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\pt-PT.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\pt-BR.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\pt-BR.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ro.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ru.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ru.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\sk.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\sl.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\sr.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\sv.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\sv.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\sw.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\ta.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\te.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\th.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\th.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\tr.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\tr.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\uk.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\vi.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\vi.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\zh-CN.pak" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\zh-Hant.mo" >NUL 2>&1
del /f/s/q "%appdata%\Spotify\locales\zh-TW.pak" >NUL 2>&1
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Spotify" /f >NUL 2>&1

ECHO  Importing Revi hosts file...
del /F /Q "%WINDIR%\system32\drivers\etc\hosts" >NUL 2>&1
ECHO 0.0.0.0 telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oca.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sqm.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 redir.metaservices.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 choice.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 choice.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wes.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 services.wes.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sqm.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.ppe.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.appex.bing.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.urs.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.appex.bing.net:443>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 settings-sandbox.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-sandbox.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 survey.watson.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.live.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statsfe2.ws.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 compatexchange.cloudapp.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cs1.wpc.v0cdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a-0001.a-msedge.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fe2.update.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statsfe2.update.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sls.update.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 diagnostics.support.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 corp.sts.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statsfe1.ws.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pre.footprintpredict.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i1.services.social.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i1.services.social.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feedback.windows.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feedback.microsoft-hohm.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feedback.search.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.content.prod.cms.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.content.prod.cms.msn.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 e10663.g.akamaiedge.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dmd.metaservices.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 schemas.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.76.0.0/14>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.96.0.0/12>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.124.0.0/16>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.112.0.0/13>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.125.0.0/17>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.74.0.0/15>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.80.0.0/12>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.120.0.0/14>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 137.116.0.0/16>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.192.0.0/11>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.32.0.0/11>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.64.0.0/14>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.55.130.182>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads1.msads.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads1.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads2.msads.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads2.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.live.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bingads.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 browser.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cache.datamart.windows.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 manage.devcenter.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mobile.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mobile.pipe.aria.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 onecollector.cloudapp.aria.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 prod.nexusrules.live.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ris.api.iris.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 self.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 settings-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 spynet2.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 spynetalt.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.alpha.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.appex.bing.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.urs.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetrysvc-by3p.smartscreen.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us.vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v10-win.vortex.data.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v10.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v10.vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v20.vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-bn2.metron.live.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-cy2.metron.live.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex.data.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 web.vortex.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.remoteapp.windowsazure.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.2mdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 b.ads1.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 b.ads2.msads.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 b.rad.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tele.trafficmanager.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1beb2a44.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.fun>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 300ca0d0.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 310ca263.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 320ca3f6.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 330ca589.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 340ca71c.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 360caa42.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 370cabd5.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 3c0cb3b4.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 3d0cb547.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 abc.pema.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-miner.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.blue>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.inwemo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 azvjudwr.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 baiduccdn1.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 berserkpl.net.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 biberukalap.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bjorksta.men>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 blockchain.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 candid.zone>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.adless.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.cloudcoins.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 chainblock.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cnhv.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-have.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-hive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinblind.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinerra.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhiveproxy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinlab.biz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinnebula.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-loot.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-webminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto.csgocpu.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryptoloot.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryweb.github.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crywebber.github.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dev.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 digger.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flare-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.megabanners.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gridiogrid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gus.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hive.tubetitties.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodlers.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodling.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 host.d-ns.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intactoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jroqvbvw.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jsccnn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jscdndel.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jyhfuqoh.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kdowqlpt.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 load.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 m.anyfiles.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.nahnoji.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.torrent.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minemytraffic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.pr0gramm.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-01.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-02.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-03.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 monerominer.rocks>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 noblock.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 okeyletsgo.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 papoto.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 playerassets.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ppoi.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 projectpoi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reservedoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rocks.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smectapop12.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sparnove.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tokyodrift.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webassembly.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wsp.marketgid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.cryptonoter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.mutuza.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xbasfbno.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cnhv.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-hive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 authedmine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 load.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 server.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.pr0gramm.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minemytraffic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-loot.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryptaloot.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryptoloot.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinerra.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-have.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-01.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-02.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-03.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.inwemo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rocks.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-miner.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jsccnn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jscdndel.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhiveproxy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinblind.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinnebula.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 monerominer.rocks>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.cloudcoins.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinlab.biz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.megabanners.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 baiduccdn1.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wsp.marketgid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 papoto.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flare-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 m.anyfiles.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.coinimp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.coinimp.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.blockchained.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.cryptonoter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.mutuza.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-webminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.adless.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hegrinhar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 verresof.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hemnes.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tidafors.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 moneone.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 plexcoin.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.monkeyminer.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go2.mercy.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinpirate.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d.cpufan.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 krb.devphp.org.ua>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nfwebminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cfcdist.gdn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 node.cfcdist.gdn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webxmr.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xmr.mining.best>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hive.tubetitties.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 playerassets.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tokyodrift.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webassembly.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.webassembly.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 okeyletsgo.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 candid.zone>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 andlache.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bablace.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bewaslac.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 biberukalap.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bowithow.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 butcalve.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 evengparme.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gridiogrid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hatcalter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kedtise.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ledinund.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nathetsof.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 renhertfo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rintindown.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sparnove.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 witthethim.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.fun>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bjorksta.men>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto.csgocpu.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 noblock.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 digger.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dev.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reservedoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.torrent.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 host.d-ns.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 abc.pema.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 js.nahnoji.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.nahnoji.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.webmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intactoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.blue>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smectapop12.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 berserkpl.net.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodlers.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodling.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 chainblock.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minescripts.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.minescripts.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wss.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 clickwith.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dronml.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 niematego.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tulip18.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 didnkinrab.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ledhenone.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 losital.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mebablo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 moonsade.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nebabrop.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pearno.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rintinwa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 willacrit.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www2.adfreetv.ch>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 new.minr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 test.minr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 staticsfs.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn-code.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 g-content.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.g-content.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.static-cnt.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cnt.statistic.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jquery-uim.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.jquery-uim.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn-jquery.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p1.interestingz.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kippbeak.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pasoherb.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 axoncoho.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 depttake.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flophous.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pr0gram.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 authedmine.eu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.monero-miner.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.datasecu.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jquery-cdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.etzbnfuigipwvs.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.terethat.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 freshrefresher.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.pzoifaum.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ws.pzoifaum.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.bhzejltg.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ws.bhzejltg.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vip.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eu.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 as.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eu.cfcdist.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 as.cfcdist.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us.cfcdist.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gustaver.ddns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 worker.salon.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.appelamule.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mepirtedic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.streambeam.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzjzewsma.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ffinwwfpqi.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ininmacerad.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mhiobjnirs.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 open-hive-server-1.pp.ua>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pool.hws.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pool.etn.spacepools.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.aalbbh84.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.aymcsx.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros01.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros02.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros03.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros04.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros05.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros06.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros07.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros08.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros09.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros10.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros11.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros12.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 npcdn1.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mxcdn2.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn6.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mxcdn1.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn02.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn4.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jqcdn2.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn1.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn5.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wpcdn1.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jqcdn01.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jqcdn03.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.website>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 video.videos.vidto.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play1.videos.vidto.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 playe.vidto.se>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 video.streaming.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eth-pocket.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xvideosharing.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bestcoinsignals.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eucsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 traviilo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wasm24.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xmr.cool>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.netflare.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdnjs.cloudflane.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.cloudflane.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 clgserv.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hide.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 graftpool.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 encoding.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 altavista.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 scaleway.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nexttime.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 never.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 2giga.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminerpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minercry.pt>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adplusplus.fr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ethtrader.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gobba.myeffect.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bauersagtnein.myeffect.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 besti.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jurty.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jurtym.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mfio.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mwor.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oei1.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wordc.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 berateveng.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ctlrnwbv.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ermaseuc.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kdmkauchahynhrs.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 uoldid.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqrcdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqassets.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqcdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jquerrycdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqwww.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 lightminer.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.lightminer.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dl.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mlib.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minr.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ws.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmst.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmnr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmcm.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmcm.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 videoplayer2.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.video2.stream.vidzi.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 001.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 002.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 003.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 004.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 005.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 006.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 007.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 008.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 authedwebmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.authedwebmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 skencituer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 site.flashx.cc>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play1.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play2.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play4.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play5.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 js.vidoza.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mm.zubovskaya-banya.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mysite.irkdsu.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.estream.nu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.estream.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.estream.nu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.estream.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.tainiesonline.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.vidzi.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.pampopholf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.pampopholf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.malictuiar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.malictuiar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.tainiesonline.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ocean2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rock2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stone2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sass2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sea2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.pc.belicimo.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.power.tainiesonline.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.s01.vidtodo.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wm.yololike.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.mix.kinostuff.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.on.animeteatr.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.mine.gay-hotvideo.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.www.intellecthosting.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mytestminer.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.vb.wearesaudis.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gramombird.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.gramombird.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ugmfvqsu.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bsyauqwerd.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ccvwtdtwyu.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 baywttgdhe.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pdheuryopd.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iaheyftbsn.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 djfhwosjck.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 najsiejfnc.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zndaowjdnf.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 yqaywudifu.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 malictuiar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proofly.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zminer.zaloapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vkcdnservice.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dexim.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 acbp0020171456.page.tl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vuryua.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minexmr.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gitgrub.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d8acddffe978b5dfcae6.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eth-pocket.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 autologica.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 whysoserius.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aster18cdn.nl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nerohut.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gnrdomimplementation.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pon.ewtuyytdf45.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hhb123.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dzizsih.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nddmcconmqsy.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 silimbompom.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 unrummaged.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fruitice.realnetwrk.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 synconnector.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 toftofcal.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gasolina.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 8jd2lfsq.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 afflow.18-plus.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 afminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aservices.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 becanium.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 brominer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn-analytics.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.static-cnt.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cloudcdn.gdn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-service.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinpot.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinrail.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 etacontent.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 exdynsrv.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 formulawire.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.bestmobiworld.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 goldoffer.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hallaert.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hashing.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 igrid.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 laserveradedomaina.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 machieved.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nametraff.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 offerreality.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ogrid.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 panelsave.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 party-vqgdyvoycc.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pertholin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 premiumstats.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 serie-vostfr.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 salamaleyum.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smartoffer.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stonecalcom.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thewhizmarketing.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thewhizproducts.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thewise.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 traffic.tc-clicks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vcfs6ip5h6.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 web.dle-news.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmining.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wp-monero-miner.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wtm.monitoringservice.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xy.nullrefexcep.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 yrdrtzmsmt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wss.rand.com.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.verifier.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.accountant>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minerad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-cube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-services.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 service4refresh.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 money-maker-script.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 money-maker-default.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-ner-mi-nis4.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-nis-ner-mi-5.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-mi-nis-ner2.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-mi-nis-ner.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mi-de-ner-nis3.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.soodatmish.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.feesocrald.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn1.pebx.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.nexioniect.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.besstahete.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.myregeneaf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.myregeneaf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reauthenticator.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rock.reauthenticator.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 serv1swork.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 str1kee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 f1tbit.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 g1thub.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 swiftmining.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cashbeet.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wmtech.website>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.notmining.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinminingonline.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alflying.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alflying.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alflying.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dubester.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dubester.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dubester.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightsy.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightsy.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightsy.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flighty.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightzy.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightzy.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightzy.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gettate.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gettate.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gettate.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mighbest.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mighbest.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mighbest.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statdynamic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alpha.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.miner.beeppool.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beatingbytes.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 besocial.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beta.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bulls.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de1.eu.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ethmedialab.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feilding.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 foxton.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ganymed.beeppool.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 himatangi.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 levin.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.terorie.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-1.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-10.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-11.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-12.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-13.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-14.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-15.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-16.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-17.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-18.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-19.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-2.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-3.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-4.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-5.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-6.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-7.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-8.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-9.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-5.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-6.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-7.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-8.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.beeppool.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-deu-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-fra-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-fra-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-gbr-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nimiq.terorie.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nimiqtest.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ninaning.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 node.alpha.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 node.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nodeb.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nodeone.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-can-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-fra-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-fra-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-fra-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-gbr-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-gbr-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-pol-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-pol-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 script.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-1.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-1.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-1.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-10.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-10.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-10.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-11.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-11.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-11.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-12.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-12.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-12.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-13.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-13.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-13.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-14.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-14.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-14.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-15.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-15.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-15.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-16.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-16.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-16.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-17.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-17.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-17.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-18.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-18.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-18.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-19.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-19.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-19.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-2.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-2.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-2.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-20.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-20.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-20.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-3.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-3.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-3.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-4.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-4.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-4.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-5.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-5.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-5.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-6.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-6.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-6.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-7.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-7.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-7.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-8.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-8.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-8.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-9.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-9.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-9.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-can-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-can-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-5.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-6.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed1.sushipool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 shannon.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq1.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq2.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq3.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq4.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq5.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq6.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tokomaru.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 whanganui.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.besocial.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jscoinminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jscoinminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.tercabilis.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.istlandoll.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s01.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s02.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s03.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s04.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s05.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s06.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s07.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s08.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s09.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s10.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s100.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s11.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s12.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s13.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 binarybusiness.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bitcoin-pay.eu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cloud-miner.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cloud-miner.eu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 easyhash.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 srcip.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 srcips.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 4967133.fls.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 6498008.fls.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aax-us-east.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aax.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-apac.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-emea.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.mo.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.pl.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.sg.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.uk.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adclick.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adman.gr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admarketing.yahoo.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admarvel.s3.amazonaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admicro1.vcmedia.vn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admicro2.vcmedia.vn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admitad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admixer.co.kr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admixer.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admob.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admulti.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adnxs.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adobesupportnumber.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adocean.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adonly.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adotsolution.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adotube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adprotected.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adpublisher.s3.amazonaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adquota.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads-twitter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.ad2iction.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.admoda.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.aerserv.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.easy-ads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.facebook.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.fotoable.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.glispa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.linkedin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.marvel.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.matomymobile.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mediaforge.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.midatlantic.aaa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mobilefuse.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mobilityware.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mobvertising.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mopub.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.n-ws.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.ookla.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pdbarea.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pinger.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pinterest.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pubmatic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.reddit>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.reward.rakuten.jp>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.taptapnetworks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.tremorhub.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.xlxtra.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.yahoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.youtube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads2.contentabc.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsafeprotected.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsame.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adscale.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsee.jp>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.goforandroid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.kimia.es>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.mobillex.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.pandora.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.ubiyoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.unityads.unity3d.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservetx.media.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.ge>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adshost2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsmo.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsmoloco.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsniper.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adspirit.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adspynet.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsrvmedia.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsrvr.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsymptotic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtaily.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtech.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtilt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtrack.king.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adultadworld.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adups.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adv.mxmcdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adversal.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adverticum.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advertise.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advertising.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advertur.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advombat.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adwhirl.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adwired.mobi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adwods.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adx.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adz.mobi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzerk.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzmedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzmobi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzworld.in>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 affinity.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 affiz.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 agile-support.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 airpush.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 almancakurslari.gen.tr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 altitude-arena.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 am15.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazing-your-prize86.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazoncareers.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazoncash.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazoncash.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonfromhome.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazongigs.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonhiring.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonmoney.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonprofits.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonprofits.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonrecruiter.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonwealth.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonwork.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amedi.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 americageekpayment.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 americageeks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amoad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amobee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amptrack.dailymail.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.brave.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.facebook.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.ff.avast.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.libertymutual.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.modul.ac.at>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.pinterest.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.pointdrive.linkedin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.query.yahoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.twitter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.yahoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 andomedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.appfireworks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.fusepowered.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.kiip.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.leadbolt.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.usebutton.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app-measurement.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app-trackings.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app.adjust.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app.link>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appclick.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appleforsystem.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appmetrica.yandex.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appscase.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 banners.klm.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 basecrew.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacon.clickequations.net.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacon.eb-collector.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons.gcp.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons2.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons3.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons4.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons5.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 becoquin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bid.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 biokamakozmetik.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bloggingfornetworking.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 branch.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 brotherprintersupportphonenumber.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 c.aaxads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 c.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdex.mu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.doublesclick.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdnjs.cloudflare.com.cdn.cloudflare.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cesid.com.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 check-testingyourprize16.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 chiropractic-wellness.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 classyleague.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 clickandflirt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 client-event-reporter.twitch.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cm.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-hive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 combee84.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 countess.twitch.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crash.discordapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crash.steampowered.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cum.fr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d2v02itv0y9u9t.cloudfront.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d355fqgqddpk8.cloudfront.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 digitechinfosolutions.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 download4.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 driverupdate.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dunmebach.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 easyads.bg>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 easydownloadnow.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 economylube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 errorconnect.webcam>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 euyexxwe.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 events.gfe.nvidia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 events.redditmedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fasterpropertybuyers.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fastframe.com.br>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fgsmjjpn.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 firebaselogging.googleapis.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flirt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 forchaklaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 format557-info.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 freshmarketer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 geniegamer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ghochv3eng.trafficmanager.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gmil.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 google-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googleads.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googleads4.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googleanalytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googletagmanager.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 goretail.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gstaticadssl.l.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 harvestbiblefellowship.us>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 heshimed.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hostedocsp.globalsign.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hotmailcustomersupport.com.au>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i-mobile.co.jp>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i-vengo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i.skimresources.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ia-tracker.fbsbx.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iad.appboy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iadsdk.apple.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iamediaserve.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 imasdk.googleapis.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 improving.duckduckgo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 incoming.telemetry.mozilla.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 infolinks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobi.cn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobi.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobicdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobisdk-a.akamaihd.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inner-active.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inner-active.mobi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 innity.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 innovid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 insightexpressai.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 integral-marketing.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intellitxt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intermarkets.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 internetcareer.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 itshurley.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jnhosting.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kallohonka.fi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kipos.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kurankitabevi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 laze35.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 lb.usemaxserver.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 log.byteoversea.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 log.pinterest.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 logfiles.zoom.us>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 lord16.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mads.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mail-ads.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 malengotours.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 matjournal.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.advisorchannel.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.asos.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.att.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.cvshealth.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.dynad.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.fedex.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 muonpreux.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 myphonesupport.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mytilene.fr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 myway.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 n4403ad.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 notify.bugsnag.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 onatonline.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oneclicksupport.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 onlinetechsoft.weebly.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p4-fbm4tfy4du3vk-rsg77dtzm53vwr6k-854535-i1-v6exp3.v4.metric.gstatic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p4-fbm4tfy4du3vk-rsg77dtzm53vwr6ks-854535-i2-v6exp3.ds.metric.gstatic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 page-confrim-safe.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead.l.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead1.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead2.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead46.l.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagefair.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partner.googleadservices.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partner.intentmedia.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partnerad.l.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partnerearning.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 passporttraveleg.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pcoptimizerpro.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 perf-events.cloud.unity3d.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pflexads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 phluant.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pixel.ad>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pixel.admobclick.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pixel.facebook.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 platinumphonesupport.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ponmile.myjino.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pubads.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 public.cloud.unity3d.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reportcentral.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rereddit.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 retailpay.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 revsherri.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rtb2.doubleverify.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 saltofearthlightofworld.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 securepubads.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sessions.bugsnag.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 settings.crashlytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 slicktimesavers.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smetrics.midatlantic.aaa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smmknight.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 spicychats.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sporthome.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ssl.google-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 st-n.ads1-adnow.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.ads-twitter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stats.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stats.mediaforge.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stats.wp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stockretail.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 storejobs.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 strnet24.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 survey.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tagmanager.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.gfe.nvidia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 theunknowncomposer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 togethernetworks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tom006.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tps20512.doubleverify.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.adform.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.cpatool.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.effiliation.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.wattpad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.zappos.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.admarketplace.net.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.bp01.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.epicgames.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.feedmob.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.feedperfect.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.intl.miui.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.klickthru.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.opencandy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.opencandy.com.s3.amazonaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 trafficjunky.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 trafficsourceoftoplevelcontentsources.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 trovi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ulla.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 universalpapercupmachines.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us04logfiles.zoom.us>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 usa-usage.ime.cootek.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 usa.cc>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 uyoutube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v6analytics.htmedia.in.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 video-ad-stats.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vietbacsecurity.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vm5apis.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wapsort.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webserve.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webstorejobs.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www-google-analytics.l.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www-googletagmanager.l.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.google-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.googletagmanager.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.googletagservices.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 youtube.cleverads.vn>>%windir%\system32\drivers\etc\hosts

ECHO  Tweaking Services...
::Windows Store
REG ADD "HKLM\SYSTEM\ControlSet001\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\ClipSVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\AppXSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\LicenseManager" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\NgcSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\NgcCtnrSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\wlidsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TokenBroker" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disk Management
REG ADD "HKLM\SYSTEM\ControlSet001\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vds" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Xbox Apps
REG ADD "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable WiFi
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WwanSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WlanSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\wcncsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\lmhosts" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Router
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable BitLocker
REG ADD "HKLM\SYSTEM\ControlSet001\Services\BDESVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Telemetry and Diagonostics
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Bluetooth
REG ADD "HKLM\SYSTEM\ControlSet001\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Firewall
REG ADD "HKLM\SYSTEM\ControlSet001\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Hyper-V
REG ADD "HKLM\SYSTEM\ControlSet001\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Windows Error Reporting and Push Notifications
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Remote Desktop
REG ADD "HKLM\SYSTEM\ControlSet001\Services\RasAuto" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SessionEnv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TermService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\UmRdpService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\RpcLocator" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Print
REG ADD "HKLM\SYSTEM\ControlSet001\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable SmartCard
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Tablet
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TabletInputService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Program Compatibility Assistant
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Task Scheduler
REG ADD "HKLM\SYSTEM\ControlSet001\Services\Schedule" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Disable WSearch
REG ADD "HKLM\SYSTEM\ControlSet001\Services\wsearch" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
::Disable Unneeded Services
REG ADD "HKLM\SYSTEM\ControlSet001\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\AppReadiness" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\NfsClnt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\p2psvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\perceptionsimulation" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PlugPlay" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\RetailDemo" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\RmSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SensorDataService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SensorService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SensrSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SharedRealitySvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\StiSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\svsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\VaultSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WalletService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\CaptureService" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\cbdhsvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\CDPUserSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\ConsentUxUserSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DeviceAssociationBrokerSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DevicePickerUserSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\DevicesFlowUserSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\MessagingService" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\PimIndexMaintenanceSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\UnistoreSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Services\UserDataSvc" /v Start /t REG_DWORD /d "4" /f >NUL 2>&1

:ending
ECHO.
ECHO  Finished with tweaking
ECHO  Report feedbacks, end of script
ECHO  Make sure your IP is now STATIC...
ECHO.
ECHO.
pause

::TO TEST MANY VALUES
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 0000000a /f
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 0000000a /f
::SEENS PROBLEMATIC
::REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AlpcWakePolicy" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >NUL 2>&1
