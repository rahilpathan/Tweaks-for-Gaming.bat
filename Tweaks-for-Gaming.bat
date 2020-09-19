@ECHO OFF &SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
title Felipe.#8581 ~ Donate: bit.ly/3goAOyc

ECHO.
ECHO  Tweaking improves latency, input lag, system responsiveness, not FPS
ECHO  Do not expect your computer to hit higher fps unless you did shit before 
ECHO  This is not realistic and that's why it's called optimization, not a miracle
ECHO.
ECHO.
ECHO  Automatization is not the best way, please learn tweaking
ECHO  You can start reading all guides on Revision discord (revi.cc)
ECHO.

:: Enabling and starting required services...
POWERSHELL "Set-ExecutionPolicy -ExecutionPolicy Unrestricted" >NUL 2>&1
SC CONFIG Winmgmt start=demand >NUL 2>&1 & SC START Winmgmt >NUL 2>&1
SC CONFIG TrustedInstaller start=demand >NUL 2>&1 & SC START TrustedInstaller >NUL 2>&1
SC CONFIG AppInfo start=demand >NUL 2>&1 & SC START AppInfo >NUL 2>&1
SC CONFIG DeviceInstall start=demand >NUL 2>&1 & SC START DeviceInstall >NUL 2>&1
SC CONFIG Dhcp start=demand >NUL 2>&1 & SC START Dhcp >NUL 2>&1
SC CONFIG w32time start=demand >NUL 2>&1 & SC START w32time >NUL 2>&1

:: Resync time
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

:: Image File Execution Options...
POWERSHELL "Remove-Item -Path \"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Enabling Windows Components...
dism /online /enable-feature /featurename:DesktopExperience /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:LegacyComponents /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:DirectPlay /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:NetFx4-AdvSrvs /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:NetFx3 /all /norestart >NUL 2>&1

:: Enabling MSI for GPU...
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >NUL 2>&1
)

:: Disabling Mitigations...
POWERSHELL "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"  >NUL 2>&1

:: Disabling RAM compression...
POWERSHELL Disable-MMAgent -MemoryCompression -ApplicationPreLaunch -ErrorAction SilentlyContinue >NUL 2>&1

:: Disabling User Account Control...
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

:: Disabling Windows Update and Defender...
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

:: Disabling IoLatencyCap...
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

:: Disabling HIPM and DIPM...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
REG ADD "%%a" /v "EnableHIPM" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "%%a" /v "EnableDIPM" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Services\=!
)
)

:: Disabling CdpUserSvcs...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /F "cdpusersvc"') DO (
REG ADD "%%a" /F /V "Start" /T REG_DWORD /d 4 >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\services\=!
)
)

:: Disabling QoS and NdisCap...
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

:: Disabling USB Hub and StorPort idle...
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

:: Installing AeroLite
IF EXIST "%WinDir%\Resources\Themes\aero\aerolite.msstyles" (
powershell "$content = [System.IO.File]::ReadAllText('%WinDir%\Resources\Themes\aero.theme').Replace('%ResourceDir%\Themes\Aero\Aero.msstyles','%ResourceDir%\Themes\Aero\Aerolite.msstyles'); [System.IO.File]::WriteAllText('%WinDir%\Resources\Themes\aerolite.theme', $content)" >NUL 2>&1
IF EXIST "%WinDir%\Resources\Themes\light.theme" (
powershell "$content = [System.IO.File]::ReadAllText('%WinDir%\Resources\Themes\light.theme').Replace('%ResourceDir%\Themes\Aero\Aero.msstyles','%ResourceDir%\Themes\Aero\Aerolite.msstyles'); [System.IO.File]::WriteAllText('%WinDir%\Resources\Themes\lightlite.theme', $content)" >NUL 2>&1 
)
)

:: Installing Process Explorer...
IF EXIST "%WINDIR%\procexp64.exe" REG ADD "HKLM\System\CurrentControlSet\Services\PCW" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
IF EXIST "%WINDIR%\procexp64.exe" REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\procexp64.exe" /f >NUL 2>&1

:: Network tweaks, takes time...
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
REG ADD "%%r" /v "*ReceiveBuffers" /t REG_SZ /d "112" /f >NUL 2>&1
REG ADD "%%r" /v "*RSS" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*RssBaseProcNumber" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*RssMaxProcNumber" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*SpeedDuplex" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TransmitBuffers" /t REG_SZ /d "112" /f >NUL 2>&1
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
POWERSHELL Disable-NetAdapterLso -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterRsc -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterIPsecOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterPowerManagement -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterChecksumOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterEncapsulatedPacketTaskOffload -Name "*" -ErrorAction SilentlyContinue

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

:: Disabling Drivers...
:: Preventing Errors
REG ADD "HKLM\System\CurrentControlSet\Services\fvevol" /v "ErrorControl" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\hidserv" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Audiosrv" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
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

:: Kernel settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f >NUL 2>&1

:: GPU settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable additional NTFS/ReFS mitigations
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >NUL 2>&1

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

:: Process Scheduling
REG ADD "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "37" /f >NUL 2>&1

:: BCD Params...
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

:: Settings based on current Windows Version
for /f "tokens=3*" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "ProductName"') do set "WinVersion=%%A %%B"
ECHO %WinVersion% | find "Windows 7" > nul
if %errorlevel% equ 0 (
:: Disabling DWM
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >NUL 2>&1
:: Mouse fix
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000703d0a0000000000e07a14000000000050b81e0000000000c0f5280000000000" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f >NUL 2>&1
:: Safety measures
REG ADD "HKLM\System\CurrentControlSet\Services\Power" /v "Start" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\atapi" /v "Start" /t REG_DWORD /d "0" /f >NUL 2>&1
)
ECHO %WinVersion% | find "Windows 8.1" > nul
if %errorlevel% equ 0 (
:: Mouse fix
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f >NUL 2>&1
REG ADD add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f >NUL 2>&1
:: Disabling mitigation
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "00000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "00000000000000000000000000000000" /f >NUL 2>&1
)
ECHO %WinVersion% | find "Windows 10" > nul
if %errorlevel% equ 0 (
:: Disable FSO Globally and GameDVR
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
:: Disable power throttling
REG ADD "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >NUL 2>&1
:: Mouse fix
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f >NUL 2>&1
:: Disabling mitigation
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "22222222222222222002000000200000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "20000020202022220000000000000000" /f >NUL 2>&1
)

:: Multimedia Profile
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >NUL 2>&1

:: Unlock Silk Smoothness
REG ADD "HKLM\System\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Seens like this reg improves dwm performance
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f >NUL 2>&1

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

:: Disable automatic maintenance
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disabling Hibernation
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

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
REG DELETE "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >NUL 2>&1

:: Disable SettingSync
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t Reg_DWORD /d "2" /f  >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t Reg_DWORD /d "5" /f >NUL 2>&1

:: Disable Windows Search
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Remove Metadata Tracking
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /f > NUL 2>&1

:: Remove Storage Sense
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense" /f > NUL 2>&1

ECHO  Debloating...
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
:: Discord
taskkill /f /im discord.exe >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_modules\397863cd8f\2\discord_game_sdk_x64.dll" /F /Q >NUL 2>&1
DEL "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_modules\397863cd8f\2\discord_game_sdk_x86.dll" /F /Q >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_cloudsync" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_dispatch" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_erlpack" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_game_utils" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_krisp" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_media" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_overlay2" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_rpc" >NUL 2>&1
rd /s /q "%HOMEPATH%\appdata\Roaming\discord\0.0.308\modules\discord_Spellcheck" >NUL 2>&1
attrib +r "%localappdata%\Discord\Update.exe" >NUL 2>&1
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
:: Process Explorer
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "EulaAccepted" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "Windowplacement" /t REG_BINARY /d "2c0000000200000003000000ffffffffffffffffffffffffffffffff75030000110000009506000069020000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "FindWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000096000000960000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "SysinfoWindowplacement" /t REG_BINARY /d "2c00000000000000010000000000000000000000ffffffffffffffff28000000280000002b0300002b020000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "PropWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000028000000280000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DllPropWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000028000000280000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "UnicodeFont" /t REG_BINARY /d "080000000000000000000000000000009001000000000000000000004d00530020005300680065006c006c00200044006c00670000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "Divider" /t REG_BINARY /d "531f0e151662ea3f" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "SavedDivider" /t REG_BINARY /d "531f0e151662ea3f" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ProcessImageColumnWidth" /t REG_DWORD /d "261" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowUnnamedHandles" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowDllView" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HandleSortColumn" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HandleSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DllSortColumn" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DllSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ProcessSortColumn" /t REG_DWORD /d "4294967295" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ProcessSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightServices" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightOwnProcesses" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightRelocatedDlls" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightJobs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightNewProc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightDelProc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightImmersive" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightProtected" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightPacked" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightNetProcess" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightSuspend" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HighlightDuration" /t REG_DWORD /d "1000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowCpuFractions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowLowerpane" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowAllUsers" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowProcessTree" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "SymbolWarningShown" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HideWhenMinimized" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "AlwaysOntop" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "OneInstance" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "NumColumnSets" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ConfirmKill" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "RefreshRate" /t REG_DWORD /d "1000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "PrcessColumnCount" /t REG_DWORD /d "12" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DllColumnCount" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "HandleColumnCount" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DefaultProcPropPage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DefaultSysInfoPage" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DefaultDllPropPage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "DbgHelpPath" /t REG_SZ /d "C:\Windows\SYSTEM32\dbghelp.dll" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "SymbolPath" /t REG_SZ /d "" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorPacked" /t REG_DWORD /d "16711808" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorImmersive" /t REG_DWORD /d "15395328" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorOwn" /t REG_DWORD /d "16765136" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorServices" /t REG_DWORD /d "13684991" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorRelocatedDlls" /t REG_DWORD /d "10551295" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorGraphBk" /t REG_DWORD /d "15790320" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorJobs" /t REG_DWORD /d "27856" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorDelProc" /t REG_DWORD /d "4605695" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorNewProc" /t REG_DWORD /d "4652870" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorNet" /t REG_DWORD /d "10551295" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorProtected" /t REG_DWORD /d "8388863" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowHeatmaps" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ColorSuspend" /t REG_DWORD /d "8421504" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "StatusBarColumns" /t REG_DWORD /d "13589" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowAllCpus" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowAllGpus" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "Opacity" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "GpuNodeUsageMask" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "GpuNodeUsageMask1" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "VerifySignatures" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "VirusTotalCheck" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "VirusTotalSubmitUnknown" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ToolbarBands" /t REG_BINARY /d "0601000000000000000000004b00000001000000000000004b00000002000000000000004b00000003000000000000004b0000000400000000000000400000000500000000000000500000000600000000000000930400000700000000000000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "UseGoogle" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowNewProcesses" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "TrayCPUHistory" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowIoTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowNetTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowDiskTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowPhysTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowCommitTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ShowGpuTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "FormatIoBytes" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "StackWindowPlacement" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer" /v "ETWstandardUserWarning" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumnMap" /v "0" /t REG_DWORD /d "26" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumnMap" /v "1" /t REG_DWORD /d "42" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumnMap" /v "2" /t REG_DWORD /d "1033" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumnMap" /v "3" /t REG_DWORD /d "1111" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumnMap" /v "4" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumns" /v "0" /t REG_DWORD /d "110" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumns" /v "1" /t REG_DWORD /d "180" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumns" /v "2" /t REG_DWORD /d "140" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumns" /v "3" /t REG_DWORD /d "300" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\DllColumns" /v "4" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\HandleColumnMap" /v "0" /t REG_DWORD /d "21" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\HandleColumnMap" /v "1" /t REG_DWORD /d "22" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\HandleColumns" /v "0" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\HandleColumns" /v "1" /t REG_DWORD /d "450" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "0" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "1" /t REG_DWORD /d "1055" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "2" /t REG_DWORD /d "1650" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "3" /t REG_DWORD /d "1065" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "4" /t REG_DWORD /d "1200" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "5" /t REG_DWORD /d "1092" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "6" /t REG_DWORD /d "1340" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "7" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "8" /t REG_DWORD /d "1333" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "9" /t REG_DWORD /d "1636" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "10" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "11" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "12" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "13" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "14" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "15" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "16" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "17" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "18" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumnMap" /v "19" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "0" /t REG_DWORD /d "261" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "1" /t REG_DWORD /d "35" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "2" /t REG_DWORD /d "37" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "3" /t REG_DWORD /d "52" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "4" /t REG_DWORD /d "85" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "5" /t REG_DWORD /d "80" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "6" /t REG_DWORD /d "60" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "7" /t REG_DWORD /d "39" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "8" /t REG_DWORD /d "65" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "9" /t REG_DWORD /d "76" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "10" /t REG_DWORD /d "31" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "11" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "12" /t REG_DWORD /d "55" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "13" /t REG_DWORD /d "31" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "14" /t REG_DWORD /d "70" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "15" /t REG_DWORD /d "70" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\ProcessColumns" /v "16" /t REG_DWORD /d "44" /f >NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\Process Explorer\VirusTotal" /v "VirusTotalTermsAccepted" /t REG_DWORD /d "1" /f >NUL 2>&1

:ending
ECHO.
ECHO  Finished with tweaking
ECHO  Report feedbacks, end of script
pause

::TO TEST MANY VALUES
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 0000000a /f
::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 0000000a /f
::SEENS PROBLEMATIC
::REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AlpcWakePolicy" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "1" /f >NUL 2>&1
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >NUL 2>&1
::QUESTIONABLE
::BCDEDIT /set linearaddress57 OptOut >NUL 2>&1
::BCDEDIT /set increaseuserva 268435328 >NUL 2>&1
::BCDEDIT /set firstmegabytepolicy UseAll >NUL 2>&1
::BCDEDIT /set avoidlowmemory 0x8000000 >NUL 2>&1
::BCDEDIT /set nolowmem Yes >NUL 2>&1
::Drivers and the kernel can be paged to disk as needed
::REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >NUL 2>&1
