
@echo off
setlocal EnableDelayedExpansion

echo ========================================
echo      Windows 10/11 Performance Booster
echo ========================================
echo.

:: Create a restore point
echo Creating System Restore Point...
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Win10Boost Script Applied", 100, 7

echo.
echo *** Applying Performance Optimizations ***
echo.

:: ============================================
:: REMOVING WINDOWS DEFAULT APPS
:: ============================================
::(Keeping Camera, Calculator, Sound recorder, BingWeather, Dolby, Netflix, Hulu, PrimeVideo, Spotify, Skype, Viber)
Powershell -Command "Get-AppxPackage -allusers *3DBuilder*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *ACGMediaPlayer*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *ActiproSoftware*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *AdobePhotoshop*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Advertising.Xml*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *AppConnector*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Asphalt8Airborne*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *AutodeskSketchBook*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *BingFinance*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *BingNews*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *BingSports*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *BingTranslator*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *BubbleWitch3Saga*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *CandyCrush*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *CyberLinkMediaSuiteEssentials*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *DisneyMagicKingdoms*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *DrawboardPDF*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Duolingo*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *EclipseManager*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Facebook*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *FarmVille2CountryEscape*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Flipboard*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *GetHelp*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Getstarted*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *HiddenCity*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *HiddenCityMysteryofShadows*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Keeper*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Lens*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *LinkedInforWindows*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *MarchofEmpires*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Messaging*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.Advertising.Xaml*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.MSPaint*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.NET.Native.Framework.1.*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.Services.Store.Engagement*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.Wallet*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.WebMediaExtensions*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.WebpImageExtension*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.WindowsFeedback*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.XboxApp*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.XboxGameOverlay*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.XboxIdentityProvider*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.YourPhone*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.ZuneMusic*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft.ZuneVideo*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Microsoft3DViewer*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *MicrosoftOfficeHub*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *MicrosoftPowerBIForWindows*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *MicrosoftSolitaireCollection*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *MicrosoftStickyNotes*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *MixedReality.Portal*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *NetworkSpeedTest*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *OneCalendar*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *OneConnect*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *OneNote*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Pandora*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *PandoraMediaInc*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *People*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Plex*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Print3D*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *ROBLOXCORPORATION.ROBLOX*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *RemoteDesktop*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Roblox*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *RoyalRevolt*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *RoyalRevolt2*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *ScreenSketch*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *SolitaireCollection*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *SpeedTest*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Sway*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Twitter*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Wallet*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Whiteboard*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *WinZipUniversal*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Windows.ContactSupport*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *WindowsAlarms*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *WindowsFeedbackHub*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *WindowsMaps*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *WindowsPhone*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *WindowsSoundRecorder*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Wunderlist*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *XING*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *Xbox*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *XboxSpeechToTextOverlay*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *communi*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *connectivity*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *feedback*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *groove*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *king.com.*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *maps*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *microsoft.windowscommunicationsapps*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *office*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *phone*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *photos*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *photoshop*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *reality*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *solit*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *tiktok*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *windowscommunicationsapps*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers *zune*|Remove-AppxPackage"
Powershell -Command "Get-AppxPackage -allusers Microsoft.549981C3F5F1|Remove-AppxPackage"

:: ============================================
:: NETWORK-SAFE SERVICE CONFIGURATION
:: ============================================
echo Configuring services (preserving network functions)...

sc config DiagTrack start= disabled
sc config dmwappushservice start= disabled
sc config RetailDemo start= disabled
sc config FontCache start= demand
sc config SysMain start= disabled
sc config WSearch start= disabled
sc config TabletInputService start= demand
sc config TrkWks start= disabled
sc config CscService start= disabled
sc config WMPNetworkSvc start= disabled
sc config PcaSvc start= disabled
sc config WerSvc start= disabled
sc config BITS start= delayed-auto
sc config DoSvc start= delayed-auto
sc config UsoSvc start= delayed-auto
sc config DusmSvc start= disabled
sc config SENS start= auto

:: ============================================
:: SCHEDULED TASKS OPTIMIZATION
:: ============================================
echo Disabling unnecessary scheduled tasks...
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Report policies" /Disable
schtasks /Change /TN "Microsoft\Windows\WaaSMedic\PerformRemediation" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable


:: ============================================
:: DISABLE TELEMETRY & PRIVACY IMPROVEMENTS
:: ============================================
echo Disabling telemetry and improving privacy...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f

:: ============================================
:: PERFORMANCE OPTIMIZATION
:: ============================================
echo Applying CPU and memory optimizations...

:: Memory Management
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v NonPagedPoolQuota /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v NonPagedPoolSize /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v PagedPoolQuota /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f

:: System Responsiveness
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 10 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v IoPriority /t REG_DWORD /d 3 /f

:: Power Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v EnergyEstimationEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v EventProcessorEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v PlatformAoAcOverride /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f

:: Session Manager and Kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableTsx /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DistributeTimers /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v MaintenanceDisabled /t REG_DWORD /d 1 /f

:: ============================================
:: OPTIMIZE VISUAL EFFECTS & UI RESPONSIVENESS
:: ============================================
echo Optimizing visual effects and UI responsiveness...
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012078010000000 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v DisableIndependentFlip /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v DisallowAnimations /t REG_DWORD /d 1 /f

:: ============================================
:: DISABLE BACKGROUND APPS & AUTO UPDATES
:: ============================================
echo Disabling background apps and automatic updates...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f

:: ============================================
:: OPTIMIZE FILESYSTEM & DISK PERFORMANCE
:: ============================================
echo Optimizing filesystem performance...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsMemoryUsage /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v Win31FileSystem /t REG_DWORD /d 0 /f

:: ============================================
:: NETWORK OPTIMIZATION - SAFE FOR SHARING
:: ============================================
echo Applying network optimizations (safe for shared drives)...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 64 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SackOpts /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Tcp1323Opts /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUDiscovery /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUBHDetect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v GlobalMaxTcpWindowSize /t REG_DWORD /d 65535 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpWindowSize /t REG_DWORD /d 65535 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableTaskOffload /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableWsd /t REG_DWORD /d 0 /f

:: ============================================
:: CLEAN TEMPORARY FILES
:: ============================================
echo Cleaning temporary files...
del /s /f /q %TEMP%\*.*
del /s /f /q %SystemRoot%\Temp\*.*

:: ============================================
:: POWER PLAN SETTINGS
:: ============================================
echo Setting high performance power plan...
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -change -monitor-timeout-ac 10
powercfg -change -monitor-timeout-dc 5
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 15
powercfg -change -hibernate-timeout-ac 0
powercfg -change -hibernate-timeout-dc 0

echo.
echo *** System Optimization Complete ***
echo.
echo It's recommended to restart your computer for all changes to take effect.
:end
pause
exit
