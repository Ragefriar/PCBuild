# Set global variables
$hosts = "C:\Windows\System32\Drivers\etc\hosts"
$portableapps = "C:\OneDrive\Apps"
$roles_enable = @("NetFx3","WMISnmpProvider","NetFx4-AdvSrvs")
$startmenu = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\"
$temp = "C:\Temp"
$userstartmenu = "C:\Users\$($env:USERNAME)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"
$webclient = New-Object System.Net.WebClient

$choco_installs = @(
    "amazondrive",                      # Amazon Drive
    "amazon-music",                     # Amazon Music
    "ccleaner",                         # CCleaner
    "chocolatey-autoupdater",           # Autoupdate Chocolatey
    "choco-upgrade-all-at-startup",     # Update Chocolatey Apps at startup
    "clink",                            # Clink
    "deluge",                           # Deluge
    "dropbox",                          # Dropbox
    "ffmpeg",                           # FFMpeg
    "googlechrome",                     # Google Chrome
    "logitechgaming",                   # Logitech Mouse Software
    "mediainfo",                        # Mediainfo
    "nordvpn",                          # NordVPN
    "notepadplusplus",                  # Notepad++
    "office365proplus",                 # Office365 Pro Plus
    "openssh",                          # OpenSSH
    "powershell-core",                  # PowerShell Core
    "rsat",                             # Windows Remote Administration Tools
    "rufus"                             # Rufus
    "visualstudiocode",                 # Visual Studio Code
    "vmwareworkstation",                # VMware Workstation Pro
    "vmware-horizon-client",            # VMware Horizon Client
    "vnc-viewer",                       # RealVNC Viewer                  
    "winrar",                           # WinRAR
    "xnviewmp"                          # XnViewMP
)
$install = @(
    "start-build",                      # Start building!
    "enable-transcript",                # Start Transcript logging
    "activate-windows",                 # Active Windows
    "install-chocolatey",               # Install Chocolatey
    "ignore-certificate-errors",        # Ignore certificate errors from install downloads
    "create-firewall-rules",            # Create 'Allow All' firewall rules
    "get-files",                        # Get files needed for script
    "enable-power-profile",             # Apply custom power profile
    "create-hkcr",                      # Create HKCR for Powershell
    "set-wallpaper",                    # Taylor Swift!!
    "disable-crashdump",                # Disable RAM crash dump
    "enable-mouse-snapto",              # Enable mouse snap-to
    "enable-system-protection",         # Enable system protection on harddisks
    "create-hosts-entries",             # Create some hosts entries

    "install-windows-components",       # Install useful Windows componenets
    "install-malwarebytes",             # Install cracked Malwarebytes
    "install-nvidia-drivers",           # Install Nvidia drivers & apply display tweaks
    "install-chocolaty-apps",           # Cycle though and install Chocolatey apps
    "install-asus-aisuite",             # Install ASUS AI Suite 3
    "install-asus-gputweak",            # Install ASUS GPU Tweak II
    "install-printer-drivers",          # Install Canon printer drivers
    "install-discord",                  # Install Disord
    "install-epic-games-launcher",      # Install Epic Games Launcher
    "install-github",                   # Install GitHub
    "install-intel-overclocking",       # Install Intel Extreme Tuning Utility
    "install-jump-desktop",             # Install Jump Desktop
    "install-jump-desktop-connect",     # Install Jump Desktop Connect
    "install-microsoft-keyboard",       # Install Microsoft Keyboard drivers
    "install-origin",                   # Install Origin
    "install-polar-flow",               # Install Polar Flow
    "install-wargaming",                # Install Wargaming Gaming Center
    "install-1password",                # Install 1Password
    "install-razer-synapse",            # Install Razer Synapse
    "install-steam",                    # Install Steam
    "install-uplay",                    # Install Uplay
    "install-battle-net",               # Install Battle.net
    "install-corsair-link",             # Install Corsair LINK
    "install-driver-booster",           # Install Driver Booster
    "install-vmware-unlocker",          # Install VMware Unlocker

    "copy-files",                       # Copy some files to Application folders
    "create-shortcuts",                 # Create shortuts for portable apps
    "sort-start-menu",                  # Organize StartMenu
    "apply-tweaks",                     # Apply some custom tweaks
    "create-powershell-context-menu",   # Create PowerShell context menu
    "create-snippingtool-context-menu", # Create Snipping Tool context menu
    "run-tweaks-script",                # Run Win10_Tweaks.ps1 script
    "set-variables",                    # Set custom variables
    "clear-temp-folders",               # Clear all temp folders
    "finish"                            # Finish & prompt for reboot
)        

function start-build {
    Clear-Host
    Write-Host ""
    Write-Host "Building the most ultimate of PC's" -Foreground Red
    Write-Host ""
}

function enable-transcript {
# Start Transcript 
    Start-Transcript -Path "C:\Temp\transcript.txt" -NoClobber
}

function activate-windows {
# Activate Windows
    Write-Host "Activating Windows"
    & c:\windows\system32\slmgr.vbs /ipk J9N9Y-BK6RQ-C42Q9-6VHYC-V8RDB
    Start-Sleep 2
}

function install-chocolatey {
# Install Chocolatey
    Write-Host "Installing Chocolatey - You can safely ignore the yellow warnings below"
    Write-Host ""
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null 
}

function ignore-certificate-errors {
# Ignore Certificate Errors
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}

function create-firewall-rules {
# Create 'Allow All' Firewall Rules
    Write-Host ""
    Write-Host "Creating firewall rules to allow all inbound and outbound"
    New-NetFirewallRule -DisplayName "Allow ALL Outbound" -Direction Outbound -LocalPort Any -Protocol Any -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "Allow ALL Inbound" -Direction Inbound -LocalPort Any -Protocol Any -Action Allow | Out-Null
}

function get-files {
# Get some files needed for script
    Write-Host "Getting some files need for the script"
    $webclient.DownloadFile("http://script.ragefire.com/files/malwarebytes.zip","$temp\malwarebytes.zip") | Out-Null
    Expand-Archive "$temp\malwarebytes.zip" -DestinationPath "$temp\Malwarebytes"
    $webclient.DownloadFile("http://script.ragefire.com/files/unlocker.zip","$temp\unlocker.zip") | Out-Null
    Expand-Archive "$temp\unlocker.zip" -DestinationPath "$temp\Unlocker"
    $webclient.DownloadFile("http://script.ragefire.com/files/scriptfiles.zip","$temp\scriptfiles.zip") | Out-Null
    Expand-Archive "$temp\scriptfiles.zip" -DestinationPath "$temp\ScriptFiles"
    $webclient.DownloadFile("http://script.ragefire.com/Wallpaper.jpg","C:\Users\$($env:USERNAME)\Pictures\Wallpaper.jpg") | Out-Null
}

function enable-power-profile {
# Customise Power Profile
    Write-Host "Applying Custom Power Profile"
    powercfg.exe -import "$temp\ScriptFiles\Custom_Power_Profile.pow" 3cf2b193-450b-42a4-9900-76ccfad6cb7b | Out-Null 
    powercfg.exe -changename 3cf2b193-450b-42a4-9900-76ccfad6cb7b "Customized Performance" | Out-Null 
    powercfg.exe -setactive 3cf2b193-450b-42a4-9900-76ccfad6cb7b | Out-Null 
}

function create-hkcr {
# Create HKCR Powershell Link
    Write-Host "Creating HKCR for Powershell"
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null 
}

function set-wallpaper {
# Set Wallpaper
Write-Host "Setting Taylor Swift Wallpaper!!!"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "Wallpaper" -Value "C:\Users\$($env:USERNAME)\Pictures\Wallpaper.jpg" | Out-Null 
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "WallpaperStyle" -Value "10" | Out-Null 
    rundll32.exe user32.dll, UpdatePerUserSystemParameters | Out-Null 
}

function disable-crashdump {
# Disable Crash Dump
    Write-Host "Disabling Crash Dump"
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name "CrashDumpEnabled" -Value "0" | Out-Null 
}

function enable-mouse-snapto {
# Set Mouse Snap To
    Write-Host "Enable Mouse SnapTo"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Mouse' -Name "SnapToDefaultButton" -Value "1" | Out-Null 
}

function enable-system-protection {
# Enable System Protection on C: and D:
    Write-Host "Enabling System Protection on Harddrive(s)"
        If (Test-Path -Path "C:\"){
           Enable-ComputerRestore -Drive "C:\" | Out-Null
            vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=100GB | Out-Null
       }
       If (Test-Path -Path "D:\"){ 
           Enable-ComputerRestore -Drive "D:\" | Out-Null
           vssadmin.exe resize shadowstorage /for=D: /on=D: /maxsize=100GB | Out-Null 
       }
}

function create-hosts-entries {
# Create Hosts entries
    Write-Host "Creating some hosts entries"
       If ((Get-Content $hosts) -notcontains "127.0.0.1 keystone.mwbsys.com"){
          Add-Content -Encoding UTF8 $hosts "127.0.0.1 keystone.mwbsys.com" | Out-Null 
           Add-Content -Encoding UTF8 $hosts "127.0.0.1 license.piriform.com" | Out-Null 
       }
}

function install-windows-components {
# Install Windows Components
    Write-Host "Installing Windows Features"
       ForEach ($install in $roles_enable){
           Dism.exe /Online /Enable-Feature /FeatureName:$install /All /NoRestart | Out-Null 
       }
}

function install-malwarebytes {
# Install MalwareBytes
    Write-Host "Installing MalwareBytes"
    New-Item "C:\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Configuration" -itemtype directory | Out-Null 
    $webclient.DownloadFile("https://downloads.malwarebytes.com/file/mb3/","$temp\malwarebyteslatest.exe") | Out-Null 
    Start-Process "$temp\Malwarebytes\1.Setup (Install first).exe" -ArgumentList "/verysilent" -Wait
    Start-Sleep -s 5
    Copy-Item -Path "$temp\Malwarebytes\license.conf" -Destination "C:\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Configuration" | Out-Null 
    Copy-Item -Path "$temp\Malwarebytes\exclusions.dat" -Destination "C:\ProgramData\Malwarebytes\Malwarebytes Anti-Malware" | Out-Null 
    Start-Process "$temp\malwarebyteslatest.exe" -ArgumentList "/verysilent" -Wait
}

function install-nvidia-drivers {
# Install Latest nVidia Driver
    Write-Host "Installing Latest nVidia Drivers"
    choco.exe install Geforce-Game-Ready-Driver -y | Out-Null
    choco.exe install Disable-nVidia-Telemetry -y | Out-Null
    Write-Host "Downloading & Setting Nvidia RGB to Full"
    $webclient.DownloadFile("https://blog.metaclassofnil.com/wp-content/uploads/2012/08/NV_RGBFullRangeToggle.zip","$temp\NvidiaRGBLatest.zip") | Out-Null
    Expand-Archive "$temp\NvidiaRGBLatest.zip" -DestinationPath "$temp\NvidiaRGBLatest" -Force
    Start-Process "$temp\NvidiaRGBLatest\NV_RGBFullRangeToggle.exe" -Wait
}

function install-chocolaty-apps {
# Install Chocolatey Apps 
    Write-Host ""
    Write-Host "Installing Apps via Chocolatey" -Foreground yellow
        ForEach ($program in $choco_installs){ 
            Write-Host "Installing $program" 
            choco.exe install $program -y | Out-Null
            choco.exe install vlc --x86 -y | Out-Null
        }
}

function install-asus-aisuite {
# Install ASUS AI Suite 3"
    Write-Host ""
    Write-Host "Installing latest Apps via Download" -Foreground yellow
    Write-Host "Downloading & Installing ASUS AI Suite 3"
    $webclient.DownloadFile("https://dlcdnet.asus.com/pub/ASUS/mb/Utility/AI_Suite_III_3.00.13_DIP5_1.05.13.zip","$temp\AsusAILatest.zip") | Out-Null
    Expand-Archive "$temp\AsusAILatest.zip" -DestinationPath "$temp\AsusAILatest" -Force
    Start-Process "$temp\AsusAILatest\AsusSetup.exe" -ArgumentList "/s" -Wait
        If (Test-Path -Path "$userstartmenu\ASUS\AI Suite 3.lnk"){
            Move-Item -Path "$startmenu\ASUS\AI Suite 3\AI Suite 3.lnk" -Destination "$startmenu\ASUS AI Suite 3.lnk" -Force
        }
}

function install-asus-gputweak {
# Install ASUS GPUTweak II
    Write-Host "Downloading & Installing ASUS GPUTweak II"
    $webclient.DownloadFile("https://dlcdnet.asus.com/pub/ASUS/vga/vga/GPUTweak2_Ver1626_20180514.zip","$temp\AsusGPUTweakLatest.zip") | Out-Null
    Expand-Archive "$temp\AsusGPUTweakLatest.zip" -DestinationPath "$temp\AsusGPUTweakLatest" -Force
    Start-Process "$temp\AsusGPUTweakLatest\GPUTweak2*\Setup.exe" -ArgumentList "/s" -Wait
        If (Test-Path -Path "$userstartmenu\ASUS\ASUS GPU Tweak II.lnk"){
            Move-Item -Path "$startmenu\ASUS\ASUS GPU Tweak II.lnk" -Destination "$startmenu\ASUS GPU Tweak II.lnk" -Force
            Remove-Item -Path "$startmenu\ASUS" -Recurse -Force
        }
}

function install-printer-drivers {
# Install Canon Printer Drivers
Write-Host "Downloading & Installing Canon Printer Drivers"
$webclient.DownloadFile("https://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do?id=MDEwMDAwMjkxMzAz&amp;cmp=ACB&amp;lang=EN","$temp\CanonDriversLatest.zip") | Out-Null
Expand-Archive "$temp\CanonDriversLatest.zip" -DestinationPath "$temp\CanonDriversLatest" -Force
Start-Process "$temp\CanonDriversLatest\mp68*\DrvSetup\setup.exe" -ArgumentList "/quiet" -Wait
    If (Test-Path -Path "$startmenu\Canon MG5200 series"){
        Remove-Item -Path "$startmenu\Canon MG5200 series" -Recurse -Force
    }
}

function install-discord {
# Install Discord
    Write-Host "Downloading & Installing Discord"
    $webclient.DownloadFile("https://discordapp.com/api/download?platform=win","$temp\DiscordLatest.exe") | Out-Null 
    Start-Process "$temp\DiscordLatest.exe" -ArgumentList "/s" -Wait
       If (Test-Path -Path "$userstartmenu\Discord Inc"){
            Move-Item -Path "$userstartmenu\Discord Inc\Discord.lnk" -Destination "$startmenu\Discord.lnk" -Force
            Remove-Item -Path "$userstartmenu\Discord Inc" -Recurse -Force
        }
}

function install-epic-games-launcher {
# Install Epic Games Launcher
    Write-Host "Downloading & Installing Epic Games Launcher"
    $webclient.DownloadFile("https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi","$temp\EpicLatest.msi") | Out-Null 
    Start-Process "$temp\EpicLatest.msi" -ArgumentList "/quiet" -Wait
       If (Test-Path -Path "$startmenu\Epic Games Launcher"){
            Move-Item -Path "$startmenu\Epic Games Launcher.lnk" -Destination "$startmenu\Games\Epic Games Launcher.lnk" -Force
        }
}

function install-github {
# Install GitHub
    Write-Host "Downloading & Installing GitHub"
    $webclient.DownloadFile("https://central.github.com/deployments/desktop/desktop/latest/win32?format=msi","$temp\GitHubLatest.msi") | Out-Null
    Start-Process "$temp\GitHubLatest.msi" -ArgumentList "/quiet" -Wait
}

function install-intel-overclocking {
# Install Intel Extreme Tuning Utility
    Write-Host "Downloading & Installing Intel Extreme Tuning Utility"
    $webclient.DownloadFile("https://downloadmirror.intel.com/24075/eng/XTUSetup.exe","$temp\IntelOverclockingLatest.exe") | Out-Null 
    Start-Process "$temp\IntelOverclockingLatest.exe" -ArgumentList "/quiet /norestart" -Wait
        If (Test-Path -Path "$startmenu\Intel"){
            Move-Item -Path "$startmenu\Intel\Intel(R) Extreme Tuning Utility.lnk" -Destination "$startmenu\Intel Extreme Tuning.lnk" -Force
            Remove-Item -Path "$startmenu\Intel" -Recurse -Force
       }
}

function install-jump-desktop {
# Install Jump Desktop
    Write-Host "Downloading & Installing Jump Desktop"
    $webclient.DownloadFile("https://jumpdesktop.com/downloads/jdwin","$temp\JumpDesktopLatest.exe") | Out-Null
    Start-Process "$temp\JumpDesktopLatest.exe" -Wait
}

function install-jump-desktop-connect {
# Install Jump Desktop Connect
    Write-Host "Downloading & Installing Jump Desktop Connect"
    $webclient.DownloadFile("https://jumpdesktop.com/downloads/connect/win","$temp\JumpDesktopConnectLatest.exe") | Out-Null
    Start-Process "$temp\JumpDesktopConnectLatest" -ArgumentList "/quiet" -Wait
}

function install-microsoft-keyboard {
# Install Microsoft Keyboard Center
    Write-Host "Downloading & Installing Microsoft Keyboard Center"
    $webclient.DownloadFile("https://go.microsoft.com/fwlink/?linkid=849754","$temp\MSKeybCenterLatest.exe") | Out-Null 
    Start-Process "$temp\MSKeybCenterLatest.exe" -ArgumentList "/silentinstall" -Wait
}

function install-origin {
# Install Origin
    Write-Host "Downloading & Installing Origin"
    $webclient.DownloadFile("https://www.dm.origin.com/download","$temp\OriginLatest.exe") | Out-Null 
    Start-Process "$temp\OriginLatest.exe" -ArgumentList "/silent /noeula" -Wait
        If (Test-Path -Path "$startmenu\Origin"){
            Move-Item -Path "$startmenu\Origin\Origin.lnk" -Destination "$startmenu\Games\Origin.lnk" -Force
            Remove-Item -Path "$startmenu\Origin" -Recurse -Force
        }
}

function install-polar-flow {
# Install Polar FlowSync
    Write-Host "Downloading & Installing Polar FlowSync"
    $webclient.DownloadFile("https://dngo5v6w7xama.cloudfront.net/connect/download/FlowSync_2.6.2.exe","$temp\PolarFlowLatest.exe") | Out-Null
    Start-Process "$temp\PolarFlowLatest.exe" -ArgumentList "/verysilent" -Wait
        If (Test-Path -Path "$startmenu\Polar"){
            Move-Item -Path "$startmenu\Polar\Polar FlowSync\Polar FlowSync.lnk" -Destination "$startmenu\Polar FlowSync.lnk" -Force
            Remove-Item -Path "$startmenu\Polar" -Recurse -Force
        }
}

function install-wargaming {
# Install Wargaming Game Center
    Write-Host "Downloading & Installing Wargaming Game Center"
    $webclient.DownloadFile("https://redirect.wargaming.net/WGC/Wargaming_Game_Center_Install_WoWS_EU.exe","$temp\WargamingLatest.exe") | Out-Null 
    Start-Process "$temp\WargamingLatest.exe" -ArgumentList "/s" -Wait
       If (Test-Path -Path "$startmenu\Wargaming.net"){
            Move-Item -Path "$startmenu\Wargaming.net\Wargaming.net Game Center.lnk" -Destination "$startmenu\Games\Wargaming.net Game Center.lnk" -Force
            Remove-Item -Path "$startmenu\Wargaming.net" -Recurse -Force
       }
}

function install-1password {
# Install 1Password
Write-Host "Downloading & Installing 1Password"
$webclient.DownloadFile("https://app-updates.agilebits.com/download/OPW4","$temp\1PasswordLatest.exe") | Out-Null 
Start-Process "$temp\1PasswordLatest.exe" -ArgumentList "/verysilent" -Wait
    If (Test-Path -Path "$startmenu\1Password"){
        Move-Item -Path "$startmenu\1Password\1Password 4.lnk" -Destination "$startmenu\1Password.lnk" -Force
        Remove-Item -Path "$startmenu\1Password" -Recurse -Force
    }
}

function install-razer-synapse {
# Install Razer Synapse
    Write-Host "Downloading & Installing Razer Synapse" -ForegroundColor Gray -NoNewline; Write-Host " - Untick 'Run' at the end of install" -ForegroundColor Red
    $webclient.DownloadFile("http://rzr.to/synapse-pc-download","$temp\RazerSynapse2Latest.exe") | Out-Null 
    Start-Process "$temp\RazerSynapse2Latest.exe" -Wait
        If (Test-Path -Path "$startmenu\Razer"){
            Move-Item -Path "$startmenu\Razer\Razer Synapse\Razer Synapse.lnk" -Destination "$startmenu\Razer Synapse.lnk" -Force
            Remove-Item -Path "$startmenu\Razer" -Recurse -Force
        }
}

function install-steam {
# Install Steam
Write-Host "Downloading & Installing Steam" -ForegroundColor Gray -NoNewline; Write-Host " - Untick 'Run' at the end of install" -ForegroundColor Red
    $webclient.DownloadFile("https://steamcdn-a.akamaihd.net/client/installer/SteamSetup.exe","$temp\SteamLatest.exe") | Out-Null 
    Start-Process "$temp\SteamLatest.exe" -Wait
        If (Test-Path -Path "$startmenu\Steam"){
            Move-Item -Path "$startmenu\Steam\Steam.lnk" -Destination "$startmenu\Games\Steam.lnk" -Force
            Remove-Item -Path "$startmenu\Steam" -Recurse -Force
        }
}

function install-uplay {
# Install Uplay
    Write-Host "Downloading & Installing UPlay" -ForegroundColor Gray -NoNewline; Write-Host " - Untick 'Run' at the end of install" -ForegroundColor Red
    $webclient.DownloadFile("http://ubi.li/4vxt9","$temp\UPlayLatest.exe") | Out-Null 
    Start-Process "$temp\UPlayLatest.exe" -Wait
        If (Test-Path -Path "$userstartmenu\Ubisoft"){
            Move-Item -Path "$userstartmenu\Ubisoft\Uplay\Uplay.lnk" -Destination "$startmenu\Games\Uplay.lnk" -Force
            Remove-Item -Path "$userstartmenu\Ubisoft" -Recurse -Force
        }
}

function install-battle-net {
# Install Battle.net
    Write-Host "Downloading & Installing Battle.net" -ForegroundColor Gray -NoNewline; Write-Host " - Manually close to continue (check taskbar icons!)" -Foreground red
    $webclient.DownloadFile("https://www.battle.net/download/getInstallerForGame?os=win&locale=enUS&version=LIVE&gameProgram=BATTLENET_APP&id=736892510.1521039208","$temp\BattleNetLatest.exe") | Out-Null 
    Start-Process "$temp\BattleNetLatest.exe" -ArgumentList "/s" -Wait
       If (Test-Path -Path "$startmenu\Battle.net"){
           Move-Item -Path "$startmenu\Battle.net\Battle.net.lnk" -Destination "$startmenu\Games\Battle.net.lnk" -Force
            Remove-Item -Path "$startmenu\Battle.net" -Recurse -Force
       }
}

function install-corsair-link {
#Install Corsair Link
    Write-Host "Downloading & Installing Corsair Link" -ForegroundColor Gray -NoNewline; Write-Host " - Manually close to continue (check taskbar icons!)" -Foreground red
    $webclient.DownloadFile("https://downloads.corsair.com/download?item=Files/Corsair-Link/Corsair-LINK-Installer-v4.9.7.35.zip","$temp\CorsairLinkLatest.zip") | Out-Null
    Expand-Archive "$temp\CorsairLinkLatest.zip" -DestinationPath "$temp\CorsairLinkLatest" -Force
    Start-Process "$temp\CorsairLinkLatest\Corsair*.exe" -ArgumentList "/s" -Wait
       If (Test-Path -Path "$startmenu\Corsair LINK 4"){
           Move-Item -Path "$startmenu\Corsair LINK 4\Corsair LINK 4.lnk" -Destination "$startmenu\Corsair LINK 4.lnk" -Force
            Remove-Item -Path "$startmenu\Corsair LINK 4" -Recurse -Force
        }
}

function install-driver-booster {
# Install Driver Booster
    Write-Host "Downloading & Installing Driver Booster" -ForegroundColor Gray -NoNewline; Write-Host " - Manually close to continue (check taskbar icons!)" -Foreground red
    $webclient.DownloadFile("https://www.iobit.com/downloadcenter.php?product=db-dl","$temp\DriverBoosterLatest.exe") | Out-Null 
    Start-Process "$temp\DriverBoosterLatest.exe" -ArgumentList "/silent" -Wait
       If (Test-Path -Path "$startmenu\Driver Booster 5"){
           Move-Item -Path "$startmenu\Driver Booster 5\Driver Booster 5.lnk" -Destination "$startmenu\Driver Booster.lnk" -Force
            Remove-Item -Path "$startmenu\Driver Booster 5" -Recurse -Force
        }
}
function install-vmware-unlocker {
# Install VMware Unlocker
    Write-Host "Installing VMware Unlocker"
    Start-Process "$temp\Unlocker\\unlocker211\win-install.cmd"
}


function New-Shortcut($TargetPath, $ShortcutPath) {
# Function to create Shortcuts    
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $TargetPath
    $Shortcut.Save()
}

function copy-files {
# Copy some files
    Write-Host ""
    Write-Host "Copying some files about"
    Copy-Item "$temp\ScriptFiles\CCleaner Professional Key.txt" -Destination "C:\Program Files\CCleaner" -force | Out-Null
    Copy-Item "$temp\ScriptFiles\Driver Booster Pro v5.0 Serial.txt" -Destination "C:\Program Files (x86)\IObit\Driver Booster" -force | Out-Null
    Copy-Item "$temp\ScriptFiles\rarreg.key" -Destination "C:\Program Files\WinRAR" -force | Out-Null
    Copy-Item "$temp\ScriptFiles\VLC MinimalX Skin.vlt" -Destination "C:\Program Files (x86)\VideoLAN\VLC\skins" -force | Out-Null 
    New-Item -Path "C:\Users\$($env:USERNAME)\AppData\Roaming\vlc" -ItemType Directory | Out-Null
    Copy-Item "$temp\ScriptFiles\vlcrc" -Destination "C:\Users\$($env:USERNAME)\AppData\Roaming\vlc" -force | Out-Null
    Copy-Item "$temp\ScriptFiles\WinRAR.exe" -Destination "C:\Program Files\WinRAR" -force | Out-Null
    Copy-Item "$temp\ScriptFiles\VMware Workstation 14 Key.txt" -Destination "C:\Program Files (x86)\VMware\VMware Workstation" -force | Out-Null
}

function create-shortcuts {
# Create some shortcuts
    Write-Host "Creating some shortcuts"
    New-Shortcut "C:\ProgramData\chocolatey\lib\rufus\tools\Rufus.exe" "$startmenu\Rufus.lnk" | Out-Null
    New-Shortcut "$portableapps\FileZilla\Filezilla.exe" "$startmenu\FileZilla.lnk" | Out-Null 
    New-Shortcut "$portableapps\FlashFXP\FlashFXP.exe" "$startmenu\FlashFXP.lnk" | Out-Null 
    New-Shortcut "$portableapps\KiTTY\kitty_portable.exe" "$startmenu\KiTTY.lnk" | Out-Null 
    New-Shortcut "$portableapps\MultiCommander\MultiCommander.exe" "$startmenu\MultiCommander.lnk" | Out-Null 
    New-Shortcut "$portableapps\Q-Dir\Q-Dir.exe" "$startmenu\Q-Dir.lnk" | Out-Null
    New-Shortcut "$portableapps\WinSCP\WinSCP.exe" "$startmenu\WinSCP.lnk" | Out-Null
    New-Shortcut "$startmenu" "C:\Users\Start Menu (All Users).lnk" | Out-Null
    New-Shortcut "$userstartmenu" "C:\Users\Start Menu ($($env:USERNAME)).lnk" | Out-Null 
}

function sort-start-menu {
# Organize Start Menu
    Write-Host "Organizing Start Menu"
    New-Item -Path "$startmenu\Games" -ItemType Directory | Out-Null
        If (Test-Path -Path "$userstartmenu\Amazon Music"){
            Move-Item -Path "$userstartmenu\Amazon Music\Amazon Music.lnk" -Destination "$startmenu\Amazon Music.lnk" -Force
            Remove-Item -Path "$userstartmenu\Amazon Music" -Recurse -Force
        }
        If (Test-Path -Path "$userstartmenu\Maintenance"){
            Remove-Item -Path "$userstartmenu\Maintenance" -Recurse -Force
        }
        If (Test-Path -Path "$userstartmenu\Amazon Drive.lnk"){
            Move-Item -Path "$userstartmenu\Amazon Drive.lnk" -Destination "$startmenu\Amazon Drive.lnk" -Force
        }
        If (Test-Path -Path "$userstartmenu\Mediainfo.lnk"){
            Move-Item -Path "$userstartmenu\Mediainfo.lnk" -Destination "$startmenu\Mediainfo.lnk" -Force
        }
        If (Test-Path -Path "$userstartmenu\WinRAR"){
            Remove-Item -Path "$userstartmenu\WinRAR" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\CCleaner"){
            Move-Item -Path "$startmenu\CCleaner\CCleaner.lnk" -Destination "$startmenu\CCleaner.lnk" -Force
            Remove-Item -Path "$startmenu\CCleaner" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\clink\0.4.8"){
            Move-Item -Path "$startmenu\clink\0.4.8\Clink v0.4.8.lnk" -Destination "$startmenu\Clink.lnk" -Force
            Remove-Item -Path "$startmenu\clink" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\clink\0.4.9"){
            Move-Item -Path "$startmenu\clink\0.4.9\Clink v0.4.9.lnk" -Destination "$startmenu\Clink.lnk" -Force
            Remove-Item -Path "$startmenu\clink" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Deluge"){
            Move-Item -Path "$startmenu\Deluge\Deluge.lnk" -Destination "$startmenu\Deluge.lnk" -Force
            Remove-Item -Path "$startmenu\Deluge" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Logitech"){
            Move-Item -Path "$startmenu\Logitech\Logitech Gaming*.lnk" -Destination "$startmenu\Logitech Gaming.lnk" -Force
            Remove-Item -Path "$startmenu\Logitech" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Maintenance"){
            Remove-Item -Path "$startmenu\Maintenance" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Malwarebytes"){
            Move-Item -Path "$startmenu\Malwarebytes\Malwarebytes.lnk" -Destination "$startmenu\Malwarebytes.lnk" -Force
            Remove-Item -Path "$startmenu\Malwarebytes" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Microsoft Office 2016 Tools"){
           Remove-Item -Path "$startmenu\Microsoft Office 2016 Tools" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\NordVPN"){
           Move-Item -Path "$startmenu\NordVPN\NordVPN.lnk" -Destination "$startmenu\NordVPN.lnk" -Force
            Remove-Item -Path "$startmenu\NordVPN" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Notepad++"){
            Move-Item -Path "$startmenu\Notepad++\Notepad++.lnk" -Destination "$startmenu\Notepad++.lnk" -Force
            Remove-Item -Path "$startmenu\Notepad++" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\PowerShell"){
           Move-Item -Path "$startmenu\PowerShell\PowerShell 6.0.2.lnk" -Destination "$startmenu\PowerShell Core.lnk" -Force
            Remove-Item -Path "$startmenu\PowerShell" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\VideoLAN"){
            Move-Item -Path "$startmenu\VideoLAN\VLC media player skinned.lnk" -Destination "$startmenu\VLC.lnk" -Force
            Remove-Item -Path "$startmenu\VideoLAN" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Visual Studio Code"){
            Move-Item -Path "$startmenu\Visual Studio Code\Visual Studio Code.lnk" -Destination "$startmenu\Visual Studio Code.lnk" -Force
            Remove-Item -Path "$startmenu\Visual Studio Code" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\VMware"){
            Move-Item -Path "$startmenu\VMware\Virtual Network Editor.lnk" -Destination "$startmenu\VMware Virtual Network Editor.lnk" -Force
            Move-Item -Path "$startmenu\VMware\VMware Workstation 14 Player.lnk" -Destination "$startmenu\VMware Workstation Player.lnk" -Force
            Move-Item -Path "$startmenu\VMware\VMware Workstation Pro.lnk" -Destination "$startmenu\VMware Workstation Pro.lnk" -Force
            Remove-Item -Path "$startmenu\VMware" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\WinRAR"){
            Remove-Item -Path "$startmenu\WinRAR" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\XnViewMP"){
            Move-Item -Path "$startmenu\XnViewMP\XnViewMP.lnk" -Destination "$startmenu\XnViewMP.lnk" -Force
            Remove-Item -Path "$startmenu\XnViewMP" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Onedrive for Business"){
           Remove-Item -Path "$startmenu\Onedrive for Business.lnk" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Skype for Business 2016"){
           Remove-Item -Path "$startmenu\Skype for Business 2016.lnk" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\NVIDIA Corporation"){
            Remove-Item -Path "$startmenu\NVIDIA Corporation" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Administrative Tools"){
            Move-Item -Path "$startmenu\Administrative Tools\*" -Destination "$userstartmenu\Administrative Tools" -Force
            Remove-Item -Path "$startmenu\Administrative Tools" -Recurse -Force
        }
        If (Test-Path -Path "$userstartmenu\Accessibility"){
            Move-Item -Path "$userstartmenu\Accessibility\*" -Destination "$startmenu\Accessories" -Force
            Remove-Item -Path "$userstartmenu\Accessibility" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Accessibility"){
            Move-Item -Path "$startmenu\Accessibility\*" -Destination "$startmenu\Accessories" -Force
            Remove-Item -Path "$startmenu\Accessibility" -Recurse -Force
        }
        If (Test-Path -Path "$userstartmenu\Accessories"){
           Move-Item -Path "$userstartmenu\Accessories\*" -Destination "$startmenu\Accessories" -Force
           Remove-Item -Path "$userstartmenu\Accessories" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Accessories"){
            Move-Item -Path "$startmenu\Accessories\System Tools\*" -Destination "$startmenu\Accessories" -Force
            Remove-Item -Path "$startmenu\Accessories\System Tools" -Recurse -Force
        }
        If (Test-Path -Path "$userstartmenu\System Tools"){
            Move-Item -Path "$userstartmenu\System Tools\*" -Destination "$startmenu\Accessories" -Force
            Remove-Item -Path "$userstartmenu\System Tools" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\System Tools"){
           Move-Item -Path "$startmenu\System Tools\*" -Destination "$startmenu\Accessories" -Force
            Remove-Item -Path "$startmenu\System Tools" -Recurse -Force
        }
        If (Test-Path -Path "$userstartmenu\Windows PowerShell"){
            Move-Item -Path "$userstartmenu\Windows PowerShell\*" -Destination "$startmenu\Accessories" -Force
            Remove-Item -Path "$userstartmenu\Windows PowerShell" -Recurse -Force
        }
        If (Test-Path -Path "$startmenu\Windows PowerShell"){
           Move-Item -Path "$startmenu\Windows PowerShell\*" -Destination "$startmenu\Accessories" -Force
           Remove-Item -Path "$startmenu\Windows PowerShell" -Recurse -Force
        }
    Remove-Item -Path "C:\Users\$($env:USERNAME)\Desktop\*.*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\Public\Desktop\*.*" -Recurse -Force -ErrorAction SilentlyContinue
}

function apply-tweaks {
# Apply some tweaks
    Write-Host "Applying some tweaks"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" | Out-Null 
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Value "100" | Out-Null 
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Value "0" | Out-Null 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value "17740032" | Out-Null 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Value "00,00,00,00" -Type "binary" | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value "1" | Out-Null 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value "0" | Out-Null 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "ConfirmationCheckBoxDoForAll" -Value "1" -Type "DWord" | Out-Null 
}

function create-powershell-context-menu {
# Create Admin PowerShell context menu
    Write-Host "Creating PowerShell context menu"
    Copy-Item -Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\adminshell.exe" -Force | Out-Null 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" -Name "C:\Windows\System32\WindowsPowerShell\v1.0\adminshell.exe" -Value "~ RUNASADMIN" | Out-Null 
    New-Item -Path "HKCR:\Directory\Background\shell" -Name "PowerShell+" -Force | Out-Null 
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\PowerShell+" -Name "(Default)" -Value "PowerShell+" | Out-Null 
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\PowerShell+" -Name "Icon" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\adminshell.exe" | Out-Null 
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\PowerShell+" -Name "HasLUAShield" -Value "" | Out-Null 
    New-Item -Path "HKCR:\Directory\Background\shell\PowerShell+" -Name "command" -Force | Out-Null 
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\PowerShell+\command" -Name "(Default)" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\adminshell.exe -noexit -command Set-Location -literalPath '%V'" | Out-Null 
}

function create-snippingtool-context-menu {
# Create Snipping Tool context menu
    Write-Host "Creating Snipping Tool context menu"
    New-Item -Path "HKCR:\Directory\Background\shell" -Name "SnippingTool" -Force | Out-Null
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\SnippingTool" -Name "(Default)" -Value "&Snipping Tool" | Out-Null 
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\SnippingTool" -Name "Icon" -Value "SnippingTool.exe"
    New-Item -Path "HKCR:\Directory\Background\shell\SnippingTool" -Name "command" -Force | Out-Null
    Set-ItemProperty -Path "HKCR:\Directory\Background\shell\SnippingTool\command" -Name "(Default)" -Value "SnippingTool.exe" | Out-Null
}

function run-tweaks-script {
# Call Tweaks Script
    Write-Host ""
    Write-Host "Running Tweak Script" -Foreground Yellow
    & "C:\Temp\Win10_Tweaks.ps1"
}

function set-variables {
# Change some variables
    Write-Host "Setting Environment Variables"
    [Environment]::SetEnvironmentVariable("OneDrive", "C:\OneDrive", "User") | Out-Null 
    Remove-ItemProperty -Path 'HKCU:\Environment' -Name "TEMP" | Out-Null 
    Remove-ItemProperty -Path 'HKCU:\Environment' -Name "TMP" | Out-Null 
}

function clear-temp-folders {
# Clear Temp folders
    Write-Host "Cleaning Temp Folders"
    Remove-Item -Path "C:\Windows\Temp\*.*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Temp\*.*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\$($env:USERNAME)\appdata\Local\Temp\*.*" -Recurse -Force -ErrorAction SilentlyContinue
}

function finish {
# Prompt to reboot
    Write-Host ""
    Write-Host "Once all on screen prompts are complete, 'Y' to reboot PC" -ForegroundColor DarkRed -BackgroundColor Yellow
    Stop-Transcript
    Restart-Computer -Confirm
}
# Run the damn stuff!!
$install | ForEach { Invoke-Expression $_ }