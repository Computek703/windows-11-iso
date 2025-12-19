##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (v3.2)
# - Visible Chocolatey installs (Chrome + Adobe)
# - Retry logic for each package (3 attempts)
# - Runs in separate visible PowerShell window (non-blocking)
# - Background watcher checks for:
#       * Windows Updates completion
#       * Chocolatey install window closing
# - Shows final banner when ALL tasks 100% done
# - Plays ding sound + toast notification on completion
##########################################################################################################################################################

function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'

$asciiArt = @"
  #####                                    #######               
 #     #  ####  #    # #####  #    #          #    ###### #    # 
 #       #    # ##  ## #    # #    #          #    #      #   #  
 #       #    # # ## # #    # #    # #####    #    #####  ####   
 #       #    # #    # #####  #    #          #    #      #  #   
 #     # #    # #    # #      #    #          #    #      #   #  
  #####   ####  #    # #       ####           #    ###### #    # 
"@
Write-Host $asciiArt -ForegroundColor Black
Write-Host "Welcome to the Compu-TEK Setup Tool!"
Write-Host "v3.2 (Visible Installs + Watcher + Toast + Ding)"
Write-Host ""

# -----------------------------
# Utility: Remove desktop shortcut
# -----------------------------
function Remove-DesktopShortcut {
    param ([string]$ShortcutName)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $path = Join-Path $desktop "$ShortcutName.lnk"
    if (Test-Path $path) {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
        Write-Host "Cleanup: Removed desktop shortcut '$ShortcutName'."
    }
}

# -----------------------------
# Install Syncro Agent
# -----------------------------
# Function: Install Syncro Agent
function Install-SyncroAgent {
    Write-Host "Installing Syncro Agent..."
    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $Url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $SavePath = "C:\Windows\Temp\SyncroSetup.exe"
        $FileArguments = "--console --customerid 1362064 --folderid 4238852"
        Invoke-WebRequest -Uri $Url -OutFile $SavePath
        Start-Process -FilePath $SavePath -ArgumentList $FileArguments -Wait
        Write-Host "Syncro Agent installed successfully."
    } else {
        Write-Host "Syncro Agent is already installed."
    }
}

# -----------------------------
# Ensure Chocolatey Installed
# -----------------------------
function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Host "Chocolatey not found. Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Host "Chocolatey installed."
        } catch {
            Write-Host "WARNING: Chocolatey install failed. Continuing..."
            return $false
        }
    } else {
        Write-Host "Chocolatey already installed."
    }
    return $true
}

# -----------------------------
# Detect Dell
# -----------------------------
function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    } catch {
        return $false
    }
}

# -----------------------------
# Install Dell Command | Update
# -----------------------------
function Install-DellCommandUpdate {
    Write-Host "Dell detected. Installing Dell Command | Update..."
    try {
        if (Ensure-Chocolatey) {
            Start-Process "choco" -ArgumentList "install dellcommandupdate -y --no-progress" -NoNewWindow -Wait
            Write-Host "Dell Command | Update installed."
        }
    } catch {
        Write-Host "WARNING: Dell Command Update failed."
    }
}

# -----------------------------
# Software installs via external visible window (Non-blocking)
# -----------------------------
function Install-SoftwarePackages {
    Write-Host "Launching visible Chocolatey install window (Chrome + Adobe)..."

    if (-not (Ensure-Chocolatey)) {
        Write-Host "Skipping software installs (Chocolatey missing)."
        return
    }

$installScript = @'
Write-Host "========================================="
Write-Host "   Compu-TEK Software Installer Window"
Write-Host "   Chrome + Adobe Reader (with retry)"
Write-Host "=========================================`n"

# -----------------------
# Verification Functions
# -----------------------

function Verify-Chrome {
    return (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe")
}

function Verify-Adobe {
    return (Test-Path "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe")
}

# -----------------------
# Retry Wrapper
# -----------------------

function Install-WithRetry {
    param(
        [string]$Pkg,
        [string]$DisplayName,
        [scriptblock]$VerifyFunction
    )

    $maxAttempts = 3
    $attempt = 1

    while ($attempt -le $maxAttempts) {
        Write-Host "`nInstalling $DisplayName (Attempt $attempt of $maxAttempts)..."

        # Install the package
        Start-Process "choco" -ArgumentList "install $Pkg -y --force" -NoNewWindow -Wait

        # Treat "already installed" as success
        if (& $VerifyFunction) {
            Write-Host "`nSUCCESS: $DisplayName installed.`n"
            return $true
        }

        Write-Host "FAILED: $DisplayName verification failed."
        $attempt++
        Start-Sleep -Seconds 2
    }

    Write-Host "`nERROR: $DisplayName failed after $maxAttempts attempts.`n"
    return $false
}

# -----------------------
# Install Chrome
# -----------------------
$chromeOK = Install-WithRetry `
    -Pkg "googlechrome" `
    -DisplayName "Google Chrome" `
    -VerifyFunction { Verify-Chrome }

# -----------------------
# Install Adobe Reader
# -----------------------
$adobeOK = Install-WithRetry `
    -Pkg "adobereader" `
    -DisplayName "Adobe Reader" `
    -VerifyFunction { Verify-Adobe }

# -----------------------
# Final Banner
# -----------------------

if ($chromeOK -and $adobeOK) {
    Write-Host "`n========================================="
    Write-Host "   ALL SOFTWARE INSTALLED SUCCESSFULLY!"
    Write-Host "=========================================`n"
} else {
    Write-Host "`n========================================="
    Write-Host "      SOME INSTALLS FAILED"
    Write-Host "=========================================`n"
}

Write-Host "This window may now be closed."
'@

    $tempScript = "$env:TEMP\CT_Chocolatey_Install.ps1"
    $installScript | Out-File -FilePath $tempScript -Encoding UTF8 -Force

    Start-Process "powershell.exe" -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempScript`""

    Write-Host "Chocolatey installs running in visible window."
}

# -----------------------------
# Hostname
# -----------------------------
function Set-Hostname {
    Write-Host "Configuring hostname..."
    try {
        $brand  = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
        $serial = (Get-CimInstance Win32_BIOS).SerialNumber
        $newName = "$brand-$serial"

        if ($env:COMPUTERNAME -ne $newName) {
            Rename-Computer -NewName $newName -Force
            Write-Host "Hostname set to: $newName"
        } else {
            Write-Host "Hostname already correct."
        }
    } catch {
        Write-Host "WARNING: Hostname change failed."
    }
}

# -----------------------------
# Windows Updates UI
# -----------------------------
function Install-WindowsUpdates-Async {
    Write-Host "Opening Windows Update interface..."
    try {
        Start-Process "ms-settings:windowsupdate"
        Start-Sleep 2
        Start-Process "control.exe" -ArgumentList "/name Microsoft.WindowsUpdate"
        Write-Host "Windows Update UI opened."
    } catch {
        Write-Host "WARNING: Windows Update UI failed."
    }
}

# -----------------------------
# Secure Boot check
# -----------------------------
function Check-SecureBootStatus {
    try {
        $state = Confirm-SecureBootUEFI
        if ($state) { Write-Host "Secure Boot: ENABLED" }
        else { Write-Host "Secure Boot: DISABLED" }
    } catch {
        Write-Host "Secure Boot: Not supported or not UEFI."
    }
}

# -----------------------------
# Quick Machine Recovery
# -----------------------------
function Enable-QuickMachineRecovery {
    Write-Host "Applying Quick Machine Recovery registry keys..."
    try {
        $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }

        Set-ItemProperty -Path $reg -Name "QuickRecoveryEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $reg -Name "ContinueSearchingEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $reg -Name "LookForSolutionEvery" -Value 0 -Type DWord
        Set-ItemProperty -Path $reg -Name "RestartEvery" -Value 0 -Type DWord

        Write-Host "QMR keys applied."
    } catch {
        Write-Host "WARNING: QMR registry update failed."
    }
}

# -----------------------------
# Completion Watcher (Ding + Toast)
# -----------------------------
function Start-CompletionWatcher {

    Write-Host "Starting background completion watcher..."

    Start-Job -ScriptBlock {

        function Updates-Done {
            try {
                $sessions = Get-CimInstance -Namespace root\cimv2\updates -ClassName MSFT_WUOperations -ErrorAction SilentlyContinue
                if (-not $sessions) { return $true }
                if ($sessions.ActiveOperation -eq 0) { return $true }
                return $false
            } catch { return $false }
        }

        function ChocoWindow-Closed {
            $p = Get-Process -Name "powershell" -ErrorAction SilentlyContinue |
                 Where-Object { $_.MainWindowTitle -like "*CT_Chocolatey_Install.ps1*" }
            return (-not $p)
        }

        $updatesDone = $false
        $chocoDone   = $false

        while ($true) {
            Start-Sleep -Seconds 10

            if (-not $updatesDone) { $updatesDone = Updates-Done }
            if (-not $chocoDone)   { $chocoDone   = ChocoWindow-Closed }

            if ($updatesDone -and $chocoDone) {

                # Ding sound
                [console]::beep(1200,500)

                # Toast Notification
                $t = @{
                    AppId      = "CompuTEK Setup"
                    Title      = "Setup Fully Complete"
                    Text       = "Windows Updates + Software Installs Finished"
                }
                try {
                    $null = New-BurntToastNotification @t
                } catch {}

                # Final banner
                cls
                Write-Host ""
                Write-Host "###############################################" -ForegroundColor Green
                Write-Host "#     COMPU-TEK SETUP FULLY COMPLETE          #" -ForegroundColor Green
                Write-Host "#  Windows Updates + Software installs done   #" -ForegroundColor Green
                Write-Host "###############################################" -ForegroundColor Green
                Write-Host ""
                break
            }
        }
    } | Out-Null
}

# -----------------------------
# OPTION 1: Smart First-Time Setup
# -----------------------------
function Run-SmartFirstTimeSetup {
    Write-Host ""
    Write-Host "===== Smart Auto Setup START ====="

    Install-WindowsUpdates-Async
    Install-SyncroAgent

    if (Is-DellSystem) { Install-DellCommandUpdate }
    else { Write-Host "Non-Dell system detected. Skipping Dell driver update." }

    Install-SoftwarePackages
    Set-Hostname
    Enable-QuickMachineRecovery
    Check-SecureBootStatus

    Start-CompletionWatcher

    Write-Host "===== Smart Auto Setup COMPLETE ====="
    Write-Host "This console will show FINAL COMPLETE when all background tasks finish."
    Write-Host ""
}

# --- Summary ---
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "All checks complete. Review results above." -ForegroundColor Cyan
if ($BitLockerSkipped) {
    Write-Host "[INFO] BitLocker test skipped automatically due to Home/Core edition." -ForegroundColor DarkGray
}
if ($SpeakerTestFailed) {
    Write-Host "[WARN] Speaker test failed -- no audible output detected." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Press Enter to close this window..." -ForegroundColor Cyan
[void][System.Console]::ReadLine()

function Run-FinalSystemReadinessCheck {

    $Host.UI.RawUI.WindowTitle = "Final System Readiness Check - Compu-TEK"
    Clear-Host

    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "      FINAL SYSTEM READINESS CHECK - COMPU-TEK" -ForegroundColor Cyan
    Write-Host "===================================================`n" -ForegroundColor Cyan

    $BitLockerSkipped   = $false
    $SpeakerTestFailed  = $false

# =====================================================
#  FINAL SYSTEM READINESS CHECK - COMPU-TEK
# =====================================================
$Host.UI.RawUI.WindowTitle = "Final System Readiness Check - Compu-TEK"
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "      FINAL SYSTEM READINESS CHECK - COMPU-TEK" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

$BitLockerSkipped = $false
$SpeakerTestFailed = $false

# --- 1. Windows Edition & Activation ---
$edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
Write-Host "[INFO] Windows Edition: $edition" -ForegroundColor Cyan

try {
    $l = Get-CimInstance SoftwareLicensingProduct |
         Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }
    if ($l) {
        Write-Host "[OK] Windows is activated." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Windows not activated!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to determine activation status." -ForegroundColor Yellow
}

# --- 1b. Disable and verify Hibernation ---
try {
    Write-Host "`n[INFO] Checking hibernation status..." -ForegroundColor Cyan
    $hiberStatus = (powercfg /a) | Select-String "Hibernate"

    if ($hiberStatus -match "not available") {
        Write-Host "[OK] Hibernation already disabled." -ForegroundColor Green
    } else {
        Write-Host "[INFO] Disabling hibernation..." -ForegroundColor Cyan
        powercfg -h off | Out-Null
        Start-Sleep -Seconds 1
        $check = (powercfg /a) | Select-String "not available"
        if ($check) {
            Write-Host "[OK] Hibernation successfully disabled." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Could not confirm hibernation is off." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[WARN] Unable to modify hibernation settings." -ForegroundColor Yellow
}

# --- 2. BitLocker (skip for Home/Core editions) ---
if ($edition -match 'Home' -or $edition -match 'Core' -or $edition -match 'SingleLanguage') {
    Write-Host "[INFO] BitLocker check skipped: Windows Home/Core edition detected." -ForegroundColor Cyan
    $BitLockerSkipped = $true
}
else {
    try {
        Write-Host "`n[INFO] Checking and repairing BitLocker configuration..." -ForegroundColor Cyan

        # --- Step 1: Remove prevention flags that could block encryption ---
        $regPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker",
            "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
        )

        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                foreach ($name in @("PreventDeviceEncryption", "PreventAutoEncryption", "DisableAutoEncryption")) {
                    $val = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name
                    if ($val -eq 1) {
                        Write-Host "[FIX] Removing BitLocker restriction flag: $name" -ForegroundColor Yellow
                        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        Write-Host "[OK] BitLocker policy flags verified." -ForegroundColor Green

        # --- Step 2: Check BitLocker status per drive ---
        $oldPref = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-Module BitLocker -ErrorAction SilentlyContinue | Out-Null
        $WarningPreference = $oldPref

        $vols = Get-BitLockerVolume -ErrorAction Stop
        if ($vols) {
            foreach ($v in $vols) {
                $label = (Get-Volume -DriveLetter $v.MountPoint.TrimEnd(':') -ErrorAction SilentlyContinue).FileSystemLabel
                if ($label -match 'Ventoy' -or $label -match 'VTOYEFI' -or
                    $v.MountPoint -match 'Ventoy' -or $v.MountPoint -match 'VTOYEFI') { continue }

                $status = $v.EncryptionPercentage
                $state  = $v.VolumeStatus
                $prot   = $v.ProtectionStatus

                if ($state -match "FullyEncrypted" -or $state -match "UsedSpaceOnlyEncrypted" -or $status -eq 100) {
                    Write-Host "[OK] BitLocker active on drive $($v.MountPoint) ($state, $status%)" -ForegroundColor Green
                }
                elseif ($prot -eq 'Off' -or $state -match "FullyDecrypted") {
                    Write-Host "[WARN] BitLocker off on drive $($v.MountPoint)" -ForegroundColor Yellow
                }
                else {
                    Write-Host "[INFO] BitLocker unknown state on $($v.MountPoint) ($state)" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "[INFO] No BitLocker volumes found." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "[WARN] Unable to query BitLocker status or clear flags." -ForegroundColor Yellow
    }
}

# --- 3. Active Virus Protection ---
try {
    $defender = $null
    $otherAV  = $null

    try { $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch {}

    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue

    if ($defender -and $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
        Write-Host "[OK] Microsoft Defender active and protecting." -ForegroundColor Green
    }
    elseif ($avProducts -and ($avProducts.productState -ne $null)) {
        $names = ($avProducts.displayName | Sort-Object -Unique) -join ", "
        Write-Host "[INFO] Third-party AV detected: $names (Defender off)" -ForegroundColor Cyan
    }
    else {
        Write-Host "[WARN] No active antivirus protection detected!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to verify antivirus protection." -ForegroundColor Yellow
}

# --- 4. Splashtop Streamer ---
try {
    $svc = Get-Service -Name "SplashtopRemoteService" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host "[OK] Splashtop Streamer running." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Splashtop Streamer not detected or not running!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to check Splashtop service." -ForegroundColor Yellow
}

# --- 5. Windows Updates ---
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
    $count    = $result.Updates.Count
    if ($count -gt 0) {
        Write-Host "[WARN] Pending Windows Updates: $count" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Windows is up to date." -ForegroundColor Green
    }
} catch {
    if ($_.Exception.HResult -eq -2145124318) {
        Write-Host "[INFO] Updates managed by WSUS or policy." -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] Windows Update check skipped due to restriction." -ForegroundColor Cyan
    }
}

# --- 6. Device Manager ---
try {
    $e = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' }
    if ($null -ne $e -and $e.Count -gt 0) {
        foreach ($i in $e) {
            Write-Host "[WARN] Device Issue: $($i.FriendlyName) ($($i.InstanceId))" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] No device issues found." -ForegroundColor Green
    }
} catch {
    Write-Host "[WARN] Unable to query Device Manager." -ForegroundColor Yellow
}

# --- 7. System Restore Point (Hardened for field use) ---
try {
    Write-Host "`n[INFO] Checking System Restore configuration..." -ForegroundColor Cyan

    # Detect system drive
    $sysDrive = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).SystemDrive
    if (-not $sysDrive) { 
        Write-Host "[WARN] Unable to detect system drive for restore point." -ForegroundColor Yellow
        throw "No system drive" 
    }

    # Check if System Protection is enabled
    $shadowInfo = vssadmin list shadowstorage 2>$null
    $enabled = $shadowInfo -match [regex]::Escape($sysDrive)

    if (-not $enabled) {
        Write-Host "[INFO] System Protection appears OFF for $sysDrive. Attempting to enable..." -ForegroundColor Cyan
        try {
            Enable-ComputerRestore -Drive $sysDrive -ErrorAction Stop
            Write-Host "[OK] System Protection enabled." -ForegroundColor Green
        } catch {
            Write-Host "[WARN] Could not enable System Protection. It may be disabled by policy on this machine." -ForegroundColor Yellow
            Write-Host "[INFO] Skipping restore point creation." -ForegroundColor DarkGray
            throw "ProtectionOff"
        }
    } else {
        Write-Host "[OK] System Protection already active on $sysDrive." -ForegroundColor Green
    }

    # Attempt to create restore point
    try {
        $dateLabel = (Get-Date).ToString("yyyy-MM-dd_HHmm")
        Write-Host "[INFO] Creating System Restore Point..." -ForegroundColor Cyan

        Checkpoint-Computer `
            -Description "Compu-TEK Readiness Check - $dateLabel" `
            -RestorePointType MODIFY_SETTINGS `
            -ErrorAction Stop

        Write-Host "[OK] Restore Point created successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Restore point could NOT be created. (Likely VSS or policy issue)" -ForegroundColor Yellow
    }

} catch {
    # This catches all failures, but *never* ends the script
    Write-Host "[INFO] System Restore section skipped due to environment restrictions." -ForegroundColor DarkGray
}

# --- 8. Audio Device / Speaker Check ---
try {
    Write-Host ""
    Write-Host "---------------------------------------------------"
    Write-Host "[8/8] Checking audio output devices..." -ForegroundColor Cyan

    $audioDevices = Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue
    $activeAudio  = $audioDevices | Where-Object { $_.Status -eq "OK" }

    if (-not $activeAudio) {
        Write-Host "[WARN] No active audio output device detected!" -ForegroundColor Yellow
        $SpeakerTestFailed = $true
    }
    else {
        $device = $activeAudio | Select-Object -First 1
        $driver = $device.DriverProviderName
        $name   = $device.Name

        Write-Host ("[OK] Active audio device detected: " + $name) -ForegroundColor Green

        if ($driver -match "Microsoft") {
            Write-Host "[WARN] Generic Microsoft audio driver in use -- verify correct sound driver installed." -ForegroundColor Yellow
        } else {
            Write-Host ("[INFO] Audio driver provider: " + $driver) -ForegroundColor Cyan
        }

        try {
            $code = @"
using System;
using System.Runtime.InteropServices;

[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
    void RegisterControlChangeNotify(IntPtr pNotify);
    void UnregisterControlChangeNotify(IntPtr pNotify);
    void GetChannelCount(out uint pnChannelCount);
    void SetMasterVolumeLevel(float fLevelDB, Guid pguidEventContext);
    void SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext);
    void GetMasterVolumeLevel(out float pfLevelDB);
    void GetMasterVolumeLevelScalar(out float pfLevel);
    void SetChannelVolumeLevel(uint nChannel, float fLevelDB, Guid pguidEventContext);
    void SetChannelVolumeLevelScalar(uint nChannel, float fLevel, Guid pguidEventContext);
    void GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
    void GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
    void SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext);
    void GetMute(out bool pbMute);
    void GetVolumeStepInfo(out uint pnStep, out uint pnStepCount);
    void VolumeStepUp(Guid pguidEventContext);
    void VolumeStepDown(Guid pguidEventContext);
    void QueryHardwareSupport(out uint pdwHardwareSupportMask);
    void GetVolumeRange(out float pflVolumeMindB, out float pflVolumeMaxdB, out float pflVolumeIncrementdB);
}

[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
    void NotImpl1();
    void GetDefaultAudioEndpoint(uint dataFlow, uint role, out IMMDevice ppDevice);
}

[Guid("D666063F-1587-4E43-81F1-B948E807363F"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
    void Activate(ref Guid id, uint clsCtx, IntPtr pActivationParams, out IAudioEndpointVolume aev);
}

[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
class MMDeviceEnumeratorComObject {}

public class VolumeControl {
    public static void SetVolumeToHalf() {
        var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
        IMMDevice device;
        enumerator.GetDefaultAudioEndpoint(0, 1, out device);
        Guid IID_IAudioEndpointVolume = typeof(IAudioEndpointVolume).GUID;
        IAudioEndpointVolume volume;
        device.Activate(ref IID_IAudioEndpointVolume, 23, IntPtr.Zero, out volume);
        volume.SetMute(false, Guid.Empty);
        volume.SetMasterVolumeLevelScalar(0.5f, Guid.Empty);
    }
}
"@
            Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
            [VolumeControl]::SetVolumeToHalf()
            Write-Host "[INFO] Speaker volume set to 50% and unmuted." -ForegroundColor Cyan
        } catch {
            Write-Host "[INFO] Unable to modify speaker volume (non-fatal)." -ForegroundColor DarkGray
        }

        try {
            Write-Host "[INFO] Playing Compu-Tek test melody..." -ForegroundColor Cyan

            function Play-Note {
                param ([int]$freq, [int]$dur)
                if ($dur -lt 150) { $dur = 150 }
                Start-Sleep -Milliseconds 30
                [console]::Beep($freq, $dur)
                Start-Sleep -Milliseconds ($dur + 150)
            }

            $notes = @{
                "G" = 392; "A" = 440; "B" = 494;
                "C" = 522; "D" = 588; "E" = 658
            }

            $melody = @(
                @("G",200),@("G",200),@("G",200),
                @("C",600),@("E",200),
                @("G",200),@("G",200),@("G",200),
                @("C",600),@("E",200),
                @("C",200),@("C",200),
                @("B",200),@("B",200),
                @("A",200),@("A",200),
                @("G",600)
            )

            foreach ($note in $melody) {
                try {
                    $freq = $notes[$note[0]]
                    $dur  = $note[1]
                    Play-Note -freq $freq -dur $dur
                } catch {
                    Start-Sleep -Milliseconds 300
                }
            }

            Write-Host "[OK] Speaker test melody completed successfully." -ForegroundColor Green
        } catch {
            Write-Host "[WARN] Speaker test failed during melody playback." -ForegroundColor Yellow
            $SpeakerTestFailed = $true
        }
    }

    $disabled = $audioDevices | Where-Object { $_.Status -ne "OK" }
    if ($disabled) {
        foreach ($d in $disabled) {
            Write-Host ("[WARN] Disabled or problem audio device: " + $d.Name) -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[WARN] Unable to query audio devices." -ForegroundColor Yellow
    $SpeakerTestFailed = $true
}

# --- Summary ---
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "All checks complete. Review results above." -ForegroundColor Cyan
if ($BitLockerSkipped) {
    Write-Host "[INFO] BitLocker test skipped automatically due to Home/Core edition." -ForegroundColor DarkGray
}
if ($SpeakerTestFailed) {
    Write-Host "[WARN] Speaker test failed -- no audible output detected." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Press Enter to close this window..." -ForegroundColor Cyan
[void][System.Console]::ReadLine()

# (Windows Edition, BitLocker, AV, Splashtop,
    # Updates, Devices, Restore Point, Audio Test, etc)

    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "Readiness check completed." -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Pause
}


# -----------------------------
# MENU
# -----------------------------
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Setup (Smart Auto Mode) [Default]"
    Write-Host "2. final system check"
    Write-Host "3. Restart Computer"
    Write-Host "4. Exit and Cleanup"
    Write-Host "=========================================="
    Write-Host "Press Enter for default (1)."
}

function MenuSelection {
    param([int]$selection)
    switch ($selection) {
        1 { Run-SmartFirstTimeSetup }
        2 { Run-FinalSystemReadinessCheck}
        3 { Write-Host "Restarting now..."; shutdown.exe /r /t 0 }
        4 { Write-Host "Cleaning up and exiting..."; Remove-DesktopShortcut "Computek Setup Script"; exit }
        default { Write-Host "Invalid selection." }
    }
}

# -----------------------------
# MAIN LOOP
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator required. Exiting."
    exit
}

do {
    Show-Menu
    $choice = Read-Host "Enter choice (1-3) [Default = 1]"
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 3) {
        $choice = [int]$choice
    } else {
        $choice = 1
    }
    MenuSelection -selection $choice
    Pause
} while ($true)
