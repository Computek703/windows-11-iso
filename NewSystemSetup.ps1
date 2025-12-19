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

function Invoke-CompuTekFinalReadinessCheck {

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

# --- 2. BitLocker ---
if ($edition -match 'Home|Core|SingleLanguage') {
    Write-Host "[INFO] BitLocker check skipped: Windows Home/Core edition detected." -ForegroundColor Cyan
    $BitLockerSkipped = $true
}
else {
    try {
        Write-Host "`n[INFO] Checking BitLocker configuration..." -ForegroundColor Cyan
        Import-Module BitLocker -ErrorAction SilentlyContinue | Out-Null
        $vols = Get-BitLockerVolume
        foreach ($v in $vols) {
            if ($v.ProtectionStatus -eq 'On') {
                Write-Host "[OK] BitLocker active on $($v.MountPoint)" -ForegroundColor Green
            } else {
                Write-Host "[WARN] BitLocker OFF on $($v.MountPoint)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "[WARN] Unable to query BitLocker." -ForegroundColor Yellow
    }
}

# --- 3. Antivirus ---
try {
    $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($def.AntivirusEnabled -and $def.RealTimeProtectionEnabled) {
        Write-Host "[OK] Microsoft Defender active." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Antivirus not fully active." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to check antivirus." -ForegroundColor Yellow
}

# --- 4. Splashtop ---
try {
    $svc = Get-Service SplashtopRemoteService -ErrorAction SilentlyContinue
    if ($svc.Status -eq "Running") {
        Write-Host "[OK] Splashtop running." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Splashtop not running." -ForegroundColor Yellow
    }
} catch {}

# --- 5. Windows Updates ---
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0")
    if ($result.Updates.Count -gt 0) {
        Write-Host "[WARN] Pending Windows Updates: $($result.Updates.Count)" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Windows up to date." -ForegroundColor Green
    }
} catch {}

# --- 6. Device Manager ---
try {
    $e = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' }
    if ($e) {
        foreach ($d in $e) {
            Write-Host "[WARN] Device issue: $($d.FriendlyName)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] No device issues." -ForegroundColor Green
    }
} catch {}

# --- 7. System Restore ---
try {
    $sysDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
    Enable-ComputerRestore -Drive $sysDrive -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "Compu-TEK Readiness Check" -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue
    Write-Host "[OK] System Restore point created." -ForegroundColor Green
} catch {
    Write-Host "[INFO] Restore point skipped." -ForegroundColor DarkGray
}

# --- 8. AUDIO TEST (UNCHANGED) ---
Write-Host "`n[INFO] Running speaker test..." -ForegroundColor Cyan
try {
    [console]::Beep(392,200)
    [console]::Beep(392,200)
    [console]::Beep(392,200)
    [console]::Beep(522,600)
    [console]::Beep(658,200)
    Write-Host "[OK] Speaker test completed." -ForegroundColor Green
} catch {
    Write-Host "[WARN] Speaker test failed." -ForegroundColor Yellow
    $SpeakerTestFailed = $true
}

# --- SUMMARY ---
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "Final System Readiness Check COMPLETE" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

return [pscustomobject]@{
    BitLockerSkipped  = $BitLockerSkipped
    SpeakerTestFailed = $SpeakerTestFailed
}

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
    $choice = Read-Host "Enter choice (1-4) [Default = 1]"
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 4) {
        $choice = [int]$choice
    } else {
        $choice = 1
    }
    MenuSelection -selection $choice
    Pause
} while ($true)
