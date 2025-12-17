####################################################################################################
# Compu-TEK First-Time System Setup Tool (v3.4)
# Option 1: Smart First-Time Setup
# Option 2: Final System Readiness Check
# Option 3: Restart
# Option 4: Exit & Cleanup
####################################################################################################

#region Console Setup
function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'
$Host.UI.RawUI.WindowTitle = "Compu-TEK System Setup Tool"
#endregion

#region Admin Check
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator privileges required. Exiting."
    exit
}
#endregion

#region Utilities
function Remove-DesktopShortcut {
    param([string]$ShortcutName)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $path = Join-Path $desktop "$ShortcutName.lnk"
    if (Test-Path $path) {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Core Setup Functions (from v3.2)

function Install-WindowsUpdates-Async {
    Write-Host "[INFO] Opening Windows Update UI..." -ForegroundColor Cyan
    Start-Process "ms-settings:windowsupdate" -ErrorAction SilentlyContinue
}

function Install-SyncroAgent {
    Write-Host "[INFO] Installing Syncro Agent..." -ForegroundColor Cyan
    if (-not (Get-Service Syncro -ErrorAction SilentlyContinue)) {
        $url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $path = "C:\Windows\Temp\SyncroSetup.exe"
        Invoke-WebRequest $url -OutFile $path -ErrorAction SilentlyContinue
        Start-Process $path -ArgumentList "--console --customerid 1362064 --folderid 4238852" -Wait
    }
}

function Is-DellSystem {
    try { (Get-CimInstance Win32_ComputerSystem).Manufacturer -match "Dell" }
    catch { $false }
}

function Install-DellCommandUpdate {
    Write-Host "[INFO] Installing Dell Command | Update..." -ForegroundColor Cyan
    Start-Process choco -ArgumentList "install dellcommandupdate -y" -Wait -ErrorAction SilentlyContinue
}

function Install-SoftwarePackages {
    Write-Host "[INFO] Launching Chrome + Adobe installer window..." -ForegroundColor Cyan

    $script = @'
$Host.UI.RawUI.WindowTitle = "CT_CHOCOWIN"
Start-Transcript "$env:TEMP\CT_Chocolatey.log" -Append

function Verify-Chrome { Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" }
function Verify-Adobe {
    Test-Path "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
}

function Install-WithRetry($pkg,$name,$verify) {
    if (& $verify) { return $true }
    for ($i=1;$i -le 3;$i++) {
        choco install $pkg -y --no-progress
        Start-Sleep 5
        if (& $verify) { return $true }
    }
    return $false
}

Install-WithRetry googlechrome "Chrome" { Verify-Chrome }
Install-WithRetry adobereader  "Adobe"  { Verify-Adobe }

Stop-Transcript
Write-Host "Install window complete."
'@

    $path = "$env:TEMP\CT_Install.ps1"
    $script | Out-File $path -Force
    Start-Process powershell "-NoExit -ExecutionPolicy Bypass -File `"$path`""
}

function Set-Hostname {
    $brand = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber
    Rename-Computer "$brand-$serial" -Force -ErrorAction SilentlyContinue
}

function Enable-QuickMachineRecovery {
    $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"
    New-Item $reg -Force | Out-Null
    Set-ItemProperty $reg QuickRecoveryEnabled 1
}
#endregion

#region OPTION 1 — Smart First-Time Setup
function Run-SmartFirstTimeSetup {

    Write-Host "`n===== SMART AUTO SETUP START =====`n" -ForegroundColor Green

    Install-WindowsUpdates-Async
    Install-SyncroAgent

    if (Is-DellSystem) { Install-DellCommandUpdate }
    Install-SoftwarePackages
    Set-Hostname
    Enable-QuickMachineRecovery

    Write-Host "`n===== SMART AUTO SETUP COMPLETE =====" -ForegroundColor Green
    Write-Host "Background tasks may still be running."
}
#endregion

#region OPTION 2 — Final System Readiness Check
function Run-FinalSystemReadinessCheck {

    $Host.UI.RawUI.WindowTitle = "Final System Readiness Check - Compu-TEK"
    Write-Host "`n=== FINAL SYSTEM READINESS CHECK ===`n" -ForegroundColor Cyan

    Write-Host "[STEP] Windows Activation..."
    $lic = Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.LicenseStatus -eq 1}
    if ($lic) { Write-Host "[OK] Activated" -ForegroundColor Green }
    else { Write-Host "[WARN] Not activated" -ForegroundColor Yellow }

    Write-Host "`n[STEP] BitLocker..."
    try {
        Get-BitLockerVolume | ForEach-Object {
            if ($_.ProtectionStatus -eq "On") {
                Write-Host "[OK] BitLocker ON $($_.MountPoint)" -ForegroundColor Green
            } else {
                Write-Host "[WARN] BitLocker OFF $($_.MountPoint)" -ForegroundColor Yellow
            }
        }
    } catch {}

    Write-Host "`n[STEP] Antivirus..."
    try {
        $def = Get-MpComputerStatus
        if ($def.RealTimeProtectionEnabled) {
            Write-Host "[OK] Defender Active" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Defender Off" -ForegroundColor Yellow
        }
    } catch {}

    Write-Host "`n[STEP] Device Manager..."
    $bad = Get-PnpDevice | Where-Object Status -eq Error
    if ($bad) {
        $bad | ForEach-Object {
            Write-Host "[WARN] Device Issue: $($_.FriendlyName)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] No device issues" -ForegroundColor Green
    }

    Write-Host "`n[STEP] System Restore (timeout protected)..."
    $job = Start-Job { Checkpoint-Computer -Description "Compu-TEK Readiness" }
    if (Wait-Job $job -Timeout 60) {
        Write-Host "[OK] Restore point created" -ForegroundColor Green
    } else {
        Stop-Job $job -Force
        Write-Host "[WARN] Restore point skipped (timeout)" -ForegroundColor Yellow
    }

    Write-Host "`n=== READINESS CHECK COMPLETE ==="
    Write-Host "Press Enter to return to menu..."
    [void][Console]::ReadLine()
}
#endregion

#region Menu
function Show-Menu {
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "       Compu-TEK System Menu"
    Write-Host "=========================================="
    Write-Host "1. Smart First-Time Setup"
    Write-Host "2. Final System Readiness Check"
    Write-Host "3. Restart Computer"
    Write-Host "4. Exit and Cleanup"
    Write-Host "=========================================="
}

function MenuSelection($sel) {
    switch ($sel) {
        1 { Run-SmartFirstTimeSetup }
        2 { Run-FinalSystemReadinessCheck }
        3 { shutdown.exe /r /t 0 }
        4 { Remove-DesktopShortcut "Computek Setup Script"; exit }
    }
}
#endregion

#region Main Loop
do {
    Show-Menu
    $choice = Read-Host "Enter choice (1-4) [Default 1]"
    if ($choice -notmatch '^[1-4]$') { $choice = 1 }
    MenuSelection $choice
    Pause
} while ($true)
#endregion
