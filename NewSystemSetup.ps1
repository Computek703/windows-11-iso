##########################################################################################################################################################
# Compu-TEK First-Time System Setup Tool (v3.3)
##########################################################################################################################################################

# -----------------------------
# Console Setup
# -----------------------------
function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'

$Host.UI.RawUI.WindowTitle = "Compu-TEK System Setup Tool"

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
Write-Host "Welcome to the Compu-TEK Setup Tool"
Write-Host "v3.3"
Write-Host ""

# -----------------------------
# Admin Check
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator privileges required. Exiting."
    exit
}

# -----------------------------
# Utility
# -----------------------------
function Remove-DesktopShortcut {
    param ([string]$ShortcutName)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $path = Join-Path $desktop "$ShortcutName.lnk"
    if (Test-Path $path) {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------
# FINAL SYSTEM READINESS CHECK
# -----------------------------
function Run-FinalSystemReadinessCheck {

    $Host.UI.RawUI.WindowTitle = "Final System Readiness Check - Compu-TEK"

    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "      FINAL SYSTEM READINESS CHECK - COMPU-TEK" -ForegroundColor Cyan
    Write-Host "===================================================`n" -ForegroundColor Cyan

    $BitLockerSkipped = $false
    $SpeakerTestFailed = $false

    # ---- Windows Edition & Activation ----
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    Write-Host "[INFO] Windows Edition: $edition" -ForegroundColor Cyan

    try {
        $l = Get-CimInstance SoftwareLicensingProduct |
             Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }
        if ($l) { Write-Host "[OK] Windows is activated." -ForegroundColor Green }
        else { Write-Host "[WARN] Windows not activated!" -ForegroundColor Yellow }
    } catch {
        Write-Host "[WARN] Unable to determine activation status." -ForegroundColor Yellow
    }

    # ---- Hibernation ----
    try {
        powercfg -h off | Out-Null
        Write-Host "[OK] Hibernation disabled." -ForegroundColor Green
    } catch {}

    # ---- BitLocker ----
    if ($edition -match 'Home|Core|SingleLanguage') {
        Write-Host "[INFO] BitLocker skipped (Home/Core)." -ForegroundColor Cyan
        $BitLockerSkipped = $true
    } else {
        try {
            $vols = Get-BitLockerVolume
            foreach ($v in $vols) {
                if ($v.ProtectionStatus -eq 'On') {
                    Write-Host "[OK] BitLocker active on $($v.MountPoint)" -ForegroundColor Green
                } else {
                    Write-Host "[WARN] BitLocker OFF on $($v.MountPoint)" -ForegroundColor Yellow
                }
            }
        } catch {}
    }

    # ---- Antivirus ----
    try {
        $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($def.AntivirusEnabled) {
            Write-Host "[OK] Defender active." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Defender inactive." -ForegroundColor Yellow
        }
    } catch {}

    # ---- Device Manager ----
    try {
        $bad = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' }
        if ($bad) {
            foreach ($d in $bad) {
                Write-Host "[WARN] Device issue: $($d.FriendlyName)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[OK] No device issues." -ForegroundColor Green
        }
    } catch {}

    # ---- Summary ----
    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "FINAL READINESS CHECK COMPLETE" -ForegroundColor Cyan
    if ($BitLockerSkipped) {
        Write-Host "[INFO] BitLocker skipped due to edition." -ForegroundColor DarkGray
    }
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "Press Enter to return to menu..."
    [void][System.Console]::ReadLine()
    return
}

# -----------------------------
# SMART FIRST TIME SETUP (placeholder)
# -----------------------------
function Run-SmartFirstTimeSetup {
    Write-Host ""
    Write-Host "===== Smart Auto Setup START ====="
    Write-Host "(Your existing setup logic runs here)"
    Write-Host "===== Smart Auto Setup COMPLETE ====="
    Write-Host ""
}

# -----------------------------
# MENU
# -----------------------------
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Setup (Smart Auto Mode) [Default]"
    Write-Host "2. Final System Readiness Check"
    Write-Host "3. Restart Computer"
    Write-Host "4. Exit and Cleanup"
    Write-Host "=========================================="
    Write-Host "Press Enter for default (1)."
}

function MenuSelection {
    param([int]$selection)
    switch ($selection) {
        1 { Run-SmartFirstTimeSetup }
        2 { Run-FinalSystemReadinessCheck }
        3 { shutdown.exe /r /t 0 }
        4 {
            Remove-DesktopShortcut "Computek Setup Script"
            exit
        }
    }
}

# -----------------------------
# MAIN LOOP
# -----------------------------
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
