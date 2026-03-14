# WinDefend Toolkit — One-line installer
# Run: irm https://raw.githubusercontent.com/JirA44/windows-security-monitor/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$REPO = "https://raw.githubusercontent.com/JirA44/windows-security-monitor/main"
$INSTALL_DIR = "$HOME\WinDefend"

Write-Host ""
Write-Host "  WinDefend Toolkit — Installer" -ForegroundColor Cyan
Write-Host "  ================================" -ForegroundColor Cyan
Write-Host ""

# Create folder
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null
    New-Item -ItemType Directory -Path "$INSTALL_DIR\reports" | Out-Null
}
Write-Host "[1/4] Install directory: $INSTALL_DIR" -ForegroundColor Green

# Download scripts
$scripts = @("install_tracker.ps1", "watchdog_pc.ps1", "check_threats.ps1")
foreach ($s in $scripts) {
    Invoke-WebRequest -Uri "$REPO/$s" -OutFile "$INSTALL_DIR\$s" -UseBasicParsing
    Write-Host "      Downloaded: $s" -ForegroundColor Gray
}
Write-Host "[2/4] Scripts downloaded" -ForegroundColor Green

# Initialize baselines
Set-Location $INSTALL_DIR
powershell -ExecutionPolicy Bypass -File "$INSTALL_DIR\install_tracker.ps1" -Init -BaselineFile "$INSTALL_DIR\install_baseline.json"
powershell -ExecutionPolicy Bypass -File "$INSTALL_DIR\watchdog_pc.ps1" -Init -BaselineFile "$INSTALL_DIR\baseline.json"
Write-Host "[3/4] Baselines initialized" -ForegroundColor Green

# Create scheduled tasks
$taskParams = @{
    Force = $true
    RunLevel = "Highest"
}
$action1 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$INSTALL_DIR\install_tracker.ps1`" -Check -BaselineFile `"$INSTALL_DIR\install_baseline.json`""
$trigger1 = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 6) -Once -At (Get-Date)
Register-ScheduledTask -TaskName "WinDefend\InstallTracker" -Action $action1 -Trigger $trigger1 @taskParams | Out-Null

$action2 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$INSTALL_DIR\watchdog_pc.ps1`" -Check -BaselineFile `"$INSTALL_DIR\baseline.json`""
$trigger2 = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "WinDefend\Watchdog" -Action $action2 -Trigger $trigger2 @taskParams | Out-Null
Write-Host "[4/4] Scheduled tasks created (every 6h + at login)" -ForegroundColor Green

Write-Host ""
Write-Host "  Done! WinDefend is active." -ForegroundColor Cyan
Write-Host ""
Write-Host "  Run a check now:" -ForegroundColor Yellow
Write-Host "    powershell -File $INSTALL_DIR\install_tracker.ps1 -Check"
Write-Host "    powershell -File $INSTALL_DIR\check_threats.ps1"
Write-Host ""
Write-Host "  Reports: $INSTALL_DIR\reports\" -ForegroundColor Gray
Write-Host ""
