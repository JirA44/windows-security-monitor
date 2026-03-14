# watchdog_pc.ps1 — Surveille nouveaux processus + entrees Startup
# Cree une baseline, puis alerte si quelque chose de nouveau apparait
param(
    [switch]$Init,
    [switch]$Check,
    [string]$BaselineFile = "$PSScriptRoot\baseline.json"
)

$whitelist = @(
    'svchost','System','Registry','smss','csrss','wininit','winlogon','lsass','services',
    'dwm','sihost','taskhostw','explorer','SearchHost','StartMenuExperienceHost',
    'RuntimeBroker','ApplicationFrameHost','ShellHost','TextInputHost','ctfmon',
    'MsMpEng','MpDefenderCoreService','NisSrv','WmiPrvSE','spoolsv','SearchIndexer',
    'node','python','claude','bash','powershell','pwsh','conhost',
    'kDrive','kDrive_client','ProtonDrive','OneDrive','GoogleDriveFS',
    'nvcontainer','NVDisplay.Container','nvsphelper64','NVIDIA Overlay',
    'ETDCtrl','ETDService','RtkAudUService64','RtkBtManServ',
    'WindowsTerminal','OpenConsole','PhoneExperienceHost','WidgetBoard',
    'AdBlock360Svc','cowork-svc','servicehost','BridgeCommunication',
    'AppHelperCap','DiagsCap','NetworkCap','OmenCap','SysInfoCap',
    'AggregatorHost','dasHost','mDNSResponder','fontdrvhost',
    'atieclxx','atiesrxx','SECOMN64','TouchpointAnalyticsClientService',
    'crashpad_handler','FileExplorerExtension','uihost','unsecapp',
    'wslservice','Memory Compression','msedgewebview2','SystemSettings',
    'UserOOBEBroker','coworkVMService','BraveCrashHandler','BraveCrashHandler64',
    'servicehost','head','grep','tail'
)

function Get-Baseline {
    $procs = Get-CimInstance Win32_Process | ForEach-Object { $_.Name -replace '\.exe$','' }
    $startup = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $runHKCU = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name
    @{ procs = ($procs | Sort-Object -Unique); startup = $startup; runHKCU = $runHKCU }
}

if ($Init) {
    $baseline = Get-Baseline
    $baseline | ConvertTo-Json | Out-File $BaselineFile -Encoding UTF8
    Write-Host "[OK] Baseline sauvegardee: $BaselineFile" -ForegroundColor Green
    Write-Host "  $($baseline.procs.Count) processus, $($baseline.startup.Count) entrees startup"
}

if ($Check) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Host "[ERR] Baseline introuvable. Lance d'abord: -Init" -ForegroundColor Red
        exit 1
    }
    $baseline = Get-Content $BaselineFile | ConvertFrom-Json
    $current = Get-Baseline

    $newProcs = $current.procs | Where-Object {
        $name = $_
        $baseline.procs -notcontains $name -and $whitelist -notcontains $name
    }
    $newStartup = $current.startup | Where-Object { $baseline.startup -notcontains $_ }
    $newRunHKCU = $current.runHKCU | Where-Object { $baseline.runHKCU -notcontains $_ }

    $alerts = @()
    if ($newProcs) { $alerts += "[PROC NOUVEAU] $($newProcs -join ', ')" }
    if ($newStartup) { $alerts += "[STARTUP NOUVEAU] $($newStartup -join ', ')" }
    if ($newRunHKCU) { $alerts += "[RUN REGISTRY NOUVEAU] $($newRunHKCU -join ', ')" }

    if ($alerts) {
        Write-Host "ALERTE SECURITE $(Get-Date -Format 'HH:mm')" -ForegroundColor Red
        $alerts | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        # Log
        $reportsDir = "$PSScriptRoot\reports"
        if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }
        $alerts | Out-File "$reportsDir\alerts-$(Get-Date -Format 'yyyyMMdd').txt" -Append -Encoding UTF8
    } else {
        Write-Host "[OK] $(Get-Date -Format 'HH:mm') Aucune menace detectee" -ForegroundColor Green
    }
}
