param([switch]$Init, [switch]$Check, [switch]$Report, [string]$BaselineFile = "$PSScriptRoot\install_baseline.json")

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $all = @()
    foreach ($p in $paths) {
        $items = Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
        $all += $items | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher
    }
    return $all | Sort-Object DisplayName -Unique
}

if ($Init) {
    $sw = Get-InstalledSoftware
    $sw | ConvertTo-Json -Depth 3 | Out-File $BaselineFile -Encoding UTF8
    Write-Host "[OK] Baseline: $($sw.Count) logiciels enregistres"
    Write-Host "  Fichier: $BaselineFile"
}

if ($Check) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Host "[ERR] Baseline manquante. Lance -Init d'abord."
        exit 1
    }

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $reportsDir = "$PSScriptRoot\reports"
    if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }
    $logFile = "$reportsDir\installs.log"
    $alertFile = "$reportsDir\alerts-$(Get-Date -Format 'yyyyMMdd').txt"

    Write-Host "=== RAPPORT $ts ==="

    # 1. INSTALLATIONS
    Write-Host "[INSTALLS]"
    $baseline = Get-Content $BaselineFile | ConvertFrom-Json
    $current = Get-InstalledSoftware
    $baseNames = $baseline | ForEach-Object { $_.DisplayName }
    $currentNames = $current | ForEach-Object { $_.DisplayName }
    $newSw = $current | Where-Object { $baseNames -notcontains $_.DisplayName }
    $removedSw = $baseline | Where-Object { $currentNames -notcontains $_.DisplayName }

    if ($newSw) {
        Write-Host "  [NOUVEAU] $($newSw.Count) logiciel(s):"
        foreach ($s in $newSw) {
            Write-Host "    + $($s.DisplayName) v$($s.DisplayVersion) ($($s.Publisher))"
            Add-Content $logFile "$ts INSTALL $($s.DisplayName) v$($s.DisplayVersion) $($s.Publisher)"
            Add-Content $alertFile "$ts [INSTALL] $($s.DisplayName)"
        }
    } else {
        Write-Host "  [OK] Aucune nouvelle installation"
    }
    if ($removedSw) {
        Write-Host "  [SUPPRIME] $($removedSw.Count) logiciel(s):"
        foreach ($s in $removedSw) { Write-Host "    - $($s.DisplayName)" }
    }

    # 2. PROCESSUS SUSPECTS (connus malveillants)
    Write-Host "[PROCESSUS SUSPECTS]"
    $suspectProcs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'wscript|cscript|mshta|regsvr32|synchrony|xmrig|cryptominer|miner' }
    if ($suspectProcs) {
        foreach ($p in $suspectProcs) {
            Write-Host "  [ALERTE] PID=$($p.ProcessId) $($p.Name)"
            Add-Content $alertFile "$ts [PROC_SUSPECT] PID=$($p.ProcessId) $($p.Name) CMD=$($p.CommandLine)"
        }
    } else {
        Write-Host "  [OK] Aucun processus suspect"
    }

    # 3. NOUVEAUX PROCESSUS vs baseline
    Write-Host "[NOUVEAUX PROCESSUS]"
    $procBaselineFile = "$PSScriptRoot\baseline.json"
    if (Test-Path $procBaselineFile) {
        $procBaseline = (Get-Content $procBaselineFile | ConvertFrom-Json).procs
        $whitelist = @('svchost','System','Registry','smss','csrss','wininit','winlogon','lsass','services','dwm',
            'sihost','taskhostw','explorer','SearchHost','StartMenuExperienceHost','RuntimeBroker',
            'ApplicationFrameHost','ShellHost','TextInputHost','ctfmon','MsMpEng','MpDefenderCoreService',
            'NisSrv','WmiPrvSE','spoolsv','SearchIndexer','node','python','claude','bash','powershell','pwsh',
            'conhost','kDrive','kDrive_client','ProtonDrive','OneDrive','GoogleDriveFS','nvcontainer',
            'NVDisplay.Container','nvsphelper64','NVIDIA Overlay','ETDCtrl','ETDService','RtkAudUService64',
            'RtkBtManServ','WindowsTerminal','OpenConsole','PhoneExperienceHost','WidgetBoard','AdBlock360Svc',
            'cowork-svc','servicehost','BridgeCommunication','AppHelperCap','DiagsCap','NetworkCap','OmenCap',
            'SysInfoCap','AggregatorHost','dasHost','mDNSResponder','fontdrvhost','atieclxx','atiesrxx',
            'SECOMN64','TouchpointAnalyticsClientService','crashpad_handler','FileExplorerExtension',
            'uihost','unsecapp','wslservice','Memory Compression','msedgewebview2','SystemSettings',
            'UserOOBEBroker','BraveCrashHandler','BraveCrashHandler64','head','grep','tail','find','sort','cat',
            'powershell','install_tracker','check_threats','watchdog_pc','tasklist','taskkill','sc')
        $currentProcs = Get-CimInstance Win32_Process | ForEach-Object { $_.Name -replace '\.exe$','' } | Sort-Object -Unique
        $newProcs = $currentProcs | Where-Object {
            $n = $_
            ($procBaseline -notcontains $n) -and ($whitelist -notcontains $n)
        }
        if ($newProcs) {
            foreach ($pn in $newProcs) {
                $detail = Get-CimInstance Win32_Process | Where-Object { ($_.Name -replace '\.exe$','') -eq $pn } | Select-Object -First 1
                Write-Host "  [NEW] $pn path=$($detail.ExecutablePath)"
                Add-Content $alertFile "$ts [NEW_PROC] $pn path=$($detail.ExecutablePath)"

            }
        } else {
            Write-Host "  [OK] Aucun nouveau processus"
        }
    }

    Write-Host "=== FIN ==="
}

if ($Report) {
    $log = "C:\Users\Hugop\security\reports\installs.log"
    if (Test-Path $log) {
        Write-Host "=== HISTORIQUE DES INSTALLATIONS ==="
        Get-Content $log | Select-Object -Last 50
    } else {
        Write-Host "Aucun historique encore."
    }
}
