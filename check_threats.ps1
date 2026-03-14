$report = @()
$report += "=== AUDIT SECURITE $(Get-Date -Format 'yyyy-MM-dd HH:mm') ==="

$report += ""
$report += "[1] PROCESSUS SUSPECTS"
$procs = Get-CimInstance Win32_Process
$found = $procs | Where-Object { $_.Name -match 'wscript|cscript|mshta|synchrony|watchdog|xmrig' }
if ($found) {
    foreach ($p in $found) {
        $report += "  PID=$($p.ProcessId) NAME=$($p.Name)"
        $report += "  CMD=$($p.CommandLine)"
    }
} else { $report += "  (aucun suspect)" }

$report += ""
$report += "[2] TACHES PLANIFIEES (hors Microsoft, actives)"
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }
foreach ($t in $tasks) {
    $exe = if ($t.Actions) { $t.Actions[0].Execute } else { "" }
    $report += "  [$($t.State)] $($t.TaskPath)$($t.TaskName) -> $exe"
}

$report += ""
$report += "[3] DEMARRAGE HKCU\Run"
$runKey = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
if ($runKey) {
    $runKey.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $report += "  $($_.Name) = $($_.Value)"
    }
} else { $report += "  (vide)" }

$report += ""
$report += "[4] DEMARRAGE HKLM\Run"
$runKeyM = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
if ($runKeyM) {
    $runKeyM.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $report += "  $($_.Name) = $($_.Value)"
    }
} else { $report += "  (vide)" }

$report += ""
$report += "[5] DOSSIER STARTUP USER"
$startupUser = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$items = Get-ChildItem $startupUser -ErrorAction SilentlyContinue
if ($items) { foreach ($i in $items) { $report += "  $($i.Name)" } }
else { $report += "  (vide)" }

$report += ""
$report += "[6] SCRIPTS (vbs/bat/js/hta) dans Temp - 7j"
$dirs = @($env:TEMP, "$env:LOCALAPPDATA\Temp")
foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        $scripts = Get-ChildItem $dir -Include '*.vbs','*.bat','*.js','*.hta','*.ps1' -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
        foreach ($s in $scripts) { $report += "  $($s.FullName)" }
    }
}

$report += ""
$report += "[7] CONNEXIONS RESEAU ETABLIES"
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
foreach ($c in $conns) {
    if ($c.RemoteAddress -ne '127.0.0.1' -and $c.RemoteAddress -ne '::1') {
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pname = if ($p) { $p.Name } else { "PID:$($c.OwningProcess)" }
        $report += "  $pname :$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort)"
    }
}

$report += ""
$report += "=== FIN AUDIT ==="

$output = $report -join "`n"
Write-Host $output
$reportsDir = "$PSScriptRoot\reports"
if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }
$output | Out-File "$reportsDir\threats-$(Get-Date -Format 'yyyyMMdd-HHmm').txt" -Encoding UTF8
