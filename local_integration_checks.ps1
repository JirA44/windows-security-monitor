# Real local integration checks: read-only observation of components that actually exist on this machine.
# Missing components are reported as absent, never assumed present; tool failures mark the check incomplete.
# No secrets are read or displayed: the tracked-file check lists file paths only, never content.

function Invoke-NodeJson {
    param([string]$Script)
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $null }
    try {
        $raw = & node -e $Script 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
        return (($raw | Out-String).Trim())
    } catch { return $null }
}

function Get-Pm2StatusMap {
    $json = Invoke-NodeJson -Script @'
const {execSync}=require('child_process');
const raw=execSync('pm2 jlist',{shell:true,stdio:['ignore','pipe','ignore']}).toString();
const arr=JSON.parse(raw);
const out=arr.map(p=>({name:p.name,status:(p.pm2_env&&p.pm2_env.status)||'unknown',pid:p.pid}));
process.stdout.write(JSON.stringify(out));
'@
    if (-not $json) { return $null }
    try { return @($json | ConvertFrom-Json) } catch { return $null }
}

function Invoke-GitRepoInspection {
    param([string]$Path, [int]$TimeoutSeconds = 30)
    $job = Start-Job -ScriptBlock {
        param($p)
        $out = @{ branch = ''; head = ''; dirty = -1; sensitive = @(); error = $null }
        try {
            $out.branch = (& git -C $p rev-parse --abbrev-ref HEAD 2>$null | Out-String).Trim()
            $out.head = (& git -C $p rev-parse --short HEAD 2>$null | Out-String).Trim()
            $out.dirty = @(& git -C $p status --porcelain 2>$null).Count
            $out.sensitive = @(& git -C $p ls-files 2>$null | Where-Object { $_ -match '(?i)(\.env($|\.)|\.pem$|id_rsa|id_ed25519|credentials|secret|\.key$|\.pfx$)' -and $_ -notmatch '(?i)\.(example|template|sample)' })
        } catch { $out.error = $_.Exception.Message }
        return $out
    } -ArgumentList $Path
    if (Wait-Job $job -Timeout $TimeoutSeconds) {
        $res = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $res
    }
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return $null
}

function Test-GitRepoComponent {
    param([object]$Component)
    $path = [string]$Component.path
    if (-not (Test-Path -LiteralPath (Join-Path $path '.git'))) { return [pscustomobject]@{ status = 'absent'; detail = 'no .git at path' } }
    $timeout = 30
    if ($Component.git_timeout_seconds) { $timeout = [int]$Component.git_timeout_seconds }
    $inspection = Invoke-GitRepoInspection -Path $path -TimeoutSeconds $timeout
    if ($null -eq $inspection) { return [pscustomobject]@{ status = 'incomplete'; detail = "git inspection timed out after ${timeout}s (repo too large or locked)" } }
    if ($inspection.error) { return [pscustomobject]@{ status = 'incomplete'; detail = "git failed: $($inspection.error)" } }
    if (-not $inspection.branch -or -not $inspection.head) { return [pscustomobject]@{ status = 'incomplete'; detail = 'git rev-parse failed' } }
    $status = 'ok'
    $detail = "$($inspection.branch)@$($inspection.head) dirty=$($inspection.dirty)"
    if (@($inspection.sensitive).Count -gt 0) {
        $status = 'fail'
        $detail += ' TRACKED-SENSITIVE-FILES(paths only): ' + (@($inspection.sensitive) -join ', ')
    }
    return [pscustomobject]@{ status = $status; detail = $detail }
}

function Test-HttpComponent {
    param([object]$Component)
    $timeout = 5
    if ($Component.timeout_seconds) { $timeout = [int]$Component.timeout_seconds }
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = Invoke-WebRequest -Uri ([string]$Component.url) -TimeoutSec $timeout -UseBasicParsing -ErrorAction Stop
        $sw.Stop()
        $code = [int]$resp.StatusCode
        if ($code -ge 200 -and $code -lt 400) {
            return [pscustomobject]@{ status = 'ok'; detail = "HTTP $code in $([Math]::Round($sw.Elapsed.TotalMilliseconds)) ms" }
        }
        return [pscustomobject]@{ status = 'fail'; detail = "HTTP $code" }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'refused|Unable to connect|No connection could be made') { return [pscustomobject]@{ status = 'absent'; detail = 'connection refused' } }
        return [pscustomobject]@{ status = 'fail'; detail = $msg }
    }
}

function Test-LogComponent {
    param([object]$Component)
    $p = [string]$Component.path
    if (-not (Test-Path -LiteralPath $p)) { return [pscustomobject]@{ status = 'absent'; detail = 'log file not found' } }
    $item = Get-Item -LiteralPath $p
    $maxAge = 1440
    if ($Component.max_age_minutes) { $maxAge = [int]$Component.max_age_minutes }
    $ageMin = [Math]::Round(((Get-Date) - $item.LastWriteTime).TotalMinutes, 1)
    if ($item.Length -le 0) { return [pscustomobject]@{ status = 'fail'; detail = 'log empty' } }
    if ($ageMin -gt $maxAge) { return [pscustomobject]@{ status = 'fail'; detail = "stale: last write $ageMin min ago (max $maxAge)" } }
    return [pscustomobject]@{ status = 'ok'; detail = "fresh: $ageMin min, $($item.Length) bytes" }
}

function Test-TaskComponent {
    param([object]$Component)
    try {
        $name = [string]$Component.task_name
        $path = '\\'
        if ($Component.task_path) { $path = [string]$Component.task_path }
        $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
        if ($null -eq $task) { return [pscustomobject]@{ status = 'absent'; detail = 'scheduled task not found' } }
        return [pscustomobject]@{ status = 'ok'; detail = "state $($task.State)" }
    } catch { return [pscustomobject]@{ status = 'incomplete'; detail = $_.Exception.Message } }
}

function Get-LocalComponentChecks {
    param(
        [string]$RegistryPath = (Join-Path $PSScriptRoot 'components.json')
    )
    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        return @([pscustomobject]@{ id = 'registry'; kind = 'registry'; required = $true; status = 'incomplete'; detail = 'components.json not found' })
    }
    try { $registry = Get-Content -Raw -LiteralPath $RegistryPath | ConvertFrom-Json }
    catch { return @([pscustomobject]@{ id = 'registry'; kind = 'registry'; required = $true; status = 'incomplete'; detail = 'components.json unreadable' }) }

    $results = @()
    $pm2Map = $null
    $pm2Attempted = $false
    foreach ($c in $registry.components) {
        $required = $false
        if ($c.required) { $required = [bool]$c.required }
        $r = [pscustomobject]@{ status = 'incomplete'; detail = 'unsupported kind' }
        switch ([string]$c.kind) {
            'git_repo' { $r = Test-GitRepoComponent -Component $c }
            'http_service' { $r = Test-HttpComponent -Component $c }
            'log_freshness' { $r = Test-LogComponent -Component $c }
            'scheduled_task' { $r = Test-TaskComponent -Component $c }
            'pm2_process' {
                if (-not $pm2Attempted) { $pm2Map = Get-Pm2StatusMap; $pm2Attempted = $true }
                if ($null -eq $pm2Map) { $r = [pscustomobject]@{ status = 'incomplete'; detail = 'node/pm2 unavailable' } }
                else {
                    $entry = @($pm2Map | Where-Object { $_.name -eq [string]$c.pm2_name })
                    if ($entry.Count -eq 0) { $r = [pscustomobject]@{ status = 'absent'; detail = 'not registered in pm2' } }
                    elseif ($entry[0].status -eq 'online') { $r = [pscustomobject]@{ status = 'ok'; detail = "online pid $($entry[0].pid)" } }
                    else { $r = [pscustomobject]@{ status = 'fail'; detail = "pm2 status $($entry[0].status)" } }
                }
            }
        }
        if ($r.status -eq 'absent' -and $required) {
            $r = [pscustomobject]@{ status = 'fail'; detail = "$($r.detail) (required component absent)" }
        }
        $results += [pscustomobject]@{ id = $c.id; kind = $c.kind; required = $required; ownership = [string]$c.ownership; status = $r.status; detail = $r.detail }
    }
    return $results
}
