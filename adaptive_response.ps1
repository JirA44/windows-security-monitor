# Graduated adaptive response executor.
# Guardrail 1: real containment runs ONLY against sandbox-owned components; every other component is journaled as an advisory dry-run recommendation.
# Guardrail 2: no process kill by name (PID + command-line identity required), no file deletion, no fund or trading action, recovery path recorded before any action.
# Guardrail 3: journal-first; if the journal cannot be written, no action is taken (log-loss safety).

function Get-ResponseActionsForLevel {
    param([string]$Level)
    switch ($Level) {
        'critical' { return @('preserve_evidence', 'suspend_sensitive_operations', 'disconnect_affected_component') }
        'high' { return @('preserve_evidence', 'isolate_affected_subject') }
        'suspect' { return @('preserve_evidence', 'increase_sampling', 'limit_affected_operation') }
        default { return @('continue_monitoring') }
    }
}

function Write-ResponseJournalEntry {
    param([string]$Path, [object]$Entry)
    try {
        $line = ($Entry | ConvertTo-Json -Compress -Depth 6)
        Add-Content -LiteralPath $Path -Value $line -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Test-JournalHasExecuted {
    param([string]$Path, [string]$Id)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $tail = @(Get-Content -LiteralPath $Path -Tail 500 -ErrorAction Stop)
        return (@($tail | Where-Object { $_ -match [regex]::Escape('"' + $Id + '"') -and $_ -match '"executed"' }).Count -gt 0)
    } catch { return $false }
}

function Test-SandboxProcessIdentity {
    param([int]$ProcessId)
    try {
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if (-not $cim) { return $false }
        if ($cim.Name -notmatch '(?i)^node') { return $false }
        if ($cim.CommandLine -notmatch 'sandbox_service\.js') { return $false }
        return $true
    } catch { return $false }
}

function Get-SandboxState {
    param([string]$SandboxRoot = (Join-Path $PSScriptRoot 'reports\sandbox'))
    $pidFile = Join-Path $SandboxRoot 'sandbox.pid'
    if (-not (Test-Path -LiteralPath $pidFile)) { return [pscustomobject]@{ running = $false; pid = 0 } }
    try { $sp = [int]((Get-Content -Raw -LiteralPath $pidFile).Trim()) } catch { return [pscustomobject]@{ running = $false; pid = 0 } }
    if ($sp -le 0) { return [pscustomobject]@{ running = $false; pid = 0 } }
    if (Test-SandboxProcessIdentity -ProcessId $sp) { return [pscustomobject]@{ running = $true; pid = $sp } }
    return [pscustomobject]@{ running = $false; pid = 0 }
}

function Wait-SandboxPort {
    param([int]$Port = 18250, [int]$TimeoutSeconds = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(1000)
            if ($ok -and $client.Connected) { $client.Close(); return $true }
            $client.Close()
        } catch { }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Start-SandboxService {
    param([string]$SandboxRoot = (Join-Path $PSScriptRoot 'reports\sandbox'), [int]$Port = 18250)
    $state = Get-SandboxState -SandboxRoot $SandboxRoot
    if ($state.running) { return [pscustomobject]@{ ok = $true; detail = "already running pid $($state.pid)" } }
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ok = $false; detail = 'node unavailable' } }
    $script = Join-Path $PSScriptRoot 'sandbox\sandbox_service.js'
    if (-not (Test-Path -LiteralPath $script)) { return [pscustomobject]@{ ok = $false; detail = 'sandbox_service.js not found' } }
    try {
        New-Item -ItemType Directory -Force -Path $SandboxRoot | Out-Null
        $log = Join-Path $SandboxRoot 'sandbox.log'
        Start-Process -FilePath 'node' -ArgumentList @($script, $Port, $SandboxRoot) -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError ($log + '.err') | Out-Null
        if (Wait-SandboxPort -Port $Port -TimeoutSeconds 10) {
            $state = Get-SandboxState -SandboxRoot $SandboxRoot
            return [pscustomobject]@{ ok = $true; detail = "started pid $($state.pid)" }
        }
        return [pscustomobject]@{ ok = $false; detail = 'port did not come up' }
    } catch { return [pscustomobject]@{ ok = $false; detail = $_.Exception.Message } }
}

function Stop-SandboxService {
    param([string]$SandboxRoot = (Join-Path $PSScriptRoot 'reports\sandbox'))
    $state = Get-SandboxState -SandboxRoot $SandboxRoot
    if (-not $state.running) { return [pscustomobject]@{ ok = $true; detail = 'already stopped' } }
    if (-not (Test-SandboxProcessIdentity -ProcessId $state.pid)) {
        return [pscustomobject]@{ ok = $false; detail = 'pid identity mismatch - refuse to stop' }
    }
    try {
        Stop-Process -Id $state.pid -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        if (Test-SandboxProcessIdentity -ProcessId $state.pid) { return [pscustomobject]@{ ok = $false; detail = 'process still alive after stop' } }
        return [pscustomobject]@{ ok = $true; detail = "stopped pid $($state.pid)" }
    } catch { return [pscustomobject]@{ ok = $false; detail = $_.Exception.Message } }
}

function Invoke-AdaptiveResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Decision,
        [Parameter(Mandatory)][string]$ComponentId,
        [string]$ComponentOwnership = 'production',
        [string]$JournalPath = (Join-Path $PSScriptRoot 'reports\response-journal.jsonl'),
        [string]$SandboxRoot = (Join-Path $PSScriptRoot 'reports\sandbox'),
        [string]$WindowId = (Get-Date -Format 'yyyyMMdd'),
        [switch]$AllowSandboxActions
    )
    $sandboxTargets = @('sandbox-service')
    $isSandbox = ($ComponentId -in $sandboxTargets) -and $ComponentOwnership -eq 'sandbox'
    $level = [string]$Decision.level
    $desired = @(Get-ResponseActionsForLevel -Level $level)
    $journalDir = Split-Path -Parent $JournalPath
    try {
        if ($journalDir -and -not (Test-Path -LiteralPath $journalDir)) { New-Item -ItemType Directory -Force -Path $journalDir -ErrorAction Stop | Out-Null }
    } catch {
        return [pscustomobject]@{ mode = 'adaptive_executor'; result = 'INCOMPLETE'; reason = 'journal_directory_unavailable_no_action_taken'; records = @() }
    }

    $records = @()
    foreach ($action in $desired) {
        $id = "$ComponentId|$action|$WindowId"
        $status = 'recorded_dry_run'
        $detail = 'advisory only: component is not sandbox-owned'
        if ($isSandbox -and $AllowSandboxActions) {
            if ($action -in @('disconnect_affected_component', 'isolate_affected_subject')) {
                $status = 'pending_execution'
                $detail = 'sandbox containment'
            }
        }
        if ($action -eq 'revoke_affected_credentials') {
            $status = 'suppressed_requires_owner'
            $detail = 'credential revocation requires a verified owner action; never automatic'
        }

        if ((Test-JournalHasExecuted -Path $JournalPath -Id $id)) {
            $records += [pscustomobject]@{ id = $id; action = $action; status = 'skipped_duplicate'; detail = 'already executed for this window' }
            continue
        }

        if ($status -eq 'pending_execution') {
            $entry = [pscustomobject]@{ ts_utc = [DateTime]::UtcNow.ToString('o'); id = $id; component = $ComponentId; ownership = $ComponentOwnership; level = $level; action = $action; status = 'executing'; detail = $detail; recovery = 'Start-SandboxService -SandboxRoot <root>' }
            if (-not (Write-ResponseJournalEntry -Path $JournalPath -Entry $entry)) {
                return [pscustomobject]@{ mode = 'adaptive_executor'; result = 'INCOMPLETE'; reason = 'journal_unwritable_no_action_taken'; records = $records }
            }
            $stop = Stop-SandboxService -SandboxRoot $SandboxRoot
            if ($stop.ok) { $entry.status = 'executed'; $entry.detail = $stop.detail } else { $entry.status = 'failed'; $entry.detail = $stop.detail }
            Write-ResponseJournalEntry -Path $JournalPath -Entry $entry | Out-Null
            $records += $entry
            continue
        }

        $entry = [pscustomobject]@{ ts_utc = [DateTime]::UtcNow.ToString('o'); id = $id; component = $ComponentId; ownership = $ComponentOwnership; level = $level; action = $action; status = $status; detail = $detail }
        if (-not (Write-ResponseJournalEntry -Path $JournalPath -Entry $entry)) {
            return [pscustomobject]@{ mode = 'adaptive_executor'; result = 'INCOMPLETE'; reason = 'journal_unwritable_no_action_taken'; records = $records }
        }
        $records += $entry
    }

    $executed = @($records | Where-Object { $_.status -eq 'failed' }).Count
    $result = 'ok'
    if ($executed -gt 0) { $result = 'PARTIAL_FAILURE' }
    return [pscustomobject]@{ mode = 'adaptive_executor'; result = $result; level = $level; component = $ComponentId; records = $records }
}
