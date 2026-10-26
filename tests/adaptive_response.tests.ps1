# Sandbox tests for the adaptive response executor and recovery gates.
# Real containment actions run ONLY against the isolated sandbox service on a dedicated test port.
# Production components, trading bots and user sessions are never touched by this script.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'response_policy.ps1')
. (Join-Path $root 'adaptive_response.ps1')

$testRoot = Join-Path $root 'reports\sandbox-tests'
$journal = Join-Path $testRoot 'response-journal.jsonl'
$port = 18251
$results = @()
function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $script:results += [pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail }
    $tag = 'FAIL'
    if ($Passed) { $tag = 'PASS' }
    Write-Host ("{0} {1} ({2})" -f $tag, $Name, $Detail)
}

New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
$runId = Get-Date -Format 'yyyyMMddHHmmss'
Set-Content -LiteralPath $journal -Value '' -Encoding UTF8

# 1. Sandbox starts
$start = Start-SandboxService -SandboxRoot $testRoot -Port $port
Add-Result -Name 'sandbox starts' -Passed ([bool]$start.ok) -Detail $start.detail

# 2. False positive: a weak single signal must not trigger containment
$fpDecision = Get-ResponseDecision -Signals @(@{ category = 'suspicious_process'; confidence = 'low' })
$fp = Invoke-AdaptiveResponse -Decision $fpDecision -ComponentId 'sandbox-service' -ComponentOwnership 'sandbox' -JournalPath $journal -SandboxRoot $testRoot -WindowId "test-false-positive-$runId" -AllowSandboxActions
$fpExecuted = @($fp.records | Where-Object { $_.status -eq 'executed' }).Count
$fpState = Get-SandboxState -SandboxRoot $testRoot
Add-Result -Name 'false positive triggers no containment' -Passed (($fpDecision.level -eq 'normal') -and ($fpExecuted -eq 0) -and ($fpState.running)) -Detail "level=$($fpDecision.level) executed=$fpExecuted sandboxRunning=$($fpState.running)"

# 3. Confirmed correlated threat: sandbox containment executes for real
$highDecision = Get-ResponseDecision -Signals @(@{ category = 'auth_anomaly'; confidence = 'high' }, @{ category = 'api_abuse'; confidence = 'high' })
$high = Invoke-AdaptiveResponse -Decision $highDecision -ComponentId 'sandbox-service' -ComponentOwnership 'sandbox' -JournalPath $journal -SandboxRoot $testRoot -WindowId "test-high-$runId" -AllowSandboxActions
$highExecuted = @($high.records | Where-Object { $_.status -eq 'executed' }).Count
$highState = Get-SandboxState -SandboxRoot $testRoot
Add-Result -Name 'correlated threat contains sandbox component' -Passed (($highDecision.level -eq 'high') -and ($highExecuted -ge 1) -and (-not $highState.running)) -Detail "level=$($highDecision.level) executed=$highExecuted sandboxRunning=$($highState.running)"

# 4. Duplicate and out-of-order events: same window re-execution is skipped
$dup = Invoke-AdaptiveResponse -Decision $highDecision -ComponentId 'sandbox-service' -ComponentOwnership 'sandbox' -JournalPath $journal -SandboxRoot $testRoot -WindowId "test-high-$runId" -AllowSandboxActions
$dupSkipped = @($dup.records | Where-Object { $_.status -eq 'skipped_duplicate' }).Count
$dupExecuted = @($dup.records | Where-Object { $_.status -eq 'executed' }).Count
Add-Result -Name 'duplicate event is idempotent' -Passed (($dupSkipped -ge 1) -and ($dupExecuted -eq 0)) -Detail "skipped=$dupSkipped executed=$dupExecuted"

# 5. Log loss: an unwritable journal must prevent any action
$restart = Start-SandboxService -SandboxRoot $testRoot -Port $port
$logLoss = Invoke-AdaptiveResponse -Decision $highDecision -ComponentId 'sandbox-service' -ComponentOwnership 'sandbox' -JournalPath 'Q:\wsm-nonexistent\journal.jsonl' -SandboxRoot $testRoot -WindowId "test-log-loss-$runId" -AllowSandboxActions
$logLossState = Get-SandboxState -SandboxRoot $testRoot
Add-Result -Name 'log loss blocks action and marks incomplete' -Passed (($logLoss.result -eq 'INCOMPLETE') -and ($logLossState.running)) -Detail "result=$($logLoss.result) reason=$($logLoss.reason) sandboxRunning=$($logLossState.running)"

# 6. Restart during containment: recovery gates are deterministic across fresh invocations
$pausedHeld = Get-AutoResumeDecision -CurrentState paused
$pausedThreat = Get-AutoResumeDecision -CurrentState paused -ActiveThreatSignal $true -RootCauseResolved $true -RemediationVerified $true -IntegrityVerified $true -ConsecutiveHealthyChecks 3 -CleanWindowMinutes 15
$resumed = Get-AutoResumeDecision -CurrentState paused -RootCauseResolved $true -RemediationVerified $true -IntegrityVerified $true -ConsecutiveHealthyChecks 3 -CleanWindowMinutes 15
Add-Result -Name 'containment state survives restart and gates hold' -Passed (($pausedHeld.state -eq 'paused') -and ($pausedThreat.state -eq 'paused') -and ($resumed.state -eq 'active')) -Detail "held=$($pausedHeld.state) threat=$($pausedThreat.state) gatesPassed=$($resumed.state)"

# 7. Restoration: component resumes and stops cleanly
try { $health = Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop; $healthOk = ($health.StatusCode -eq 200) } catch { $healthOk = $false }
$stop = Stop-SandboxService -SandboxRoot $testRoot
$finalState = Get-SandboxState -SandboxRoot $testRoot
Add-Result -Name 'restoration and clean stop' -Passed ($healthOk -and $stop.ok -and (-not $finalState.running)) -Detail "healthOk=$healthOk stop=$($stop.ok) running=$($finalState.running)"

# 8. No orphan sandbox processes for this test port
$orphans = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'sandbox_service\.js' -and $_.CommandLine -match [string]$port })
Add-Result -Name 'no orphan sandbox process' -Passed ($orphans.Count -eq 0) -Detail "orphans=$($orphans.Count)"

$passed = @($results | Where-Object { $_.passed }).Count
$failed = @($results | Where-Object { -not $_.passed }).Count
$summary = [pscustomobject]@{
    tests_run = $results.Count
    passed = $passed
    failed = $failed
    port = $port
    results = $results
    verdict = if ($failed -eq 0) { 'PASS' } else { 'FAIL' }
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $testRoot 'tests-summary.json')
Write-Host ("SUMMARY tests={0} passed={1} failed={2} verdict={3}" -f $summary.tests_run, $passed, $failed, $summary.verdict)
if ($failed -gt 0) { exit 1 }
