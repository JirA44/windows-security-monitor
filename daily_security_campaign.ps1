param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'response_policy.ps1')
. (Join-Path $PSScriptRoot 'local_integration_checks.ps1')

$campaignWatch = [System.Diagnostics.Stopwatch]::StartNew()
$failures = @()
$incomplete = @()
function Write-CampaignProgress {
    param([string]$Section)
    Write-Host ("[campaign {0,7:n1}s] {1}" -f $script:campaignWatch.Elapsed.TotalSeconds, $Section)
}

$fixed = @(
    @{ name = 'empty-is-normal'; signals = @(); expected = 'normal' },
    @{ name = 'one-weak-process-is-not-critical'; signals = @(@{ category = 'suspicious_process'; confidence = 'low' }); expected = 'normal' },
    @{ name = 'single-medium-startup-change'; signals = @(@{ category = 'new_startup'; confidence = 'medium' }); expected = 'suspect' },
    @{ name = 'agent behavior anomaly limits only its sensitive work'; signals = @(@{ category = 'behavior_anomaly'; confidence = 'low'; entity_type = 'agent' }); expected = 'suspect'; required_action = 'pause_sensitive_automation' },
    @{ name = 'prompt injection pauses only affected agent work'; signals = @(@{ category = 'agent_prompt_injection'; confidence = 'low'; entity_type = 'agent' }); expected = 'suspect'; required_action = 'pause_sensitive_automation' },
    @{ name = 'backup tampering is critical'; signals = @(@{ category = 'backup_tamper'; confidence = 'high'; entity_type = 'backup_service' }); expected = 'critical' },
    @{ name = 'correlated-independent-signals'; signals = @(@{ category = 'auth_anomaly'; confidence = 'high' }, @{ category = 'api_abuse'; confidence = 'high' }); expected = 'high' },
    @{ name = 'confirmed-exfiltration-trips-breaker'; signals = @(@{ category = 'exfiltration'; confidence = 'high' }); expected = 'critical' },
    @{ name = 'unknown-signal-is-ignored'; signals = @(@{ category = 'made_up'; confidence = 'high' }); expected = 'normal' }
)

Write-CampaignProgress 'fixed policy checks'
$checks = @()
foreach ($case in $fixed) {
    $actual = Get-ResponseDecision -Signals $case.signals
    $casePassed = $actual.level -eq $case.expected
    if ($case.required_action) { $casePassed = $casePassed -and ($actual.recommended_actions -contains $case.required_action) }
    $checks += [pscustomobject]@{ name = $case.name; expected = $case.expected; actual = $actual.level; required_action = $case.required_action; passed = $casePassed }
}
foreach ($failedCheck in @($checks | Where-Object { -not $_.passed })) { $failures += "fixed check: $($failedCheck.name)" }

$recoveryCases = @(
    @{ name = 'unresolved-cause-stays-paused'; parameters = @{ CurrentState = 'paused'; RootCauseResolved = $false; RemediationVerified = $true; IntegrityVerified = $true; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'paused' },
    @{ name = 'all-recovery-gates-resume'; parameters = @{ CurrentState = 'paused'; RootCauseResolved = $true; RemediationVerified = $true; IntegrityVerified = $true; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'active' },
    @{ name = 'active-threat-blocks-resume'; parameters = @{ CurrentState = 'paused'; ActiveThreatSignal = $true; RootCauseResolved = $true; RemediationVerified = $true; IntegrityVerified = $true; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'paused' },
    @{ name = 'credential-rotation-required'; parameters = @{ CurrentState = 'paused'; RootCauseResolved = $true; RemediationVerified = $true; IntegrityVerified = $true; CredentialRotationRequired = $true; CredentialRotationVerified = $false; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'paused' },
    @{ name = 'regression-repauses-component'; parameters = @{ CurrentState = 'active'; ActiveThreatSignal = $true }; expected = 'paused' }
)
Write-CampaignProgress 'recovery gate checks'
$recoveryChecks = @()
foreach ($case in $recoveryCases) {
    $parameters = $case.parameters
    $actual = Get-AutoResumeDecision @parameters
    $recoveryChecks += [pscustomobject]@{ name = $case.name; expected = $case.expected; actual = $actual.state; passed = ($actual.state -eq $case.expected) }
}
foreach ($failedCheck in @($recoveryChecks | Where-Object { -not $_.passed })) { $failures += "recovery check: $($failedCheck.name)" }

Write-CampaignProgress 'seeded novel scenario'
# Stable per-day seed: today's novel scenario can be replayed from the report.
$day = Get-Date -Format 'yyyy-MM-dd'
$seed = 17
foreach ($ch in ($day + '|WinDefend-Daily-Campaign').ToCharArray()) { $seed = (($seed * 31) + [int]$ch) % 2147483647 }
$random = [System.Random]::new([int]$seed)
$catalog = @('suspicious_process','behavior_anomaly','agent_prompt_injection','credential_replay','swarm_activity','new_startup','auth_anomaly','api_abuse','secret_exposure','defender_confirmed','integrity_tamper','exfiltration','log_tamper','monitor_tamper','backup_tamper','control_plane_compromise','supply_chain_compromise','resource_exhaustion','network_partition','concurrent_race','recovery_regression','data_integrity_loss')
$entityCatalog = @('user','service','service_account','agent','process','api','connector','bot','venue','backup_service','control_plane','monitor','build_pipeline','database','queue','network')
$confidenceCatalog = @('low','medium','high')
$reportPath = Join-Path $OutputDirectory ('campaign-' + (Get-Date -Format 'yyyyMMdd') + '.json')
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$knownSignatures = @{}
Get-ChildItem -LiteralPath $OutputDirectory -Filter 'campaign-*.json' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $reportPath } | ForEach-Object {
    try {
        $oldReport = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
        $signatureParts = @($oldReport.novel_scenario.signals | ForEach-Object { "$($_.category):$($_.confidence):$($_.entity_type)" } | Sort-Object)
        if ($signatureParts.Count -gt 0) { $knownSignatures[$signatureParts -join '|'] = $true }
    } catch { }
}

# Reuse today's scenario on reruns; on a new day, select a deterministic scenario not in prior reports.
$novelSignals = @()
if (Test-Path -LiteralPath $reportPath) {
    try {
        $todayReport = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
        if ([int]$todayReport.seed -eq [int]$seed) { $novelSignals = @($todayReport.novel_scenario.signals) }
    } catch { }
}
if ($novelSignals.Count -eq 0) {
    for ($attempt = 0; $attempt -lt 100 -and $novelSignals.Count -eq 0; $attempt++) {
        $candidate = @()
        $novelCount = 1 + $random.Next(1, 4)
        for ($i = 0; $i -lt $novelCount; $i++) {
            $signal = @{ category = $catalog[$random.Next(0, $catalog.Count)]; confidence = $confidenceCatalog[$random.Next(0, $confidenceCatalog.Count)] }
            if ($signal.category -eq 'behavior_anomaly') { $signal.entity_type = $entityCatalog[$random.Next(0, $entityCatalog.Count)] }
            $candidate += $signal
        }
        $signatureParts = @($candidate | ForEach-Object { "$($_.category):$($_.confidence):$($_.entity_type)" } | Sort-Object)
        $signature = $signatureParts -join '|'
        if (-not $knownSignatures.ContainsKey($signature)) { $novelSignals = $candidate }
    }
    if ($novelSignals.Count -eq 0) { $incomplete += 'could not generate a new daily scenario' }
}
$novelDecision = Get-ResponseDecision -Signals $novelSignals
$replayDecision = Get-ResponseDecision -Signals $novelSignals
$replayVerified = ($replayDecision.level -eq $novelDecision.level) -and ($replayDecision.score -eq $novelDecision.score)
if (-not $replayVerified) { $failures += 'novel scenario is not replayable from the recorded signals' }

Write-CampaignProgress 'policy fuzz (5000 synthetic decisions)'
# Bounded policy-engine stress test: synthetic in-memory events only; no network or host changes.
$policyWatch = [System.Diagnostics.Stopwatch]::StartNew()
$fuzzCases = 5000
$errors = 0
for ($i = 0; $i -lt $fuzzCases; $i++) {
    $n = $random.Next(0, 8)
    $signals = @()
    for ($j = 0; $j -lt $n; $j++) {
        $signal = @{ category = $catalog[$random.Next(0, $catalog.Count)]; confidence = $confidenceCatalog[$random.Next(0, $confidenceCatalog.Count)] }
        if ($signal.category -eq 'behavior_anomaly') { $signal.entity_type = $entityCatalog[$random.Next(0, $entityCatalog.Count)] }
        $signals += $signal
    }
    $decision = Get-ResponseDecision -Signals $signals
    if ($decision.level -notin @('normal','suspect','high','critical') -or $decision.mode -ne 'advisory_simulation') { $errors++ }
    if (@($signals | Where-Object { $_.category -eq 'behavior_anomaly' }).Count -gt 0 -and
        ($decision.level -eq 'normal' -or $decision.recommended_actions -notcontains 'limit_affected_operation')) { $errors++ }
}
$policyWatch.Stop()
if ($errors -gt 0) { $failures += "policy fuzz produced $errors inconsistent decisions" }
if ($policyWatch.Elapsed.TotalSeconds -ge 60) { $failures += 'policy fuzz exceeded its 60s budget' }

# Real local components: read-only observation, absent components are reported, never assumed present.
Write-CampaignProgress 'local component checks (git/pm2/http/logs/tasks)'
$localComponents = @()
try { $localComponents = @(Get-LocalComponentChecks -RegistryPath (Join-Path $PSScriptRoot 'components.json')) }
catch { $incomplete += "local component checks failed: $($_.Exception.Message)" }
foreach ($lc in @($localComponents | Where-Object { $_.status -eq 'fail' })) { $failures += "local component $($lc.id): $($lc.detail)" }
foreach ($lc in @($localComponents | Where-Object { $_.status -eq 'incomplete' })) { $incomplete += "local component $($lc.id) incomplete: $($lc.detail)" }

# Bounded sandbox load and HTTP fuzz: isolated 127.0.0.1 service, synthetic traffic only.
Write-CampaignProgress 'sandbox load + http fuzz'
$sandboxRoot = Join-Path $OutputDirectory 'sandbox'
$sandboxPort = 18250
$load = [pscustomobject]@{ status = 'incomplete'; detail = 'not run' }
$httpFuzz = [pscustomobject]@{ status = 'incomplete'; detail = 'not run' }
$restoration = [pscustomobject]@{ sandbox_stopped = $false; detail = 'not run' }
. (Join-Path $PSScriptRoot 'adaptive_response.ps1')
$nodeAvailable = [bool](Get-Command node -ErrorAction SilentlyContinue)
if (-not $nodeAvailable) { $incomplete += 'node unavailable: sandbox load and fuzz skipped' }
else {
    $start = Start-SandboxService -SandboxRoot $sandboxRoot -Port $sandboxPort
    if (-not $start.ok) { $incomplete += "sandbox service did not start: $($start.detail)" }
    else {
        $loadScript = @'
const http=require('http');
const port=Number(process.argv[1]);const total=Number(process.argv[2]||160);const concurrency=Number(process.argv[3]||4);const budgetMs=Number(process.argv[4]||30000);
const start=Date.now();let done=0,ok=0,errors=0;const lat=[];
function one(){return new Promise(res=>{const t0=Date.now();const req=http.get({host:'127.0.0.1',port,path:'/health',timeout:2000},r=>{r.resume();r.on('end',()=>{lat.push(Date.now()-t0);if(r.statusCode===200)ok++;else errors++;res();});});req.on('error',()=>{errors++;res();});req.on('timeout',()=>{req.destroy();errors++;res();});});}
(async()=>{const lanes=Array.from({length:concurrency},async()=>{while(done<total&&Date.now()-start<budgetMs){done++;await one();}});await Promise.all(lanes);lat.sort((a,b)=>a-b);const p=q=>lat.length?lat[Math.min(lat.length-1,Math.floor(q*lat.length))]:null;process.stdout.write(JSON.stringify({requests:done,ok,errors,p50_ms:p(0.5),p95_ms:p(0.95),elapsed_ms:Date.now()-start}));})().catch(e=>{process.stdout.write(JSON.stringify({error:String(e)}));});
'@
        try {
            $loadRaw = (& node -e $loadScript $sandboxPort 160 4 30000 2>$null | Out-String).Trim()
            $load = [pscustomobject]@{ status = 'ok'; detail = 'bounded load completed'; result = ($loadRaw | ConvertFrom-Json) }
        } catch { $incomplete += "load test failed to run: $($_.Exception.Message)" }
        if ($load.status -eq 'ok' -and $load.result.errors -gt 0) { $failures += "load test saw $($load.result.errors) errors" }

        $fuzzScript = @'
const net=require('net');
const port=Number(process.argv[1]);const iterations=Number(process.argv[2]||100);let s=Number(process.argv[3]||1)>>>0;
function rnd(){s=(s*1664525+1013904223)>>>0;return s/4294967296;}
const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \r\n:%{}[]';
function payload(i){const n=1+Math.floor(rnd()*512);let out='';for(let k=0;k<n;k++)out+=chars[Math.floor(rnd()*chars.length)];
 if(i%4===0)out='GET /'+out.slice(0,50)+' HTTP/1.1\r\nHost: x\r\n\r\n';
 if(i%4===1)out='POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: '+(n+1000)+'\r\n\r\n'+out;
 if(i%4===2)out='\x00\x01\x02'+out;return out;}
(async()=>{let done=0;for(let i=0;i<iterations;i++){await new Promise(res=>{const c=net.connect(port,'127.0.0.1',()=>{c.write(payload(i));setTimeout(()=>{c.destroy();res();},30);});c.on('error',()=>res());c.on('close',()=>res());});done++;}
 process.stdout.write(JSON.stringify({iterations:done}));})().catch(e=>{process.stdout.write(JSON.stringify({error:String(e)}));});
'@
        try {
            $fuzzRaw = (& node -e $fuzzScript $sandboxPort 100 $seed 2>$null | Out-String).Trim()
            $fuzzResult = $fuzzRaw | ConvertFrom-Json
            try {
                $aliveResp = Invoke-WebRequest -Uri "http://127.0.0.1:$sandboxPort/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                $alive = ($aliveResp.StatusCode -eq 200)
            } catch { $alive = $false }
            $httpFuzz = [pscustomobject]@{ status = 'ok'; iterations = $fuzzResult.iterations; server_alive_after = $alive }
            if (-not $alive) { $failures += 'sandbox HTTP server died under fuzz' }
        } catch { $incomplete += "http fuzz failed to run: $($_.Exception.Message)" }

        $stop = Stop-SandboxService -SandboxRoot $sandboxRoot
        $state = Get-SandboxState -SandboxRoot $sandboxRoot
        $restoration = [pscustomobject]@{ sandbox_stopped = ((-not $state.running) -and $stop.ok); detail = $stop.detail }
        if (-not $restoration.sandbox_stopped) { $failures += "sandbox restoration failed: $($stop.detail)" }
    }
}

# Real adaptive-response exercises against the isolated sandbox, including false positives, duplicates, log loss, restart and restoration.
Write-CampaignProgress 'adaptive-response sandbox tests'
$responseSandbox = [pscustomobject]@{ status = 'incomplete'; detail = 'not run' }
$testsScript = Join-Path $PSScriptRoot 'tests\adaptive_response.tests.ps1'
if (-not (Test-Path -LiteralPath $testsScript)) { $incomplete += 'adaptive-response sandbox tests are not installed' }
else {
    $testsProc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $testsScript) -PassThru -WindowStyle Hidden
    $testsTimedOut = -not $testsProc.WaitForExit(180000)
    if ($testsTimedOut) {
        try { $testsProc.Kill() } catch { }
        $testsRoot = Join-Path $PSScriptRoot 'reports\sandbox-tests'
        Stop-SandboxService -SandboxRoot $testsRoot | Out-Null
        $incomplete += 'adaptive-response sandbox tests timed out (180s) and were stopped'
    }
    $testsSummaryPath = Join-Path $PSScriptRoot 'reports\sandbox-tests\tests-summary.json'
    if (-not $testsTimedOut -and (Test-Path -LiteralPath $testsSummaryPath)) {
        try {
            $ts = Get-Content -Raw -LiteralPath $testsSummaryPath | ConvertFrom-Json
            $responseSandbox = [pscustomobject]@{ status = 'ok'; tests_run = $ts.tests_run; passed = $ts.passed; failed = $ts.failed; verdict = $ts.verdict; results = $ts.results }
            if ($ts.failed -gt 0) { $failures += "adaptive-response sandbox tests failed: $($ts.failed)" }
            if ($testsProc.ExitCode -ne 0 -and $ts.failed -eq 0) { $incomplete += 'adaptive-response sandbox tests exited non-zero without a failure summary' }
        } catch { $incomplete += 'adaptive-response sandbox summary unreadable' }
    } else { $incomplete += 'adaptive-response sandbox tests produced no summary' }
}

$campaignWatch.Stop()
$gitBranch = ''
$gitHead = ''
try {
    $gitBranch = (& git -C $PSScriptRoot rev-parse --abbrev-ref HEAD 2>$null | Out-String).Trim()
    $gitHead = (& git -C $PSScriptRoot rev-parse --short HEAD 2>$null | Out-String).Trim()
} catch { }
if (-not $gitHead) { $gitHead = 'not-a-git-checkout' }

$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem } catch { }

$result = 'PASS'
if ($failures.Count -gt 0) { $result = 'FAIL' }
elseif ($incomplete.Count -gt 0) { $result = 'INCOMPLETE' }

$report = [pscustomobject]@{
    schema_version = 3
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    mode = 'simulation_plus_readonly_local_checks_no_live_response'
    seed = $seed
    environment = [pscustomobject]@{
        os = $(if ($os) { [string]$os.Caption } else { 'unknown' })
        os_version = $(if ($os) { [string]$os.Version } else { 'unknown' })
        ps_version = $PSVersionTable.PSVersion.ToString()
        machine = $env:COMPUTERNAME
        repo_branch = $gitBranch
        repo_commit = $gitHead
        script_root = $PSScriptRoot
    }
    resource_limits = [pscustomobject]@{
        policy_fuzz_cases = $fuzzCases
        policy_fuzz_budget_seconds = 60
        load_requests = 160
        load_concurrency = 4
        load_budget_ms = 30000
        http_fuzz_iterations = 100
    }
    fixed_checks = $checks
    recovery_checks = $recoveryChecks
    novel_scenario = [pscustomobject]@{ signals = $novelSignals; expected_replay_seed = $seed; unique_against_prior_reports = $true; resulting_level = $novelDecision.level; replay_verified = $replayVerified }
    stress = [pscustomobject]@{ synthetic_cases = $fuzzCases; errors = $errors; elapsed_seconds = [Math]::Round($policyWatch.Elapsed.TotalSeconds, 3); time_budget_seconds = 60 }
    local_components = $localComponents
    load_test = $load
    http_fuzz = $httpFuzz
    response_sandbox = $responseSandbox
    restoration = $restoration
    duration_seconds = [Math]::Round($campaignWatch.Elapsed.TotalSeconds, 3)
    failures = $failures
    incomplete = $incomplete
    result = $result
}
$report | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $reportPath
$report | ConvertTo-Json -Depth 12
if ($result -eq 'FAIL') { exit 1 }
if ($result -eq 'INCOMPLETE') { exit 2 }
