param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'response_policy.ps1')

$fixed = @(
    @{ name = 'empty-is-normal'; signals = @(); expected = 'normal' },
    @{ name = 'one-weak-process-is-not-critical'; signals = @(@{ category = 'suspicious_process'; confidence = 'low' }); expected = 'normal' },
    @{ name = 'single-medium-startup-change'; signals = @(@{ category = 'new_startup'; confidence = 'medium' }); expected = 'suspect' },
    @{ name = 'correlated-independent-signals'; signals = @(@{ category = 'auth_anomaly'; confidence = 'high' }, @{ category = 'api_abuse'; confidence = 'high' }); expected = 'high' },
    @{ name = 'confirmed-exfiltration-trips-breaker'; signals = @(@{ category = 'exfiltration'; confidence = 'high' }); expected = 'critical' },
    @{ name = 'unknown-signal-is-ignored'; signals = @(@{ category = 'made_up'; confidence = 'high' }); expected = 'normal' }
)

$checks = @()
foreach ($case in $fixed) {
    $actual = Get-ResponseDecision -Signals $case.signals
    $checks += [pscustomobject]@{ name = $case.name; expected = $case.expected; actual = $actual.level; passed = ($actual.level -eq $case.expected) }
}

# Stable per-day seed: today's novel scenario can be replayed from the report.
$day = Get-Date -Format 'yyyy-MM-dd'
$seed = 17
foreach ($ch in ($day + '|WinDefend-Daily-Campaign').ToCharArray()) { $seed = (($seed * 31) + [int]$ch) % 2147483647 }
$random = [System.Random]::new([int]$seed)
$catalog = @('suspicious_process','new_startup','auth_anomaly','api_abuse','secret_exposure','defender_confirmed','integrity_tamper','exfiltration','log_tamper')
$confidenceCatalog = @('low','medium','high')
$reportPath = Join-Path $OutputDirectory ('campaign-' + (Get-Date -Format 'yyyyMMdd') + '.json')
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$knownSignatures = @{}
Get-ChildItem -LiteralPath $OutputDirectory -Filter 'campaign-*.json' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $reportPath } | ForEach-Object {
    try {
        $oldReport = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
        $signatureParts = @($oldReport.novel_scenario.signals | ForEach-Object { "$($_.category):$($_.confidence)" } | Sort-Object)
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
            $candidate += @{ category = $catalog[$random.Next(0, $catalog.Count)]; confidence = $confidenceCatalog[$random.Next(0, $confidenceCatalog.Count)] }
        }
        $signatureParts = @($candidate | ForEach-Object { "$($_.category):$($_.confidence)" } | Sort-Object)
        $signature = $signatureParts -join '|'
        if (-not $knownSignatures.ContainsKey($signature)) { $novelSignals = $candidate }
    }
    if ($novelSignals.Count -eq 0) { throw 'Could not generate a new daily scenario; campaign marked incomplete.' }
}
$novelDecision = Get-ResponseDecision -Signals $novelSignals

# Bounded policy-engine stress test: synthetic in-memory events only; no network or host changes.
$watch = [System.Diagnostics.Stopwatch]::StartNew()
$fuzzCases = 5000
$errors = 0
for ($i = 0; $i -lt $fuzzCases; $i++) {
    $n = $random.Next(0, 8)
    $signals = @()
    for ($j = 0; $j -lt $n; $j++) {
        $signals += @{ category = $catalog[$random.Next(0, $catalog.Count)]; confidence = $confidenceCatalog[$random.Next(0, $confidenceCatalog.Count)] }
    }
    $decision = Get-ResponseDecision -Signals $signals
    if ($decision.level -notin @('normal','suspect','high','critical') -or $decision.mode -ne 'advisory_simulation') { $errors++ }
}
$watch.Stop()

$passed = (@($checks | Where-Object { -not $_.passed }).Count -eq 0) -and ($errors -eq 0) -and ($watch.Elapsed.TotalSeconds -lt 60)
$report = [pscustomobject]@{
    schema_version = 1
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    mode = 'simulation_only_no_live_response'
    seed = $seed
    fixed_checks = $checks
    novel_scenario = [pscustomobject]@{ signals = $novelSignals; expected_replay_seed = $seed; unique_against_prior_reports = $true; resulting_level = $novelDecision.level }
    stress = [pscustomobject]@{ synthetic_cases = $fuzzCases; errors = $errors; elapsed_seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3); time_budget_seconds = 60 }
    result = if ($passed) { 'PASS' } else { 'FAIL' }
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $reportPath
$report | ConvertTo-Json -Depth 8
if (-not $passed) { exit 1 }

