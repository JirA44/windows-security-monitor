$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'response_policy.ps1')
$tests = @(
    @{ name = 'empty baseline'; signals = @(); expected = 'normal' },
    @{ name = 'weak single signal'; signals = @(@{ category = 'suspicious_process'; confidence = 'low' }); expected = 'normal' },
    @{ name = 'medium startup signal'; signals = @(@{ category = 'new_startup'; confidence = 'medium' }); expected = 'suspect' },
    @{ name = 'correlated signals'; signals = @(@{ category = 'auth_anomaly'; confidence = 'high' }, @{ category = 'api_abuse'; confidence = 'high' }); expected = 'high' },
    @{ name = 'direct critical signal'; signals = @(@{ category = 'exfiltration'; confidence = 'high' }); expected = 'critical' },
    @{ name = 'unknown signal'; signals = @(@{ category = 'not_a_real_signal'; confidence = 'high' }); expected = 'normal' }
)
$failed = 0
foreach ($test in $tests) {
    $result = Get-ResponseDecision -Signals $test.signals
    $ok = $result.level -eq $test.expected -and $result.mode -eq 'advisory_simulation'
    Write-Host (('{0} {1} (expected {2}, got {3})' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $test.name, $test.expected, $result.level))
    if (-not $ok) { $failed++ }
}
if ($failed -gt 0) { exit 1 }

