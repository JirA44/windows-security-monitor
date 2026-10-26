$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'response_policy.ps1')
$tests = @(
    @{ name = 'empty baseline'; signals = @(); expected = 'normal' },
    @{ name = 'weak single signal'; signals = @(@{ category = 'suspicious_process'; confidence = 'low' }); expected = 'normal' },
    @{ name = 'medium startup signal'; signals = @(@{ category = 'new_startup'; confidence = 'medium' }); expected = 'suspect' },
    @{ name = 'unexpected user behavior triggers verification'; signals = @(@{ category = 'behavior_anomaly'; confidence = 'low'; entity_type = 'user' }); expected = 'suspect'; required_action = 'step_up_identity_verification' },
    @{ name = 'unexpected agent behavior limits automation'; signals = @(@{ category = 'behavior_anomaly'; confidence = 'low'; entity_type = 'agent' }); expected = 'suspect'; required_action = 'pause_sensitive_automation' },
    @{ name = 'unexpected API behavior is scoped'; signals = @(@{ category = 'behavior_anomaly'; confidence = 'low'; entity_type = 'api' }); expected = 'suspect'; required_action = 'limit_affected_operation' },
    @{ name = 'low-confidence agent prompt injection pauses only automation'; signals = @(@{ category = 'agent_prompt_injection'; confidence = 'low'; entity_type = 'agent' }); expected = 'suspect'; required_action = 'pause_sensitive_automation' },
    @{ name = 'correlated signals'; signals = @(@{ category = 'auth_anomaly'; confidence = 'high' }, @{ category = 'api_abuse'; confidence = 'high' }); expected = 'high' },
    @{ name = 'direct critical signal'; signals = @(@{ category = 'exfiltration'; confidence = 'high' }); expected = 'critical' },
    @{ name = 'backup tampering trips critical response'; signals = @(@{ category = 'backup_tamper'; confidence = 'high'; entity_type = 'backup_service' }); expected = 'critical' },
    @{ name = 'unknown signal'; signals = @(@{ category = 'not_a_real_signal'; confidence = 'high' }); expected = 'normal' }
)
$failed = 0
foreach ($test in $tests) {
    $result = Get-ResponseDecision -Signals $test.signals
    $ok = $result.level -eq $test.expected -and $result.mode -eq 'advisory_simulation'
    if ($test.required_action) { $ok = $ok -and ($result.recommended_actions -contains $test.required_action) }
    Write-Host (('{0} {1} (expected {2}, got {3})' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $test.name, $test.expected, $result.level))
    if (-not $ok) { $failed++ }
}

$recoveryTests = @(
    @{ name = 'unresolved cause keeps component paused'; parameters = @{ CurrentState = 'paused'; RootCauseResolved = $false; RemediationVerified = $true; IntegrityVerified = $true; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'paused' },
    @{ name = 'automatically resume after all gates pass'; parameters = @{ CurrentState = 'paused'; RootCauseResolved = $true; RemediationVerified = $true; IntegrityVerified = $true; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'active' },
    @{ name = 'never resume while threat remains active'; parameters = @{ CurrentState = 'paused'; ActiveThreatSignal = $true; RootCauseResolved = $true; RemediationVerified = $true; IntegrityVerified = $true; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'paused' },
    @{ name = 'credential rotation is a recovery gate'; parameters = @{ CurrentState = 'paused'; RootCauseResolved = $true; RemediationVerified = $true; IntegrityVerified = $true; CredentialRotationRequired = $true; CredentialRotationVerified = $false; ConsecutiveHealthyChecks = 3; CleanWindowMinutes = 15 }; expected = 'paused' },
    @{ name = 'regression re-pauses a running component'; parameters = @{ CurrentState = 'active'; ActiveThreatSignal = $true }; expected = 'paused' }
)
foreach ($test in $recoveryTests) {
    $parameters = $test.parameters
    $result = Get-AutoResumeDecision @parameters
    $ok = $result.state -eq $test.expected
    Write-Host (('{0} {1} (expected {2}, got {3})' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $test.name, $test.expected, $result.state))
    if (-not $ok) { $failed++ }
}
if ($failed -gt 0) { exit 1 }

