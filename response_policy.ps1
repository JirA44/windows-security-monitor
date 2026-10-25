function Get-ResponseDecision {
    [CmdletBinding()]
    param([object[]]$Signals = @())

    $weights = @{
        suspicious_process = 1.0
        behavior_anomaly  = 1.0
        agent_prompt_injection = 2.0
        credential_replay = 3.0
        swarm_activity = 2.0
        new_startup        = 2.0
        auth_anomaly       = 2.0
        api_abuse          = 1.5
        secret_exposure    = 3.0
        defender_confirmed = 4.0
        integrity_tamper   = 3.0
        exfiltration       = 4.0
        log_tamper         = 4.0
        monitor_tamper     = 4.0
        backup_tamper      = 4.0
        control_plane_compromise = 4.0
        supply_chain_compromise = 4.0
        resource_exhaustion = 2.0
        network_partition  = 1.0
        concurrent_race    = 2.0
        recovery_regression = 2.0
        data_integrity_loss = 3.0
    }
    $confidenceValues = @{ low = 0.25; medium = 0.60; high = 1.0 }
    $normalized = @()

    foreach ($signal in @($Signals)) {
        if (-not $signal -or -not $weights.ContainsKey([string]$signal.category)) { continue }
        $confidence = [string]$signal.confidence
        if (-not $confidenceValues.ContainsKey($confidence)) { continue }
        $normalized += [pscustomobject]@{
            category = [string]$signal.category
            confidence = $confidence
            entity_type = if ($signal -is [System.Collections.IDictionary] -and $signal.Contains('entity_type')) { [string]$signal['entity_type'] } elseif ($signal.PSObject.Properties['entity_type']) { [string]$signal.entity_type } else { 'system' }
            score = [double]$weights[[string]$signal.category] * [double]$confidenceValues[$confidence]
        }
    }

    $score = [Math]::Round((($normalized | Measure-Object -Property score -Sum).Sum), 2)
    $independent = @($normalized | Select-Object -ExpandProperty category -Unique).Count
    $criticalDirect = @($normalized | Where-Object {
        $_.confidence -eq 'high' -and $_.category -in @('defender_confirmed','exfiltration','log_tamper','monitor_tamper','backup_tamper','control_plane_compromise','supply_chain_compromise','data_integrity_loss')
    }).Count -gt 0
    $behaviorDeviation = @($normalized | Where-Object { $_.category -in @('behavior_anomaly','agent_prompt_injection') }).Count -gt 0

    if ($criticalDirect -or ($independent -ge 2 -and $score -ge 4.0)) {
        $level = 'critical'
        $actions = @('disconnect_affected_component', 'suspend_sensitive_operations', 'preserve_evidence')
    } elseif ($score -ge 2.0) {
        $level = 'high'
        $actions = @('isolate_affected_subject', 'revoke_affected_credentials', 'preserve_evidence')
    } elseif ($behaviorDeviation) {
        # Any unexpected behavioral deviation is suspicious, even when confidence is low.
        # Scope the response to the observed entity and operation; do not disconnect the whole system.
        $level = 'suspect'
        $actions = @('verify_entity_context', 'limit_affected_operation', 'preserve_evidence', 'increase_sampling')
    } elseif ($score -ge 0.75) {
        $level = 'suspect'
        $actions = @('preserve_evidence', 'increase_sampling')
    } else {
        $level = 'normal'
        $actions = @('continue_monitoring')
    }

    if ($behaviorDeviation) {
        $actions += @('verify_entity_context', 'limit_affected_operation')
        if (@($normalized | Where-Object { $_.category -eq 'behavior_anomaly' -and $_.entity_type -eq 'user' }).Count -gt 0) {
            $actions += 'step_up_identity_verification'
        }
        if (@($normalized | Where-Object { $_.category -eq 'behavior_anomaly' -and $_.entity_type -in @('service','service_account','agent','process','api','connector','bot','venue') }).Count -gt 0) {
            $actions += 'pause_sensitive_automation'
        }
        $actions = @($actions | Select-Object -Unique)
    }

    [pscustomobject]@{
        mode = 'advisory_simulation'
        level = $level
        score = $score
        independent_signal_categories = $independent
        recommended_actions = $actions
        accepted_signal_count = $normalized.Count
    }
}

function Get-AutoResumeDecision {
    [CmdletBinding()]
    param(
        [ValidateSet('active','paused','recovering')][string]$CurrentState = 'active',
        [bool]$ActiveThreatSignal = $false,
        [bool]$RootCauseResolved = $false,
        [bool]$RemediationVerified = $false,
        [bool]$IntegrityVerified = $false,
        [bool]$CredentialRotationRequired = $false,
        [bool]$CredentialRotationVerified = $false,
        [ValidateRange(0,1000)][int]$ConsecutiveHealthyChecks = 0,
        [ValidateRange(1,1000)][int]$RequiredHealthyChecks = 3,
        [ValidateRange(0,100000)][int]$CleanWindowMinutes = 0,
        [ValidateRange(1,100000)][int]$RequiredCleanWindowMinutes = 15
    )

    if ($ActiveThreatSignal) {
        return [pscustomobject]@{ mode = 'advisory_simulation'; state = 'paused'; action = 'pause_affected_component'; reason = 'active_threat_signal' }
    }
    if ($CurrentState -ne 'paused') {
        return [pscustomobject]@{ mode = 'advisory_simulation'; state = $CurrentState; action = 'no_resume_needed'; reason = 'component_not_paused' }
    }

    $credentialReady = (-not $CredentialRotationRequired) -or $CredentialRotationVerified
    $ready = $RootCauseResolved -and $RemediationVerified -and $IntegrityVerified -and $credentialReady -and
        ($ConsecutiveHealthyChecks -ge $RequiredHealthyChecks) -and ($CleanWindowMinutes -ge $RequiredCleanWindowMinutes)
    if ($ready) {
        return [pscustomobject]@{ mode = 'advisory_simulation'; state = 'active'; action = 'resume_affected_component'; reason = 'recovery_gates_passed' }
    }
    return [pscustomobject]@{ mode = 'advisory_simulation'; state = 'paused'; action = 'keep_component_paused'; reason = 'recovery_gates_incomplete' }
}

