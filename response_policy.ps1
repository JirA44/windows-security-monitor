function Get-ResponseDecision {
    [CmdletBinding()]
    param([object[]]$Signals = @())

    $weights = @{
        suspicious_process = 1.0
        new_startup        = 2.0
        auth_anomaly       = 2.0
        api_abuse          = 1.5
        secret_exposure    = 3.0
        defender_confirmed = 4.0
        integrity_tamper   = 3.0
        exfiltration       = 4.0
        log_tamper         = 4.0
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
            score = [double]$weights[[string]$signal.category] * [double]$confidenceValues[$confidence]
        }
    }

    $score = [Math]::Round((($normalized | Measure-Object -Property score -Sum).Sum), 2)
    $independent = @($normalized | Select-Object -ExpandProperty category -Unique).Count
    $criticalDirect = @($normalized | Where-Object {
        $_.confidence -eq 'high' -and $_.category -in @('defender_confirmed','exfiltration','log_tamper')
    }).Count -gt 0

    if ($criticalDirect -or ($independent -ge 2 -and $score -ge 4.0)) {
        $level = 'critical'
        $actions = @('disconnect_affected_component', 'suspend_sensitive_operations', 'preserve_evidence')
    } elseif ($score -ge 2.0) {
        $level = 'high'
        $actions = @('isolate_affected_subject', 'revoke_affected_credentials', 'preserve_evidence')
    } elseif ($score -ge 0.75) {
        $level = 'suspect'
        $actions = @('preserve_evidence', 'increase_sampling')
    } else {
        $level = 'normal'
        $actions = @('continue_monitoring')
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

