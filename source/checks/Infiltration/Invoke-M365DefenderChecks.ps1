# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-M365DefenderChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365DefenderChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ── M365DEF-001: Preset Security Policies ────────────────────────────
function Test-InfiltrationM365DEF001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Defender') -Subject 'Defender for Office configuration'
    if ($na) { return $na }

    $defender = $AuditData.M365Services.Defender
    if (-not $defender -or -not $defender.ProtectionPolicyRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Defender for Office 365 protection policy data not available (EXO module not connected or no Defender license)'
    }

    $rules = $defender.ProtectionPolicyRules
    if ($rules.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No preset security policy rules found — consider enabling Standard or Strict preset policies' `
            -Details @{ PresetPolicyCount = 0 }
    }

    # Check for Standard and Strict preset policies
    $standardPreset = @($rules | Where-Object {
        $_.Name -match 'Standard' -or $_.Identity -match 'Standard'
    })
    $strictPreset = @($rules | Where-Object {
        $_.Name -match 'Strict' -or $_.Identity -match 'Strict'
    })

    $enabledRules = @($rules | Where-Object { $_.State -eq 'Enabled' })

    $status = if ($strictPreset.Count -gt 0 -and ($strictPreset | Where-Object { $_.State -eq 'Enabled' })) { 'PASS' }
              elseif ($standardPreset.Count -gt 0 -and ($standardPreset | Where-Object { $_.State -eq 'Enabled' })) { 'PASS' }
              elseif ($standardPreset.Count -gt 0 -or $strictPreset.Count -gt 0) { 'WARN' }
              else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Preset policies: $($standardPreset.Count) Standard, $($strictPreset.Count) Strict ($($enabledRules.Count) of $($rules.Count) rules enabled)" `
        -Details @{
            StandardPresetCount = $standardPreset.Count
            StrictPresetCount = $strictPreset.Count
            TotalRules = $rules.Count
            EnabledRules = $enabledRules.Count
            Rules = @($rules | ForEach-Object {
                @{
                    Name = $_.Name
                    Identity = $_.Identity
                    State = $_.State
                    Priority = $_.Priority
                }
            })
        }
}

# ── M365DEF-002: Alert Policy Inventory ──────────────────────────────
function Test-InfiltrationM365DEF002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Defender') -Subject 'Defender for Office configuration'
    if ($na) { return $na }

    $defender = $AuditData.M365Services.Defender
    if (-not $defender -or -not $defender.ProtectionAlerts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Defender protection alert data not available'
    }

    $alerts = $defender.ProtectionAlerts
    if ($alerts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No alert policies found — default alert policies may have been removed' `
            -Details @{ AlertCount = 0 }
    }

    $enabled = @($alerts | Where-Object { $_.IsEnabled -eq $true -or $_.Disabled -eq $false })
    $disabled = @($alerts | Where-Object { $_.IsEnabled -eq $false -or $_.Disabled -eq $true })

    # Group by severity for reporting
    $highSeverity = @($alerts | Where-Object { $_.Severity -eq 'High' })
    $mediumSeverity = @($alerts | Where-Object { $_.Severity -eq 'Medium' })
    $lowSeverity = @($alerts | Where-Object { $_.Severity -eq 'Low' -or $_.Severity -eq 'Informational' })

    # Check that critical default alerts are enabled
    $disabledHighSeverity = @($disabled | Where-Object { $_.Severity -eq 'High' })

    $status = if ($disabledHighSeverity.Count -gt 0) { 'FAIL' }
              elseif ($disabled.Count -gt 0) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($alerts.Count) alert policies ($($enabled.Count) enabled, $($disabled.Count) disabled). Severity: $($highSeverity.Count) High, $($mediumSeverity.Count) Medium, $($lowSeverity.Count) Low/Info" `
        -Details @{
            TotalAlerts = $alerts.Count
            EnabledCount = $enabled.Count
            DisabledCount = $disabled.Count
            HighSeverityCount = $highSeverity.Count
            MediumSeverityCount = $mediumSeverity.Count
            LowSeverityCount = $lowSeverity.Count
            DisabledHighSeverityCount = $disabledHighSeverity.Count
            Alerts = @($alerts | Select-Object -First 30 | ForEach-Object {
                @{
                    Name = $_.Name
                    Severity = $_.Severity
                    Category = $_.Category
                    IsEnabled = $_.IsEnabled
                }
            })
        }
}

# ── M365DEF-003: Threat Intelligence Configuration ───────────────────
function Test-InfiltrationM365DEF003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Defender') -Subject 'Defender for Office configuration'
    if ($na) { return $na }

    $defender = $AuditData.M365Services.Defender
    if (-not $defender) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Defender for Office 365 data not available'
    }

    # Check for AIR (Automated Investigation and Response) configuration
    $airConfig = $defender.AIRConfiguration
    $threatExplorer = $defender.ThreatExplorerEnabled

    # If we have no specific threat intel data, check what we can from protection rules
    if (-not $airConfig -and -not $threatExplorer -and -not $defender.ProtectionPolicyRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Threat intelligence configuration data not available — requires Defender for Office 365 Plan 2'
    }

    $issues = [System.Collections.Generic.List[string]]::new()
    $details = @{}

    # Check AIR configuration if available
    if ($airConfig) {
        $details['AIREnabled'] = $airConfig.Enabled
        if ($airConfig.Enabled -ne $true) {
            $issues.Add('Automated Investigation and Response (AIR) is not enabled')
        }
    } else {
        $details['AIREnabled'] = 'Unknown'
        $issues.Add('AIR configuration data not available — may require Defender P2 license')
    }

    # Check Threat Explorer availability
    if ($null -ne $threatExplorer) {
        $details['ThreatExplorerEnabled'] = $threatExplorer
        if ($threatExplorer -ne $true) {
            $issues.Add('Threat Explorer is not enabled')
        }
    } else {
        $details['ThreatExplorerEnabled'] = 'Unknown'
    }

    # Evaluate based on preset policy rules as a proxy for overall Defender configuration
    if ($defender.ProtectionPolicyRules) {
        $details['ProtectionRuleCount'] = $defender.ProtectionPolicyRules.Count
    }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -eq 1 -and $issues[0] -match 'not available') { 'WARN' }
              else { 'WARN' }

    $description = if ($issues.Count -eq 0) {
        'Threat intelligence components (AIR, Threat Explorer) are configured'
    } else {
        "Threat intelligence: $($issues.Count) issue(s) — $($issues -join '; ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details $details
}
