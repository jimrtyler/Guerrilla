# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-LoggingAlertingChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'LoggingAlertingChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Fortification$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── LOG-001: Audit Log Retention Settings ────────────────────────────────
function Test-FortificationLOG001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Audit log retention is determined by Workspace edition and BigQuery export configuration
    # Enterprise editions retain admin audit logs for 6 months, other logs vary
    # BigQuery export is recommended for long-term retention
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Customer' -Subject 'tenant information'
    if ($na) { return $na }

    $edition = $AuditData.Tenant.edition ?? $AuditData.Tenant.Edition ?? $null

    if ($edition) {
        $status = switch -Wildcard ($edition) {
            '*enterprise*' { 'PASS' }
            '*business*'   { 'WARN' }
            default        { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Workspace edition: $edition. Log retention varies by edition. Verify BigQuery export for long-term retention" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Edition = $edition; Note = 'Enterprise editions retain admin logs for 6 months. Configure BigQuery export for longer retention' }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Audit log retention settings not determinable via API. Verify in Admin Console > Reporting > Audit and configure BigQuery export for long-term retention' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Log retention varies by Workspace edition. BigQuery export recommended for compliance' }
}

# ── LOG-002: Alert Center Rules Inventory ────────────────────────────────
function Test-FortificationLOG002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'AlertRules' -Subject 'Alert Center rules'
    if ($na) { return $na }

    if ($null -eq $AuditData.AlertRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Alert rules data not available. Verify in Admin Console > Security > Alert center that alert rules are configured for security events' `
            -OrgUnitPath $OrgUnitPath
    }

    $rules = @($AuditData.AlertRules)
    if ($rules.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No alert rules configured. Security events are not being monitored' `
            -OrgUnitPath $OrgUnitPath
    }

    $status = if ($rules.Count -ge 5) { 'PASS' }
              elseif ($rules.Count -ge 2) { 'WARN' }
              else { 'WARN' }

    $ruleNames = @($rules | ForEach-Object { $_.name ?? $_.Name ?? $_.displayName ?? 'Unnamed rule' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($rules.Count) alert rule(s) configured in Alert Center" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ RuleCount = $rules.Count; RuleNames = $ruleNames }
}

# ── LOG-003: Activity Rules Coverage Analysis ────────────────────────────
function Test-FortificationLOG003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'AlertRules' -Subject 'Alert Center rules'
    if ($na) { return $na }

    if (-not $AuditData.AlertRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Alert rules data not available. Verify that activity rules cover login, Drive, Admin, email, and OAuth event categories' `
            -OrgUnitPath $OrgUnitPath
    }

    $rules = @($AuditData.AlertRules)

    # Analyze coverage across key security domains
    $expectedDomains = @('Login', 'Drive', 'Admin', 'Email', 'OAuth')
    $coveredDomains = [System.Collections.Generic.List[string]]::new()
    $uncoveredDomains = [System.Collections.Generic.List[string]]::new()

    foreach ($domain in $expectedDomains) {
        $domainLower = $domain.ToLower()
        $hasCoverage = $false
        foreach ($rule in $rules) {
            $ruleName = ($rule.name ?? $rule.Name ?? $rule.displayName ?? '').ToLower()
            $ruleSource = ($rule.source ?? $rule.Source ?? '').ToLower()
            if ($ruleName -match $domainLower -or $ruleSource -match $domainLower) {
                $hasCoverage = $true
                break
            }
        }
        if ($hasCoverage) { $coveredDomains.Add($domain) }
        else { $uncoveredDomains.Add($domain) }
    }

    $coverageRate = [Math]::Round(($coveredDomains.Count / $expectedDomains.Count) * 100, 0)

    $status = if ($uncoveredDomains.Count -eq 0) { 'PASS' }
              elseif ($uncoveredDomains.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if ($uncoveredDomains.Count -eq 0) {
        "All $($expectedDomains.Count) key security domains have alert coverage ($coverageRate%)"
    } else {
        "$coverageRate% coverage: Missing rules for $($uncoveredDomains -join ', ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            CoveredDomains   = @($coveredDomains)
            UncoveredDomains = @($uncoveredDomains)
            CoverageRate     = $coverageRate
            TotalRules       = $rules.Count
        }
}

# ── LOG-004: Data Export Settings ────────────────────────────────────────
function Test-FortificationLOG004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: cloud_sharing_options.cloud_data_sharing { sharingOptions=enum(DISABLED…) }.
    # This governs whether organizational data may be shared outside the tenant — the
    # closest policy-backed signal for "users can bulk-export org data". DISABLED is secure.
    # (Caveat: this is the cloud-data-sharing control, not the dedicated Google Takeout
    # service toggle, which the Cloud Identity Policy API does not expose separately.)
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'cloud_sharing_options.cloud_data_sharing' -Field 'sharingOptions')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No cloud-data-sharing policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $note = "Cloud data sharing option(s): $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    $enabled = @($vals | Where-Object { "$_" -match '(?i)ENABLED' })
    $disabled = @($vals | Where-Object { "$_" -match '(?i)DISABLED' })

    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Cloud data sharing outside the organization is enabled — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Allows organizational data to be shared/exported outside the domain' }
    }
    if ($disabled.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Cloud data sharing outside the organization is disabled — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    # Unrecognized enum value(s) — never PASS on unknown.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Cloud data sharing option not recognized as secure — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── LOG-005: Admin Email Alerts Configuration ────────────────────────────
function Test-FortificationLOG005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: rule.system_defined_alerts { displayName=str; action={alertCenterAction}; state=enum(ACTIVE…) }.
    # System-defined alert rules are what surface critical admin/security events to Alert Center
    # (and to email recipients). Count the ACTIVE ones. PASS when ≥1 is active.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'rule.system_defined_alerts')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No system-defined alert policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $active = @($vals | Where-Object { "$($_.state)".Trim() -match '(?i)^ACTIVE$' })
    if ($active.Count -gt 0) {
        $names = @($active | ForEach-Object { $_.displayName } | Where-Object { $_ })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "$($active.Count) of $($vals.Count) system-defined alert rule(s) active" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ ActiveCount = $active.Count; TotalRules = $vals.Count; ActiveRules = $names }
    }

    # No active alert rules. Severity is Medium -> WARN (would FAIL only if Critical).
    $status = if ("$($CheckDefinition.severity)" -match '(?i)critical') { 'FAIL' } else { 'WARN' }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "No system-defined alert rules are active ($($vals.Count) defined, none ACTIVE)" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Enable system-defined alert rules so critical admin/security events generate Alert Center notifications' }
}

# ── LOG-006: Reporting API Access ────────────────────────────────────────
function Test-FortificationLOG006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainWideDelegation' -Subject 'domain-wide delegation grants'
    if ($na) { return $na }

    # Check domain-wide delegation for Reports API scopes
    if ($AuditData.DomainWideDelegation) {
        $grants = @($AuditData.DomainWideDelegation)
        $reportsGrants = [System.Collections.Generic.List[string]]::new()

        foreach ($grant in $grants) {
            $clientId = $grant.clientId ?? $grant.ClientId ?? 'Unknown'
            $scopes = $grant.scopes ?? $grant.Scopes ?? @()
            $scopeStr = ($scopes -join ' ').ToLower()

            if ($scopeStr -match 'reports' -or $scopeStr -match 'audit') {
                $reportsGrants.Add($clientId)
            }
        }

        if ($reportsGrants.Count -gt 0) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue "$($reportsGrants.Count) domain-wide delegation grant(s) with Reports/Audit API access. Review for authorization" `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ GrantsWithReportsAccess = @($reportsGrants) }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No domain-wide delegation grants with Reports API access detected' `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Reporting API access review requires domain-wide delegation data. Verify in Admin Console > Security > API controls > Domain-wide delegation' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Reports API access should be restricted to authorized service accounts only' }
}
