# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Entra ID Governance dispatcher + checks (entitlement-management access packages).
# Collector: Get-EntraGovernanceData -> $AuditData.Governance. A failed collection is
# Not Assessed via Get-NotAssessedFinding; an empty-but-collected result means
# entitlement management is not in use (nothing to govern) -> PASS, never a false FAIL.
function Invoke-EntraGovernanceChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraGovernanceChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                Write-Warning "Check $($check.id) failed: $($_.Exception.Message)"
            }
        }
    }

    return @($findings)
}

# Shared Not-Assessed guard for the governance checks: a failed collection of the
# assignment policies (or the Governance source as a whole) is Not Assessed.
function Get-GovernanceNaFinding {
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string[]]$SourceKey)
    Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Governance.Errors) `
        -SourceKey $SourceKey -Subject 'Entra ID Governance entitlement-management data'
}

# ── EIDGOV-001: Assignment policies require approval ──────────────────────
function Test-InfiltrationEIDGOV001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-GovernanceNaFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -SourceKey @('Governance', 'AssignmentPolicies')
    if ($na) { return $na }

    $policies = @($AuditData.Governance.AssignmentPolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No entitlement-management assignment policies (entitlement management not in use)' `
            -Details @{ PolicyCount = 0 }
    }

    $noApproval = @($policies | Where-Object { $_.requestApprovalSettings.isApprovalRequired -ne $true })
    $status = if ($noApproval.Count -eq 0) { 'PASS' } else { 'WARN' }
    $cv = if ($status -eq 'PASS') {
        "All $($policies.Count) access-package assignment policies require approval"
    } else {
        "$($noApproval.Count) of $($policies.Count) assignment policies grant access without approval — review"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{
            PolicyCount      = $policies.Count
            NoApprovalCount  = $noApproval.Count
            NoApprovalPolicies = @($noApproval | ForEach-Object { $_.displayName })
        }
}

# ── EIDGOV-002: Assignment policies enforce access reviews ────────────────
function Test-InfiltrationEIDGOV002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-GovernanceNaFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -SourceKey @('Governance', 'AssignmentPolicies')
    if ($na) { return $na }

    $policies = @($AuditData.Governance.AssignmentPolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No entitlement-management assignment policies (entitlement management not in use)' `
            -Details @{ PolicyCount = 0 }
    }

    $noReview = @($policies | Where-Object { $_.reviewSettings.isEnabled -ne $true })
    $status = if ($noReview.Count -eq 0) { 'PASS' } else { 'WARN' }
    $cv = if ($status -eq 'PASS') {
        "All $($policies.Count) assignment policies have access reviews enabled"
    } else {
        "$($noReview.Count) of $($policies.Count) assignment policies have no access reviews — standing access is never re-justified"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{
            PolicyCount   = $policies.Count
            NoReviewCount = $noReview.Count
            NoReviewPolicies = @($noReview | ForEach-Object { $_.displayName })
        }
}

# ── EIDGOV-003: Assignments are time-bound ───────────────────────────────
function Test-InfiltrationEIDGOV003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-GovernanceNaFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -SourceKey @('Governance', 'AssignmentPolicies')
    if ($na) { return $na }

    $policies = @($AuditData.Governance.AssignmentPolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No entitlement-management assignment policies (entitlement management not in use)' `
            -Details @{ PolicyCount = 0 }
    }

    # expiration.type 'noExpiration' (or an absent expiration) = perpetual access.
    $perpetual = @($policies | Where-Object {
        $t = $_.expiration.type
        $null -eq $t -or $t -eq 'noExpiration'
    })
    $status = if ($perpetual.Count -eq 0) { 'PASS' } else { 'WARN' }
    $cv = if ($status -eq 'PASS') {
        "All $($policies.Count) assignment policies expire assignments (time-bound)"
    } else {
        "$($perpetual.Count) of $($policies.Count) assignment policies grant perpetual (never-expiring) access"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{
            PolicyCount    = $policies.Count
            PerpetualCount = $perpetual.Count
            PerpetualPolicies = @($perpetual | ForEach-Object { $_.displayName })
        }
}

# ── EIDGOV-004: External eligibility is controlled ───────────────────────
function Test-InfiltrationEIDGOV004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-GovernanceNaFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -SourceKey @('Governance', 'AssignmentPolicies')
    if ($na) { return $na }

    $policies = @($AuditData.Governance.AssignmentPolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No entitlement-management assignment policies (entitlement management not in use)' `
            -Details @{ PolicyCount = 0 }
    }

    # allowedTargetScope values that include outside-the-tenant users.
    $externalScopes = @('allExternalUsers', 'allConfiguredConnectedOrganizationUsers', 'allMemberUsers')
    $external = @($policies | Where-Object { $externalScopes -contains $_.allowedTargetScope })
    # The dangerous case: external eligibility AND no approval gate.
    $externalNoApproval = @($external | Where-Object { $_.requestApprovalSettings.isApprovalRequired -ne $true })

    if ($externalNoApproval.Count -gt 0) {
        $status = 'FAIL'
        $cv = "$($externalNoApproval.Count) of $($policies.Count) assignment policies allow external/all-users eligibility WITHOUT approval"
    } elseif ($external.Count -gt 0) {
        $status = 'WARN'
        $cv = "$($external.Count) of $($policies.Count) assignment policies allow external eligibility (approval-gated) — confirm scope"
    } else {
        $status = 'PASS'
        $cv = "All $($policies.Count) assignment policies are scoped to internal/specific users"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{
            PolicyCount             = $policies.Count
            ExternalCount           = $external.Count
            ExternalNoApprovalCount = $externalNoApproval.Count
            ExternalNoApprovalPolicies = @($externalNoApproval | ForEach-Object { $_.displayName })
        }
}

# ── EIDGOV-005: Catalog external visibility reviewed ─────────────────────
function Test-InfiltrationEIDGOV005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-GovernanceNaFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -SourceKey @('Governance', 'Catalogs')
    if ($na) { return $na }

    $catalogs = @($AuditData.Governance.Catalogs)
    if ($catalogs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No entitlement-management catalogs (entitlement management not in use)' `
            -Details @{ CatalogCount = 0 }
    }

    $externallyVisible = @($catalogs | Where-Object { $_.isExternallyVisible -eq $true })
    $status = if ($externallyVisible.Count -eq 0) { 'PASS' } else { 'WARN' }
    $cv = if ($status -eq 'PASS') {
        "None of $($catalogs.Count) catalogs are externally visible"
    } else {
        "$($externallyVisible.Count) of $($catalogs.Count) catalogs are externally visible — confirm each is intended for B2B collaboration"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{
            CatalogCount            = $catalogs.Count
            ExternallyVisibleCount  = $externallyVisible.Count
            ExternallyVisibleCatalogs = @($externallyVisible | ForEach-Object { $_.displayName })
        }
}
