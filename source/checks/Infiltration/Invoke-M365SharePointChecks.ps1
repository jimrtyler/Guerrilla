# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-M365SharePointChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365SharePointChecks'
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

# ── M365SPO-001: External Sharing Settings ───────────────────────────
function Test-InfiltrationM365SPO001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'SharePoint') -Subject 'SharePoint configuration'
    if ($na) { return $na }

    $sp = $AuditData.M365Services.SharePoint
    if (-not $sp -or $null -eq $sp.SharingCapability) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SharePoint sharing capability data not available (SPO admin module not connected)'
    }

    $sharingCapability = $sp.SharingCapability

    $status = switch ($sharingCapability) {
        'Disabled'                          { 'PASS' }
        'ExistingExternalUserSharingOnly'   { 'PASS' }
        'ExternalUserSharingOnly'           { 'PASS' }
        'ExternalUserAndGuestSharing'       { 'FAIL' }
        default                             { 'WARN' }
    }

    $description = switch ($sharingCapability) {
        'Disabled'                          { 'External sharing is completely disabled' }
        'ExistingExternalUserSharingOnly'   { 'Sharing restricted to existing external users only' }
        'ExternalUserSharingOnly'           { 'Sharing restricted to authenticated external users only' }
        'ExternalUserAndGuestSharing'       { 'External sharing allows anonymous guest links — consider restricting' }
        default                             { "Unrecognized sharing capability: $sharingCapability" }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            SharingCapability = $sharingCapability
            Status = $status
        }
}

# ── M365SPO-002: Guest Access Expiration ─────────────────────────────
function Test-InfiltrationM365SPO002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'SharePoint') -Subject 'SharePoint configuration'
    if ($na) { return $na }

    $sp = $AuditData.M365Services.SharePoint
    if (-not $sp -or $null -eq $sp.ExternalUserExpireInDays) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SharePoint guest expiration data not available (SPO admin module not connected)'
    }

    $expireDays = $sp.ExternalUserExpireInDays

    $status = if ($expireDays -gt 0 -and $expireDays -le 90) { 'PASS' }
              elseif ($expireDays -gt 90) { 'WARN' }
              else { 'FAIL' }

    $description = if ($expireDays -le 0) {
        'Guest access expiration is NOT configured — external users retain access indefinitely'
    } elseif ($expireDays -le 90) {
        "Guest access expires after $expireDays days (within recommended 90-day window)"
    } else {
        "Guest access expires after $expireDays days (exceeds recommended 90-day maximum)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            ExternalUserExpireInDays = $expireDays
            RecommendedMaxDays = 90
        }
}

# ── M365SPO-003: Default Sharing Link Type ───────────────────────────
function Test-InfiltrationM365SPO003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'SharePoint') -Subject 'SharePoint configuration'
    if ($na) { return $na }

    $sp = $AuditData.M365Services.SharePoint
    if (-not $sp -or $null -eq $sp.DefaultSharingLinkType) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SharePoint default sharing link type data not available (SPO admin module not connected)'
    }

    $linkType = $sp.DefaultSharingLinkType

    $status = switch ($linkType) {
        'Direct'           { 'PASS' }
        'SpecificPeople'   { 'PASS' }
        'Internal'         { 'WARN' }
        'AnonymousAccess'  { 'FAIL' }
        default            { 'WARN' }
    }

    $description = switch ($linkType) {
        'Direct'           { 'Default sharing link scoped to specific people (most restrictive)' }
        'SpecificPeople'   { 'Default sharing link scoped to specific people' }
        'Internal'         { 'Default sharing link scoped to organization — consider restricting to specific people' }
        'AnonymousAccess'  { 'Default sharing link allows anonymous access — strongly recommend restricting' }
        default            { "Unrecognized default sharing link type: $linkType" }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            DefaultSharingLinkType = $linkType
        }
}

# ── M365SPO-004: Site Creation Restrictions ──────────────────────────
function Test-InfiltrationM365SPO004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'SharePoint') -Subject 'SharePoint configuration'
    if ($na) { return $na }

    $sp = $AuditData.M365Services.SharePoint
    if (-not $sp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SharePoint tenant data not available (SPO admin module not connected)'
    }

    # Check SelfServiceSiteCreationDisabled or equivalent property
    $siteCreationDisabled = $sp.SelfServiceSiteCreationDisabled
    $siteCreationManagedPath = $sp.SelfServiceSiteCreationManagedPath

    if ($null -eq $siteCreationDisabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Site creation restriction data not available'
    }

    $status = if ($siteCreationDisabled -eq $true) { 'PASS' } else { 'WARN' }

    $description = if ($siteCreationDisabled -eq $true) {
        'Self-service site creation is disabled — only admins can create sites'
    } else {
        'Self-service site creation is enabled — users can create SharePoint sites without admin approval'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            SelfServiceSiteCreationDisabled = $siteCreationDisabled
            SelfServiceSiteCreationManagedPath = $siteCreationManagedPath
        }
}

# ── M365SPO-005: DLP Policy Configuration ────────────────────────────
function Test-InfiltrationM365SPO005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'SharePoint') -Subject 'SharePoint configuration'
    if ($na) { return $na }

    $dlpPolicies = $AuditData.M365Services.DlpPolicies
    if (-not $dlpPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DLP policy data not available (Purview compliance module not connected)'
    }

    if ($dlpPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No DLP policies configured — sensitive data in SharePoint/OneDrive is unprotected' `
            -Details @{ PolicyCount = 0 }
    }

    # Check for policies that cover SharePoint/OneDrive workloads
    $spoPolicies = @($dlpPolicies | Where-Object {
        $_.Workload -match 'SharePoint' -or
        $_.Workload -match 'OneDriveForBusiness' -or
        $_.Workload -match 'SPO'
    })

    $enabledPolicies = @($dlpPolicies | Where-Object { $_.Mode -eq 'Enable' -or $_.Enabled -eq $true })

    $status = if ($spoPolicies.Count -gt 0 -and $enabledPolicies.Count -gt 0) { 'PASS' }
              elseif ($dlpPolicies.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($dlpPolicies.Count) DLP policies found ($($spoPolicies.Count) covering SharePoint/OneDrive, $($enabledPolicies.Count) enabled)" `
        -Details @{
            TotalPolicyCount = $dlpPolicies.Count
            SharePointPolicyCount = $spoPolicies.Count
            EnabledPolicyCount = $enabledPolicies.Count
            Policies = @($dlpPolicies | Select-Object -First 20 | ForEach-Object {
                @{
                    Name = $_.Name
                    Mode = $_.Mode
                    Workload = $_.Workload
                    Enabled = $_.Enabled
                }
            })
        }
}
