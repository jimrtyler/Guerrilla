# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-M365PowerPlatformChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365PowerPlatformChecks'
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

# ── M365PP-001: Environment Creation Restrictions ────────────────────
function Test-InfiltrationM365PP001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'PowerPlatform') -Subject 'Power Platform configuration'
    if ($na) { return $na }

    $pp = $AuditData.M365Services.PowerPlatform
    if (-not $pp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Power Platform data not available (Power Platform admin module not connected)'
    }

    $envCreationRestricted = $pp.EnvironmentCreationRestricted
    $disableEnvironmentCreationByNonAdminUsers = $pp.DisableEnvironmentCreationByNonAdminUsers

    # Check either property depending on data source
    $restricted = $envCreationRestricted -eq $true -or $disableEnvironmentCreationByNonAdminUsers -eq $true

    if ($null -eq $envCreationRestricted -and $null -eq $disableEnvironmentCreationByNonAdminUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Environment creation restriction settings not available'
    }

    $status = if ($restricted) { 'PASS' } else { 'FAIL' }

    $description = if ($restricted) {
        'Environment creation is restricted to administrators only'
    } else {
        'Any user can create Power Platform environments — restrict to admins to prevent sprawl'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            EnvironmentCreationRestricted = $envCreationRestricted
            DisableEnvironmentCreationByNonAdminUsers = $disableEnvironmentCreationByNonAdminUsers
        }
}

# ── M365PP-002: DLP Policies for Connectors ──────────────────────────
function Test-InfiltrationM365PP002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'PowerPlatform') -Subject 'Power Platform configuration'
    if ($na) { return $na }

    $pp = $AuditData.M365Services.PowerPlatform
    if (-not $pp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Power Platform data not available (Power Platform admin module not connected)'
    }

    $dlpPolicies = $pp.DlpPolicies

    if ($null -eq $dlpPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Power Platform DLP policy data not available'
    }

    if ($dlpPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No Power Platform DLP policies configured — connectors are unrestricted and data can flow between any services' `
            -Details @{ PolicyCount = 0 }
    }

    # Check for tenant-wide vs environment-specific policies
    $tenantPolicies = @($dlpPolicies | Where-Object {
        $_.EnvironmentType -eq 'AllEnvironments' -or
        $_.Scope -eq 'Tenant' -or
        $_.IsDefault -eq $true
    })

    $envPolicies = @($dlpPolicies | Where-Object {
        $_.EnvironmentType -ne 'AllEnvironments' -and
        $_.Scope -ne 'Tenant' -and
        $_.IsDefault -ne $true
    })

    $status = if ($tenantPolicies.Count -gt 0) { 'PASS' }
              elseif ($envPolicies.Count -gt 0) { 'WARN' }
              else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($dlpPolicies.Count) DLP policies ($($tenantPolicies.Count) tenant-wide, $($envPolicies.Count) environment-specific)" `
        -Details @{
            TotalPolicies = $dlpPolicies.Count
            TenantWidePolicies = $tenantPolicies.Count
            EnvironmentPolicies = $envPolicies.Count
            Policies = @($dlpPolicies | Select-Object -First 20 | ForEach-Object {
                @{
                    DisplayName = $_.DisplayName
                    EnvironmentType = $_.EnvironmentType
                    Scope = $_.Scope
                    IsDefault = $_.IsDefault
                    CreatedTime = $_.CreatedTime
                }
            })
        }
}

# ── M365PP-003: Tenant Isolation ─────────────────────────────────────
function Test-InfiltrationM365PP003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'PowerPlatform') -Subject 'Power Platform configuration'
    if ($na) { return $na }

    $pp = $AuditData.M365Services.PowerPlatform
    if (-not $pp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Power Platform data not available (Power Platform admin module not connected)'
    }

    $tenantIsolationEnabled = $pp.TenantIsolationEnabled
    $tenantIsolationConfig = $pp.TenantIsolationConfig

    if ($null -eq $tenantIsolationEnabled -and $null -eq $tenantIsolationConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Power Platform tenant isolation settings not available'
    }

    # Determine isolation state from available data
    $isolated = $false
    if ($null -ne $tenantIsolationEnabled) {
        $isolated = $tenantIsolationEnabled -eq $true
    } elseif ($null -ne $tenantIsolationConfig) {
        $isolated = $tenantIsolationConfig.Enabled -eq $true -or
                    $tenantIsolationConfig.IsDisabled -eq $false
    }

    $status = if ($isolated) { 'PASS' } else { 'FAIL' }

    $description = if ($isolated) {
        'Power Platform tenant isolation is enabled — cross-tenant connector traffic is blocked'
    } else {
        'Power Platform tenant isolation is NOT enabled — connectors can communicate with external tenants'
    }

    $details = @{
        TenantIsolationEnabled = $isolated
    }

    # Add allowed tenants if available
    if ($tenantIsolationConfig -and $tenantIsolationConfig.AllowedTenants) {
        $details['AllowedTenantCount'] = $tenantIsolationConfig.AllowedTenants.Count
        $details['AllowedTenants'] = @($tenantIsolationConfig.AllowedTenants | Select-Object -First 20 | ForEach-Object {
            @{
                TenantId = $_.TenantId
                TenantName = $_.TenantName
                Direction = $_.Direction
            }
        })
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details $details
}
