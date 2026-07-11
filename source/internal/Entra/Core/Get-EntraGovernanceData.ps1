# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraGovernanceData {
    <#
    .SYNOPSIS
        Collect Entra ID Governance entitlement-management data (access packages,
        catalogs, assignment policies) for the EIDGOV checks.

    .DESCRIPTION
        Access packages are a standing-grant mechanism that is rarely reviewed after
        creation. These endpoints are v1.0 entitlement-management resources. A failed
        fetch is recorded in Errors so the checks report Not Assessed rather than a
        false clean pass; an empty result that COLLECTED successfully means
        entitlement management is simply not in use (nothing to govern).

        NOTE: entitlement-management sub-field names (requestApprovalSettings,
        reviewSettings, expiration, allowedTargetScope, isExternallyVisible) are read
        by the checks and should be confirmed against a live governance-licensed
        tenant; absent fields degrade to the safe branch, never a fabricated verdict.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        AccessPackages    = @()
        Catalogs          = @()
        AssignmentPolicies = @()
        Errors            = @{}
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Entra ID Governance (entitlement management)'
    }

    try {
        $data.AccessPackages = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identityGovernance/entitlementManagement/accessPackages' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AccessPackages'] = $_.Exception.Message
    }

    try {
        $data.Catalogs = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identityGovernance/entitlementManagement/catalogs' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Catalogs'] = $_.Exception.Message
    }

    try {
        $data.AssignmentPolicies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identityGovernance/entitlementManagement/assignmentPolicies' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AssignmentPolicies'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE `
            -Message "Governance: $($data.AccessPackages.Count) access packages, $($data.AssignmentPolicies.Count) assignment policies"
    }

    return $data
}
