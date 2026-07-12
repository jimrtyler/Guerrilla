# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

function Get-GuerrillaCategoryDefinitionName {
    <#
    .SYNOPSIS
        Maps a category check function name to its Data/AuditChecks definition file base name.
    .DESCRIPTION
        Convention: Invoke-<Name> reads Data/AuditChecks/<Name>.json (verified for every
        shipped category function). The one exception is the data-driven EIDSCA dispatcher,
        whose catalog is EidscaChecks.json.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CategoryFunction)

    switch ($CategoryFunction) {
        'Invoke-EntraEidscaChecks' { return 'EidscaChecks' }
        default { return ($CategoryFunction -replace '^Invoke-', '') }
    }
}

function Get-GuerrillaFailedCategoryFinding {
    <#
    .SYNOPSIS
        Synthesizes Not-Assessed (ERROR) findings for every check a failed category
        function would have produced.
    .DESCRIPTION
        When a category check function THROWS, it contributes no findings at all — and
        in the next run-over-run comparison its checks would classify as benign
        "retired" (present before, absent now) instead of lost visibility. That is the
        exact failure mode the run history exists to expose: a broken collector must
        never look like a retired check set.

        This helper loads the failed function's check definitions and emits one ERROR
        finding per check ("Not Assessed" in the run record), so the checks stay
        present in the record and classify as LostVisibility / StillNotAssessed.

        If the definitions genuinely cannot be loaded, it falls back to a single
        synthesized ERROR finding whose id is derived from the category — the failure
        is then still visible in the diff (as one new/lost check) rather than silent.

        Findings are emitted to the pipeline (zero or more objects).
    #>
    [CmdletBinding()]
    param(
        # The category check function that failed, e.g. 'Invoke-ADTrustChecks'.
        [Parameter(Mandatory)][string]$CategoryFunction,

        # Why it failed (exception message); recorded in the finding evidence.
        [Parameter(Mandatory)][AllowEmptyString()][string]$Reason,

        # Org unit scope the category would have been evaluated at (GWS audits pass a TargetOU).
        [string]$OrgUnitPath = '/'
    )

    $defCategory = Get-GuerrillaCategoryDefinitionName -CategoryFunction $CategoryFunction

    $defs = $null
    try {
        $defs = Get-AuditCategoryDefinitions -Category $defCategory
    } catch {
        Write-Verbose "Get-GuerrillaFailedCategoryFinding: no definitions for '$defCategory': $_"
    }

    $currentValue = "Not Assessed — check category '$defCategory' failed to run ($Reason). " +
        'These controls were not evaluated; absence of evidence is not compliance.'
    $details = @{
        NotAssessed            = $true
        FailedCategoryFunction = $CategoryFunction
        CollectionError        = "$Reason"
    }

    if ($defs -and @($defs.checks).Count -gt 0) {
        foreach ($check in @($defs.checks)) {
            New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath -Details $details
        }
        return
    }

    # Fallback: the check set could not be determined. One loud synthetic ERROR
    # finding per failed category, so the failure surfaces in the diff instead of
    # the whole category silently vanishing.
    $syntheticDef = @{
        id              = "CATFAIL-$($defCategory.ToUpperInvariant())"
        name            = "Check category '$defCategory' failed to run"
        severity        = 'High'
        zeroTrustPillar = ''
        description     = "The category function $CategoryFunction threw before producing findings, and its check definitions could not be loaded."
        _categoryName   = $defCategory
    }
    New-AuditFinding -CheckDefinition $syntheticDef -Status 'ERROR' `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath -Details $details
}

function Get-GuerrillaPlatformCheckFunction {
    <#
    .SYNOPSIS
        The full list of category check functions a platform audit runs (Categories = All).
    .DESCRIPTION
        Used by Invoke-Campaign to synthesize Not-Assessed findings for EVERY check of a
        platform whose sub-audit failed outright, so the platform's checks appear in the
        campaign run record (and classify as lost visibility) instead of vanishing.

        Kept in one place next to Get-GuerrillaFailedCategoryFinding; must track the
        categoryMap tables in Invoke-ADAudit / Invoke-EntraAudit / Invoke-GWSAudit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('AD', 'Entra', 'GWS')]
        [string]$Platform
    )

    switch ($Platform) {
        'AD' {
            @('Invoke-ADDomainForestChecks', 'Invoke-ADTrustChecks', 'Invoke-ADPrivilegedAccountChecks',
              'Invoke-ADPasswordPolicyChecks', 'Invoke-ADKerberosChecks', 'Invoke-ADAclDelegationChecks',
              'Invoke-ADGroupPolicyChecks', 'Invoke-ADLogonScriptChecks', 'Invoke-ADCertificateServicesChecks',
              'Invoke-ADStaleObjectChecks', 'Invoke-ADNetworkChecks', 'Invoke-TierZeroChecks',
              'Invoke-ADLoggingChecks', 'Invoke-ADTradecraftChecks', 'Invoke-ADAttackPathChecks')
        }
        'Entra' {
            @('Invoke-EntraCAChecks', 'Invoke-EntraAuthChecks', 'Invoke-EntraPIMChecks', 'Invoke-EntraAppChecks',
              'Invoke-EntraFedChecks', 'Invoke-EntraTenantChecks', 'Invoke-EntraEidscaChecks',
              'Invoke-EntraGovernanceChecks', 'Invoke-EntraAIAgentChecks', 'Invoke-AzureIAMChecks',
              'Invoke-IntuneChecks', 'Invoke-M365ExchangeChecks', 'Invoke-M365SharePointChecks',
              'Invoke-M365TeamsChecks', 'Invoke-M365DefenderChecks', 'Invoke-M365AuditChecks',
              'Invoke-M365PowerPlatformChecks')
        }
        'GWS' {
            @('Invoke-AuthenticationChecks', 'Invoke-EmailSecurityChecks', 'Invoke-DriveSecurityChecks',
              'Invoke-OAuthSecurityChecks', 'Invoke-AdminManagementChecks', 'Invoke-CollaborationChecks',
              'Invoke-DeviceManagementChecks', 'Invoke-LoggingAlertingChecks', 'Invoke-GwsServiceChecks',
              'Invoke-GoogleTradecraftChecks', 'Invoke-K12Checks')
        }
    }
}
