# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-GuerrillaConditionalAccess {
    <#
    .SYNOPSIS
        Conditional Access "what-if" simulation — evaluates a simulated sign-in against the tenant's live
        CA policies via the Microsoft Graph evaluate API, and returns the enforced outcome.

    .DESCRIPTION
        Simulates a sign-in against the tenant's live Conditional Access policies. Builds the request
        and POSTs to https://graph.microsoft.com/beta/identity/conditionalAccess/evaluate, then
        normalizes the applied policies into a single verdict (Block / MfaRequired / CompliantDeviceRequired
        / PasswordChangeRequired / Grant / NotApplied / Unknown).

        The evaluate API is in BETA. If the response is empty or an unrecognised shape, the verdict is
        'Unknown' (callers treat that as Not Assessed — never a false PASS).

    .PARAMETER UserId
        Object ID (GUID) of the user to simulate the sign-in for.

    .PARAMETER AccessToken
        Microsoft Graph access token (needs Policy.Read.ConditionalAccess + the CA evaluate beta scope).

    .PARAMETER IncludeApplications
        App ID(s) the sign-in targets. Default 'All'. (Application-context simulation.)

    .PARAMETER UserAction
        Instead of an app, simulate a user action ('registerOrJoinDevices' / 'registerSecurityInformation').

    .PARAMETER DevicePlatform / ClientAppType / SignInRiskLevel / UserRiskLevel / Country / IpAddress
        Optional sign-in conditions, mirroring the Graph what-if conditions.

    .PARAMETER AllResults
        Return all evaluated policies, not just the ones that apply.

    .EXAMPLE
        Test-GuerrillaConditionalAccess -UserId $uid -AccessToken $tok -ClientAppType exchangeActiveSync
        # Is legacy auth blocked for this user? -> .Result should be 'Block'
    #>
    [CmdletBinding(DefaultParameterSetName = 'App')]
    [OutputType('Guerrilla.CAWhatIfResult')]
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$AccessToken,

        [Parameter(ParameterSetName = 'App')][string[]]$IncludeApplications = @('All'),
        [Parameter(ParameterSetName = 'UserAction')]
        [ValidateSet('registerOrJoinDevices', 'registerSecurityInformation')]
        [string[]]$UserAction,

        [ValidateSet('all', 'Android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux')]
        [string]$DevicePlatform,
        [ValidateSet('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'easSupported', 'other')]
        [string]$ClientAppType,
        [ValidateSet('None', 'Low', 'Medium', 'High')][string]$SignInRiskLevel,
        [ValidateSet('None', 'Low', 'Medium', 'High')][string]$UserRiskLevel,
        [string]$Country,
        [string]$IpAddress,
        [switch]$AllResults
    )

    $context = if ($PSCmdlet.ParameterSetName -eq 'UserAction') {
        @{ '@odata.type' = '#microsoft.graph.userActionContext'; userAction = ($(if ($UserAction.Count -eq 1) { $UserAction[0] } else { $UserAction })) }
    } else {
        @{ '@odata.type' = '#microsoft.graph.applicationContext'; includeApplications = @($IncludeApplications) }
    }

    $conditions = @{}
    if ($SignInRiskLevel) { $conditions.signInRiskLevel = $SignInRiskLevel }
    if ($UserRiskLevel)   { $conditions.userRiskLevel = $UserRiskLevel }
    if ($ClientAppType)   { $conditions.clientAppType = $ClientAppType }
    if ($DevicePlatform)  { $conditions.devicePlatform = $DevicePlatform }
    if ($Country)         { $conditions.country = $Country }
    if ($IpAddress)       { $conditions.ipAddress = $IpAddress }

    $body = @{
        AppliedPoliciesOnly = (-not $AllResults)
        signInIdentity      = @{ '@odata.type' = '#microsoft.graph.userSignIn'; userId = $UserId }
        signInContext       = $context
        signInConditions    = $conditions
    }

    $verdict = @{ Result = 'Unknown'; AppliedPolicies = @() }
    $applied = @()
    try {
        $resp = Invoke-GraphApi -AccessToken $AccessToken -Uri '/identity/conditionalAccess/evaluate' `
            -Method Post -Body $body -Beta
        $applied = @($resp.value)
        if (-not $AllResults) { $applied = @($applied | Where-Object { $_.policyApplies -eq $true }) }
        $verdict = ConvertTo-CAWhatIfVerdict -AppliedPolicies $applied
    } catch {
        Write-Warning "CA what-if evaluation failed (beta API): $_"
    }

    [PSCustomObject]@{
        PSTypeName      = 'Guerrilla.CAWhatIfResult'
        UserId          = $UserId
        Context         = ($context.'@odata.type' -replace '#microsoft\.graph\.', '')
        Conditions      = $conditions
        Result          = $verdict.Result
        AppliedPolicies = @($verdict.AppliedPolicies)
        Raw             = $applied
    }
}
