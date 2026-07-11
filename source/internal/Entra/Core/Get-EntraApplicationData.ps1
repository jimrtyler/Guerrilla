# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraApplicationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        AppRegistrations  = @()
        ServicePrincipals = @()
        ConsentGrants     = @()
        Errors            = @{}
    }

    # ── App Registrations ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting app registrations'
    }
    try {
        $data.AppRegistrations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/applications' `
            -QueryParameters @{
                '$select' = 'id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess,isFallbackPublicClient,web,spa,publicClient'
            } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AppRegistrations'] = $_.Exception.Message
    }

    # ── Service Principals ────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting service principals'
    }
    try {
        $data.ServicePrincipals = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/servicePrincipals' `
            -QueryParameters @{
                '$select' = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials,signInAudience'
            } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['ServicePrincipals'] = $_.Exception.Message
    }

    # ── OAuth2 Permission Grants (Consent) ────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting OAuth2 consent grants'
    }
    try {
        $data.ConsentGrants = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/oauth2PermissionGrants' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['ConsentGrants'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Collected $($data.AppRegistrations.Count) apps, $($data.ServicePrincipals.Count) SPs, $($data.ConsentGrants.Count) consent grants"
    }

    return $data
}
