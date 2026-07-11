# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraAuthMethodsData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        AuthMethodsPolicy     = $null
        MethodConfigurations   = @()
        UserRegistrationDetails = @()
        PasswordResetPolicy    = $null
        AuthorizationPolicy    = $null
        DirectorySettings      = @()
        Errors                 = @{}
    }

    # ── Authentication Methods Policy ─────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting authentication methods policy'
    }
    try {
        $data.AuthMethodsPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authenticationMethodsPolicy'
    } catch {
        $data.Errors['AuthMethodsPolicy'] = $_.Exception.Message
    }

    # ── Authentication Method Configurations ──────────────────────────────
    # The parent authenticationMethodsPolicy already includes the full
    # authenticationMethodConfigurations array. The standalone collection endpoint
    # (.../authenticationMethodsPolicy/authenticationMethodConfigurations) is NOT directly
    # addressable — it 400s on both v1.0 and beta — so source it from the parent object.
    $data.MethodConfigurations = @($data.AuthMethodsPolicy.authenticationMethodConfigurations)

    # ── User Registration Details (MFA status) ────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting MFA registration details'
    }
    try {
        $data.UserRegistrationDetails = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/reports/authenticationMethods/userRegistrationDetails' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['UserRegistrationDetails'] = $_.Exception.Message
    }

    # ── Authorization Policy (SSPR, user settings) ────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting authorization policy'
    }
    try {
        $data.AuthorizationPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authorizationPolicy'
    } catch {
        $data.Errors['AuthorizationPolicy'] = $_.Exception.Message
    }

    # ── Directory Settings (password protection) ──────────────────────────
    # Directory/group settings live at /groupSettings on v1.0 (the bare /settings segment
    # is beta-only and 400s on v1.0). The "Password Rule Settings" template
    # (BannedPasswordList, EnableBannedPasswordCheck, LockoutThreshold, ...) is here.
    try {
        $data.DirectorySettings = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/groupSettings' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['DirectorySettings'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        $mfaCount = @($data.UserRegistrationDetails | Where-Object { $_.isMfaRegistered }).Count
        $totalUsers = $data.UserRegistrationDetails.Count
        Write-ProgressLine -Phase INFILTRATE -Message "MFA registered: $mfaCount / $totalUsers users"
    }

    return $data
}
