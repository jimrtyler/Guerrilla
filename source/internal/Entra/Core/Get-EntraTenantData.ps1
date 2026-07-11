# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraTenantData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        Organization            = $null
        AuthorizationPolicy     = $null
        SecurityDefaults        = $null
        CrossTenantAccess       = $null
        CrossTenantPartners     = @()
        SubscribedSkus          = @()
        AdminUnits              = @()
        Domains                 = @()
        AdminConsentRequestPolicy = $null
        DelegatedAdminRelationships = @()
        Errors                  = @{}
    }

    # ── Organization Settings ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting organization settings'
    }
    try {
        $orgResponse = Invoke-GraphApi -AccessToken $AccessToken -Uri '/organization'
        $data.Organization = if ($orgResponse.value) { $orgResponse.value[0] } else { $orgResponse }
    } catch {
        $data.Errors['Organization'] = $_.Exception.Message
    }

    # ── Authorization Policy ──────────────────────────────────────────────
    try {
        $data.AuthorizationPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authorizationPolicy'
    } catch {
        $data.Errors['AuthorizationPolicy'] = $_.Exception.Message
    }

    # ── Security Defaults ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Checking security defaults'
    }
    try {
        $data.SecurityDefaults = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/identitySecurityDefaultsEnforcementPolicy'
    } catch {
        $data.Errors['SecurityDefaults'] = $_.Exception.Message
    }

    # ── Cross-Tenant Access Policy ────────────────────────────────────────
    # The container (/crossTenantAccessPolicy) carries no b2bCollaboration*
    # settings — those live on the *default* policy. Fetch both and attach the
    # default under .default so EIDTNT-005 evaluates the real B2B posture
    # instead of seeing a null default and falsely passing.
    try {
        $data.CrossTenantAccess = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/crossTenantAccessPolicy'
        $ctapDefault = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/crossTenantAccessPolicy/default'
        if ($data.CrossTenantAccess -and $ctapDefault) {
            $data.CrossTenantAccess | Add-Member -NotePropertyName default `
                -NotePropertyValue $ctapDefault -Force
        } elseif (-not $data.CrossTenantAccess) {
            $data.CrossTenantAccess = $ctapDefault
        }
    } catch {
        $data.Errors['CrossTenantAccess'] = $_.Exception.Message
    }

    # ── Cross-Tenant Partners ─────────────────────────────────────────────
    try {
        $data.CrossTenantPartners = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/crossTenantAccessPolicy/partners' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['CrossTenantPartners'] = $_.Exception.Message
    }

    # ── Subscribed SKUs (Licenses) ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting license inventory'
    }
    try {
        $data.SubscribedSkus = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/subscribedSkus' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['SubscribedSkus'] = $_.Exception.Message
    }

    # ── Administrative Units ──────────────────────────────────────────────
    try {
        $data.AdminUnits = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/directory/administrativeUnits' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AdminUnits'] = $_.Exception.Message
    }

    # ── Domains ───────────────────────────────────────────────────────────
    try {
        $data.Domains = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/domains' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Domains'] = $_.Exception.Message
    }

    # ── Admin Consent Request Policy ──────────────────────────────────────
    try {
        $data.AdminConsentRequestPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/adminConsentRequestPolicy'
    } catch {
        $data.Errors['AdminConsentRequestPolicy'] = $_.Exception.Message
    }

    # ── Partner Delegated Admin (GDAP) Relationships ──────────────────────
    # CSP/partner delegated administration is a Kaseya-class propagation path
    # (compromise one partner -> inherit delegated admin in every downstream
    # customer tenant) yet is invisible in most admin consoles and rarely
    # reviewed. Collected so EIDTNT-015/016 can grade privileged exposure and
    # grant hygiene. Failure is recorded, not swallowed: an empty result reaches
    # the checks as "no relationships" ONLY when the call succeeded — a failed
    # call is Not Assessed via Errors['DelegatedAdminRelationships'], never a pass.
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting partner delegated admin (GDAP) relationships'
    }
    try {
        $data.DelegatedAdminRelationships = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/tenantRelationships/delegatedAdminRelationships' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['DelegatedAdminRelationships'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        $tenantName = $data.Organization.displayName ?? 'Unknown'
        Write-ProgressLine -Phase INFILTRATE -Message "Tenant: $tenantName, $($data.SubscribedSkus.Count) licenses, $($data.AdminUnits.Count) admin units"
    }

    return $data
}
