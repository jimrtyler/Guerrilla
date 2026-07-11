# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GoogleAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceAccountKeyPath,

        [Parameter(Mandatory)]
        [string]$AdminEmail,

        [string[]]$Scopes = @('https://www.googleapis.com/auth/admin.reports.audit.readonly'),

        [string]$ImpersonateUser,

        [switch]$ForceRefresh
    )

    # Build cache key from sorted scopes + impersonation target
    $impersonateEmail = if ($ImpersonateUser) { $ImpersonateUser } else { $AdminEmail }
    $cacheKey = (($Scopes | Sort-Object) -join '|') + '|' + $impersonateEmail

    # Initialize per-scope token cache
    if (-not $script:TokenCache) {
        $script:TokenCache = @{}
    }

    # Check cached token for this scope set
    if (-not $ForceRefresh -and $script:TokenCache.ContainsKey($cacheKey)) {
        $cached = $script:TokenCache[$cacheKey]
        if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt ($cached.Expiry - 60)) {
            Write-Verbose "Using cached access token for scopes: $($Scopes -join ', ')"
            return $cached.Token
        }
    }

    # Backward compat: also check legacy single-token cache for default scope
    if (-not $ForceRefresh -and -not $ImpersonateUser -and $Scopes.Count -eq 1 -and
        $Scopes[0] -eq 'https://www.googleapis.com/auth/admin.reports.audit.readonly' -and
        $script:CachedAccessToken -and $script:TokenExpiry -and
        [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt ($script:TokenExpiry - 60)) {
        Write-Verbose 'Using cached access token (legacy cache)'
        return $script:CachedAccessToken
    }

    # Read service account JSON
    if (-not (Test-Path $ServiceAccountKeyPath)) {
        throw "Service account key file not found: $ServiceAccountKeyPath"
    }

    $serviceAccount = Get-Content -Path $ServiceAccountKeyPath -Raw | ConvertFrom-Json

    if (-not $serviceAccount.client_email -or -not $serviceAccount.private_key) {
        throw "Invalid service account key file: missing client_email or private_key"
    }

    # Create JWT
    $jwt = New-GoogleJwt `
        -ServiceAccountEmail $serviceAccount.client_email `
        -PrivateKeyPem $serviceAccount.private_key `
        -Scopes $Scopes `
        -ImpersonateUser $impersonateEmail

    # Exchange JWT for access token
    $tokenUri = 'https://oauth2.googleapis.com/token'
    $body = @{
        grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        assertion  = $jwt
    }

    try {
        $response = Invoke-RestMethod -TimeoutSec 30 -Uri $tokenUri -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        throw "Google OAuth2 token exchange failed (HTTP $statusCode): $($_.ErrorDetails.Message ?? $_.Exception.Message)"
    }

    if (-not $response.access_token) {
        throw "Google OAuth2 response did not contain an access_token"
    }

    # Cache in per-scope cache
    $script:TokenCache[$cacheKey] = @{
        Token  = $response.access_token
        Expiry = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $response.expires_in
    }

    # Also update legacy cache for backward compatibility
    if (-not $ImpersonateUser) {
        $script:CachedAccessToken = $response.access_token
        $script:TokenExpiry = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $response.expires_in
    }

    Write-Verbose "Access token obtained, expires in $($response.expires_in) seconds"
    return $response.access_token
}
