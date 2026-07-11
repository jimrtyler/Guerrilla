# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [string]$CertificateThumbprint,

        [securestring]$ClientSecret,

        [string[]]$Scopes = @('https://graph.microsoft.com/.default'),

        [string]$ResourceUrl = 'https://graph.microsoft.com',

        [switch]$DeviceCode,

        [switch]$ForceRefresh
    )

    # Build cache key from tenant + client + resource
    $cacheKey = "$TenantId|$ClientId|$ResourceUrl"

    # Initialize token cache
    if (-not $script:GraphTokenCache) {
        $script:GraphTokenCache = @{}
    }

    # Check cached token
    if (-not $ForceRefresh -and $script:GraphTokenCache.ContainsKey($cacheKey)) {
        $cached = $script:GraphTokenCache[$cacheKey]
        if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt ($cached.Expiry - 120)) {
            Write-Verbose "Using cached Graph access token for $ResourceUrl"
            return $cached.Token
        }
    }

    # Determine auth flow
    if ($DeviceCode) {
        $token = Get-GraphTokenDeviceCode -TenantId $TenantId -ClientId $ClientId -Scopes $Scopes
    } elseif ($CertificateThumbprint) {
        $token = Get-GraphTokenCertificate -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -Scopes $Scopes
    } elseif ($ClientSecret) {
        $token = Get-GraphTokenClientSecret -TenantId $TenantId -ClientId $ClientId `
            -ClientSecret $ClientSecret -Scopes $Scopes
    } else {
        # Try MSAL.PS if available for interactive/cached token
        $token = Get-GraphTokenMSAL -TenantId $TenantId -ClientId $ClientId -Scopes $Scopes
    }

    if (-not $token) {
        throw "Failed to acquire access token for $ResourceUrl. Provide -ClientSecret, -CertificateThumbprint, or -DeviceCode."
    }

    # Cache the token
    $script:GraphTokenCache[$cacheKey] = @{
        Token  = $token.AccessToken
        Expiry = $token.ExpiresOn
    }

    Write-Verbose "Graph access token acquired, expires at $([DateTimeOffset]::FromUnixTimeSeconds($token.ExpiresOn).UtcDateTime.ToString('u'))"
    return $token.AccessToken
}

# ── Client Secret Flow ────────────────────────────────────────────────────
function Get-GraphTokenClientSecret {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [securestring]$ClientSecret,
        [string[]]$Scopes
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $plainSecret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password

    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $ClientId
        client_secret = $plainSecret
        scope         = $Scopes -join ' '
    }

    try {
        $response = Invoke-RestMethod -TimeoutSec 30 -Uri $tokenUri -Method Post -Body $body `
            -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        throw "Graph OAuth2 token request failed (HTTP $statusCode): $($_.ErrorDetails.Message ?? $_.Exception.Message)"
    }

    if (-not $response.access_token) {
        throw 'Graph OAuth2 response did not contain an access_token'
    }

    return @{
        AccessToken = $response.access_token
        ExpiresOn   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $response.expires_in
    }
}

# ── Certificate Flow ──────────────────────────────────────────────────────
function Get-GraphTokenCertificate {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string[]]$Scopes
    )

    # Find certificate in current user or local machine store
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My\$CertificateThumbprint -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My\$CertificateThumbprint -ErrorAction SilentlyContinue
    }
    if (-not $cert) {
        throw "Certificate with thumbprint '$CertificateThumbprint' not found in CurrentUser or LocalMachine store"
    }

    # Build client assertion JWT
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # JWT Header
    $x5t = [Convert]::ToBase64String($cert.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '='
    $headerJson = @{ alg = 'RS256'; typ = 'JWT'; x5t = $x5t } | ConvertTo-Json -Compress
    $headerB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)) -replace '\+', '-' -replace '/', '_' -replace '='

    # JWT Payload
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $payloadJson = @{
        aud = $tokenUri
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now
        exp = $now + 600
    } | ConvertTo-Json -Compress
    $payloadB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) -replace '\+', '-' -replace '/', '_' -replace '='

    # Sign
    $dataToSign = [System.Text.Encoding]::UTF8.GetBytes("$headerB64.$payloadB64")
    $rsaKey = $cert.PrivateKey
    if (-not $rsaKey) {
        $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    }
    $signature = $rsaKey.SignData($dataToSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureB64 = [Convert]::ToBase64String($signature) -replace '\+', '-' -replace '/', '_' -replace '='

    $clientAssertion = "$headerB64.$payloadB64.$signatureB64"

    $body = @{
        grant_type            = 'client_credentials'
        client_id             = $ClientId
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $clientAssertion
        scope                 = $Scopes -join ' '
    }

    try {
        $response = Invoke-RestMethod -TimeoutSec 30 -Uri $tokenUri -Method Post -Body $body `
            -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        throw "Graph certificate auth failed (HTTP $statusCode): $($_.ErrorDetails.Message ?? $_.Exception.Message)"
    }

    if (-not $response.access_token) {
        throw 'Graph OAuth2 certificate response did not contain an access_token'
    }

    return @{
        AccessToken = $response.access_token
        ExpiresOn   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $response.expires_in
    }
}

# ── Device Code Flow ──────────────────────────────────────────────────────
function Get-GraphTokenDeviceCode {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string[]]$Scopes
    )

    $deviceCodeUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        client_id = $ClientId
        scope     = $Scopes -join ' '
    }

    try {
        $deviceResponse = Invoke-RestMethod -TimeoutSec 30 -Uri $deviceCodeUri -Method Post -Body $body `
            -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    } catch {
        throw "Device code request failed: $($_.ErrorDetails.Message ?? $_.Exception.Message)"
    }

    Write-Host $deviceResponse.message -ForegroundColor Yellow

    $pollBody = @{
        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
        client_id   = $ClientId
        device_code = $deviceResponse.device_code
    }

    $expiresAt = [DateTimeOffset]::UtcNow.AddSeconds($deviceResponse.expires_in)
    $interval = [Math]::Max($deviceResponse.interval, 5)

    while ([DateTimeOffset]::UtcNow -lt $expiresAt) {
        Start-Sleep -Seconds $interval
        try {
            $response = Invoke-RestMethod -TimeoutSec 30 -Uri $tokenUri -Method Post -Body $pollBody `
                -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop

            if ($response.access_token) {
                return @{
                    AccessToken = $response.access_token
                    ExpiresOn   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $response.expires_in
                }
            }
        } catch {
            $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errorBody.error -eq 'authorization_pending') {
                continue
            } elseif ($errorBody.error -eq 'slow_down') {
                $interval += 5
                continue
            } else {
                throw "Device code polling failed: $($errorBody.error_description ?? $_.Exception.Message)"
            }
        }
    }

    throw 'Device code authentication timed out'
}

# ── MSAL.PS Flow ──────────────────────────────────────────────────────────
function Get-GraphTokenMSAL {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string[]]$Scopes
    )

    if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
        Write-Verbose 'MSAL.PS module not available, cannot acquire token via MSAL'
        return $null
    }

    Import-Module MSAL.PS -ErrorAction SilentlyContinue
    if (-not (Get-Command Get-MsalToken -ErrorAction SilentlyContinue)) {
        return $null
    }

    try {
        $msalToken = Get-MsalToken -ClientId $ClientId -TenantId $TenantId `
            -Scopes $Scopes -Silent -ErrorAction Stop
        return @{
            AccessToken = $msalToken.AccessToken
            ExpiresOn   = $msalToken.ExpiresOn.ToUnixTimeSeconds()
        }
    } catch {
        try {
            $msalToken = Get-MsalToken -ClientId $ClientId -TenantId $TenantId `
                -Scopes $Scopes -Interactive -ErrorAction Stop
            return @{
                AccessToken = $msalToken.AccessToken
                ExpiresOn   = $msalToken.ExpiresOn.ToUnixTimeSeconds()
            }
        } catch {
            Write-Verbose "MSAL.PS token acquisition failed: $_"
            return $null
        }
    }
}
