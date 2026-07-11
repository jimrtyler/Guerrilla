# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-CleanApiError {
    <#
    .SYNOPSIS
        Extracts a clean error message from Graph/ARM API error responses.
    .DESCRIPTION
        API error responses come as JSON blobs. This extracts just the code
        and message for clean warning output instead of dumping raw JSON.
    #>
    [CmdletBinding()]
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $raw = $ErrorRecord.ErrorDetails.Message
    if (-not $raw) { return $ErrorRecord.Exception.Message }

    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($parsed.error) {
            $code = $parsed.error.code
            $msg  = $parsed.error.message
            if ($code -and $msg) { return "$code — $msg" }
            if ($msg) { return $msg }
        }
        if ($parsed.error_description) { return $parsed.error_description }
    } catch {
        # Not JSON — return raw but truncate if huge
    }

    if ($raw.Length -gt 200) { return $raw.Substring(0, 200) + '...' }
    return $raw
}

function Invoke-GraphApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('Get', 'Post', 'Patch', 'Delete')]
        [string]$Method = 'Get',

        [hashtable]$Body,
        [hashtable]$QueryParameters,

        [int]$MaxRetries = 3,

        [switch]$Paginate,

        [string]$ApiVersion = 'v1.0',

        [switch]$Beta,

        [switch]$Quiet,

        [int]$ThrottleDelayMs = 0,

        [int]$MaxPages = 0,

        [string]$ConsistencyLevel,

        # By default a could-not-assess failure (non-license 400, retry-exhausted
        # 429/503/504, network/unexpected errors) THROWS, so the calling collector's
        # try/catch records it in its Errors map and dependent checks report
        # "Not Assessed" instead of silently scoring PASS on missing data. Best-effort
        # callers (the continuous-monitoring event collectors) pass this switch to keep
        # the old behavior of returning $null and moving on. 404 (legitimately absent)
        # and license/capability-gated 400 always return $null regardless.
        [switch]$ReturnNullOnError
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
    }
    if ($ConsistencyLevel) {
        $headers['ConsistencyLevel'] = $ConsistencyLevel
    }

    # Determine base URL
    $baseUrl = 'https://graph.microsoft.com'
    $version = if ($Beta) { 'beta' } else { $ApiVersion }

    # If URI is a relative path, prepend base URL + version
    $fullUri = if ($Uri -match '^https?://') {
        $Uri
    } else {
        $cleanUri = $Uri.TrimStart('/')
        "$baseUrl/$version/$cleanUri"
    }

    # Append query parameters
    if ($QueryParameters -and $QueryParameters.Count -gt 0) {
        $queryString = ($QueryParameters.GetEnumerator() | ForEach-Object {
            "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value.ToString()))"
        }) -join '&'
        $separator = if ($fullUri.Contains('?')) { '&' } else { '?' }
        $fullUri = "$fullUri$separator$queryString"
    }

    $allItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $nextLink = $null
    $pageCount = 0

    do {
        $requestUri = if ($nextLink) { $nextLink } else { $fullUri }

        $response = $null
        for ($attempt = 0; $attempt -lt $MaxRetries; $attempt++) {
            try {
                $invokeParams = @{
                    Uri         = $requestUri
                    Headers     = $headers
                    Method      = $Method
                    ErrorAction = 'Stop'
                    TimeoutSec  = 120
                }
                if ($Body -and $Method -in @('Post', 'Patch')) {
                    $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 20)
                    $invokeParams['ContentType'] = 'application/json'
                }

                $response = Invoke-RestMethod @invokeParams
                break
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__

                if ($statusCode -eq 429 -and $attempt -lt ($MaxRetries - 1)) {
                    # Throttled — respect Retry-After header
                    $retryAfter = $_.Exception.Response.Headers |
                        Where-Object { $_.Key -eq 'Retry-After' } |
                        Select-Object -ExpandProperty Value -First 1
                    $wait = if ($retryAfter) { [int]$retryAfter[0] } else { [Math]::Pow(2, $attempt + 1) }
                    Write-Verbose "Graph API throttled (429), waiting ${wait}s (attempt $($attempt + 1)/$MaxRetries)"
                    Start-Sleep -Seconds $wait
                } elseif ($statusCode -in @(503, 504) -and $attempt -lt ($MaxRetries - 1)) {
                    $wait = [Math]::Pow(2, $attempt + 1)
                    Write-Verbose "Graph API unavailable ($statusCode), waiting ${wait}s"
                    Start-Sleep -Seconds $wait
                } elseif ($statusCode -eq 400) {
                    $cleanMsg = Get-CleanApiError $_
                    # License/feature-gated endpoints (e.g. PIM schedule instances need
                    # Entra ID P2) are an expected capability gap, not an error — surface
                    # them quietly so a tenant without P2 doesn't see alarming red warnings.
                    # A capability gap is "known absent", so it always returns $null.
                    if ($cleanMsg -match 'AadPremiumLicenseRequired|Premium License|Entra ID P2|ID Governance license') {
                        Write-Verbose "Graph API 400 (license/capability-gated) for $($Uri): $cleanMsg"
                        return $null
                    }
                    # A generic 400 means we could not assess this source. Fail loud so
                    # the collector records it — returning $null here would let a
                    # dependent check score PASS on data it never actually saw.
                    if ($ReturnNullOnError) {
                        Write-Warning "Graph API 400 for $($Uri): $cleanMsg"
                        return $null
                    }
                    throw "Graph API 400 for $($Uri): $cleanMsg"
                } elseif ($statusCode -in @(401, 403)) {
                    $cleanMsg = Get-CleanApiError $_
                    throw "Graph API $statusCode for $($Uri): $cleanMsg — Verify app permissions (Application, not Delegated) and admin consent."
                } elseif ($statusCode -eq 404) {
                    Write-Verbose "Graph API resource not found (404) for $requestUri"
                    return $null
                } else {
                    if ($attempt -eq ($MaxRetries - 1)) {
                        $cleanMsg = Get-CleanApiError $_
                        # Retries exhausted (throttling, transient 5xx, or network
                        # errors). This is could-not-assess, not "nothing there" — fail
                        # loud by default so the collector records it and dependent
                        # checks report Not Assessed rather than a false PASS.
                        if ($ReturnNullOnError) {
                            Write-Warning "Graph API failed after $MaxRetries retries for $($Uri): $cleanMsg"
                            return $null
                        }
                        throw "Graph API failed after $MaxRetries retries for $($Uri): $cleanMsg"
                    }
                    $wait = [Math]::Pow(2, $attempt + 1)
                    Start-Sleep -Seconds $wait
                }
            }
        }

        if (-not $response) {
            break
        }

        if ($Paginate) {
            # Collect items from value array
            $items = $response.value
            if ($items) {
                foreach ($item in @($items)) {
                    $allItems.Add($item)
                }
            }
            $nextLink = $response.'@odata.nextLink'
            $pageCount++

            if (-not $Quiet -and $pageCount % 5 -eq 0) {
                Write-Verbose "Fetched $pageCount pages, $($allItems.Count) items so far"
            }

            if ($ThrottleDelayMs -gt 0 -and $nextLink) {
                Start-Sleep -Milliseconds $ThrottleDelayMs
            }

            if ($MaxPages -gt 0 -and $pageCount -ge $MaxPages) {
                Write-Verbose "Reached max pages limit ($MaxPages)"
                break
            }
        } else {
            # Non-paginated: return raw response
            return $response
        }
    } while ($Paginate -and $nextLink)

    if ($Paginate) {
        return @($allItems)
    }

    return $response
}

# ── Batch Request Helper ──────────────────────────────────────────────────
function Invoke-GraphBatchRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [hashtable[]]$Requests,

        [switch]$Beta
    )

    $version = if ($Beta) { 'beta' } else { 'v1.0' }
    $batchUri = "https://graph.microsoft.com/$version/`$batch"

    # Process in chunks of 20 (Graph batch limit)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $chunks = for ($i = 0; $i -lt $Requests.Count; $i += 20) {
        , @($Requests[$i..[Math]::Min($i + 19, $Requests.Count - 1)])
    }

    foreach ($chunk in $chunks) {
        $batchBody = @{
            requests = @($chunk | ForEach-Object { $_ })
        }

        $headers = @{
            Authorization  = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }

        try {
            $response = Invoke-RestMethod -Uri $batchUri -Method Post -TimeoutSec 120 `
                -Headers $headers -Body ($batchBody | ConvertTo-Json -Depth 20) -ErrorAction Stop

            foreach ($resp in $response.responses) {
                $results.Add([PSCustomObject]@{
                    Id         = $resp.id
                    Status     = $resp.status
                    Body       = $resp.body
                    Headers    = $resp.headers
                })
            }
        } catch {
            Write-Warning "Graph batch request failed: $(Get-CleanApiError $_)"
        }
    }

    return @($results)
}
