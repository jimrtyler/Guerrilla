# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-GoogleAdminApi {
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
        [string]$ItemsProperty,
        [switch]$Quiet
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    $allItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pageToken = $null
    $pageCount = 0

    do {
        # Build query string
        $params = @{}
        if ($QueryParameters) {
            foreach ($key in $QueryParameters.Keys) {
                $params[$key] = $QueryParameters[$key]
            }
        }
        if ($pageToken) {
            $params['pageToken'] = $pageToken
        }

        $queryString = if ($params.Count -gt 0) {
            ($params.GetEnumerator() | ForEach-Object {
                "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value.ToString()))"
            }) -join '&'
        } else { '' }

        $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
        $fullUri = if ($queryString) { "$Uri$separator$queryString" } else { $Uri }

        $response = $null
        for ($attempt = 0; $attempt -lt $MaxRetries; $attempt++) {
            try {
                $invokeParams = @{
                    Uri         = $fullUri
                    Headers     = $headers
                    Method      = $Method
                    ErrorAction = 'Stop'
                    TimeoutSec  = 120
                }
                if ($Body -and $Method -in @('Post', 'Patch')) {
                    $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 10)
                    $invokeParams['ContentType'] = 'application/json'
                }
                $response = Invoke-RestMethod @invokeParams
                break
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -in @(429, 503) -and $attempt -lt ($MaxRetries - 1)) {
                    $wait = [Math]::Pow(2, $attempt + 1)
                    Write-Verbose "Rate limited ($statusCode), waiting ${wait}s..."
                    Start-Sleep -Seconds $wait
                } elseif ($statusCode -eq 400) {
                    $errMsg = $_.ErrorDetails.Message ?? $_.Exception.Message
                    if ($errMsg -match 'Mail service not enabled|FAILED_PRECONDITION') {
                        Write-Verbose "Skipped (service not enabled): $Uri"
                    } else {
                        Write-Warning "API returned 400 for $Uri`: $errMsg"
                    }
                    return $null
                } elseif ($statusCode -in @(401, 403)) {
                    $msg = $_.ErrorDetails.Message ?? $_.Exception.Message
                    throw "Authentication/authorization failed ($statusCode) for $Uri`. Check service account permissions and domain-wide delegation. $msg"
                } elseif ($statusCode -eq 404) {
                    Write-Verbose "Resource not found (404) for $Uri"
                    return $null
                } else {
                    if ($attempt -eq ($MaxRetries - 1)) {
                        Write-Warning "API call failed after $MaxRetries retries for $Uri`: $($_.ErrorDetails.Message ?? $_.Exception.Message)"
                        return $null
                    }
                    $wait = [Math]::Pow(2, $attempt + 1)
                    Start-Sleep -Seconds $wait
                }
            }
        }

        if (-not $response) {
            break
        }

        if ($Paginate -and $ItemsProperty) {
            $items = $response.$ItemsProperty
            if ($items) {
                foreach ($item in @($items)) {
                    $allItems.Add($item)
                }
            }
            $pageToken = $response.nextPageToken
            $pageCount++

            if (-not $Quiet -and $pageCount % 5 -eq 0) {
                Write-Verbose "Fetched $pageCount pages, $($allItems.Count) items so far"
            }
        } else {
            # Non-paginated: return raw response
            return $response
        }
    } while ($Paginate -and $pageToken)

    if ($Paginate) {
        return @($allItems)
    }

    return $response
}
