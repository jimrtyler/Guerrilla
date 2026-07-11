# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-AzureRMApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('Get', 'Post', 'Patch', 'Put', 'Delete')]
        [string]$Method = 'Get',

        [hashtable]$Body,
        [hashtable]$QueryParameters,

        [string]$ApiVersion = '2022-12-01',

        [int]$MaxRetries = 3,

        [switch]$Paginate,

        [switch]$Quiet
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
    }

    $baseUrl = 'https://management.azure.com'

    # Build full URI
    $fullUri = if ($Uri -match '^https?://') {
        $Uri
    } else {
        $cleanUri = $Uri.TrimStart('/')
        "$baseUrl/$cleanUri"
    }

    # Ensure api-version is included
    $params = @{}
    if ($QueryParameters) {
        foreach ($key in $QueryParameters.Keys) {
            $params[$key] = $QueryParameters[$key]
        }
    }
    if (-not $params.ContainsKey('api-version') -and -not ($fullUri -match 'api-version=')) {
        $params['api-version'] = $ApiVersion
    }

    if ($params.Count -gt 0) {
        $queryString = ($params.GetEnumerator() | ForEach-Object {
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
                if ($Body -and $Method -in @('Post', 'Patch', 'Put')) {
                    $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 20)
                    $invokeParams['ContentType'] = 'application/json'
                }

                $response = Invoke-RestMethod @invokeParams
                break
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__

                if ($statusCode -eq 429 -and $attempt -lt ($MaxRetries - 1)) {
                    $retryAfter = $_.Exception.Response.Headers |
                        Where-Object { $_.Key -eq 'Retry-After' } |
                        Select-Object -ExpandProperty Value -First 1
                    $wait = if ($retryAfter) { [int]$retryAfter[0] } else { [Math]::Pow(2, $attempt + 1) }
                    Write-Verbose "ARM API throttled (429), waiting ${wait}s"
                    Start-Sleep -Seconds $wait
                } elseif ($statusCode -in @(503, 504) -and $attempt -lt ($MaxRetries - 1)) {
                    $wait = [Math]::Pow(2, $attempt + 1)
                    Write-Verbose "ARM API unavailable ($statusCode), waiting ${wait}s"
                    Start-Sleep -Seconds $wait
                } elseif ($statusCode -eq 400) {
                    Write-Warning "ARM API 400 for $($Uri): $(Get-CleanApiError $_)"
                    return $null
                } elseif ($statusCode -in @(401, 403)) {
                    $cleanMsg = Get-CleanApiError $_
                    throw "ARM API $statusCode for $($Uri): $cleanMsg — Verify Azure RBAC permissions."
                } elseif ($statusCode -eq 404) {
                    Write-Verbose "ARM API resource not found (404) for $requestUri"
                    return $null
                } else {
                    if ($attempt -eq ($MaxRetries - 1)) {
                        Write-Warning "ARM API failed after $MaxRetries retries for $($Uri): $(Get-CleanApiError $_)"
                        return $null
                    }
                    $wait = [Math]::Pow(2, $attempt + 1)
                    Start-Sleep -Seconds $wait
                }
            }
        }

        if (-not $response) { break }

        if ($Paginate) {
            $items = $response.value
            if ($items) {
                foreach ($item in @($items)) {
                    $allItems.Add($item)
                }
            }
            $nextLink = $response.nextLink
            $pageCount++

            if (-not $Quiet -and $pageCount % 5 -eq 0) {
                Write-Verbose "ARM: Fetched $pageCount pages, $($allItems.Count) items"
            }
        } else {
            return $response
        }
    } while ($Paginate -and $nextLink)

    if ($Paginate) {
        return @($allItems)
    }

    return $response
}
