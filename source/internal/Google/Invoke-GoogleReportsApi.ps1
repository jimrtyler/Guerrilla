# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-GoogleReportsApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [ValidateSet('login', 'admin', 'token', 'user_accounts', 'drive')]
        [string]$ApplicationName,

        [string]$UserKey = 'all',
        [datetime]$StartTime,
        [string]$EventName,
        [int]$MaxRetries = 3,
        [switch]$Quiet
    )

    $baseUri = "https://admin.googleapis.com/admin/reports/v1/activity/users/$UserKey/applications/$ApplicationName"
    $headers = @{ Authorization = "Bearer $AccessToken" }

    $allEvents = [System.Collections.Generic.List[hashtable]]::new()
    $pageToken = $null
    $pageCount = 0

    do {
        # Build query parameters
        $queryParams = @{}
        if ($StartTime) {
            $queryParams['startTime'] = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        }
        if ($EventName) {
            $queryParams['eventName'] = $EventName
        }
        if ($pageToken) {
            $queryParams['pageToken'] = $pageToken
        }
        $queryParams['maxResults'] = 1000

        $queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value))" }) -join '&'
        $uri = if ($queryString) { "$baseUri`?$queryString" } else { $baseUri }

        $response = $null
        for ($attempt = 0; $attempt -lt $MaxRetries; $attempt++) {
            try {
                $response = Invoke-RestMethod -TimeoutSec 30 -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                break
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -in @(429, 503) -and $attempt -lt ($MaxRetries - 1)) {
                    $wait = [Math]::Pow(2, $attempt)
                    Write-Verbose "Rate limited ($statusCode), waiting ${wait}s..."
                    Start-Sleep -Seconds $wait
                } elseif ($statusCode -eq 400) {
                    Write-Warning "Application '$ApplicationName' returned 400: $($_.ErrorDetails.Message ?? $_.Exception.Message)"
                    return @($allEvents)
                } elseif ($statusCode -in @(401, 403)) {
                    throw "Authentication failed ($statusCode) for $ApplicationName. Check service account permissions and domain-wide delegation. $($_.ErrorDetails.Message ?? $_.Exception.Message)"
                } else {
                    if ($attempt -eq ($MaxRetries - 1)) {
                        Write-Warning "API call failed after $MaxRetries retries for $ApplicationName`: $($_.ErrorDetails.Message ?? $_.Exception.Message)"
                        return @($allEvents)
                    }
                    $wait = [Math]::Pow(2, $attempt)
                    Start-Sleep -Seconds $wait
                }
            }
        }

        if (-not $response) {
            Write-Warning "No response received for $ApplicationName after $MaxRetries retries"
            break
        }

        # Parse activities into flat event list
        foreach ($activity in @($response.items)) {
            if (-not $activity) { continue }
            $ipAddress = $activity.ipAddress
            $actorEmail = $activity.actor.email
            $eventTime = $activity.id.time

            foreach ($event in @($activity.events)) {
                if (-not $event) { continue }
                $evtName = $event.name
                $params = @{}
                foreach ($p in @($event.parameters)) {
                    if (-not $p -or -not $p.name) { continue }
                    $val = if ($p.value) { $p.value }
                          elseif ($p.multiValue) { $p.multiValue }
                          elseif ($null -ne $p.boolValue) { $p.boolValue }
                          elseif ($p.intValue) { $p.intValue }
                          else { '' }
                    $params[$p.name] = $val
                }

                $allEvents.Add(@{
                    Timestamp   = $eventTime
                    User        = $actorEmail
                    EventName   = $evtName
                    IpAddress   = $ipAddress
                    Source      = $ApplicationName
                    Params      = $params
                })
            }
        }

        $pageCount++
        if (-not $Quiet -and $pageCount % 10 -eq 0) {
            Write-Progress -Activity "Fetching $ApplicationName events" `
                -Status "Page $pageCount, $($allEvents.Count) events" `
                -PercentComplete -1
        }

        $pageToken = $response.nextPageToken
    } while ($pageToken)

    if (-not $Quiet) {
        Write-Progress -Activity "Fetching $ApplicationName events" -Completed
    }

    return @($allEvents)
}
