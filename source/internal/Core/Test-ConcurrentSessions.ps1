# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ConcurrentSessions {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @(),

        [int]$WindowMinutes = 5
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($LoginEvents.Count -lt 2) { return @($results) }

    # Parse and sort by timestamp
    $parsed = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($event in $LoginEvents) {
        $ip = $event.IpAddress
        if (-not $ip) { continue }
        $ts = if ($event.Timestamp -is [datetime]) { $event.Timestamp } else {
            try { [datetime]::Parse($event.Timestamp) } catch { continue }
        }
        $parsed.Add(@{
            Timestamp = $ts
            IpAddress = $ip
            EventName = $event.EventName
            Event     = $event
        })
    }

    if ($parsed.Count -lt 2) { return @($results) }

    $sorted = @($parsed | Sort-Object { $_.Timestamp })
    $window = [TimeSpan]::FromMinutes($WindowMinutes)
    $reported = [System.Collections.Generic.HashSet[string]]::new()

    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $current = $sorted[$i]
        $concurrentIps = [System.Collections.Generic.HashSet[string]]::new()
        [void]$concurrentIps.Add($current.IpAddress)
        $concurrentEvents = [System.Collections.Generic.List[hashtable]]::new()
        $concurrentEvents.Add($current)

        for ($j = $i + 1; $j -lt $sorted.Count; $j++) {
            $other = $sorted[$j]
            if (($other.Timestamp - $current.Timestamp) -gt $window) { break }
            if ($other.IpAddress -ne $current.IpAddress) {
                [void]$concurrentIps.Add($other.IpAddress)
                $concurrentEvents.Add($other)
            }
        }

        if ($concurrentIps.Count -ge 2) {
            $key = ($concurrentIps | Sort-Object) -join '|'
            $timeKey = $current.Timestamp.ToString('yyyyMMddHHmm')
            $reportKey = "${key}:${timeKey}"
            if (-not $reported.Contains($reportKey)) {
                [void]$reported.Add($reportKey)
                $results.Add([PSCustomObject]@{
                    WindowStart   = $current.Timestamp
                    WindowEnd     = ($concurrentEvents | Sort-Object { $_.Timestamp } | Select-Object -Last 1).Timestamp
                    DistinctIps   = @($concurrentIps | Sort-Object)
                    IpCount       = $concurrentIps.Count
                    EventCount    = $concurrentEvents.Count
                })
            }
        }
    }

    return @($results)
}
