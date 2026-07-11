# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365BulkFileExfiltration {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @(),

        [int]$Threshold = 100,

        [int]$WindowMinutes = 30
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($Events.Count -lt $Threshold) {
        return @($results)
    }

    # Group events by actor for per-user burst detection
    $eventsByActor = @{}
    foreach ($event in $Events) {
        $actor = $event.Actor ?? 'Unknown'
        if (-not $eventsByActor.ContainsKey($actor)) {
            $eventsByActor[$actor] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $eventsByActor[$actor].Add($event)
    }

    foreach ($actor in $eventsByActor.Keys) {
        $actorEvents = @($eventsByActor[$actor])

        if ($actorEvents.Count -lt $Threshold) { continue }

        # Sort by timestamp
        $sorted = @($actorEvents | Sort-Object {
            try { [datetime]::Parse($_.Timestamp) } catch { [datetime]::MinValue }
        })

        # Sliding window detection with 5-minute bucket deduplication
        $detectedWindows = [System.Collections.Generic.HashSet[string]]::new()

        for ($i = 0; $i -lt $sorted.Count; $i++) {
            try {
                $windowStart = [datetime]::Parse($sorted[$i].Timestamp)
            } catch {
                continue
            }
            $windowEnd = $windowStart.AddMinutes($WindowMinutes)

            # Count events in window
            $windowEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
            for ($j = $i; $j -lt $sorted.Count; $j++) {
                try {
                    $evtTime = [datetime]::Parse($sorted[$j].Timestamp)
                } catch {
                    continue
                }
                if ($evtTime -gt $windowEnd) { break }
                $windowEvents.Add($sorted[$j])
            }

            if ($windowEvents.Count -ge $Threshold) {
                # Deduplicate overlapping windows using 5-minute bucketing
                $bucketKey = "$actor|$($windowStart.ToString('yyyyMMddHH'))$([Math]::Floor($windowStart.Minute / 5) * 5)"
                if ($detectedWindows.Contains($bucketKey)) { continue }
                [void]$detectedWindows.Add($bucketKey)

                # Gather file details
                $uniqueFiles = @($windowEvents | ForEach-Object {
                    $_.TargetName ?? 'unknown'
                } | Sort-Object -Unique)

                $activityBreakdown = @{}
                foreach ($evt in $windowEvents) {
                    $act = $evt.Activity ?? 'Unknown'
                    $activityBreakdown[$act] = ($activityBreakdown[$act] ?? 0) + 1
                }

                # Severity assessment
                $severity = if ($windowEvents.Count -ge ($Threshold * 3)) { 'Critical' }
                            elseif ($windowEvents.Count -ge ($Threshold * 2)) { 'High' }
                            else { 'Medium' }

                $results.Add([PSCustomObject]@{
                    Timestamp     = $windowStart.ToString('o')
                    Actor         = $actor
                    DetectionType = 'm365BulkFileExfiltration'
                    Description   = "Bulk file operation: $($windowEvents.Count) files in $WindowMinutes min by $actor ($($uniqueFiles.Count) unique files)"
                    Details       = @{
                        WindowStart       = $windowStart.ToString('o')
                        WindowEnd         = $windowEnd.ToString('o')
                        FileCount         = $windowEvents.Count
                        UniqueFileCount   = $uniqueFiles.Count
                        SampleFiles       = @($uniqueFiles | Select-Object -First 10)
                        ActivityBreakdown = $activityBreakdown
                    }
                    Severity      = $severity
                })

                # Skip ahead past this window to avoid duplicate detections
                for ($k = $i + 1; $k -lt $sorted.Count; $k++) {
                    try {
                        if ([datetime]::Parse($sorted[$k].Timestamp) -gt $windowEnd) {
                            $i = $k - 1
                            break
                        }
                    } catch {
                        continue
                    }
                    if ($k -eq $sorted.Count - 1) { $i = $k }
                }
            }
        }
    }

    return @($results)
}
