# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-BruteForce {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @(),

        [int]$FailureThreshold = 5,
        [int]$WindowMinutes = 10
    )

    $results = [PSCustomObject]@{
        Detected        = $false
        FailureCount    = 0
        SuccessAfter    = $false
        FailureWindow   = $null
        SuccessEvent    = $null
        AttackingIps    = @()
    }

    # Separate successes and failures
    $failures = [System.Collections.Generic.List[hashtable]]::new()
    $successes = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($event in $LoginEvents) {
        $eventName = $event.EventName
        if ($eventName -eq 'login_failure') {
            $ts = if ($event.Timestamp -is [datetime]) { $event.Timestamp } else {
                try { [datetime]::Parse($event.Timestamp) } catch { continue }
            }
            $failures.Add(@{ Timestamp = $ts; IpAddress = $event.IpAddress; Event = $event })
        } elseif ($eventName -eq 'login_success') {
            $ts = if ($event.Timestamp -is [datetime]) { $event.Timestamp } else {
                try { [datetime]::Parse($event.Timestamp) } catch { continue }
            }
            $successes.Add(@{ Timestamp = $ts; IpAddress = $event.IpAddress; Event = $event })
        }
    }

    if ($failures.Count -lt $FailureThreshold) { return $results }

    # Sort failures by timestamp
    $sortedFailures = @($failures | Sort-Object { $_.Timestamp })
    $window = [TimeSpan]::FromMinutes($WindowMinutes)

    # Sliding window to find burst of failures
    $maxBurstCount = 0
    $bestBurstStart = $null
    $bestBurstEnd = $null
    $bestBurstIps = @()

    for ($i = 0; $i -lt $sortedFailures.Count; $i++) {
        $windowStart = $sortedFailures[$i].Timestamp
        $windowEnd = $windowStart + $window
        $burstIps = [System.Collections.Generic.HashSet[string]]::new()
        $burstCount = 0

        for ($j = $i; $j -lt $sortedFailures.Count; $j++) {
            if ($sortedFailures[$j].Timestamp -gt $windowEnd) { break }
            $burstCount++
            if ($sortedFailures[$j].IpAddress) {
                [void]$burstIps.Add($sortedFailures[$j].IpAddress)
            }
        }

        if ($burstCount -gt $maxBurstCount) {
            $maxBurstCount = $burstCount
            $bestBurstStart = $windowStart
            $bestBurstEnd = $sortedFailures[[Math]::Min($i + $burstCount - 1, $sortedFailures.Count - 1)].Timestamp
            $bestBurstIps = @($burstIps | Sort-Object)
        }
    }

    if ($maxBurstCount -ge $FailureThreshold) {
        $results.Detected = $true
        $results.FailureCount = $maxBurstCount
        $results.AttackingIps = $bestBurstIps
        $results.FailureWindow = [PSCustomObject]@{
            Start    = $bestBurstStart
            End      = $bestBurstEnd
            Duration = ($bestBurstEnd - $bestBurstStart)
        }

        # Check for success after the failure burst
        $sortedSuccesses = @($successes | Sort-Object { $_.Timestamp })
        foreach ($s in $sortedSuccesses) {
            if ($s.Timestamp -gt $bestBurstStart) {
                $results.SuccessAfter = $true
                $results.SuccessEvent = [PSCustomObject]@{
                    Timestamp = $s.Timestamp
                    IpAddress = $s.IpAddress
                }
                break
            }
        }
    }

    return $results
}
