# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADLdapQueryAnomaly {
    [CmdletBinding()]
    param(
        [array]$RecentlyChanged = @()
    )

    # LDAP query anomaly detection via baseline comparison
    # In a baseline comparison model, we detect high-volume enumeration artifacts:
    # - Unusually high number of recently-changed objects that suggest bulk LDAP enumeration tools
    #   modified metadata (e.g., lastLogon timestamps updated by enumeration)
    # - Objects that appear in recently-changed with whenChanged very close together,
    #   which can indicate automated tooling sweeping through AD

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($RecentlyChanged.Count -eq 0) { return @() }

    # Detect burst patterns in recently changed objects
    # Group changes by minute to find bursts
    $changesByMinute = @{}
    foreach ($obj in $RecentlyChanged) {
        if (-not $obj.whenChanged) { continue }
        try {
            $when = [datetime]::Parse($obj.whenChanged)
            $minuteKey = $when.ToString('yyyyMMddHHmm')
            if (-not $changesByMinute.ContainsKey($minuteKey)) {
                $changesByMinute[$minuteKey] = 0
            }
            $changesByMinute[$minuteKey]++
        } catch { }
    }

    # Flag if any single minute has more than 100 changes (potential enumeration)
    $burstMinutes = @($changesByMinute.GetEnumerator() | Where-Object { $_.Value -gt 100 })

    if ($burstMinutes.Count -eq 0) { return @() }

    $totalBurstChanges = ($burstMinutes | Measure-Object -Property Value -Sum).Sum
    $peakMinute = ($burstMinutes | Sort-Object -Property Value -Descending | Select-Object -First 1)

    $detectionId = "adLdapQueryAnomaly_$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'LDAP Enumeration Burst Detected'
        DetectionType = 'adLdapQueryAnomaly'
        Description   = "LDAP QUERY ANOMALY - $totalBurstChanges object changes detected in $($burstMinutes.Count) burst minute(s). Peak: $($peakMinute.Value) changes at $($peakMinute.Key). This pattern is consistent with automated AD enumeration tools (BloodHound, ADRecon, etc.)."
        Details       = @{
            BurstMinutes      = $burstMinutes.Count
            TotalBurstChanges = $totalBurstChanges
            PeakMinute        = $peakMinute.Key
            PeakCount         = $peakMinute.Value
        }
        Count         = $burstMinutes.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
