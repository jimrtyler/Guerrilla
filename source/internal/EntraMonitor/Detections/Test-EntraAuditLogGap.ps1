# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraAuditLogGap {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @(),

        [int]$GapThresholdHours = 24
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($AuditEvents.Count -lt 2) { return @($results) }

    # Parse and sort all timestamps
    $timestamps = [System.Collections.Generic.List[datetime]]::new()
    foreach ($event in $AuditEvents) {
        $ts = $event.Timestamp
        if (-not $ts) { continue }
        try {
            $dt = if ($ts -is [datetime]) { $ts.ToUniversalTime() } else { [datetime]::Parse($ts).ToUniversalTime() }
            $timestamps.Add($dt)
        } catch {
            continue
        }
    }

    if ($timestamps.Count -lt 2) { return @($results) }

    $timestamps.Sort()

    # Check for gaps exceeding threshold
    for ($i = 0; $i -lt $timestamps.Count - 1; $i++) {
        $gap = $timestamps[$i + 1] - $timestamps[$i]
        if ($gap.TotalHours -ge $GapThresholdHours) {
            $results.Add([PSCustomObject]@{
                GapStart     = $timestamps[$i]
                GapEnd       = $timestamps[$i + 1]
                GapHours     = [Math]::Round($gap.TotalHours, 1)
                GapDays      = [Math]::Round($gap.TotalDays, 1)
                EventsBefore = $i + 1
                EventsAfter  = $timestamps.Count - $i - 1
            })
        }
    }

    return @($results)
}
