# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-AfterHoursLogin {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @(),

        [int]$BusinessHoursStart = 7,
        [int]$BusinessHoursEnd = 19,
        [string]$Timezone = 'UTC',
        [string[]]$BusinessDays = @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday')
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Resolve timezone
    $tz = try {
        [TimeZoneInfo]::FindSystemTimeZoneById($Timezone)
    } catch {
        try {
            # Try common name mappings
            $mappedTz = switch ($Timezone) {
                'EST' { 'Eastern Standard Time' }
                'CST' { 'Central Standard Time' }
                'MST' { 'Mountain Standard Time' }
                'PST' { 'Pacific Standard Time' }
                default { $Timezone }
            }
            [TimeZoneInfo]::FindSystemTimeZoneById($mappedTz)
        } catch {
            Write-Verbose "Unknown timezone '$Timezone', defaulting to UTC"
            [TimeZoneInfo]::Utc
        }
    }

    $businessDaySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($day in $BusinessDays) { [void]$businessDaySet.Add($day) }

    foreach ($event in $LoginEvents) {
        $ts = if ($event.Timestamp -is [datetime]) { $event.Timestamp } else {
            try { [datetime]::Parse($event.Timestamp) } catch { continue }
        }

        # Convert to local timezone
        $localTime = [TimeZoneInfo]::ConvertTimeFromUtc($ts.ToUniversalTime(), $tz)
        $hour = $localTime.Hour
        $dayName = $localTime.DayOfWeek.ToString()

        $isAfterHours = $false
        $reason = ''

        if (-not $businessDaySet.Contains($dayName)) {
            $isAfterHours = $true
            $reason = "Weekend/non-business day ($dayName)"
        } elseif ($hour -lt $BusinessHoursStart -or $hour -ge $BusinessHoursEnd) {
            $isAfterHours = $true
            $reason = "Outside business hours ($($localTime.ToString('HH:mm')) local, business hours ${BusinessHoursStart}:00-${BusinessHoursEnd}:00)"
        }

        if ($isAfterHours) {
            $results.Add([PSCustomObject]@{
                Timestamp     = $ts
                LocalTime     = $localTime
                IpAddress     = $event.IpAddress
                EventName     = $event.EventName
                DayOfWeek     = $dayName
                LocalHour     = $hour
                Reason        = $reason
                Timezone      = $tz.Id
            })
        }
    }

    return @($results)
}
