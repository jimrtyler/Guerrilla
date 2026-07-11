# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ImpossibleTravel {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @(),

        [hashtable]$GeoData = @{},

        [double]$MaxSpeedKmh = 900
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($LoginEvents.Count -lt 2) { return @($results) }

    # Filter to events with IP and geo data that has coordinates
    $geoEvents = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($event in $LoginEvents) {
        $ip = $event.IpAddress
        if (-not $ip) { continue }
        if (-not $GeoData.ContainsKey($ip) -or -not $GeoData[$ip]) { continue }
        $geo = $GeoData[$ip]
        if ($null -eq $geo.Latitude -or $null -eq $geo.Longitude) { continue }
        if ($geo.Latitude -eq 0 -and $geo.Longitude -eq 0) { continue }
        $geoEvents.Add($event)
    }

    if ($geoEvents.Count -lt 2) { return @($results) }

    # Sort by timestamp
    $sorted = @($geoEvents | Sort-Object { $_.Timestamp })

    # Compare consecutive logins
    for ($i = 0; $i -lt $sorted.Count - 1; $i++) {
        $eventA = $sorted[$i]
        $eventB = $sorted[$i + 1]

        $ipA = $eventA.IpAddress
        $ipB = $eventB.IpAddress
        if ($ipA -eq $ipB) { continue }

        $geoA = $GeoData[$ipA]
        $geoB = $GeoData[$ipB]

        $distanceKm = Get-HaversineDistance -Lat1 $geoA.Latitude -Lon1 $geoA.Longitude `
                                            -Lat2 $geoB.Latitude -Lon2 $geoB.Longitude

        if ($distanceKm -lt 100) { continue }

        $tsA = if ($eventA.Timestamp -is [datetime]) { $eventA.Timestamp } else {
            try { [datetime]::Parse($eventA.Timestamp) } catch { continue }
        }
        $tsB = if ($eventB.Timestamp -is [datetime]) { $eventB.Timestamp } else {
            try { [datetime]::Parse($eventB.Timestamp) } catch { continue }
        }

        $hoursDiff = [Math]::Abs(($tsB - $tsA).TotalHours)
        if ($hoursDiff -lt 0.01) { $hoursDiff = 0.01 }

        $requiredSpeed = $distanceKm / $hoursDiff

        if ($requiredSpeed -gt $MaxSpeedKmh) {
            $results.Add([PSCustomObject]@{
                FromIp          = $ipA
                ToIp            = $ipB
                FromCountry     = $geoA.CountryCode
                ToCountry       = $geoB.CountryCode
                FromTime        = $tsA
                ToTime          = $tsB
                DistanceKm      = [Math]::Round($distanceKm, 0)
                TimeDiffHours   = [Math]::Round($hoursDiff, 2)
                RequiredSpeedKmh = [Math]::Round($requiredSpeed, 0)
            })
        }
    }

    return @($results)
}

function Get-HaversineDistance {
    [CmdletBinding()]
    param(
        [double]$Lat1, [double]$Lon1,
        [double]$Lat2, [double]$Lon2
    )

    $R = 6371.0
    $dLat = ($Lat2 - $Lat1) * [Math]::PI / 180.0
    $dLon = ($Lon2 - $Lon1) * [Math]::PI / 180.0
    $a = [Math]::Sin($dLat / 2) * [Math]::Sin($dLat / 2) +
         [Math]::Cos($Lat1 * [Math]::PI / 180.0) * [Math]::Cos($Lat2 * [Math]::PI / 180.0) *
         [Math]::Sin($dLon / 2) * [Math]::Sin($dLon / 2)
    $c = 2 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a))
    return $R * $c
}
