# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-FieldReportJson {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Profiles = @(),

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $alerts = foreach ($p in $Profiles) {
        $entry = @{
            email        = $p.Email
            threatLevel  = $p.ThreatLevel
            threatScore  = $p.ThreatScore
            indicators   = @($p.Indicators)
            attackerIps  = @($p.KnownAttackerIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
            cloudIps     = @($p.CloudIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
            signals      = @{
                impossibleTravel   = if ($p.ImpossibleTravel) { $p.ImpossibleTravel.Count } else { 0 }
                concurrentSessions = if ($p.ConcurrentSessions) { $p.ConcurrentSessions.Count } else { 0 }
                userAgentAnomalies = if ($p.UserAgentAnomalies) { $p.UserAgentAnomalies.Count } else { 0 }
                bruteForce         = if ($p.BruteForce -and $p.BruteForce.Detected) { $p.BruteForce.SuccessAfter } else { $null }
                afterHoursLogins   = if ($p.AfterHoursLogins) { $p.AfterHoursLogins.Count } else { 0 }
                newDevices         = if ($p.NewDevices) { $p.NewDevices.Count } else { 0 }
            }
        }
        $entry
    }

    $alerts | ConvertTo-Json -Depth 5 | Set-Content -Path $FilePath -Encoding UTF8
}
