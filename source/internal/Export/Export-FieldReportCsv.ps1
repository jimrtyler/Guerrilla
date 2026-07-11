# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-FieldReportCsv {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Profiles = @(),

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($p in $Profiles) {
        $cloudIps = @($p.CloudIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique) -join ', '
        $attackerIps = @($p.KnownAttackerIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique) -join ', '

        $bruteForceStatus = if ($p.BruteForce -and $p.BruteForce.Detected) {
            if ($p.BruteForce.SuccessAfter) { 'SUCCESS' } else { 'ATTEMPT' }
        } else { '' }

        [PSCustomObject]@{
            Email                    = $p.Email
            ThreatLevel              = $p.ThreatLevel
            ThreatScore              = '{0:N0}' -f $p.ThreatScore
            KnownCompromised         = if ($p.IsKnownCompromised) { 'YES' } else { '' }
            Remediated               = if ($p.WasRemediated) { 'YES' } else { '' }
            KnownAttackerIpHits      = $p.KnownAttackerIpLogins.Count
            CloudIpLogins            = $p.CloudIpLogins.Count
            ReauthFromCloud          = $p.ReauthFromCloud.Count
            RiskyActions             = $p.RiskyActions.Count
            SuspiciousCountryLogins  = $p.SuspiciousCountryLogins.Count
            SuspiciousOAuthGrants    = $p.SuspiciousOAuthGrants.Count
            ImpossibleTravel         = if ($p.ImpossibleTravel) { $p.ImpossibleTravel.Count } else { 0 }
            ConcurrentSessions       = if ($p.ConcurrentSessions) { $p.ConcurrentSessions.Count } else { 0 }
            UserAgentAnomalies       = if ($p.UserAgentAnomalies) { $p.UserAgentAnomalies.Count } else { 0 }
            BruteForce               = $bruteForceStatus
            AfterHoursLogins         = if ($p.AfterHoursLogins) { $p.AfterHoursLogins.Count } else { 0 }
            NewDevices               = if ($p.NewDevices) { $p.NewDevices.Count } else { 0 }
            TotalLoginEvents         = $p.TotalLoginEvents
            Indicators               = $p.Indicators -join ' | '
            CloudIpsSeen             = $cloudIps
            AttackerIpsSeen          = $attackerIps
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
