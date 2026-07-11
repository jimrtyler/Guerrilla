# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-SurveillanceReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Profiles,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($p in $Profiles) {
        [PSCustomObject]@{
            UserPrincipalName      = $p.UserPrincipalName
            ThreatLevel            = $p.ThreatLevel
            ThreatScore            = '{0:N0}' -f $p.ThreatScore
            RiskySignIns           = $p.RiskySignIns.Count
            ImpossibleTravel       = $p.ImpossibleTravelDetections.Count
            AnonymousIpSignIns     = $p.AnonymousIpSignIns.Count
            LeakedCredentials      = $p.LeakedCredentials.Count
            PasswordSpray          = $p.PasswordSprayDetections.Count
            GlobalAdminAssignments = $p.GlobalAdminAssignments.Count
            CAPolicyChanges        = $p.CAPolicyChanges.Count
            ServicePrincipalCreds  = $p.ServicePrincipalCredChanges.Count
            FederationChanges      = $p.FederationChanges.Count
            CloudIpSignIns         = $p.CloudIpSignIns.Count
            ForeignCountrySignIns  = $p.ForeignCountrySignIns.Count
            Indicators             = $p.Indicators -join ' | '
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
