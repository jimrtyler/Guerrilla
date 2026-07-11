# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-SurveillanceReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Profiles,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $alerts = foreach ($p in $Profiles) {
        $entry = @{
            userPrincipalName = $p.UserPrincipalName
            threatLevel       = $p.ThreatLevel
            threatScore       = $p.ThreatScore
            indicators        = @($p.Indicators)
            signals           = @{
                riskySignIns           = $p.RiskySignIns.Count
                impossibleTravel       = $p.ImpossibleTravelDetections.Count
                unfamiliarSignIns      = $p.UnfamiliarSignIns.Count
                anonymousIpSignIns     = $p.AnonymousIpSignIns.Count
                malwareIpSignIns       = $p.MalwareIpSignIns.Count
                leakedCredentials      = $p.LeakedCredentials.Count
                passwordSpray          = $p.PasswordSprayDetections.Count
                anomalousTokens        = $p.AnomalousTokenDetections.Count
                globalAdminAssignments = $p.GlobalAdminAssignments.Count
                privilegedRoleChanges  = $p.PrivilegedRoleChanges.Count
                caPolicyChanges        = $p.CAPolicyChanges.Count
                servicePrincipalCreds  = $p.ServicePrincipalCredChanges.Count
                appPermissionGrants    = $p.AppPermissionGrants.Count
                federationChanges      = $p.FederationChanges.Count
                guestInvitations       = $p.GuestInvitations.Count
                authMethodChanges      = $p.AuthMethodChanges.Count
                tenantSettingChanges   = $p.TenantSettingChanges.Count
                cloudIpSignIns         = $p.CloudIpSignIns.Count
                foreignCountrySignIns  = $p.ForeignCountrySignIns.Count
                vpnTorSignIns          = $p.VpnTorSignIns.Count
            }
            ipClassifications = @{}
        }

        # Include IP classification summary
        if ($p.IpClassifications -and $p.IpClassifications.Count -gt 0) {
            foreach ($ipKey in $p.IpClassifications.Keys) {
                $ipInfo = $p.IpClassifications[$ipKey]
                $entry.ipClassifications[$ipKey] = @{
                    class   = $ipInfo.Class
                    country = $ipInfo.Country
                    events  = @($ipInfo.Events)
                }
            }
        }

        $entry
    }

    $alerts | ConvertTo-Json -Depth 5 | Set-Content -Path $FilePath -Encoding UTF8
}
