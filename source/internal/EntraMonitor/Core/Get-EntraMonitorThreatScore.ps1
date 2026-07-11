# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraMonitorThreatScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Profile,

        [hashtable]$Weights
    )

    # Default weights
    if (-not $Weights) {
        $Weights = @{
            entraRiskySignIn           = 50
            entraForeignCountry        = 40
            entraCloudIp               = 35
            entraVpnTor                = 45
            entraImpossibleTravel      = 70
            entraUnfamiliarSignIn      = 30
            entraAnonymousIp           = 50
            entraMalwareIp             = 80
            entraLeakedCredential      = 90
            entraPasswordSpray         = 75
            entraAnomalousToken        = 65
            entraPrivilegedRole        = 50
            entraGlobalAdmin           = 90
            entraCAPolicyChange        = 60
            entraServicePrincipalCred  = 70
            entraAppPermission         = 55
            entraFederationChange      = 85
            entraGuestInvitation       = 15
            entraAdminUnitChange       = 30
            entraAuthMethodChange      = 40
            entraAuditLogGap           = 60
            entraTenantSettingChange   = 45
            entraSubscriptionPermChange = 50
        }
    }

    $score = 0.0
    $indicators = [System.Collections.Generic.List[string]]::new()

    # Leaked credentials — strongest identity signal
    if ($Profile.LeakedCredentials.Count -gt 0) {
        $n = $Profile.LeakedCredentials.Count
        $score += $Weights.entraLeakedCredential
        $indicators.Add(
            "LEAKED CREDENTIAL - $n credential leak detection(s) from Entra ID Protection"
        )
    }

    # Global Admin assignment — critical privilege escalation
    if ($Profile.GlobalAdminAssignments.Count -gt 0) {
        $n = $Profile.GlobalAdminAssignments.Count
        $score += $Weights.entraGlobalAdmin
        $targets = @($Profile.GlobalAdminAssignments | ForEach-Object { $_.TargetUser } | Where-Object { $_ } | Sort-Object -Unique)
        $targetDisplay = if ($targets.Count -gt 0) { $targets -join ', ' } else { 'unknown' }
        $indicators.Add(
            "GLOBAL ADMIN ASSIGNMENT - $n Global Administrator role assignment(s) to: $targetDisplay"
        )
    }

    # Federation changes — domain trust manipulation
    if ($Profile.FederationChanges.Count -gt 0) {
        $n = $Profile.FederationChanges.Count
        $score += $Weights.entraFederationChange
        $domains = @($Profile.FederationChanges | ForEach-Object { $_.DomainName } | Where-Object { $_ } | Sort-Object -Unique)
        $domainDisplay = if ($domains.Count -gt 0) { $domains -join ', ' } else { 'tenant' }
        $indicators.Add(
            "FEDERATION CHANGE - $n federation/domain trust modification(s) affecting: $domainDisplay"
        )
    }

    # Malware IP sign-ins
    if ($Profile.MalwareIpSignIns.Count -gt 0) {
        $n = $Profile.MalwareIpSignIns.Count
        $score += $Weights.entraMalwareIp
        $ips = @($Profile.MalwareIpSignIns | ForEach-Object { $_.IpAddress } | Where-Object { $_ } | Sort-Object -Unique)
        $indicators.Add(
            "MALWARE IP - $n sign-in(s) from known malicious IP(s): $($ips -join ', ')"
        )
    }

    # Password spray
    if ($Profile.PasswordSprayDetections.Count -gt 0) {
        $n = $Profile.PasswordSprayDetections.Count
        $score += $Weights.entraPasswordSpray
        $indicators.Add(
            "PASSWORD SPRAY - $n password spray detection(s) from Entra ID Protection"
        )
    }

    # Impossible travel
    if ($Profile.ImpossibleTravelDetections.Count -gt 0) {
        $n = $Profile.ImpossibleTravelDetections.Count
        $score += $Weights.entraImpossibleTravel
        $locations = @($Profile.ImpossibleTravelDetections | ForEach-Object {
            $loc = $_.Location
            if ($loc.Country) { $loc.Country } elseif ($loc.City) { $loc.City } else { 'unknown' }
        } | Sort-Object -Unique)
        $indicators.Add(
            "IMPOSSIBLE TRAVEL - $n impossible travel detection(s) involving: $($locations -join ', ')"
        )
    }

    # Service principal credential changes
    if ($Profile.ServicePrincipalCredChanges.Count -gt 0) {
        $n = $Profile.ServicePrincipalCredChanges.Count
        $score += $Weights.entraServicePrincipalCred
        $apps = @($Profile.ServicePrincipalCredChanges | ForEach-Object { $_.AppName } | Where-Object { $_ } | Sort-Object -Unique)
        $appDisplay = if ($apps.Count -gt 0) { $apps -join ', ' } else { 'unknown' }
        $indicators.Add(
            "SERVICE PRINCIPAL CREDENTIAL - $n credential addition/change(s) on: $appDisplay"
        )
    }

    # Anomalous token
    if ($Profile.AnomalousTokenDetections.Count -gt 0) {
        $n = $Profile.AnomalousTokenDetections.Count
        $score += $Weights.entraAnomalousToken
        $indicators.Add(
            "ANOMALOUS TOKEN - $n anomalous token detection(s) from Entra ID Protection"
        )
    }

    # Conditional Access policy changes
    if ($Profile.CAPolicyChanges.Count -gt 0) {
        $n = $Profile.CAPolicyChanges.Count
        $score += $Weights.entraCAPolicyChange
        $disabling = @($Profile.CAPolicyChanges | Where-Object { $_.IsDisabling })
        $detail = if ($disabling.Count -gt 0) { "$($disabling.Count) disabled/deleted" } else { "$n modified" }
        $policies = @($Profile.CAPolicyChanges | ForEach-Object { $_.PolicyName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $policyDisplay = if ($policies.Count -gt 0) { $policies -join ', ' } else { 'unknown' }
        $indicators.Add(
            "CA POLICY CHANGE - $detail, policies: $policyDisplay"
        )
    }

    # App permission grants
    if ($Profile.AppPermissionGrants.Count -gt 0) {
        $n = $Profile.AppPermissionGrants.Count
        $score += $Weights.entraAppPermission
        $highPriv = @($Profile.AppPermissionGrants | Where-Object { $_.IsHighPrivilege })
        $detail = if ($highPriv.Count -gt 0) { "$($highPriv.Count) high-privilege" } else { "$n granted" }
        $apps = @($Profile.AppPermissionGrants | ForEach-Object { $_.AppName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $appDisplay = if ($apps.Count -gt 0) { $apps -join ', ' } else { 'unknown' }
        $indicators.Add(
            "APP PERMISSION GRANT - $detail permission grant(s) to: $appDisplay"
        )
    }

    # Risky sign-ins
    if ($Profile.RiskySignIns.Count -gt 0) {
        $n = $Profile.RiskySignIns.Count
        $score += $Weights.entraRiskySignIn
        $highRisk = @($Profile.RiskySignIns | Where-Object { $_.RiskLevel -eq 'high' })
        $detail = if ($highRisk.Count -gt 0) { "$($highRisk.Count) high-risk" } else { "$n medium-risk" }
        $indicators.Add(
            "RISKY SIGN-IN - $detail sign-in(s) flagged by Entra ID Protection"
        )
    }

    # Anonymous IP sign-ins
    if ($Profile.AnonymousIpSignIns.Count -gt 0) {
        $n = $Profile.AnonymousIpSignIns.Count
        $score += $Weights.entraAnonymousIp
        $indicators.Add(
            "ANONYMOUS IP - $n sign-in(s) from anonymized/anonymous IP addresses"
        )
    }

    # Privileged role changes
    if ($Profile.PrivilegedRoleChanges.Count -gt 0) {
        $n = $Profile.PrivilegedRoleChanges.Count
        $score += $Weights.entraPrivilegedRole
        $roles = @($Profile.PrivilegedRoleChanges | ForEach-Object { $_.RoleName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $roleDisplay = if ($roles.Count -gt 0) { $roles -join ', ' } else { 'unknown' }
        $indicators.Add(
            "PRIVILEGED ROLE CHANGE - $n role assignment change(s): $roleDisplay"
        )
    }

    # Subscription permission changes
    if ($Profile.SubscriptionPermChanges.Count -gt 0) {
        $n = $Profile.SubscriptionPermChanges.Count
        $sensitive = @($Profile.SubscriptionPermChanges | Where-Object { $_.IsSensitive })
        if ($sensitive.Count -gt 0) {
            $score += $Weights.entraSubscriptionPermChange
            $indicators.Add(
                "SUBSCRIPTION PERMISSION - $($sensitive.Count) sensitive Azure RBAC/ownership change(s)"
            )
        }
    }

    # VPN/Tor sign-ins
    if ($Profile.VpnTorSignIns.Count -gt 0) {
        $n = $Profile.VpnTorSignIns.Count
        $score += $Weights.entraVpnTor
        $classes = @($Profile.VpnTorSignIns | ForEach-Object { $_.IpClass } | Sort-Object -Unique)
        $indicators.Add(
            "VPN/TOR SIGN-IN - $n sign-in(s) from $($classes -join ', ') services"
        )
    }

    # Tenant setting changes
    if ($Profile.TenantSettingChanges.Count -gt 0) {
        $highSev = @($Profile.TenantSettingChanges | Where-Object { $_.IsHighSeverity })
        if ($highSev.Count -gt 0) {
            $score += $Weights.entraTenantSettingChange
            $settings = @($highSev | ForEach-Object { $_.SettingName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
            $settingDisplay = if ($settings.Count -gt 0) { $settings -join ', ' } else { 'unknown' }
            $indicators.Add(
                "TENANT SETTING CHANGE - $($highSev.Count) security-relevant tenant setting change(s): $settingDisplay"
            )
        }
    }

    # Auth method changes
    if ($Profile.AuthMethodChanges.Count -gt 0) {
        $adminActions = @($Profile.AuthMethodChanges | Where-Object { $_.IsAdminAction })
        if ($adminActions.Count -gt 0) {
            $score += $Weights.entraAuthMethodChange
            $targets = @($adminActions | ForEach-Object { $_.TargetUser } | Where-Object { $_ } | Sort-Object -Unique)
            $targetDisplay = if ($targets.Count -gt 0) { $targets -join ', ' } else { 'unknown' }
            $indicators.Add(
                "AUTH METHOD CHANGE - $($adminActions.Count) admin-initiated auth method change(s) for: $targetDisplay"
            )
        }
    }

    # Foreign country sign-ins
    if ($Profile.ForeignCountrySignIns.Count -gt 0) {
        $n = $Profile.ForeignCountrySignIns.Count
        $score += $Weights.entraForeignCountry
        $countries = @($Profile.ForeignCountrySignIns | ForEach-Object { $_.GeoCountry } | Sort-Object -Unique)
        $countryDisplay = $countries | ForEach-Object {
            $name = if ($script:SuspiciousCountries) { $script:SuspiciousCountries.displayNames.$_ } else { $null }
            if ($name) { "$name ($_)" } else { $_ }
        }
        $indicators.Add(
            "FOREIGN COUNTRY SIGN-IN - $n sign-in(s) from suspicious countries: $($countryDisplay -join ', ')"
        )
    }

    # Cloud IP sign-ins
    if ($Profile.CloudIpSignIns.Count -gt 0) {
        $n = $Profile.CloudIpSignIns.Count
        $score += $Weights.entraCloudIp
        $uniqueIps = @($Profile.CloudIpSignIns | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
        $indicators.Add(
            "CLOUD IP SIGN-IN - $n sign-in(s) from $($uniqueIps.Count) cloud/hosting provider IP(s)"
        )
    }

    # Unfamiliar sign-ins
    if ($Profile.UnfamiliarSignIns.Count -gt 0) {
        $n = $Profile.UnfamiliarSignIns.Count
        $score += $Weights.entraUnfamiliarSignIn
        $indicators.Add(
            "UNFAMILIAR SIGN-IN - $n unfamiliar feature detection(s) from Entra ID Protection"
        )
    }

    # Admin unit changes
    if ($Profile.AdminUnitChanges.Count -gt 0) {
        $n = $Profile.AdminUnitChanges.Count
        $score += $Weights.entraAdminUnitChange
        $units = @($Profile.AdminUnitChanges | ForEach-Object { $_.AdminUnitName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $unitDisplay = if ($units.Count -gt 0) { $units -join ', ' } else { 'unknown' }
        $indicators.Add(
            "ADMIN UNIT CHANGE - $n administrative unit change(s): $unitDisplay"
        )
    }

    # Audit log gaps
    if ($Profile.AuditLogGaps.Count -gt 0) {
        $n = $Profile.AuditLogGaps.Count
        $score += $Weights.entraAuditLogGap
        $maxGap = ($Profile.AuditLogGaps | Sort-Object GapHours -Descending | Select-Object -First 1).GapHours
        $indicators.Add(
            "AUDIT LOG GAP - $n gap(s) detected in audit logs, max gap: ${maxGap}h"
        )
    }

    # Guest invitations — low signal
    if ($Profile.GuestInvitations.Count -gt 0) {
        $n = $Profile.GuestInvitations.Count
        $score += $Weights.entraGuestInvitation
        $guests = @($Profile.GuestInvitations | ForEach-Object { $_.InvitedEmail } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $guestDisplay = if ($guests.Count -gt 0) { $guests -join ', ' } else { 'unknown' }
        $indicators.Add(
            "GUEST INVITATION - $n external user invitation(s): $guestDisplay"
        )
    }

    # Assign threat level
    $threatLevel = switch ($true) {
        ($score -ge 100) { 'CRITICAL'; break }
        ($score -ge 60)  { 'HIGH'; break }
        ($score -ge 30)  { 'MEDIUM'; break }
        ($score -gt 0)   { 'LOW'; break }
        default          { 'Clean' }
    }

    $Profile.ThreatScore = $score
    $Profile.ThreatLevel = $threatLevel
    $Profile.Indicators = @($indicators)

    return $Profile
}
