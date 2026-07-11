# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function New-EntraRiskProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [hashtable[]]$SignInEvents = @(),
        [hashtable[]]$RiskDetections = @(),
        [hashtable[]]$AuditEvents = @(),
        [hashtable]$GeoData = @{},
        [hashtable]$DetectionConfig = @{},
        [hashtable]$DetectionFilter = @{}
    )

    # Helper: check if a detection signal is enabled in the filter
    function Test-DetectionEnabled([string]$SignalKey) {
        if (-not $DetectionFilter -or $DetectionFilter.Count -eq 0) { return $true }
        return $DetectionFilter[$SignalKey] -ne $false
    }

    $profile = [PSCustomObject]@{
        PSTypeName                = 'Guerrilla.EntraRiskProfile'
        UserPrincipalName         = $UserPrincipalName
        ThreatLevel               = 'Clean'
        ThreatScore               = 0.0
        Indicators                = @()
        # Sign-in based detections
        RiskySignIns              = [System.Collections.Generic.List[PSCustomObject]]::new()
        ForeignCountrySignIns     = [System.Collections.Generic.List[PSCustomObject]]::new()
        CloudIpSignIns            = [System.Collections.Generic.List[PSCustomObject]]::new()
        VpnTorSignIns             = [System.Collections.Generic.List[PSCustomObject]]::new()
        # Risk detection based detections
        ImpossibleTravelDetections = [System.Collections.Generic.List[PSCustomObject]]::new()
        UnfamiliarSignIns         = [System.Collections.Generic.List[PSCustomObject]]::new()
        AnonymousIpSignIns        = [System.Collections.Generic.List[PSCustomObject]]::new()
        MalwareIpSignIns          = [System.Collections.Generic.List[PSCustomObject]]::new()
        LeakedCredentials         = [System.Collections.Generic.List[PSCustomObject]]::new()
        PasswordSprayDetections   = [System.Collections.Generic.List[PSCustomObject]]::new()
        AnomalousTokenDetections  = [System.Collections.Generic.List[PSCustomObject]]::new()
        # Audit-based detections
        PrivilegedRoleChanges     = [System.Collections.Generic.List[PSCustomObject]]::new()
        GlobalAdminAssignments    = [System.Collections.Generic.List[PSCustomObject]]::new()
        CAPolicyChanges           = [System.Collections.Generic.List[PSCustomObject]]::new()
        ServicePrincipalCredChanges = [System.Collections.Generic.List[PSCustomObject]]::new()
        AppPermissionGrants       = [System.Collections.Generic.List[PSCustomObject]]::new()
        FederationChanges         = [System.Collections.Generic.List[PSCustomObject]]::new()
        GuestInvitations          = [System.Collections.Generic.List[PSCustomObject]]::new()
        AdminUnitChanges          = [System.Collections.Generic.List[PSCustomObject]]::new()
        AuthMethodChanges         = [System.Collections.Generic.List[PSCustomObject]]::new()
        AuditLogGaps              = @()
        TenantSettingChanges      = [System.Collections.Generic.List[PSCustomObject]]::new()
        SubscriptionPermChanges   = [System.Collections.Generic.List[PSCustomObject]]::new()
        # Metadata
        TotalSignInEvents         = $SignInEvents.Count
        TotalRiskDetections       = $RiskDetections.Count
        TotalAuditEvents          = $AuditEvents.Count
        IpClassifications         = @{}
    }

    # --- Sign-in event analysis ---

    # Suspicious country set
    $suspiciousCountryCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($script:SuspiciousCountries -and $script:SuspiciousCountries.codes) {
        foreach ($code in $script:SuspiciousCountries.codes) {
            [void]$suspiciousCountryCodes.Add($code)
        }
    }

    foreach ($event in $SignInEvents) {
        $ip = $event.IpAddress
        if (-not $ip) { continue }

        $ipClass = Get-CloudIpClassification -IpAddress $ip
        $geoCountry = if ($GeoData.ContainsKey($ip) -and $GeoData[$ip]) { $GeoData[$ip].CountryCode } else { '' }

        # Track IP classifications
        if (-not $profile.IpClassifications.ContainsKey($ip)) {
            $profile.IpClassifications[$ip] = @{
                Class   = $ipClass
                Country = $geoCountry
                Events  = [System.Collections.Generic.List[string]]::new()
            }
        }
        $profile.IpClassifications[$ip].Events.Add($event.AppDisplayName ?? 'sign-in')

        # Cloud IP sign-ins (any cloud provider or known attacker)
        $isCloudIp = $ipClass -and ($ipClass -eq 'known_attacker' -or ($script:CloudProviderClasses -and $script:CloudProviderClasses.Contains($ipClass)))
        if ((Test-DetectionEnabled 'cloudIpSignIns') -and $isCloudIp) {
            $profile.CloudIpSignIns.Add([PSCustomObject]@{
                Timestamp         = $event.Timestamp
                UserPrincipalName = $event.UserPrincipalName
                IpAddress         = $ip
                IpClass           = $ipClass
                AppDisplayName    = $event.AppDisplayName
                Location          = $event.Location
            })
        }

        # VPN/Tor sign-ins
        if ((Test-DetectionEnabled 'vpnTorSignIns') -and $ipClass -in @('vpn', 'tor', 'proxy')) {
            $profile.VpnTorSignIns.Add([PSCustomObject]@{
                Timestamp         = $event.Timestamp
                UserPrincipalName = $event.UserPrincipalName
                IpAddress         = $ip
                IpClass           = $ipClass
                AppDisplayName    = $event.AppDisplayName
                Location          = $event.Location
            })
        }

        # Foreign country sign-ins
        $locationCountry = $event.Location.Country ?? ''
        if (-not $geoCountry -and $locationCountry) { $geoCountry = $locationCountry }
        if ((Test-DetectionEnabled 'foreignCountrySignIns') -and $geoCountry -and $suspiciousCountryCodes.Contains($geoCountry)) {
            $profile.ForeignCountrySignIns.Add([PSCustomObject]@{
                Timestamp         = $event.Timestamp
                UserPrincipalName = $event.UserPrincipalName
                IpAddress         = $ip
                GeoCountry        = $geoCountry
                AppDisplayName    = $event.AppDisplayName
                Location          = $event.Location
            })
        }
    }

    # --- Risky sign-in detection ---
    if ((Test-DetectionEnabled 'riskySignIns') -and $SignInEvents.Count -gt 0) {
        foreach ($item in (Test-EntraRiskySignIn -SignInEvents $SignInEvents)) {
            $profile.RiskySignIns.Add($item)
        }
    }

    # --- Risk detection based signals ---
    if ($RiskDetections.Count -gt 0) {
        if (Test-DetectionEnabled 'impossibleTravel') {
            foreach ($item in (Test-EntraImpossibleTravel -RiskDetections $RiskDetections)) {
                $profile.ImpossibleTravelDetections.Add($item)
            }
        }
        if (Test-DetectionEnabled 'unfamiliarProperties') {
            foreach ($item in (Test-EntraUnfamiliarSignIn -RiskDetections $RiskDetections)) {
                $profile.UnfamiliarSignIns.Add($item)
            }
        }
        if (Test-DetectionEnabled 'anonymousIp') {
            foreach ($item in (Test-EntraAnonymousIp -RiskDetections $RiskDetections)) {
                $profile.AnonymousIpSignIns.Add($item)
            }
        }
        if (Test-DetectionEnabled 'malwareIp') {
            foreach ($item in (Test-EntraMalwareIp -RiskDetections $RiskDetections)) {
                $profile.MalwareIpSignIns.Add($item)
            }
        }
        if (Test-DetectionEnabled 'leakedCredentials') {
            foreach ($item in (Test-EntraLeakedCredential -RiskDetections $RiskDetections)) {
                $profile.LeakedCredentials.Add($item)
            }
        }
        if (Test-DetectionEnabled 'passwordSpray') {
            foreach ($item in (Test-EntraPasswordSpray -RiskDetections $RiskDetections)) {
                $profile.PasswordSprayDetections.Add($item)
            }
        }
        if (Test-DetectionEnabled 'anomalousToken') {
            foreach ($item in (Test-EntraAnomalousToken -RiskDetections $RiskDetections)) {
                $profile.AnomalousTokenDetections.Add($item)
            }
        }
    }

    # --- Audit-based signals ---
    if ($AuditEvents.Count -gt 0) {
        if (Test-DetectionEnabled 'privilegedRoleChanges') {
            foreach ($item in (Test-EntraPrivilegedRoleChange -AuditEvents $AuditEvents)) {
                $profile.PrivilegedRoleChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'globalAdminAssignment') {
            foreach ($item in (Test-EntraGlobalAdminAssignment -AuditEvents $AuditEvents)) {
                $profile.GlobalAdminAssignments.Add($item)
            }
        }
        if (Test-DetectionEnabled 'conditionalAccessChanges') {
            foreach ($item in (Test-EntraCAPolicyChange -AuditEvents $AuditEvents)) {
                $profile.CAPolicyChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'servicePrincipalCredentials') {
            foreach ($item in (Test-EntraServicePrincipalCred -AuditEvents $AuditEvents)) {
                $profile.ServicePrincipalCredChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'appPermissionGrants') {
            foreach ($item in (Test-EntraAppPermissionGrant -AuditEvents $AuditEvents)) {
                $profile.AppPermissionGrants.Add($item)
            }
        }
        if (Test-DetectionEnabled 'federationChanges') {
            foreach ($item in (Test-EntraFederationChange -AuditEvents $AuditEvents)) {
                $profile.FederationChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'guestInvitations') {
            foreach ($item in (Test-EntraGuestInvitation -AuditEvents $AuditEvents)) {
                $profile.GuestInvitations.Add($item)
            }
        }
        if (Test-DetectionEnabled 'adminUnitChanges') {
            foreach ($item in (Test-EntraAdminUnitChange -AuditEvents $AuditEvents)) {
                $profile.AdminUnitChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'authMethodChanges') {
            foreach ($item in (Test-EntraAuthMethodChange -AuditEvents $AuditEvents)) {
                $profile.AuthMethodChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'tenantSettingChanges') {
            foreach ($item in (Test-EntraTenantSettingChange -AuditEvents $AuditEvents)) {
                $profile.TenantSettingChanges.Add($item)
            }
        }
        if (Test-DetectionEnabled 'subscriptionPermChanges') {
            foreach ($item in (Test-EntraSubscriptionPermChange -AuditEvents $AuditEvents)) {
                $profile.SubscriptionPermChanges.Add($item)
            }
        }

        # Audit log gaps
        if (Test-DetectionEnabled 'auditLogGaps') {
            $gapThreshold = if ($DetectionConfig.auditLogGapThresholdHours) { $DetectionConfig.auditLogGapThresholdHours } else { 24 }
            $profile.AuditLogGaps = @(Test-EntraAuditLogGap -AuditEvents $AuditEvents -GapThresholdHours $gapThreshold)
        }
    }

    # --- Score the profile ---
    $weights = $null
    if ($DetectionConfig.entraWeights) { $weights = $DetectionConfig.entraWeights }
    $profile = Get-EntraMonitorThreatScore -Profile $profile -Weights $weights

    return $profile
}
