# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function New-UserCompromiseProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Email,

        [hashtable[]]$LoginEvents = @(),
        [hashtable[]]$TokenEvents = @(),
        [hashtable[]]$AccountEvents = @(),
        [hashtable[]]$AdminEvents = @(),
        [hashtable[]]$DriveEvents = @(),
        [hashtable]$GeoData = @{},
        [bool]$IsKnownCompromised = $false,
        [bool]$WasRemediated = $false,
        [hashtable]$DetectionConfig = @{},
        [hashtable]$DetectionFilter = @{},
        [hashtable]$PreviousDevices = @{},
        [string]$InternalDomain = ''
    )

    # Helper: check if a detection signal is enabled in the filter
    # If DetectionFilter is null/empty, all signals are enabled (backwards compatible)
    function Test-DetectionEnabled([string]$SignalKey) {
        if (-not $DetectionFilter -or $DetectionFilter.Count -eq 0) { return $true }
        return $DetectionFilter[$SignalKey] -ne $false
    }

    $profile = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = $Email
        ThreatLevel             = 'Clean'
        ThreatScore             = 0.0
        IsKnownCompromised      = $IsKnownCompromised
        WasRemediated           = $WasRemediated
        Indicators              = @()
        KnownAttackerIpLogins   = [System.Collections.Generic.List[PSCustomObject]]::new()
        CloudIpLogins           = [System.Collections.Generic.List[PSCustomObject]]::new()
        ReauthFromCloud         = [System.Collections.Generic.List[PSCustomObject]]::new()
        RiskyActions            = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousCountryLogins = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousOAuthGrants   = [System.Collections.Generic.List[PSCustomObject]]::new()
        ImpossibleTravel        = @()
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @()
        BruteForce              = $null
        AfterHoursLogins        = @()
        NewDevices              = @()
        IpClassifications       = @{}
        TotalLoginEvents        = $LoginEvents.Count
        LoginEvents             = $LoginEvents
        TokenEvents             = $TokenEvents
        AccountEvents           = $AccountEvents
        AdminEvents             = $AdminEvents
        DriveEvents             = $DriveEvents
        # Phase 4.1: Expanded monitoring signals
        AdminPrivilegeEscalations = [System.Collections.Generic.List[PSCustomObject]]::new()
        EmailForwardingRules      = [System.Collections.Generic.List[PSCustomObject]]::new()
        DriveExternalShares       = [System.Collections.Generic.List[PSCustomObject]]::new()
        BulkFileDownloads         = @()
        HighRiskOAuthApps         = [System.Collections.Generic.List[PSCustomObject]]::new()
        UserSuspensions           = [System.Collections.Generic.List[PSCustomObject]]::new()
        TwoSvDisablements         = [System.Collections.Generic.List[PSCustomObject]]::new()
        DomainWideDelegations     = [System.Collections.Generic.List[PSCustomObject]]::new()
        WorkspaceSettingChanges   = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    # Suspicious country set
    $suspiciousCountryCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($code in $script:SuspiciousCountries.codes) {
        [void]$suspiciousCountryCodes.Add($code)
    }

    # Analyze login events
    foreach ($event in $LoginEvents) {
        $ip = $event.IpAddress
        if (-not $ip) { continue }

        $ipClass = Get-CloudIpClassification -IpAddress $ip
        $geoCountry = if ($GeoData.ContainsKey($ip) -and $GeoData[$ip]) { $GeoData[$ip].CountryCode } else { '' }

        # Build enriched event object
        $enrichedEvent = [PSCustomObject]@{
            Timestamp  = $event.Timestamp
            User       = $event.User
            EventName  = $event.EventName
            IpAddress  = $ip
            IpClass    = $ipClass
            GeoCountry = $geoCountry
            Source     = $event.Source
            Params     = $event.Params
        }

        # Track IP classifications
        if (-not $profile.IpClassifications.ContainsKey($ip)) {
            $profile.IpClassifications[$ip] = @{
                Class   = $ipClass
                Country = $geoCountry
                Events  = [System.Collections.Generic.List[string]]::new()
            }
        }
        $profile.IpClassifications[$ip].Events.Add($event.EventName)

        $loginType = $event.Params['login_type']
        $eventName = $event.EventName

        # Signal 1: Known attacker IP
        if ((Test-DetectionEnabled 'knownAttackerIps') -and $ipClass -eq 'known_attacker') {
            $profile.KnownAttackerIpLogins.Add($enrichedEvent)
        }

        # Signal 2: Cloud provider IP login (any cloud provider or known attacker)
        $isCloudIp = $ipClass -and ($ipClass -eq 'known_attacker' -or $script:CloudProviderClasses.Contains($ipClass))
        if ((Test-DetectionEnabled 'cloudIpLogins') -and $isCloudIp) {
            $profile.CloudIpLogins.Add($enrichedEvent)
        }

        # Signal 3: Reauth from cloud IP (exact attack pattern)
        if ((Test-DetectionEnabled 'reauthFromCloudIp') -and $isCloudIp -and $loginType -eq 'reauth') {
            $profile.ReauthFromCloud.Add($enrichedEvent)
        }

        # Signal 4: Risky sensitive action
        if ((Test-DetectionEnabled 'riskySensitiveActions') -and $eventName -eq 'risky_sensitive_action_allowed') {
            $profile.RiskyActions.Add($enrichedEvent)
        }

        # Signal 5: Suspicious country login
        if ((Test-DetectionEnabled 'suspiciousCountryLogins') -and $geoCountry -and $suspiciousCountryCodes.Contains($geoCountry)) {
            $profile.SuspiciousCountryLogins.Add($enrichedEvent)
        }
    }

    # Analyze token/OAuth events
    foreach ($event in $TokenEvents) {
        $ip = $event.IpAddress
        $ipClass = if ($ip) { Get-CloudIpClassification -IpAddress $ip } else { '' }
        $eventName = $event.EventName

        $enrichedEvent = [PSCustomObject]@{
            Timestamp  = $event.Timestamp
            User       = $event.User
            EventName  = $eventName
            IpAddress  = $ip
            IpClass    = $ipClass
            GeoCountry = ''
            Source     = $event.Source
            Params     = $event.Params
        }

        # OAuth authorize from cloud IP (any cloud provider or known attacker)
        $isCloudToken = $ipClass -and ($ipClass -eq 'known_attacker' -or $script:CloudProviderClasses.Contains($ipClass))
        if ((Test-DetectionEnabled 'oauthFromCloudIp') -and $eventName -eq 'authorize' -and $isCloudToken) {
            $profile.SuspiciousOAuthGrants.Add($enrichedEvent)
        }
    }

    # --- New detection signals ---

    # Impossible travel
    if ((Test-DetectionEnabled 'impossibleTravel') -and $LoginEvents.Count -ge 2 -and $GeoData.Count -gt 0) {
        $maxSpeed = if ($DetectionConfig.impossibleTravelSpeedKmh) { $DetectionConfig.impossibleTravelSpeedKmh } else { 900 }
        $profile.ImpossibleTravel = @(Test-ImpossibleTravel -LoginEvents $LoginEvents -GeoData $GeoData -MaxSpeedKmh $maxSpeed)
    }

    # Concurrent sessions
    if ((Test-DetectionEnabled 'concurrentSessions') -and $LoginEvents.Count -ge 2) {
        $windowMin = if ($DetectionConfig.concurrentSessionWindowMinutes) { $DetectionConfig.concurrentSessionWindowMinutes } else { 5 }
        $profile.ConcurrentSessions = @(Test-ConcurrentSessions -LoginEvents $LoginEvents -WindowMinutes $windowMin)
    }

    # User agent anomalies
    if ((Test-DetectionEnabled 'userAgentAnomalies') -and $LoginEvents.Count -gt 0) {
        $profile.UserAgentAnomalies = @(Test-UserAgentAnomaly -LoginEvents $LoginEvents)
    }

    # Brute force
    if ((Test-DetectionEnabled 'bruteForce') -and $LoginEvents.Count -gt 0) {
        $failThreshold = if ($DetectionConfig.bruteForceFailureThreshold) { $DetectionConfig.bruteForceFailureThreshold } else { 5 }
        $failWindow = if ($DetectionConfig.bruteForceWindowMinutes) { $DetectionConfig.bruteForceWindowMinutes } else { 10 }
        $profile.BruteForce = Test-BruteForce -LoginEvents $LoginEvents -FailureThreshold $failThreshold -WindowMinutes $failWindow
    }

    # After-hours logins
    if ((Test-DetectionEnabled 'afterHoursLogins') -and $LoginEvents.Count -gt 0) {
        $bhStart = if ($DetectionConfig.businessHoursStart) { $DetectionConfig.businessHoursStart } else { 7 }
        $bhEnd = if ($DetectionConfig.businessHoursEnd) { $DetectionConfig.businessHoursEnd } else { 19 }
        $bhTz = if ($DetectionConfig.businessHoursTimezone) { $DetectionConfig.businessHoursTimezone } else { 'UTC' }
        $bhDays = if ($DetectionConfig.businessDays) { $DetectionConfig.businessDays } else { @('Monday','Tuesday','Wednesday','Thursday','Friday') }
        $profile.AfterHoursLogins = @(Test-AfterHoursLogin -LoginEvents $LoginEvents `
            -BusinessHoursStart $bhStart -BusinessHoursEnd $bhEnd -Timezone $bhTz -BusinessDays $bhDays)
    }

    # New device detection
    if ((Test-DetectionEnabled 'newDeviceDetection') -and $LoginEvents.Count -gt 0) {
        $profile.NewDevices = @(Test-NewDevice -LoginEvents $LoginEvents -PreviousDevices $PreviousDevices)
    }

    # --- Phase 4.1: Expanded Google Workspace detection signals ---

    # Admin privilege escalation
    if ((Test-DetectionEnabled 'adminPrivilegeEscalations') -and $AdminEvents.Count -gt 0) {
        $profile.AdminPrivilegeEscalations = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-AdminAction -AdminEvents $AdminEvents)) {
            $profile.AdminPrivilegeEscalations.Add($item)
        }
    }

    # Email forwarding rule creation
    if ((Test-DetectionEnabled 'emailForwardingRules') -and $AdminEvents.Count -gt 0) {
        $profile.EmailForwardingRules = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-EmailForwarding -AdminEvents $AdminEvents)) {
            $profile.EmailForwardingRules.Add($item)
        }
    }

    # Drive external sharing
    if ((Test-DetectionEnabled 'driveExternalSharing') -and $DriveEvents.Count -gt 0) {
        $profile.DriveExternalShares = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-DriveExternalSharing -DriveEvents $DriveEvents -InternalDomain $InternalDomain)) {
            $profile.DriveExternalShares.Add($item)
        }
    }

    # Bulk file download detection
    if ((Test-DetectionEnabled 'bulkFileDownloads') -and $DriveEvents.Count -gt 0) {
        $bulkThreshold = if ($DetectionConfig.bulkDownloadThreshold) { $DetectionConfig.bulkDownloadThreshold } else { 50 }
        $bulkWindow = if ($DetectionConfig.bulkDownloadWindowMinutes) { $DetectionConfig.bulkDownloadWindowMinutes } else { 10 }
        $profile.BulkFileDownloads = @(Test-BulkFileDownload -DriveEvents $DriveEvents -Threshold $bulkThreshold -WindowMinutes $bulkWindow)
    }

    # High-risk OAuth app detection
    if ((Test-DetectionEnabled 'highRiskOAuthApps') -and $TokenEvents.Count -gt 0) {
        $highRiskPatterns = if ($DetectionConfig.highRiskOAuthAppPatterns) { $DetectionConfig.highRiskOAuthAppPatterns } else { @() }
        $profile.HighRiskOAuthApps = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-HighRiskOAuthApp -TokenEvents $TokenEvents -HighRiskPatterns $highRiskPatterns)) {
            $profile.HighRiskOAuthApps.Add($item)
        }
    }

    # User suspension/deletion monitoring
    if ((Test-DetectionEnabled 'userSuspensions') -and $AdminEvents.Count -gt 0) {
        $profile.UserSuspensions = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-UserSuspension -AdminEvents $AdminEvents)) {
            $profile.UserSuspensions.Add($item)
        }
    }

    # 2SV disablement monitoring
    if ((Test-DetectionEnabled 'twoStepDisablement') -and $AdminEvents.Count -gt 0) {
        $profile.TwoSvDisablements = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-2svDisablement -AdminEvents $AdminEvents)) {
            $profile.TwoSvDisablements.Add($item)
        }
    }

    # Domain-wide delegation monitoring
    if ((Test-DetectionEnabled 'domainWideDelegation') -and $AdminEvents.Count -gt 0) {
        $profile.DomainWideDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-DomainWideDelegation -AdminEvents $AdminEvents)) {
            $profile.DomainWideDelegations.Add($item)
        }
    }

    # Workspace setting change monitoring
    if ((Test-DetectionEnabled 'workspaceSettingChanges') -and $AdminEvents.Count -gt 0) {
        $profile.WorkspaceSettingChanges = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($item in (Test-WorkspaceSettingChange -AdminEvents $AdminEvents)) {
            $profile.WorkspaceSettingChanges.Add($item)
        }
    }

    # Score the profile
    $profile = Get-ThreatScore -Profile $profile

    return $profile
}
