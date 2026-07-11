# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ThreatScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Profile,
        [hashtable]$Weights
    )

    # Default weights
    if (-not $Weights) {
        $Weights = @{
            knownAttackerIp          = 100
            reauthFromCloud          = 60
            impossibleTravel         = 70
            riskyAction              = 50
            riskyActionFromCloud     = 30   # bonus on top of riskyAction
            concurrentSessions       = 45
            suspiciousCountry        = 40
            bruteForceAttempt        = 20
            bruteForceSuccess        = 55   # replaces attempt weight when success follows
            userAgentAnomaly         = 30
            oauthFromCloud           = 25
            afterHoursLogin          = 15
            cloudLoginsOnly          = 15
            newDevice                = 10
            newDeviceFromCloud       = 35   # replaces newDevice when from cloud IP
            # Phase 4.1: Google Workspace expanded monitoring signals
            adminPrivilegeEscalation = 60
            emailForwardingRule      = 45
            driveExternalSharing     = 25
            bulkFileDownload         = 40
            highRiskOAuthApp         = 55
            userSuspension           = 20
            twoSvDisablement         = 50
            domainWideDelegation     = 80
            workspaceSettingChange   = 35
        }
    }

    $score = 0.0
    $indicators = [System.Collections.Generic.List[string]]::new()

    # Known attacker IPs — strongest signal
    if ($Profile.KnownAttackerIpLogins.Count -gt 0) {
        $n = $Profile.KnownAttackerIpLogins.Count
        $score += $Weights.knownAttackerIp
        $uniqueIps = @($Profile.KnownAttackerIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
        $indicators.Add(
            "KNOWN ATTACKER IP - $n login(s) from $($uniqueIps.Count) known attacker IP(s): $($uniqueIps -join ', ')"
        )
    }

    # Reauth from cloud IP — exact attack fingerprint
    if ($Profile.ReauthFromCloud.Count -gt 0) {
        $n = $Profile.ReauthFromCloud.Count
        $score += $Weights.reauthFromCloud
        $indicators.Add(
            "REAUTH FROM CLOUD - $n reauth login(s) from cloud provider IPs (matches attack pattern)"
        )
    }

    # Risky sensitive actions
    if ($Profile.RiskyActions.Count -gt 0) {
        $n = $Profile.RiskyActions.Count
        $score += $Weights.riskyAction

        $cloudRisky = @($Profile.RiskyActions | Where-Object {
            $_.IpClass -and ($_.IpClass -eq 'known_attacker' -or $script:CloudProviderClasses.Contains($_.IpClass))
        })

        if ($cloudRisky.Count -gt 0) {
            $score += $Weights.riskyActionFromCloud
            $indicators.Add(
                "RISKY ACTION FROM CLOUD IP - $($cloudRisky.Count) risky sensitive action(s) from cloud/hosting IPs"
            )
        } else {
            $indicators.Add(
                "RISKY SENSITIVE ACTION - $n risky action(s) allowed"
            )
        }
    }

    # Suspicious country logins
    if ($Profile.SuspiciousCountryLogins.Count -gt 0) {
        $n = $Profile.SuspiciousCountryLogins.Count
        $score += $Weights.suspiciousCountry
        $countries = @($Profile.SuspiciousCountryLogins | ForEach-Object { $_.GeoCountry } | Sort-Object -Unique)
        $countryDisplay = $countries | ForEach-Object {
            $name = $script:SuspiciousCountries.displayNames.$_
            if ($name) { "$name ($_)" } else { $_ }
        }
        $indicators.Add(
            "SUSPICIOUS COUNTRY LOGIN - $n login(s) from $($countryDisplay -join ', ')"
        )
    }

    # OAuth grants from cloud IPs
    if ($Profile.SuspiciousOAuthGrants.Count -gt 0) {
        $n = $Profile.SuspiciousOAuthGrants.Count
        $score += $Weights.oauthFromCloud
        $apps = @($Profile.SuspiciousOAuthGrants | ForEach-Object { $_.Params.app_name } | Where-Object { $_ } | Sort-Object -Unique)
        $appList = if ($apps.Count -gt 0) { $apps -join ', ' } else { 'unknown' }
        $indicators.Add(
            "OAUTH FROM CLOUD IP - $n OAuth grant(s) from cloud IPs: $appList"
        )
    }

    # Cloud IP logins without other strong signals
    if ($Profile.CloudIpLogins.Count -gt 0 -and
        $Profile.ReauthFromCloud.Count -eq 0 -and
        $Profile.KnownAttackerIpLogins.Count -eq 0) {
        $n = $Profile.CloudIpLogins.Count
        if ($n -ge 3) {
            $score += $Weights.cloudLoginsOnly
            $indicators.Add(
                "CLOUD IP LOGINS - $n login(s) from cloud/hosting provider IPs"
            )
        }
    }

    # Impossible travel
    if ($Profile.ImpossibleTravel.Count -gt 0) {
        $n = $Profile.ImpossibleTravel.Count
        $score += $Weights.impossibleTravel
        $trip = $Profile.ImpossibleTravel[0]
        $indicators.Add(
            "IMPOSSIBLE TRAVEL - $n instance(s), e.g. $($trip.FromCountry) to $($trip.ToCountry) ($($trip.DistanceKm) km in $($trip.TimeDiffHours)h)"
        )
    }

    # Concurrent sessions
    if ($Profile.ConcurrentSessions.Count -gt 0) {
        $n = $Profile.ConcurrentSessions.Count
        $score += $Weights.concurrentSessions
        $maxIps = ($Profile.ConcurrentSessions | Sort-Object IpCount -Descending | Select-Object -First 1).IpCount
        $indicators.Add(
            "CONCURRENT SESSIONS - $n window(s) with multiple IPs (max $maxIps IPs simultaneously)"
        )
    }

    # User agent anomalies
    if ($Profile.UserAgentAnomalies.Count -gt 0) {
        $n = $Profile.UserAgentAnomalies.Count
        $score += $Weights.userAgentAnomaly
        $labels = @($Profile.UserAgentAnomalies | ForEach-Object { $_.MatchLabel } | Sort-Object -Unique)
        $indicators.Add(
            "USER AGENT ANOMALY - $n suspicious client(s): $($labels -join ', ')"
        )
    }

    # Brute force
    if ($Profile.BruteForce -and $Profile.BruteForce.Detected) {
        $bf = $Profile.BruteForce
        if ($bf.SuccessAfter) {
            $score += $Weights.bruteForceSuccess
            $indicators.Add(
                "BRUTE FORCE SUCCESS - $($bf.FailureCount) failures followed by successful login from $($bf.AttackingIps.Count) IP(s)"
            )
        } else {
            $score += $Weights.bruteForceAttempt
            $indicators.Add(
                "BRUTE FORCE ATTEMPT - $($bf.FailureCount) login failures in $([Math]::Round($bf.FailureWindow.Duration.TotalMinutes, 1)) min from $($bf.AttackingIps.Count) IP(s)"
            )
        }
    }

    # After-hours logins
    if ($Profile.AfterHoursLogins.Count -gt 0) {
        $n = $Profile.AfterHoursLogins.Count
        $score += $Weights.afterHoursLogin
        $weekendCount = @($Profile.AfterHoursLogins | Where-Object { $_.Reason -match 'Weekend|non-business' }).Count
        $lateCount = $n - $weekendCount
        $detail = @()
        if ($lateCount -gt 0) { $detail += "$lateCount outside hours" }
        if ($weekendCount -gt 0) { $detail += "$weekendCount weekend" }
        $indicators.Add(
            "AFTER HOURS LOGIN - $n login(s) outside business hours ($($detail -join ', '))"
        )
    }

    # New devices
    if ($Profile.NewDevices.Count -gt 0) {
        $n = $Profile.NewDevices.Count
        $cloudDevices = @($Profile.NewDevices | Where-Object { $_.IsCloudIp })
        if ($cloudDevices.Count -gt 0) {
            $score += $Weights.newDeviceFromCloud
            $indicators.Add(
                "NEW DEVICE FROM CLOUD IP - $($cloudDevices.Count) first-seen device(s) from cloud/hosting IPs"
            )
        } else {
            $score += $Weights.newDevice
            $indicators.Add(
                "NEW DEVICE - $n first-seen device(s)"
            )
        }
    }

    # --- Phase 4.1: Expanded Google Workspace monitoring signals ---

    # Admin privilege escalation
    if ($Profile.PSObject.Properties['AdminPrivilegeEscalations'] -and $Profile.AdminPrivilegeEscalations.Count -gt 0) {
        $n = $Profile.AdminPrivilegeEscalations.Count
        $score += $Weights.adminPrivilegeEscalation
        $roles = @($Profile.AdminPrivilegeEscalations | ForEach-Object { $_.RoleName } | Sort-Object -Unique)
        $indicators.Add(
            "ADMIN PRIVILEGE ESCALATION - $n admin role assignment(s): $($roles -join ', ')"
        )
    }

    # Email forwarding rule creation
    if ($Profile.PSObject.Properties['EmailForwardingRules'] -and $Profile.EmailForwardingRules.Count -gt 0) {
        $n = $Profile.EmailForwardingRules.Count
        $score += $Weights.emailForwardingRule
        $destinations = @($Profile.EmailForwardingRules | ForEach-Object { $_.ForwardTo } | Where-Object { $_ } | Sort-Object -Unique)
        $destDisplay = if ($destinations.Count -gt 0) { $destinations -join ', ' } else { 'unknown' }
        $indicators.Add(
            "EMAIL FORWARDING RULE - $n forwarding rule(s) created to: $destDisplay"
        )
    }

    # Drive external sharing
    if ($Profile.PSObject.Properties['DriveExternalShares'] -and $Profile.DriveExternalShares.Count -gt 0) {
        $n = $Profile.DriveExternalShares.Count
        $score += $Weights.driveExternalSharing
        $indicators.Add(
            "DRIVE EXTERNAL SHARING - $n file(s) shared externally"
        )
    }

    # Bulk file download
    if ($Profile.PSObject.Properties['BulkFileDownloads'] -and $Profile.BulkFileDownloads.Count -gt 0) {
        $n = $Profile.BulkFileDownloads.Count
        $maxCount = ($Profile.BulkFileDownloads | Sort-Object EventCount -Descending | Select-Object -First 1).EventCount
        $score += $Weights.bulkFileDownload
        $indicators.Add(
            "BULK FILE DOWNLOAD - $n burst(s) detected, max $maxCount downloads in window"
        )
    }

    # High-risk OAuth app
    if ($Profile.PSObject.Properties['HighRiskOAuthApps'] -and $Profile.HighRiskOAuthApps.Count -gt 0) {
        $n = $Profile.HighRiskOAuthApps.Count
        $score += $Weights.highRiskOAuthApp
        $apps = @($Profile.HighRiskOAuthApps | ForEach-Object { $_.AppName } | Where-Object { $_ } | Sort-Object -Unique)
        $appList = if ($apps.Count -gt 0) { $apps -join ', ' } else { 'unknown' }
        $indicators.Add(
            "HIGH-RISK OAUTH APP - $n risky OAuth app grant(s): $appList"
        )
    }

    # User suspension/deletion (info signal)
    if ($Profile.PSObject.Properties['UserSuspensions'] -and $Profile.UserSuspensions.Count -gt 0) {
        $n = $Profile.UserSuspensions.Count
        $score += $Weights.userSuspension
        $targets = @($Profile.UserSuspensions | ForEach-Object { $_.TargetUser } | Sort-Object -Unique)
        $indicators.Add(
            "USER SUSPENSION/DELETION - $n user(s) suspended or deleted: $($targets -join ', ')"
        )
    }

    # 2SV disablement
    if ($Profile.PSObject.Properties['TwoSvDisablements'] -and $Profile.TwoSvDisablements.Count -gt 0) {
        $n = $Profile.TwoSvDisablements.Count
        $adminActions = @($Profile.TwoSvDisablements | Where-Object { $_.IsAdminAction })
        if ($adminActions.Count -gt 0) {
            $score += $Weights.twoSvDisablement
            $targets = @($adminActions | ForEach-Object { $_.TargetUser } | Sort-Object -Unique)
            $indicators.Add(
                "2SV DISABLEMENT - $($adminActions.Count) admin-initiated 2SV disable(s) for: $($targets -join ', ')"
            )
        }
    }

    # Domain-wide delegation
    if ($Profile.PSObject.Properties['DomainWideDelegations'] -and $Profile.DomainWideDelegations.Count -gt 0) {
        $n = $Profile.DomainWideDelegations.Count
        $score += $Weights.domainWideDelegation
        $dangerous = @($Profile.DomainWideDelegations | Where-Object { $_.HasDangerousScope })
        $detail = if ($dangerous.Count -gt 0) { "$($dangerous.Count) with dangerous scopes" } else { 'API client access grants' }
        $indicators.Add(
            "DOMAIN-WIDE DELEGATION - $n delegation grant(s): $detail"
        )
    }

    # Workspace setting changes
    if ($Profile.PSObject.Properties['WorkspaceSettingChanges'] -and $Profile.WorkspaceSettingChanges.Count -gt 0) {
        $n = $Profile.WorkspaceSettingChanges.Count
        $highSev = @($Profile.WorkspaceSettingChanges | Where-Object { $_.IsHighSeverity })
        if ($highSev.Count -gt 0) {
            $score += $Weights.workspaceSettingChange
            $settings = @($highSev | ForEach-Object { $_.SettingName } | Sort-Object -Unique | Select-Object -First 3)
            $indicators.Add(
                "WORKSPACE SETTING CHANGE - $($highSev.Count) security-relevant setting change(s): $($settings -join ', ')"
            )
        }
    }

    # Known compromised baseline tag
    if ($Profile.IsKnownCompromised) {
        $indicators.Insert(0, 'CONFIRMED COMPROMISED (known victim)')
        if ($score -lt 100) {
            $score = [Math]::Max($score, 100)
        }
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
