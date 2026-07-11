# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ReconDemo {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [switch]$NoOpen
    )

    if (-not $OutputPath) {
        $outDir = Join-Path (Get-GuerrillaDataRoot) 'Reports'
        if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
        $OutputPath = Join-Path $outDir "demo_field_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    }

    Write-GuerrillaText 'Generating demo field report...' -Color Olive

    # --- Mock data ---
    $now = [datetime]::UtcNow

    # Helper to build a mock enriched event
    $mockEvent = {
        param([string]$User, [string]$EventName, [string]$Ip, [string]$IpClass,
              [string]$Country, [datetime]$Time, [string]$Source, [hashtable]$Params)
        [PSCustomObject]@{
            Timestamp  = $Time
            User       = $User
            EventName  = $EventName
            IpAddress  = $Ip
            IpClass    = $IpClass
            GeoCountry = $Country
            Source     = $Source ?? 'login'
            Params     = $Params ?? @{}
        }
    }

    $profiles = @()

    # ============================================================
    # USER 1: CRITICAL — known attacker IP + impossible travel + brute force success
    # ============================================================
    $u1 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'sarah.chen@acme.com'
        ThreatLevel             = 'CRITICAL'
        ThreatScore             = 260.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @(
            'KNOWN ATTACKER IP - 1 login(s) from 1 known attacker IP(s): 185.220.101.42'
            'IMPOSSIBLE TRAVEL - 1 instance(s), e.g. DE to US (6,379 km in 0.5h)'
            'REAUTH FROM CLOUD - 1 reauth login(s) from cloud provider IPs (matches attack pattern)'
            'BRUTE FORCE SUCCESS - 7 failures followed by successful login from 2 IP(s)'
            'RISKY ACTION FROM CLOUD IP - 1 risky sensitive action(s) from cloud/hosting IPs'
        )
        KnownAttackerIpLogins   = @(
            (& $mockEvent 'sarah.chen@acme.com' 'login_success' '185.220.101.42' 'known_attacker' 'DE' ($now.AddHours(-6)) 'login' @{ login_type = 'exchange' })
        )
        CloudIpLogins           = @(
            (& $mockEvent 'sarah.chen@acme.com' 'login_success' '3.236.48.201' 'aws' 'US' ($now.AddHours(-4)) 'login' @{ login_type = 'reauth' })
        )
        ReauthFromCloud         = @(
            (& $mockEvent 'sarah.chen@acme.com' 'login_success' '3.236.48.201' 'aws' 'US' ($now.AddHours(-4)) 'login' @{ login_type = 'reauth' })
        )
        RiskyActions            = @(
            (& $mockEvent 'sarah.chen@acme.com' 'risky_sensitive_action_allowed' '3.236.48.201' 'aws' 'US' ($now.AddHours(-3.5)) 'login' @{})
        )
        SuspiciousCountryLogins = @()
        SuspiciousOAuthGrants   = @()
        ImpossibleTravel        = @(
            [PSCustomObject]@{
                FromIp = '185.220.101.42'; ToIp = '3.236.48.201'
                FromCountry = 'DE'; ToCountry = 'US'
                FromTime = $now.AddHours(-6); ToTime = $now.AddHours(-5.5)
                DistanceKm = 6379; TimeDiffHours = 0.5; RequiredSpeedKmh = 12758
            }
        )
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @()
        BruteForce              = [PSCustomObject]@{
            Detected = $true; FailureCount = 7; SuccessAfter = $true
            AttackingIps = @('185.220.101.42', '45.33.32.156')
            FailureWindow = [PSCustomObject]@{
                Start = $now.AddHours(-6.5); End = $now.AddHours(-6.1)
                Duration = [TimeSpan]::FromMinutes(24)
            }
            SuccessEvent = [PSCustomObject]@{
                Timestamp = $now.AddHours(-6); IpAddress = '185.220.101.42'
            }
        }
        AfterHoursLogins        = @(
            [PSCustomObject]@{
                Timestamp = $now.AddHours(-6); LocalTime = $now.AddHours(-6)
                IpAddress = '185.220.101.42'; EventName = 'login_success'
                DayOfWeek = 'Wednesday'; LocalHour = 3; Timezone = 'UTC'
                Reason = 'Outside business hours (03:00 local, business hours 7:00-19:00)'
            }
        )
        NewDevices              = @(
            [PSCustomObject]@{
                Timestamp = $now.AddHours(-6); IpAddress = '185.220.101.42'
                IpClass = 'known_attacker'; IsCloudIp = $true
                DeviceId = $null; UserAgent = 'python-requests/2.31.0'
                Fingerprint = 'ua:python-requests/2.31.0'; EventName = 'login_success'
            }
        )
        IpClassifications       = @{
            '185.220.101.42' = @{ Class = 'known_attacker'; Country = 'DE'; Events = @('login_success') }
            '3.236.48.201'   = @{ Class = 'aws'; Country = 'US'; Events = @('login_success', 'risky_sensitive_action_allowed') }
            '98.137.246.8'   = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success') }
        }
        TotalLoginEvents        = 14
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u1

    # ============================================================
    # USER 2: CRITICAL — confirmed compromised, reauth from Azure, OAuth grant
    # ============================================================
    $u2 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'james.rodriguez@acme.com'
        ThreatLevel             = 'CRITICAL'
        ThreatScore             = 185.0
        IsKnownCompromised      = $true
        WasRemediated           = $true
        Indicators              = @(
            'CONFIRMED COMPROMISED (known victim)'
            'REAUTH FROM CLOUD - 3 reauth login(s) from cloud provider IPs (matches attack pattern)'
            'OAUTH FROM CLOUD IP - 2 OAuth grant(s) from cloud IPs: MailDaemon, CloudSync Pro'
            'CONCURRENT SESSIONS - 2 window(s) with multiple IPs (max 3 IPs simultaneously)'
            'SUSPICIOUS COUNTRY LOGIN - 1 login(s) from Russia (RU)'
        )
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @(
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '20.42.128.97' 'azure' 'US' ($now.AddDays(-2)) 'login' @{ login_type = 'reauth' })
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '20.42.128.97' 'azure' 'US' ($now.AddDays(-1.5)) 'login' @{ login_type = 'reauth' })
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '35.198.42.6' 'gcp' 'NL' ($now.AddDays(-1)) 'login' @{ login_type = 'reauth' })
        )
        ReauthFromCloud         = @(
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '20.42.128.97' 'azure' 'US' ($now.AddDays(-2)) 'login' @{ login_type = 'reauth' })
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '20.42.128.97' 'azure' 'US' ($now.AddDays(-1.5)) 'login' @{ login_type = 'reauth' })
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '35.198.42.6' 'gcp' 'NL' ($now.AddDays(-1)) 'login' @{ login_type = 'reauth' })
        )
        RiskyActions            = @()
        SuspiciousCountryLogins = @(
            (& $mockEvent 'james.rodriguez@acme.com' 'login_success' '95.165.8.42' '' 'RU' ($now.AddDays(-3)) 'login' @{})
        )
        SuspiciousOAuthGrants   = @(
            (& $mockEvent 'james.rodriguez@acme.com' 'authorize' '20.42.128.97' 'azure' '' ($now.AddDays(-1.8)) 'token' @{ app_name = 'MailDaemon' })
            (& $mockEvent 'james.rodriguez@acme.com' 'authorize' '35.198.42.6' 'gcp' '' ($now.AddDays(-0.9)) 'token' @{ app_name = 'CloudSync Pro' })
        )
        ImpossibleTravel        = @()
        ConcurrentSessions      = @(
            [PSCustomObject]@{
                WindowStart = $now.AddDays(-2); WindowEnd = $now.AddDays(-2).AddMinutes(3)
                DistinctIps = @('20.42.128.97', '95.165.8.42', '73.162.201.44'); IpCount = 3; EventCount = 4
            }
            [PSCustomObject]@{
                WindowStart = $now.AddDays(-1); WindowEnd = $now.AddDays(-1).AddMinutes(2)
                DistinctIps = @('35.198.42.6', '73.162.201.44'); IpCount = 2; EventCount = 3
            }
        )
        UserAgentAnomalies      = @()
        BruteForce              = $null
        AfterHoursLogins        = @()
        NewDevices              = @()
        IpClassifications       = @{
            '20.42.128.97' = @{ Class = 'azure'; Country = 'US'; Events = @('login_success', 'login_success', 'authorize') }
            '35.198.42.6'  = @{ Class = 'gcp'; Country = 'NL'; Events = @('login_success', 'authorize') }
            '95.165.8.42'  = @{ Class = ''; Country = 'RU'; Events = @('login_success') }
            '73.162.201.44' = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success', 'login_success') }
        }
        TotalLoginEvents        = 22
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u2

    # ============================================================
    # USER 3: HIGH — impossible travel + Tor + suspicious UA
    # ============================================================
    $u3 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'mike.oconnor@acme.com'
        ThreatLevel             = 'HIGH'
        ThreatScore             = 85.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @(
            'IMPOSSIBLE TRAVEL - 1 instance(s), e.g. US to JP (10,847 km in 2.1h)'
            'USER AGENT ANOMALY - 1 suspicious client(s): Selenium automation'
            'AFTER HOURS LOGIN - 3 login(s) outside business hours (1 outside hours, 2 weekend)'
        )
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @()
        ReauthFromCloud         = @()
        RiskyActions            = @()
        SuspiciousCountryLogins = @()
        SuspiciousOAuthGrants   = @()
        ImpossibleTravel        = @(
            [PSCustomObject]@{
                FromIp = '73.162.201.44'; ToIp = '126.78.215.3'
                FromCountry = 'US'; ToCountry = 'JP'
                FromTime = $now.AddDays(-1); ToTime = $now.AddDays(-1).AddHours(2.1)
                DistanceKm = 10847; TimeDiffHours = 2.1; RequiredSpeedKmh = 5165
            }
        )
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @(
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-1); IpAddress = '126.78.215.3'
                UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Selenium/4.8.0'
                MatchLabel = 'Selenium automation'; EventName = 'login_success'
            }
        )
        BruteForce              = $null
        AfterHoursLogins        = @(
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-1); LocalTime = $now.AddDays(-1)
                IpAddress = '126.78.215.3'; EventName = 'login_success'
                DayOfWeek = 'Wednesday'; LocalHour = 2; Timezone = 'UTC'
                Reason = 'Outside business hours (02:00 local, business hours 7:00-19:00)'
            }
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-3); LocalTime = $now.AddDays(-3)
                IpAddress = '73.162.201.44'; EventName = 'login_success'
                DayOfWeek = 'Saturday'; LocalHour = 14; Timezone = 'UTC'
                Reason = 'Weekend/non-business day (Saturday)'
            }
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-4); LocalTime = $now.AddDays(-4)
                IpAddress = '73.162.201.44'; EventName = 'login_success'
                DayOfWeek = 'Sunday'; LocalHour = 10; Timezone = 'UTC'
                Reason = 'Weekend/non-business day (Sunday)'
            }
        )
        NewDevices              = @()
        IpClassifications       = @{
            '73.162.201.44' = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success', 'login_success') }
            '126.78.215.3'  = @{ Class = ''; Country = 'JP'; Events = @('login_success') }
        }
        TotalLoginEvents        = 8
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u3

    # ============================================================
    # USER 4: HIGH — VPN + brute force attempt + suspicious country
    # ============================================================
    $u4 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'anna.petrov@acme.com'
        ThreatLevel             = 'HIGH'
        ThreatScore             = 75.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @(
            'SUSPICIOUS COUNTRY LOGIN - 2 login(s) from China (CN), Nigeria (NG)'
            'NEW DEVICE FROM CLOUD IP - 1 first-seen device(s) from cloud/hosting IPs'
            'BRUTE FORCE ATTEMPT - 8 login failures in 4.2 min from 3 IP(s)'
        )
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @(
            (& $mockEvent 'anna.petrov@acme.com' 'login_success' '159.89.174.12' 'digitalocean' 'NL' ($now.AddDays(-1)) 'login' @{})
        )
        ReauthFromCloud         = @()
        RiskyActions            = @()
        SuspiciousCountryLogins = @(
            (& $mockEvent 'anna.petrov@acme.com' 'login_success' '119.84.32.5' '' 'CN' ($now.AddDays(-2)) 'login' @{})
            (& $mockEvent 'anna.petrov@acme.com' 'login_success' '154.118.42.8' '' 'NG' ($now.AddDays(-1.5)) 'login' @{})
        )
        SuspiciousOAuthGrants   = @()
        ImpossibleTravel        = @()
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @()
        BruteForce              = [PSCustomObject]@{
            Detected = $true; FailureCount = 8; SuccessAfter = $false
            AttackingIps = @('119.84.32.5', '154.118.42.8', '103.42.18.9')
            FailureWindow = [PSCustomObject]@{
                Start = $now.AddDays(-2).AddMinutes(-5); End = $now.AddDays(-2).AddMinutes(-0.8)
                Duration = [TimeSpan]::FromMinutes(4.2)
            }
            SuccessEvent = $null
        }
        AfterHoursLogins        = @()
        NewDevices              = @(
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-1); IpAddress = '159.89.174.12'
                IpClass = 'digitalocean'; IsCloudIp = $true
                DeviceId = 'dev-x7829'; UserAgent = $null
                Fingerprint = 'device:dev-x7829'; EventName = 'login_success'
            }
        )
        IpClassifications       = @{
            '119.84.32.5'   = @{ Class = ''; Country = 'CN'; Events = @('login_failure', 'login_failure', 'login_failure', 'login_success') }
            '154.118.42.8'  = @{ Class = ''; Country = 'NG'; Events = @('login_failure', 'login_failure', 'login_success') }
            '103.42.18.9'   = @{ Class = 'vpn'; Country = 'SG'; Events = @('login_failure', 'login_failure', 'login_failure') }
            '159.89.174.12' = @{ Class = 'digitalocean'; Country = 'NL'; Events = @('login_success') }
            '72.134.89.201' = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success') }
        }
        TotalLoginEvents        = 18
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u4

    # ============================================================
    # USER 5: MEDIUM — cloud logins + after hours + new device
    # ============================================================
    $u5 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'david.kim@acme.com'
        ThreatLevel             = 'MEDIUM'
        ThreatScore             = 40.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @(
            'OAUTH FROM CLOUD IP - 1 OAuth grant(s) from cloud IPs: DataPipeline'
            'AFTER HOURS LOGIN - 5 login(s) outside business hours (3 outside hours, 2 weekend)'
        )
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @(
            (& $mockEvent 'david.kim@acme.com' 'login_success' '34.102.136.180' 'gcp' 'US' ($now.AddDays(-3)) 'login' @{})
        )
        ReauthFromCloud         = @()
        RiskyActions            = @()
        SuspiciousCountryLogins = @()
        SuspiciousOAuthGrants   = @(
            (& $mockEvent 'david.kim@acme.com' 'authorize' '34.102.136.180' 'gcp' '' ($now.AddDays(-3)) 'token' @{ app_name = 'DataPipeline' })
        )
        ImpossibleTravel        = @()
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @()
        BruteForce              = $null
        AfterHoursLogins        = @(
            [PSCustomObject]@{ Timestamp = $now.AddDays(-1); LocalTime = $now.AddDays(-1); IpAddress = '72.134.89.201'; EventName = 'login_success'; DayOfWeek = 'Wednesday'; LocalHour = 23; Timezone = 'UTC'; Reason = 'Outside business hours (23:00 local, business hours 7:00-19:00)' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-2); LocalTime = $now.AddDays(-2); IpAddress = '72.134.89.201'; EventName = 'login_success'; DayOfWeek = 'Tuesday'; LocalHour = 4; Timezone = 'UTC'; Reason = 'Outside business hours (04:00 local, business hours 7:00-19:00)' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-3); LocalTime = $now.AddDays(-3); IpAddress = '34.102.136.180'; EventName = 'login_success'; DayOfWeek = 'Monday'; LocalHour = 1; Timezone = 'UTC'; Reason = 'Outside business hours (01:00 local, business hours 7:00-19:00)' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-5); LocalTime = $now.AddDays(-5); IpAddress = '72.134.89.201'; EventName = 'login_success'; DayOfWeek = 'Saturday'; LocalHour = 14; Timezone = 'UTC'; Reason = 'Weekend/non-business day (Saturday)' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-6); LocalTime = $now.AddDays(-6); IpAddress = '72.134.89.201'; EventName = 'login_success'; DayOfWeek = 'Sunday'; LocalHour = 9; Timezone = 'UTC'; Reason = 'Weekend/non-business day (Sunday)' }
        )
        NewDevices              = @()
        IpClassifications       = @{
            '34.102.136.180' = @{ Class = 'gcp'; Country = 'US'; Events = @('login_success', 'authorize') }
            '72.134.89.201'  = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success', 'login_success', 'login_success', 'login_success') }
        }
        TotalLoginEvents        = 11
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u5

    # ============================================================
    # USER 6: MEDIUM — Tor exit node + user agent anomaly
    # ============================================================
    $u6 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'lisa.nakamura@acme.com'
        ThreatLevel             = 'MEDIUM'
        ThreatScore             = 45.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @(
            'USER AGENT ANOMALY - 2 suspicious client(s): Python requests library, curl'
            'CLOUD IP LOGINS - 3 login(s) from cloud/hosting provider IPs'
        )
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @(
            (& $mockEvent 'lisa.nakamura@acme.com' 'login_success' '104.16.132.229' 'cloudflare' 'US' ($now.AddDays(-1)) 'login' @{})
            (& $mockEvent 'lisa.nakamura@acme.com' 'login_success' '104.16.132.229' 'cloudflare' 'US' ($now.AddDays(-2)) 'login' @{})
            (& $mockEvent 'lisa.nakamura@acme.com' 'login_success' '152.89.196.211' 'ovh' 'FR' ($now.AddDays(-3)) 'login' @{})
        )
        ReauthFromCloud         = @()
        RiskyActions            = @()
        SuspiciousCountryLogins = @()
        SuspiciousOAuthGrants   = @()
        ImpossibleTravel        = @()
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @(
            [PSCustomObject]@{ Timestamp = $now.AddDays(-1); IpAddress = '104.16.132.229'; UserAgent = 'python-requests/2.28.1'; MatchLabel = 'Python requests library'; EventName = 'login_success' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-3); IpAddress = '152.89.196.211'; UserAgent = 'curl/7.88.0'; MatchLabel = 'curl'; EventName = 'login_success' }
        )
        BruteForce              = $null
        AfterHoursLogins        = @()
        NewDevices              = @()
        IpClassifications       = @{
            '104.16.132.229' = @{ Class = 'cloudflare'; Country = 'US'; Events = @('login_success', 'login_success') }
            '152.89.196.211' = @{ Class = 'ovh'; Country = 'FR'; Events = @('login_success') }
            '192.168.1.10'   = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success') }
        }
        TotalLoginEvents        = 7
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u6

    # ============================================================
    # USER 7: LOW — new device only
    # ============================================================
    $u7 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'robert.patel@acme.com'
        ThreatLevel             = 'LOW'
        ThreatScore             = 10.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @('NEW DEVICE - 2 first-seen device(s)')
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @()
        ReauthFromCloud         = @()
        RiskyActions            = @()
        SuspiciousCountryLogins = @()
        SuspiciousOAuthGrants   = @()
        ImpossibleTravel        = @()
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @()
        BruteForce              = $null
        AfterHoursLogins        = @()
        NewDevices              = @(
            [PSCustomObject]@{ Timestamp = $now.AddDays(-1); IpAddress = '72.134.89.201'; IpClass = ''; IsCloudIp = $false; DeviceId = 'pixel-8-new'; UserAgent = $null; Fingerprint = 'device:pixel-8-new'; EventName = 'login_success' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-2); IpAddress = '72.134.89.201'; IpClass = ''; IsCloudIp = $false; DeviceId = $null; UserAgent = 'Mozilla/5.0 (Linux; Android 14) Chrome/121.0'; Fingerprint = 'ua:Mozilla/5.0 (Linux; Android 14) Chrome/121.0'; EventName = 'login_success' }
        )
        IpClassifications       = @{
            '72.134.89.201' = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success', 'login_success') }
        }
        TotalLoginEvents        = 5
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u7

    # ============================================================
    # USER 8: LOW — after-hours only
    # ============================================================
    $u8 = [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = 'emily.watson@acme.com'
        ThreatLevel             = 'LOW'
        ThreatScore             = 15.0
        IsKnownCompromised      = $false
        WasRemediated           = $false
        Indicators              = @('AFTER HOURS LOGIN - 2 login(s) outside business hours (2 outside hours)')
        KnownAttackerIpLogins   = @()
        CloudIpLogins           = @()
        ReauthFromCloud         = @()
        RiskyActions            = @()
        SuspiciousCountryLogins = @()
        SuspiciousOAuthGrants   = @()
        ImpossibleTravel        = @()
        ConcurrentSessions      = @()
        UserAgentAnomalies      = @()
        BruteForce              = $null
        AfterHoursLogins        = @(
            [PSCustomObject]@{ Timestamp = $now.AddDays(-1); LocalTime = $now.AddDays(-1); IpAddress = '72.134.89.201'; EventName = 'login_success'; DayOfWeek = 'Monday'; LocalHour = 22; Timezone = 'UTC'; Reason = 'Outside business hours (22:00 local, business hours 7:00-19:00)' }
            [PSCustomObject]@{ Timestamp = $now.AddDays(-3); LocalTime = $now.AddDays(-3); IpAddress = '72.134.89.201'; EventName = 'login_success'; DayOfWeek = 'Thursday'; LocalHour = 5; Timezone = 'UTC'; Reason = 'Outside business hours (05:00 local, business hours 7:00-19:00)' }
        )
        NewDevices              = @()
        IpClassifications       = @{
            '72.134.89.201' = @{ Class = ''; Country = 'US'; Events = @('login_success', 'login_success', 'login_success', 'login_success') }
        }
        TotalLoginEvents        = 6
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
    $profiles += $u8

    # --- Generate report ---
    $totalUsers = 247
    $cleanCount = $totalUsers - $profiles.Count
    $totalEvents = 12483

    Write-GuerrillaText "  Generating HTML report with $($profiles.Count) flagged users..." -Color Dim

    Export-FieldReportHtml `
        -Profiles $profiles `
        -AllProfilesCount $totalUsers `
        -CleanCount $cleanCount `
        -AllEventsCount $totalEvents `
        -DaysBack 30 `
        -TimestampStr (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `
        -FilePath $OutputPath

    Write-GuerrillaText "Demo report generated: $OutputPath" -Color Sage

    if (-not $NoOpen) {
        Write-GuerrillaText 'Opening in browser...' -Color Dim
        Invoke-Item $OutputPath
    }

    [PSCustomObject]@{
        FilePath     = $OutputPath
        FlaggedUsers = $profiles.Count
        TotalUsers   = $totalUsers
    }
}
