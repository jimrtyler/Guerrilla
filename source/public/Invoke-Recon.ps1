# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Recon {
    [CmdletBinding()]
    param(
        [string]$ServiceAccountKeyPath,
        [string]$AdminEmail,
        [ValidateRange(1, 180)]
        [int]$DaysBack,
        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode,
        [string]$OutputDirectory,
        [switch]$Force,
        [switch]$NoReports,
        [switch]$NoGeoIp,
        [switch]$Quiet,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,

        [Alias('MissionConfig')]
        [string]$ConfigFile
    )

    $tempSaPath = $null
    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $vaultName = $missionCfg.VaultName

        # Resolve GWS credentials from vault
        $gwsRef = $missionCfg.Config.credentials.references.googleWorkspace
        if ($gwsRef) {
            if (-not $PSBoundParameters.ContainsKey('ServiceAccountKeyPath')) {
                try {
                    $saJson = Get-GuerrillaCredential -VaultKey $gwsRef.vaultKey -VaultName $vaultName
                    $tempSaPath = Join-Path ([System.IO.Path]::GetTempPath()) "guerrilla-sa-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
                    $saJson | Set-Content -Path $tempSaPath -Encoding UTF8
                    $ServiceAccountKeyPath = $tempSaPath
                } catch {
                    Write-Warning "Failed to resolve GWS service account from vault: $_"
                }
            }
            if (-not $PSBoundParameters.ContainsKey('AdminEmail')) {
                try {
                    $AdminEmail = Get-GuerrillaCredential -VaultKey "$($gwsRef.vaultKey)_ADMIN_EMAIL" -VaultName $vaultName
                } catch {
                    Write-Verbose "AdminEmail not found in vault — will fall back to config.json or parameter."
                }
            }
        }

        # Apply monitoring interval from mission config
        $gwsEnv = $missionCfg.EnabledEnvironments['googleWorkspace']
        if ($gwsEnv -and $gwsEnv.monitoring -and $gwsEnv.monitoring.intervalMinutes) {
            # Store for potential use by Register-Patrol
            $script:MissionMonitorInterval = $gwsEnv.monitoring.intervalMinutes
        }

        # Extract detection filter from mission config
        if ($gwsEnv -and $gwsEnv.monitoring -and $gwsEnv.monitoring.detections) {
            $script:DetectionFilter = $gwsEnv.monitoring.detections
        }
    }

    # The mission-config path may have staged the vault service-account key to a
    # temp file (guerrilla-sa-*.json). Guarantee it is removed when the scan ends -
    # including on throw - so the private key never lingers in the temp directory.
    try {
        $scanId = [guid]::NewGuid().ToString()
        $scanStart = [datetime]::UtcNow

        # --- Load config ---
        $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
        $config = $null
        if (Test-Path $cfgPath) {
            $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
        }

        # Merge parameters over config over defaults
        $keyPath  = if ($ServiceAccountKeyPath) { $ServiceAccountKeyPath }
                    elseif ($config) { $config.google.serviceAccountKeyPath }
                    else { $null }
        $admin    = if ($AdminEmail) { $AdminEmail }
                    elseif ($config) { $config.google.adminEmail }
                    else { $null }
        $days     = if ($PSBoundParameters.ContainsKey('DaysBack')) { $DaysBack }
                    elseif ($config -and $config.google.defaultDaysBack) { $config.google.defaultDaysBack }
                    else { 30 }
        $mode     = if ($ScanMode) { $ScanMode }
                    elseif ($config -and $config.google.defaultScanMode) { $config.google.defaultScanMode }
                    else { 'Fast' }
        $outDir   = if ($OutputDirectory) { $OutputDirectory }
                    elseif ($config -and $config.output.directory) { $config.output.directory }
                    else { Join-Path (Get-GuerrillaDataRoot) 'Reports' }

        # Validate required parameters
        if (-not $keyPath) { throw 'ServiceAccountKeyPath is required. Provide it as a parameter or set it in config.' }
        if (-not $admin)   { throw 'AdminEmail is required. Provide it as a parameter or set it in config.' }

        # --- Operation header ---
        if (-not $Quiet) {
            Write-OperationHeader -Operation 'RECONNAISSANCE SWEEP' -Mode $mode -Target $admin -DaysBack $days
        }

        # --- Load state ---
        $state = Get-OperationState -ConfigPath $cfgPath
        $startTime = $null

        if ($Force -or -not $state) {
            # First run or forced: look back $days
            $startTime = [datetime]::UtcNow.AddDays(-$days)
            if (-not $state) {
                if (-not $Quiet) { Write-ProgressLine -Phase INFO -Message "First run" -Detail "scanning $days days of history" }
            } else {
                if (-not $Quiet) { Write-ProgressLine -Phase INFO -Message "Forced rescan" -Detail "scanning $days days of history" }
            }
        } else {
            # Subsequent run: use watermark
            $startTime = [datetime]::Parse($state.watermark).ToUniversalTime()
            $daysSinceWatermark = [Math]::Round(([datetime]::UtcNow - $startTime).TotalDays, 1)
            if (-not $Quiet) { Write-ProgressLine -Phase INFO -Message "Incremental scan" -Detail "since watermark ($daysSinceWatermark days)" }
        }

        # --- Authenticate ---
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Authenticating to Google Workspace' }
        $accessToken = Get-GoogleAccessToken -ServiceAccountKeyPath $keyPath -AdminEmail $admin

        # --- Collect events ---
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Login events' }
        $loginEvents = Invoke-GoogleReportsApi -AccessToken $accessToken -ApplicationName 'login' -StartTime $startTime -Quiet:$Quiet
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Login events' -Detail "$($loginEvents.Count) found" }

        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Admin events' }
        $adminEvents = Invoke-GoogleReportsApi -AccessToken $accessToken -ApplicationName 'admin' -StartTime $startTime -Quiet:$Quiet
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Admin events' -Detail "$($adminEvents.Count) found" }

        $tokenEvents = @()
        $accountEvents = @()
        $driveEvents = @()
        if ($mode -eq 'Full') {
            if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'OAuth token events (full mode)' }
            $tokenEvents = Invoke-GoogleReportsApi -AccessToken $accessToken -ApplicationName 'token' -StartTime $startTime -Quiet:$Quiet
            if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'OAuth token events' -Detail "$($tokenEvents.Count) found" }

            if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'User account events' }
            $accountEvents = Invoke-GoogleReportsApi -AccessToken $accessToken -ApplicationName 'user_accounts' -StartTime $startTime -Quiet:$Quiet
            if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'User account events' -Detail "$($accountEvents.Count) found" }

            if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Drive events (full mode)' }
            $driveEvents = Invoke-GoogleReportsApi -AccessToken $accessToken -ApplicationName 'drive' -StartTime $startTime -Quiet:$Quiet
            if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Drive events' -Detail "$($driveEvents.Count) found" }
        }

        $totalEvents = $loginEvents.Count + $adminEvents.Count + $tokenEvents.Count + $accountEvents.Count + $driveEvents.Count
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Total events collected' -Detail "$($totalEvents.ToString('N0'))" }

        # --- GeoIP enrichment ---
        $geoData = @{}
        if (-not $NoGeoIp) {
            $allIps = @($loginEvents | ForEach-Object { $_.IpAddress } | Where-Object { $_ } | Sort-Object -Unique)
            if ($allIps.Count -gt 0) {
                if (-not $Quiet) { Write-ProgressLine -Phase ENRICHING -Message "GeoIP: $($allIps.Count) unique IPs" }
                $geoData = Get-IpGeoData -IpAddresses $allIps
                if (-not $Quiet) { Write-ProgressLine -Phase ENRICHING -Message "GeoIP enrichment" -Detail "done" }
            }
        }

        # --- Build known compromised users set ---
        $knownCompromised = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($config -and $config.detection.knownCompromisedUsers) {
            foreach ($u in $config.detection.knownCompromisedUsers) {
                [void]$knownCompromised.Add($u)
            }
        }

        # --- Identify remediated users from admin events ---
        $remediatedUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($event in $adminEvents) {
            if ($event.EventName -in @('CHANGE_PASSWORD', 'RESET_SIGNIN_COOKIES', 'TURN_OFF_2_STEP_VERIFICATION')) {
                $targetEmail = $event.Params['USER_EMAIL']
                if ($targetEmail) { [void]$remediatedUsers.Add($targetEmail) }
            }
        }

        # --- Bucket events by user ---
        $userLoginEvents = @{}
        $userTokenEvents = @{}
        $userAccountEvents = @{}
        $userAdminEvents = @{}
        $userDriveEvents = @{}

        foreach ($event in $loginEvents) {
            $user = $event.User
            if (-not $user) { continue }
            if (-not $userLoginEvents.ContainsKey($user)) {
                $userLoginEvents[$user] = [System.Collections.Generic.List[hashtable]]::new()
            }
            $userLoginEvents[$user].Add($event)
        }

        foreach ($event in $tokenEvents) {
            $user = $event.User
            if (-not $user) { continue }
            if (-not $userTokenEvents.ContainsKey($user)) {
                $userTokenEvents[$user] = [System.Collections.Generic.List[hashtable]]::new()
            }
            $userTokenEvents[$user].Add($event)
        }

        foreach ($event in $accountEvents) {
            $user = $event.User
            if (-not $user) { continue }
            if (-not $userAccountEvents.ContainsKey($user)) {
                $userAccountEvents[$user] = [System.Collections.Generic.List[hashtable]]::new()
            }
            $userAccountEvents[$user].Add($event)
        }

        foreach ($event in $adminEvents) {
            $user = $event.User
            if (-not $user) { continue }
            if (-not $userAdminEvents.ContainsKey($user)) {
                $userAdminEvents[$user] = [System.Collections.Generic.List[hashtable]]::new()
            }
            $userAdminEvents[$user].Add($event)
        }

        foreach ($event in $driveEvents) {
            $user = $event.User
            if (-not $user) { continue }
            if (-not $userDriveEvents.ContainsKey($user)) {
                $userDriveEvents[$user] = [System.Collections.Generic.List[hashtable]]::new()
            }
            $userDriveEvents[$user].Add($event)
        }

        # --- Build detection config for new signals ---
        $detectionCfg = @{}
        if ($config -and $config.detection) {
            $det = $config.detection
            if ($det.businessHoursStart)     { $detectionCfg.businessHoursStart = $det.businessHoursStart }
            if ($det.businessHoursEnd)       { $detectionCfg.businessHoursEnd = $det.businessHoursEnd }
            if ($det.businessHoursTimezone)  { $detectionCfg.businessHoursTimezone = $det.businessHoursTimezone }
            if ($det.businessDays)           { $detectionCfg.businessDays = $det.businessDays }
            if ($det.impossibleTravelSpeedKmh) { $detectionCfg.impossibleTravelSpeedKmh = $det.impossibleTravelSpeedKmh }
            if ($det.concurrentSessionWindowMinutes) { $detectionCfg.concurrentSessionWindowMinutes = $det.concurrentSessionWindowMinutes }
            if ($det.bruteForceFailureThreshold) { $detectionCfg.bruteForceFailureThreshold = $det.bruteForceFailureThreshold }
            if ($det.bruteForceWindowMinutes) { $detectionCfg.bruteForceWindowMinutes = $det.bruteForceWindowMinutes }
            if ($det.bulkDownloadThreshold) { $detectionCfg.bulkDownloadThreshold = $det.bulkDownloadThreshold }
            if ($det.bulkDownloadWindowMinutes) { $detectionCfg.bulkDownloadWindowMinutes = $det.bulkDownloadWindowMinutes }
            if ($det.highRiskOAuthAppPatterns) { $detectionCfg.highRiskOAuthAppPatterns = $det.highRiskOAuthAppPatterns }
        }

        # Load previous device fingerprints from state for new-device detection
        $previousDevices = @{}
        if ($state -and $state.knownDevices) {
            $previousDevices = $state.knownDevices
        }

        # Extract internal domain from admin email for external sharing detection
        $internalDomain = ''
        if ($admin -match '@(.+)$') { $internalDomain = $Matches[1] }

        # --- Build profiles for all users ---
        $allUsers = @($userLoginEvents.Keys + $userTokenEvents.Keys + $userAccountEvents.Keys + $userAdminEvents.Keys + $userDriveEvents.Keys | Sort-Object -Unique)
        if (-not $Quiet) { Write-ProgressLine -Phase ANALYZING -Message "$($allUsers.Count) users" }

        $profiles = @{}
        foreach ($email in $allUsers) {
            $uLogin   = if ($userLoginEvents.ContainsKey($email)) { @($userLoginEvents[$email]) } else { @() }
            $uToken   = if ($userTokenEvents.ContainsKey($email)) { @($userTokenEvents[$email]) } else { @() }
            $uAccount = if ($userAccountEvents.ContainsKey($email)) { @($userAccountEvents[$email]) } else { @() }
            $uAdmin   = if ($userAdminEvents.ContainsKey($email)) { @($userAdminEvents[$email]) } else { @() }
            $uDrive   = if ($userDriveEvents.ContainsKey($email)) { @($userDriveEvents[$email]) } else { @() }

            $userPrevDevices = if ($previousDevices.ContainsKey($email)) { $previousDevices[$email] } else { @{} }

            $profileParams = @{
                Email              = $email
                LoginEvents        = $uLogin
                TokenEvents        = $uToken
                AccountEvents      = $uAccount
                AdminEvents        = $uAdmin
                DriveEvents        = $uDrive
                GeoData            = $geoData
                IsKnownCompromised = $knownCompromised.Contains($email)
                WasRemediated      = $remediatedUsers.Contains($email)
                DetectionConfig    = $detectionCfg
                PreviousDevices    = $userPrevDevices
                InternalDomain     = $internalDomain
            }
            if ($script:DetectionFilter) {
                $profileParams['DetectionFilter'] = $script:DetectionFilter
            }

            $profile = New-UserCompromiseProfile @profileParams

            $profiles[$email] = $profile
        }

        # --- Pass 2 (Fast mode): Targeted token fetch for flagged users ---
        if ($mode -eq 'Fast') {
            $suspects = @($profiles.Values | Where-Object {
                $_.ThreatScore -gt 0 -and $_.ThreatLevel -in @('CRITICAL', 'HIGH', 'MEDIUM')
            } | ForEach-Object { $_.Email })

            if ($suspects.Count -gt 0) {
                if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message "Pass 2: OAuth for $($suspects.Count) flagged users" }

                foreach ($userEmail in $suspects) {
                    $userTokenEvts = Invoke-GoogleReportsApi `
                        -AccessToken $accessToken `
                        -ApplicationName 'token' `
                        -UserKey $userEmail `
                        -StartTime $startTime `
                        -Quiet:$Quiet

                    if ($userTokenEvts.Count -gt 0) {
                        $totalEvents += $userTokenEvts.Count
                        $profile = $profiles[$userEmail]

                        # Re-analyze OAuth signals
                        $profile.SuspiciousOAuthGrants = [System.Collections.Generic.List[PSCustomObject]]::new()
                        foreach ($event in $userTokenEvts) {
                            $ip = $event.IpAddress
                            $ipClass = if ($ip) { Get-CloudIpClassification -IpAddress $ip } else { '' }
                            $isCloud = $ipClass -and ($ipClass -eq 'known_attacker' -or $script:CloudProviderClasses.Contains($ipClass))
                            if ($event.EventName -eq 'authorize' -and $isCloud) {
                                $profile.SuspiciousOAuthGrants.Add([PSCustomObject]@{
                                    Timestamp  = $event.Timestamp
                                    User       = $event.User
                                    EventName  = $event.EventName
                                    IpAddress  = $ip
                                    IpClass    = $ipClass
                                    GeoCountry = ''
                                    Source     = $event.Source
                                    Params     = $event.Params
                                })
                            }
                        }

                        # Re-score
                        $profiles[$userEmail] = Get-ThreatScore -Profile $profile
                    }
                }
            } else {
                if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'No flagged users' -Detail 'skipping OAuth fetch' }
            }
        }

        # --- Sort and categorize ---
        $allProfiles = @($profiles.Values | Sort-Object -Property ThreatScore -Descending)
        $flagged = @($allProfiles | Where-Object { $_.ThreatScore -gt 0 })
        $cleanCount = $allProfiles.Count - $flagged.Count

        # --- Determine new threats (compare against state) ---
        $alertedUsers = if ($state -and $state.alertedUsers -and -not $Force) { $state.alertedUsers } else { @{} }
        $newThreats = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($profile in $flagged) {
            $isNew = $false
            if (-not $alertedUsers.ContainsKey($profile.Email)) {
                $isNew = $true
            } else {
                $prev = $alertedUsers[$profile.Email]
                # Escalation check
                $levelOrder = @{ 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
                $prevLevel = $levelOrder[$prev.lastThreatLevel]
                $currLevel = $levelOrder[$profile.ThreatLevel]
                if ($currLevel -gt $prevLevel) { $isNew = $true }

                # New indicator check
                $prevHashes = [System.Collections.Generic.HashSet[string]]::new()
                if ($prev.indicatorHashes) {
                    foreach ($h in $prev.indicatorHashes) { [void]$prevHashes.Add($h) }
                }
                foreach ($ind in $profile.Indicators) {
                    $hash = [System.BitConverter]::ToString(
                        [System.Security.Cryptography.SHA256]::HashData(
                            [System.Text.Encoding]::UTF8.GetBytes($ind)
                        )
                    ).Replace('-', '').Substring(0, 16)
                    if (-not $prevHashes.Contains($hash)) {
                        $isNew = $true
                        break
                    }
                }
            }

            if ($isNew) {
                $newThreats.Add($profile)
            }
        }

        # --- Print themed field report ---
        if (-not $Quiet) {
            $critCount = @($flagged | Where-Object ThreatLevel -eq 'CRITICAL').Count
            $highCount = @($flagged | Where-Object ThreatLevel -eq 'HIGH').Count
            $medCount  = @($flagged | Where-Object ThreatLevel -eq 'MEDIUM').Count
            $lowCount  = @($flagged | Where-Object ThreatLevel -eq 'LOW').Count

            Write-FieldReport `
                -TotalUsers $allProfiles.Count `
                -FlaggedCount $flagged.Count `
                -CleanCount $cleanCount `
                -CriticalCount $critCount `
                -HighCount $highCount `
                -MediumCount $medCount `
                -LowCount $lowCount `
                -NewThreats $newThreats.Count `
                -TotalEvents $totalEvents `
                -FlaggedUsers $flagged

            if ($newThreats.Count -gt 0) {
                Write-InterceptAlert -NewThreats @($newThreats)
            }
        }

        # --- Generate reports ---
        $csvPath = $null; $htmlPath = $null; $jsonPath = $null
        if (-not $NoReports) {
            if (-not (Test-Path $outDir)) {
                New-Item -Path $outDir -ItemType Directory -Force | Out-Null
            }
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

            $genCsv  = if ($config -and $null -ne $config.output.generateCsv) { $config.output.generateCsv } else { $true }
            $genHtml = if ($config -and $null -ne $config.output.generateHtml) { $config.output.generateHtml } else { $true }
            $genJson = if ($config -and $null -ne $config.output.generateJson) { $config.output.generateJson } else { $true }

            if ($genCsv -and $flagged.Count -gt 0) {
                $csvPath = Join-Path $outDir "field_report_$timestamp.csv"
                Export-FieldReportCsv -Profiles $flagged -FilePath $csvPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message "CSV report" -Detail $csvPath }
            }
            if ($genHtml) {
                $htmlPath = Join-Path $outDir "field_report_$timestamp.html"
                Export-FieldReportHtml -Profiles $flagged -AllProfilesCount $allProfiles.Count `
                    -CleanCount $cleanCount -AllEventsCount $totalEvents `
                    -DaysBack $days -TimestampStr (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `
                    -FilePath $htmlPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message "HTML report" -Detail $htmlPath }
            }
            if ($genJson -and $newThreats.Count -gt 0) {
                $jsonPath = Join-Path $outDir "NEW_COMPROMISES_SIGNAL_$timestamp.json"
                Export-FieldReportJson -Profiles @($newThreats) -FilePath $jsonPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message "Signal JSON" -Detail $jsonPath }
            }
        }

        # --- Update state ---
        $newAlertedUsers = @{}
        if ($alertedUsers) {
            foreach ($key in $alertedUsers.Keys) {
                $newAlertedUsers[$key] = $alertedUsers[$key]
            }
        }

        foreach ($profile in $flagged) {
            $indicatorHashes = @($profile.Indicators | ForEach-Object {
                [System.BitConverter]::ToString(
                    [System.Security.Cryptography.SHA256]::HashData(
                        [System.Text.Encoding]::UTF8.GetBytes($_)
                    )
                ).Replace('-', '').Substring(0, 16)
            })

            if ($newAlertedUsers.ContainsKey($profile.Email)) {
                $existing = $newAlertedUsers[$profile.Email]
                $existing.lastThreatLevel = $profile.ThreatLevel
                $existing.lastThreatScore = $profile.ThreatScore
                $existing.indicatorHashes = $indicatorHashes
                if ($profile.Email -in $newThreats.Email) {
                    $existing.lastAlerted = [datetime]::UtcNow.ToString('o')
                    $existing.alertCount = ($existing.alertCount ?? 0) + 1
                }
            } else {
                $newAlertedUsers[$profile.Email] = @{
                    firstDetected    = [datetime]::UtcNow.ToString('o')
                    lastAlerted      = [datetime]::UtcNow.ToString('o')
                    lastThreatLevel  = $profile.ThreatLevel
                    lastThreatScore  = $profile.ThreatScore
                    alertCount       = 1
                    indicatorHashes  = $indicatorHashes
                }
            }
        }

        $scanHistory = [System.Collections.Generic.List[object]]::new()
        if ($state -and $state.scanHistory) {
            foreach ($entry in $state.scanHistory) { $scanHistory.Add($entry) }
        }
        $scanHistory.Add(@{
            scanId        = $scanId
            timestamp     = [datetime]::UtcNow.ToString('o')
            daysAnalyzed  = $days
            mode          = $mode
            criticalCount = @($flagged | Where-Object ThreatLevel -eq 'CRITICAL').Count
            highCount     = @($flagged | Where-Object ThreatLevel -eq 'HIGH').Count
            flaggedCount  = $flagged.Count
            totalUsers    = $allProfiles.Count
        })

        # Collect device fingerprints for future new-device detection
        $newKnownDevices = if ($previousDevices) { @{} + $previousDevices } else { @{} }
        foreach ($p in $allProfiles) {
            if ($p.NewDevices.Count -gt 0) {
                if (-not $newKnownDevices.ContainsKey($p.Email)) {
                    $newKnownDevices[$p.Email] = @{}
                }
                foreach ($dev in $p.NewDevices) {
                    $newKnownDevices[$p.Email][$dev.Fingerprint] = @{
                        firstSeen = $dev.Timestamp
                        ipAddress = $dev.IpAddress
                    }
                }
            }
        }

        $newState = @{
            schemaVersion = 1
            watermark     = [datetime]::UtcNow.ToString('o')
            lastScanId    = $scanId
            alertedUsers  = $newAlertedUsers
            scanHistory   = $scanHistory
            knownDevices  = $newKnownDevices
        }
        Save-OperationState -State $newState -ConfigPath $cfgPath

        # --- Emit result object ---
        $result = [PSCustomObject]@{
            PSTypeName          = 'Guerrilla.ScanResult'
            ScanId              = $scanId
            Timestamp           = $scanStart
            DaysAnalyzed        = $days
            ScanMode            = $mode
            TotalUsersScanned   = $allProfiles.Count
            TotalEventsAnalyzed = $totalEvents
            CriticalCount       = @($flagged | Where-Object ThreatLevel -eq 'CRITICAL').Count
            HighCount           = @($flagged | Where-Object ThreatLevel -eq 'HIGH').Count
            MediumCount         = @($flagged | Where-Object ThreatLevel -eq 'MEDIUM').Count
            LowCount            = @($flagged | Where-Object ThreatLevel -eq 'LOW').Count
            CleanCount          = $cleanCount
            FlaggedUsers        = $flagged
            NewThreats          = @($newThreats)
            CsvReportPath       = $csvPath
            HtmlReportPath      = $htmlPath
            JsonAlertPath       = $jsonPath
            AllProfiles         = $profiles
        }

        return $result
    } finally {
        if ($tempSaPath -and (Test-Path $tempSaPath)) {
            Remove-Item -Path $tempSaPath -Force -ErrorAction SilentlyContinue
        }
    }
}
