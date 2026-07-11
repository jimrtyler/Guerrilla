# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Surveillance {
    <#
    .SYNOPSIS
        Performs continuous Entra ID security monitoring via Microsoft Graph API.

    .DESCRIPTION
        Invoke-Surveillance executes a comprehensive audit of Entra ID sign-in logs, risk
        detections, and directory audit events to detect identity-based threats. It monitors
        risky sign-ins, impossible travel, anonymous IP sign-ins, leaked credentials, password
        spray attacks, privileged role changes, conditional access policy modifications,
        service principal credential additions, federation domain changes, and more.

        Provides agentless identity threat detection — UEBA-style behavioral analysis and sign-in
        risk evaluation over Entra ID sign-in and audit telemetry.

    .PARAMETER TenantId
        The Azure AD / Entra ID tenant ID.

    .PARAMETER ClientId
        The application (client) ID for authentication.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for app-only authentication.

    .PARAMETER ClientSecret
        Client secret for app-only authentication.

    .PARAMETER DeviceCode
        Use device code flow for interactive authentication.

    .PARAMETER DaysBack
        Number of days to look back on first run or forced rescan. Default: 7. Range: 1-180.

    .PARAMETER ScanMode
        Fast: Sign-in events + risk detections only.
        Full: All three endpoints including directory audits. Default: Fast.

    .PARAMETER OutputDirectory
        Directory for report output. Default: per-user data dir + /Guerrilla/Reports
        (Windows: $env:APPDATA; macOS: ~/Library/Application Support; Linux: $XDG_CONFIG_HOME or ~/.config)

    .PARAMETER Force
        Force a full rescan ignoring the watermark from previous runs.

    .PARAMETER NoReports
        Skip report generation.

    .PARAMETER Quiet
        Suppress console output.

    .PARAMETER ConfigPath
        Path to Guerrilla configuration file.

    .EXAMPLE
        Invoke-Surveillance -TenantId 'contoso.onmicrosoft.com' -ClientId $appId -ClientSecret $secret

    .EXAMPLE
        Invoke-Surveillance -TenantId $tenantId -ClientId $appId -DeviceCode -ScanMode Full -DaysBack 30

    .EXAMPLE
        Invoke-Surveillance -TenantId $tenantId -ClientId $appId -CertificateThumbprint $thumb -Force
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,

        [string]$ClientId,

        [string]$CertificateThumbprint,

        [securestring]$ClientSecret,

        [switch]$DeviceCode,

        [ValidateRange(1, 180)]
        [int]$DaysBack = 7,

        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode = 'Fast',

        [string]$OutputDirectory,

        [switch]$Force,

        [switch]$NoReports,

        [switch]$Quiet,

        [Alias('RuntimeConfig')]
        [string]$ConfigPath,

        [Alias('MissionConfig')]
        [string]$ConfigFile,

        [string]$VaultName = 'Guerrilla'
    )

    $vaultName = $VaultName

    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $vaultName = $missionCfg.VaultName

        # Resolve Microsoft Graph credentials from vault
        $graphRef = $missionCfg.Config.credentials.references.microsoftGraph
        if ($graphRef) {
            if ($graphRef.tenantIdVaultKey -and -not $PSBoundParameters.ContainsKey('TenantId')) {
                try {
                    $TenantId = Get-GuerrillaCredential -VaultKey $graphRef.tenantIdVaultKey -VaultName $vaultName
                } catch {
                    Write-Warning "Failed to resolve TenantId from vault: $_"
                }
            }
            if ($graphRef.clientIdVaultKey -and -not $PSBoundParameters.ContainsKey('ClientId')) {
                try {
                    $ClientId = Get-GuerrillaCredential -VaultKey $graphRef.clientIdVaultKey -VaultName $vaultName
                } catch {
                    Write-Warning "Failed to resolve ClientId from vault: $_"
                }
            }
            if ($graphRef.vaultKey -and -not $PSBoundParameters.ContainsKey('CertificateThumbprint') -and -not $PSBoundParameters.ContainsKey('ClientSecret')) {
                try {
                    $secretVal = Get-GuerrillaCredential -VaultKey $graphRef.vaultKey -VaultName $vaultName
                    if ($graphRef.authMethod -eq 'certificate') {
                        $CertificateThumbprint = $secretVal
                    } else {
                        $ClientSecret = $secretVal | ConvertTo-SecureString -AsPlainText -Force
                    }
                } catch {
                    Write-Warning "Failed to resolve Graph auth credential from vault: $_"
                }
            }
        }

        # Apply monitoring interval from mission config
        $entraEnv = $missionCfg.EnabledEnvironments['entraAzure']
        if ($entraEnv -and $entraEnv.monitoring -and $entraEnv.monitoring.intervalMinutes) {
            $script:MissionMonitorInterval = $entraEnv.monitoring.intervalMinutes
        }

        # Extract detection filter from mission config
        if ($entraEnv -and $entraEnv.monitoring -and $entraEnv.monitoring.detections) {
            $script:DetectionFilter = $entraEnv.monitoring.detections
        }
    }

    $scanId = [guid]::NewGuid().ToString()
    $scanStart = [datetime]::UtcNow

    # --- 1. Load config ---
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if ($cfgPath -and (Test-Path $cfgPath)) {
        try {
            $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            Write-Warning "Failed to load config from $cfgPath - using defaults."
        }
    }

    # Merge parameters over config over defaults
    $tenantId = if ($TenantId) { $TenantId }
                elseif ($config -and $config.entra.tenantId) { $config.entra.tenantId }
                else { $null }
    $clientId = if ($ClientId) { $ClientId }
                elseif ($config -and $config.entra.clientId) { $config.entra.clientId }
                else { $null }
    $certThumb = if ($CertificateThumbprint) { $CertificateThumbprint }
                 elseif ($config -and $config.entra.certificateThumbprint) { $config.entra.certificateThumbprint }
                 else { $null }
    $days = if ($PSBoundParameters.ContainsKey('DaysBack')) { $DaysBack }
            elseif ($config -and $config.entra.defaultDaysBack) { $config.entra.defaultDaysBack }
            else { 7 }
    $mode = if ($PSBoundParameters.ContainsKey('ScanMode')) { $ScanMode }
            elseif ($config -and $config.entra.defaultScanMode) { $config.entra.defaultScanMode }
            else { 'Fast' }
    $outDir = if ($OutputDirectory) { $OutputDirectory }
              elseif ($config -and $config.output.directory) { $config.output.directory }
              else { Join-Path (Get-GuerrillaDataRoot) 'Reports' }

    # Final fallback: the safehouse vault under the default keys Set-Safehouse stores
    # interactively — so a vault-only setup (no mission-config file) runs without extra
    # parameters, matching Invoke-Infiltration / Invoke-Fortification behaviour.
    if (-not $tenantId) { $tenantId = Get-SafehouseSecret -VaultKey 'GUERRILLA_GRAPH_TENANT'   -VaultName $vaultName }
    if (-not $clientId) { $clientId = Get-SafehouseSecret -VaultKey 'GUERRILLA_GRAPH_CLIENTID' -VaultName $vaultName }
    if (-not $certThumb -and -not $ClientSecret) {
        $secretVal = Get-SafehouseSecret -VaultKey 'GUERRILLA_GRAPH_SECRET' -VaultName $vaultName
        if ($secretVal) { $ClientSecret = $secretVal | ConvertTo-SecureString -AsPlainText -Force }
    }

    # Validate required parameters
    if (-not $tenantId) { throw 'TenantId is required. Provide it as a parameter, store it in the safehouse (Set-Safehouse), or set entra.tenantId in config.' }
    if (-not $clientId) { throw 'ClientId is required. Provide it as a parameter, store it in the safehouse (Set-Safehouse), or set entra.clientId in config.' }

    # --- 2. Operation header ---
    if (-not $Quiet) {
        Write-OperationHeader -Operation 'SURVEILLANCE SWEEP' -Mode $mode -Target $tenantId -DaysBack $days
    }

    # --- 3. Load theater state ---
    $state = Get-TheaterState -Theater 'entra' -ConfigPath $cfgPath
    $startTime = $null

    if ($Force -or -not $state) {
        # First run or forced: look back $days
        $startTime = [datetime]::UtcNow.AddDays(-$days)
        if (-not $state) {
            if (-not $Quiet) { Write-ProgressLine -Phase INFO -Message 'First run' -Detail "scanning $days days of history" }
        } else {
            if (-not $Quiet) { Write-ProgressLine -Phase INFO -Message 'Forced rescan' -Detail "scanning $days days of history" }
        }
    } else {
        # Subsequent run: use watermark
        $startTime = [datetime]::Parse($state.watermark).ToUniversalTime()
        $daysSinceWatermark = [Math]::Round(([datetime]::UtcNow - $startTime).TotalDays, 1)
        if (-not $Quiet) { Write-ProgressLine -Phase INFO -Message 'Incremental scan' -Detail "since watermark ($daysSinceWatermark days)" }
    }

    # --- 4. Authenticate to Microsoft Graph ---
    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Authenticating to Microsoft Graph'
    }

    $authParams = @{
        TenantId = $tenantId
        ClientId = $clientId
    }
    if ($certThumb) { $authParams['CertificateThumbprint'] = $certThumb }
    if ($ClientSecret) { $authParams['ClientSecret'] = $ClientSecret }
    if ($DeviceCode) { $authParams['DeviceCode'] = $true }

    try {
        $graphToken = Get-GraphAccessToken @authParams `
            -Scopes @('https://graph.microsoft.com/.default')
    } catch {
        throw "SURVEILLANCE: Failed to authenticate to Microsoft Graph: $_"
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Authenticated to Microsoft Graph'
    }

    # --- 5. Build detection config ---
    $detectionCfg = @{}
    if ($config -and $config.detection) {
        $det = $config.detection
        if ($det.impossibleTravelSpeedKmh)   { $detectionCfg.impossibleTravelSpeedKmh = $det.impossibleTravelSpeedKmh }
        if ($det.auditLogGapThresholdHours)  { $detectionCfg.auditLogGapThresholdHours = $det.auditLogGapThresholdHours }
        if ($det.entraWeights)               { $detectionCfg.entraWeights = $det.entraWeights }
    }
    if ($config -and $config.entra) {
        $entraCfg = $config.entra
        if ($entraCfg.detectionWeights) { $detectionCfg.entraWeights = $entraCfg.detectionWeights }
    }

    # --- 6. Collect events ---
    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Collecting sign-in events'
    }
    # Each collector is isolated so one forbidden/unavailable Graph endpoint degrades to a
    # skip instead of aborting the whole sweep (mirrors Invoke-Infiltration's resilience).
    $signInEvents = @()
    try {
        $signInEvents = @(Get-EntraSignInEvents -AccessToken $graphToken -StartTime $startTime -Quiet:$Quiet)
    } catch {
        Write-Warning "Sign-in event collection failed: $_"
    }
    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Sign-in events' -Detail "$($signInEvents.Count) found"
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Collecting risk detections'
    }
    # Identity-Protection risk detections require the IdentityRiskEvent.Read.All /
    # IdentityRiskyUser.Read.All application scopes AND an Entra ID P2 license — a missing
    # scope/license degrades to a clear skip rather than killing the sweep.
    $riskDetections = @()
    try {
        $riskDetections = @(Get-EntraRiskDetections -AccessToken $graphToken -StartTime $startTime -Quiet:$Quiet)
    } catch {
        if ($_.Exception.Message -match 'scopes are missing|Forbidden|AadPremiumLicenseRequired|\b403\b') {
            if (-not $Quiet) {
                Write-ProgressLine -Phase INFO -Message 'Risk detections skipped' -Detail 'requires IdentityRiskEvent.Read.All + IdentityRiskyUser.Read.All scopes and an Entra ID P2 license'
            }
        } else {
            Write-Warning "Risk detection collection failed: $_"
        }
    }
    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Risk detections' -Detail "$($riskDetections.Count) found"
    }

    $auditEvents = @()
    if ($mode -eq 'Full') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase SURVEILLANCE -Message 'Collecting directory audit events (full mode)'
        }
        try {
            $auditEvents = @(Get-EntraDirectoryAudits -AccessToken $graphToken -StartTime $startTime -Quiet:$Quiet)
        } catch {
            Write-Warning "Directory audit collection failed: $_"
        }
        if (-not $Quiet) {
            Write-ProgressLine -Phase SURVEILLANCE -Message 'Directory audit events' -Detail "$($auditEvents.Count) found"
        }
    }

    $totalEvents = $signInEvents.Count + $riskDetections.Count + $auditEvents.Count
    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message 'Total events collected' -Detail "$($totalEvents.ToString('N0'))"
    }

    # --- 7. Bucket events by user principal name ---
    $userSignInEvents = @{}
    $userRiskDetections = @{}
    $userAuditEvents = @{}

    foreach ($event in $signInEvents) {
        $upn = $event.UserPrincipalName
        if (-not $upn) { continue }
        if (-not $userSignInEvents.ContainsKey($upn)) {
            $userSignInEvents[$upn] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $userSignInEvents[$upn].Add($event)
    }

    foreach ($event in $riskDetections) {
        $upn = $event.UserPrincipalName
        if (-not $upn) { continue }
        if (-not $userRiskDetections.ContainsKey($upn)) {
            $userRiskDetections[$upn] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $userRiskDetections[$upn].Add($event)
    }

    foreach ($event in $auditEvents) {
        $upn = $event.InitiatedBy
        if (-not $upn) { continue }
        if (-not $userAuditEvents.ContainsKey($upn)) {
            $userAuditEvents[$upn] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $userAuditEvents[$upn].Add($event)
    }

    # --- 8. Build risk profiles for all users ---
    $allUsers = @($userSignInEvents.Keys + $userRiskDetections.Keys + $userAuditEvents.Keys | Sort-Object -Unique)
    if (-not $Quiet) {
        Write-ProgressLine -Phase ANALYZING -Message "$($allUsers.Count) identities to analyze"
    }

    $profiles = @{}
    foreach ($upn in $allUsers) {
        $userSignIns = if ($userSignInEvents.ContainsKey($upn)) { @($userSignInEvents[$upn]) } else { @() }
        $userRisks = if ($userRiskDetections.ContainsKey($upn)) { @($userRiskDetections[$upn]) } else { @() }
        $userAudits = if ($userAuditEvents.ContainsKey($upn)) { @($userAuditEvents[$upn]) } else { @() }

        $riskProfileParams = @{
            UserPrincipalName = $upn
            SignInEvents      = @($userSignIns)
            RiskDetections    = @($userRisks)
            AuditEvents       = @($userAudits)
            DetectionConfig   = $detectionCfg
        }
        if ($script:DetectionFilter) {
            $riskProfileParams['DetectionFilter'] = $script:DetectionFilter
        }

        $profile = New-EntraRiskProfile @riskProfileParams

        $profiles[$upn] = $profile
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase ANALYZING -Message 'Risk profiles built' -Detail "$($profiles.Count) identities scored"
    }

    # --- 9. Sort and categorize ---
    $allProfiles = @($profiles.Values | Sort-Object -Property ThreatScore -Descending)
    $flagged = @($allProfiles | Where-Object { $_.ThreatLevel -ne 'Clean' })
    $cleanCount = $allProfiles.Count - $flagged.Count

    $criticalCount = @($flagged | Where-Object ThreatLevel -eq 'CRITICAL').Count
    $highCount     = @($flagged | Where-Object ThreatLevel -eq 'HIGH').Count
    $mediumCount   = @($flagged | Where-Object ThreatLevel -eq 'MEDIUM').Count
    $lowCount      = @($flagged | Where-Object ThreatLevel -eq 'LOW').Count

    # --- 10. Determine new threats (compare against state) ---
    $alertedUsers = if ($state -and $state.alertedUsers -and -not $Force) { $state.alertedUsers } else { @{} }
    $newThreats = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($profile in $flagged) {
        $isNew = $false
        $upn = $profile.UserPrincipalName

        if (-not $alertedUsers.ContainsKey($upn)) {
            $isNew = $true
        } else {
            $prev = $alertedUsers[$upn]

            # Escalation check
            $levelOrder = @{ 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
            $prevLevel = $levelOrder[$prev.lastThreatLevel]
            $currLevel = $levelOrder[$profile.ThreatLevel]
            if ($currLevel -gt $prevLevel) { $isNew = $true }

            # New indicator check via SHA256 hashing
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

    # --- 11. Console report ---
    if (-not $Quiet) {
        Write-SurveillanceReport `
            -TotalEntities $allProfiles.Count `
            -FlaggedCount $flagged.Count `
            -CleanCount $cleanCount `
            -CriticalCount $criticalCount `
            -HighCount $highCount `
            -MediumCount $mediumCount `
            -LowCount $lowCount `
            -NewThreats $newThreats.Count `
            -TotalEvents $totalEvents `
            -FlaggedUsers @($flagged)

        if ($newThreats.Count -gt 0) {
            $interceptThreats = @($newThreats | ForEach-Object {
                [PSCustomObject]@{
                    Email       = $_.UserPrincipalName
                    ThreatScore = $_.ThreatScore
                    ThreatLevel = $_.ThreatLevel
                    Indicators  = @($_.Indicators)
                }
            })
            Write-InterceptAlert -NewThreats $interceptThreats
        }
    }

    # --- 12. Export reports ---
    $csvPath = $null; $htmlPath = $null; $jsonPath = $null

    if (-not $NoReports) {
        if (-not (Test-Path $outDir)) {
            New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        }
        $timestampStr = $scanStart.ToString('yyyyMMdd-HHmmss')
        $tenantLabel = $tenantId -replace '[^a-zA-Z0-9]', '_'
        $baseName = "surveillance-$tenantLabel-$timestampStr"

        $genCsv  = if ($config -and $null -ne $config.output.generateCsv) { $config.output.generateCsv } else { $true }
        $genHtml = if ($config -and $null -ne $config.output.generateHtml) { $config.output.generateHtml } else { $true }
        $genJson = if ($config -and $null -ne $config.output.generateJson) { $config.output.generateJson } else { $true }

        if (-not $Quiet) {
            Write-ProgressLine -Phase SURVEILLANCE -Message 'Generating reports'
        }

        if ($genCsv -and $flagged.Count -gt 0) {
            try {
                $csvPath = Join-Path $outDir "$baseName.csv"
                Export-SurveillanceReportCsv -Profiles @($flagged) -FilePath $csvPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'CSV report' -Detail $csvPath }
            } catch {
                Write-Warning "CSV report generation failed: $_"
            }
        }

        if ($genHtml) {
            try {
                $htmlPath = Join-Path $outDir "$baseName.html"
                Export-SurveillanceReportHtml `
                    -Profiles @($flagged) `
                    -AllProfilesCount $allProfiles.Count `
                    -CleanCount $cleanCount `
                    -AllEventsCount $totalEvents `
                    -DaysBack $days `
                    -TimestampStr (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `
                    -FilePath $htmlPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'HTML report' -Detail $htmlPath }
            } catch {
                Write-Warning "HTML report generation failed: $_"
            }
        }

        if ($genJson -and $flagged.Count -gt 0) {
            try {
                $jsonPath = Join-Path $outDir "$baseName.json"
                Export-SurveillanceReportJson -Profiles @($flagged) -FilePath $jsonPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'JSON report' -Detail $jsonPath }
            } catch {
                Write-Warning "JSON report generation failed: $_"
            }
        }

        if (-not $Quiet) {
            Write-ProgressLine -Phase SURVEILLANCE -Message "Reports saved to $outDir"
        }
    }

    # --- 13. Update state ---
    $newAlertedUsers = @{}
    if ($alertedUsers) {
        foreach ($key in $alertedUsers.Keys) {
            $newAlertedUsers[$key] = $alertedUsers[$key]
        }
    }

    foreach ($profile in $flagged) {
        $upn = $profile.UserPrincipalName
        $indicatorHashes = @($profile.Indicators | ForEach-Object {
            [System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::HashData(
                    [System.Text.Encoding]::UTF8.GetBytes($_)
                )
            ).Replace('-', '').Substring(0, 16)
        })

        if ($newAlertedUsers.ContainsKey($upn)) {
            $existing = $newAlertedUsers[$upn]
            $existing.lastThreatLevel = $profile.ThreatLevel
            $existing.lastThreatScore = $profile.ThreatScore
            $existing.indicatorHashes = $indicatorHashes
            if ($upn -in $newThreats.UserPrincipalName) {
                $existing.lastAlerted = [datetime]::UtcNow.ToString('o')
                $existing.alertCount = ($existing.alertCount ?? 0) + 1
            }
        } else {
            $newAlertedUsers[$upn] = @{
                firstDetected    = [datetime]::UtcNow.ToString('o')
                lastAlerted      = [datetime]::UtcNow.ToString('o')
                lastThreatLevel  = $profile.ThreatLevel
                lastThreatScore  = $profile.ThreatScore
                alertCount       = 1
                indicatorHashes  = $indicatorHashes
            }
        }
    }

    # MON-4: append via Add-ScanHistoryEntry (List-based) — the old `+=` idiom threw
    # "Item has already been added" on every run after the first.
    $scanHistory = Add-ScanHistoryEntry -ExistingHistory $state.scanHistory -Entry @{
        scanId        = $scanId
        timestamp     = [datetime]::UtcNow.ToString('o')
        daysAnalyzed  = $days
        mode          = $mode
        criticalCount = $criticalCount
        highCount     = $highCount
        mediumCount   = $mediumCount
        lowCount      = $lowCount
        flaggedCount  = $flagged.Count
        totalEntities = $allProfiles.Count
        totalEvents   = $totalEvents
        newThreats    = $newThreats.Count
    }

    $newState = @{
        schemaVersion = 1
        watermark     = [datetime]::UtcNow.ToString('o')
        lastScanId    = $scanId
        alertedUsers  = $newAlertedUsers
        scanHistory   = $scanHistory
    }
    Save-TheaterState -Theater 'entra' -State $newState -ConfigPath $cfgPath

    # --- 14. Complete ---
    $scanEnd = [datetime]::UtcNow
    $scanDuration = $scanEnd - $scanStart

    if (-not $Quiet) {
        Write-ProgressLine -Phase SURVEILLANCE -Message "Surveillance sweep complete in $([Math]::Round($scanDuration.TotalSeconds, 1))s"
    }

    # --- 15. Emit result object ---
    $result = [PSCustomObject]@{
        PSTypeName            = 'Guerrilla.SurveillanceResult'
        ScanId                = $scanId
        Timestamp             = $scanStart
        Theater               = 'EntraID'
        TenantId              = $tenantId
        DaysAnalyzed          = $days
        ScanMode              = $mode
        TotalEntitiesScanned  = $allProfiles.Count
        TotalEventsAnalyzed   = $totalEvents
        CriticalCount         = $criticalCount
        HighCount             = $highCount
        MediumCount           = $mediumCount
        LowCount              = $lowCount
        FlaggedEntities       = @($flagged)
        NewThreats            = @($newThreats)
        AllProfiles           = $profiles
        CsvReportPath         = $csvPath
        HtmlReportPath        = $htmlPath
        JsonReportPath        = $jsonPath
        Duration              = $scanDuration
    }

    return $result
}
