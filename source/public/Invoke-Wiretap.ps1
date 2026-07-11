# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Wiretap {
    <#
    .SYNOPSIS
        Performs continuous M365 security monitoring across Exchange, SharePoint, Teams, Defender, and Power Platform.

    .DESCRIPTION
        Invoke-Wiretap executes a comprehensive audit of Microsoft 365 activity logs to detect
        security-relevant changes and threats. It monitors transport rule modifications, mailbox
        forwarding rules, eDiscovery searches, DLP policy changes, external sharing modifications,
        Teams external access changes, bulk file exfiltration, Power Automate flow creation,
        Defender alert policy changes, and audit log disablements.

        Provides agentless M365 audit-log threat hunting and mailbox-compromise investigation over the
        unified audit log — surfacing the indicators a SOC would hunt for after a suspected compromise.

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
        Fast: Exchange transport/forwarding rules + audit log status only.
        Full: All M365 service categories. Default: Fast.

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
        Invoke-Wiretap -TenantId 'contoso.onmicrosoft.com' -ClientId $appId -ClientSecret $secret

    .EXAMPLE
        Invoke-Wiretap -TenantId $tenantId -ClientId $appId -DeviceCode -ScanMode Full -DaysBack 30

    .EXAMPLE
        Invoke-Wiretap -TenantId $tenantId -ClientId $appId -CertificateThumbprint $thumb -Force
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
        $m365Env = $missionCfg.EnabledEnvironments['m365']
        if ($m365Env -and $m365Env.monitoring -and $m365Env.monitoring.intervalMinutes) {
            $script:MissionMonitorInterval = $m365Env.monitoring.intervalMinutes
        }

        # Extract detection filter from mission config
        if ($m365Env -and $m365Env.monitoring -and $m365Env.monitoring.detections) {
            $script:DetectionFilter = $m365Env.monitoring.detections
        }
    }

    $scanId = [guid]::NewGuid().ToString()
    $scanStart = [datetime]::UtcNow

    # --- Load config ---
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if ($cfgPath -and (Test-Path $cfgPath)) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
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
            elseif ($config -and $config.m365.defaultDaysBack) { $config.m365.defaultDaysBack }
            else { 7 }
    $mode = if ($PSBoundParameters.ContainsKey('ScanMode')) { $ScanMode }
            elseif ($config -and $config.m365.defaultScanMode) { $config.m365.defaultScanMode }
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

    # --- Operation header ---
    if (-not $Quiet) {
        Write-OperationHeader -Operation 'WIRETAP SWEEP' -Mode $mode -Target $tenantId -DaysBack $days
    }

    # --- Load theater state ---
    $state = Get-TheaterState -Theater 'm365' -ConfigPath $cfgPath
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

    # --- Authenticate to Microsoft Graph ---
    if (-not $Quiet) {
        Write-ProgressLine -Phase WIRETAP -Message 'Authenticating to Microsoft Graph'
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
        throw "Failed to authenticate to Microsoft Graph: $_"
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase WIRETAP -Message 'Authenticated to Microsoft Graph'
    }

    # --- Build detection config ---
    $detectionCfg = @{}
    if ($config -and $config.m365) {
        $m365Cfg = $config.m365
        if ($m365Cfg.bulkExfiltrationThreshold) { $detectionCfg.bulkExfiltrationThreshold = $m365Cfg.bulkExfiltrationThreshold }
        if ($m365Cfg.bulkExfiltrationWindowMinutes) { $detectionCfg.bulkExfiltrationWindowMinutes = $m365Cfg.bulkExfiltrationWindowMinutes }
        if ($m365Cfg.externalConnectorPatterns) { $detectionCfg.externalConnectorPatterns = $m365Cfg.externalConnectorPatterns }
    }

    # --- Collect events ---
    if (-not $Quiet) {
        Write-ProgressLine -Phase WIRETAP -Message 'Collecting M365 audit events'
    }

    $categorizedEvents = Get-M365AuditEvents `
        -AccessToken $graphToken `
        -StartTime $startTime `
        -ScanMode $mode `
        -Quiet:$Quiet

    $totalEvents = 0
    foreach ($catKey in $categorizedEvents.Keys) {
        if ($catKey -ne 'Errors') {
            $totalEvents += $categorizedEvents[$catKey].Count
        }
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase WIRETAP -Message 'Total events collected' -Detail "$($totalEvents.ToString('N0'))"
    }

    # Report collection errors
    if ($categorizedEvents.Errors -and $categorizedEvents.Errors.Count -gt 0 -and -not $Quiet) {
        Write-ProgressLine -Phase INFO -Message "Data collection had $($categorizedEvents.Errors.Count) error(s)"
        foreach ($errKey in $categorizedEvents.Errors.Keys) {
            Write-ProgressLine -Phase INFO -Message "  $errKey" -Detail $categorizedEvents.Errors[$errKey]
        }
    }

    # --- Build change profiles ---
    if (-not $Quiet) {
        Write-ProgressLine -Phase ANALYZING -Message 'Building M365 change profiles'
    }

    $m365ProfileParams = @{
        CategorizedEvents = $categorizedEvents
        DetectionConfig   = $detectionCfg
    }
    if ($script:DetectionFilter) {
        $m365ProfileParams['DetectionFilter'] = $script:DetectionFilter
    }
    $changeProfile = New-M365ChangeProfile @m365ProfileParams

    # --- Score the profile ---
    if (-not $Quiet) {
        Write-ProgressLine -Phase ANALYZING -Message 'Scoring threat indicators'
    }

    # Load scoring weights from config if available
    $weights = $null
    if ($config -and $config.m365.weights) {
        $weights = $config.m365.weights
    }

    $changeProfile = Get-M365MonitorThreatScore -Profile $changeProfile -Weights $weights

    # --- Collect all flagged changes ---
    $flaggedChanges = [System.Collections.Generic.List[PSCustomObject]]::new()

    $detectionProperties = @(
        'TransportRuleChanges', 'ForwardingRules', 'EDiscoverySearches',
        'DLPPolicyChanges', 'ExternalSharingChanges', 'TeamsExternalAccessChanges',
        'BulkFileExfiltrations', 'PowerAutomateFlows', 'DefenderAlertChanges',
        'AuditLogDisablements'
    )

    foreach ($prop in $detectionProperties) {
        if ($changeProfile.PSObject.Properties[$prop] -and $changeProfile.$prop.Count -gt 0) {
            foreach ($item in $changeProfile.$prop) {
                $flaggedChanges.Add($item)
            }
        }
    }

    # --- Determine new threats (compare against state) ---
    $alertedEvents = if ($state -and $state.alertedEvents -and -not $Force) { $state.alertedEvents } else { @{} }
    $newThreats = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($change in $flaggedChanges) {
        $eventKey = "$($change.DetectionType)|$($change.Timestamp)|$($change.Actor)"
        $changeHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA256]::HashData(
                [System.Text.Encoding]::UTF8.GetBytes($eventKey)
            )
        ).Replace('-', '').Substring(0, 16)

        if (-not $alertedEvents.ContainsKey($changeHash)) {
            $newThreats.Add($change)
        }
    }

    # --- Count by severity using detection type mapping ---
    $m365SeverityMap = @{
        'TransportRuleChange'   = 'HIGH'
        'ForwardingRule'        = 'HIGH'
        'EDiscoverySearch'      = 'MEDIUM'
        'DLPPolicyChange'       = 'MEDIUM'
        'ExternalSharingChange' = 'LOW'
        'TeamsExternalAccess'   = 'LOW'
        'BulkFileExfiltration'  = 'CRITICAL'
        'PowerAutomateFlow'     = 'MEDIUM'
        'DefenderAlertChange'   = 'HIGH'
        'AuditLogDisablement'   = 'CRITICAL'
    }
    $critCount = @($flaggedChanges | Where-Object { $m365SeverityMap[$_.DetectionType] -eq 'CRITICAL' }).Count
    $highCount = @($flaggedChanges | Where-Object { $m365SeverityMap[$_.DetectionType] -eq 'HIGH' }).Count
    $medCount  = @($flaggedChanges | Where-Object { $m365SeverityMap[$_.DetectionType] -eq 'MEDIUM' }).Count
    $lowCount  = @($flaggedChanges | Where-Object { $m365SeverityMap[$_.DetectionType] -eq 'LOW' }).Count

    # Ensure at least 1 critical if the overall threat level is CRITICAL
    $critCount = if ($changeProfile.ThreatLevel -eq 'CRITICAL') { [Math]::Max(1, $critCount) } else { $critCount }

    # --- Console report ---
    if (-not $Quiet) {
        Write-WiretapReport `
            -TenantId $tenantId `
            -TotalEvents $totalEvents `
            -ThreatLevel $changeProfile.ThreatLevel `
            -ThreatScore $changeProfile.ThreatScore `
            -Indicators @($changeProfile.Indicators) `
            -FlaggedChanges @($flaggedChanges) `
            -NewThreats @($newThreats) `
            -CriticalCount $critCount `
            -HighCount $highCount `
            -MediumCount $medCount `
            -LowCount $lowCount

        if ($newThreats.Count -gt 0) {
            # Wrap as objects with standard fields for Write-InterceptAlert compatibility
            $alertObjects = @($newThreats | ForEach-Object {
                [PSCustomObject]@{
                    Email       = $_.Actor
                    ThreatLevel = $changeProfile.ThreatLevel
                    ThreatScore = $changeProfile.ThreatScore
                    Indicators  = @("$($_.DetectionType): $($_.Description)")
                }
            })
            Write-InterceptAlert -NewThreats $alertObjects
        }
    }

    # --- Generate reports ---
    $csvPath = $null; $htmlPath = $null; $jsonPath = $null
    if (-not $NoReports) {
        if (-not (Test-Path $outDir)) {
            New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        }
        $timestamp = $scanStart.ToString('yyyyMMdd-HHmmss')
        $tenantLabel = $tenantId -replace '[^a-zA-Z0-9]', '_'
        $baseName = "wiretap-$tenantLabel-$timestamp"

        $genCsv  = if ($config -and $null -ne $config.output.generateCsv) { $config.output.generateCsv } else { $true }
        $genHtml = if ($config -and $null -ne $config.output.generateHtml) { $config.output.generateHtml } else { $true }
        $genJson = if ($config -and $null -ne $config.output.generateJson) { $config.output.generateJson } else { $true }

        if (-not $Quiet) {
            Write-ProgressLine -Phase WIRETAP -Message 'Generating reports'
        }

        if ($genHtml) {
            try {
                $htmlPath = Join-Path $outDir "$baseName.html"
                Export-WiretapReportHtml -Result $changeProfile -TenantId $tenantId `
                    -TotalEvents $totalEvents -DaysBack $days `
                    -FlaggedChanges @($flaggedChanges) -NewThreats @($newThreats) `
                    -OutputPath $htmlPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'HTML report' -Detail $htmlPath }
            } catch {
                Write-Warning "HTML report generation failed: $_"
            }
        }

        if ($genCsv -and $flaggedChanges.Count -gt 0) {
            try {
                $csvPath = Join-Path $outDir "$baseName.csv"
                Export-WiretapReportCsv -FlaggedChanges @($flaggedChanges) -OutputPath $csvPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'CSV report' -Detail $csvPath }
            } catch {
                Write-Warning "CSV report generation failed: $_"
            }
        }

        if ($genJson) {
            try {
                $jsonPath = Join-Path $outDir "$baseName.json"
                Export-WiretapReportJson -Result $changeProfile -TenantId $tenantId `
                    -ScanId $scanId -TotalEvents $totalEvents -DaysBack $days `
                    -FlaggedChanges @($flaggedChanges) -NewThreats @($newThreats) `
                    -OutputPath $jsonPath
                if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'JSON report' -Detail $jsonPath }
            } catch {
                Write-Warning "JSON report generation failed: $_"
            }
        }

        if (-not $Quiet) {
            Write-ProgressLine -Phase WIRETAP -Message "Reports saved to $outDir"
        }
    }

    # --- Update state ---
    $newAlertedEvents = @{}
    if ($alertedEvents) {
        foreach ($key in $alertedEvents.Keys) {
            $newAlertedEvents[$key] = $alertedEvents[$key]
        }
    }

    foreach ($change in $flaggedChanges) {
        $eventKey = "$($change.DetectionType)|$($change.Timestamp)|$($change.Actor)"
        $changeHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA256]::HashData(
                [System.Text.Encoding]::UTF8.GetBytes($eventKey)
            )
        ).Replace('-', '').Substring(0, 16)

        $newAlertedEvents[$changeHash] = @{
            detectionType = $change.DetectionType
            actor         = $change.Actor
            timestamp     = $change.Timestamp
            firstDetected = [datetime]::UtcNow.ToString('o')
        }
    }

    # MON-4: append via Add-ScanHistoryEntry (List-based) — the old `+=` idiom threw
    # "Item has already been added" on every run after the first.
    $scanHistory = Add-ScanHistoryEntry -ExistingHistory $state.scanHistory -Entry @{
        scanId        = $scanId
        timestamp     = [datetime]::UtcNow.ToString('o')
        daysAnalyzed  = $days
        mode          = $mode
        threatLevel   = $changeProfile.ThreatLevel
        threatScore   = $changeProfile.ThreatScore
        flaggedCount  = $flaggedChanges.Count
        newThreats    = $newThreats.Count
        totalEvents   = $totalEvents
    }

    $newState = @{
        schemaVersion  = 1
        watermark      = [datetime]::UtcNow.ToString('o')
        lastScanId     = $scanId
        alertedEvents  = $newAlertedEvents
        scanHistory    = $scanHistory
    }
    Save-TheaterState -Theater 'm365' -State $newState -ConfigPath $cfgPath

    # --- Complete ---
    $scanEnd = [datetime]::UtcNow
    $scanDuration = $scanEnd - $scanStart

    if (-not $Quiet) {
        Write-ProgressLine -Phase WIRETAP -Message "Wiretap sweep complete in $([Math]::Round($scanDuration.TotalSeconds, 1))s"
    }

    # --- Emit result object ---
    $result = [PSCustomObject]@{
        PSTypeName          = 'Guerrilla.WiretapResult'
        ScanId              = $scanId
        Timestamp           = $scanStart
        Theater             = 'M365'
        TenantId            = $tenantId
        DaysAnalyzed        = $days
        ScanMode            = $mode
        TotalEventsAnalyzed = $totalEvents
        ThreatLevel         = $changeProfile.ThreatLevel
        ThreatScore         = $changeProfile.ThreatScore
        CriticalCount       = $critCount
        HighCount           = $highCount
        MediumCount         = $medCount
        LowCount            = $lowCount
        FlaggedChanges      = @($flaggedChanges)
        NewThreats          = @($newThreats)
        Indicators          = @($changeProfile.Indicators)
        ChangeProfile       = $changeProfile
        CsvReportPath       = $csvPath
        HtmlReportPath      = $htmlPath
        JsonReportPath      = $jsonPath
        Duration            = $scanDuration
    }

    return $result
}
