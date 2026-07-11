# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Campaign {
    <#
    .SYNOPSIS
        Runs a unified security audit across Google Workspace, Active Directory, and Microsoft Cloud.

    .DESCRIPTION
        Invoke-Campaign orchestrates a full-spectrum security assessment by calling the existing
        Fortification (Google Workspace), Reconnaissance (Active Directory), and Infiltration
        (Entra ID / Azure / Intune / M365) audits and combining their findings into one unified report.

        Each theater is optional — skip what doesn't apply to your org.

    .PARAMETER Theaters
        Which theaters to audit. Default: auto-detect from provided credentials.
        Valid values: Workspace, AD, Cloud

    .PARAMETER ServiceAccountKeyPath
        Google service account key JSON path (enables Workspace theater).

    .PARAMETER AdminEmail
        Google Workspace admin email (enables Workspace theater).

    .PARAMETER Server
        AD domain controller (enables AD theater). Omit to use current domain.

    .PARAMETER Credential
        AD credentials. Omit to use current user.

    .PARAMETER TenantId
        Entra ID tenant ID (enables Cloud theater).

    .PARAMETER ClientId
        Entra app registration client ID (enables Cloud theater).

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for Entra app-only auth.

    .PARAMETER ClientSecret
        Client secret for Entra app-only auth.

    .PARAMETER DeviceCode
        Use device code flow for Entra interactive auth.

    .PARAMETER OutputDirectory
        Directory for report output. Default: per-user data dir + /Guerrilla/Reports
        (Windows: $env:APPDATA; macOS: ~/Library/Application Support; Linux: $XDG_CONFIG_HOME or ~/.config)

    .PARAMETER NoDelta
        Skip delta comparison with previous scan.

    .PARAMETER Quiet
        Suppress console output.

    .PARAMETER ConfigPath
        Path to Guerrilla configuration file.

    .EXAMPLE
        Invoke-Campaign -Theaters Cloud -TenantId $t -ClientId $c -DeviceCode

    .EXAMPLE
        Invoke-Campaign -Theaters AD, Cloud -TenantId $t -ClientId $c -ClientSecret $s

    .EXAMPLE
        Invoke-Campaign -ServiceAccountKeyPath $key -AdminEmail $admin -TenantId $t -ClientId $c -DeviceCode
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Workspace', 'AD', 'Cloud')]
        [string[]]$Theaters,

        # ── Google Workspace ──
        [string]$ServiceAccountKeyPath,
        [string]$AdminEmail,
        [string]$TargetOU,

        # ── Active Directory ──
        [string]$Server,
        [pscredential]$Credential,

        # ── Microsoft Cloud ──
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [securestring]$ClientSecret,
        [switch]$DeviceCode,

        # ── Shared ──
        [string]$OutputDirectory,
        [switch]$NoDelta,
        [switch]$Quiet,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,
        [Alias('MissionConfig')]
        [string]$ConfigFile,
        [string]$VaultName = 'Guerrilla',

        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$ReportStyle = 'Professional',

        [switch]$TestMode
    )

    $tempSaPath = $null
    $vaultName = $VaultName
    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $vaultName = $missionCfg.VaultName

        # Determine theaters from enabled environments
        if (-not $PSBoundParameters.ContainsKey('Theaters')) {
            $Theaters = @()
            if ($missionCfg.EnabledEnvironments.ContainsKey('googleWorkspace')) { $Theaters += 'Workspace' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('activeDirectory')) { $Theaters += 'AD' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('entraAzure') -or
                $missionCfg.EnabledEnvironments.ContainsKey('m365') -or
                $missionCfg.EnabledEnvironments.ContainsKey('intune')) { $Theaters += 'Cloud' }
        }

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
                    Write-Verbose "GWS service account not in vault — will require explicit parameters."
                }
            }
            if (-not $PSBoundParameters.ContainsKey('AdminEmail')) {
                try {
                    $AdminEmail = Get-GuerrillaCredential -VaultKey "$($gwsRef.vaultKey)_ADMIN_EMAIL" -VaultName $vaultName
                } catch {
                    Write-Verbose "AdminEmail not found in vault."
                }
            }
        }

        # Resolve Microsoft Graph credentials from vault
        $graphRef = $missionCfg.Config.credentials.references.microsoftGraph
        if ($graphRef) {
            if ($graphRef.tenantIdVaultKey -and -not $PSBoundParameters.ContainsKey('TenantId')) {
                try { $TenantId = Get-GuerrillaCredential -VaultKey $graphRef.tenantIdVaultKey -VaultName $vaultName } catch {}
            }
            if ($graphRef.clientIdVaultKey -and -not $PSBoundParameters.ContainsKey('ClientId')) {
                try { $ClientId = Get-GuerrillaCredential -VaultKey $graphRef.clientIdVaultKey -VaultName $vaultName } catch {}
            }
            if ($graphRef.vaultKey -and -not $PSBoundParameters.ContainsKey('CertificateThumbprint') -and -not $PSBoundParameters.ContainsKey('ClientSecret')) {
                try {
                    $secretVal = Get-GuerrillaCredential -VaultKey $graphRef.vaultKey -VaultName $vaultName
                    if ($graphRef.authMethod -eq 'certificate') {
                        $CertificateThumbprint = $secretVal
                    } else {
                        $ClientSecret = $secretVal | ConvertTo-SecureString -AsPlainText -Force
                    }
                } catch {}
            }
        }

        # Resolve AD credentials from vault
        $adRef = $missionCfg.Config.credentials.references.activeDirectory
        if ($adRef -and $adRef.type -eq 'serviceAccount' -and -not $PSBoundParameters.ContainsKey('Credential')) {
            try {
                $Credential = Get-GuerrillaCredential -VaultKey ($adRef.vaultKey ?? 'GUERRILLA_AD_CREDENTIAL') -VaultName $vaultName
            } catch {}
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
        if ($cfgPath -and (Test-Path $cfgPath)) {
            $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
        }

        $outDir = if ($OutputDirectory) { $OutputDirectory }
                  elseif ($config -and $config.output.directory) { $config.output.directory }
                  else { Join-Path (Get-GuerrillaDataRoot) 'Reports' }

        # Final fallback: pull any still-missing credentials from the safehouse vault
        # under the default keys Set-Safehouse stores interactively. This runs before
        # theater auto-detection and the per-theater requirement checks below, so a
        # vault-only setup (no mission-config file) drives a full campaign.
        if (-not $ServiceAccountKeyPath) {
            $saJson = Get-SafehouseSecret -VaultKey 'GUERRILLA_GWS_SA' -VaultName $vaultName
            if ($saJson) {
                $tempSaPath = Join-Path ([System.IO.Path]::GetTempPath()) "guerrilla-sa-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
                $saJson | Set-Content -Path $tempSaPath -Encoding UTF8
                $ServiceAccountKeyPath = $tempSaPath
            }
        }
        if (-not $AdminEmail) {
            $AdminEmail = Get-SafehouseSecret -VaultKey 'GUERRILLA_GWS_SA_ADMIN_EMAIL' -VaultName $vaultName
        }
        if (-not $TenantId) {
            $TenantId = Get-SafehouseSecret -VaultKey 'GUERRILLA_GRAPH_TENANT' -VaultName $vaultName
        }
        if (-not $ClientId) {
            $ClientId = Get-SafehouseSecret -VaultKey 'GUERRILLA_GRAPH_CLIENTID' -VaultName $vaultName
        }
        if (-not $CertificateThumbprint -and -not $ClientSecret) {
            $secretVal = Get-SafehouseSecret -VaultKey 'GUERRILLA_GRAPH_SECRET' -VaultName $vaultName
            if ($secretVal) { $ClientSecret = $secretVal | ConvertTo-SecureString -AsPlainText -Force }
        }

        # --- Auto-detect theaters from provided credentials ---
        if (-not $Theaters) {
            if ($TestMode) {
                # Test mode needs no credentials — simulate the full big report.
                $Theaters = @('Workspace', 'AD', 'Cloud')
            }
            else {
                $Theaters = @()
                if ($ServiceAccountKeyPath -and $AdminEmail) { $Theaters += 'Workspace' }
                if ($Server -or $Credential -or (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
                    $Theaters += 'AD'
                }
                if ($TenantId -and $ClientId) { $Theaters += 'Cloud' }

                if ($Theaters.Count -eq 0) {
                    throw 'No theaters could be determined. Provide -Theaters or supply credentials for at least one theater.'
                }
            }
        }

        # Test mode renders zeroed timestamps for deterministic demo/sample output.
        $script:GuerrillaTestMode = [bool]$TestMode

        # --- Operation header ---
        if (-not $Quiet) {
            $theaterLabel = $Theaters -join ' + '
            Write-OperationHeader -Operation 'CAMPAIGN AUDIT' -Mode $theaterLabel -Target 'Full Spectrum' -DaysBack 0
        }

        # --- Run each theater ---
        $theaterResults = @{}
        $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

        # ── Workspace Theater ──────────────────────────────────────────────
        if ('Workspace' -in $Theaters) {
            if (-not $TestMode -and (-not $ServiceAccountKeyPath -or -not $AdminEmail)) {
                throw 'Workspace theater requires -ServiceAccountKeyPath and -AdminEmail'
            }

            if (-not $Quiet) {
                Write-ProgressLine -Phase CAMPAIGN -Message 'Launching Workspace theater (Fortification)'
            }

            $fortParams = @{
                ServiceAccountKeyPath = $ServiceAccountKeyPath
                AdminEmail            = $AdminEmail
                NoReports             = $true
                NoDelta               = $NoDelta.IsPresent
                Quiet                 = $Quiet.IsPresent
            }
            if ($ConfigPath) { $fortParams['ConfigPath'] = $ConfigPath }
            if ($ConfigFile) { $fortParams['ConfigFile'] = $ConfigFile }
            if ($TargetOU) { $fortParams['TargetOU'] = $TargetOU }
            if ($TestMode) { $fortParams['TestMode'] = $true }

            try {
                $fortResult = Invoke-Fortification @fortParams
                $theaterResults['Google Workspace'] = $fortResult

                foreach ($f in @($fortResult.Findings)) {
                    $f | Add-Member -NotePropertyName 'Theater' -NotePropertyValue 'Google Workspace' -Force
                    $allFindings.Add($f)
                }

                if (-not $Quiet) {
                    Write-ProgressLine -Phase CAMPAIGN -Message "Workspace: $($fortResult.Findings.Count) checks, score $($fortResult.OverallScore)/100"
                }
            } catch {
                Write-Warning "Workspace theater failed: $_"
                $theaterResults['Google Workspace'] = @{ Error = $_.Exception.Message }
            }
        }

        # ── AD Theater ─────────────────────────────────────────────────────
        if ('AD' -in $Theaters) {
            if (-not $Quiet) {
                Write-ProgressLine -Phase CAMPAIGN -Message 'Launching AD theater (Reconnaissance)'
            }

            $reconParams = @{
                NoReports = $true
                NoDelta   = $NoDelta.IsPresent
                Quiet     = $Quiet.IsPresent
            }
            if ($Server) { $reconParams['Server'] = $Server }
            if ($Credential) { $reconParams['Credential'] = $Credential }
            if ($ConfigPath) { $reconParams['ConfigPath'] = $ConfigPath }
            if ($ConfigFile) { $reconParams['ConfigFile'] = $ConfigFile }
            if ($TestMode) { $reconParams['TestMode'] = $true }

            try {
                $reconResult = Invoke-Reconnaissance @reconParams
                $theaterResults['Active Directory'] = $reconResult

                foreach ($f in @($reconResult.Findings)) {
                    $f | Add-Member -NotePropertyName 'Theater' -NotePropertyValue 'Active Directory' -Force
                    $allFindings.Add($f)
                }

                if (-not $Quiet) {
                    $domainLabel = $reconResult.DomainName ?? 'Current Domain'
                    Write-ProgressLine -Phase CAMPAIGN -Message "AD ($domainLabel): $($reconResult.Findings.Count) checks, score $($reconResult.OverallScore)/100"
                }
            } catch {
                Write-Warning "AD theater failed: $_"
                $theaterResults['Active Directory'] = @{ Error = $_.Exception.Message }
            }
        }

        # ── Cloud Theater ──────────────────────────────────────────────────
        if ('Cloud' -in $Theaters) {
            if (-not $TestMode -and (-not $TenantId -or -not $ClientId)) {
                throw 'Cloud theater requires -TenantId and -ClientId'
            }

            if (-not $Quiet) {
                Write-ProgressLine -Phase CAMPAIGN -Message 'Launching Cloud theater (Infiltration)'
            }

            $infilParams = @{
                TenantId  = $TenantId
                ClientId  = $ClientId
                NoReports = $true
                NoDelta   = $NoDelta.IsPresent
                Quiet     = $Quiet.IsPresent
            }
            if ($CertificateThumbprint) { $infilParams['CertificateThumbprint'] = $CertificateThumbprint }
            if ($ClientSecret) { $infilParams['ClientSecret'] = $ClientSecret }
            if ($DeviceCode) { $infilParams['DeviceCode'] = $true }
            if ($ConfigPath) { $infilParams['ConfigPath'] = $ConfigPath }
            if ($ConfigFile) { $infilParams['ConfigFile'] = $ConfigFile }
            if ($TestMode) { $infilParams['TestMode'] = $true }

            try {
                $infilResult = Invoke-Infiltration @infilParams
                $theaterResults['Microsoft Cloud'] = $infilResult

                foreach ($f in @($infilResult.Findings)) {
                    $f | Add-Member -NotePropertyName 'Theater' -NotePropertyValue 'Microsoft Cloud' -Force
                    $allFindings.Add($f)
                }

                if (-not $Quiet) {
                    Write-ProgressLine -Phase CAMPAIGN -Message "Cloud ($TenantId): $($infilResult.Findings.Count) checks, score $($infilResult.Score.OverallScore)/100"
                }
            } catch {
                Write-Warning "Cloud theater failed: $_"
                $theaterResults['Microsoft Cloud'] = @{ Error = $_.Exception.Message }
            }
        }

        # --- Unified scoring ---
        if (-not $Quiet) {
            Write-ProgressLine -Phase CAMPAIGN -Message 'Calculating unified posture score'
        }

        $unifiedScore = Get-AuditPostureScore -Findings @($allFindings)
        $overallScore = $unifiedScore.OverallScore
        $scoreLabel = Get-FortificationScoreLabel -Score $overallScore

        # --- Build per-theater score summary ---
        $theaterScores = @{}
        foreach ($theaterName in $theaterResults.Keys) {
            $theaterFindings = @($allFindings | Where-Object Theater -eq $theaterName)
            if ($theaterFindings.Count -gt 0) {
                $ts = Get-AuditPostureScore -Findings $theaterFindings
                $theaterScores[$theaterName] = @{
                    Score        = $ts.OverallScore
                    ScoreLabel   = Get-FortificationScoreLabel -Score $ts.OverallScore
                    FindingCount = $theaterFindings.Count
                    PassCount    = @($theaterFindings | Where-Object Status -eq 'PASS').Count
                    FailCount    = @($theaterFindings | Where-Object Status -eq 'FAIL').Count
                    WarnCount    = @($theaterFindings | Where-Object Status -eq 'WARN').Count
                    SkipCount    = @($theaterFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count
                    CategoryScores = $ts.CategoryScores
                }
            }
        }

        # --- Console report ---
        if (-not $Quiet) {
            Write-CampaignReport `
                -OverallScore $overallScore `
                -ScoreLabel $scoreLabel `
                -TheaterScores $theaterScores `
                -CategoryScores $unifiedScore.CategoryScores `
                -Findings @($allFindings)
        }

        # --- Generate reports ---
        $scanEnd = [datetime]::UtcNow
        $scanDuration = $scanEnd - $scanStart

        $result = [PSCustomObject]@{
            PSTypeName     = 'Guerrilla.CampaignResult'
            ScanId         = $scanId
            ScanStart      = $scanStart
            ScanEnd        = $scanEnd
            Duration       = $scanDuration
            Theaters       = $Theaters
            OverallScore   = $overallScore
            ScoreLabel     = $scoreLabel
            TheaterScores  = $theaterScores
            CategoryScores = $unifiedScore.CategoryScores
            Findings       = @($allFindings)
            TheaterResults = $theaterResults
        }

        if (-not (Test-Path $outDir)) {
            New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        }

        # Test mode uses a zeroed timestamp so report filenames are deterministic.
        $timestamp = if ($script:GuerrillaTestMode) { '00000000-000000' } else { $scanStart.ToString('yyyyMMdd-HHmmss') }
        $baseName = "campaign-$timestamp"

        if (-not $Quiet) {
            Write-ProgressLine -Phase CAMPAIGN -Message 'Generating unified reports'
        }

        try {
            if (-not $PSBoundParameters.ContainsKey('ReportStyle') -and $config -and $config.output -and ($config.output.reportStyle -in 'Guerrilla', 'Professional', 'Slate')) {
                $ReportStyle = [string]$config.output.reportStyle
            }
            $htmlPath = Join-Path $outDir "$baseName.html"
            Export-CampaignReportHtml -Result $result -OutputPath $htmlPath `
                -Style $ReportStyle -Branding (Get-GuerrillaBranding -Config $config)
            $result | Add-Member -NotePropertyName 'HtmlReportPath' -NotePropertyValue $htmlPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'HTML report' -Detail $htmlPath }
        } catch {
            Write-Warning "HTML report generation failed: $_"
        }

        try {
            $csvPath = Join-Path $outDir "$baseName.csv"
            Export-CampaignReportCsv -Result $result -OutputPath $csvPath
            $result | Add-Member -NotePropertyName 'CsvReportPath' -NotePropertyValue $csvPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'CSV report' -Detail $csvPath }
        } catch {
            Write-Warning "CSV report generation failed: $_"
        }

        try {
            $jsonPath = Join-Path $outDir "$baseName.json"
            Export-CampaignReportJson -Result $result -OutputPath $jsonPath
            $result | Add-Member -NotePropertyName 'JsonReportPath' -NotePropertyValue $jsonPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'JSON report' -Detail $jsonPath }
        } catch {
            Write-Warning "JSON report generation failed: $_"
        }

        if (-not $Quiet) {
            Write-ProgressLine -Phase CAMPAIGN -Message "Campaign complete in $([Math]::Round($scanDuration.TotalSeconds, 1))s — $($allFindings.Count) checks across $($Theaters.Count) theater(s)"
        }

        return $result
    } finally {
        if ($tempSaPath -and (Test-Path $tempSaPath)) {
            Remove-Item -Path $tempSaPath -Force -ErrorAction SilentlyContinue
        }
    }
}
