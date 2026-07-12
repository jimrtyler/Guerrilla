# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Campaign {
    <#
    .SYNOPSIS
        Runs a unified security audit across Google Workspace, Active Directory, and Microsoft Cloud.

    .DESCRIPTION
        Invoke-Campaign orchestrates a full-spectrum security assessment by calling the
        Invoke-GWSAudit (Google Workspace), Invoke-ADAudit (Active Directory), and
        Invoke-EntraAudit (Entra ID / Azure / Intune / M365) audits and combining their
        findings into one unified report.

        Each platform is optional — skip what doesn't apply to your org.

    .PARAMETER Platforms
        Which platforms to audit. Default: auto-detect from provided credentials.
        Valid values: AD, Entra, GWS (legacy values Workspace and Cloud are accepted
        as synonyms for GWS and Entra). -Theaters is accepted as a deprecated alias
        for this parameter.

    .PARAMETER ServiceAccountKeyPath
        Google service account key JSON path (enables Workspace platform).

    .PARAMETER AdminEmail
        Google Workspace admin email (enables Workspace platform).

    .PARAMETER StudentOU
        Organizational unit(s) containing student accounts, routed by shape:
        '/'-prefixed Workspace OU paths (e.g. '/Students') go to the GWS audit,
        'OU=' distinguished names (e.g. 'OU=Students,DC=district,DC=org') go to
        the AD audit. A designation for the OU-scoped K12 checks, not a
        collection filter; when omitted those checks report Not Assessed. Part
        of the run's comparison identity, so a student-scoped campaign is never
        diffed against a whole-tenant campaign.

    .PARAMETER Server
        AD domain controller (enables AD platform). Omit to use current domain.

    .PARAMETER Credential
        AD credentials. Omit to use current user.

    .PARAMETER TenantId
        Entra ID tenant ID (enables Cloud platform).

    .PARAMETER ClientId
        Entra app registration client ID (enables Cloud platform).

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
        Skip the run-over-run comparison and do not record this run in the local run history.

    .PARAMETER Quiet
        Suppress console output.

    .PARAMETER ConfigPath
        Path to Guerrilla configuration file.

    .EXAMPLE
        Invoke-Campaign -Platforms Cloud -TenantId $t -ClientId $c -DeviceCode

    .EXAMPLE
        Invoke-Campaign -Platforms AD, Cloud -TenantId $t -ClientId $c -ClientSecret $s

    .EXAMPLE
        Invoke-Campaign -ServiceAccountKeyPath $key -AdminEmail $admin -TenantId $t -ClientId $c -DeviceCode
    #>
    [CmdletBinding()]
    param(
        [Alias('Theaters')]
        [ValidateSet('AD', 'Entra', 'GWS', 'Workspace', 'Cloud')]
        [string[]]$Platforms,

        # ── Google Workspace ──
        [string]$ServiceAccountKeyPath,
        [string]$AdminEmail,
        [string]$TargetOU,

        # Student-OU designation, routed by shape: '/'-prefixed Workspace OU
        # paths go to the GWS audit, 'OU=' distinguished names go to the AD
        # audit. Part of the run's comparison identity on every platform.
        [AllowEmptyCollection()][string[]]$StudentOU = @(),

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

    # Canonical platform names are AD / Entra / GWS; Workspace and Cloud remain
    # accepted (pre-rename vocabulary) and normalize to the internal values used
    # by the launch blocks below.
    if ($Platforms) {
        $Platforms = @($Platforms | ForEach-Object {
            switch ($_) { 'GWS' { 'Workspace' } 'Entra' { 'Cloud' } default { $_ } }
        } | Select-Object -Unique)
    }

    $tempSaPath = $null
    $vaultName = $VaultName
    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $vaultName = $missionCfg.VaultName

        # Determine platforms from enabled environments
        if (-not $PSBoundParameters.ContainsKey('Platforms')) {
            $Platforms = @()
            if ($missionCfg.EnabledEnvironments.ContainsKey('googleWorkspace')) { $Platforms += 'Workspace' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('activeDirectory')) { $Platforms += 'AD' }
            if ($missionCfg.EnabledEnvironments.ContainsKey('entraAzure') -or
                $missionCfg.EnabledEnvironments.ContainsKey('m365') -or
                $missionCfg.EnabledEnvironments.ContainsKey('intune')) { $Platforms += 'Cloud' }
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
        # platform auto-detection and the per-platform requirement checks below, so a
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

        # --- Auto-detect platforms from provided credentials ---
        if (-not $Platforms) {
            if ($TestMode) {
                # Test mode needs no credentials — simulate the full big report.
                $Platforms = @('Workspace', 'AD', 'Cloud')
            }
            else {
                $Platforms = @()
                if ($ServiceAccountKeyPath -and $AdminEmail) { $Platforms += 'Workspace' }
                if ($Server -or $Credential -or (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
                    $Platforms += 'AD'
                }
                if ($TenantId -and $ClientId) { $Platforms += 'Cloud' }

                if ($Platforms.Count -eq 0) {
                    throw 'No platforms could be determined. Provide -Platforms or supply credentials for at least one platform.'
                }
            }
        }

        # Test mode renders zeroed timestamps for deterministic demo/sample output.
        $script:GuerrillaTestMode = [bool]$TestMode

        # --- Operation header ---
        if (-not $Quiet) {
            $platformLabel = $Platforms -join ' + '
            Write-OperationHeader -Operation 'CAMPAIGN AUDIT' -Mode $platformLabel -Target 'Full Spectrum' -DaysBack 0
        }

        # --- Run each platform ---
        $platformResults = @{}
        $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Route the student-OU designation by shape: Workspace OU paths vs AD DNs.
        # An entry matching neither shape is a mistake worth stopping for, not guessing.
        $gwsStudentOus = @(ConvertTo-GuerrillaStudentOuList -StudentOu @($StudentOU | Where-Object { "$_".Trim().StartsWith('/') }) -EnsureLeadingSlash)
        $adStudentOus = @(ConvertTo-GuerrillaStudentOuList -StudentOu @($StudentOU | Where-Object { "$_".Trim() -match '^(?i)OU=' }))
        $unroutable = @($StudentOU | Where-Object { $s = "$_".Trim(); $s -and -not $s.StartsWith('/') -and $s -notmatch '^(?i)OU=' })
        if ($unroutable.Count) {
            throw ("-StudentOU entries could not be routed to a platform (expected a '/'-prefixed " +
                "Workspace OU path or an 'OU=' distinguished name): $($unroutable -join ', ')")
        }

        # ── Workspace Platform ──────────────────────────────────────────────
        if ('Workspace' -in $Platforms) {
            if (-not $TestMode -and (-not $ServiceAccountKeyPath -or -not $AdminEmail)) {
                throw 'Workspace platform requires -ServiceAccountKeyPath and -AdminEmail'
            }

            if (-not $Quiet) {
                Write-ProgressLine -Phase CAMPAIGN -Message 'Launching Google Workspace audit'
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
            if ($gwsStudentOus.Count) { $fortParams['StudentOU'] = $gwsStudentOus }
            if ($TestMode) { $fortParams['TestMode'] = $true }

            try {
                $fortResult = Invoke-GWSAudit @fortParams
                $platformResults['Google Workspace'] = $fortResult

                foreach ($f in @($fortResult.Findings)) {
                    $f | Add-Member -NotePropertyName 'Platform' -NotePropertyValue 'Google Workspace' -Force
                    $allFindings.Add($f)
                }

                if (-not $Quiet) {
                    Write-ProgressLine -Phase CAMPAIGN -Message "Workspace: $($fortResult.Findings.Count) checks, score $($fortResult.OverallScore)/100"
                }
            } catch {
                Write-Warning "Workspace platform failed: $_"
                $platformResults['Google Workspace'] = @{ Error = $_.Exception.Message }
            }
        }

        # ── AD Platform ─────────────────────────────────────────────────────
        if ('AD' -in $Platforms) {
            if (-not $Quiet) {
                Write-ProgressLine -Phase CAMPAIGN -Message 'Launching Active Directory audit'
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
            if ($adStudentOus.Count) { $reconParams['StudentOU'] = $adStudentOus }
            if ($TestMode) { $reconParams['TestMode'] = $true }

            try {
                $reconResult = Invoke-ADAudit @reconParams
                $platformResults['Active Directory'] = $reconResult

                foreach ($f in @($reconResult.Findings)) {
                    $f | Add-Member -NotePropertyName 'Platform' -NotePropertyValue 'Active Directory' -Force
                    $allFindings.Add($f)
                }

                if (-not $Quiet) {
                    $domainLabel = $reconResult.DomainName ?? 'Current Domain'
                    Write-ProgressLine -Phase CAMPAIGN -Message "AD ($domainLabel): $($reconResult.Findings.Count) checks, score $($reconResult.OverallScore)/100"
                }
            } catch {
                Write-Warning "AD platform failed: $_"
                $platformResults['Active Directory'] = @{ Error = $_.Exception.Message }
            }
        }

        # ── Cloud Platform ──────────────────────────────────────────────────
        if ('Cloud' -in $Platforms) {
            if (-not $TestMode -and (-not $TenantId -or -not $ClientId)) {
                throw 'Cloud platform requires -TenantId and -ClientId'
            }

            if (-not $Quiet) {
                Write-ProgressLine -Phase CAMPAIGN -Message 'Launching Entra ID / M365 audit'
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
                $infilResult = Invoke-EntraAudit @infilParams
                $platformResults['Microsoft Cloud'] = $infilResult

                foreach ($f in @($infilResult.Findings)) {
                    $f | Add-Member -NotePropertyName 'Platform' -NotePropertyValue 'Microsoft Cloud' -Force
                    $allFindings.Add($f)
                }

                if (-not $Quiet) {
                    Write-ProgressLine -Phase CAMPAIGN -Message "Cloud ($TenantId): $($infilResult.Findings.Count) checks, score $($infilResult.Score.OverallScore)/100"
                }
            } catch {
                Write-Warning "Cloud platform failed: $_"
                $platformResults['Microsoft Cloud'] = @{ Error = $_.Exception.Message }
            }
        }

        # --- Unified scoring ---
        if (-not $Quiet) {
            Write-ProgressLine -Phase CAMPAIGN -Message 'Calculating unified posture score'
        }

        $unifiedScore = Get-AuditPostureScore -Findings @($allFindings)
        $overallScore = $unifiedScore.OverallScore
        $scoreLabel = Get-AuditScoreLabel -Score $overallScore

        # --- Build per-platform score summary ---
        $platformScores = @{}
        foreach ($platformName in $platformResults.Keys) {
            $platformFindings = @($allFindings | Where-Object Platform -eq $platformName)
            if ($platformFindings.Count -gt 0) {
                $ts = Get-AuditPostureScore -Findings $platformFindings
                $platformScores[$platformName] = @{
                    Score        = $ts.OverallScore
                    ScoreLabel   = Get-AuditScoreLabel -Score $ts.OverallScore
                    FindingCount = $platformFindings.Count
                    PassCount    = @($platformFindings | Where-Object Status -eq 'PASS').Count
                    FailCount    = @($platformFindings | Where-Object Status -eq 'FAIL').Count
                    WarnCount    = @($platformFindings | Where-Object Status -eq 'WARN').Count
                    SkipCount    = @($platformFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count
                    CategoryScores = $ts.CategoryScores
                }
            }
        }

        # --- Run-over-run comparison against the local run history ---
        # The campaign records its own combined series (platform set = all
        # platforms run) alongside the per-platform series the sub-audits keep.
        $runRecord = $null
        $runDiff = $null
        if (-not $NoDelta -and -not $TestMode) {
            if (-not $Quiet) { Write-ProgressLine -Phase CAMPAIGN -Message 'Comparing against previous run' }
            try {
                # Series identity is keyed on the REQUESTED platform set, never the set
                # that happened to succeed: one transient platform failure must not move
                # the campaign to a different history series (or a false "first run"),
                # and the failed platform's checks must surface as lost visibility in
                # the diff instead of silently vanishing from the record.
                $platformInfo = @{
                    Workspace = @{ ResultKey = 'Google Workspace'; RecordName = 'GWS' }
                    AD        = @{ ResultKey = 'Active Directory'; RecordName = 'AD' }
                    Cloud     = @{ ResultKey = 'Microsoft Cloud'; RecordName = 'Entra' }
                }
                $recordPlatforms = @()
                $targetIds = @()
                $recordFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($f in $allFindings) { $recordFindings.Add($f) }

                foreach ($requested in $Platforms) {
                    $info = $platformInfo[$requested]
                    if (-not $info) { continue }
                    $recordPlatforms += $info.RecordName

                    $sub = $platformResults[$info.ResultKey]
                    $failed = ($null -eq $sub) -or ($sub -is [hashtable] -and $sub.Error)
                    if (-not $failed) {
                        $id = $sub.DomainName ?? $sub.TenantId ?? $sub.TenantDomain
                        if ($id) { $targetIds += "$id" }
                        continue
                    }

                    # Failed platform: best-effort target identity from the requested
                    # inputs, matching what the sub-audit itself would have derived
                    # where that is knowable (TenantId for Cloud, the admin domain for
                    # Workspace, the machine's DNS domain for AD). If none can be
                    # determined the series hash may not match earlier runs — but the
                    # platform is never silently dropped from the series key.
                    $fallbackId = switch ($requested) {
                        'Cloud'     { $TenantId }
                        'Workspace' { if ($AdminEmail) { "$AdminEmail".Split('@')[-1] } }
                        'AD'        { if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } elseif ($Server) { $Server } }
                    }
                    if ($fallbackId) { $targetIds += "$fallbackId" }

                    # Synthesize Not-Assessed (ERROR) findings for every check the
                    # platform would have produced, so they classify as lost
                    # visibility in the diff instead of benign "retired".
                    $reason = if ($sub -is [hashtable] -and $sub.Error) { "$($sub.Error)" } else { 'platform audit did not run' }
                    foreach ($fn in @(Get-GuerrillaPlatformCheckFunction -Platform $info.RecordName)) {
                        foreach ($na in @(Get-GuerrillaFailedCategoryFinding -CategoryFunction $fn `
                                -Reason "$($info.ResultKey) audit failed: $reason")) {
                            $recordFindings.Add($na)
                        }
                    }
                }

                if ($recordPlatforms.Count -gt 0 -and $targetIds.Count -gt 0) {
                    $campaignStudentOus = @($gwsStudentOus) + @($adStudentOus)
                    $runRecord = New-GuerrillaRunRecord -Findings @($recordFindings) -Platforms $recordPlatforms `
                        -TargetId $targetIds -ScanId $scanId -OverallScore $overallScore `
                        -TargetOu ($TargetOU ? $TargetOU : '/') -StudentOu $campaignStudentOus
                    $previousRun = Get-GuerrillaPreviousRun -Platforms $recordPlatforms -TargetHash $runRecord.scope.targetHash `
                        -TargetOu ($TargetOU ? $TargetOU : '/') -StudentOu $campaignStudentOus
                    $runDiff = Compare-GuerrillaRun -Previous $previousRun -Current $runRecord
                }
            } catch {
                Write-Warning "Run comparison unavailable: $_"
            }
        }

        # --- Console report ---
        if (-not $Quiet) {
            Write-CampaignReport `
                -OverallScore $overallScore `
                -ScoreLabel $scoreLabel `
                -PlatformScores $platformScores `
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
            Platforms       = $Platforms
            OverallScore   = $overallScore
            ScoreLabel     = $scoreLabel
            PlatformScores  = $platformScores
            CategoryScores = $unifiedScore.CategoryScores
            Findings       = @($allFindings)
            RunComparison  = $runDiff
            PlatformResults = $platformResults
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

        # --- Record this completed run: it becomes the next run's baseline ---
        if ($runRecord) {
            try {
                $null = Save-GuerrillaRunRecord -Record $runRecord
            } catch {
                Write-Warning "Run history not updated: $_"
            }
        }

        if (-not $Quiet) {
            Write-ProgressLine -Phase CAMPAIGN -Message "Campaign complete in $([Math]::Round($scanDuration.TotalSeconds, 1))s — $($allFindings.Count) checks across $($Platforms.Count) platform(s)"
        }

        return $result
    } finally {
        if ($tempSaPath -and (Test-Path $tempSaPath)) {
            Remove-Item -Path $tempSaPath -Force -ErrorAction SilentlyContinue
        }
    }
}
