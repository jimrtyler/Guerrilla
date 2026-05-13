# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
# =============================================================================
function Invoke-Fortification {
    [CmdletBinding()]
    param(
        [string]$ServiceAccountKeyPath,
        [string]$AdminEmail,

        [ValidateSet('All', 'Authentication', 'EmailSecurity', 'DriveSecurity', 'OAuthSecurity',
                     'AdminManagement', 'Collaboration', 'DeviceManagement', 'LoggingAlerting')]
        [string[]]$Categories = @('All'),

        [switch]$IncludeChildOUs,
        [string]$TargetOU = '/',
        [int]$UserSampleSize = 500,
        [string]$OutputDirectory,
        [switch]$NoReports,
        [switch]$NoDelta,
        [switch]$Quiet,
        [string]$ConfigPath,
        [string]$ConfigFile
    )

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

        # Apply targetOU from mission config
        if (-not $PSBoundParameters.ContainsKey('TargetOU')) {
            $gwsAudit = $missionCfg.EnabledEnvironments['googleWorkspace']
            if ($gwsAudit -and $gwsAudit.audit -and $gwsAudit.audit.targetOU) {
                $TargetOU = $gwsAudit.audit.targetOU
            }
        }

        # Apply categories from mission config
        if (-not $PSBoundParameters.ContainsKey('Categories')) {
            $gwsEnv = $missionCfg.EnabledEnvironments['googleWorkspace']
            if ($gwsEnv -and $gwsEnv.audit -and $gwsEnv.audit.categories) {
                $missionCats = @($gwsEnv.audit.categories.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
                if ($missionCats.Count -gt 0) { $Categories = $missionCats }
            }
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
    $keyPath = if ($ServiceAccountKeyPath) { $ServiceAccountKeyPath }
               elseif ($config) { $config.google.serviceAccountKeyPath }
               else { $null }
    $admin   = if ($AdminEmail) { $AdminEmail }
               elseif ($config) { $config.google.adminEmail }
               else { $null }
    $outDir  = if ($OutputDirectory) { $OutputDirectory }
               elseif ($config -and $config.output.directory) { $config.output.directory }
               else { Join-Path $env:APPDATA 'PSGuerrilla/Reports' }

    # Validate required parameters
    if (-not $keyPath) { throw 'ServiceAccountKeyPath is required. Provide it as a parameter or set it in config.' }
    if (-not $admin)   { throw 'AdminEmail is required. Provide it as a parameter or set it in config.' }

    # --- Operation header ---
    if (-not $Quiet) {
        Write-OperationHeader -Operation 'FORTIFICATION AUDIT' -Mode 'Config' -Target $admin -DaysBack 0
    }

    # --- Determine scopes needed ---
    $scopes = Get-FortificationScopes -Categories $Categories

    # --- Authenticate ---
    if (-not $Quiet) { Write-ProgressLine -Phase AUDITING -Message 'Authenticating to Google Workspace' }
    $accessToken = Get-GoogleAccessToken -ServiceAccountKeyPath $keyPath -AdminEmail $admin -Scopes $scopes

    # --- Collect data ---
    if (-not $Quiet) { Write-ProgressLine -Phase AUDITING -Message 'Beginning data collection' }
    $auditData = Get-FortificationData `
        -AccessToken $accessToken `
        -ServiceAccountKeyPath $keyPath `
        -AdminEmail $admin `
        -Categories $Categories `
        -UserSampleSize $UserSampleSize `
        -TargetOU $TargetOU `
        -Quiet:$Quiet

    # Report collection errors
    if ($auditData.Errors.Count -gt 0 -and -not $Quiet) {
        Write-ProgressLine -Phase INFO -Message "Data collection had $($auditData.Errors.Count) error(s)"
        foreach ($errKey in $auditData.Errors.Keys) {
            Write-ProgressLine -Phase INFO -Message "  $errKey" -Detail $auditData.Errors[$errKey]
        }
    }

    # --- Run checks ---
    if (-not $Quiet) { Write-ProgressLine -Phase FORTIFYING -Message 'Evaluating configuration checks' }
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $categoryMap = @{
        Authentication   = 'Invoke-AuthenticationChecks'
        EmailSecurity    = 'Invoke-EmailSecurityChecks'
        DriveSecurity    = 'Invoke-DriveSecurityChecks'
        OAuthSecurity    = 'Invoke-OAuthSecurityChecks'
        AdminManagement  = 'Invoke-AdminManagementChecks'
        Collaboration    = 'Invoke-CollaborationChecks'
        DeviceManagement = 'Invoke-DeviceManagementChecks'
        LoggingAlerting  = 'Invoke-LoggingAlertingChecks'
    }

    $categoriesToRun = if ($Categories -contains 'All') { $categoryMap.Keys } else { $Categories }

    foreach ($cat in $categoriesToRun) {
        $funcName = $categoryMap[$cat]
        if (-not $funcName) { continue }

        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            if (-not $Quiet) { Write-ProgressLine -Phase FORTIFYING -Message $cat }
            try {
                $catFindings = & $funcName -AuditData $auditData -OrgUnitPath $TargetOU
                foreach ($f in @($catFindings)) {
                    $allFindings.Add($f)
                }
                $passed = @($catFindings | Where-Object Status -eq 'PASS').Count
                $failed = @($catFindings | Where-Object Status -eq 'FAIL').Count
                if (-not $Quiet) {
                    Write-ProgressLine -Phase FORTIFYING -Message $cat -Detail "P:$passed F:$failed / $($catFindings.Count)"
                }
            } catch {
                Write-Warning "Category $cat failed: $_"
            }
        }
    }

    # --- Score ---
    if (-not $Quiet) { Write-ProgressLine -Phase FORTIFYING -Message 'Calculating posture score' }
    $scoreResult = Get-AuditPostureScore -Findings @($allFindings)
    $overallScore = $scoreResult.OverallScore
    $scoreLabel = Get-FortificationScoreLabel -Score $overallScore

    # --- Delta comparison ---
    $delta = $null
    if (-not $NoDelta) {
        $stateDir = Split-Path $cfgPath -Parent
        $statePath = Join-Path $stateDir 'fortification-state.json'
        if (Test-Path $statePath) {
            if (-not $Quiet) { Write-ProgressLine -Phase FORTIFYING -Message 'Comparing against previous scan' }
            try {
                $previousState = Get-Content -Path $statePath -Raw | ConvertFrom-Json -AsHashtable
                $delta = Compare-FortificationState -CurrentFindings @($allFindings) -PreviousState $previousState
            } catch {
                Write-Verbose "Delta comparison failed: $_"
            }
        }
    }

    # --- Severity counts ---
    $failFindings = @($allFindings | Where-Object Status -eq 'FAIL')
    $critCount = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount  = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount  = @($failFindings | Where-Object Severity -eq 'Low').Count
    $passCount = @($allFindings | Where-Object Status -eq 'PASS').Count
    $failCount = $failFindings.Count
    $warnCount = @($allFindings | Where-Object Status -eq 'WARN').Count
    $skipCount = @($allFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    # --- Console report ---
    if (-not $Quiet) {
        Write-FortificationReport `
            -OverallScore $overallScore `
            -ScoreLabel $scoreLabel `
            -CategoryScores $scoreResult.CategoryScores `
            -TotalChecks $allFindings.Count `
            -PassCount $passCount `
            -FailCount $failCount `
            -WarnCount $warnCount `
            -SkipCount $skipCount `
            -CriticalCount $critCount `
            -HighCount $highCount `
            -MediumCount $medCount `
            -LowCount $lowCount `
            -TopFindings @($allFindings)
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

        if ($genCsv) {
            $csvPath = Join-Path $outDir "fortification_report_$timestamp.csv"
            Export-FortificationReportCsv -Findings @($allFindings) -FilePath $csvPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'CSV report' -Detail $csvPath }
        }
        if ($genHtml) {
            $htmlPath = Join-Path $outDir "fortification_report_$timestamp.html"
            Export-FortificationReportHtml `
                -Findings @($allFindings) `
                -OverallScore $overallScore `
                -ScoreLabel $scoreLabel `
                -CategoryScores $scoreResult.CategoryScores `
                -TenantDomain ($auditData.Tenant.Domain ?? $admin.Split('@')[-1]) `
                -Delta $delta `
                -FilePath $htmlPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'HTML report' -Detail $htmlPath }
        }
        if ($genJson) {
            $jsonPath = Join-Path $outDir "fortification_report_$timestamp.json"
            Export-FortificationReportJson `
                -Findings @($allFindings) `
                -OverallScore $overallScore `
                -ScoreLabel $scoreLabel `
                -CategoryScores $scoreResult.CategoryScores `
                -TenantDomain ($auditData.Tenant.Domain ?? $admin.Split('@')[-1]) `
                -ScanId $scanId `
                -Delta $delta `
                -FilePath $jsonPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'JSON report' -Detail $jsonPath }
        }
    }

    # --- Save state for future delta ---
    if (-not $NoDelta) {
        $stateDir = Split-Path $cfgPath -Parent
        if (-not (Test-Path $stateDir)) {
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
        }
        $statePath = Join-Path $stateDir 'fortification-state.json'
        $newState = @{
            schemaVersion     = 1
            lastScanTimestamp = [datetime]::UtcNow.ToString('o')
            lastScanId        = $scanId
            overallScore      = $overallScore
            findings          = @($allFindings | ForEach-Object {
                @{
                    checkId      = $_.CheckId
                    status       = $_.Status
                    currentValue = $_.CurrentValue
                    orgUnitPath  = $_.OrgUnitPath
                    severity     = $_.Severity
                    category     = $_.Category
                }
            })
            categoryScores    = $scoreResult.CategoryScores
        }
        $newState | ConvertTo-Json -Depth 5 | Set-Content -Path $statePath -Encoding UTF8
    }

    # --- Emit result object ---
    $result = [PSCustomObject]@{
        PSTypeName     = 'PSGuerrilla.AuditResult'
        ScanId         = $scanId
        Timestamp      = $scanStart
        TenantDomain   = $auditData.Tenant.Domain ?? $admin.Split('@')[-1]
        OverallScore   = $overallScore
        ScoreLabel     = $scoreLabel
        CategoryScores = $scoreResult.CategoryScores
        TotalChecks    = $allFindings.Count
        PassCount      = $passCount
        FailCount      = $failCount
        WarnCount      = $warnCount
        SkipCount      = $skipCount
        CriticalCount  = $critCount
        HighCount      = $highCount
        MediumCount    = $medCount
        LowCount       = $lowCount
        Findings       = @($allFindings)
        Delta          = $delta
        HtmlReportPath = $htmlPath
        CsvReportPath  = $csvPath
        JsonReportPath = $jsonPath
    }

    return $result
}

function Get-FortificationScopes {
    [CmdletBinding()]
    param(
        [string[]]$Categories = @('All')
    )

    $scopeMap = @{
        Authentication   = @(
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
            'https://www.googleapis.com/auth/admin.directory.orgunit.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
        )
        EmailSecurity    = @(
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
            'https://www.googleapis.com/auth/admin.directory.domain.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
            'https://www.googleapis.com/auth/gmail.settings.basic'
        )
        DriveSecurity    = @(
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
            'https://www.googleapis.com/auth/admin.directory.orgunit.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
        )
        OAuthSecurity    = @(
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
            'https://www.googleapis.com/auth/admin.reports.audit.readonly'
            'https://www.googleapis.com/auth/admin.directory.domain.readonly'
        )
        AdminManagement  = @(
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
            'https://www.googleapis.com/auth/admin.directory.group.readonly'
            'https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly'
            'https://www.googleapis.com/auth/admin.directory.orgunit.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
        )
        Collaboration    = @(
            'https://www.googleapis.com/auth/admin.directory.orgunit.readonly'
            'https://www.googleapis.com/auth/admin.directory.group.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
        )
        DeviceManagement = @(
            'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly'
            'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly'
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
            'https://www.googleapis.com/auth/chrome.management.policy.readonly'
        )
        LoggingAlerting  = @(
            'https://www.googleapis.com/auth/admin.directory.customer.readonly'
            'https://www.googleapis.com/auth/apps.alerts'
        )
    }

    $allScopes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $categoriesToInclude = if ($Categories -contains 'All') { $scopeMap.Keys } else { $Categories }

    foreach ($cat in $categoriesToInclude) {
        if ($scopeMap.ContainsKey($cat)) {
            foreach ($scope in $scopeMap[$cat]) {
                [void]$allScopes.Add($scope)
            }
        }
    }

    return @($allScopes)
}
