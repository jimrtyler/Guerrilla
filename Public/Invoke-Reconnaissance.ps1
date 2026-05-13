# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Reconnaissance {
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'DomainForest', 'Trusts', 'PrivilegedAccounts', 'PasswordPolicy',
                     'Kerberos', 'ACLDelegation', 'GroupPolicy', 'LogonScripts',
                     'CertificateServices', 'StaleObjects', 'Network')]
        [string[]]$Categories = @('All'),

        [string]$Server,
        [pscredential]$Credential,

        [string]$OutputDirectory,
        [switch]$NoReports,
        [switch]$NoDelta,
        [switch]$Quiet,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,
        [Alias('MissionConfig')]
        [string]$ConfigFile,

        [string]$NtdsPath,
        [string]$WeakPasswordList,

        [int]$InactiveDays = 90,
        [int]$PasswordAgeDays = 365
    )

    # --- Resolve mission config (guerrilla-config.json) ---
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $vaultName = $missionCfg.VaultName

        # Resolve AD credentials from vault
        $adRef = $missionCfg.Config.credentials.references.activeDirectory
        if ($adRef -and $adRef.type -eq 'serviceAccount' -and -not $PSBoundParameters.ContainsKey('Credential')) {
            try {
                $Credential = Get-GuerrillaCredential -VaultKey ($adRef.vaultKey ?? 'GUERRILLA_AD_CREDENTIAL') -VaultName $vaultName
            } catch {
                Write-Verbose "AD credential not found in vault — will use current user context."
            }
        }

        # Apply categories from mission config
        if (-not $PSBoundParameters.ContainsKey('Categories')) {
            $adEnv = $missionCfg.EnabledEnvironments['activeDirectory']
            if ($adEnv -and $adEnv.audit -and $adEnv.audit.categories) {
                $missionCats = @($adEnv.audit.categories.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
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

    $outDir = if ($OutputDirectory) { $OutputDirectory }
              elseif ($config -and $config.output.directory) { $config.output.directory }
              else { Join-Path (Get-PSGuerrillaDataRoot) 'Reports' }

    # --- Operation header ---
    if (-not $Quiet) {
        $targetLabel = if ($Server) { $Server } else { 'Current Domain' }
        Write-OperationHeader -Operation 'RECONNAISSANCE AUDIT' -Mode 'AD Security' -Target $targetLabel -DaysBack 0
    }

    # --- Connect to AD ---
    if (-not $Quiet) { Write-ProgressLine -Phase RECON -Message 'Connecting to Active Directory' }
    try {
        $connParams = @{}
        if ($Server) { $connParams['Server'] = $Server }
        if ($Credential) { $connParams['Credential'] = $Credential }
        $connection = New-LdapConnection @connParams
    } catch {
        throw "Failed to connect to Active Directory: $_"
    }

    $domainName = $connection.DomainDN -replace 'DC=', '' -replace ',', '.'
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message "Connected to $domainName"
    }

    # --- Collect data ---
    if (-not $Quiet) { Write-ProgressLine -Phase RECON -Message 'Beginning data collection' }
    $auditData = Get-ReconnaissanceData `
        -Connection $connection `
        -Categories $Categories `
        -InactiveDays $InactiveDays `
        -PasswordAgeDays $PasswordAgeDays `
        -NtdsPath $NtdsPath `
        -WeakPasswordList $WeakPasswordList `
        -Quiet:$Quiet

    # Report collection errors
    if ($auditData.Errors.Count -gt 0 -and -not $Quiet) {
        Write-ProgressLine -Phase INFO -Message "Data collection had $($auditData.Errors.Count) error(s)"
        foreach ($errKey in $auditData.Errors.Keys) {
            Write-ProgressLine -Phase INFO -Message "  $errKey" -Detail $auditData.Errors[$errKey]
        }
    }

    # --- Run checks ---
    if (-not $Quiet) { Write-ProgressLine -Phase RECON -Message 'Evaluating security checks' }
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $categoryMap = @{
        DomainForest       = 'Invoke-ADDomainForestChecks'
        Trusts             = 'Invoke-ADTrustChecks'
        PrivilegedAccounts = 'Invoke-ADPrivilegedAccountChecks'
        PasswordPolicy     = 'Invoke-ADPasswordPolicyChecks'
        Kerberos           = 'Invoke-ADKerberosChecks'
        ACLDelegation      = 'Invoke-ADAclDelegationChecks'
        GroupPolicy        = 'Invoke-ADGroupPolicyChecks'
        LogonScripts       = 'Invoke-ADLogonScriptChecks'
        CertificateServices = 'Invoke-ADCertificateServicesChecks'
        StaleObjects       = 'Invoke-ADStaleObjectChecks'
        Network            = 'Invoke-ADNetworkChecks'
    }

    $categoriesToRun = if ($Categories -contains 'All') { $categoryMap.Keys } else { $Categories }

    foreach ($cat in $categoriesToRun) {
        $funcName = $categoryMap[$cat]
        if (-not $funcName) { continue }

        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            if (-not $Quiet) { Write-ProgressLine -Phase RECON -Message $cat }
            try {
                $catFindings = & $funcName -AuditData $auditData
                foreach ($f in @($catFindings)) {
                    $allFindings.Add($f)
                }
                $passed = @($catFindings | Where-Object Status -eq 'PASS').Count
                $failed = @($catFindings | Where-Object Status -eq 'FAIL').Count
                if (-not $Quiet) {
                    Write-ProgressLine -Phase RECON -Message $cat -Detail "P:$passed F:$failed / $($catFindings.Count)"
                }
            } catch {
                Write-Warning "Category $cat failed: $_"
            }
        }
    }

    # --- Score ---
    if (-not $Quiet) { Write-ProgressLine -Phase RECON -Message 'Calculating posture score' }
    $scoreResult = Get-AuditPostureScore -Findings @($allFindings)
    $overallScore = $scoreResult.OverallScore
    $scoreLabel = Get-FortificationScoreLabel -Score $overallScore

    # --- Delta comparison ---
    $delta = $null
    if (-not $NoDelta) {
        $stateDir = Split-Path $cfgPath -Parent
        $statePath = Join-Path $stateDir 'reconnaissance-state.json'
        if (Test-Path $statePath) {
            if (-not $Quiet) { Write-ProgressLine -Phase RECON -Message 'Comparing against previous scan' }
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
        Write-ReconnaissanceReport `
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
            -TopFindings @($allFindings) `
            -DomainName $domainName
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
            $csvPath = Join-Path $outDir "reconnaissance_report_$timestamp.csv"
            Export-ReconnaissanceReportCsv -Findings @($allFindings) -FilePath $csvPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'CSV report' -Detail $csvPath }
        }
        if ($genHtml) {
            $htmlPath = Join-Path $outDir "reconnaissance_report_$timestamp.html"
            Export-ReconnaissanceReportHtml `
                -Findings @($allFindings) `
                -OverallScore $overallScore `
                -ScoreLabel $scoreLabel `
                -CategoryScores $scoreResult.CategoryScores `
                -DomainName $domainName `
                -Delta $delta `
                -FilePath $htmlPath
            if (-not $Quiet) { Write-ProgressLine -Phase REPORTING -Message 'HTML report' -Detail $htmlPath }
        }
        if ($genJson) {
            $jsonPath = Join-Path $outDir "reconnaissance_report_$timestamp.json"
            Export-ReconnaissanceReportJson `
                -Findings @($allFindings) `
                -OverallScore $overallScore `
                -ScoreLabel $scoreLabel `
                -CategoryScores $scoreResult.CategoryScores `
                -DomainName $domainName `
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
        $statePath = Join-Path $stateDir 'reconnaissance-state.json'
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
        PSTypeName     = 'PSGuerrilla.ReconResult'
        ScanId         = $scanId
        Timestamp      = $scanStart
        DomainName     = $domainName
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
