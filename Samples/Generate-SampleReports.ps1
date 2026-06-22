# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
<#
.SYNOPSIS
    Generates sample HTML reports for PSGuerrilla with every check flagged as FAIL.
.DESCRIPTION
    Loads all audit check definitions and creates mock AuditFinding objects with
    Status = FAIL for every check. Calls the module's actual HTML export functions
    to produce reports identical to real scan output.
.EXAMPLE
    .\Samples\Generate-SampleReports.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Guerrilla', 'Professional', 'Slate')]
    [string]$Style = 'Guerrilla'
)

$ErrorActionPreference = 'Stop'

# Import module (quiet to suppress banner)
$env:PSGUERRILLA_QUIET = '1'
Import-Module (Join-Path $PSScriptRoot '../PSGuerrilla.psd1') -Force
$env:PSGUERRILLA_QUIET = $null

$samplesDir = $PSScriptRoot

# Non-default themes are written to suffixed showcase files (e.g.
# Fortification-AllFail-Professional.html) and carry demo white-label branding so
# the professional look and the firm header are both visible. The default
# 'Guerrilla' run keeps the canonical committed filenames and no branding.
$styleSuffix = if ($Style -eq 'Guerrilla') { '' } else { "-$Style" }
$demoBranding = if ($Style -eq 'Guerrilla') { $null } else {
    @{
        FirmName        = 'Northwind Security'
        ConsultantName  = 'A. Analyst'
        ConsultantEmail = 'analyst@northwind.example'
        ClientName      = 'Globex Corporation'
        Confidentiality = 'CONFIDENTIAL'
    }
}
$dataDir = Join-Path $PSScriptRoot '../Data/AuditChecks'

# --- Helper: generate a realistic "bad" CurrentValue based on check context ---
function Get-BadCurrentValue {
    param([hashtable]$Check)

    $name = $Check.name.ToLower()

    if ($name -match 'enabl|audit|log')       { return 'Disabled' }
    if ($name -match 'mfa|multi.factor')       { return 'Not enforced' }
    if ($name -match 'encrypt')                { return 'Disabled' }
    if ($name -match 'password.*length')       { return '4 characters' }
    if ($name -match 'password.*age')          { return 'Never expires' }
    if ($name -match 'password.*complex')      { return 'Not required' }
    if ($name -match 'password.*history')      { return '0 passwords remembered' }
    if ($name -match 'lockout')                { return 'No lockout configured' }
    if ($name -match 'expir')                  { return 'Never' }
    if ($name -match 'shar|external')          { return 'Anyone (no restrictions)' }
    if ($name -match 'forward')               { return 'Allowed to external' }
    if ($name -match 'guest|anonymous')        { return 'Unrestricted' }
    if ($name -match 'admin|privilege')        { return 'Excessive permissions found' }
    if ($name -match 'stale|inactive|orphan')  { return 'Multiple found' }
    if ($name -match 'sign|smb|ldap|ntlm')    { return 'Not required' }
    if ($name -match 'delegation')             { return 'Unconstrained' }
    if ($name -match 'kerberos|spn')           { return 'Weak encryption (RC4)' }
    if ($name -match 'cert|ca |adcs|esc\d')    { return 'Vulnerable configuration' }
    if ($name -match 'gpo|group policy')       { return 'Misconfigured' }
    if ($name -match 'trust')                  { return 'SID filtering disabled' }
    if ($name -match 'compliance|policy')      { return 'Non-compliant' }
    if ($name -match 'conditional access')     { return 'Not configured' }
    if ($name -match 'pim|role')               { return 'Permanent assignments found' }
    if ($name -match 'app|oauth|consent')      { return 'Unreviewed permissions' }
    if ($name -match 'federation')             { return 'Insecure configuration' }
    if ($name -match 'intune|endpoint|device') { return 'Not enrolled' }
    if ($name -match 'defender|threat')        { return 'Disabled' }
    if ($name -match 'retention')              { return '0 days' }
    if ($name -match 'dkim|dmarc|spf')         { return 'Not configured' }
    if ($name -match 'transport|rule')         { return 'Insecure rules found' }

    switch ($Check.severity) {
        'Critical' { return 'Not configured (critical risk)' }
        'High'     { return 'Disabled' }
        'Medium'   { return 'Default (insecure)' }
        default    { return 'Not configured' }
    }
}

# --- Helper: load checks from JSON files and create all-FAIL findings ---
function New-AllFailFindings {
    param([string[]]$CheckFiles)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($file in $CheckFiles) {
        $path = Join-Path $dataDir $file
        $defs = Get-Content -Path $path -Raw | ConvertFrom-Json -AsHashtable

        # Pool of fake accounts used to demonstrate the "affected accounts" list for
        # checks that declare an affectedLabel (real scans populate these from live data).
        $sampleAccounts = @(
            'jsmith@sample.org', 'akumar@sample.org', 'mchen@sample.org', 'rlopez@sample.org',
            'tokafor@sample.org', 'dwilson@sample.org', 'bnguyen@sample.org', 'pgarcia@sample.org'
        )

        foreach ($check in $defs.checks) {
            $details = @{}
            if ($check.affectedLabel) {
                $idNum = [int]([regex]::Match([string]$check.id, '\d+').Value)
                $count = ($idNum % 5) + 3
                $details.AffectedItems = @($sampleAccounts | Select-Object -First $count)
                $details.AffectedLabel = $check.affectedLabel
            }

            $finding = [PSCustomObject]@{
                PSTypeName       = 'PSGuerrilla.AuditFinding'
                CheckId          = $check.id
                CheckName        = $check.name
                Category         = $defs.categoryName
                Subcategory      = $check.subcategory ?? ''
                Severity         = $check.severity
                Status           = 'FAIL'
                Description      = $check.description
                CurrentValue     = (Get-BadCurrentValue -Check $check)
                RecommendedValue = $check.recommendedValue ?? ''
                OrgUnitPath      = '/'
                RemediationUrl   = $check.remediationUrl ?? ''
                RemediationSteps = $check.remediationSteps ?? ''
                ReferenceUrl     = $check.referenceUrl ?? ''
                ReferenceTitle   = $check.referenceTitle ?? ''
                Compliance       = @{
                    NistSp80053  = @($check.compliance.nistSp80053 ?? @())
                    MitreAttack  = @($check.compliance.mitreAttack ?? @())
                    CisBenchmark = @($check.compliance.cisBenchmark ?? @())
                    Anssi        = @($check.compliance.anssi ?? @())
                    NsaAsd       = @($check.compliance.nsaAsd ?? @())
                    CisAd        = @($check.compliance.cisAd ?? @())
                    CisM365      = @($check.compliance.cisM365 ?? @())
                    CisAzure     = @($check.compliance.cisAzure ?? @())
                }
                Details          = $details
                Timestamp        = [datetime]::UtcNow
            }
            $findings.Add($finding)
        }
    }

    return , $findings.ToArray()
}

# --- Helper: compute posture score (mirrors Get-AuditPostureScore) ---
function Get-PostureScore {
    param([PSCustomObject[]]$Findings)

    $severityWeights = @{ Critical = 10; High = 6; Medium = 3; Low = 1; Info = 0 }

    $categories = $Findings | Group-Object -Property Category
    $categoryScores = @{}

    foreach ($cat in $categories) {
        $catFindings = @($cat.Group)
        $passCount = @($catFindings | Where-Object Status -eq 'PASS').Count
        $failCount = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $warnCount = @($catFindings | Where-Object Status -eq 'WARN').Count
        $skipCount = @($catFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count

        $deductions = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -notin @('FAIL', 'WARN')) { continue }
            $weight = $severityWeights[$f.Severity] ?? 1
            $multiplier = if ($f.Status -eq 'WARN') { 0.5 } else { 1.0 }
            $deductions += ($weight * $multiplier)
        }

        $maxPossible = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -in @('SKIP', 'ERROR')) { continue }
            $maxPossible += ($severityWeights[$f.Severity] ?? 1)
        }

        $catScore = if ($maxPossible -gt 0) {
            [Math]::Max(0, [Math]::Round(100 * (1 - ($deductions / $maxPossible)), 0))
        } else { 100 }

        $categoryScores[$cat.Name] = @{
            Score = [int]$catScore
            Pass  = $passCount
            Fail  = $failCount
            Warn  = $warnCount
            Skip  = $skipCount
            Total = $catFindings.Count
        }
    }

    $totalWeight = 0.0
    $weightedSum = 0.0
    foreach ($cat in $categoryScores.GetEnumerator()) {
        $catFindings = @($Findings | Where-Object { $_.Category -eq $cat.Key -and $_.Status -notin @('SKIP', 'ERROR') })
        $catWeight = 0.0
        foreach ($f in $catFindings) { $catWeight += ($severityWeights[$f.Severity] ?? 1) }
        $totalWeight += $catWeight
        $weightedSum += ($cat.Value.Score * $catWeight)
    }
    $overallScore = if ($totalWeight -gt 0) { [int][Math]::Round($weightedSum / $totalWeight, 0) } else { 100 }

    return @{
        OverallScore   = $overallScore
        CategoryScores = $categoryScores
    }
}

# --- Helper: score label ---
function Get-ScoreLabel {
    param([int]$Score)
    if ($Score -ge 90) { return 'FORTRESS' }
    if ($Score -ge 75) { return 'DEFENDED POSITION' }
    if ($Score -ge 60) { return 'CONTESTED GROUND' }
    if ($Score -ge 40) { return 'EXPOSED FLANK' }
    if ($Score -ge 20) { return 'UNDER SIEGE' }
    return 'OVERRUN'
}

# Get module reference for calling private export functions
$mod = Get-Module PSGuerrilla

# ============================================================================
# REPORT 1: Fortification (Google Workspace)
# ============================================================================
Write-Host 'Generating Fortification report (Google Workspace)...' -ForegroundColor Cyan

$gwsFiles = @(
    'AuthenticationChecks.json'
    'EmailSecurityChecks.json'
    'DriveSecurityChecks.json'
    'OAuthSecurityChecks.json'
    'AdminManagementChecks.json'
    'CollaborationChecks.json'
    'DeviceManagementChecks.json'
    'LoggingAlertingChecks.json'
)

$gwsFindings = New-AllFailFindings -CheckFiles $gwsFiles
$gwsScore = Get-PostureScore -Findings $gwsFindings
$gwsLabel = Get-ScoreLabel -Score $gwsScore.OverallScore
$gwsPath = Join-Path $samplesDir "Fortification-AllFail$styleSuffix.html"

& $mod {
    param($Findings, $OverallScore, $ScoreLabel, $CategoryScores, $TenantDomain, $FilePath, $Style, $Branding)
    Export-FortificationReportHtml `
        -Findings $Findings `
        -OverallScore $OverallScore `
        -ScoreLabel $ScoreLabel `
        -CategoryScores $CategoryScores `
        -TenantDomain $TenantDomain `
        -FilePath $FilePath `
        -Style $Style `
        -Branding $Branding
} $gwsFindings $gwsScore.OverallScore $gwsLabel $gwsScore.CategoryScores 'sample.org' $gwsPath $Style $demoBranding

Write-Host "  -> $gwsPath ($($gwsFindings.Count) checks, score: $($gwsScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 2: Reconnaissance (Active Directory)
# ============================================================================
Write-Host 'Generating Reconnaissance report (Active Directory)...' -ForegroundColor Cyan

# Discover every Active Directory reconnaissance check file automatically so newly
# added categories (e.g. Logging, Network, Tradecraft, TierZero) can never silently
# drop out of the sample report — the old hardcoded list omitted 4 files and
# undercounted AD by 28 checks (reported 175 instead of the real 203).
# Match is CASE-SENSITIVE on an uppercase 'D' so the Google Workspace
# 'AdminManagementChecks.json' (lowercase 'd') is not captured.
$adFiles = @(
    Get-ChildItem -Path $dataDir -Filter '*.json' |
        Where-Object { $_.Name -cmatch '^(AD[A-Z]|TierZero)' } |
        Select-Object -ExpandProperty Name |
        Sort-Object
)

$adFindings = New-AllFailFindings -CheckFiles $adFiles

# Populate realistic transitive attack-path chains on the ADPATH findings so the sample report's
# "Attack Paths to Tier-0" section showcases real chains (live scans fill these from collected
# ACL + privileged-membership data; the all-FAIL generator can't synthesize a graph on its own).
$sampleChains = @(
    [PSCustomObject]@{ SourceIsPrivileged = $false; Length = 3; Path = 'SAMPLE\jsmith --[WriteDacl]--> ServiceDesk-Operators  ==>  ServiceDesk-Operators --[GenericAll]--> Tier1-Server-Admins  ==>  Tier1-Server-Admins --[MemberOf]--> Domain Admins  =>  reaches domain admins (Tier-0 group)' }
    [PSCustomObject]@{ SourceIsPrivileged = $false; Length = 2; Path = 'SAMPLE\HelpDesk --[GenericAll]--> Workstation-Admins  ==>  Workstation-Admins --[MemberOf]--> Domain Admins  =>  reaches domain admins (Tier-0 group)' }
    [PSCustomObject]@{ SourceIsPrivileged = $true;  Length = 2; Path = 'Account Operators --[GenericWrite]--> Backup-Admins  ==>  Backup-Admins --[MemberOf]--> Administrators  =>  reaches administrators (Tier-0 group)' }
)
$sampleSingleHop = @(
    [PSCustomObject]@{ SourceIsPrivileged = $false; Length = 1; Path = 'SAMPLE\BackupOperators --[WriteDacl]--> AdminSDHolder  =>  reaches all protected groups via SDProp' }
)
foreach ($f in $adFindings) {
    if ($f.CheckId -eq 'ADPATH-002') {
        $f.Details = @{ ChainCount = $sampleChains.Count; NonPrivilegedCount = 2; Chains = $sampleChains; AffectedItems = @($sampleChains.Path) }
    } elseif ($f.CheckId -eq 'ADPATH-001') {
        $f.Details = @{ Chains = $sampleSingleHop; AffectedItems = @($sampleSingleHop.Path) }
    }
}

$adScore = Get-PostureScore -Findings $adFindings
$adLabel = Get-ScoreLabel -Score $adScore.OverallScore
$adPath = Join-Path $samplesDir "Reconnaissance-AllFail$styleSuffix.html"

# Sample BloodHound OpenGraph export so the report's BloodHound callout references a real artifact.
$bhSamplePath = Join-Path $samplesDir 'Reconnaissance-BloodHound.json'
$sampleBhAudit = @{
    ACLs = @{ DangerousACEs = @(
        [PSCustomObject]@{ IdentityReference = 'SAMPLE\HelpDesk'; IdentitySID = 'S-1-5-21-99-1-1-1147'; ActiveDirectoryRights = 'GenericAll'; ObjectClass = 'group'; ObjectName = 'Workstation-Admins'; ObjectSID = 'S-1-5-21-99-1-1-1200' }
        [PSCustomObject]@{ IdentityReference = 'SAMPLE\BackupOperators'; IdentitySID = 'S-1-5-21-99-1-1-1149'; ActiveDirectoryRights = 'WriteDacl'; ObjectName = 'AdminSDHolder' }
    ) }
    PrivilegedAccounts = @{ PrivilegedGroups = @{
        'Domain Admins' = @( [PSCustomObject]@{ IsGroup = $true; SamAccountName = 'Workstation-Admins'; SID = 'S-1-5-21-99-1-1-1200' } )
    } }
}
& $mod { param($a, $p) Export-BloodHoundData -AuditData $a -OutputPath $p | Out-Null } $sampleBhAudit $bhSamplePath

& $mod {
    param($Findings, $OverallScore, $ScoreLabel, $CategoryScores, $DomainName, $FilePath, $Style, $Branding, $BloodHoundPath)
    Export-ReconnaissanceReportHtml `
        -Findings $Findings `
        -OverallScore $OverallScore `
        -ScoreLabel $ScoreLabel `
        -CategoryScores $CategoryScores `
        -DomainName $DomainName `
        -FilePath $FilePath `
        -Style $Style `
        -Branding $Branding `
        -BloodHoundPath $BloodHoundPath
} $adFindings $adScore.OverallScore $adLabel $adScore.CategoryScores 'SAMPLE.LOCAL' $adPath $Style $demoBranding $bhSamplePath

Write-Host "  -> $adPath ($($adFindings.Count) checks, score: $($adScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 3: Infiltration (Entra ID / Azure / Intune / M365)
# ============================================================================
Write-Host 'Generating Infiltration report (Entra ID / M365)...' -ForegroundColor Cyan

$entraFiles = @(
    'EntraAuthChecks.json'
    'EntraCAChecks.json'
    'EntraPIMChecks.json'
    'EntraAppChecks.json'
    'EntraFedChecks.json'
    'EntraTenantChecks.json'
    'EidscaChecks.json'
    'AzureIAMChecks.json'
    'IntuneChecks.json'
    'M365ExchangeChecks.json'
    'M365SharePointChecks.json'
    'M365TeamsChecks.json'
    'M365DefenderChecks.json'
    'M365AuditChecks.json'
    'M365PowerPlatformChecks.json'
)

$entraFindings = New-AllFailFindings -CheckFiles $entraFiles
$entraScore = Get-PostureScore -Findings $entraFindings
$entraPath = Join-Path $samplesDir "Infiltration-AllFail$styleSuffix.html"

$infiltrationResult = [PSCustomObject]@{
    PSTypeName = 'PSGuerrilla.InfiltrationResult'
    TenantId   = '00000000-0000-0000-0000-000000000000'
    ScanStart  = [datetime]::UtcNow
    Findings   = $entraFindings
    Score      = $entraScore
}

& $mod {
    param($Result, $OutputPath, $Style, $Branding)
    Export-InfiltrationReportHtml -Result $Result -OutputPath $OutputPath -Style $Style -Branding $Branding
} $infiltrationResult $entraPath $Style $demoBranding

Write-Host "  -> $entraPath ($($entraFindings.Count) checks, score: $($entraScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 4: Campaign (unified — all theaters in one report)
# ============================================================================
Write-Host 'Generating Campaign report (all theaters)...' -ForegroundColor Cyan

function New-TheaterEntry {
    param([hashtable]$Score, [PSCustomObject[]]$Findings)
    @{
        Score          = $Score.OverallScore
        ScoreLabel     = (Get-ScoreLabel -Score $Score.OverallScore)
        PassCount      = @($Findings | Where-Object Status -eq 'PASS').Count
        FailCount      = @($Findings | Where-Object Status -eq 'FAIL').Count
        WarnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
        SkipCount      = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
        FindingCount   = @($Findings).Count
        CategoryScores = $Score.CategoryScores
    }
}

$campaignFindings = @($gwsFindings + $adFindings + $entraFindings)
$campaignScore = Get-PostureScore -Findings $campaignFindings
$campaignPath = Join-Path $samplesDir "Campaign-AllFail$styleSuffix.html"

$campaignResult = [PSCustomObject]@{
    PSTypeName    = 'PSGuerrilla.CampaignResult'
    Findings      = $campaignFindings
    OverallScore  = $campaignScore.OverallScore
    ScoreLabel    = (Get-ScoreLabel -Score $campaignScore.OverallScore)
    Theaters      = @('Google Workspace', 'Active Directory', 'Entra ID / M365')
    TheaterScores = @{
        'Google Workspace'  = (New-TheaterEntry -Score $gwsScore   -Findings $gwsFindings)
        'Active Directory'  = (New-TheaterEntry -Score $adScore    -Findings $adFindings)
        'Entra ID / M365'   = (New-TheaterEntry -Score $entraScore -Findings $entraFindings)
    }
    ScanStart     = [datetime]::UtcNow
    Duration      = [timespan]::FromMinutes(5)
    ScanId        = 'sample-campaign'
}

& $mod {
    param($Result, $OutputPath, $Style, $Branding)
    Export-CampaignReportHtml -Result $Result -OutputPath $OutputPath -Style $Style -Branding $Branding
} $campaignResult $campaignPath $Style $demoBranding

Write-Host "  -> $campaignPath ($($campaignFindings.Count) checks, score: $($campaignScore.OverallScore))" -ForegroundColor Green

# ============================================================================
# REPORT 5: Technical (all checks) — the README-linked sample at the repo root
# ============================================================================
# Only (re)generated for the default Guerrilla style; the README links this single file, so keeping
# it in the generator means it can never silently fall behind the report templates again.
if ($Style -eq 'Guerrilla') {
    Write-Host 'Generating Technical report (README sample)...' -ForegroundColor Cyan
    $techPath = Join-Path $PSScriptRoot '../PSGuerrilla-Sample-Report.html'
    & $mod {
        param($Findings, $OutputPath)
        Export-TechnicalReport -Findings $Findings -OutputPath $OutputPath -OrganizationName 'Sample Organization (All Checks Failing)'
    } $campaignFindings $techPath
    Write-Host "  -> $techPath ($($campaignFindings.Count) checks)" -ForegroundColor Green
}

# ============================================================================
Write-Host ''
Write-Host 'All sample reports generated.' -ForegroundColor Cyan
Write-Host "Total checks: GWS=$($gwsFindings.Count), AD=$($adFindings.Count), Entra=$($entraFindings.Count), Campaign=$($campaignFindings.Count)" -ForegroundColor DarkGray
