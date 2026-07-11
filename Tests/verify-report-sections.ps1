# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Shared report sections (Security Maturity, Attack Paths to Tier-0) and their inclusion in all three
# HTML reports: AD reconnaissance (+ BloodHound callout), the GWS fortification report (maturity), and
# the unified Campaign report (maturity + attack paths). Run: pwsh -File Tests/verify-report-sections.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

function New-F($id, $cat, $status, $sev, [hashtable]$details = @{}, $cv = '') {
    [PSCustomObject]@{
        PSTypeName = 'Guerrilla.AuditFinding'
        CheckId = $id; CheckName = "$id check"; Category = $cat; Subcategory = ''
        Severity = $sev; Status = $status; Description = 'desc'; CurrentValue = $cv
        RecommendedValue = 'rec'; OrgUnitPath = '/'; RemediationUrl = ''; RemediationSteps = 'fix it'
        ReferenceUrl = ''; ReferenceTitle = ''
        Compliance = @{ NistSp80053=@(); MitreAttack=@(); CisBenchmark=@(); Anssi=@(); NsaAsd=@(); CisAd=@(); CisM365=@(); CisAzure=@() }
        Details = $details; Timestamp = [datetime]::UtcNow
    }
}

$chainObj = [PSCustomObject]@{
    Source = 'CORP\HelpDesk'; SourceIsPrivileged = $false; Length = 2
    ReachesTier0 = 'domain admins (Tier-0 group)'
    Path = 'CORP\HelpDesk --[GenericAll]--> CORP-Helpdesk-Admins  ==>  CORP-Helpdesk-Admins --[MemberOf]--> Domain Admins  =>  reaches domain admins (Tier-0 group)'
}
$adFindings = @(
    New-F 'ADPRIV-001' 'PrivilegedAccounts' 'FAIL' 'Critical'
    New-F 'ADPRIV-002' 'PrivilegedAccounts' 'PASS' 'High'
    New-F 'ADKERB-001' 'Kerberos' 'PASS' 'Medium'
    New-F 'ADPATH-002' 'AttackPath' 'FAIL' 'Critical' @{ Chains = @($chainObj); AffectedItems = @($chainObj.Path) } '1 transitive chain'
    # ADPATH-001 uses Details.Paths (NOT Chains) — the shape that broke v2.20/2.21 on real data.
    # Includes a genuine non-priv path (no Length property -> hop count derived) + an Expected
    # service-account path that MUST be excluded from the visuals.
    (New-F 'ADPATH-001' 'AttackPath' 'FAIL' 'Critical' @{
        PathCount = 1; ExpectedCount = 1
        AffectedItems = @('CORP\AppSvc --[WriteDacl]--> AdminSDHolder  =>  reaches all protected groups via SDProp')
        Paths = @(
            [PSCustomObject]@{ Source = 'CORP\AppSvc'; SourceIsPrivileged = $false; Expected = $false; Path = 'CORP\AppSvc --[WriteDacl]--> AdminSDHolder  =>  reaches all protected groups via SDProp' }
            [PSCustomObject]@{ Source = 'MSOL_a1b2'; SourceIsPrivileged = $true;  Expected = $true;  Path = 'MSOL_a1b2 --[GetChangesAll]--> Domain Root  =>  reaches the domain (DCSync)' }
        )
    } '1 escalation path')
)
$gwsFindings = @(
    New-F 'GWS-AUTH-001' 'Authentication' 'FAIL' 'High'
    New-F 'GWS-AUTH-002' 'Authentication' 'PASS' 'Medium'
    New-F 'GTRADE-001' 'Adversary Tradecraft' 'WARN' 'High'
)

# ── 1. Shared helpers in isolation ──
$h = & $mod {
    param($ad, $gws)
    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    [PSCustomObject]@{
        Maturity      = Get-GuerrillaMaturitySectionHtml -Findings $ad -Esc $esc
        Paths         = Get-GuerrillaAttackPathSectionHtml -Findings $ad -Esc $esc
        PathsOmitGWS  = Get-GuerrillaAttackPathSectionHtml -Findings $gws -Esc $esc -OmitIfAbsent
        Color3        = Get-GuerrillaMaturityLevelColor 3
        Carto         = Get-GuerrillaCartographyHtml -Findings $ad -Esc $esc
        CartoGWS      = Get-GuerrillaCartographyHtml -Findings $gws -Esc $esc
        ChainData     = Get-GuerrillaAttackChainData -Findings $ad
        Ioe           = Get-GuerrillaIndicatorsOfExposureHtml -Findings $ad -Esc $esc
        IoeAllPass    = Get-GuerrillaIndicatorsOfExposureHtml -Findings @([pscustomobject]@{ CheckId='P1'; CheckName='p'; Category='Kerberos'; Severity='Low'; Status='PASS'; CurrentValue=''; Details=@{} }) -Esc $esc
    }
} $adFindings $gwsFindings

Add-R 'helper: maturity returns a section'      ($h.Maturity -match '<h2>Security Maturity</h2>') ''
Add-R 'helper: attack-path renders ADPATH-002 chain' ($h.Paths -match 'MemberOf.*Domain Admins') ''
Add-R 'helper: attack-path renders ADPATH-001 Paths' ($h.Paths -match 'WriteDacl.*AdminSDHolder') ''
Add-R 'helper: Expected service-acct path excluded'  (-not ($h.Paths -match 'MSOL_a1b2')) ''
Add-R 'helper: chain data reads both shapes'    ($h.ChainData.Count -eq 2) "got=$($h.ChainData.Count)"
Add-R 'helper: hop count derived when no Length' (@($h.ChainData | Where-Object { $_.Path -match 'AdminSDHolder' }).Length -eq 1) ''
Add-R 'helper: OmitIfAbsent => empty on GWS'    ([string]::IsNullOrEmpty($h.PathsOmitGWS)) ''
Add-R 'helper: level color maps'                ($h.Color3 -eq 'var(--gold)') "got=$($h.Color3)"
Add-R 'helper: IOE emits ranked section'        (($h.Ioe -match '<h2>Indicators of Exposure</h2>') -and ($h.Ioe -match 'ioe-item')) ''
Add-R 'helper: IOE Critical ranked first'       ($h.Ioe -match '(?s)Indicators of Exposure.*?sev-critical') ''
Add-R 'helper: IOE empty when all pass'         ([string]::IsNullOrEmpty($h.IoeAllPass)) ''
Add-R 'helper: cartography emits SVG'           (($h.Carto -match '<svg ') -and ($h.Carto -match '<h2>Attack-Path Cartography</h2>')) ''
Add-R 'helper: cartography includes ADPATH-001 node' ($h.Carto -match 'AdminSDHolder') ''
Add-R 'helper: cartography has nodes+arrow'     (($h.Carto -match '<rect ') -and ($h.Carto -match 'marker-end')) ''
Add-R 'helper: cartography empty on GWS'        ([string]::IsNullOrEmpty($h.CartoGWS)) ''

# ── 2. AD reconnaissance report: all three sections ──
$catScores = @{
    PrivilegedAccounts = @{ Score = 40; Pass = 1; Fail = 1; Warn = 0; Skip = 0 }
    Kerberos           = @{ Score = 90; Pass = 1; Fail = 0; Warn = 0; Skip = 0 }
    AttackPath         = @{ Score = 0;  Pass = 0; Fail = 1; Warn = 0; Skip = 0 }
}
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-recon-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".html")
try {
    & $mod {
        param($f, $cs, $fp, $bh)
        Export-ReconnaissanceReportHtml -Findings $f -OverallScore 43 -ScoreLabel 'Poor' `
            -CategoryScores $cs -DomainName 'corp.local' -FilePath $fp -BloodHoundPath $bh
    } $adFindings $catScores $tmp '/tmp/corp-bloodhound.json'
    $html = Get-Content $tmp -Raw
    Add-R 'recon: Security Maturity present'    ($html -match '<h2>Security Maturity</h2>') ''
    Add-R 'recon: Indicators of Exposure present' ($html -match '<h2>Indicators of Exposure</h2>') ''
    Add-R 'recon: interactive filter bar present' (($html -match 'id="ggFilter"') -and ($html -match 'id="ggSearch"')) ''
    Add-R 'recon: finding rows tagged for filter' (($html -match 'class="gg-row"') -and ($html -match 'data-status=') -and ($html -match 'data-sev=')) ''
    Add-R 'recon: filter script present'          ($html -match "querySelectorAll\('tr\.gg-row'\)") ''
    Add-R 'recon: Cartography (SVG) present'    (($html -match '<h2>Attack-Path Cartography</h2>') -and ($html -match '<svg ')) ''
    Add-R 'recon: Attack Paths present'         ($html -match '<h2>Attack Paths to Tier-0</h2>') ''
    Add-R 'recon: full chain rendered'          ($html -match 'MemberOf.*Domain Admins') ''
    Add-R 'recon: BloodHound callout + path'    (($html -match '<h2>BloodHound Export</h2>') -and ($html -match 'corp-bloodhound.json')) ''
} finally { Remove-Item $tmp -ErrorAction SilentlyContinue }

# ── 3. GWS fortification report: maturity present, no attack-path section ──
$gwsCat = @{
    Authentication        = @{ Score = 50; Pass = 1; Fail = 1; Warn = 0; Skip = 0 }
    'Adversary Tradecraft' = @{ Score = 70; Pass = 0; Fail = 0; Warn = 1; Skip = 0 }
}
$tmp2 = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-gws-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".html")
try {
    & $mod {
        param($f, $cs, $fp)
        Export-FortificationReportHtml -Findings $f -OverallScore 55 -ScoreLabel 'Fair' `
            -CategoryScores $cs -TenantDomain 'example.com' -FilePath $fp
    } $gwsFindings $gwsCat $tmp2
    $html2 = Get-Content $tmp2 -Raw
    Add-R 'gws: Security Maturity present'      ($html2 -match '<h2>Security Maturity</h2>') ''
    Add-R 'gws: Indicators of Exposure present' ($html2 -match '<h2>Indicators of Exposure</h2>') ''
    Add-R 'gws: no Attack Paths section'        (-not ($html2 -match '<h2>Attack Paths to Tier-0</h2>')) ''
    Add-R 'gws: Tradecraft finding surfaced'    ($html2 -match 'GTRADE-001') ''
} finally { Remove-Item $tmp2 -ErrorAction SilentlyContinue }

# ── 4. Campaign (big) report: maturity + attack paths across theaters ──
$result = [PSCustomObject]@{
    Findings = @($adFindings + $gwsFindings)
    OverallScore = 49; ScoreLabel = 'Poor'
    Theaters = @('Active Directory', 'Google Workspace')
    TheaterScores = @{
        'Active Directory' = @{ Score=43; ScoreLabel='Poor'; PassCount=2; FailCount=2; WarnCount=0; SkipCount=0; FindingCount=4
            CategoryScores = @{ AttackPath=@{Score=0;Pass=0;Fail=1;Warn=0;Skip=0}; PrivilegedAccounts=@{Score=40;Pass=1;Fail=1;Warn=0;Skip=0}; Kerberos=@{Score=90;Pass=1;Fail=0;Warn=0;Skip=0} } }
        'Google Workspace' = @{ Score=55; ScoreLabel='Fair'; PassCount=1; FailCount=1; WarnCount=1; SkipCount=0; FindingCount=3
            CategoryScores = @{ Authentication=@{Score=50;Pass=1;Fail=1;Warn=0;Skip=0}; 'Adversary Tradecraft'=@{Score=70;Pass=0;Fail=0;Warn=1;Skip=0} } }
    }
    ScanStart = [datetime]::UtcNow; Duration = [timespan]::FromMinutes(3); ScanId = 'camp-test'
}
$tmp3 = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-camp-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".html")
try {
    & $mod {
        param($r, $fp)
        Export-CampaignReportHtml -Result $r -OutputPath $fp
    } $result $tmp3
    $html3 = Get-Content $tmp3 -Raw
    Add-R 'campaign: Security Maturity present'  ($html3 -match '<h2>Security Maturity</h2>') ''
    Add-R 'campaign: Indicators of Exposure present' ($html3 -match '<h2>Indicators of Exposure</h2>') ''
    Add-R 'campaign: Cartography (SVG) present'  (($html3 -match '<h2>Attack-Path Cartography</h2>') -and ($html3 -match '<svg ')) ''
    Add-R 'campaign: Attack Paths present'       ($html3 -match '<h2>Attack Paths to Tier-0</h2>') ''
    Add-R 'campaign: full chain rendered'        ($html3 -match 'MemberOf.*Domain Admins') ''
    Add-R 'campaign: both theaters present'      (($html3 -match 'Active Directory') -and ($html3 -match 'Google Workspace')) ''
} finally { Remove-Item $tmp3 -ErrorAction SilentlyContinue }

# ── 5. Technical report (README-linked sample type): maturity + attack paths via shared helpers ──
$tmp4 = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-tech-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".html")
try {
    & $mod {
        param($f, $fp)
        Export-TechnicalReport -Findings $f -OutputPath $fp -OrganizationName 'Test Org' | Out-Null
    } $adFindings $tmp4
    $html4 = Get-Content $tmp4 -Raw
    Add-R 'technical: Security Maturity present' ($html4 -match '<h2>Security Maturity</h2>') ''
    Add-R 'technical: Indicators of Exposure present' ($html4 -match '<h2>Indicators of Exposure</h2>') ''
    Add-R 'technical: Cartography (SVG) present' (($html4 -match '<h2>Attack-Path Cartography</h2>') -and ($html4 -match '<svg ')) ''
    Add-R 'technical: Attack Paths present'      ($html4 -match '<h2>Attack Paths to Tier-0</h2>') ''
    Add-R 'technical: full chain rendered'       ($html4 -match 'MemberOf.*Domain Admins') ''
} finally { Remove-Item $tmp4 -ErrorAction SilentlyContinue }

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($x in $results) {
    $mark = if ($x.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($x.Name)"; if ($x.Detail) { $line += "  ($($x.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
