# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-BudgetJustification {
    <#
    .SYNOPSIS
        Generates a board-ready budget justification document from audit findings.
    .DESCRIPTION
        Produces an HTML document suitable for presenting to school boards, executives,
        or budget committees. Groups remediation items by cost tier, shows total cost
        estimates, and maps findings to compliance requirements.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Budget-Justification.html in current directory.
    .PARAMETER ProfileName
        Baseline profile context. Default: uses configured profile.
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER ConfigPath
        Override config file path.
    .EXAMPLE
        Export-BudgetJustification -OrganizationName 'Springfield USD'
        Generates a budget justification report for the district.
    .EXAMPLE
        $findings = Invoke-Fortification -PassThru; Export-BudgetJustification -Findings $findings -OutputPath ./budget.html
        Generates report from specific findings.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,

        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ProfileName,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath
    )

    # Load config
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if ($cfgPath -and (Test-Path $cfgPath)) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
    }

    if (-not $ProfileName) { $ProfileName = $config.profile ?? 'Default' }
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Budget-Justification.html' }

    # Load findings from state if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        $dataDir = Get-GuerrillaDataRoot
        $findingsFiles = @()
        if (Test-Path $dataDir) {
            $findingsFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($findingsFiles.Count -gt 0) {
            $Findings = @()
            foreach ($f in $findingsFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $Findings += @($data)
                } catch { Write-Verbose "Failed to load findings: $_" }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null }
    }

    # Load remediation costs
    $remPath = Join-Path $script:ModuleRoot 'Data/RemediationCosts.json'
    $remData = $null
    if (Test-Path $remPath) {
        $remData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
    }

    # Get all actionable findings with cost info
    $allFixes = Get-ResourceConstrainedFixes -Findings $Findings -MaxCostTier 'Medium' -RemediationData $remData

    # Also get high/enterprise items
    $tierOrder = @{ 'Free' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Enterprise' = 4 }
    $highCostFixes = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($finding in $Findings) {
        if ($finding.Status -notin @('FAIL', 'WARN')) { continue }
        $checkId = $finding.CheckId ?? $finding.Id ?? ''
        $prefix = if ($checkId -match '^([A-Z0-9]+)-') { $Matches[1] } else { '' }
        $costInfo = $remData.overrides.$checkId ?? $remData.categoryDefaults.$prefix
        if (-not $costInfo) { continue }
        $tier = $costInfo.costTier ?? 'Medium'
        if ($tierOrder[$tier] -gt 2) {
            $highCostFixes.Add([PSCustomObject]@{
                CheckId    = $checkId
                CheckName  = $finding.Name ?? $checkId
                Severity   = $finding.Severity ?? 'Medium'
                Status     = $finding.Status
                CostTier   = $tier
                Effort     = $costInfo.effort ?? 'High'
                Category   = $finding.Category ?? $prefix
                Notes      = $costInfo.notes ?? ''
            })
        }
    }

    # Calculate summary stats
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $totalChecks = $Findings.Count
    $criticalFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count

    # Guerrilla Score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings } catch { }
    $score = $scoreResult.Score ?? 'N/A'
    $label = $scoreResult.Label ?? ''

    # Group fixes by cost tier
    $freeFixes = @($allFixes | Where-Object CostTier -eq 'Free')
    $lowFixes = @($allFixes | Where-Object CostTier -eq 'Low')
    $medFixes = @($allFixes | Where-Object CostTier -eq 'Medium')

    # Cost estimates from RemediationCosts.json tiers
    $costRanges = $remData.costTiers ?? @{}

    # Build compliance impact summary
    $complianceMappings = @()
    try { $complianceMappings = Get-ComplianceCrosswalk -Findings $Findings -FailOnly } catch { }
    $complianceFrameworks = @($complianceMappings | Group-Object Framework | ForEach-Object {
        [PSCustomObject]@{ Framework = $_.Name; GapCount = $_.Count }
    })

    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Build fix rows HTML
    $fixRowsHtml = { param($fixes, $tierLabel)
        $rows = ''
        foreach ($fix in $fixes) {
            $sevColor = switch ($fix.Severity) {
                'Critical' { '#af0000' }
                'High'     { '#d75f00' }
                'Medium'   { '#ff8700' }
                default    { '#d7af5f' }
            }
            $rows += @"
<tr>
<td style="padding:6px 10px;border-bottom:1px solid #333;">$($fix.CheckId)</td>
<td style="padding:6px 10px;border-bottom:1px solid #333;">$([System.Web.HttpUtility]::HtmlEncode($fix.CheckName))</td>
<td style="padding:6px 10px;border-bottom:1px solid #333;color:$sevColor;">$($fix.Severity)</td>
<td style="padding:6px 10px;border-bottom:1px solid #333;">$($fix.Effort)</td>
<td style="padding:6px 10px;border-bottom:1px solid #333;">~$($fix.EstimatedHours)h</td>
</tr>
"@
        }
        return $rows
    }

    $freeRows = & $fixRowsHtml $freeFixes 'Free'
    $lowRows = & $fixRowsHtml $lowFixes 'Low'
    $medRows = & $fixRowsHtml $medFixes 'Medium'

    $complianceRows = ''
    foreach ($fw in $complianceFrameworks) {
        $complianceRows += "<tr><td style='padding:6px 10px;border-bottom:1px solid #333;'>$($fw.Framework)</td><td style='padding:6px 10px;border-bottom:1px solid #333;color:#af0000;'>$($fw.GapCount) gap(s)</td></tr>`n"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Budget Justification - $([System.Web.HttpUtility]::HtmlEncode($OrganizationName))</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #ffd7af; margin: 0; padding: 20px; }
.container { max-width: 900px; margin: 0 auto; }
h1 { color: #afaf5f; border-bottom: 2px solid #585858; padding-bottom: 10px; }
h2 { color: #afaf5f; margin-top: 30px; }
h3 { color: #d7af5f; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }
.summary-card { background: #262626; border: 1px solid #585858; border-radius: 6px; padding: 15px; text-align: center; }
.summary-card .value { font-size: 2em; font-weight: bold; }
.summary-card .label { color: #585858; font-size: 0.85em; margin-top: 5px; }
.score-critical { color: #af0000; }
.score-high { color: #d75f00; }
.score-medium { color: #ff8700; }
.score-good { color: #87af87; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; background: #262626; }
th { background: #333; color: #afaf5f; padding: 8px 10px; text-align: left; }
.tier-header { background: #333; color: #afaf5f; padding: 10px; margin-top: 20px; border-radius: 4px 4px 0 0; }
.phase { background: #262626; border: 1px solid #585858; border-radius: 6px; padding: 15px; margin: 15px 0; }
.phase-title { color: #afaf5f; font-size: 1.1em; font-weight: bold; }
.phase-cost { color: #87af87; float: right; }
.footer { color: #585858; font-size: 0.8em; margin-top: 40px; border-top: 1px solid #333; padding-top: 10px; }
@media print { body { background: #fff; color: #333; } h1, h2, h3 { color: #333; } table, .summary-card, .phase { border-color: #ccc; background: #f9f9f9; } .footer { color: #999; } }
</style>
</head>
<body>
<div class="container">
<h1>Security Budget Justification</h1>
<p><strong>$([System.Web.HttpUtility]::HtmlEncode($OrganizationName))</strong> | Profile: $ProfileName | Generated: $timestamp UTC</p>

<h2>Executive Summary</h2>
<div class="summary-grid">
<div class="summary-card">
<div class="value $(if ([int]$score -ge 75) { 'score-good' } elseif ([int]$score -ge 40) { 'score-medium' } else { 'score-critical' })">$score</div>
<div class="label">Guerrilla Score$(if ($label) { " ($label)" })</div>
</div>
<div class="summary-card">
<div class="value score-critical">$criticalFails</div>
<div class="label">Critical Failures</div>
</div>
<div class="summary-card">
<div class="value score-high">$highFails</div>
<div class="label">High Failures</div>
</div>
<div class="summary-card">
<div class="value">$totalChecks</div>
<div class="label">Total Checks ($passCount pass / $failCount fail / $warnCount warn)</div>
</div>
</div>

$(if ($complianceFrameworks.Count -gt 0) {
@"
<h2>Compliance Impact</h2>
<p>The following compliance frameworks have gaps based on current audit findings:</p>
<table>
<tr><th>Framework</th><th>Gaps Found</th></tr>
$complianceRows
</table>
"@
})

<h2>Recommended Investment Phases</h2>

<div class="phase">
<div class="phase-title">Phase 1: Quick Wins (No Cost) <span class="phase-cost">$($costRanges.Free.annualCostRange ?? '$0')</span></div>
<p>Configuration changes using existing tools — highest ROI, immediate security improvement.</p>
$(if ($freeFixes.Count -gt 0) {
@"
<table>
<tr><th>Check</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Time</th></tr>
$freeRows
</table>
<p><strong>$($freeFixes.Count) action(s)</strong> | Estimated total effort: $([Math]::Round(($freeFixes | Measure-Object EstimatedHours -Sum).Sum, 1)) hours</p>
"@
} else { '<p>No free fixes identified.</p>' })
</div>

<div class="phase">
<div class="phase-title">Phase 2: Low-Cost Improvements <span class="phase-cost">$($costRanges.Low.annualCostRange ?? '$0 - $500')</span></div>
<p>Minor purchases or license add-ons within existing budget.</p>
$(if ($lowFixes.Count -gt 0) {
@"
<table>
<tr><th>Check</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Time</th></tr>
$lowRows
</table>
<p><strong>$($lowFixes.Count) action(s)</strong> | Estimated total effort: $([Math]::Round(($lowFixes | Measure-Object EstimatedHours -Sum).Sum, 1)) hours</p>
"@
} else { '<p>No low-cost fixes identified.</p>' })
</div>

<div class="phase">
<div class="phase-title">Phase 3: Moderate Investment <span class="phase-cost">$($costRanges.Medium.annualCostRange ?? '$500 - $5,000')</span></div>
<p>License upgrades or add-on products for enhanced security capabilities.</p>
$(if ($medFixes.Count -gt 0) {
@"
<table>
<tr><th>Check</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Time</th></tr>
$medRows
</table>
<p><strong>$($medFixes.Count) action(s)</strong> | Estimated total effort: $([Math]::Round(($medFixes | Measure-Object EstimatedHours -Sum).Sum, 1)) hours</p>
"@
} else { '<p>No medium-cost fixes identified.</p>' })
</div>

$(if ($highCostFixes.Count -gt 0) {
@"
<div class="phase">
<div class="phase-title">Phase 4: Strategic Investment <span class="phase-cost">$($costRanges.High.annualCostRange ?? '$5,000+')</span></div>
<p>Major purchases or infrastructure changes for long-term security posture improvement.</p>
<p><strong>$($highCostFixes.Count) item(s)</strong> identified requiring significant investment. Contact your security advisor for detailed scoping.</p>
</div>
"@
})

<div class="footer">
<p>Generated by Guerrilla v2.1.0 | $timestamp UTC | This report is for internal planning purposes.</p>
</div>
</div>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.BudgetJustification'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Budget justification exported to $OutputPath"
        Summary    = [PSCustomObject]@{
            GuerrillaScore  = $score
            TotalChecks     = $totalChecks
            CriticalFails   = $criticalFails
            HighFails       = $highFails
            FreeFixCount    = $freeFixes.Count
            LowCostFixCount = $lowFixes.Count
            MedCostFixCount = $medFixes.Count
            HighCostFixCount = $highCostFixes.Count
            ComplianceGaps   = $complianceFrameworks
        }
    }
}
