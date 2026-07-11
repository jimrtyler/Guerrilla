# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-TechnicalReport {
    <#
    .SYNOPSIS
        Generates a full technical security assessment report with remediation commands.
    .DESCRIPTION
        Produces a detailed HTML report for IT staff and security administrators. Includes
        every finding with check ID, current vs recommended values, severity, remediation
        steps, PowerShell commands, and compliance references.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Technical-Report.html
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER IncludePass
        Include passing checks in the report. Default: false (only FAIL/WARN).
    .EXAMPLE
        Export-TechnicalReport -OrganizationName 'Springfield USD'
    .EXAMPLE
        Export-TechnicalReport -IncludePass -OutputPath ./full-report.html
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [switch]$IncludePass
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Technical-Report.html' }

    $dataDir = Get-GuerrillaDataRoot
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null }
    }

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
    $html = [System.Text.StringBuilder]::new(131072)

    # Risk acceptance lookup
    $riskAcceptances = @{}
    try {
        foreach ($ra in (Get-RiskAcceptance -Status Active)) {
            $riskAcceptances[$ra.CheckId] = $ra
        }
    } catch { }

    # Stats
    $totalChecks = $Findings.Count
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $critCount = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count

    # Category breakdown
    $categories = @($Findings | Group-Object Category | Sort-Object { @($_.Group | Where-Object Status -eq 'FAIL').Count } -Descending)

    # Filter findings for display
    $displayFindings = if ($IncludePass) { $Findings } else { @($Findings | Where-Object Status -in @('FAIL', 'WARN')) }
    $displayFindings = @($displayFindings | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }}, CheckId)

    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Technical Security Report - $(& $esc $OrganizationName)</title>
<style>
:root { --bg:#1a1f16; --surface:#242b1e; --surface-alt:#2d3526; --border:#3d4a35; --text:#d4c9a8; --text-muted:#8a8468; --olive:#a8b58b; --amber:#d4883a; --sage:#6b9b6b; --parchment:#d4c4a0; --gold:#c9a84c; --dim:#6b6b5a; --deep-orange:#c75c2e; --dark-red:#8b2500; --critical:#c75c2e; --high:#d4883a; --medium:#c9a84c; --low:#6b9b6b; }
body { font-family:'Segoe UI',Tahoma,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; }
.container { max-width:1000px; margin:0 auto; }
h1 { color:var(--olive); border-bottom:2px solid var(--border); padding-bottom:10px; }
h2 { color:var(--olive); margin-top:30px; }
h3 { color:var(--gold); }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin:15px 0; }
.stat { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px; text-align:center; }
.stat .val { font-size:1.5em; font-weight:bold; }
.stat .lbl { color:var(--text-muted); font-size:0.8em; }
table { width:100%; border-collapse:collapse; margin:10px 0; }
th { background:var(--surface-alt); color:var(--olive); padding:8px 10px; text-align:left; font-size:0.85em; }
td { padding:6px 10px; border-bottom:1px solid var(--border); font-size:0.85em; }
.finding { background:var(--surface); border:1px solid var(--border); border-radius:6px; margin:12px 0; overflow:hidden; }
.finding-header { padding:12px 15px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
.finding-body { padding:12px 15px; }
.finding-body dt { color:var(--olive); font-weight:bold; margin-top:8px; font-size:0.85em; }
.finding-body dd { margin:2px 0 8px 0; }
.sev-badge { padding:2px 8px; border-radius:3px; font-size:0.8em; font-weight:bold; }
.sev-Critical { background:var(--dark-red); color:#fff; }
.sev-High { background:var(--deep-orange); color:#fff; }
.sev-Medium { background:var(--gold); color:var(--bg); }
.sev-Low { background:var(--sage); color:var(--bg); }
.status-FAIL { color:var(--deep-orange); font-weight:bold; }
.status-WARN { color:var(--gold); }
.status-PASS { color:var(--sage); }
.status-ACCEPTED { color:var(--dim); font-style:italic; }
code { background:var(--surface-alt); padding:2px 6px; border-radius:3px; font-size:0.9em; }
pre { background:var(--surface-alt); padding:10px; border-radius:4px; overflow-x:auto; font-size:0.85em; }
.footer { color:var(--dim); font-size:0.8em; margin-top:40px; border-top:1px solid var(--border); padding-top:10px; }
@media print { body { background:#fff; color:#333; } :root { --bg:#fff; --surface:#f9f9f9; --surface-alt:#eee; --border:#ccc; --text:#333; --text-muted:#666; --olive:#5a6b3a; --sage:#3a7a3a; --gold:#8a7a2a; --amber:#aa6a1a; --deep-orange:#aa3a0a; --dark-red:#7a1a00; --dim:#999; } .finding { page-break-inside:avoid; } }
</style>
</head>
<body>
<div class="container">
<h1>Technical Security Assessment Report</h1>
<p>$(& $esc $OrganizationName) | $timestamp UTC</p>

<div class="stats">
<div class="stat"><div class="val">$totalChecks</div><div class="lbl">Total Checks</div></div>
<div class="stat"><div class="val" style="color:var(--sage);">$passCount</div><div class="lbl">Pass</div></div>
<div class="stat"><div class="val" style="color:var(--deep-orange);">$failCount</div><div class="lbl">Fail</div></div>
<div class="stat"><div class="val" style="color:var(--gold);">$warnCount</div><div class="lbl">Warn</div></div>
<div class="stat"><div class="val" style="color:var(--dark-red);">$critCount</div><div class="lbl">Critical</div></div>
</div>

<h2>Category Breakdown</h2>
<table>
<tr><th>Category</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Total</th></tr>
"@)

    foreach ($cat in $categories) {
        $cp = @($cat.Group | Where-Object Status -eq 'PASS').Count
        $cf = @($cat.Group | Where-Object Status -eq 'FAIL').Count
        $cw = @($cat.Group | Where-Object Status -eq 'WARN').Count
        [void]$html.Append("<tr><td>$(& $esc $cat.Name)</td><td style='color:var(--sage)'>$cp</td><td style='color:var(--deep-orange)'>$cf</td><td style='color:var(--gold)'>$cw</td><td>$($cat.Count)</td></tr>`n")
    }

    [void]$html.Append('</table>')

    # Security Maturity + Attack Paths (shared sections). Maturity spans all checks; the attack-path
    # section only renders when AD attack-path findings are present (-OmitIfAbsent).
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $Findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $Findings -Esc $esc -OmitIfAbsent))

    [void]$html.Append(@"
<h2>Detailed Findings ($($displayFindings.Count))</h2>
"@)

    foreach ($finding in $displayFindings) {
        $checkId = $finding.CheckId ?? $finding.Id ?? 'N/A'
        $name = & $esc ($finding.Name ?? $finding.CheckName ?? $checkId)
        $sev = $finding.Severity ?? 'Medium'
        $status = $finding.Status ?? 'FAIL'

        # Check risk acceptance
        $isAccepted = $riskAcceptances.ContainsKey($checkId)
        $statusDisplay = if ($isAccepted) { 'ACCEPTED' } else { $status }
        $statusClass = "status-$statusDisplay"

        [void]$html.Append(@"
<div class="finding">
<div class="finding-header">
<div><strong>$checkId</strong> — $name</div>
<div><span class="sev-badge sev-$sev">$sev</span> <span class="$statusClass">$statusDisplay</span></div>
</div>
<div class="finding-body">
<dl>
$(if ($finding.Description) { "<dt>Description</dt><dd>$(& $esc $finding.Description)</dd>" })
$(if ($finding.RecommendedValue) { "<dt>Recommended</dt><dd>$(& $esc $finding.RecommendedValue)</dd>" })
$(if ($finding.RemediationSteps) { "<dt>Remediation Steps</dt><dd>$(& $esc $finding.RemediationSteps)</dd>" })
$(if ($finding.RemediationUrl) { "<dt>Reference</dt><dd><a href='$(& $esc $finding.RemediationUrl)' style='color:var(--olive)'>$(& $esc $finding.RemediationUrl)</a></dd>" })
$(if ($isAccepted) { "<dt>Risk Acceptance</dt><dd style='color:var(--dim);font-style:italic;'>Accepted by $($riskAcceptances[$checkId].AcceptedBy) — $($riskAcceptances[$checkId].Justification)</dd>" })
$(if ($finding.Compliance) {
    $compHtml = '<dt>Compliance</dt><dd>'
    if ($finding.Compliance.nistSp80053) { $compHtml += "NIST: $($finding.Compliance.nistSp80053 -join ', ') | " }
    if ($finding.Compliance.mitreAttack) { $compHtml += "MITRE: $($finding.Compliance.mitreAttack -join ', ') | " }
    if ($finding.Compliance.cisBenchmark) { $compHtml += "CIS: $($finding.Compliance.cisBenchmark -join ', ')" }
    $compHtml += '</dd>'
    $compHtml
})
</dl>
</div>
</div>
"@)
    }

    [void]$html.Append(@"
<div class="footer">
<p>Generated by Guerrilla v2.1.0 | $timestamp UTC</p>
</div>
</div>
</body>
</html>
"@)

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.TechnicalReport'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Technical report exported to $OutputPath"
        FindingsCount = $displayFindings.Count
    }
}
