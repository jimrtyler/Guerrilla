# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-FortificationReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [string]$TenantDomain = '',
        [hashtable]$Delta,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional',

        [hashtable]$Branding
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    # Render the affected accounts/objects captured in a finding's Details as one or more
    # labeled BULLETED lists — delegates to the shared Get-GuerrillaReportAffectedHtml so the
    # Fortification, AD, Entra and Campaign reports all surface affected entities identically.
    $renderAffected = {
        param($Details)
        Get-GuerrillaReportAffectedHtml -Details $Details
    }

    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # --- Counts ---
    $totalChecks = $Findings.Count
    $passCount   = @($Findings | Where-Object Status -eq 'PASS').Count
    $failCount   = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount   = @($Findings | Where-Object Status -eq 'WARN').Count
    $skipCount   = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')
    $critCount    = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount    = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount     = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount     = @($failFindings | Where-Object Severity -eq 'Low').Count

    # --- Module version ---
    $moduleVersion = '2.0.0'
    try {
        $modVer = $ExecutionContext.SessionState.Module.Version
        if ($modVer) { $moduleVersion = $modVer.ToString() }
    } catch { }

    # --- Score color ---
    $scoreColor = switch ($true) {
        ($OverallScore -ge 90) { 'var(--sage)';        break }
        ($OverallScore -ge 75) { 'var(--olive)';       break }
        ($OverallScore -ge 60) { 'var(--gold)';        break }
        ($OverallScore -ge 40) { 'var(--amber)';       break }
        ($OverallScore -ge 20) { 'var(--deep-orange)'; break }
        default                { 'var(--dark-red)' }
    }

    $themeStyle   = Get-GuerrillaReportThemeStyleBlock -Style $Style
    $displayLabel = Resolve-GuerrillaReportScoreLabel -Score $OverallScore -Style $Style -Fallback $ScoreLabel
    $brand        = Get-GuerrillaReportBrandingHtml -Branding $Branding

    $html = [System.Text.StringBuilder]::new(65536)

    # ═══════════════════════════════════════════════════════════════
    # HEAD
    # ═══════════════════════════════════════════════════════════════
    $tenantTitle = if ($TenantDomain) { " - $(& $esc $TenantDomain)" } else { '' }

    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guerrilla Fortification Report$tenantTitle - $timestampStr</title>
<style>
$themeStyle
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: var(--font-body);
    background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 24px; max-width: 1400px; margin: 0 auto;
  }
  h1 { font-size: 1.6em; color: var(--parchment); letter-spacing: 2px; text-transform: uppercase; }
  h2 {
    font-size: 1.2em; margin: 32px 0 16px; padding-bottom: 8px; color: var(--parchment);
    border-bottom: 2px solid var(--border); letter-spacing: 1px; text-transform: uppercase;
  }
  h3 { font-size: 1.05em; margin: 16px 0 8px; color: var(--olive); }
  h4 { font-size: 0.95em; margin: 12px 0 8px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
  .subtitle { color: var(--dim); font-size: 0.85em; margin-bottom: 24px; }

  /* Score Panel */
  .score-panel {
    background: var(--surface); border: 2px solid var(--border);
    border-radius: 4px; padding: 24px 32px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 32px;
  }
  .score-ring {
    width: 120px; height: 120px; position: relative; flex-shrink: 0;
  }
  .score-ring svg { transform: rotate(-90deg); }
  .score-ring .value {
    position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; font-size: 2em; font-weight: 700;
  }
  .score-detail .label {
    font-size: 1.3em; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
  }
  .score-detail .desc { color: var(--dim); font-size: 0.85em; margin-top: 4px; }

  /* Executive Summary */
  .exec-summary {
    background: var(--surface-alt); border: 1px solid var(--border); border-left: 4px solid var(--amber);
    border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px;
  }
  .exec-summary h3 { margin-top: 0; color: var(--parchment); }
  .exec-summary p { margin: 8px 0; font-size: 0.9em; }

  /* Stat cards */
  .stat-grid {
    display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px;
  }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 14px 20px; text-align: center;
    flex: 1 1 140px; min-width: 120px;
  }
  .stat-card .value { font-size: 1.8em; font-weight: 700; }
  .stat-card .label { color: var(--dim); font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }

  /* Category cards */
  .category-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 12px; margin-bottom: 24px;
  }
  .cat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 16px;
  }
  .cat-card .cat-header {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;
  }
  .cat-card .cat-name {
    font-size: 0.9em; font-weight: 700; color: var(--olive); text-transform: uppercase; letter-spacing: 1px;
  }
  .cat-card .cat-score { font-size: 1.4em; font-weight: 700; }
  .cat-card .cat-bar-bg {
    height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-bottom: 8px;
  }
  .cat-card .cat-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
  .cat-card .cat-counts { font-size: 0.8em; color: var(--dim); }
  .cat-card .cat-counts span { margin-right: 10px; }

  /* Badges */
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 2px;
    font-size: 0.75em; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace;
    white-space: nowrap;
  }
  .badge-pass { background: var(--pass); color: #d4c9a8; }
  .badge-fail { background: var(--fail); color: #fff; }
  .badge-accepted { background: var(--dim); color: var(--text); font-style: italic; }
  .badge-warn { background: var(--warn); color: #1a1f16; }
  .badge-skip { background: var(--skip); color: #d4c9a8; }
  .badge-error { background: var(--skip); color: #d4c9a8; }
  .badge-critical { background: var(--critical); color: #fff; }
  .badge-high { background: var(--high); color: #1a1f16; }
  .badge-medium { background: var(--medium); color: #1a1f16; }
  .badge-low { background: var(--low); color: #1a1f16; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 0.85em; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
  th {
    background: var(--surface); font-weight: 700; font-size: 0.8em; color: var(--dim);
    text-transform: uppercase; letter-spacing: 1px; position: sticky; top: 0;
  }
  tr:nth-child(even) { background: rgba(45, 53, 38, 0.4); }
  tr:hover { background: rgba(168, 181, 139, 0.08); }
  td { vertical-align: top; }

  /* Priority table highlight */
  .priority-table tr td:first-child { font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace; font-size: 0.85em; }

  /* Collapsible category details */
  details.cat-detail {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; margin-bottom: 12px;
  }
  details.cat-detail summary {
    padding: 12px 16px; cursor: pointer; list-style: none;
    display: flex; align-items: center; gap: 12px;
    font-weight: 700; color: var(--olive); text-transform: uppercase; letter-spacing: 1px;
  }
  details.cat-detail summary::-webkit-details-marker { display: none; }
  details.cat-detail summary::before {
    content: '\25b6'; font-size: 0.7em; color: var(--dim); transition: transform 0.2s;
  }
  details.cat-detail[open] summary::before { transform: rotate(90deg); }
  details.cat-detail .detail-body { padding: 0 16px 16px; overflow-x: auto; }

  /* Compliance table */
  .compliance-table td code {
    display: inline-block; padding: 1px 5px; border-radius: 2px;
    font-size: 0.85em; margin: 1px 2px; background: rgba(168, 181, 139, 0.1);
    border: 1px solid var(--border);
  }

  /* Delta section */
  .delta-section {
    background: var(--surface-alt); border: 1px solid var(--border); border-left: 4px solid var(--gold);
    border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px;
  }
  .delta-section h3 { margin-top: 0; color: var(--parchment); }
  .delta-arrow-up { color: var(--pass); font-weight: 700; }
  .delta-arrow-down { color: var(--fail); font-weight: 700; }
  .delta-arrow-same { color: var(--dim); font-weight: 700; }

  code { font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace; font-size: 0.9em; color: var(--olive); }
  a { color: var(--gold); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .remediation-cell { max-width: 300px; font-size: 0.85em; }

  /* Affected accounts + actionable links (extra row beneath a finding) */
  tr.finding-extra td {
    background: rgba(199, 92, 46, 0.06);
    border-left: 3px solid var(--amber);
    padding: 4px 10px 12px 14px;
  }
  tr.finding-extra:hover td { background: rgba(199, 92, 46, 0.06); }
  .extra-wrap { display: flex; flex-direction: column; gap: 8px; }
  .affected { font-size: 0.85em; line-height: 1.5; margin-top: 4px; }
  .affected-label { color: var(--amber); font-weight: 600; }
  .affected-items { color: var(--text); margin: 4px 0 0 0; padding-left: 20px; }
  .affected-items li { word-break: break-word; margin: 1px 0; }
  .affected-items li.more { list-style: none; margin-left: -20px; font-style: italic; opacity: .7; color: var(--dim); }
  .extra-links { display: flex; flex-wrap: wrap; gap: 18px; font-size: 0.85em; margin-top: 2px; }
  .extra-links .why a { color: var(--gold); font-weight: 700; }
  .extra-links .admin-link { color: var(--olive); font-weight: 700; }

  /* Print styles */
  @media print {
    body { background: #fff; color: #000; }
    .score-panel, .stat-card, .cat-card, .cat-detail, .exec-summary, .delta-section {
      border-color: #ccc; background: #f9f9f9;
    }
    details.cat-detail { break-inside: avoid; }
    a { color: #336; }
  }
</style>
</head>
<body>
"@)

    # ═══════════════════════════════════════════════════════════════
    # HEADER
    # ═══════════════════════════════════════════════════════════════
    $domainLine = if ($TenantDomain) { " &mdash; $(& $esc $TenantDomain)" } else { '' }

    [void]$html.Append(@"
$($brand.Banner)
$($brand.Header)
<h1>&#x1F6E1; Guerrilla Fortification Report</h1>
<div class="subtitle">
  Generated $timestampStr$domainLine &mdash;
  $totalChecks configuration checks evaluated
</div>
"@)

    # ═══════════════════════════════════════════════════════════════
    # SCORE PANEL (SVG ring)
    # ═══════════════════════════════════════════════════════════════
    $circumference = [Math]::Round(2 * [Math]::PI * 52, 1)  # radius 52
    $dashOffset    = [Math]::Round($circumference - ($circumference * $OverallScore / 100), 1)

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="$scoreColor" stroke-width="8"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashOffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value" style="color:$scoreColor">$OverallScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$(& $esc $displayLabel)</div>
    <div class="desc">Fortification Score (0&ndash;100). Weighted assessment of $totalChecks Google Workspace configuration checks.</div>
  </div>
</div>
"@)

    # ═══════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════
    $summaryVerdict = if ($critCount -gt 0) {
        "Immediate action required. $critCount critical-severity configuration failure(s) detected that expose the tenant to significant risk."
    } elseif ($highCount -gt 0) {
        "Remediation recommended. $highCount high-severity finding(s) identified that should be addressed promptly."
    } elseif ($medCount -gt 0) {
        "Monitor and improve. $medCount medium-severity finding(s) warrant review and hardening."
    } elseif ($failCount -gt 0) {
        "Minor gaps detected. $lowCount low-severity finding(s) present. Overall posture is sound."
    } else {
        "All checks passed. The tenant configuration meets baseline security expectations."
    }

    [void]$html.Append(@"
<div class="exec-summary">
  <h3>Executive Summary</h3>
  <p><strong>Assessment:</strong> $summaryVerdict</p>
  <p><strong>Scope:</strong> $totalChecks configuration checks across $($CategoryScores.Count) categories.</p>
  <p><strong>Results:</strong> $passCount passed, $failCount failed, $warnCount warnings, $skipCount skipped.</p>
"@)
    if ($critCount -gt 0) {
        [void]$html.Append("<p style=`"color:var(--critical)`"><strong>&#9888; $critCount critical finding(s) require immediate remediation.</strong></p>")
    }
    [void]$html.Append('</div>')

    # --- Stat cards ---
    [void]$html.Append(@"
<div class="stat-grid">
  <div class="stat-card"><div class="value" style="color:var(--parchment)">$totalChecks</div><div class="label">Total Checks</div></div>
  <div class="stat-card"><div class="value" style="color:var(--pass)">$passCount</div><div class="label">Passed</div></div>
  <div class="stat-card"><div class="value" style="color:var(--fail)">$failCount</div><div class="label">Failed</div></div>
  <div class="stat-card"><div class="value" style="color:var(--warn)">$warnCount</div><div class="label">Warnings</div></div>
  <div class="stat-card"><div class="value" style="color:var(--skip)">$skipCount</div><div class="label">Skipped</div></div>
  <div class="stat-card"><div class="value" style="color:var(--critical)">$critCount</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="value" style="color:var(--high)">$highCount</div><div class="label">High</div></div>
  <div class="stat-card"><div class="value" style="color:var(--medium)">$medCount</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="value" style="color:var(--low)">$lowCount</div><div class="label">Low</div></div>
</div>
"@)

    # ═══════════════════════════════════════════════════════════════
    # SECURITY MATURITY (shared section — spans the GWS categories)
    # ═══════════════════════════════════════════════════════════════
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc))

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY SCORE DASHBOARD
    # ═══════════════════════════════════════════════════════════════
    [void]$html.Append('<h2>Category Scores</h2>')
    [void]$html.Append('<div class="category-grid">')

    foreach ($cat in ($CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $catScore = $cat.Value.Score
        $catColor = switch ($true) {
            ($catScore -ge 90) { 'var(--sage)';        break }
            ($catScore -ge 75) { 'var(--olive)';       break }
            ($catScore -ge 60) { 'var(--gold)';        break }
            ($catScore -ge 40) { 'var(--amber)';       break }
            default            { 'var(--deep-orange)' }
        }

        [void]$html.Append(@"
<div class="cat-card">
  <div class="cat-header">
    <span class="cat-name">$(& $esc $cat.Key)</span>
    <span class="cat-score" style="color:$catColor">$catScore</span>
  </div>
  <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${catScore}%;background:$catColor"></div></div>
  <div class="cat-counts">
    <span style="color:var(--pass)">Pass: $($cat.Value.Pass)</span>
    <span style="color:var(--fail)">Fail: $($cat.Value.Fail)</span>
    <span style="color:var(--warn)">Warn: $($cat.Value.Warn)</span>
  </div>
</div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══════════════════════════════════════════════════════════════
    # CRITICAL & HIGH FINDINGS TABLE
    # ═══════════════════════════════════════════════════════════════
    $priorityFindings = @($failFindings | Where-Object { $_.Severity -in @('Critical', 'High') } |
        Sort-Object { if ($_.Severity -eq 'Critical') { 0 } else { 1 } }, CheckId)

    if ($priorityFindings.Count -gt 0) {
        [void]$html.Append('<h2>Priority Findings &mdash; Critical &amp; High</h2>')
        [void]$html.Append(@'
<table class="priority-table">
  <tr>
    <th>Check ID</th><th>Check Name</th><th>Category</th><th>Severity</th><th>Current Value</th><th>Remediation</th>
  </tr>
'@)
        foreach ($f in $priorityFindings) {
            $sevClass = $f.Severity.ToLower()
            $remParts = [System.Collections.Generic.List[string]]::new()
            if ($f.RemediationUrl) {
                $remParts.Add("<a href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">&#x2699; Fix in Admin Console &#x2197;</a>")
            }
            if ($f.ReferenceUrl) {
                $remParts.Add("<a href=`"$(& $esc $f.ReferenceUrl)`" target=`"_blank`" rel=`"noopener`" style=`"color:var(--gold)`">&#9888; Why it's unsafe &#x2197;</a>")
            }
            $remLink = if ($remParts.Count -gt 0) { $remParts -join '<br>' } else { '&mdash;' }

            [void]$html.Append(@"
  <tr>
    <td><code>$(& $esc $f.CheckId)</code></td>
    <td>$(& $esc $f.CheckName)</td>
    <td>$(& $esc $f.Category)</td>
    <td><span class="badge badge-$sevClass">$($f.Severity)</span></td>
    <td>$(& $esc $f.CurrentValue)</td>
    <td>$remLink</td>
  </tr>
"@)
        }
        [void]$html.Append('</table>')
    }

    # ═══════════════════════════════════════════════════════════════
    # PER-CATEGORY DETAIL SECTIONS
    # ═══════════════════════════════════════════════════════════════
    [void]$html.Append('<h2>Detailed Findings by Category</h2>')

    $categories = $Findings | Group-Object -Property Category | Sort-Object Name

    foreach ($catGroup in $categories) {
        $catName     = $catGroup.Name
        $catFindings = @($catGroup.Group | Sort-Object {
            switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
        }, CheckId)

        $catHasFailures = @($catFindings | Where-Object Status -eq 'FAIL').Count -gt 0
        $openAttr = if ($catHasFailures) { ' open' } else { '' }

        $catInfo = $CategoryScores[$catName]
        $catScoreStr = if ($catInfo) { " &mdash; Score: $($catInfo.Score)/100" } else { '' }

        [void]$html.Append("<details class=`"cat-detail`"$openAttr>")
        [void]$html.Append("<summary>$(& $esc $catName)$catScoreStr <span style=`"color:var(--dim);font-weight:400;font-size:0.85em;text-transform:none`">($($catFindings.Count) checks)</span></summary>")
        [void]$html.Append('<div class="detail-body">')
        [void]$html.Append(@'
<table>
  <tr>
    <th>Check ID</th><th>Name</th><th>Severity</th><th>Status</th>
    <th>Current Value</th><th>Recommended Value</th><th>Remediation Steps</th>
  </tr>
'@)
        foreach ($f in $catFindings) {
            $isAccepted  = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }
            $sevClass    = $f.Severity.ToLower()

            $remedSteps = if ($f.RemediationSteps) {
                "<div class=`"remediation-cell`">$(& $esc $f.RemediationSteps)</div>"
            } else { '&mdash;' }

            [void]$html.Append(@"
  <tr>
    <td><code>$(& $esc $f.CheckId)</code></td>
    <td>$(& $esc $f.CheckName)</td>
    <td><span class="badge badge-$sevClass">$($f.Severity)</span></td>
    <td><span class="badge badge-$statusClass">$statusLabel</span></td>
    <td>$(& $esc $f.CurrentValue)</td>
    <td>$(& $esc $f.RecommendedValue)</td>
    <td>$remedSteps</td>
  </tr>
"@)

            # --- Extra row: affected accounts + why-unsafe article + admin console deep-link ---
            $affectedHtml = & $renderAffected $f.Details
            $linkParts = [System.Collections.Generic.List[string]]::new()
            if ($f.Status -in @('FAIL', 'WARN', 'ERROR')) {
                if ($f.ReferenceUrl) {
                    $whyTitle = if ($f.ReferenceTitle) { $f.ReferenceTitle } else { 'Why this is unsafe' }
                    $linkParts.Add("<span class=`"why`">&#9888; <a href=`"$(& $esc $f.ReferenceUrl)`" target=`"_blank`" rel=`"noopener`">Why this is unsafe: $(& $esc $whyTitle) &#x2197;</a></span>")
                }
                if ($f.RemediationUrl) {
                    $linkParts.Add("<a class=`"admin-link`" href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">&#x2699; Fix in Admin Console &#x2197;</a>")
                }
            }
            $linksHtml = if ($linkParts.Count -gt 0) { "<div class=`"extra-links`">$($linkParts -join '')</div>" } else { '' }
            if ($affectedHtml -or $linksHtml) {
                [void]$html.Append("<tr class=`"finding-extra`"><td colspan=`"7`"><div class=`"extra-wrap`">$affectedHtml$linksHtml</div></td></tr>")
            }
        }
        [void]$html.Append('</table>')
        [void]$html.Append('</div></details>')
    }

    # ═══════════════════════════════════════════════════════════════
    # COMPLIANCE CROSS-REFERENCE
    # ═══════════════════════════════════════════════════════════════
    $complianceFindings = @($failFindings | Where-Object {
        ($_.Compliance.NistSp80053 -and $_.Compliance.NistSp80053.Count -gt 0) -or
        ($_.Compliance.MitreAttack -and $_.Compliance.MitreAttack.Count -gt 0) -or
        ($_.Compliance.CisBenchmark -and $_.Compliance.CisBenchmark.Count -gt 0)
    } | Sort-Object {
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }, CheckId)

    if ($complianceFindings.Count -gt 0) {
        [void]$html.Append('<h2>Compliance Cross-Reference</h2>')
        [void]$html.Append(@'
<table class="compliance-table">
  <tr>
    <th>Check ID</th><th>Check Name</th><th>Severity</th>
    <th>NIST SP 800-53</th><th>MITRE ATT&amp;CK</th><th>CIS Benchmark</th>
  </tr>
'@)
        foreach ($f in $complianceFindings) {
            $sevClass = $f.Severity.ToLower()

            $nistCodes = if ($f.Compliance.NistSp80053 -and $f.Compliance.NistSp80053.Count -gt 0) {
                ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '&mdash;' }

            $mitreCodes = if ($f.Compliance.MitreAttack -and $f.Compliance.MitreAttack.Count -gt 0) {
                ($f.Compliance.MitreAttack | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '&mdash;' }

            $cisCodes = if ($f.Compliance.CisBenchmark -and $f.Compliance.CisBenchmark.Count -gt 0) {
                ($f.Compliance.CisBenchmark | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '&mdash;' }

            [void]$html.Append(@"
  <tr>
    <td><code>$(& $esc $f.CheckId)</code></td>
    <td>$(& $esc $f.CheckName)</td>
    <td><span class="badge badge-$sevClass">$($f.Severity)</span></td>
    <td>$nistCodes</td>
    <td>$mitreCodes</td>
    <td>$cisCodes</td>
  </tr>
"@)
        }
        [void]$html.Append('</table>')
    }

    # ═══════════════════════════════════════════════════════════════
    # DELTA REPORT
    # ═══════════════════════════════════════════════════════════════
    if ($Delta) {
        [void]$html.Append('<h2>Delta Report &mdash; Changes Since Last Scan</h2>')
        [void]$html.Append('<div class="delta-section">')
        [void]$html.Append('<h3>Score Change</h3>')

        $scoreChange = if ($null -ne $Delta.ScoreChange) { $Delta.ScoreChange } else { 0 }
        $arrowClass = if ($scoreChange -gt 0) { 'delta-arrow-up' }
                      elseif ($scoreChange -lt 0) { 'delta-arrow-down' }
                      else { 'delta-arrow-same' }
        $arrowChar = if ($scoreChange -gt 0) { "&#9650; +$scoreChange" }
                     elseif ($scoreChange -lt 0) { "&#9660; $scoreChange" }
                     else { '&#9654; No change' }
        $prevScore = if ($null -ne $Delta.PreviousScore) { $Delta.PreviousScore } else { '?' }

        [void]$html.Append("<p><strong>Previous Score:</strong> $prevScore &rarr; <strong>Current Score:</strong> $OverallScore <span class=`"$arrowClass`">$arrowChar</span></p>")

        # New failures
        if ($Delta.NewFailures -and $Delta.NewFailures.Count -gt 0) {
            [void]$html.Append("<h4 style=`"color:var(--fail)`">New Failures ($($Delta.NewFailures.Count))</h4>")
            [void]$html.Append('<table><tr><th>Check ID</th><th>Check Name</th><th>Severity</th><th>Category</th></tr>')
            foreach ($nf in $Delta.NewFailures) {
                $nfSev = if ($nf.severity) { $nf.severity } elseif ($nf.Severity) { $nf.Severity } else { '' }
                $nfSevClass = $nfSev.ToLower()
                $nfId   = if ($nf.checkId) { $nf.checkId } elseif ($nf.CheckId) { $nf.CheckId } else { '' }
                $nfName = if ($nf.checkName) { $nf.checkName } elseif ($nf.CheckName) { $nf.CheckName } else { '' }
                $nfCat  = if ($nf.category) { $nf.category } elseif ($nf.Category) { $nf.Category } else { '' }

                [void]$html.Append("<tr><td><code>$(& $esc $nfId)</code></td><td>$(& $esc $nfName)</td><td><span class=`"badge badge-$nfSevClass`">$(& $esc $nfSev)</span></td><td>$(& $esc $nfCat)</td></tr>")
            }
            [void]$html.Append('</table>')
        }

        # Resolved items
        if ($Delta.Resolved -and $Delta.Resolved.Count -gt 0) {
            [void]$html.Append("<h4 style=`"color:var(--pass)`">Resolved ($($Delta.Resolved.Count))</h4>")
            [void]$html.Append('<table><tr><th>Check ID</th><th>Check Name</th><th>Severity</th><th>Category</th></tr>')
            foreach ($res in $Delta.Resolved) {
                $resSev = if ($res.severity) { $res.severity } elseif ($res.Severity) { $res.Severity } else { '' }
                $resSevClass = $resSev.ToLower()
                $resId   = if ($res.checkId) { $res.checkId } elseif ($res.CheckId) { $res.CheckId } else { '' }
                $resName = if ($res.checkName) { $res.checkName } elseif ($res.CheckName) { $res.CheckName } else { '' }
                $resCat  = if ($res.category) { $res.category } elseif ($res.Category) { $res.Category } else { '' }

                [void]$html.Append("<tr><td><code>$(& $esc $resId)</code></td><td>$(& $esc $resName)</td><td><span class=`"badge badge-$resSevClass`">$(& $esc $resSev)</span></td><td>$(& $esc $resCat)</td></tr>")
            }
            [void]$html.Append('</table>')
        }

        if ((-not $Delta.NewFailures -or $Delta.NewFailures.Count -eq 0) -and (-not $Delta.Resolved -or $Delta.Resolved.Count -eq 0)) {
            [void]$html.Append('<p style="color:var(--dim)">No changes in pass/fail status since the previous scan.</p>')
        }

        [void]$html.Append('</div>')
    }

    # ═══════════════════════════════════════════════════════════════
    # FOOTER
    # ═══════════════════════════════════════════════════════════════
    [void]$html.Append(@"
<div style="margin-top: 40px; padding-top: 16px; border-top: 2px solid var(--border);
            color: var(--dim); font-size: 0.8em; text-align: center; letter-spacing: 1px;">
  &#x1F6E1; Guerrilla Fortification Report &nbsp;|&nbsp;
  $timestampStr &nbsp;|&nbsp;
  Generated by Guerrilla v$moduleVersion &nbsp;|&nbsp;
  $totalChecks checks &nbsp;|&nbsp; Score: $OverallScore/100 ($displayLabel)
  <br>By Jim Tyler, Microsoft MVP &nbsp;|&nbsp; <a href="https://github.com/jimrtyler" style="color:var(--dim)">GitHub</a> &nbsp;|&nbsp; <a href="https://linkedin.com/in/jamestyler" style="color:var(--dim)">LinkedIn</a> &nbsp;|&nbsp; <a href="https://youtube.com/@jimrtyler" style="color:var(--dim)">YouTube</a>
</div>
</body>
</html>
"@)

    [System.IO.File]::WriteAllText($FilePath, $html.ToString(), [System.Text.Encoding]::UTF8)
}
