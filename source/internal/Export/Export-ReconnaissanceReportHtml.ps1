# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ReconnaissanceReportHtml {
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

        [string]$DomainName = '',
        [hashtable]$Delta,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional',

        [hashtable]$Branding,

        # When a BloodHound OpenGraph export was written, its path — surfaced as a report callout.
        [string]$BloodHoundPath
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

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

    $domainTitle = if ($DomainName) { " - $(& $esc $DomainName)" } else { '' }

    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guerrilla AD Reconnaissance Report$domainTitle - $timestampStr</title>
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
  .subtitle { color: var(--dim); font-size: 0.85em; margin-bottom: 24px; }
  .score-panel {
    background: var(--surface); border: 2px solid var(--border);
    border-radius: 4px; padding: 24px 32px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 32px;
  }
  .score-ring { width: 120px; height: 120px; position: relative; flex-shrink: 0; }
  .score-ring svg { transform: rotate(-90deg); }
  .score-ring .value {
    position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; font-size: 2em; font-weight: 700;
  }
  .score-detail .label {
    font-size: 1.3em; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
  }
  .score-detail .desc { color: var(--dim); font-size: 0.85em; margin-top: 4px; }
  .exec-summary {
    background: var(--surface-alt); border: 1px solid var(--border); border-left: 4px solid var(--amber);
    border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px;
  }
  .exec-summary h3 { margin-top: 0; color: var(--parchment); }
  .exec-summary p { margin: 8px 0; font-size: 0.9em; }
  .stat-grid { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 14px 20px; text-align: center;
    flex: 1 1 140px; min-width: 120px;
  }
  .stat-card .value { font-size: 1.8em; font-weight: 700; }
  .stat-card .label { color: var(--dim); font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }
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
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 2px;
    font-size: 0.75em; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; font-family: inherit; white-space: nowrap;
  }
  .badge-pass { background: var(--pass); color: #d4c9a8; }
  .badge-fail { background: var(--fail); color: #fff; }
  .badge-accepted { background: var(--dim); color: var(--text); font-style: italic; }
  .badge-warn { background: var(--warn); color: #1a1f16; }
  .badge-skip { background: var(--skip); color: #d4c9a8; }
  .badge-critical { background: var(--critical); color: #fff; }
  .badge-high { background: var(--high); color: #1a1f16; }
  .badge-medium { background: var(--medium); color: #1a1f16; }
  .badge-low { background: var(--low); color: #1a1f16; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 0.85em; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
  th {
    background: var(--surface); font-weight: 700; font-size: 0.8em; color: var(--dim);
    text-transform: uppercase; letter-spacing: 1px; position: sticky; top: 0;
  }
  tr:nth-child(even) { background: rgba(45, 53, 38, 0.4); }
  tr:hover { background: rgba(168, 181, 139, 0.08); }
  td { vertical-align: top; }
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
  .compliance-table td code {
    display: inline-block; padding: 1px 5px; border-radius: 2px;
    font-size: 0.85em; margin: 1px 2px; background: rgba(168, 181, 139, 0.1);
    border: 1px solid var(--border);
  }
  /* Affected entities (bulleted detail row beneath a FAIL/WARN finding) */
  tr.finding-extra td {
    background: rgba(199, 92, 46, 0.06); border-left: 3px solid var(--amber);
    padding: 4px 10px 12px 14px;
  }
  tr.finding-extra:hover td { background: rgba(199, 92, 46, 0.06); }
  .affected { margin-top: 4px; font-size: 0.85em; }
  .affected-label { color: var(--amber); font-weight: 600; }
  .affected-items { color: var(--text); margin: 4px 0 0 0; padding-left: 20px; }
  .affected-items li { word-break: break-word; margin: 1px 0; }
  .affected-items li.more { list-style: none; margin-left: -20px; font-style: italic; opacity: .7; color: var(--dim); }
  .delta-section {
    background: var(--surface-alt); border: 1px solid var(--border); border-left: 4px solid var(--gold);
    border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px;
  }
  .delta-section h3 { margin-top: 0; color: var(--parchment); }
  .delta-arrow-up { color: var(--pass); font-weight: 700; }
  .delta-arrow-down { color: var(--fail); font-weight: 700; }
  code { font-family: inherit; font-size: 0.9em; color: var(--olive); }
  a { color: var(--gold); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--dim); font-size: 0.8em; }
</style>
</head>
<body>
"@)

    # ═══ HEADER ═══
    [void]$html.Append(@"
$($brand.Banner)
$($brand.Header)
<h1>AD Reconnaissance Report</h1>
<div class="subtitle">Domain: $(& $esc $DomainName) &mdash; Generated: $timestampStr</div>
"@)

    # ═══ SCORE PANEL ═══
    $circumference = 2 * [Math]::PI * 50
    $dashoffset = $circumference * (1 - ($OverallScore / 100))

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashoffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value" style="color:$scoreColor">$OverallScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$displayLabel</div>
    <div class="desc">Active Directory security posture score (0-100)</div>
    <div class="desc">$totalChecks checks evaluated &mdash; $passCount passed, $failCount failed, $warnCount warnings, $skipCount skipped</div>
  </div>
</div>
"@)

    # ═══ EXECUTIVE SUMMARY ═══
    $verdict = switch ($true) {
        ($OverallScore -ge 90) { 'The Active Directory environment demonstrates strong security posture with minimal findings.'; break }
        ($OverallScore -ge 75) { 'The AD environment has good security posture with some areas requiring attention.'; break }
        ($OverallScore -ge 60) { 'The AD environment has fair security posture. Several important findings require remediation.'; break }
        ($OverallScore -ge 40) { 'The AD environment has poor security posture. Multiple critical and high-severity findings need immediate attention.'; break }
        default { 'The AD environment has critical security deficiencies. Immediate remediation is required to prevent compromise.' }
    }

    [void]$html.Append(@"
<div class="exec-summary">
  <h3>Executive Summary</h3>
  <p>$(& $esc $verdict)</p>
  <p>Critical: <strong>$critCount</strong> &mdash; High: <strong>$highCount</strong> &mdash;
     Medium: <strong>$medCount</strong> &mdash; Low: <strong>$lowCount</strong></p>
</div>
"@)

    # ═══ SECURITY MATURITY (CMMI 1-5) — shared section ═══
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc))

    # ═══ INDICATORS OF EXPOSURE — shared ranked exposure view ═══
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc))

    # ═══ ATTACK-PATH CARTOGRAPHY (visual map) + ATTACK PATHS list — shared sections ═══
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $Findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $Findings -Esc $esc))

    # ═══ BLOODHOUND EXPORT CALLOUT ═══
    if ($BloodHoundPath) {
        [void]$html.Append(@"
<h2>BloodHound Export</h2>
<div class="exec-summary" style="border-left-color:var(--gold)">
  <p>An OpenGraph export of the collected AD attack graph was written to <code>$(& $esc $BloodHoundPath)</code>.</p>
  <p>Import in BloodHound CE: <strong>Administration &rarr; File Ingest</strong> &rarr; upload the file, then run the built-in pathfinding queries. Nodes are SID-keyed (they overlay native SharpHound data) and edges use native BloodHound kinds.</p>
</div>
"@)
    }

    # ═══ STAT CARDS ═══
    [void]$html.Append('<div class="stat-grid">')
    $statCards = @(
        @{ Value = $totalChecks; Label = 'Total Checks'; Color = 'var(--parchment)' }
        @{ Value = $passCount;   Label = 'Passed';       Color = 'var(--pass)' }
        @{ Value = $critCount;   Label = 'Critical';     Color = 'var(--critical)' }
        @{ Value = $highCount;   Label = 'High';         Color = 'var(--high)' }
        @{ Value = $medCount;    Label = 'Medium';        Color = 'var(--medium)' }
        @{ Value = $lowCount;    Label = 'Low';           Color = 'var(--low)' }
    )
    foreach ($card in $statCards) {
        [void]$html.Append(@"
  <div class="stat-card">
    <div class="value" style="color:$($card.Color)">$($card.Value)</div>
    <div class="label">$($card.Label)</div>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ DELTA SECTION ═══
    if ($Delta) {
        $arrow = if ($Delta.ScoreChange -gt 0) { "<span class='delta-arrow-up'>&#9650; +$($Delta.ScoreChange)</span>" }
                 elseif ($Delta.ScoreChange -lt 0) { "<span class='delta-arrow-down'>&#9660; $($Delta.ScoreChange)</span>" }
                 else { "<span style='color:var(--dim)'>&#9654; No change</span>" }
        $prevDate = if ($Delta.PreviousScanTimestamp) {
            $ts = $Delta.PreviousScanTimestamp
            if ($ts -is [datetime]) {
                $ts.ToString('yyyy-MM-ddTHH:mm:ss')
            } else {
                $s = "$ts"
                if ($s.Length -ge 19) { $s.Substring(0, 19) } else { $s }
            }
        } else { 'Unknown' }
        [void]$html.Append(@"
<div class="delta-section">
  <h3>Change Since Previous Scan</h3>
  <p>Previous scan: $prevDate &mdash; Score change: $arrow (was $($Delta.PreviousScore))</p>
"@)
        if ($Delta.NewFailures.Count -gt 0) {
            [void]$html.Append("<p style='color:var(--fail)'>New failures: $($Delta.NewFailures.Count)</p><ul style='margin:4px 0 8px 20px;font-size:0.9em'>")
            foreach ($nf in $Delta.NewFailures | Select-Object -First 10) {
                [void]$html.Append("<li><span class='badge badge-$($nf.Severity.ToLower())'>$($nf.Severity)</span> $(& $esc $nf.CheckId) - $(& $esc $nf.CheckName)</li>")
            }
            [void]$html.Append('</ul>')
        }
        if ($Delta.Resolved.Count -gt 0) {
            [void]$html.Append("<p style='color:var(--pass)'>Resolved: $($Delta.Resolved.Count)</p><ul style='margin:4px 0 8px 20px;font-size:0.9em'>")
            foreach ($r in $Delta.Resolved | Select-Object -First 10) {
                [void]$html.Append("<li>$(& $esc $r.CheckId) - $(& $esc $r.CheckName)</li>")
            }
            [void]$html.Append('</ul>')
        }
        [void]$html.Append('</div>')
    }

    # ═══ CATEGORY SCORES ═══
    [void]$html.Append('<h2>Category Breakdown</h2><div class="category-grid">')
    foreach ($cat in ($CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $cs = $cat.Value.Score
        $cc = switch ($true) {
            ($cs -ge 90) { 'var(--sage)'; break }
            ($cs -ge 75) { 'var(--olive)'; break }
            ($cs -ge 60) { 'var(--gold)'; break }
            ($cs -ge 40) { 'var(--amber)'; break }
            default { 'var(--deep-orange)' }
        }
        [void]$html.Append(@"
  <div class="cat-card">
    <div class="cat-header">
      <div class="cat-name">$(& $esc $cat.Key)</div>
      <div class="cat-score" style="color:$cc">$cs</div>
    </div>
    <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${cs}%;background:$cc"></div></div>
    <div class="cat-counts">
      <span style="color:var(--pass)">Pass: $($cat.Value.Pass)</span>
      <span style="color:var(--fail)">Fail: $($cat.Value.Fail)</span>
      <span style="color:var(--warn)">Warn: $($cat.Value.Warn)</span>
      <span style="color:var(--skip)">Skip: $($cat.Value.Skip)</span>
    </div>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ PRIORITY FINDINGS ═══
    $priorityFindings = @($Findings | Where-Object { $_.Status -eq 'FAIL' } |
        Sort-Object @{Expression={@{Critical=0;High=1;Medium=2;Low=3;Info=4}[$_.Severity] ?? 5}},CheckId)

    # ═══ INTERACTIVE FILTER BAR (live status/severity/search over the findings tables below) ═══
    [void]$html.Append((Get-GuerrillaFindingsFilterHtml))

    if ($priorityFindings.Count -gt 0) {
        [void]$html.Append(@"
<h2>Findings by Priority</h2>
<table class="priority-table">
  <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Category</th><th>Check</th><th>Finding</th><th>Remediation</th></tr></thead>
  <tbody>
"@)
        foreach ($f in $priorityFindings) {
            $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $sevClass = $f.Severity.ToLower()
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }
            $remediation = if ($f.RemediationSteps) { $f.RemediationSteps } else { $f.RecommendedValue }
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            [void]$html.Append(@"
    <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td><span class="badge badge-$sevClass">$(& $esc $f.Severity)</span></td>
      <td><span class="badge badge-$statusClass">$(& $esc $statusLabel)</span></td>
      <td>$(& $esc $f.Category)</td>
      <td>$(& $esc $f.CheckName)</td>
      <td>$(& $esc $f.CurrentValue)</td>
      <td><small>$(& $esc $remediation)</small></td>
    </tr>
"@)
            if ($f.Status -in @('FAIL', 'WARN')) {
                $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
                if ($affectedHtml) {
                    [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`">$affectedHtml</td></tr>")
                }
            }
        }
        [void]$html.Append('</tbody></table>')
    }

    # ═══ DETAILED CATEGORY SECTIONS ═══
    [void]$html.Append('<h2>Detailed Findings by Category</h2>')

    $categoryGroups = $Findings | Group-Object -Property Category | Sort-Object Name
    foreach ($group in $categoryGroups) {
        $catFindings = @($group.Group | Sort-Object @{Expression={@{Critical=0;High=1;Medium=2;Low=3;Info=4}[$_.Severity] ?? 5}},CheckId)
        $catPass = @($catFindings | Where-Object Status -eq 'PASS').Count
        $catFail = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $catWarn = @($catFindings | Where-Object Status -eq 'WARN').Count

        [void]$html.Append(@"
<details class="cat-detail">
  <summary>$(& $esc $group.Name) &mdash; $($catFindings.Count) checks (P:$catPass F:$catFail W:$catWarn)</summary>
  <div class="detail-body">
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Check</th><th>Current Value</th><th>Recommended</th><th>Remediation</th></tr></thead>
      <tbody>
"@)
        foreach ($f in $catFindings) {
            $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $sevClass = $f.Severity.ToLower()
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            [void]$html.Append(@"
        <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
          <td><code>$(& $esc $f.CheckId)</code></td>
          <td><span class="badge badge-$sevClass">$(& $esc $f.Severity)</span></td>
          <td><span class="badge badge-$statusClass">$(& $esc $statusLabel)</span></td>
          <td>$(& $esc $f.CheckName)<br><small style="color:var(--dim)">$(& $esc $f.Description)</small></td>
          <td>$(& $esc $f.CurrentValue)</td>
          <td>$(& $esc $f.RecommendedValue)</td>
          <td><small>$(& $esc $f.RemediationSteps)</small></td>
        </tr>
"@)
            if ($f.Status -in @('FAIL', 'WARN')) {
                $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
                if ($affectedHtml) {
                    [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`">$affectedHtml</td></tr>")
                }
            }
        }
        [void]$html.Append('</tbody></table></div></details>')
    }

    # ═══ COMPLIANCE MAPPING ═══
    $findingsWithCompliance = @($Findings | Where-Object {
        $_.Compliance.MitreAttack.Count -gt 0 -or $_.Compliance.NistSp80053.Count -gt 0 -or
        ($_.Compliance.Anssi ?? @()).Count -gt 0 -or ($_.Compliance.CisAd ?? @()).Count -gt 0
    })
    if ($findingsWithCompliance.Count -gt 0) {
        [void]$html.Append(@"
<h2>Compliance Mapping</h2>
<table class="compliance-table">
  <thead><tr><th>Check ID</th><th>Status</th><th>MITRE ATT&amp;CK</th><th>NIST SP 800-53</th><th>CIS AD</th><th>ANSSI</th></tr></thead>
  <tbody>
"@)
        foreach ($f in ($findingsWithCompliance | Where-Object Status -eq 'FAIL' | Select-Object -First 50)) {
            $mitre = ($f.Compliance.MitreAttack | ForEach-Object { "<code>$_</code>" }) -join ' '
            $nist = ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$_</code>" }) -join ' '
            $cisAd = (($f.Compliance.CisAd ?? @()) | ForEach-Object { "<code>$_</code>" }) -join ' '
            $anssi = (($f.Compliance.Anssi ?? @()) | ForEach-Object { "<code>$_</code>" }) -join ' '
            $statusClass = $f.Status.ToLower()
            [void]$html.Append(@"
    <tr>
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td><span class="badge badge-$statusClass">$(& $esc $f.Status)</span></td>
      <td>$mitre</td><td>$nist</td><td>$cisAd</td><td>$anssi</td>
    </tr>
"@)
        }
        [void]$html.Append('</tbody></table>')
    }

    # ═══ FOOTER ═══
    [void]$html.Append(@"
<div class="footer">
  <p>Generated by Guerrilla v$moduleVersion &mdash; AD Reconnaissance Module</p>
  <p>Report generated: $timestampStr</p>
  <p>By Jim Tyler, Microsoft MVP &mdash; <a href="https://github.com/jimrtyler">GitHub</a> | <a href="https://linkedin.com/in/jamestyler">LinkedIn</a> | <a href="https://youtube.com/@jimrtyler">YouTube</a></p>
</div>
</body></html>
"@)

    Set-Content -Path $FilePath -Value $html.ToString() -Encoding UTF8
}
