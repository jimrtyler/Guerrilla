# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-CampaignReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,  # Guerrilla.CampaignResult

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional',

        [hashtable]$Branding
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $findings      = $Result.Findings
    $overallScore  = $Result.OverallScore
    $scoreLabel    = $Result.ScoreLabel
    $theaterScores = $Result.TheaterScores
    $theaters      = $Result.Theaters
    $scanStart     = $Result.ScanStart
    $duration      = $Result.Duration
    $scanId        = $Result.ScanId

    $timestampStr = $scanStart.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    $themeStyle   = Get-GuerrillaReportThemeStyleBlock -Style $Style
    $displayLabel = Resolve-GuerrillaReportScoreLabel -Score $overallScore -Style $Style -Fallback $scoreLabel
    $brand        = Get-GuerrillaReportBrandingHtml -Branding $Branding
    $durationStr  = if ($duration.TotalMinutes -ge 1) {
        '{0}m {1}s' -f [int][Math]::Floor($duration.TotalMinutes), $duration.Seconds
    } else {
        '{0}s' -f [int]$duration.TotalSeconds
    }

    # --- Counts ---
    $totalChecks = $findings.Count
    $passCount   = @($findings | Where-Object Status -eq 'PASS').Count
    $failCount   = @($findings | Where-Object Status -eq 'FAIL').Count
    $warnCount   = @($findings | Where-Object Status -eq 'WARN').Count
    $skipCount   = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($findings | Where-Object Status -eq 'FAIL')
    $critCount    = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount    = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount     = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount     = @($failFindings | Where-Object Severity -eq 'Low').Count

    # --- Module version ---
    $moduleVersion = '2.0.0'
    try {
        $manifestPath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'Guerrilla.psd1'
        if (Test-Path $manifestPath) {
            $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction SilentlyContinue
            if ($manifest.ModuleVersion) { $moduleVersion = $manifest.ModuleVersion }
        }
    } catch { }

    # --- Score color helper ---
    $getScoreColor = {
        param([int]$s)
        switch ($true) {
            ($s -ge 90) { 'var(--sage)';        break }
            ($s -ge 75) { 'var(--olive)';       break }
            ($s -ge 60) { 'var(--gold)';        break }
            ($s -ge 40) { 'var(--amber)';       break }
            ($s -ge 20) { 'var(--deep-orange)'; break }
            default     { 'var(--dark-red)' }
        }
    }

    $scoreColor = & $getScoreColor $overallScore

    # --- Theater display name mapping ---
    $theaterDisplayNames = @{
        'Workspace' = 'Google Workspace'
        'AD'        = 'Active Directory'
        'Cloud'     = 'Microsoft Cloud'
    }

    $html = [System.Text.StringBuilder]::new(131072)

    # =================================================================
    # HEAD
    # =================================================================
    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guerrilla Campaign Report - $timestampStr</title>
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
  .score-stats {
    display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px;
  }
  .score-stats .ss-item { font-size: 0.85em; }
  .score-stats .ss-val { font-weight: 700; font-size: 1.1em; }

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

  /* Theater cards */
  .theater-grid {
    display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px;
  }
  .theater-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 20px; flex: 1 1 280px; min-width: 260px;
  }
  .theater-card .theater-header {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;
  }
  .theater-card .theater-name {
    font-size: 1em; font-weight: 700; color: var(--parchment); text-transform: uppercase; letter-spacing: 1px;
  }
  .theater-card .theater-score { font-size: 1.8em; font-weight: 700; }
  .theater-card .theater-label { font-size: 0.8em; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
  .theater-card .theater-bar-bg {
    height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin: 8px 0;
  }
  .theater-card .theater-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
  .theater-card .theater-counts { font-size: 0.8em; color: var(--dim); display: flex; gap: 10px; flex-wrap: wrap; }
  .theater-card .theater-counts span { white-space: nowrap; }

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
  .badge-warn { background: var(--warn); color: #1a1f16; }
  .badge-skip { background: var(--skip); color: #d4c9a8; }
  .badge-error { background: var(--skip); color: #d4c9a8; }
  .badge-critical { background: var(--critical); color: #fff; }
  .badge-high { background: var(--high); color: #1a1f16; }
  .badge-medium { background: var(--medium); color: #1a1f16; }
  .badge-low { background: var(--low); color: #1a1f16; }
  .badge-theater {
    display: inline-block; padding: 2px 8px; border-radius: 2px;
    font-size: 0.72em; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace;
    white-space: nowrap; border: 1px solid var(--border);
  }
  .badge-workspace { background: rgba(107, 155, 107, 0.15); color: var(--sage); border-color: var(--sage); }
  .badge-ad { background: rgba(201, 168, 76, 0.15); color: var(--gold); border-color: var(--gold); }
  .badge-cloud { background: rgba(168, 181, 139, 0.15); color: var(--olive); border-color: var(--olive); }

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

  .priority-table tr td:first-child { font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace; font-size: 0.85em; }

  /* Collapsible theater sections */
  details.theater-detail {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; margin-bottom: 12px;
  }
  details.theater-detail summary {
    padding: 12px 16px; cursor: pointer; list-style: none;
    display: flex; align-items: center; gap: 12px;
    font-weight: 700; color: var(--parchment); text-transform: uppercase; letter-spacing: 1px;
  }
  details.theater-detail summary::-webkit-details-marker { display: none; }
  details.theater-detail summary::before {
    content: '\25b6'; font-size: 0.7em; color: var(--dim); transition: transform 0.2s;
  }
  details.theater-detail[open] summary::before { transform: rotate(90deg); }
  details.theater-detail .detail-body { padding: 0 16px 16px; }

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

  /* Finding detail rows */
  .finding-detail-row { display: none; }
  .finding-detail-row.expanded { display: table-row; }
  .finding-detail-row td {
    padding: 16px 20px; background: var(--surface-alt);
    border-left: 3px solid var(--border);
  }
  .finding-detail-content {
    display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
  }
  .finding-detail-content .fd-block { margin-bottom: 8px; }
  .finding-detail-content .fd-label {
    font-size: 0.8em; color: var(--dim); text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 4px;
  }
  .finding-detail-content .fd-value { font-size: 0.9em; }
  .finding-detail-content .fd-full { grid-column: 1 / -1; }

  /* Affected entities (bulleted) */
  .affected { margin-top: 4px; }
  .affected-label { color: var(--amber); font-weight: 600; }
  .affected-items { margin: 4px 0 0 0; padding-left: 20px; }
  .affected-items li { word-break: break-word; margin: 1px 0; }
  .affected-items li.more { list-style: none; margin-left: -20px; font-style: italic; opacity: .7; color: var(--dim); }

  /* Filter bar */
  .filter-bar {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; align-items: center;
  }
  .filter-bar .filter-group {
    display: flex; gap: 4px; align-items: center;
    border: 1px solid var(--border); border-radius: 4px; padding: 4px 8px;
    background: var(--surface);
  }
  .filter-bar .filter-label {
    font-size: 0.75em; color: var(--dim); text-transform: uppercase; letter-spacing: 1px;
    margin-right: 4px;
  }
  .filter-btn {
    background: transparent; border: 1px solid var(--border); border-radius: 2px;
    padding: 3px 10px; color: var(--text); cursor: pointer;
    font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace;
    font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px;
    transition: background 0.15s, border-color 0.15s;
  }
  .filter-btn:hover { background: rgba(168, 181, 139, 0.1); }
  .filter-btn.active { background: rgba(168, 181, 139, 0.2); border-color: var(--olive); color: var(--parchment); }
  .filter-count {
    font-size: 0.8em; color: var(--dim); margin-left: 12px; white-space: nowrap;
  }

  /* Compliance table */
  .compliance-table td code {
    display: inline-block; padding: 1px 5px; border-radius: 2px;
    font-size: 0.85em; margin: 1px 2px; background: rgba(168, 181, 139, 0.1);
    border: 1px solid var(--border);
  }

  .clickable-row { cursor: pointer; }
  .clickable-row:hover { background: rgba(168, 181, 139, 0.12) !important; }

  code { font-family: 'Fira Code', 'JetBrains Mono', Consolas, monospace; font-size: 0.9em; color: var(--olive); }
  a { color: var(--gold); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .remediation-cell { max-width: 300px; font-size: 0.85em; }

  /* Print styles */
  @media print {
    body { background: #fff; color: #000; }
    .score-panel, .stat-card, .cat-card, .cat-detail, .theater-card, .theater-detail,
    .filter-bar { border-color: #ccc; background: #f9f9f9; }
    .filter-bar { display: none; }
    details.cat-detail, details.theater-detail { break-inside: avoid; }
    .finding-detail-row { display: table-row !important; }
    a { color: #336; }
  }
</style>
</head>
<body>
"@)

    # =================================================================
    # HEADER
    # =================================================================
    $theaterList = ($theaters | ForEach-Object {
        $displayName = $theaterDisplayNames[$_]
        if (-not $displayName) { $displayName = $_ }
        & $esc $displayName
    }) -join ', '

    [void]$html.Append(@"
$($brand.Banner)
$($brand.Header)
<h1>&#x2694; Campaign Report</h1>
<div class="subtitle">
  Unified Security Posture Assessment &mdash; Generated $timestampStr &mdash;
  $totalChecks checks across $($theaters.Count) theaters ($theaterList)<br>
  Scan ID: $(& $esc $scanId) &mdash; Duration: $durationStr &mdash;
  Guerrilla v$moduleVersion
</div>
"@)

    # =================================================================
    # SCORE PANEL (SVG ring)
    # =================================================================
    $circumference = [Math]::Round(2 * [Math]::PI * 52, 1)  # radius 52
    $dashOffset    = [Math]::Round($circumference - ($circumference * $overallScore / 100), 1)

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="$scoreColor" stroke-width="8"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashOffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value" style="color:$scoreColor">$overallScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$(& $esc $displayLabel)</div>
    <div class="desc">Campaign Score (0&ndash;100). Weighted assessment of $totalChecks checks across $($theaters.Count) theaters.</div>
    <div class="score-stats">
      <span class="ss-item"><span class="ss-val" style="color:var(--pass)">$passCount</span> Passed</span>
      <span class="ss-item"><span class="ss-val" style="color:var(--fail)">$failCount</span> Failed</span>
      <span class="ss-item"><span class="ss-val" style="color:var(--warn)">$warnCount</span> Warnings</span>
      <span class="ss-item"><span class="ss-val" style="color:var(--skip)">$skipCount</span> Skipped</span>
    </div>
  </div>
</div>
"@)

    # =================================================================
    # STAT CARDS
    # =================================================================
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

    # =================================================================
    # SECURITY MATURITY + ATTACK PATHS (shared sections)
    # Maturity spans all theaters; attack paths only render if an AD theater was scanned.
    # =================================================================
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $findings -Esc $esc -OmitIfAbsent))

    # =================================================================
    # THEATER SUMMARY CARDS
    # =================================================================
    [void]$html.Append('<h2>Theater Summary</h2>')
    [void]$html.Append('<div class="theater-grid">')

    foreach ($theaterKey in ($theaterScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $tName  = $theaterKey.Key
        $tData  = $theaterKey.Value
        $tScore = $tData.Score
        $tColor = & $getScoreColor $tScore
        $tLabel = Resolve-GuerrillaReportScoreLabel -Score $tScore -Style $Style -Fallback ([string]$tData.ScoreLabel)

        $tPassCount = if ($null -ne $tData.PassCount) { $tData.PassCount } else { 0 }
        $tFailCount = if ($null -ne $tData.FailCount) { $tData.FailCount } else { 0 }
        $tWarnCount = if ($null -ne $tData.WarnCount) { $tData.WarnCount } else { 0 }
        $tSkipCount = if ($null -ne $tData.SkipCount) { $tData.SkipCount } else { 0 }
        $tFindingCount = if ($null -ne $tData.FindingCount) { $tData.FindingCount } else { 0 }

        [void]$html.Append(@"
<div class="theater-card">
  <div class="theater-header">
    <div>
      <span class="theater-name">$(& $esc $tName)</span>
      <div class="theater-label">$(& $esc $tLabel) &mdash; $tFindingCount checks</div>
    </div>
    <span class="theater-score" style="color:$tColor">$tScore</span>
  </div>
  <div class="theater-bar-bg"><div class="theater-bar-fill" style="width:${tScore}%;background:$tColor"></div></div>
  <div class="theater-counts">
    <span style="color:var(--pass)">Pass: $tPassCount</span>
    <span style="color:var(--fail)">Fail: $tFailCount</span>
    <span style="color:var(--warn)">Warn: $tWarnCount</span>
    <span style="color:var(--skip)">Skip: $tSkipCount</span>
  </div>
</div>
"@)
    }
    [void]$html.Append('</div>')

    # =================================================================
    # CATEGORY SCORE GRID (grouped by theater)
    # =================================================================
    [void]$html.Append('<h2>Category Scores by Theater</h2>')

    foreach ($theaterKey in ($theaterScores.GetEnumerator() | Sort-Object Key)) {
        $tName = $theaterKey.Key
        $tData = $theaterKey.Value
        $tCategoryScores = $tData.CategoryScores

        if (-not $tCategoryScores -or $tCategoryScores.Count -eq 0) { continue }

        $tHasFailures = $false
        foreach ($cs in $tCategoryScores.Values) {
            if ($cs.Fail -and $cs.Fail -gt 0) { $tHasFailures = $true; break }
        }
        $openAttr = if ($tHasFailures) { ' open' } else { '' }

        [void]$html.Append("<details class=`"theater-detail`"$openAttr>")
        [void]$html.Append("<summary>$(& $esc $tName) <span style=`"color:var(--dim);font-weight:400;font-size:0.85em;text-transform:none`">($($tCategoryScores.Count) categories)</span></summary>")
        [void]$html.Append('<div class="detail-body">')
        [void]$html.Append('<div class="category-grid">')

        foreach ($cat in ($tCategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
            $catScore = $cat.Value.Score
            $catColor = & $getScoreColor $catScore
            $catPass  = if ($null -ne $cat.Value.Pass) { $cat.Value.Pass } else { 0 }
            $catFail  = if ($null -ne $cat.Value.Fail) { $cat.Value.Fail } else { 0 }
            $catWarn  = if ($null -ne $cat.Value.Warn) { $cat.Value.Warn } else { 0 }

            [void]$html.Append(@"
<div class="cat-card">
  <div class="cat-header">
    <span class="cat-name">$(& $esc $cat.Key)</span>
    <span class="cat-score" style="color:$catColor">$catScore</span>
  </div>
  <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${catScore}%;background:$catColor"></div></div>
  <div class="cat-counts">
    <span style="color:var(--pass)">Pass: $catPass</span>
    <span style="color:var(--fail)">Fail: $catFail</span>
    <span style="color:var(--warn)">Warn: $catWarn</span>
  </div>
</div>
"@)
        }
        [void]$html.Append('</div>') # category-grid
        [void]$html.Append('</div></details>')
    }

    # =================================================================
    # FINDINGS TABLE (interactive with filters)
    # =================================================================
    [void]$html.Append('<h2>All Findings</h2>')

    # --- Filter bar ---
    [void]$html.Append('<div class="filter-bar" id="filterBar">')

    # Theater filter group
    [void]$html.Append('<div class="filter-group"><span class="filter-label">Theater:</span>')
    [void]$html.Append('<button class="filter-btn active" data-filter-type="theater" data-filter-value="all" onclick="toggleFilter(this)">All</button>')
    foreach ($theaterKey in ($theaterScores.GetEnumerator() | Sort-Object Key)) {
        $tName = $theaterKey.Key
        $tSlug = ($tName -replace '[^a-zA-Z0-9]', '-').ToLower()
        [void]$html.Append("<button class=`"filter-btn`" data-filter-type=`"theater`" data-filter-value=`"$(& $esc $tSlug)`" onclick=`"toggleFilter(this)`">$(& $esc $tName)</button>")
    }
    [void]$html.Append('</div>')

    # Status filter group
    [void]$html.Append('<div class="filter-group"><span class="filter-label">Status:</span>')
    [void]$html.Append('<button class="filter-btn active" data-filter-type="status" data-filter-value="all" onclick="toggleFilter(this)">All</button>')
    foreach ($statusVal in @('PASS', 'FAIL', 'WARN', 'SKIP')) {
        [void]$html.Append("<button class=`"filter-btn`" data-filter-type=`"status`" data-filter-value=`"$statusVal`" onclick=`"toggleFilter(this)`">$statusVal</button>")
    }
    [void]$html.Append('</div>')

    # Severity filter group
    [void]$html.Append('<div class="filter-group"><span class="filter-label">Severity:</span>')
    [void]$html.Append('<button class="filter-btn active" data-filter-type="severity" data-filter-value="all" onclick="toggleFilter(this)">All</button>')
    foreach ($sevVal in @('Critical', 'High', 'Medium', 'Low')) {
        [void]$html.Append("<button class=`"filter-btn`" data-filter-type=`"severity`" data-filter-value=`"$sevVal`" onclick=`"toggleFilter(this)`">$sevVal</button>")
    }
    [void]$html.Append('</div>')

    [void]$html.Append('<span class="filter-count" id="filterCount">Showing all findings</span>')
    [void]$html.Append('</div>') # filter-bar

    # --- Findings table ---
    [void]$html.Append(@'
<table id="findingsTable">
  <thead>
  <tr>
    <th>Theater</th><th>Check ID</th><th>Check Name</th><th>Category</th>
    <th>Severity</th><th>Status</th><th>Current Value</th>
  </tr>
  </thead>
  <tbody>
'@)

    $sortedFindings = @($findings | Sort-Object {
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }, {
        switch ($_.Status) { 'FAIL' { 0 } 'WARN' { 1 } 'PASS' { 2 } 'SKIP' { 3 } default { 4 } }
    }, CheckId)

    $findingIdx = 0
    foreach ($f in $sortedFindings) {
        $statusClass = $f.Status.ToLower()
        $sevClass    = $f.Severity.ToLower()
        $theater     = if ($f.Theater) { $f.Theater } else { 'Unknown' }
        $theaterSlug = ($theater -replace '[^a-zA-Z0-9]', '-').ToLower()

        # Determine theater badge class
        $theaterBadgeClass = switch -Wildcard ($theater) {
            '*Workspace*' { 'badge-workspace'; break }
            '*Active*'    { 'badge-ad'; break }
            '*Cloud*'     { 'badge-cloud'; break }
            '*Microsoft*' { 'badge-cloud'; break }
            default       { '' }
        }

        [void]$html.Append(@"
  <tr class="clickable-row finding-row" data-theater="$theaterSlug" data-status="$($f.Status)" data-severity="$($f.Severity)" data-idx="$findingIdx" onclick="toggleFindingDetail($findingIdx)">
    <td><span class="badge badge-theater $theaterBadgeClass">$(& $esc $theater)</span></td>
    <td><code>$(& $esc $f.CheckId)</code></td>
    <td>$(& $esc $f.CheckName)</td>
    <td>$(& $esc $f.Category)</td>
    <td><span class="badge badge-$sevClass">$($f.Severity)</span></td>
    <td><span class="badge badge-$statusClass">$($f.Status)</span></td>
    <td>$(& $esc $f.CurrentValue)</td>
  </tr>
"@)

        # --- Finding detail row (hidden by default) ---
        $descHtml = if ($f.Description) { & $esc $f.Description } else { '&mdash;' }
        $curValHtml = if ($f.CurrentValue) { & $esc $f.CurrentValue } else { '&mdash;' }
        $recValHtml = if ($f.RecommendedValue) { & $esc $f.RecommendedValue } else { '&mdash;' }
        $remStepsHtml = if ($f.RemediationSteps) { & $esc $f.RemediationSteps } else { '&mdash;' }
        $remUrlHtml = if ($f.RemediationUrl) {
            "<a href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">$(& $esc $f.RemediationUrl) &#x2197;</a>"
        } else { '&mdash;' }

        # Compliance mappings
        $compHtml = [System.Text.StringBuilder]::new(512)
        if ($f.Compliance) {
            $compEntries = @()
            if ($f.Compliance.NistSp80053 -and $f.Compliance.NistSp80053.Count -gt 0) {
                $codes = ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                $compEntries += "<strong>NIST SP 800-53:</strong> $codes"
            }
            if ($f.Compliance.MitreAttack -and $f.Compliance.MitreAttack.Count -gt 0) {
                $codes = ($f.Compliance.MitreAttack | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                $compEntries += "<strong>MITRE ATT&amp;CK:</strong> $codes"
            }
            if ($f.Compliance.CisBenchmark -and $f.Compliance.CisBenchmark.Count -gt 0) {
                $codes = ($f.Compliance.CisBenchmark | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                $compEntries += "<strong>CIS Benchmark:</strong> $codes"
            }

            # Handle any additional compliance keys beyond the known three
            foreach ($compKey in $f.Compliance.Keys) {
                if ($compKey -in @('NistSp80053', 'MitreAttack', 'CisBenchmark')) { continue }
                $compVal = $f.Compliance[$compKey]
                if ($compVal -and $compVal.Count -gt 0) {
                    $codes = ($compVal | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                    $compEntries += "<strong>$(& $esc $compKey):</strong> $codes"
                }
            }

            if ($compEntries.Count -gt 0) {
                [void]$compHtml.Append($compEntries -join '<br>')
            } else {
                [void]$compHtml.Append('&mdash;')
            }
        } else {
            [void]$compHtml.Append('&mdash;')
        }

        # Affected entities (FAIL/WARN only) — bulleted list of impacted accounts/objects.
        $affectedBlock = ''
        if ($f.Status -in @('FAIL', 'WARN')) {
            $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
            if ($affectedHtml) {
                $affectedBlock = @"

        <div class="fd-block fd-full">
          <div class="fd-label">Affected Entities</div>
          <div class="fd-value">$affectedHtml</div>
        </div>
"@
            }
        }

        [void]$html.Append(@"
  <tr class="finding-detail-row" data-detail-idx="$findingIdx">
    <td colspan="7">
      <div class="finding-detail-content">
        <div class="fd-block fd-full">
          <div class="fd-label">Description</div>
          <div class="fd-value">$descHtml</div>
        </div>$affectedBlock
        <div class="fd-block">
          <div class="fd-label">Current Value</div>
          <div class="fd-value">$curValHtml</div>
        </div>
        <div class="fd-block">
          <div class="fd-label">Recommended Value</div>
          <div class="fd-value">$recValHtml</div>
        </div>
        <div class="fd-block fd-full">
          <div class="fd-label">Remediation Steps</div>
          <div class="fd-value">$remStepsHtml</div>
        </div>
        <div class="fd-block fd-full">
          <div class="fd-label">Remediation URL</div>
          <div class="fd-value">$remUrlHtml</div>
        </div>
        <div class="fd-block fd-full">
          <div class="fd-label">Compliance Mappings</div>
          <div class="fd-value">$($compHtml.ToString())</div>
        </div>
      </div>
    </td>
  </tr>
"@)
        $findingIdx++
    }

    [void]$html.Append('</tbody></table>')

    # =================================================================
    # COMPLIANCE CROSS-REFERENCE
    # =================================================================
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
    <th>Theater</th><th>Check ID</th><th>Check Name</th><th>Severity</th>
    <th>NIST SP 800-53</th><th>MITRE ATT&amp;CK</th><th>CIS Benchmark</th>
  </tr>
'@)
        foreach ($f in $complianceFindings) {
            $sevClass = $f.Severity.ToLower()
            $theater  = if ($f.Theater) { $f.Theater } else { 'Unknown' }
            $theaterBadgeClass = switch -Wildcard ($theater) {
                '*Workspace*' { 'badge-workspace'; break }
                '*Active*'    { 'badge-ad'; break }
                '*Cloud*'     { 'badge-cloud'; break }
                '*Microsoft*' { 'badge-cloud'; break }
                default       { '' }
            }

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
    <td><span class="badge badge-theater $theaterBadgeClass">$(& $esc $theater)</span></td>
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

    # =================================================================
    # JAVASCRIPT
    # =================================================================
    [void]$html.Append(@'
<script>
(function() {
  'use strict';

  var activeFilters = {
    theater: 'all',
    status: 'all',
    severity: 'all'
  };

  window.toggleFilter = function(btn) {
    var type = btn.getAttribute('data-filter-type');
    var value = btn.getAttribute('data-filter-value');

    // Deactivate all buttons in this filter group
    var siblings = btn.parentNode.querySelectorAll('.filter-btn');
    for (var i = 0; i < siblings.length; i++) {
      siblings[i].classList.remove('active');
    }
    btn.classList.add('active');
    activeFilters[type] = value;

    applyFilters();
  };

  window.toggleFindingDetail = function(idx) {
    var detailRows = document.querySelectorAll('.finding-detail-row[data-detail-idx="' + idx + '"]');
    for (var i = 0; i < detailRows.length; i++) {
      detailRows[i].classList.toggle('expanded');
    }
  };

  function applyFilters() {
    var rows = document.querySelectorAll('#findingsTable tbody .finding-row');
    var detailRows = document.querySelectorAll('#findingsTable tbody .finding-detail-row');
    var visibleCount = 0;
    var totalCount = rows.length;

    // Hide all detail rows first
    for (var d = 0; d < detailRows.length; d++) {
      detailRows[d].classList.remove('expanded');
    }

    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var theater = row.getAttribute('data-theater');
      var status = row.getAttribute('data-status');
      var severity = row.getAttribute('data-severity');
      var idx = row.getAttribute('data-idx');

      var showTheater = (activeFilters.theater === 'all' || theater === activeFilters.theater);
      var showStatus = (activeFilters.status === 'all' || status === activeFilters.status);
      var showSeverity = (activeFilters.severity === 'all' || severity === activeFilters.severity);

      if (showTheater && showStatus && showSeverity) {
        row.style.display = '';
        visibleCount++;
      } else {
        row.style.display = 'none';
        // Also hide associated detail row
        var detail = document.querySelector('.finding-detail-row[data-detail-idx="' + idx + '"]');
        if (detail) detail.style.display = 'none';
      }
    }

    var countEl = document.getElementById('filterCount');
    if (countEl) {
      if (visibleCount === totalCount) {
        countEl.textContent = 'Showing all ' + totalCount + ' findings';
      } else {
        countEl.textContent = 'Showing ' + visibleCount + ' of ' + totalCount + ' findings';
      }
    }
  }
})();
</script>
'@)

    # =================================================================
    # FOOTER
    # =================================================================
    [void]$html.Append(@"
<div style="margin-top: 40px; padding-top: 16px; border-top: 2px solid var(--border);
            color: var(--dim); font-size: 0.8em; text-align: center; letter-spacing: 1px;">
  &#x2694; Guerrilla Campaign Report &nbsp;|&nbsp;
  $timestampStr &nbsp;|&nbsp;
  Generated by Guerrilla v$moduleVersion &nbsp;|&nbsp;
  $totalChecks checks across $($theaters.Count) theaters &nbsp;|&nbsp; Score: $overallScore/100 ($(& $esc $displayLabel))
  <br>By Jim Tyler, Microsoft MVP &nbsp;|&nbsp; <a href="https://github.com/jimrtyler" style="color:var(--dim)">GitHub</a> &nbsp;|&nbsp; <a href="https://linkedin.com/in/jamestyler" style="color:var(--dim)">LinkedIn</a> &nbsp;|&nbsp; <a href="https://youtube.com/@jimrtyler" style="color:var(--dim)">YouTube</a>
</div>
</body>
</html>
"@)

    Set-Content -Path $OutputPath -Value $html.ToString() -Encoding UTF8
}
