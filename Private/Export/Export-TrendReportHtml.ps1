<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

    A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
#>
function Export-TrendReportHtml {
    <#
    .SYNOPSIS
        Generates an HTML trend report with embedded SVG sparklines.
    .PARAMETER History
        Array of score history entries (timestamp, score, label).
    .PARAMETER OutputPath
        File path for the HTML output.
    .PARAMETER OrganizationName
        Organization name for the report header.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$History,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$OrganizationName = 'Organization'
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    # ConvertFrom-Json on PS 7.5+ rehydrates ISO 8601 strings into [DateTime],
    # which would interpolate as a culture-dependent string. Always normalize.
    $fmtTs = {
        param($t)
        if ($null -eq $t) { return '' }
        if ($t -is [datetime]) { return $t.ToString('yyyy-MM-ddTHH:mm:ssZ') }
        return "$t"
    }
    $html = [System.Text.StringBuilder]::new(32768)

    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Calculate stats
    $scores = @($History | ForEach-Object { [int]$_.Score })
    $avgScore = if ($scores.Count -gt 0) { [Math]::Round(($scores | Measure-Object -Average).Average, 0) } else { 0 }
    $maxScore = if ($scores.Count -gt 0) { ($scores | Measure-Object -Maximum).Maximum } else { 0 }
    $minScore = if ($scores.Count -gt 0) { ($scores | Measure-Object -Minimum).Minimum } else { 0 }
    $latestScore = if ($scores.Count -gt 0) { $scores[-1] } else { 0 }
    $firstScore = if ($scores.Count -gt 0) { $scores[0] } else { 0 }
    $delta = $latestScore - $firstScore
    $trendDir = if ($delta -gt 2) { 'Improving' } elseif ($delta -lt -2) { 'Declining' } else { 'Stable' }
    $trendArrow = if ($delta -gt 2) { '&#x25B2;' } elseif ($delta -lt -2) { '&#x25BC;' } else { '&#x25CF;' }
    $trendColor = if ($delta -gt 2) { 'var(--sage)' } elseif ($delta -lt -2) { 'var(--dark-red)' } else { 'var(--gold)' }

    # Build SVG sparkline
    $svgWidth = 700
    $svgHeight = 200
    $padding = 40
    $chartW = $svgWidth - (2 * $padding)
    $chartH = $svgHeight - (2 * $padding)

    $svgPoints = ''
    $svgDots = ''
    if ($scores.Count -gt 1) {
        $xStep = $chartW / ([Math]::Max(1, $scores.Count - 1))
        for ($i = 0; $i -lt $scores.Count; $i++) {
            $x = $padding + ($i * $xStep)
            $y = $padding + $chartH - ($scores[$i] / 100.0 * $chartH)
            $svgPoints += "$x,$y "
            $svgDots += "<circle cx='$x' cy='$y' r='4' fill='var(--olive)' stroke='var(--bg)' stroke-width='2'><title>$(& $fmtTs $History[$i].Timestamp): $($scores[$i])</title></circle>`n"
        }
    } elseif ($scores.Count -eq 1) {
        $x = $padding + ($chartW / 2)
        $y = $padding + $chartH - ($scores[0] / 100.0 * $chartH)
        $svgPoints = "$x,$y"
        $svgDots = "<circle cx='$x' cy='$y' r='4' fill='var(--olive)' stroke='var(--bg)' stroke-width='2'/>"
    }

    # Grid lines for SVG
    $gridLines = ''
    foreach ($val in @(0, 20, 40, 60, 80, 100)) {
        $gy = $padding + $chartH - ($val / 100.0 * $chartH)
        $gridLines += "<line x1='$padding' y1='$gy' x2='$($svgWidth - $padding)' y2='$gy' stroke='var(--border)' stroke-dasharray='4,4'/>`n"
        $gridLines += "<text x='$($padding - 5)' y='$($gy + 4)' fill='var(--text-muted)' font-size='11' text-anchor='end'>$val</text>`n"
    }

    # Scan history table rows
    $tableRows = ''
    for ($i = $History.Count - 1; $i -ge 0; $i--) {
        $entry = $History[$i]
        $scoreColor = switch ($true) {
            ([int]$entry.Score -ge 90) { 'var(--sage)'; break }
            ([int]$entry.Score -ge 75) { 'var(--olive)'; break }
            ([int]$entry.Score -ge 60) { 'var(--gold)'; break }
            ([int]$entry.Score -ge 40) { 'var(--amber)'; break }
            ([int]$entry.Score -ge 20) { 'var(--deep-orange)'; break }
            default { 'var(--dark-red)' }
        }
        $entryDelta = if ($i -gt 0) { [int]$entry.Score - [int]$History[$i-1].Score } else { 0 }
        $deltaDisplay = if ($entryDelta -gt 0) { "+$entryDelta" } elseif ($entryDelta -lt 0) { "$entryDelta" } else { '—' }
        $deltaColor = if ($entryDelta -gt 0) { 'var(--sage)' } elseif ($entryDelta -lt 0) { 'var(--dark-red)' } else { 'var(--dim)' }

        $tableRows += @"
<tr>
<td style="padding:6px 12px;border-bottom:1px solid var(--border);">$(& $esc (& $fmtTs $entry.Timestamp))</td>
<td style="padding:6px 12px;border-bottom:1px solid var(--border);color:$scoreColor;font-weight:bold;">$($entry.Score)</td>
<td style="padding:6px 12px;border-bottom:1px solid var(--border);">$(& $esc ($entry.Label ?? ''))</td>
<td style="padding:6px 12px;border-bottom:1px solid var(--border);color:$deltaColor;">$deltaDisplay</td>
<td style="padding:6px 12px;border-bottom:1px solid var(--border);">$(& $esc ($entry.ProfileUsed ?? 'Default'))</td>
</tr>
"@
    }

    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Trend Report - $(& $esc $OrganizationName)</title>
<style>
:root { --bg:#1a1f16; --surface:#242b1e; --surface-alt:#2d3526; --border:#3d4a35; --text:#d4c9a8; --text-muted:#8a8468; --olive:#a8b58b; --amber:#d4883a; --sage:#6b9b6b; --parchment:#d4c4a0; --gold:#c9a84c; --dim:#6b6b5a; --deep-orange:#c75c2e; --dark-red:#8b2500; }
body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; }
.container { max-width:900px; margin:0 auto; }
h1 { color:var(--olive); border-bottom:2px solid var(--border); padding-bottom:10px; }
h2 { color:var(--olive); margin-top:30px; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin:20px 0; }
.stat-card { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:15px; text-align:center; }
.stat-card .value { font-size:1.8em; font-weight:bold; }
.stat-card .label { color:var(--text-muted); font-size:0.85em; margin-top:4px; }
.chart-container { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:20px; margin:20px 0; }
table { width:100%; border-collapse:collapse; background:var(--surface); }
th { background:var(--surface-alt); color:var(--olive); padding:8px 12px; text-align:left; }
.footer { color:var(--dim); font-size:0.8em; margin-top:40px; border-top:1px solid var(--border); padding-top:10px; }
@media print { body { background:#fff; color:#333; } :root { --bg:#fff; --surface:#f9f9f9; --surface-alt:#eee; --border:#ccc; --text:#333; --text-muted:#666; --olive:#5a6b3a; --sage:#3a7a3a; --gold:#8a7a2a; --amber:#aa6a1a; --deep-orange:#aa3a0a; --dark-red:#7a1a00; --dim:#999; } }
</style>
</head>
<body>
<div class="container">
<h1>Security Trend Report</h1>
<p>$(& $esc $OrganizationName) | $($History.Count) scan(s) | $timestamp UTC</p>

<div class="stats-grid">
<div class="stat-card"><div class="value" style="color:$trendColor;">$latestScore</div><div class="label">Current Score</div></div>
<div class="stat-card"><div class="value">$avgScore</div><div class="label">Average Score</div></div>
<div class="stat-card"><div class="value" style="color:$trendColor;">$trendArrow $trendDir</div><div class="label">Trend ($(if($delta -ge 0){"+$delta"}else{"$delta"}))</div></div>
<div class="stat-card"><div class="value">$maxScore / $minScore</div><div class="label">Highest / Lowest</div></div>
</div>

<h2>Score History</h2>
<div class="chart-container">
<svg viewBox="0 0 $svgWidth $svgHeight" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;">
$gridLines
$(if ($svgPoints) { "<polyline points='$svgPoints' fill='none' stroke='var(--olive)' stroke-width='2.5' stroke-linejoin='round'/>" })
$svgDots
</svg>
</div>

<h2>Scan Log</h2>
<table>
<tr><th>Timestamp</th><th>Score</th><th>Label</th><th>Delta</th><th>Profile</th></tr>
$tableRows
</table>

<div class="footer">
<p>Generated by PSGuerrilla v2.1.0 | $timestamp UTC</p>
<p>By Jim Tyler, Microsoft MVP &mdash; <a href="https://github.com/jimrtyler">GitHub</a> | <a href="https://linkedin.com/in/jamestyler">LinkedIn</a> | <a href="https://youtube.com/@jimrtyler">YouTube</a></p>
</div>
</div>
</body>
</html>
"@)

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
    return $OutputPath
}
