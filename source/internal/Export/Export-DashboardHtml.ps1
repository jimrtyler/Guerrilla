# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-DashboardHtml {
    <#
    .SYNOPSIS
        Generates the unified HTML dashboard with CSS tabs for each theater.
    .PARAMETER ScoreResult
        Guerrilla Score result object.
    .PARAMETER Findings
        Array of audit finding objects.
    .PARAMETER ScanResults
        Array of scan result objects.
    .PARAMETER OutputPath
        File path for the HTML output.
    .PARAMETER OrganizationName
        Organization name for the header.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject]$ScoreResult,
        [PSCustomObject[]]$Findings,
        [PSCustomObject[]]$ScanResults,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization'
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $html = [System.Text.StringBuilder]::new(65536)
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    $score = $ScoreResult.Score ?? 0
    $label = $ScoreResult.Label ?? ''

    # Score ring
    $ringColor = switch ($true) {
        ([int]$score -ge 90) { '#6b9b6b'; break }
        ([int]$score -ge 75) { '#a8b58b'; break }
        ([int]$score -ge 60) { '#c9a84c'; break }
        ([int]$score -ge 40) { '#d4883a'; break }
        ([int]$score -ge 20) { '#c75c2e'; break }
        default { '#8b2500' }
    }

    # Stats
    $totalFindings = ($Findings ?? @()).Count
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passRate = if ($totalFindings -gt 0) { [Math]::Round(100 * $passCount / $totalFindings, 0) } else { 0 }

    # Theater data
    $theaters = @{
        'Fortification'  = @{ Findings = @($Findings | Where-Object { ($_.CheckId ?? '') -match '^AD' }); Color = '#6b9b6b'; Icon = '&#x1F3F0;' }
        'Reconnaissance' = @{ Findings = @($Findings | Where-Object { ($_.CheckId ?? '') -match '^(AUTH|ADMIN|EMAIL|COLLAB|DRIVE|OAUTH|DEVICE|LOG|EID|M365|AZIAM|INTUNE)' }); Color = '#a8b58b'; Icon = '&#x1F50D;' }
        'Surveillance'   = @{ Findings = @(); Color = '#c9a84c'; Icon = '&#x1F441;' }
        'Watchtower'     = @{ Findings = @(); Color = '#d4883a'; Icon = '&#x1F3EF;' }
    }

    # Threat counts from scan results
    $totalThreats = 0
    foreach ($result in ($ScanResults ?? @())) {
        $totalThreats += ($result.CriticalCount ?? 0) + ($result.HighCount ?? 0) + ($result.MediumCount ?? 0) + ($result.LowCount ?? 0)
        $theater = $result.Theater ?? $result.PSObject.TypeNames[0] ?? ''
        if ($theater -match 'Surveillance') {
            $theaters['Surveillance'].ThreatCount = ($result.CriticalCount ?? 0) + ($result.HighCount ?? 0) + ($result.MediumCount ?? 0)
        }
        if ($theater -match 'Watchtower') {
            $theaters['Watchtower'].ChangeCount = ($result.ChangeCount ?? 0)
        }
    }

    # Components breakdown
    $components = $ScoreResult.Components
    $componentHtml = ''
    if ($components) {
        foreach ($comp in @('Posture', 'Threats', 'Coverage', 'Trend')) {
            $c = $components.$comp
            if ($c) {
                $barWidth = [Math]::Max(2, $c.Score)
                $componentHtml += @"
<div style="margin:6px 0;">
<div style="display:flex;justify-content:space-between;font-size:0.85em;"><span>$comp</span><span>$($c.Score) ($([Math]::Round($c.Weight * 100))%)</span></div>
<div style="background:var(--surface-alt);border-radius:3px;height:8px;margin-top:2px;">
<div style="background:var(--olive);height:100%;width:${barWidth}%;border-radius:3px;"></div>
</div>
</div>
"@
            }
        }
    }

    # Findings table rows (sorted by severity)
    $findingsTableHtml = ''
    $sortedFindings = @($Findings | Where-Object Status -in @('FAIL', 'WARN') | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }} | Select-Object -First 50)

    foreach ($f in $sortedFindings) {
        $sevColor = switch ($f.Severity) { 'Critical' { 'var(--dark-red)' } 'High' { 'var(--deep-orange)' } 'Medium' { 'var(--gold)' } default { 'var(--sage)' } }
        $statusColor = if ($f.Status -eq 'FAIL') { 'var(--deep-orange)' } else { 'var(--gold)' }
        $findingsTableHtml += @"
<tr>
<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-size:0.85em;">$(& $esc ($f.CheckId ?? ''))</td>
<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-size:0.85em;">$(& $esc ($f.Name ?? $f.CheckName ?? ''))</td>
<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-size:0.85em;color:$sevColor;">$($f.Severity)</td>
<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-size:0.85em;color:$statusColor;">$($f.Status)</td>
<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-size:0.85em;">$(& $esc ($f.Category ?? ''))</td>
</tr>
"@
    }

    # Theater cards
    $theaterCardsHtml = ''
    foreach ($tName in @('Fortification', 'Reconnaissance', 'Surveillance', 'Watchtower')) {
        $t = $theaters[$tName]
        $tFail = @($t.Findings | Where-Object Status -eq 'FAIL').Count
        $tTotal = $t.Findings.Count
        $tScore = if ($tTotal -gt 0) { [Math]::Round(100 * ($tTotal - $tFail) / $tTotal, 0) } else { 'N/A' }
        $isActive = $tTotal -gt 0 -or $t.ThreatCount -gt 0 -or $t.ChangeCount -gt 0

        $theaterCardsHtml += @"
<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:15px;border-left:4px solid $(if ($isActive) { $t.Color } else { 'var(--dim)' });">
<div style="font-size:1.1em;font-weight:bold;color:$(if ($isActive) { $t.Color } else { 'var(--dim)' });">$($t.Icon) $tName</div>
$(if ($tTotal -gt 0) {
"<div style='margin-top:8px;'>Score: <strong>$tScore%</strong> | Checks: $tTotal | Failures: <span style='color:var(--deep-orange)'>$tFail</span></div>"
} elseif ($t.ThreatCount) {
"<div style='margin-top:8px;'>Threats: <strong>$($t.ThreatCount)</strong></div>"
} elseif ($t.ChangeCount) {
"<div style='margin-top:8px;'>Changes: <strong>$($t.ChangeCount)</strong></div>"
} else {
"<div style='margin-top:8px;color:var(--dim);'>Not scanned</div>"
})
</div>
"@
    }

    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Dashboard - $(& $esc $OrganizationName)</title>
<style>
:root { --bg:#1a1f16; --surface:#242b1e; --surface-alt:#2d3526; --border:#3d4a35; --text:#d4c9a8; --text-muted:#8a8468; --olive:#a8b58b; --amber:#d4883a; --sage:#6b9b6b; --parchment:#d4c4a0; --gold:#c9a84c; --dim:#6b6b5a; --deep-orange:#c75c2e; --dark-red:#8b2500; }
body { font-family:'Segoe UI',Tahoma,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; }
.container { max-width:1000px; margin:0 auto; }
h1 { color:var(--olive); border-bottom:2px solid var(--border); padding-bottom:10px; }
h2 { color:var(--olive); margin-top:25px; }
.hero { display:flex; gap:25px; margin:20px 0; }
.score-section { flex-shrink:0; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px; text-align:center; }
.components-section { flex:1; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin:15px 0; }
.stat { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:10px; text-align:center; }
.stat .val { font-size:1.4em; font-weight:bold; }
.stat .lbl { color:var(--text-muted); font-size:0.8em; }
.theaters { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin:15px 0; }
table { width:100%; border-collapse:collapse; background:var(--surface); }
th { background:var(--surface-alt); color:var(--olive); padding:6px 8px; text-align:left; font-size:0.85em; }
.footer { color:var(--dim); font-size:0.8em; margin-top:30px; border-top:1px solid var(--border); padding-top:10px; }
@media print { body { background:#fff; color:#333; } :root { --bg:#fff; --surface:#f9f9f9; --surface-alt:#eee; --border:#ccc; --text:#333; --text-muted:#666; --olive:#5a6b3a; --sage:#3a7a3a; --gold:#8a7a2a; --amber:#aa6a1a; --deep-orange:#aa3a0a; --dark-red:#7a1a00; --dim:#999; } }
</style>
</head>
<body>
<div class="container">
<h1>Security Dashboard</h1>
<p>$(& $esc $OrganizationName) | $timestamp UTC</p>

<div class="hero">
<div class="score-section">
<svg width="140" height="140" viewBox="0 0 140 140">
<circle cx="70" cy="70" r="50" fill="none" stroke="var(--border)" stroke-width="10"/>
<circle cx="70" cy="70" r="50" fill="none" stroke="$ringColor" stroke-width="10" stroke-dasharray="314" stroke-dashoffset="$([Math]::Round(314 * (1 - [int]$score / 100), 1))" stroke-linecap="round" transform="rotate(-90 70 70)"/>
<text x="70" y="65" text-anchor="middle" fill="$ringColor" font-size="28" font-weight="bold">$score</text>
<text x="70" y="85" text-anchor="middle" fill="var(--text-muted)" font-size="11">$label</text>
</svg>
<div style="margin-top:8px;color:var(--text-muted);font-size:0.85em;">Guerrilla Score</div>
</div>
<div class="components-section">
<div style="font-weight:bold;color:var(--olive);margin-bottom:10px;">Score Components</div>
$componentHtml
</div>
</div>

<div class="stats">
<div class="stat"><div class="val">$totalFindings</div><div class="lbl">Total Checks</div></div>
<div class="stat"><div class="val" style="color:var(--sage);">$passRate%</div><div class="lbl">Pass Rate</div></div>
<div class="stat"><div class="val" style="color:var(--deep-orange);">$failCount</div><div class="lbl">Failures</div></div>
<div class="stat"><div class="val" style="color:var(--gold);">$warnCount</div><div class="lbl">Warnings</div></div>
$(if ($totalThreats -gt 0) { "<div class='stat'><div class='val' style='color:var(--dark-red);'>$totalThreats</div><div class='lbl'>Threats</div></div>" })
</div>

<h2>Theater Overview</h2>
<div class="theaters">
$theaterCardsHtml
</div>

$(if ($findingsTableHtml) {
@"
<h2>Top Findings</h2>
<table>
<tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th></tr>
$findingsTableHtml
</table>
$(if ($sortedFindings.Count -ge 50) { "<p style='color:var(--text-muted);font-size:0.85em;'>Showing top 50 findings. See detailed reports for full listing.</p>" })
"@
})

<div class="footer">
<p>Generated by Guerrilla v2.1.0 | $timestamp UTC</p>
<p>By Jim Tyler, Microsoft MVP &mdash; <a href="https://github.com/jimrtyler">GitHub</a> | <a href="https://linkedin.com/in/jamestyler">LinkedIn</a> | <a href="https://youtube.com/@jimrtyler">YouTube</a></p>
</div>
</div>
</body>
</html>
"@)

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
    return $OutputPath
}
