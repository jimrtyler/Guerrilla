# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-WiretapReportHtml {
    <#
    .SYNOPSIS
        Exports Wiretap results to an HTML report.

    .DESCRIPTION
        Generates a dark guerrilla-themed HTML report of M365 Wiretap scan results including
        Guerrilla Score, tenant info, threat breakdown, flagged changes table, and new threats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [int]$TotalEvents,
        [int]$DaysBack,

        [PSCustomObject[]]$FlaggedChanges = @(),
        [PSCustomObject[]]$NewThreats = @(),

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # Count by risk level
    $critCount = 0; $highCount = 0; $medCount = 0; $lowCount = 0
    foreach ($c in $FlaggedChanges) {
        switch ($c.RiskLevel) {
            'Critical' { $critCount++ }
            'High'     { $highCount++ }
            'Medium'   { $medCount++ }
            'Low'      { $lowCount++ }
        }
    }

    # Guerrilla Score
    $guerrillaScore = 100
    $guerrillaScore -= ($critCount * 25)
    $guerrillaScore -= ($highCount * 15)
    $guerrillaScore -= ($medCount * 8)
    $guerrillaScore -= ($lowCount * 3)
    $guerrillaScore = [Math]::Max(0, [Math]::Min(100, $guerrillaScore))

    $scoreInfo = Get-GuerrillaScoreLabel -Score $guerrillaScore

    $html = [System.Text.StringBuilder]::new(65536)

    # --- Head ---
    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Guerrilla Wiretap Report - $(& $esc $timestampStr)</title>
<style>
  :root {
    --bg: #1a1f16; --surface: #242b1e; --surface-alt: #2d3526; --border: #3d4a35;
    --text: #d4c9a8; --text-muted: #8a8468;
    --olive: #a8b58b; --amber: #d4883a; --sage: #6b9b6b;
    --parchment: #d4c4a0; --gold: #c9a84c; --dim: #6b6b5a;
    --deep-orange: #c75c2e; --dark-red: #8b2500;
    --critical: #c75c2e; --high: #d4883a; --medium: #c9a84c;
    --low: #6b9b6b; --clean: #4a7a4a;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Courier New', Consolas, monospace;
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

  /* Guerrilla Score */
  .score-panel {
    background: var(--surface); border: 2px solid var(--border);
    border-radius: 4px; padding: 20px 24px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 24px;
  }
  .score-ring {
    width: 100px; height: 100px; position: relative; flex-shrink: 0;
  }
  .score-ring svg { transform: rotate(-90deg); }
  .score-ring .value {
    position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; font-size: 1.8em; font-weight: 700;
  }
  .score-detail .label { font-size: 1.3em; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; }
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
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px; margin-bottom: 24px;
  }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 14px; text-align: center;
  }
  .stat-card .value { font-size: 1.8em; font-weight: 700; }
  .stat-card .label { color: var(--dim); font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }

  /* Badges */
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 2px;
    font-size: 0.75em; font-weight: 700; color: #fff; letter-spacing: 1px;
    text-transform: uppercase; font-family: 'Courier New', monospace;
  }
  .badge-critical { background: var(--critical); }
  .badge-high { background: var(--high); color: #1a1f16; }
  .badge-medium { background: var(--medium); color: #1a1f16; }
  .badge-low { background: var(--low); color: #1a1f16; }
  .badge-new { background: #6b4c8a; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 0.9em; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--surface); font-weight: 700; font-size: 0.8em; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
  tr:hover { background: rgba(168, 181, 139, 0.05); }

  .indicator {
    display: block; background: var(--surface); border-left: 3px solid var(--amber);
    padding: 4px 10px; margin: 4px 0; font-size: 0.85em;
  }

  /* Collapsible details */
  details.change-detail {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; margin-bottom: 12px;
  }
  details.change-detail summary {
    padding: 12px 16px; cursor: pointer; list-style: none;
    display: flex; align-items: center; gap: 12px;
  }
  details.change-detail summary::-webkit-details-marker { display: none; }
  details.change-detail summary::before {
    content: '\25b6'; font-size: 0.7em; color: var(--dim); transition: transform 0.2s;
  }
  details.change-detail[open] summary::before { transform: rotate(90deg); }
  details.change-detail .detail-body { padding: 0 16px 16px; }

  .new-threat {
    background: rgba(199, 92, 46, 0.08); border: 1px solid rgba(199, 92, 46, 0.25);
    border-radius: 4px; padding: 14px; margin: 12px 0;
  }
  .new-threat h4 { color: var(--amber); margin-top: 0; font-size: 0.95em; text-transform: uppercase; letter-spacing: 1px; }

  code { font-family: 'Courier New', Consolas, monospace; font-size: 0.9em; color: var(--olive); }
  a { color: var(--gold); }

  /* Print styles */
  @media print {
    body { background: #fff; color: #000; }
    .score-panel, .stat-card, .change-detail, .exec-summary, .new-threat { border-color: #ccc; background: #f9f9f9; }
    details.change-detail { break-inside: avoid; }
  }
</style>
</head>
<body>
<h1>&#x1f50a; Guerrilla Wiretap Report</h1>
<div class="subtitle">
  Generated $(& $esc $timestampStr) &mdash;
  Tenant: $(& $esc $TenantId) &mdash;
  $($TotalEvents.ToString('N0')) events analyzed across $DaysBack day(s)
</div>
"@)

    # --- Guerrilla Score Panel ---
    $scoreColor = switch ($scoreInfo.Label) {
        'FORTRESS'          { 'var(--sage)' }
        'DEFENDED POSITION' { 'var(--sage)' }
        'CONTESTED GROUND'  { 'var(--gold)' }
        'EXPOSED FLANK'     { 'var(--amber)' }
        'UNDER SIEGE'       { 'var(--deep-orange)' }
        'OVERRUN'           { 'var(--dark-red)' }
        default             { 'var(--dim)' }
    }

    $circumference = 251.2  # 2 * PI * 40
    $dashOffset = $circumference - ($circumference * $guerrillaScore / 100)
    $totalFlagged = $critCount + $highCount + $medCount + $lowCount

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg width="100" height="100" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="40" fill="none" stroke="var(--border)" stroke-width="8"/>
      <circle cx="50" cy="50" r="40" fill="none" stroke="$scoreColor" stroke-width="8"
              stroke-dasharray="$circumference" stroke-dashoffset="$([Math]::Round($dashOffset, 1))"
              stroke-linecap="round"/>
    </svg>
    <div class="value" style="color:$scoreColor">$guerrillaScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$($scoreInfo.Label)</div>
    <div class="desc">M365 tenant security posture score. Higher is better. Based on $totalFlagged flagged change(s) across $($TotalEvents.ToString('N0')) events.</div>
  </div>
</div>
"@)

    # --- Threat Level Banner ---
    $threatLevel = $Result.ThreatLevel
    $threatScore = $Result.ThreatScore
    $threatColor = switch ($threatLevel) {
        'CRITICAL' { 'var(--critical)' }
        'HIGH'     { 'var(--high)' }
        'MEDIUM'   { 'var(--medium)' }
        'LOW'      { 'var(--low)' }
        default    { 'var(--sage)' }
    }

    # --- Executive Summary ---
    $summaryVerdict = if ($critCount -gt 0) {
        "Immediate action required. $critCount critical M365 security change(s) detected."
    } elseif ($highCount -gt 0) {
        "Investigation recommended. $highCount high-severity change(s) require review."
    } elseif ($medCount -gt 0) {
        "Monitor closely. $medCount medium-severity change(s) warrant attention."
    } elseif ($lowCount -gt 0) {
        "Low-level activity detected. $lowCount minor change(s) logged. No immediate action needed."
    } else {
        "No suspicious changes detected. M365 tenant appears clean."
    }

    [void]$html.Append(@"
<div class="exec-summary">
  <h3>Executive Summary</h3>
  <p><strong>Threat Level:</strong> <span style="color:$threatColor;font-weight:700">$threatLevel</span> &mdash; Score: $($threatScore.ToString('N0'))</p>
  <p><strong>Assessment:</strong> $summaryVerdict</p>
  <p><strong>Scope:</strong> Tenant $(& $esc $TenantId), $($TotalEvents.ToString('N0')) events over $DaysBack day(s).</p>
  <p><strong>Findings:</strong> $totalFlagged change(s) flagged &mdash; $critCount critical, $highCount high, $medCount medium, $lowCount low. $($NewThreats.Count) new threat(s).</p>
</div>
"@)

    # --- Summary Stats ---
    [void]$html.Append('<div class="stat-grid">')
    [void]$html.Append(@"
  <div class="stat-card"><div class="value" style="color:var(--parchment)">$($TotalEvents.ToString('N0'))</div><div class="label">Events</div></div>
  <div class="stat-card"><div class="value" style="color:var(--critical)">$critCount</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="value" style="color:var(--high)">$highCount</div><div class="label">High</div></div>
  <div class="stat-card"><div class="value" style="color:var(--medium)">$medCount</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="value" style="color:var(--low)">$lowCount</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="value" style="color:var(--amber)">$($NewThreats.Count)</div><div class="label">New Threats</div></div>
"@)
    [void]$html.Append('</div>')

    # --- Indicators ---
    $indicators = @($Result.Indicators)
    if ($indicators.Count -gt 0) {
        [void]$html.Append('<h2>Security Indicators</h2>')
        foreach ($ind in $indicators) {
            [void]$html.Append("<div class=`"indicator`">$(& $esc $ind)</div>")
        }
    }

    # --- Threat Breakdown by Detection Type ---
    if ($FlaggedChanges.Count -gt 0) {
        [void]$html.Append('<h2>Threat Breakdown</h2>')

        $typeGroups = @{}
        foreach ($c in $FlaggedChanges) {
            $type = if ($c.DetectionType) { $c.DetectionType } else { 'Unknown' }
            if (-not $typeGroups.ContainsKey($type)) { $typeGroups[$type] = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 } }
            $typeGroups[$type].Total++
            switch ($c.RiskLevel) {
                'Critical' { $typeGroups[$type].Critical++ }
                'High'     { $typeGroups[$type].High++ }
                'Medium'   { $typeGroups[$type].Medium++ }
                'Low'      { $typeGroups[$type].Low++ }
            }
        }

        [void]$html.Append('<table><tr><th>Detection Type</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>')
        foreach ($entry in ($typeGroups.GetEnumerator() | Sort-Object { $_.Value.Total } -Descending)) {
            $g = $entry.Value
            $countOrEmpty = { param($n) if ($n -gt 0) { $n } else { '' } }
            [void]$html.Append("<tr><td><strong>$(& $esc $entry.Key)</strong></td>")
            [void]$html.Append("<td style=`"color:var(--critical)`">$(& $countOrEmpty $g.Critical)</td>")
            [void]$html.Append("<td style=`"color:var(--high)`">$(& $countOrEmpty $g.High)</td>")
            [void]$html.Append("<td style=`"color:var(--medium)`">$(& $countOrEmpty $g.Medium)</td>")
            [void]$html.Append("<td style=`"color:var(--low)`">$(& $countOrEmpty $g.Low)</td>")
            [void]$html.Append("<td>$($g.Total)</td></tr>")
        }
        [void]$html.Append('</table>')
    }

    # --- Flagged Changes Table ---
    if ($FlaggedChanges.Count -gt 0) {
        [void]$html.Append('<h2>Flagged Changes</h2>')
        [void]$html.Append('<table><tr><th>Time</th><th>Actor</th><th>Detection</th><th>Risk</th><th>Description</th></tr>')

        $sortedChanges = @($FlaggedChanges | Sort-Object {
            $riskOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
            $riskOrder[$_.RiskLevel] ?? 4
        })

        foreach ($c in $sortedChanges) {
            $levelClass = ($c.RiskLevel ?? 'low').ToLower()
            $badge = "<span class=`"badge badge-$levelClass`">$($c.RiskLevel ?? 'Unknown')</span>"

            $ts = $c.Timestamp
            if ($ts -is [datetime]) { $ts = $ts.ToString('yyyy-MM-dd HH:mm:ss') }

            [void]$html.Append('<tr>')
            [void]$html.Append("<td style=`"white-space:nowrap`">$(& $esc $ts)</td>")
            [void]$html.Append("<td>$(& $esc ($c.Actor ?? ''))</td>")
            [void]$html.Append("<td><strong>$(& $esc ($c.DetectionType ?? ''))</strong></td>")
            [void]$html.Append("<td>$badge</td>")
            [void]$html.Append("<td style=`"font-size:0.85em`">$(& $esc ($c.Description ?? ''))</td>")
            [void]$html.Append('</tr>')
        }
        [void]$html.Append('</table>')

        # Collapsible detail sections for critical/high changes
        $detailChanges = @($FlaggedChanges | Where-Object { $_.RiskLevel -in @('Critical', 'High') })
        if ($detailChanges.Count -gt 0) {
            [void]$html.Append('<h2>Detailed Analysis</h2>')
            foreach ($c in $detailChanges) {
                $levelClass = ($c.RiskLevel ?? 'low').ToLower()
                $openAttr = if ($c.RiskLevel -eq 'Critical') { ' open' } else { '' }

                [void]$html.Append("<details class=`"change-detail`"$openAttr>")
                [void]$html.Append("<summary><span class=`"badge badge-$levelClass`">$($c.RiskLevel)</span> <strong>$(& $esc ($c.DetectionType ?? ''))</strong> <span style=`"color:var(--dim)`">&mdash; $(& $esc ($c.Actor ?? 'Unknown'))</span></summary>")
                [void]$html.Append('<div class="detail-body">')

                $ts = $c.Timestamp
                if ($ts -is [datetime]) { $ts = $ts.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }

                [void]$html.Append("<p><strong>Timestamp:</strong> $(& $esc $ts)</p>")
                [void]$html.Append("<p><strong>Actor:</strong> $(& $esc ($c.Actor ?? '')) $(if ($c.ActorId) { "(<code>$(& $esc $c.ActorId)</code>)" })</p>")
                [void]$html.Append("<p><strong>Detection:</strong> $(& $esc ($c.DetectionType ?? ''))</p>")
                if ($c.Description) {
                    [void]$html.Append("<p><strong>Description:</strong> $(& $esc $c.Description)</p>")
                }
                if ($c.Activity -or $c.OperationType) {
                    [void]$html.Append("<p><strong>Activity:</strong> $(& $esc ($c.Activity ?? $c.OperationType ?? ''))</p>")
                }
                if ($c.Result) {
                    [void]$html.Append("<p><strong>Result:</strong> $(& $esc $c.Result)</p>")
                }

                # Type-specific details
                if ($c.RuleName) { [void]$html.Append("<p><strong>Rule:</strong> $(& $esc $c.RuleName)</p>") }
                if ($c.PolicyName) { [void]$html.Append("<p><strong>Policy:</strong> $(& $esc $c.PolicyName)</p>") }
                if ($c.FlowName) { [void]$html.Append("<p><strong>Flow:</strong> $(& $esc $c.FlowName)</p>") }
                if ($c.TargetMailbox) { [void]$html.Append("<p><strong>Target Mailbox:</strong> $(& $esc $c.TargetMailbox)</p>") }
                if ($c.ForwardingDestination) { [void]$html.Append("<p><strong>Forwarding To:</strong> <span style=`"color:var(--critical)`">$(& $esc $c.ForwardingDestination)</span></p>") }
                if ($c.FileCount) { [void]$html.Append("<p><strong>Files:</strong> $($c.FileCount)</p>") }
                if ($c.AffectedScope) { [void]$html.Append("<p><strong>Scope:</strong> $(& $esc $c.AffectedScope)</p>") }

                # Boolean flags
                $flags = [System.Collections.Generic.List[string]]::new()
                if ($c.IsExternal) { $flags.Add('External') }
                if ($c.IsServerSide) { $flags.Add('Server-Side') }
                if ($c.IsDisabled) { $flags.Add('Disabled') }
                if ($c.IsRemoved) { $flags.Add('Removed') }
                if ($c.IsWeakened -or $c.SharingWeakened -or $c.AccessWeakened) { $flags.Add('Security Weakened') }
                if ($flags.Count -gt 0) {
                    [void]$html.Append("<p><strong>Flags:</strong> $($flags -join ', ')</p>")
                }

                [void]$html.Append('</div></details>')
            }
        }
    } else {
        [void]$html.Append('<h2>Flagged Changes</h2>')
        [void]$html.Append('<p style="color:var(--sage)">No suspicious changes detected. M365 tenant appears clean.</p>')
    }

    # --- New Threats Highlight ---
    if ($NewThreats.Count -gt 0) {
        [void]$html.Append('<h2>New Threats</h2>')
        foreach ($t in $NewThreats) {
            $levelClass = ($t.RiskLevel ?? 'low').ToLower()

            $ts = $t.Timestamp
            if ($ts -is [datetime]) { $ts = $ts.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }

            [void]$html.Append('<div class="new-threat">')
            [void]$html.Append("<h4><span class=`"badge badge-$levelClass`">$($t.RiskLevel ?? 'Unknown')</span> <span class=`"badge badge-new`">NEW</span> $(& $esc ($t.DetectionType ?? ''))</h4>")
            [void]$html.Append("<p><strong>Actor:</strong> $(& $esc ($t.Actor ?? '')) &mdash; $(& $esc $ts)</p>")
            if ($t.Description) {
                [void]$html.Append("<p>$(& $esc $t.Description)</p>")
            }
            [void]$html.Append('</div>')
        }
    }

    # --- Detection Counts Reference ---
    [void]$html.Append(@"
<h2>Detection Category Summary</h2>
<table>
  <tr><th>Category</th><th>Count</th></tr>
  <tr><td>Transport Rule Changes</td><td>$($Result.TransportRuleChanges.Count)</td></tr>
  <tr><td>Forwarding Rules</td><td>$($Result.ForwardingRules.Count)</td></tr>
  <tr><td>eDiscovery Searches</td><td>$($Result.EDiscoverySearches.Count)</td></tr>
  <tr><td>DLP Policy Changes</td><td>$($Result.DLPPolicyChanges.Count)</td></tr>
  <tr><td>External Sharing Changes</td><td>$($Result.ExternalSharingChanges.Count)</td></tr>
  <tr><td>Teams External Access</td><td>$($Result.TeamsExternalAccessChanges.Count)</td></tr>
  <tr><td>Bulk File Exfiltrations</td><td>$($Result.BulkFileExfiltrations.Count)</td></tr>
  <tr><td>Power Automate Flows</td><td>$($Result.PowerAutomateFlows.Count)</td></tr>
  <tr><td>Defender Alert Changes</td><td>$($Result.DefenderAlertChanges.Count)</td></tr>
  <tr><td>Audit Log Disablements</td><td>$($Result.AuditLogDisablements.Count)</td></tr>
</table>
"@)

    # --- Footer ---
    [void]$html.Append(@"
<div style="margin-top: 40px; padding-top: 16px; border-top: 2px solid var(--border);
            color: var(--dim); font-size: 0.8em; text-align: center; letter-spacing: 1px;">
  &#x1f50a; Guerrilla Wiretap Report &nbsp;|&nbsp;
  $(& $esc $timestampStr) &nbsp;|&nbsp;
  Tenant: $(& $esc $TenantId) &nbsp;|&nbsp;
  $($TotalEvents.ToString('N0')) events &nbsp;|&nbsp;
  $totalFlagged flagged change(s) &nbsp;|&nbsp;
  Guerrilla Score: $guerrillaScore ($($scoreInfo.Label))
  <br>By Jim Tyler, Microsoft MVP &nbsp;|&nbsp; <a href="https://github.com/jimrtyler" style="color:var(--dim)">GitHub</a> &nbsp;|&nbsp; <a href="https://linkedin.com/in/jamestyler" style="color:var(--dim)">LinkedIn</a> &nbsp;|&nbsp; <a href="https://youtube.com/@jimrtyler" style="color:var(--dim)">YouTube</a>
</div>
</body>
</html>
"@)

    [System.IO.File]::WriteAllText($OutputPath, $html.ToString(), [System.Text.Encoding]::UTF8)
}
