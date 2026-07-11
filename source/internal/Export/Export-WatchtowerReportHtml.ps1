# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-WatchtowerReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ChangeProfile,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$FlaggedChanges,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [datetime]$Timestamp,

        [Parameter(Mandatory)]
        [string]$ScanMode,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $timestampStr = $Timestamp.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # Count by severity
    $critCount = 0; $highCount = 0; $medCount = 0; $lowCount = 0
    $newCount = 0
    if ($FlaggedChanges) {
        foreach ($c in $FlaggedChanges) {
            switch ($c.Severity) {
                'CRITICAL' { $critCount++ }
                'HIGH'     { $highCount++ }
                'MEDIUM'   { $medCount++ }
                'LOW'      { $lowCount++ }
            }
            if ($c.IsNew) { $newCount++ }
        }
    }

    # Guerrilla Score
    $guerrillaScore = 100.0
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
<title>Guerrilla Watchtower Report - $(& $esc $timestampStr)</title>
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
  h4 { font-size: 0.95em; margin: 12px 0 8px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
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
  .badge-new {
    background: rgba(199, 92, 46, 0.2); color: var(--critical);
    border: 1px solid var(--critical); font-size: 0.7em; padding: 1px 6px;
  }

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

  /* Change categories */
  .category-grid {
    display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0;
  }
  .category-tag {
    display: inline-block; background: var(--surface); border: 1px solid var(--border);
    border-radius: 2px; padding: 4px 10px; font-size: 0.85em;
  }
  .category-tag .cat-label { color: var(--olive); }
  .category-tag .cat-count { color: var(--parchment); font-weight: 700; margin-left: 4px; }

  /* Detection signals reference */
  .attack-section {
    background: var(--surface-alt); border: 1px solid var(--border);
    border-radius: 4px; padding: 16px; margin: 16px 0;
  }
  .attack-section h3 { color: var(--parchment); margin-top: 0; }

  code { font-family: 'Courier New', Consolas, monospace; font-size: 0.9em; color: var(--olive); }
  a { color: var(--gold); }

  /* Print styles */
  @media print {
    body { background: #fff; color: #000; }
    .score-panel, .stat-card, .change-detail, .exec-summary, .attack-section { border-color: #ccc; background: #f9f9f9; }
    details.change-detail { break-inside: avoid; }
  }
</style>
</head>
<body>
<h1>&#x1f6e1; Guerrilla Watchtower Report</h1>
<div class="subtitle">
  Generated $(& $esc $timestampStr) &mdash; Domain: $(& $esc $DomainName) &mdash; Mode: $(& $esc $ScanMode) &mdash; Scan ID: $(& $esc $ScanId)
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
    <div class="value" style="color:$scoreColor">$([Math]::Round($guerrillaScore))</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$($scoreInfo.Label)</div>
    <div class="desc">Active Directory security posture score. Higher is better. Based on $totalFlagged flagged change(s) in domain $(& $esc $DomainName).</div>
  </div>
</div>
"@)

    # --- Executive Summary ---
    $summaryVerdict = if ($critCount -gt 0) {
        "Immediate action required. $critCount critical change(s) detected in Active Directory."
    } elseif ($highCount -gt 0) {
        "Investigation recommended. $highCount high-severity change(s) require review."
    } elseif ($medCount -gt 0) {
        "Monitor closely. $medCount medium-severity change(s) warrant attention."
    } elseif ($lowCount -gt 0) {
        "Low-level changes detected. $lowCount minor change(s) logged. No immediate action needed."
    } else {
        "No suspicious changes detected. Active Directory appears clean."
    }

    [void]$html.Append(@"
<div class="exec-summary">
  <h3>Executive Summary</h3>
  <p><strong>Assessment:</strong> $summaryVerdict</p>
  <p><strong>Domain:</strong> $(& $esc $DomainName) &mdash; Scan Mode: $(& $esc $ScanMode) &mdash; Scan ID: <code>$(& $esc $ScanId)</code></p>
  <p><strong>Findings:</strong> $totalFlagged change(s) flagged &mdash; $critCount critical, $highCount high, $medCount medium, $lowCount low.</p>
"@)
    if ($newCount -gt 0) {
        [void]$html.Append("<p style=`"color:var(--critical)`"><strong>&#9888; $newCount NEW threat(s) detected since last scan.</strong> These require immediate investigation.</p>")
    }
    [void]$html.Append('</div>')

    # --- Summary Stats ---
    [void]$html.Append('<div class="stat-grid">')
    [void]$html.Append(@"
  <div class="stat-card"><div class="value" style="color:var(--critical)">$critCount</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="value" style="color:var(--high)">$highCount</div><div class="label">High</div></div>
  <div class="stat-card"><div class="value" style="color:var(--medium)">$medCount</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="value" style="color:var(--low)">$lowCount</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="value" style="color:var(--parchment)">$totalFlagged</div><div class="label">Total Flagged</div></div>
  <div class="stat-card"><div class="value" style="color:var(--amber)">$newCount</div><div class="label">New Threats</div></div>
"@)
    [void]$html.Append('</div>')

    # --- Change Categories ---
    $categories = [System.Collections.Generic.List[string[]]]::new()
    if ($ChangeProfile.GroupChanges.Count -gt 0) { $categories.Add(@('Group Membership', "$($ChangeProfile.GroupChanges.Count)")) }
    if ($ChangeProfile.GPOChanges.Count -gt 0) { $categories.Add(@('Group Policy Objects', "$($ChangeProfile.GPOChanges.Count)")) }
    if ($ChangeProfile.GPOLinkChanges.Count -gt 0) { $categories.Add(@('GPO Links', "$($ChangeProfile.GPOLinkChanges.Count)")) }
    if ($ChangeProfile.TrustChanges.Count -gt 0) { $categories.Add(@('Trust Relationships', "$($ChangeProfile.TrustChanges.Count)")) }
    if ($ChangeProfile.ACLChanges.Count -gt 0) { $categories.Add(@('ACL Permissions', "$($ChangeProfile.ACLChanges.Count)")) }
    if ($ChangeProfile.AdminSDHolderChanged) { $categories.Add(@('AdminSDHolder', '1')) }
    if ($ChangeProfile.KrbtgtChanged) { $categories.Add(@('krbtgt Account', '1')) }
    if ($ChangeProfile.CertTemplateChanges.Count -gt 0) { $categories.Add(@('Certificate Templates', "$($ChangeProfile.CertTemplateChanges.Count)")) }
    if ($ChangeProfile.DelegationChanges.Count -gt 0) { $categories.Add(@('Delegations', "$($ChangeProfile.DelegationChanges.Count)")) }
    if ($ChangeProfile.DNSChanges.Count -gt 0) { $categories.Add(@('DNS Records', "$($ChangeProfile.DNSChanges.Count)")) }
    if ($ChangeProfile.SchemaChanges.Count -gt 0) { $categories.Add(@('Schema', "$($ChangeProfile.SchemaChanges.Count)")) }
    if ($ChangeProfile.NewComputers.Count -gt 0) { $categories.Add(@('New Computers', "$($ChangeProfile.NewComputers.Count)")) }
    if ($ChangeProfile.NewServiceAccounts.Count -gt 0) { $categories.Add(@('New Service Accounts', "$($ChangeProfile.NewServiceAccounts.Count)")) }

    if ($categories.Count -gt 0) {
        [void]$html.Append('<h2>Change Categories</h2>')
        [void]$html.Append('<div class="category-grid">')
        foreach ($cat in $categories) {
            [void]$html.Append("<span class=`"category-tag`"><span class=`"cat-label`">$(& $esc $cat[0])</span><span class=`"cat-count`">$($cat[1])</span></span>")
        }
        [void]$html.Append('</div>')
    }

    # --- Threat Breakdown Table ---
    [void]$html.Append('<h2>Threat Breakdown</h2>')
    if ($FlaggedChanges -and $FlaggedChanges.Count -gt 0) {
        # Group by detection type
        $typeGroups = @{}
        foreach ($c in $FlaggedChanges) {
            $type = if ($c.DetectionType) { $c.DetectionType } else { 'Unknown' }
            if (-not $typeGroups.ContainsKey($type)) {
                $typeGroups[$type] = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0; New = 0 }
            }
            $typeGroups[$type].Total++
            if ($c.IsNew) { $typeGroups[$type].New++ }
            switch ($c.Severity) {
                'CRITICAL' { $typeGroups[$type].Critical++ }
                'HIGH'     { $typeGroups[$type].High++ }
                'MEDIUM'   { $typeGroups[$type].Medium++ }
                'LOW'      { $typeGroups[$type].Low++ }
            }
        }

        [void]$html.Append('<table><tr><th>Detection Type</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>New</th><th>Total</th></tr>')
        foreach ($entry in ($typeGroups.GetEnumerator() | Sort-Object { $_.Value.Total } -Descending)) {
            $g = $entry.Value
            $countOrEmpty = { param($n) if ($n -gt 0) { $n } else { '' } }
            [void]$html.Append("<tr><td><strong>$(& $esc $entry.Key)</strong></td>")
            [void]$html.Append("<td style=`"color:var(--critical)`">$(& $countOrEmpty $g.Critical)</td>")
            [void]$html.Append("<td style=`"color:var(--high)`">$(& $countOrEmpty $g.High)</td>")
            [void]$html.Append("<td style=`"color:var(--medium)`">$(& $countOrEmpty $g.Medium)</td>")
            [void]$html.Append("<td style=`"color:var(--low)`">$(& $countOrEmpty $g.Low)</td>")
            [void]$html.Append("<td style=`"color:var(--amber)`">$(& $countOrEmpty $g.New)</td>")
            [void]$html.Append("<td>$($g.Total)</td></tr>")
        }
        [void]$html.Append('</table>')
    } else {
        [void]$html.Append('<p style="color:var(--sage)">No suspicious changes detected. Active Directory appears clean.</p>')
    }

    # --- Flagged Changes Detail ---
    if ($FlaggedChanges -and $FlaggedChanges.Count -gt 0) {
        [void]$html.Append('<h2>Flagged Changes</h2>')

        $severityOrder = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3 }
        $sorted = $FlaggedChanges | Sort-Object {
            if ($severityOrder.ContainsKey($_.Severity)) { $severityOrder[$_.Severity] } else { 99 }
        }

        [void]$html.Append('<table><tr><th>Detection</th><th>Severity</th><th>Score</th><th>New</th><th>Description</th></tr>')
        foreach ($c in $sorted) {
            $levelClass = $c.Severity.ToLower()
            $badge = "<span class=`"badge badge-$levelClass`">$($c.Severity)</span>"
            $newBadge = if ($c.IsNew) { ' <span class="badge badge-new">NEW</span>' } else { '' }

            $descText = & $esc $c.Description
            if ($descText.Length -gt 120) {
                $descText = $descText.Substring(0, 117) + '...'
            }

            [void]$html.Append('<tr>')
            [void]$html.Append("<td><strong>$(& $esc $c.DetectionName)</strong></td>")
            [void]$html.Append("<td>$badge</td>")
            [void]$html.Append("<td>$($c.Score.ToString('N0'))</td>")
            [void]$html.Append("<td>$newBadge</td>")
            [void]$html.Append("<td style=`"font-size:0.85em`">$descText</td>")
            [void]$html.Append('</tr>')
        }
        [void]$html.Append('</table>')

        # Collapsible detail sections for critical/high changes
        $detailChanges = @($sorted | Where-Object { $_.Severity -in @('CRITICAL', 'HIGH') })
        if ($detailChanges.Count -gt 0) {
            [void]$html.Append('<h2>Detailed Analysis</h2>')
            foreach ($c in $detailChanges) {
                $levelClass = $c.Severity.ToLower()
                $openAttr = if ($c.Severity -eq 'CRITICAL') { ' open' } else { '' }
                $newTag = if ($c.IsNew) { ' <span class="badge badge-new">NEW</span>' } else { '' }

                [void]$html.Append("<details class=`"change-detail`"$openAttr>")
                [void]$html.Append("<summary><span class=`"badge badge-$levelClass`">$($c.Severity)</span> <strong>$(& $esc $c.DetectionName)</strong>$newTag <span style=`"color:var(--dim)`">&mdash; Score: $($c.Score.ToString('N0'))</span></summary>")
                [void]$html.Append('<div class="detail-body">')

                [void]$html.Append("<p><strong>Detection ID:</strong> <code>$(& $esc $c.DetectionId)</code></p>")
                [void]$html.Append("<p><strong>Type:</strong> $(& $esc $c.DetectionType)</p>")
                [void]$html.Append("<p><strong>Description:</strong> $(& $esc $c.Description)</p>")

                # Render details hashtable if present
                if ($c.Details -and $c.Details -is [hashtable] -and $c.Details.Count -gt 0) {
                    [void]$html.Append('<h4>Details</h4>')
                    [void]$html.Append('<table>')

                    foreach ($key in ($c.Details.Keys | Sort-Object)) {
                        $val = $c.Details[$key]

                        if ($null -eq $val) { continue }

                        if ($val -is [array] -and $val.Count -gt 0) {
                            # Array of hashtables (e.g., Changes array)
                            if ($val[0] -is [hashtable]) {
                                [void]$html.Append("<tr><td colspan=`"2`"><strong>$(& $esc $key)</strong> ($($val.Count) item(s))</td></tr>")
                                foreach ($item in ($val | Select-Object -First 10)) {
                                    $parts = [System.Collections.Generic.List[string]]::new()
                                    foreach ($iKey in ($item.Keys | Sort-Object)) {
                                        $iVal = $item[$iKey]
                                        if ($iVal -is [array]) { $iVal = $iVal -join '; ' }
                                        $parts.Add("$(& $esc $iKey)=$(& $esc ([string]$iVal))")
                                    }
                                    [void]$html.Append("<tr><td></td><td style=`"font-size:0.85em`"><code>$($parts -join ' | ')</code></td></tr>")
                                }
                                if ($val.Count -gt 10) {
                                    [void]$html.Append("<tr><td></td><td style=`"color:var(--dim)`">... and $($val.Count - 10) more</td></tr>")
                                }
                            } else {
                                # Array of simple values
                                [void]$html.Append("<tr><td><strong>$(& $esc $key)</strong></td><td><code>$(& $esc ($val -join '; '))</code></td></tr>")
                            }
                        } elseif ($val -is [hashtable]) {
                            # Nested hashtable
                            $subParts = $val.GetEnumerator() | ForEach-Object { "$(& $esc $_.Key)=$(& $esc ([string]$_.Value))" }
                            [void]$html.Append("<tr><td><strong>$(& $esc $key)</strong></td><td><code>$($subParts -join ' | ')</code></td></tr>")
                        } else {
                            [void]$html.Append("<tr><td><strong>$(& $esc $key)</strong></td><td>$(& $esc ([string]$val))</td></tr>")
                        }
                    }
                    [void]$html.Append('</table>')
                }

                [void]$html.Append('</div></details>')
            }
        }

        # Medium/Low summary for completeness
        $medLowChanges = @($sorted | Where-Object { $_.Severity -in @('MEDIUM', 'LOW') })
        if ($medLowChanges.Count -gt 0) {
            [void]$html.Append('<h2>Additional Findings</h2>')
            foreach ($c in $medLowChanges) {
                $levelClass = $c.Severity.ToLower()
                $newTag = if ($c.IsNew) { ' <span class="badge badge-new">NEW</span>' } else { '' }

                [void]$html.Append("<details class=`"change-detail`">")
                [void]$html.Append("<summary><span class=`"badge badge-$levelClass`">$($c.Severity)</span> <strong>$(& $esc $c.DetectionName)</strong>$newTag <span style=`"color:var(--dim)`">&mdash; Score: $($c.Score.ToString('N0'))</span></summary>")
                [void]$html.Append('<div class="detail-body">')
                [void]$html.Append("<p><strong>Detection ID:</strong> <code>$(& $esc $c.DetectionId)</code></p>")
                [void]$html.Append("<p><strong>Description:</strong> $(& $esc $c.Description)</p>")

                if ($c.Details -and $c.Details -is [hashtable] -and $c.Details.Count -gt 0) {
                    [void]$html.Append('<h4>Details</h4>')
                    foreach ($key in ($c.Details.Keys | Sort-Object)) {
                        $val = $c.Details[$key]
                        if ($null -eq $val) { continue }
                        if ($val -is [array]) {
                            [void]$html.Append("<div class=`"indicator`"><strong>$(& $esc $key):</strong> $(& $esc ($val -join '; '))</div>")
                        } elseif ($val -is [hashtable]) {
                            $subParts = $val.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
                            [void]$html.Append("<div class=`"indicator`"><strong>$(& $esc $key):</strong> $(& $esc ($subParts -join ' | '))</div>")
                        } else {
                            [void]$html.Append("<div class=`"indicator`"><strong>$(& $esc $key):</strong> $(& $esc ([string]$val))</div>")
                        }
                    }
                }

                [void]$html.Append('</div></details>')
            }
        }
    }

    # --- Detection Signals Reference ---
    [void]$html.Append(@'
<div class="attack-section">
  <h3>Detection Signals Reference</h3>
  <p style="margin-bottom:8px;">This assessment monitors for the following Active Directory change indicators:</p>
  <table>
    <tr><th>Signal</th><th>Weight</th><th>Description</th></tr>
    <tr><td>Enterprise Admin Change</td><td>95</td><td>Membership change in Enterprise Admins group</td></tr>
    <tr><td>DCSync Permission</td><td>95</td><td>Replication permissions granted to non-standard account</td></tr>
    <tr><td>Domain Admin Change</td><td>90</td><td>Membership change in Domain Admins group</td></tr>
    <tr><td>Trust Relationship</td><td>85</td><td>New or modified Active Directory trust relationship</td></tr>
    <tr><td>AdminSDHolder Change</td><td>80</td><td>ACL modification on the AdminSDHolder container</td></tr>
    <tr><td>Schema Change</td><td>80</td><td>Active Directory schema version modification</td></tr>
    <tr><td>Privileged Group Change</td><td>70</td><td>Membership change in other privileged groups (Schema Admins, Operators, etc.)</td></tr>
    <tr><td>krbtgt Password Change</td><td>70</td><td>Password reset on the krbtgt service account</td></tr>
    <tr><td>Replication Anomaly</td><td>70</td><td>Replication permissions granted to non-DC accounts</td></tr>
    <tr><td>Certificate Template</td><td>65</td><td>Certificate template created, modified, or removed</td></tr>
    <tr><td>Delegation Change</td><td>60</td><td>OU delegation modification with dangerous rights</td></tr>
    <tr><td>Certificate Enrollment</td><td>55</td><td>Certificate template with enrollee-supplied subject and authentication EKU</td></tr>
    <tr><td>GPO Modification</td><td>50</td><td>Group Policy Object created, modified, or removed</td></tr>
    <tr><td>OU Permission Change</td><td>50</td><td>ACL modification on Organizational Unit</td></tr>
    <tr><td>GPO Link Change</td><td>45</td><td>GPO link configuration changed (linked, unlinked, enforced)</td></tr>
    <tr><td>Sensitive Password</td><td>40</td><td>Password change on privileged account</td></tr>
    <tr><td>DNS Record Change</td><td>35</td><td>DNS record addition or removal (especially wpad, isatap, _msdcs)</td></tr>
    <tr><td>Service Account Creation</td><td>30</td><td>New service account detected</td></tr>
    <tr><td>LDAP Query Anomaly</td><td>25</td><td>Burst of recently-changed objects (&gt;100/minute)</td></tr>
    <tr><td>Computer Account Creation</td><td>20</td><td>New computer account joined to domain</td></tr>
  </table>
</div>
'@)

    # --- Footer ---
    [void]$html.Append(@"
<div style="margin-top: 40px; padding-top: 16px; border-top: 2px solid var(--border);
            color: var(--dim); font-size: 0.8em; text-align: center; letter-spacing: 1px;">
  &#x1f6e1; Guerrilla Watchtower Report &nbsp;|&nbsp;
  $(& $esc $timestampStr) &nbsp;|&nbsp;
  Domain: $(& $esc $DomainName) &nbsp;|&nbsp;
  $totalFlagged flagged change(s) &nbsp;|&nbsp;
  Guerrilla Score: $([Math]::Round($guerrillaScore)) ($($scoreInfo.Label))
  <br>By Jim Tyler, Microsoft MVP &nbsp;|&nbsp; <a href="https://github.com/jimrtyler" style="color:var(--dim)">GitHub</a> &nbsp;|&nbsp; <a href="https://linkedin.com/in/jamestyler" style="color:var(--dim)">LinkedIn</a> &nbsp;|&nbsp; <a href="https://youtube.com/@jimrtyler" style="color:var(--dim)">YouTube</a>
</div>
</body>
</html>
"@)

    [System.IO.File]::WriteAllText($FilePath, $html.ToString(), [System.Text.Encoding]::UTF8)
}
