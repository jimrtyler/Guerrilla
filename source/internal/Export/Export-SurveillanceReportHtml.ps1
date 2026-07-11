# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-SurveillanceReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Profiles,

        [int]$AllProfilesCount,
        [int]$CleanCount,
        [int]$AllEventsCount,
        [int]$DaysBack,
        [string]$TimestampStr,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    # Count by level
    $levelCounts = @{}
    foreach ($p in $Profiles) {
        $levelCounts[$p.ThreatLevel] = ($levelCounts[$p.ThreatLevel] ?? 0) + 1
    }

    $critCount = $levelCounts['CRITICAL'] ?? 0
    $highCount = $levelCounts['HIGH'] ?? 0
    $medCount  = $levelCounts['MEDIUM'] ?? 0
    $lowCount  = $levelCounts['LOW'] ?? 0

    # --- Guerrilla Score calculation ---
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
<title>Guerrilla Surveillance Report - $(& $esc $TimestampStr)</title>
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
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
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
  .badge-clean { background: var(--clean); color: #d4c9a8; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 0.9em; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--surface); font-weight: 700; font-size: 0.8em; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
  tr:hover { background: rgba(168, 181, 139, 0.05); }

  /* IP tags */
  .ip-tag {
    display: inline-block; padding: 1px 5px; border-radius: 2px;
    font-size: 0.75em; margin: 1px 2px; font-family: 'Courier New', monospace;
    letter-spacing: 0.5px; text-transform: uppercase;
  }
  .ip-attacker { background: rgba(199, 92, 46, 0.25); color: var(--critical); border: 1px solid var(--critical); }
  .ip-cloud { background: rgba(212, 136, 58, 0.2); color: var(--high); border: 1px solid var(--high); }
  .ip-tor { background: rgba(107, 76, 138, 0.3); color: #a87cc9; border: 1px solid #6b4c8a; }
  .ip-vpn { background: rgba(58, 107, 138, 0.3); color: #5a9bc9; border: 1px solid #3a6b8a; }
  .ip-proxy { background: rgba(138, 132, 104, 0.3); color: var(--dim); border: 1px solid var(--dim); }

  .indicator {
    display: block; background: var(--surface); border-left: 3px solid var(--amber);
    padding: 4px 10px; margin: 4px 0; font-size: 0.85em;
  }

  /* Collapsible user details */
  details.user-detail {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; margin-bottom: 12px;
  }
  details.user-detail summary {
    padding: 12px 16px; cursor: pointer; list-style: none;
    display: flex; align-items: center; gap: 12px;
  }
  details.user-detail summary::-webkit-details-marker { display: none; }
  details.user-detail summary::before {
    content: '\25b6'; font-size: 0.7em; color: var(--dim); transition: transform 0.2s;
  }
  details.user-detail[open] summary::before { transform: rotate(90deg); }
  details.user-detail .detail-body { padding: 0 16px 16px; }

  .signal-section {
    background: rgba(199, 92, 46, 0.08); border: 1px solid rgba(199, 92, 46, 0.25);
    border-radius: 4px; padding: 14px; margin: 12px 0;
  }
  .signal-section h4 { color: var(--amber); margin-top: 0; }

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
    .score-panel, .stat-card, .user-detail, .attack-section, .signal-section, .exec-summary { border-color: #ccc; background: #f9f9f9; }
    details.user-detail { break-inside: avoid; }
  }
</style>
</head>
<body>
<h1>&#x2694; Guerrilla Surveillance Report</h1>
<div class="subtitle">
  Generated $(& $esc $TimestampStr) &mdash;
  $($AllEventsCount.ToString('N0')) events analyzed across $DaysBack days &mdash; Entra ID
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
    <div class="desc">Entra ID security posture score. Higher is better. Based on $($Profiles.Count) flagged identity(ies) out of $AllProfilesCount total.</div>
  </div>
</div>
"@)

    # --- Executive Summary ---
    $summaryVerdict = if ($critCount -gt 0) {
        "Immediate action required. $critCount identity(ies) show critical indicators of compromise."
    } elseif ($highCount -gt 0) {
        "Investigation recommended. $highCount identity(ies) show high-severity indicators."
    } elseif ($medCount -gt 0) {
        "Monitor closely. $medCount identity(ies) show moderate indicators that warrant review."
    } elseif ($lowCount -gt 0) {
        "Low-level signals detected. $lowCount identity(ies) have minor anomalies. No immediate action needed."
    } else {
        "No threats detected. All $AllProfilesCount identities appear clean."
    }

    [void]$html.Append(@"
<div class="exec-summary">
  <h3>Executive Summary</h3>
  <p><strong>Assessment:</strong> $summaryVerdict</p>
  <p><strong>Scope:</strong> $($AllProfilesCount.ToString('N0')) identities, $($AllEventsCount.ToString('N0')) events over $DaysBack days.</p>
  <p><strong>Findings:</strong> $($Profiles.Count) identity(ies) flagged &mdash; $critCount critical, $highCount high, $medCount medium, $lowCount low.</p>
</div>
"@)

    # --- Summary Stats ---
    [void]$html.Append('<div class="stat-grid">')
    [void]$html.Append(@"
  <div class="stat-card"><div class="value" style="color:var(--parchment)">$($AllProfilesCount.ToString('N0'))</div><div class="label">Identities Scanned</div></div>
  <div class="stat-card"><div class="value" style="color:var(--critical)">$critCount</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="value" style="color:var(--high)">$highCount</div><div class="label">High</div></div>
  <div class="stat-card"><div class="value" style="color:var(--medium)">$medCount</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="value" style="color:var(--low)">$lowCount</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="value" style="color:var(--clean)">$($CleanCount.ToString('N0'))</div><div class="label">Clean</div></div>
"@)
    [void]$html.Append('</div>')

    # --- Detection Signals Reference ---
    [void]$html.Append(@'
<div class="attack-section">
  <h3>Entra ID Detection Signals</h3>
  <p style="margin-bottom:8px;">This assessment scans for the following Entra ID indicators of compromise:</p>
  <table>
    <tr><th>Signal</th><th>Source</th><th>Description</th></tr>
    <tr><td>Leaked Credentials</td><td>Risk Detection</td><td>User credentials found exposed in dark web or paste sites</td></tr>
    <tr><td>Impossible Travel</td><td>Risk Detection</td><td>Logins from geographically impossible locations within short timeframes</td></tr>
    <tr><td>Password Spray</td><td>Risk Detection</td><td>Multiple accounts targeted with common passwords</td></tr>
    <tr><td>Anonymous IP Sign-In</td><td>Risk Detection</td><td>Sign-in from anonymizing services (Tor, VPN, proxy)</td></tr>
    <tr><td>Malware IP Sign-In</td><td>Risk Detection</td><td>Sign-in from IP addresses associated with malware C2</td></tr>
    <tr><td>Anomalous Token</td><td>Risk Detection</td><td>Unusual token characteristics indicating token theft or replay</td></tr>
    <tr><td>Federation Change</td><td>Directory Audit</td><td>Domain federation settings modified (potential backdoor)</td></tr>
    <tr><td>Global Admin Assignment</td><td>Directory Audit</td><td>Global Administrator role assigned to an identity</td></tr>
    <tr><td>CA Policy Change</td><td>Directory Audit</td><td>Conditional Access policy created, modified, or deleted</td></tr>
    <tr><td>Service Principal Creds</td><td>Directory Audit</td><td>Credentials added to a service principal or application</td></tr>
    <tr><td>App Permission Grant</td><td>Directory Audit</td><td>Application granted high-privilege API permissions</td></tr>
    <tr><td>Cloud IP Sign-In</td><td>Sign-In Log</td><td>Sign-in from cloud/hosting provider IP address</td></tr>
    <tr><td>Foreign Country Sign-In</td><td>Sign-In Log</td><td>Sign-in from flagged high-risk country</td></tr>
    <tr><td>Risky Sign-In</td><td>Sign-In Log</td><td>Sign-in flagged at risk level by Entra ID Protection</td></tr>
  </table>
</div>
'@)

    # --- Threat Level Breakdown Bars ---
    if ($Profiles.Count -gt 0) {
        $maxBar = 40
        $rawMax = @($critCount, $highCount, $medCount, $lowCount) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
        $maxCount = [Math]::Max(1, $rawMax)

        [void]$html.Append('<h2>Threat Level Breakdown</h2>')
        [void]$html.Append('<div style="margin-bottom:24px">')

        if ($critCount -gt 0) {
            $barWidth = [Math]::Max(2, [Math]::Round($critCount / $maxCount * $maxBar))
            [void]$html.Append("<div style=`"margin:6px 0;display:flex;align-items:center;gap:10px`"><span style=`"width:90px;color:var(--critical);font-weight:700`">CRITICAL</span><span style=`"color:var(--text);width:30px;text-align:right`">$critCount</span><div style=`"background:var(--critical);height:18px;width:${barWidth}%;border-radius:2px`"></div></div>")
        }
        if ($highCount -gt 0) {
            $barWidth = [Math]::Max(2, [Math]::Round($highCount / $maxCount * $maxBar))
            [void]$html.Append("<div style=`"margin:6px 0;display:flex;align-items:center;gap:10px`"><span style=`"width:90px;color:var(--high);font-weight:700`">HIGH</span><span style=`"color:var(--text);width:30px;text-align:right`">$highCount</span><div style=`"background:var(--high);height:18px;width:${barWidth}%;border-radius:2px`"></div></div>")
        }
        if ($medCount -gt 0) {
            $barWidth = [Math]::Max(2, [Math]::Round($medCount / $maxCount * $maxBar))
            [void]$html.Append("<div style=`"margin:6px 0;display:flex;align-items:center;gap:10px`"><span style=`"width:90px;color:var(--medium);font-weight:700`">MEDIUM</span><span style=`"color:var(--text);width:30px;text-align:right`">$medCount</span><div style=`"background:var(--medium);height:18px;width:${barWidth}%;border-radius:2px`"></div></div>")
        }
        if ($lowCount -gt 0) {
            $barWidth = [Math]::Max(2, [Math]::Round($lowCount / $maxCount * $maxBar))
            [void]$html.Append("<div style=`"margin:6px 0;display:flex;align-items:center;gap:10px`"><span style=`"width:90px;color:var(--low);font-weight:700`">LOW</span><span style=`"color:var(--text);width:30px;text-align:right`">$lowCount</span><div style=`"background:var(--low);height:18px;width:${barWidth}%;border-radius:2px`"></div></div>")
        }

        [void]$html.Append('</div>')
    }

    # --- Flagged Identities Summary Table ---
    [void]$html.Append('<h2>Flagged Identities</h2>')
    if ($Profiles.Count -eq 0) {
        [void]$html.Append('<p style="color:var(--sage)">No identities flagged. All accounts appear clean.</p>')
    } else {
        [void]$html.Append('<table><tr><th>Identity</th><th>Threat</th><th>Score</th><th>Risky</th><th>Travel</th><th>Anon IP</th><th>Leaked</th><th>Spray</th><th>Admin</th><th>CA</th><th>SPN</th><th>Fed</th><th>Cloud</th><th>Country</th></tr>')
        foreach ($p in $Profiles) {
            $levelClass = $p.ThreatLevel.ToLower()
            $badge = "<span class=`"badge badge-$levelClass`">$($p.ThreatLevel)</span>"

            $countOrEmpty = { param($n) if ($n -gt 0) { $n } else { '' } }

            [void]$html.Append("<tr><td><strong>$(& $esc $p.UserPrincipalName)</strong></td><td>$badge</td><td>$($p.ThreatScore.ToString('N0'))</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.RiskySignIns.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.ImpossibleTravelDetections.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.AnonymousIpSignIns.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.LeakedCredentials.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.PasswordSprayDetections.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.GlobalAdminAssignments.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.CAPolicyChanges.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.ServicePrincipalCredChanges.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.FederationChanges.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.CloudIpSignIns.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.ForeignCountrySignIns.Count)</td>")
            [void]$html.Append('</tr>')
        }
        [void]$html.Append('</table>')
    }

    # --- Detailed collapsible sections for all flagged identities ---
    $detailProfiles = @($Profiles | Where-Object { $_.ThreatScore -gt 0 })
    if ($detailProfiles.Count -gt 0) {
        [void]$html.Append('<h2>Detailed Analysis</h2>')

        foreach ($p in $detailProfiles) {
            $levelClass = $p.ThreatLevel.ToLower()
            $openAttr = if ($p.ThreatLevel -in @('CRITICAL', 'HIGH')) { ' open' } else { '' }

            [void]$html.Append("<details class=`"user-detail`"$openAttr>")
            [void]$html.Append("<summary><span class=`"badge badge-$levelClass`">$($p.ThreatLevel)</span> <strong>$(& $esc $p.UserPrincipalName)</strong> <span style=`"color:var(--dim)`">&mdash; Score: $($p.ThreatScore.ToString('N0'))</span></summary>")
            [void]$html.Append('<div class="detail-body">')

            # Indicators
            [void]$html.Append('<h4>Indicators</h4>')
            foreach ($ind in $p.Indicators) {
                [void]$html.Append("<div class=`"indicator`">$(& $esc $ind)</div>")
            }

            # --- Risk Detection signals ---

            # Impossible Travel
            if ($p.ImpossibleTravelDetections -and $p.ImpossibleTravelDetections.Count -gt 0) {
                [void]$html.Append('<div class="signal-section"><h4>Impossible Travel Detections</h4>')
                [void]$html.Append('<table><tr><th>Time</th><th>Risk Level</th><th>IP</th><th>Location</th><th>Detail</th></tr>')
                foreach ($det in $p.ImpossibleTravelDetections) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td><span class=`"badge badge-$($det.RiskLevel.ToLower())`">$(& $esc $det.RiskLevel)</span></td><td><code>$(& $esc $det.IpAddress)</code></td><td>$(& $esc $det.Location)</td><td style=`"font-size:0.85em`">$(& $esc $det.AdditionalInfo)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Leaked Credentials
            if ($p.LeakedCredentials -and $p.LeakedCredentials.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`" style=`"border-color:var(--critical)`"><h4>Leaked Credentials ($($p.LeakedCredentials.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Risk Level</th><th>Detail</th></tr>')
                foreach ($det in $p.LeakedCredentials) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td><span class=`"badge badge-$($det.RiskLevel.ToLower())`">$(& $esc $det.RiskLevel)</span></td><td style=`"font-size:0.85em`">$(& $esc $det.AdditionalInfo)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Password Spray
            if ($p.PasswordSprayDetections -and $p.PasswordSprayDetections.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Password Spray Detections ($($p.PasswordSprayDetections.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Risk Level</th><th>IP</th><th>Detail</th></tr>')
                foreach ($det in $p.PasswordSprayDetections) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td><span class=`"badge badge-$($det.RiskLevel.ToLower())`">$(& $esc $det.RiskLevel)</span></td><td><code>$(& $esc $det.IpAddress)</code></td><td style=`"font-size:0.85em`">$(& $esc $det.AdditionalInfo)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Anonymous IP Sign-Ins
            if ($p.AnonymousIpSignIns -and $p.AnonymousIpSignIns.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Anonymous IP Sign-Ins ($($p.AnonymousIpSignIns.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Risk Level</th><th>IP</th><th>Location</th></tr>')
                foreach ($det in $p.AnonymousIpSignIns) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td><span class=`"badge badge-$($det.RiskLevel.ToLower())`">$(& $esc $det.RiskLevel)</span></td><td><code>$(& $esc $det.IpAddress)</code></td><td>$(& $esc $det.Location)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Anomalous Tokens
            if ($p.AnomalousTokenDetections -and $p.AnomalousTokenDetections.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Anomalous Token Detections ($($p.AnomalousTokenDetections.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Risk Level</th><th>IP</th><th>Detail</th></tr>')
                foreach ($det in $p.AnomalousTokenDetections) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td><span class=`"badge badge-$($det.RiskLevel.ToLower())`">$(& $esc $det.RiskLevel)</span></td><td><code>$(& $esc $det.IpAddress)</code></td><td style=`"font-size:0.85em`">$(& $esc $det.AdditionalInfo)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # --- Audit-based signals ---

            # Global Admin Assignments
            if ($p.GlobalAdminAssignments -and $p.GlobalAdminAssignments.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`" style=`"border-color:var(--critical)`"><h4>Global Admin Assignments ($($p.GlobalAdminAssignments.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Target</th><th>Operation</th><th>Detail</th></tr>')
                foreach ($det in $p.GlobalAdminAssignments) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td>$(& $esc $det.TargetUser)</td><td>$(& $esc $det.OperationType)</td><td style=`"font-size:0.85em`">$(& $esc $det.Detail)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # CA Policy Changes
            if ($p.CAPolicyChanges -and $p.CAPolicyChanges.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Conditional Access Policy Changes ($($p.CAPolicyChanges.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Policy</th><th>Operation</th><th>Detail</th></tr>')
                foreach ($det in $p.CAPolicyChanges) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td>$(& $esc $det.PolicyName)</td><td>$(& $esc $det.OperationType)</td><td style=`"font-size:0.85em`">$(& $esc $det.Detail)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Service Principal Credential Changes
            if ($p.ServicePrincipalCredChanges -and $p.ServicePrincipalCredChanges.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Service Principal Credential Changes ($($p.ServicePrincipalCredChanges.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>App</th><th>Operation</th><th>Detail</th></tr>')
                foreach ($det in $p.ServicePrincipalCredChanges) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td>$(& $esc $det.AppDisplayName)</td><td>$(& $esc $det.OperationType)</td><td style=`"font-size:0.85em`">$(& $esc $det.Detail)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Federation Changes
            if ($p.FederationChanges -and $p.FederationChanges.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`" style=`"border-color:var(--critical)`"><h4>Federation Domain Changes ($($p.FederationChanges.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>Domain</th><th>Operation</th><th>Detail</th></tr>')
                foreach ($det in $p.FederationChanges) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td>$(& $esc $det.DomainName)</td><td>$(& $esc $det.OperationType)</td><td style=`"font-size:0.85em`">$(& $esc $det.Detail)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # App Permission Grants
            if ($p.AppPermissionGrants -and $p.AppPermissionGrants.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Application Permission Grants ($($p.AppPermissionGrants.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>App</th><th>Permission</th><th>Detail</th></tr>')
                foreach ($det in ($p.AppPermissionGrants | Select-Object -First 10)) {
                    $detTs = if ($det.Timestamp -is [datetime]) { $det.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $det.Timestamp }
                    [void]$html.Append("<tr><td>$detTs</td><td>$(& $esc $det.AppDisplayName)</td><td>$(& $esc $det.Permission)</td><td style=`"font-size:0.85em`">$(& $esc $det.Detail)</td></tr>")
                }
                if ($p.AppPermissionGrants.Count -gt 10) {
                    [void]$html.Append("<tr><td colspan=`"4`" style=`"color:var(--dim)`">... and $($p.AppPermissionGrants.Count - 10) more</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # --- Sign-in based signals ---

            # Cloud IP Sign-Ins
            if ($p.CloudIpSignIns -and $p.CloudIpSignIns.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Cloud/Hosting IP Sign-Ins ($($p.CloudIpSignIns.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>IP</th><th>Type</th><th>App</th></tr>')
                foreach ($evt in ($p.CloudIpSignIns | Select-Object -First 10)) {
                    $evtTs = if ($evt.Timestamp -is [datetime]) { $evt.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $evt.Timestamp }
                    $tag = if ($evt.IpClass -eq 'known_attacker') {
                        '<span class="ip-tag ip-attacker">Attacker</span>'
                    } elseif ($evt.IpClass -and $script:CloudProviderClasses -and $script:CloudProviderClasses.Contains($evt.IpClass)) {
                        "<span class=`"ip-tag ip-cloud`">$($evt.IpClass.ToUpper())</span>"
                    } else {
                        "<span class=`"ip-tag ip-cloud`">Cloud</span>"
                    }
                    [void]$html.Append("<tr><td>$evtTs</td><td><code>$(& $esc $evt.IpAddress)</code> $tag</td><td>$(& $esc $evt.IpClass)</td><td>$(& $esc $evt.AppDisplayName)</td></tr>")
                }
                if ($p.CloudIpSignIns.Count -gt 10) {
                    [void]$html.Append("<tr><td colspan=`"4`" style=`"color:var(--dim)`">... and $($p.CloudIpSignIns.Count - 10) more</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Foreign Country Sign-Ins
            if ($p.ForeignCountrySignIns -and $p.ForeignCountrySignIns.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>Foreign Country Sign-Ins ($($p.ForeignCountrySignIns.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>IP</th><th>Country</th><th>App</th></tr>')
                foreach ($evt in ($p.ForeignCountrySignIns | Select-Object -First 10)) {
                    $evtTs = if ($evt.Timestamp -is [datetime]) { $evt.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $evt.Timestamp }
                    [void]$html.Append("<tr><td>$evtTs</td><td><code>$(& $esc $evt.IpAddress)</code></td><td>$(& $esc $evt.GeoCountry)</td><td>$(& $esc $evt.AppDisplayName)</td></tr>")
                }
                if ($p.ForeignCountrySignIns.Count -gt 10) {
                    [void]$html.Append("<tr><td colspan=`"4`" style=`"color:var(--dim)`">... and $($p.ForeignCountrySignIns.Count - 10) more</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # VPN/Tor Sign-Ins
            if ($p.VpnTorSignIns -and $p.VpnTorSignIns.Count -gt 0) {
                [void]$html.Append("<div class=`"signal-section`"><h4>VPN/Tor/Proxy Sign-Ins ($($p.VpnTorSignIns.Count))</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>IP</th><th>Type</th><th>App</th></tr>')
                foreach ($evt in ($p.VpnTorSignIns | Select-Object -First 10)) {
                    $evtTs = if ($evt.Timestamp -is [datetime]) { $evt.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $evt.Timestamp }
                    $tag = switch ($evt.IpClass) {
                        'tor'   { '<span class="ip-tag ip-tor">Tor</span>' }
                        'vpn'   { '<span class="ip-tag ip-vpn">VPN</span>' }
                        'proxy' { '<span class="ip-tag ip-proxy">Proxy</span>' }
                        default { '' }
                    }
                    [void]$html.Append("<tr><td>$evtTs</td><td><code>$(& $esc $evt.IpAddress)</code> $tag</td><td>$(& $esc $evt.IpClass)</td><td>$(& $esc $evt.AppDisplayName)</td></tr>")
                }
                if ($p.VpnTorSignIns.Count -gt 10) {
                    [void]$html.Append("<tr><td colspan=`"4`" style=`"color:var(--dim)`">... and $($p.VpnTorSignIns.Count - 10) more</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # IP breakdown
            if ($p.IpClassifications.Count -gt 0) {
                [void]$html.Append('<h4>IP Address Breakdown</h4>')
                [void]$html.Append('<table><tr><th>IP</th><th>Type</th><th>Country</th><th>Events</th></tr>')

                $sortedIps = $p.IpClassifications.GetEnumerator() | Sort-Object {
                    switch ($_.Value.Class) {
                        'known_attacker' { 0 }
                        'tor'            { 1 }
                        { $_ -and $script:CloudProviderClasses -and $script:CloudProviderClasses.Contains($_) } { 2 }
                        'vpn'            { 3 }
                        'proxy'          { 4 }
                        default          { 5 }
                    }
                }

                foreach ($entry in $sortedIps) {
                    $ip = $entry.Key
                    $info = $entry.Value
                    $tag = if ($info.Class -eq 'known_attacker') {
                        '<span class="ip-tag ip-attacker">Attacker</span>'
                    } elseif ($info.Class -eq 'tor') {
                        '<span class="ip-tag ip-tor">Tor</span>'
                    } elseif ($info.Class -eq 'vpn') {
                        '<span class="ip-tag ip-vpn">VPN</span>'
                    } elseif ($info.Class -eq 'proxy') {
                        '<span class="ip-tag ip-proxy">Proxy</span>'
                    } elseif ($info.Class -and $script:CloudProviderClasses -and $script:CloudProviderClasses.Contains($info.Class)) {
                        "<span class=`"ip-tag ip-cloud`">$($info.Class.ToUpper())</span>"
                    } else {
                        '<span style="color:var(--dim)">Residential</span>'
                    }

                    $country = if ($info.Country) { $info.Country } else { '&mdash;' }

                    $eventCounts = @{}
                    foreach ($evt in $info.Events) {
                        $eventCounts[$evt] = ($eventCounts[$evt] ?? 0) + 1
                    }
                    $eventsSummary = ($eventCounts.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)($($_.Value))" }) -join ', '

                    [void]$html.Append("<tr><td><code>$(& $esc $ip)</code></td><td>$tag</td><td>$(& $esc $country)</td><td style=`"font-size:0.8em`">$(& $esc $eventsSummary)</td></tr>")
                }
                [void]$html.Append('</table>')
            }

            [void]$html.Append('</div></details>')
        }
    }

    # --- Footer ---
    [void]$html.Append(@"
<div style="margin-top: 40px; padding-top: 16px; border-top: 2px solid var(--border);
            color: var(--dim); font-size: 0.8em; text-align: center; letter-spacing: 1px;">
  &#x2694; Guerrilla Surveillance Report &nbsp;|&nbsp;
  $(& $esc $TimestampStr) &nbsp;|&nbsp;
  $($AllEventsCount.ToString('N0')) events &nbsp;|&nbsp; $($AllProfilesCount.ToString('N0')) identities &nbsp;|&nbsp;
  Guerrilla Score: $guerrillaScore ($($scoreInfo.Label))
  <br>By Jim Tyler, Microsoft MVP &nbsp;|&nbsp; <a href="https://github.com/jimrtyler" style="color:var(--dim)">GitHub</a> &nbsp;|&nbsp; <a href="https://linkedin.com/in/jamestyler" style="color:var(--dim)">LinkedIn</a> &nbsp;|&nbsp; <a href="https://youtube.com/@jimrtyler" style="color:var(--dim)">YouTube</a>
</div>
</body>
</html>
"@)

    [System.IO.File]::WriteAllText($FilePath, $html.ToString(), [System.Text.Encoding]::UTF8)
}
