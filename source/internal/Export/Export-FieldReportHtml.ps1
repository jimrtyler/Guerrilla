# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-FieldReportHtml {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Profiles = @(),

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
<title>Guerrilla Field Report - $(& $esc $TimestampStr)</title>
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
  .badge-known { background: #6b4c8a; }
  .badge-remediated { background: #3a6b8a; }

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
<h1>&#x2694; Guerrilla Field Report</h1>
<div class="subtitle">
  Generated $(& $esc $TimestampStr) &mdash;
  $($AllEventsCount.ToString('N0')) events analyzed across $DaysBack days
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
    <div class="desc">Organization security posture score. Higher is better. Based on $($Profiles.Count) flagged user(s) out of $AllProfilesCount total.</div>
  </div>
</div>
"@)

    # --- Executive Summary ---
    $summaryVerdict = if ($critCount -gt 0) {
        "Immediate action required. $critCount user(s) show critical indicators of compromise."
    } elseif ($highCount -gt 0) {
        "Investigation recommended. $highCount user(s) show high-severity indicators."
    } elseif ($medCount -gt 0) {
        "Monitor closely. $medCount user(s) show moderate indicators that warrant review."
    } elseif ($lowCount -gt 0) {
        "Low-level signals detected. $lowCount user(s) have minor anomalies. No immediate action needed."
    } else {
        "No threats detected. All $AllProfilesCount user accounts appear clean."
    }

    $unremediatedCrit = @($Profiles | Where-Object { $_.ThreatLevel -eq 'CRITICAL' -and -not $_.WasRemediated }).Count

    [void]$html.Append(@"
<div class="exec-summary">
  <h3>Executive Summary</h3>
  <p><strong>Assessment:</strong> $summaryVerdict</p>
  <p><strong>Scope:</strong> $($AllProfilesCount.ToString('N0')) user accounts, $($AllEventsCount.ToString('N0')) events over $DaysBack days.</p>
  <p><strong>Findings:</strong> $($Profiles.Count) user(s) flagged &mdash; $critCount critical, $highCount high, $medCount medium, $lowCount low.</p>
"@)
    if ($unremediatedCrit -gt 0) {
        [void]$html.Append("<p style=`"color:var(--critical)`"><strong>&#9888; $unremediatedCrit critical user(s) have NOT been remediated.</strong> Password reset and session revocation recommended immediately.</p>")
    }
    [void]$html.Append('</div>')

    # --- Summary Stats ---
    [void]$html.Append('<div class="stat-grid">')
    [void]$html.Append(@"
  <div class="stat-card"><div class="value" style="color:var(--parchment)">$($AllProfilesCount.ToString('N0'))</div><div class="label">Users Scanned</div></div>
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
  <h3>Detection Signals</h3>
  <p style="margin-bottom:8px;">This assessment scans for the following indicators of compromise:</p>
  <table>
    <tr><th>Signal</th><th>Weight</th><th>Description</th></tr>
    <tr><td>Known Attacker IP</td><td>100</td><td>Login from IP observed across multiple confirmed compromises</td></tr>
    <tr><td>Impossible Travel</td><td>70</td><td>Logins from geographically distant locations faster than physically possible</td></tr>
    <tr><td>Reauth from Cloud</td><td>60</td><td>Session token replay (reauth) from cloud provider IPs</td></tr>
    <tr><td>Brute Force + Success</td><td>55</td><td>Burst of login failures followed by a successful login</td></tr>
    <tr><td>Risky Sensitive Action</td><td>50</td><td>Google-flagged risky action with bypassed challenge</td></tr>
    <tr><td>Concurrent Sessions</td><td>45</td><td>Same account accessed from multiple IPs within minutes</td></tr>
    <tr><td>Suspicious Country</td><td>40</td><td>Login from a flagged high-risk country</td></tr>
    <tr><td>New Device from Cloud</td><td>35</td><td>First-seen device/browser from a cloud or hosting provider IP</td></tr>
    <tr><td>Risky Action + Cloud</td><td>30</td><td>Risky action performed from cloud/hosting IP (bonus)</td></tr>
    <tr><td>User Agent Anomaly</td><td>30</td><td>Login from automation tool, headless browser, or scripting library</td></tr>
    <tr><td>OAuth from Cloud</td><td>25</td><td>OAuth app authorization from cloud provider IP</td></tr>
    <tr><td>Brute Force Attempt</td><td>20</td><td>5+ login failures in 10 minutes (no success observed)</td></tr>
    <tr><td>After-Hours Login</td><td>15</td><td>Login outside configured business hours</td></tr>
    <tr><td>Cloud IP Logins</td><td>15</td><td>3+ logins from cloud/hosting IPs (weak signal alone)</td></tr>
    <tr><td>New Device</td><td>10</td><td>First-seen device/browser (residential IP)</td></tr>
  </table>
</div>
'@)

    # --- Known Attacker IPs Reference ---
    if ($script:KnownAttackerIps -and $script:KnownAttackerIps.ips) {
        $ipUserMap = @{}
        foreach ($p in $Profiles) {
            foreach ($event in $p.KnownAttackerIpLogins) {
                if (-not $ipUserMap.ContainsKey($event.IpAddress)) { $ipUserMap[$event.IpAddress] = [System.Collections.Generic.HashSet[string]]::new() }
                [void]$ipUserMap[$event.IpAddress].Add($p.Email)
            }
        }

        [void]$html.Append('<h2>Known Attacker IPs</h2>')
        [void]$html.Append('<table><tr><th>IP Address</th><th>Classification</th><th>Note</th><th>Users Affected</th></tr>')
        foreach ($entry in ($script:KnownAttackerIps.ips | Sort-Object -Property address)) {
            $ip = $entry.address
            $users = if ($ipUserMap.ContainsKey($ip)) { ($ipUserMap[$ip] | Sort-Object) -join ', ' } else { '<em style="color:var(--dim)">not seen</em>' }
            [void]$html.Append("<tr><td><code>$(& $esc $ip)</code></td><td><span class=`"ip-tag ip-attacker`">Attacker</span></td><td>$(& $esc $entry.note)</td><td>$users</td></tr>")
        }
        [void]$html.Append('</table>')
    }

    # --- Flagged Users Summary Table ---
    [void]$html.Append('<h2>Flagged Users</h2>')
    if ($Profiles.Count -eq 0) {
        [void]$html.Append('<p style="color:var(--sage)">No users flagged. All accounts appear clean.</p>')
    } else {
        [void]$html.Append('<table><tr><th>User</th><th>Threat</th><th>Score</th><th>Attacker</th><th>Cloud</th><th>Reauth</th><th>Risky</th><th>Country</th><th>OAuth</th><th>Travel</th><th>Brute</th><th>Status</th></tr>')
        foreach ($p in $Profiles) {
            $levelClass = $p.ThreatLevel.ToLower()
            $badge = "<span class=`"badge badge-$levelClass`">$($p.ThreatLevel)</span>"
            $tags = ''
            if ($p.IsKnownCompromised) { $tags += ' <span class="badge badge-known">Known</span>' }
            if ($p.WasRemediated) { $tags += ' <span class="badge badge-remediated">Remediated</span>' }
            elseif ($p.ThreatScore -ge 60 -and -not $p.IsKnownCompromised) {
                $tags += ' <span class="badge badge-critical">Unremediated</span>'
            }

            $countOrEmpty = { param($n) if ($n -gt 0) { $n } else { '' } }
            $bfMark = if ($p.BruteForce -and $p.BruteForce.Detected) {
                if ($p.BruteForce.SuccessAfter) { '<span style="color:var(--critical)">&#9888;</span>' } else { '&#10003;' }
            } else { '' }
            $travelCount = if ($p.ImpossibleTravel) { $p.ImpossibleTravel.Count } else { 0 }

            [void]$html.Append("<tr><td><strong>$(& $esc $p.Email)</strong>$tags</td><td>$badge</td><td>$($p.ThreatScore.ToString('N0'))</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.KnownAttackerIpLogins.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.CloudIpLogins.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.ReauthFromCloud.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.RiskyActions.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.SuspiciousCountryLogins.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $p.SuspiciousOAuthGrants.Count)</td>")
            [void]$html.Append("<td>$(& $countOrEmpty $travelCount)</td>")
            [void]$html.Append("<td>$bfMark</td>")
            [void]$html.Append('<td></td></tr>')
        }
        [void]$html.Append('</table>')
    }

    # --- Detailed collapsible sections for all flagged users ---
    $detailProfiles = @($Profiles | Where-Object { $_.ThreatScore -gt 0 })
    if ($detailProfiles.Count -gt 0) {
        [void]$html.Append('<h2>Detailed Analysis</h2>')

        foreach ($p in $detailProfiles) {
            $levelClass = $p.ThreatLevel.ToLower()
            $openAttr = if ($p.ThreatLevel -in @('CRITICAL', 'HIGH')) { ' open' } else { '' }

            [void]$html.Append("<details class=`"user-detail`"$openAttr>")
            [void]$html.Append("<summary><span class=`"badge badge-$levelClass`">$($p.ThreatLevel)</span> <strong>$(& $esc $p.Email)</strong> <span style=`"color:var(--dim)`">&mdash; Score: $($p.ThreatScore.ToString('N0'))</span></summary>")
            [void]$html.Append('<div class="detail-body">')

            # Status badges
            if ($p.IsKnownCompromised) {
                [void]$html.Append('<p><span class="badge badge-known">Confirmed Compromised</span></p>')
            }
            if ($p.WasRemediated) {
                [void]$html.Append('<p><span class="badge badge-remediated">Admin remediation detected (password reset / session revoke)</span></p>')
            } elseif ($p.ThreatScore -ge 60) {
                [void]$html.Append('<p><span class="badge badge-critical">NO ADMIN REMEDIATION DETECTED - IMMEDIATE ACTION REQUIRED</span></p>')
            }

            # Indicators
            [void]$html.Append('<h4>Indicators</h4>')
            foreach ($ind in $p.Indicators) {
                [void]$html.Append("<div class=`"indicator`">$(& $esc $ind)</div>")
            }

            # --- New signal sections ---

            # Impossible Travel
            if ($p.ImpossibleTravel -and $p.ImpossibleTravel.Count -gt 0) {
                [void]$html.Append('<div class="signal-section"><h4>Impossible Travel</h4>')
                [void]$html.Append('<table><tr><th>From</th><th>To</th><th>Distance</th><th>Time Gap</th><th>Speed Required</th></tr>')
                foreach ($trip in $p.ImpossibleTravel) {
                    $fromTs = if ($trip.FromTime -is [datetime]) { $trip.FromTime.ToString('yyyy-MM-dd HH:mm') } else { $trip.FromTime }
                    $toTs = if ($trip.ToTime -is [datetime]) { $trip.ToTime.ToString('yyyy-MM-dd HH:mm') } else { $trip.ToTime }
                    [void]$html.Append("<tr>")
                    [void]$html.Append("<td><code>$(& $esc $trip.FromIp)</code> $(& $esc $trip.FromCountry)<br><span style=`"color:var(--dim);font-size:0.8em`">$fromTs</span></td>")
                    [void]$html.Append("<td><code>$(& $esc $trip.ToIp)</code> $(& $esc $trip.ToCountry)<br><span style=`"color:var(--dim);font-size:0.8em`">$toTs</span></td>")
                    [void]$html.Append("<td>$($trip.DistanceKm.ToString('N0')) km</td>")
                    [void]$html.Append("<td>$($trip.TimeDiffHours)h</td>")
                    [void]$html.Append("<td style=`"color:var(--critical)`">$($trip.RequiredSpeedKmh.ToString('N0')) km/h</td>")
                    [void]$html.Append('</tr>')
                }
                [void]$html.Append('</table></div>')
            }

            # Concurrent Sessions
            if ($p.ConcurrentSessions -and $p.ConcurrentSessions.Count -gt 0) {
                [void]$html.Append('<div class="signal-section"><h4>Concurrent Sessions</h4>')
                [void]$html.Append('<table><tr><th>Window Start</th><th>IPs</th><th>Events</th></tr>')
                foreach ($cs in $p.ConcurrentSessions) {
                    $wsTs = if ($cs.WindowStart -is [datetime]) { $cs.WindowStart.ToString('yyyy-MM-dd HH:mm:ss') } else { $cs.WindowStart }
                    $ipList = ($cs.DistinctIps | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ', '
                    [void]$html.Append("<tr><td>$wsTs</td><td>$ipList</td><td>$($cs.EventCount)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # Brute Force
            if ($p.BruteForce -and $p.BruteForce.Detected) {
                $bf = $p.BruteForce
                $bfColor = if ($bf.SuccessAfter) { 'var(--critical)' } else { 'var(--amber)' }
                [void]$html.Append("<div class=`"signal-section`" style=`"border-color:$bfColor`"><h4>Brute Force Detection</h4>")
                $bfStart = if ($bf.FailureWindow.Start -is [datetime]) { $bf.FailureWindow.Start.ToString('yyyy-MM-dd HH:mm:ss') } else { $bf.FailureWindow.Start }
                $bfEnd = if ($bf.FailureWindow.End -is [datetime]) { $bf.FailureWindow.End.ToString('yyyy-MM-dd HH:mm:ss') } else { $bf.FailureWindow.End }
                [void]$html.Append("<p><strong>$($bf.FailureCount) failures</strong> from $bfStart to $bfEnd</p>")
                [void]$html.Append("<p>Attacking IPs: $(($bf.AttackingIps | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ', ')</p>")
                if ($bf.SuccessAfter) {
                    $sucTs = if ($bf.SuccessEvent.Timestamp -is [datetime]) { $bf.SuccessEvent.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { $bf.SuccessEvent.Timestamp }
                    [void]$html.Append("<p style=`"color:var(--critical)`"><strong>&#9888; SUCCESSFUL LOGIN AFTER BRUTE FORCE</strong> at $sucTs from <code>$(& $esc $bf.SuccessEvent.IpAddress)</code></p>")
                }
                [void]$html.Append('</div>')
            }

            # User Agent Anomalies
            if ($p.UserAgentAnomalies -and $p.UserAgentAnomalies.Count -gt 0) {
                [void]$html.Append('<div class="signal-section"><h4>Suspicious User Agents</h4>')
                [void]$html.Append('<table><tr><th>Time</th><th>IP</th><th>Detection</th><th>User Agent</th></tr>')
                foreach ($ua in $p.UserAgentAnomalies) {
                    $uaTs = if ($ua.Timestamp -is [datetime]) { $ua.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { $ua.Timestamp }
                    [void]$html.Append("<tr><td>$uaTs</td><td><code>$(& $esc $ua.IpAddress)</code></td><td style=`"color:var(--amber)`">$(& $esc $ua.MatchLabel)</td><td style=`"font-size:0.8em;word-break:break-all`">$(& $esc $ua.UserAgent)</td></tr>")
                }
                [void]$html.Append('</table></div>')
            }

            # After-Hours Logins (show summary, not full list)
            if ($p.AfterHoursLogins -and $p.AfterHoursLogins.Count -gt 0) {
                $ahCount = $p.AfterHoursLogins.Count
                $weekendAh = @($p.AfterHoursLogins | Where-Object { $_.Reason -match 'Weekend|non-business' }).Count
                $lateAh = $ahCount - $weekendAh
                [void]$html.Append("<div class=`"signal-section`"><h4>After-Hours Logins ($ahCount total)</h4>")
                [void]$html.Append("<p>$lateAh outside business hours, $weekendAh on weekends/non-business days</p>")
                # Show first 5
                [void]$html.Append('<table><tr><th>Time (UTC)</th><th>Local Time</th><th>IP</th><th>Reason</th></tr>')
                foreach ($ah in ($p.AfterHoursLogins | Select-Object -First 5)) {
                    $ahTs = if ($ah.Timestamp -is [datetime]) { $ah.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $ah.Timestamp }
                    $ahLocal = if ($ah.LocalTime -is [datetime]) { $ah.LocalTime.ToString('yyyy-MM-dd HH:mm') } else { $ah.LocalTime }
                    [void]$html.Append("<tr><td>$ahTs</td><td>$ahLocal</td><td><code>$(& $esc $ah.IpAddress)</code></td><td style=`"font-size:0.85em`">$(& $esc $ah.Reason)</td></tr>")
                }
                if ($ahCount -gt 5) { [void]$html.Append("<tr><td colspan=`"4`" style=`"color:var(--dim)`">... and $($ahCount - 5) more</td></tr>") }
                [void]$html.Append('</table></div>')
            }

            # New Devices
            if ($p.NewDevices -and $p.NewDevices.Count -gt 0) {
                $cloudDevs = @($p.NewDevices | Where-Object { $_.IsCloudIp })
                [void]$html.Append("<div class=`"signal-section`"><h4>New Devices ($($p.NewDevices.Count) total, $($cloudDevs.Count) from cloud IPs)</h4>")
                [void]$html.Append('<table><tr><th>Time</th><th>IP</th><th>Type</th><th>Fingerprint</th></tr>')
                foreach ($dev in ($p.NewDevices | Select-Object -First 10)) {
                    $devTs = if ($dev.Timestamp -is [datetime]) { $dev.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $dev.Timestamp }
                    $devTag = if ($dev.IsCloudIp) { "<span class=`"ip-tag ip-cloud`">$($dev.IpClass)</span>" }
                               elseif ($dev.IpClass) { "<span style=`"color:var(--dim)`">$(& $esc $dev.IpClass)</span>" }
                               else { '' }
                    [void]$html.Append("<tr><td>$devTs</td><td><code>$(& $esc $dev.IpAddress)</code> $devTag</td><td>$(if($dev.DeviceId){'Device ID'}else{'User Agent'})</td><td style=`"font-size:0.8em;word-break:break-all`">$(& $esc $dev.Fingerprint)</td></tr>")
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

                    $country = if ($info.Country) {
                        $name = if ($script:SuspiciousCountries) { $script:SuspiciousCountries.displayNames.($info.Country) } else { $null }
                        if ($name) { "$(& $esc $name) ($($info.Country))" } else { $info.Country }
                    } else { '&mdash;' }

                    $eventCounts = @{}
                    foreach ($evt in $info.Events) {
                        $eventCounts[$evt] = ($eventCounts[$evt] ?? 0) + 1
                    }
                    $eventsSummary = ($eventCounts.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)($($_.Value))" }) -join ', '

                    [void]$html.Append("<tr><td><code>$(& $esc $ip)</code></td><td>$tag</td><td>$country</td><td style=`"font-size:0.8em`">$(& $esc $eventsSummary)</td></tr>")
                }
                [void]$html.Append('</table>')
            }

            # Suspicious event timeline
            $suspiciousEvents = @(
                @($p.KnownAttackerIpLogins)
                @($p.ReauthFromCloud)
                @($p.RiskyActions)
                @($p.SuspiciousOAuthGrants)
                @($p.SuspiciousCountryLogins)
            ) | Where-Object { $_ } | Sort-Object -Property Timestamp

            $seen = [System.Collections.Generic.HashSet[string]]::new()
            $deduped = foreach ($e in $suspiciousEvents) {
                $key = "$($e.Timestamp)|$($e.EventName)|$($e.IpAddress)"
                if ($seen.Add($key)) { $e }
            }

            if ($deduped) {
                [void]$html.Append('<h4>Suspicious Event Timeline</h4>')
                [void]$html.Append('<table><tr><th>Time</th><th>Event</th><th>IP</th><th>Type</th><th>Details</th></tr>')
                foreach ($e in ($deduped | Select-Object -First 30)) {
                    $ts = $e.Timestamp
                    if ($ts) {
                        try {
                            $dt = if ($ts -is [datetime]) { $ts.ToUniversalTime() } else { [datetime]::Parse($ts).ToUniversalTime() }
                            $ts = $dt.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
                        } catch { }
                    }

                    $ipTag = if ($e.IpClass -eq 'known_attacker') {
                        "<code>$(& $esc $e.IpAddress)</code> <span class=`"ip-tag ip-attacker`">Attacker</span>"
                    } elseif ($e.IpClass -eq 'tor') {
                        "<code>$(& $esc $e.IpAddress)</code> <span class=`"ip-tag ip-tor`">Tor</span>"
                    } elseif ($e.IpClass -and $script:CloudProviderClasses -and $script:CloudProviderClasses.Contains($e.IpClass)) {
                        "<code>$(& $esc $e.IpAddress)</code> <span class=`"ip-tag ip-cloud`">$($e.IpClass.ToUpper())</span>"
                    } elseif ($e.IpAddress) {
                        "<code>$(& $esc $e.IpAddress)</code>"
                    } else { '&mdash;' }

                    $details = @()
                    if ($e.Params.login_type)            { $details += "login_type=$($e.Params.login_type)" }
                    if ($e.Params.app_name)              { $details += "app=$($e.Params.app_name)" }
                    if ($e.Params.login_challenge_method) { $details += "challenge=$($e.Params.login_challenge_method)" }

                    [void]$html.Append("<tr><td style=`"white-space:nowrap`">$(& $esc $ts)</td><td><code>$(& $esc $e.EventName)</code></td><td>$ipTag</td><td>$(& $esc $e.Source)</td><td style=`"font-size:0.8em`">$(& $esc ($details -join ', '))</td></tr>")
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
  &#x2694; Generated by Guerrilla &nbsp;|&nbsp;
  $(& $esc $TimestampStr) &nbsp;|&nbsp;
  $($AllEventsCount.ToString('N0')) events &nbsp;|&nbsp; $($AllProfilesCount.ToString('N0')) users &nbsp;|&nbsp;
  Guerrilla Score: $guerrillaScore ($($scoreInfo.Label))
</div>
</body>
</html>
"@)

    [System.IO.File]::WriteAllText($FilePath, $html.ToString(), [System.Text.Encoding]::UTF8)
}
