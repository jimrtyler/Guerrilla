# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Format-SignalContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ScanResult,

        [Parameter(Mandatory)]
        [ValidateSet('Html', 'Text', 'Sms')]
        [string]$Format,

        [PSCustomObject[]]$Threats
    )

    if (-not $Threats) { $Threats = $ScanResult.NewThreats }
    if (-not $Threats -or $Threats.Count -eq 0) { return $null }

    $critCount = @($Threats | Where-Object ThreatLevel -eq 'CRITICAL').Count
    $highCount = @($Threats | Where-Object ThreatLevel -eq 'HIGH').Count
    $medCount  = @($Threats | Where-Object ThreatLevel -eq 'MEDIUM').Count

    # Guard scan-metadata: a null Timestamp would throw on .ToString() and, because
    # this runs before any provider dispatch, abort delivery on EVERY channel.
    $scanTime = if ($ScanResult.Timestamp) {
        try { $ScanResult.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } catch { 'n/a' }
    } else { 'n/a' }
    $usersScanned   = $ScanResult.TotalUsersScanned   ?? 'n/a'
    $eventsAnalyzed = $ScanResult.TotalEventsAnalyzed ?? 'n/a'

    switch ($Format) {
        'Sms' {
            if ($Threats.Count -eq 1) {
                $t = $Threats[0]
                $topInd = if ($t.Indicators.Count -gt 0) { $t.Indicators[0] } else { 'Suspicious activity' }
                # Truncate indicator for SMS
                if ($topInd.Length -gt 100) { $topInd = $topInd.Substring(0, 97) + '...' }
                return "Guerrilla SIGNAL: NEW COMPROMISE - $($t.Email) (Score:$($t.ThreatScore.ToString('N0')), $($t.ThreatLevel)). $topInd. Details emailed."
            } else {
                $parts = @("Guerrilla SIGNAL: $($Threats.Count) new threats detected.")
                if ($critCount -gt 0) { $parts += "$critCount CRITICAL" }
                if ($highCount -gt 0) { $parts += "$highCount HIGH" }
                if ($medCount -gt 0)  { $parts += "$medCount MEDIUM" }
                $top = $Threats | Sort-Object -Property ThreatScore -Descending | Select-Object -First 1
                $parts += "Top: $($top.Email) (Score:$($top.ThreatScore.ToString('N0')))"
                $parts += "Details emailed."
                return $parts -join ' '
            }
        }

        'Text' {
            $lines = @()
            $lines += 'Guerrilla Field Report Alert'
            $lines += '=' * 50
            $lines += "Scan Time: $scanTime UTC"
            $lines += "Users Scanned: $usersScanned"
            $lines += "New Threats: $($Threats.Count)"
            if ($critCount) { $lines += "CRITICAL: $critCount" }
            if ($highCount) { $lines += "HIGH: $highCount" }
            if ($medCount)  { $lines += "MEDIUM: $medCount" }
            $lines += ''
            $lines += 'FLAGGED USERS:'
            $lines += '-' * 50
            foreach ($t in $Threats) {
                $lines += "$($t.ThreatLevel) (Score: $($t.ThreatScore.ToString('N0'))) - $($t.Email)"
                foreach ($ind in $t.Indicators) {
                    $lines += "  - $ind"
                }
                $lines += ''
            }
            return $lines -join "`n"
        }

        'Html' {
            $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
            $sb = [System.Text.StringBuilder]::new(4096)

            [void]$sb.Append(@"
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, sans-serif; max-width: 700px; margin: 0 auto; background: #0d1117; color: #e6edf3; padding: 24px; border-radius: 8px;">
<h2 style="margin: 0 0 8px; color: #e6edf3;">Guerrilla Field Report Alert</h2>
<p style="color: #8b949e; margin: 0 0 16px;">Scan: $scanTime UTC | $usersScanned users scanned | $eventsAnalyzed events analyzed</p>
<table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
<tr>
"@)
            if ($critCount -gt 0) {
                [void]$sb.Append("<td style=`"text-align: center; padding: 12px; background: rgba(248,81,73,0.15); border-radius: 6px;`"><div style=`"font-size: 2em; font-weight: 700; color: #f85149;`">$critCount</div><div style=`"color: #8b949e; font-size: 0.85em;`">CRITICAL</div></td>")
            }
            if ($highCount -gt 0) {
                [void]$sb.Append("<td style=`"text-align: center; padding: 12px; background: rgba(219,109,40,0.15); border-radius: 6px;`"><div style=`"font-size: 2em; font-weight: 700; color: #db6d28;`">$highCount</div><div style=`"color: #8b949e; font-size: 0.85em;`">HIGH</div></td>")
            }
            if ($medCount -gt 0) {
                [void]$sb.Append("<td style=`"text-align: center; padding: 12px; background: rgba(210,153,34,0.15); border-radius: 6px;`"><div style=`"font-size: 2em; font-weight: 700; color: #d29922;`">$medCount</div><div style=`"color: #8b949e; font-size: 0.85em;`">MEDIUM</div></td>")
            }

            [void]$sb.Append('</tr></table>')

            foreach ($t in ($Threats | Sort-Object -Property ThreatScore -Descending)) {
                $levelColor = switch ($t.ThreatLevel) {
                    'CRITICAL' { '#f85149' }
                    'HIGH'     { '#db6d28' }
                    'MEDIUM'   { '#d29922' }
                    default    { '#58a6ff' }
                }

                [void]$sb.Append(@"
<div style="background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin-bottom: 12px;">
<h3 style="margin: 0 0 8px;">$(& $esc $t.Email) <span style="background: $levelColor; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 0.75em;">$($t.ThreatLevel) ($($t.ThreatScore.ToString('N0')))</span></h3>
<ul style="margin: 0; padding-left: 20px; font-size: 0.9em;">
"@)
                foreach ($ind in $t.Indicators) {
                    [void]$sb.Append("<li style=`"margin-bottom: 4px;`">$(& $esc $ind)</li>")
                }
                [void]$sb.Append('</ul></div>')
            }

            [void]$sb.Append('</div>')
            return $sb.ToString()
        }
    }
}
