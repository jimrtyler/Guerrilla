# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-InfiltrationReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [PSCustomObject[]]$PreviousFindings,

        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional',

        [hashtable]$Branding
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $findings = $Result.Findings
    $score = $Result.Score
    $overallScore = $score.OverallScore
    $categoryScores = $score.CategoryScores
    $timestampStr = $Result.ScanStart.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    $totalChecks = $findings.Count
    $passCount = @($findings | Where-Object Status -eq 'PASS').Count
    $failCount = @($findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($findings | Where-Object Status -eq 'WARN').Count
    $skipCount = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($findings | Where-Object Status -eq 'FAIL')
    $critCount = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount = @($failFindings | Where-Object Severity -eq 'Low').Count

    $moduleVersion = '2.0.0'
    try {
        $modVer = $ExecutionContext.SessionState.Module.Version
        if ($modVer) { $moduleVersion = $modVer.ToString() }
    } catch { }

    $scoreColor = switch ($true) {
        ($overallScore -ge 90) { 'var(--sage)';        break }
        ($overallScore -ge 75) { 'var(--olive)';       break }
        ($overallScore -ge 60) { 'var(--gold)';        break }
        ($overallScore -ge 40) { 'var(--amber)';       break }
        ($overallScore -ge 20) { 'var(--deep-orange)'; break }
        default                { 'var(--dark-red)' }
    }

    $scoreLabel = Get-FortificationScoreLabel -Score $overallScore
    $scoreLabel = Resolve-GuerrillaReportScoreLabel -Score $overallScore -Style $Style -Fallback $scoreLabel
    $scoreDash = [Math]::Round(251.2 * (1 - $overallScore / 100), 1)
    $brand = Get-GuerrillaReportBrandingHtml -Branding $Branding

    $html = [System.Text.StringBuilder]::new(65536)

    [void]$html.AppendLine('<!DOCTYPE html>')
    [void]$html.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$html.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$html.AppendLine("<title>Infiltration Report - $(& $esc $Result.TenantId)</title>")
    [void]$html.AppendLine('<style>')
    [void]$html.AppendLine((Get-GuerrillaReportThemeStyleBlock -Style $Style))
    [void]$html.AppendLine('*{margin:0;padding:0;box-sizing:border-box}')
    [void]$html.AppendLine('body{background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6;padding:2rem}')
    [void]$html.AppendLine('.container{max-width:1200px;margin:0 auto}')
    [void]$html.AppendLine('.header{text-align:center;margin-bottom:2rem;padding:2rem;background:var(--surface);border:1px solid var(--border);border-radius:8px}')
    [void]$html.AppendLine('.header h1{color:var(--olive);font-size:1.8rem;margin-bottom:.5rem}')
    [void]$html.AppendLine('.header .subtitle{color:var(--dim);font-size:1rem}')
    [void]$html.AppendLine('.header .tenant{color:var(--parchment);font-size:1.1rem;margin-top:.5rem}')
    [void]$html.AppendLine('.score-section{display:flex;align-items:center;justify-content:center;gap:2rem;margin:2rem 0}')
    [void]$html.AppendLine('.score-ring{position:relative;width:120px;height:120px}')
    [void]$html.AppendLine('.score-ring svg{transform:rotate(-90deg)}')
    [void]$html.AppendLine('.score-ring .value{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:2rem;font-weight:700}')
    [void]$html.AppendLine('.score-ring .label{position:absolute;top:70%;left:50%;transform:translate(-50%,0);font-size:.8rem;color:var(--dim)}')
    [void]$html.AppendLine('.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1rem;margin:1.5rem 0}')
    [void]$html.AppendLine('.stat{text-align:center;padding:1rem;background:var(--surface);border:1px solid var(--border);border-radius:6px}')
    [void]$html.AppendLine('.stat .num{font-size:1.8rem;font-weight:700}.stat .lbl{color:var(--dim);font-size:.85rem}')
    [void]$html.AppendLine('.cats{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin:2rem 0}')
    [void]$html.AppendLine('.cat{padding:1rem;background:var(--surface);border:1px solid var(--border);border-radius:6px}')
    [void]$html.AppendLine('.cat .cat-name{color:var(--olive);font-weight:600;margin-bottom:.5rem;font-size:.9rem}')
    [void]$html.AppendLine('.cat .cat-score{font-size:1.5rem;font-weight:700}')
    [void]$html.AppendLine('.cat .cat-bar{height:6px;background:var(--border);border-radius:3px;margin:.5rem 0}')
    [void]$html.AppendLine('.cat .cat-bar-fill{height:100%;border-radius:3px;transition:width .3s}')
    [void]$html.AppendLine('.cat .cat-stats{color:var(--dim);font-size:.8rem}')
    [void]$html.AppendLine('.section{margin:2rem 0}.section h2{color:var(--olive);border-bottom:1px solid var(--border);padding-bottom:.5rem;margin-bottom:1rem}')
    [void]$html.AppendLine('.filters{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}')
    [void]$html.AppendLine('.filters button{padding:.4rem .8rem;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;font-size:.85rem}')
    [void]$html.AppendLine('.filters button.active{background:var(--olive);color:var(--bg);border-color:var(--olive)}')
    [void]$html.AppendLine('table{width:100%;border-collapse:collapse;margin:1rem 0}')
    [void]$html.AppendLine('th{background:var(--surface);color:var(--olive);text-align:left;padding:.7rem;border:1px solid var(--border);font-size:.85rem}')
    [void]$html.AppendLine('td{padding:.6rem .7rem;border:1px solid var(--border);font-size:.85rem;vertical-align:top}')
    [void]$html.AppendLine('tr:nth-child(even){background:rgba(139,139,62,.05)}')
    [void]$html.AppendLine('.sev-critical{color:var(--dark-red);font-weight:700}.sev-high{color:var(--deep-orange);font-weight:600}')
    [void]$html.AppendLine('.sev-medium{color:var(--amber)}.sev-low{color:var(--sage)}.sev-info{color:var(--dim)}')
    [void]$html.AppendLine('.st-pass{color:var(--sage)}.st-fail{color:var(--deep-orange)}.st-warn{color:var(--amber)}.st-skip{color:var(--dim)}.st-accepted{color:var(--dim);font-style:italic}')
    [void]$html.AppendLine('.detail-toggle{cursor:pointer;color:var(--olive);text-decoration:underline;font-size:.85rem}')
    [void]$html.AppendLine('.detail-content{display:none;padding:.5rem;background:rgba(0,0,0,.2);border-radius:4px;margin-top:.5rem;font-size:.8rem;white-space:pre-wrap}')
    [void]$html.AppendLine('.remediation-link{color:var(--sage);text-decoration:none;font-size:.8rem}')
    [void]$html.AppendLine('.remediation-link:hover{text-decoration:underline}')
    [void]$html.AppendLine('tr.finding-extra td{background:rgba(199,92,46,.06);border-left:3px solid var(--amber)}')
    [void]$html.AppendLine('.affected{margin-top:4px;font-size:.85rem}')
    [void]$html.AppendLine('.affected-label{color:var(--amber);font-weight:600}')
    [void]$html.AppendLine('.affected-items{color:var(--text);margin:4px 0 0 0;padding-left:20px}')
    [void]$html.AppendLine('.affected-items li{word-break:break-word;margin:1px 0}')
    [void]$html.AppendLine('.affected-items li.more{list-style:none;margin-left:-20px;font-style:italic;opacity:.7;color:var(--dim)}')
    [void]$html.AppendLine('.footer{text-align:center;color:var(--dim);margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);font-size:.85rem}')
    [void]$html.AppendLine('.delta{padding:1rem;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin:1rem 0}')
    [void]$html.AppendLine('.delta .improved{color:var(--sage)}.delta .regressed{color:var(--deep-orange)}.delta .new{color:var(--amber)}')
    [void]$html.AppendLine('</style></head><body><div class="container">')
    [void]$html.AppendLine($brand.Banner)
    [void]$html.AppendLine($brand.Header)

    # Header
    [void]$html.AppendLine('<div class="header">')
    [void]$html.AppendLine('<h1>INFILTRATION REPORT</h1>')
    [void]$html.AppendLine('<div class="subtitle">Entra ID / Azure / M365 Security Audit</div>')
    [void]$html.AppendLine("<div class=`"tenant`">Tenant: $(& $esc $Result.TenantId)</div>")
    [void]$html.AppendLine("<div class=`"subtitle`">$timestampStr | Guerrilla v$moduleVersion</div>")
    [void]$html.AppendLine('</div>')

    # Score section
    [void]$html.AppendLine('<div class="score-section">')
    [void]$html.AppendLine('<div class="score-ring">')
    [void]$html.AppendLine('<svg width="120" height="120"><circle cx="60" cy="60" r="40" fill="none" stroke="var(--border)" stroke-width="8"/>')
    [void]$html.AppendLine("<circle cx=`"60`" cy=`"60`" r=`"40`" fill=`"none`" stroke=`"$scoreColor`" stroke-width=`"8`" stroke-dasharray=`"251.2`" stroke-dashoffset=`"$scoreDash`" stroke-linecap=`"round`"/>")
    [void]$html.AppendLine('</svg>')
    [void]$html.AppendLine("<div class=`"value`" style=`"color:$scoreColor`">$overallScore</div>")
    [void]$html.AppendLine("<div class=`"label`">$(& $esc $scoreLabel)</div>")
    [void]$html.AppendLine('</div>')

    # Summary stats
    [void]$html.AppendLine('<div class="stats">')
    [void]$html.AppendLine("<div class=`"stat`"><div class=`"num`" style=`"color:var(--parchment)`">$totalChecks</div><div class=`"lbl`">Total</div></div>")
    [void]$html.AppendLine("<div class=`"stat`"><div class=`"num`" style=`"color:var(--sage)`">$passCount</div><div class=`"lbl`">Passed</div></div>")
    [void]$html.AppendLine("<div class=`"stat`"><div class=`"num`" style=`"color:var(--deep-orange)`">$failCount</div><div class=`"lbl`">Failed</div></div>")
    [void]$html.AppendLine("<div class=`"stat`"><div class=`"num`" style=`"color:var(--amber)`">$warnCount</div><div class=`"lbl`">Warnings</div></div>")
    [void]$html.AppendLine("<div class=`"stat`"><div class=`"num`" style=`"color:var(--dim)`">$skipCount</div><div class=`"lbl`">Skipped</div></div>")
    [void]$html.AppendLine('</div></div>')

    # Zero Trust posture (CISA ZTMM) — pillar scores that disclose their own coverage.
    $ztScores = @($findings | Get-ZeroTrustScore)
    if ($ztScores.Count) {
        $ztLine = ($ztScores | ForEach-Object {
            $pct  = if ($null -ne $_.ScorePercent) { "$($_.ScorePercent)%" } else { 'n/a' }
            $mark = if ($_.CoverageConfidence -ne 'Solid') { " <span style=`"opacity:.7`">($($_.CoverageConfidence))</span>" } else { '' }
            "$(& $esc $_.Pillar) <strong>$pct</strong>$mark"
        }) -join ' &middot; '
        [void]$html.AppendLine("<div class=`"zt-posture`" style=`"text-align:center;margin:0 0 1.5rem;color:var(--dim);font-size:.85rem`"><strong style=`"color:var(--parchment)`">Zero Trust posture</strong> (CISA ZTMM): $ztLine</div>")
    }

    # Severity breakdown
    if ($failCount -gt 0) {
        [void]$html.AppendLine('<div class="stats">')
        [void]$html.AppendLine("<div class=`"stat`"><div class=`"num sev-critical`">$critCount</div><div class=`"lbl`">Critical</div></div>")
        [void]$html.AppendLine("<div class=`"stat`"><div class=`"num sev-high`">$highCount</div><div class=`"lbl`">High</div></div>")
        [void]$html.AppendLine("<div class=`"stat`"><div class=`"num sev-medium`">$medCount</div><div class=`"lbl`">Medium</div></div>")
        [void]$html.AppendLine("<div class=`"stat`"><div class=`"num sev-low`">$lowCount</div><div class=`"lbl`">Low</div></div>")
        [void]$html.AppendLine('</div>')
    }

    # Category score cards
    [void]$html.AppendLine('<div class="section"><h2>Category Scores</h2><div class="cats">')
    foreach ($cat in ($categoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $catScore = $cat.Value.Score
        $catColor = switch ($true) {
            ($catScore -ge 90) { 'var(--sage)';        break }
            ($catScore -ge 75) { 'var(--olive)';       break }
            ($catScore -ge 60) { 'var(--gold)';        break }
            ($catScore -ge 40) { 'var(--amber)';       break }
            default            { 'var(--deep-orange)' }
        }
        [void]$html.AppendLine('<div class="cat">')
        [void]$html.AppendLine("<div class=`"cat-name`">$(& $esc $cat.Key)</div>")
        [void]$html.AppendLine("<div class=`"cat-score`" style=`"color:$catColor`">$catScore</div>")
        [void]$html.AppendLine("<div class=`"cat-bar`"><div class=`"cat-bar-fill`" style=`"width:${catScore}%;background:$catColor`"></div></div>")
        [void]$html.AppendLine("<div class=`"cat-stats`">Pass: $($cat.Value.Pass) | Fail: $($cat.Value.Fail) | Warn: $($cat.Value.Warn) | Skip: $($cat.Value.Skip)</div>")
        [void]$html.AppendLine('</div>')
    }
    [void]$html.AppendLine('</div></div>')

    # Delta comparison
    if ($PreviousFindings -and $PreviousFindings.Count -gt 0) {
        $prevLookup = @{}
        foreach ($pf in $PreviousFindings) {
            if ($pf.checkId) { $prevLookup[$pf.checkId] = $pf }
        }

        $improved = [System.Collections.Generic.List[string]]::new()
        $regressed = [System.Collections.Generic.List[string]]::new()
        $newChecks = [System.Collections.Generic.List[string]]::new()

        foreach ($f in $findings) {
            if ($prevLookup.ContainsKey($f.CheckId)) {
                $prev = $prevLookup[$f.CheckId]
                $prevStatus = $prev.status ?? $prev.Status
                if ($f.Status -eq 'PASS' -and $prevStatus -in @('FAIL', 'WARN')) {
                    $improved.Add("$($f.CheckId): $($f.CheckName)")
                } elseif ($f.Status -eq 'FAIL' -and $prevStatus -in @('PASS', 'WARN')) {
                    $regressed.Add("$($f.CheckId): $($f.CheckName)")
                }
            } else {
                $newChecks.Add("$($f.CheckId): $($f.CheckName)")
            }
        }

        if ($improved.Count -gt 0 -or $regressed.Count -gt 0 -or $newChecks.Count -gt 0) {
            [void]$html.AppendLine('<div class="section"><h2>Delta from Previous Scan</h2><div class="delta">')
            if ($improved.Count -gt 0) {
                [void]$html.AppendLine("<p class=`"improved`">Improved ($($improved.Count)):</p><ul>")
                foreach ($i in $improved) { [void]$html.AppendLine("<li>$(& $esc $i)</li>") }
                [void]$html.AppendLine('</ul>')
            }
            if ($regressed.Count -gt 0) {
                [void]$html.AppendLine("<p class=`"regressed`">Regressed ($($regressed.Count)):</p><ul>")
                foreach ($r in $regressed) { [void]$html.AppendLine("<li>$(& $esc $r)</li>") }
                [void]$html.AppendLine('</ul>')
            }
            if ($newChecks.Count -gt 0) {
                [void]$html.AppendLine("<p class=`"new`">New checks ($($newChecks.Count)):</p><ul>")
                foreach ($n in $newChecks | Select-Object -First 20) { [void]$html.AppendLine("<li>$(& $esc $n)</li>") }
                [void]$html.AppendLine('</ul>')
            }
            [void]$html.AppendLine('</div></div>')
        }
    }

    # Findings table
    [void]$html.AppendLine('<div class="section"><h2>All Findings</h2>')
    [void]$html.AppendLine('<div class="filters">')
    [void]$html.AppendLine('<button class="active" onclick="filterFindings(''all'')">All</button>')
    [void]$html.AppendLine('<button onclick="filterFindings(''FAIL'')">Failed</button>')
    [void]$html.AppendLine('<button onclick="filterFindings(''WARN'')">Warnings</button>')
    [void]$html.AppendLine('<button onclick="filterFindings(''PASS'')">Passed</button>')
    [void]$html.AppendLine('<button onclick="filterFindings(''SKIP'')">Skipped</button>')
    [void]$html.AppendLine('</div>')

    [void]$html.AppendLine('<table id="findings-table"><thead><tr>')
    [void]$html.AppendLine('<th>ID</th><th>Check</th><th>Category</th><th>Severity</th><th>Status</th><th>Current Value</th><th>Remediation</th>')
    [void]$html.AppendLine('</tr></thead><tbody>')

    foreach ($f in ($findings | Sort-Object -Property @{Expression = { switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } 'Info' { 4 } default { 5 } } }}, @{Expression = { switch ($_.Status) { 'FAIL' { 0 } 'WARN' { 1 } 'PASS' { 2 } 'SKIP' { 3 } 'ERROR' { 4 } default { 5 } } }})) {
        $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
        $sevClass = "sev-$($f.Severity.ToLower())"
        $stClass = if ($isAccepted) { 'st-accepted' } else { "st-$($f.Status.ToLower())" }
        $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }

        [void]$html.AppendLine("<tr data-status=`"$statusLabel`" data-severity=`"$($f.Severity)`">")
        [void]$html.AppendLine("<td><code>$(& $esc $f.CheckId)</code></td>")
        [void]$html.AppendLine("<td><strong>$(& $esc $f.CheckName)</strong><br><small style=`"color:var(--dim)`">$(& $esc $f.Description)</small></td>")
        [void]$html.AppendLine("<td>$(& $esc $f.Category)<br><small>$(& $esc $f.Subcategory)</small></td>")
        [void]$html.AppendLine("<td class=`"$sevClass`">$($f.Severity)</td>")
        [void]$html.AppendLine("<td class=`"$stClass`"><strong>$statusLabel</strong></td>")
        [void]$html.AppendLine("<td>$(& $esc $f.CurrentValue)</td>")

        $remCell = ''
        if ($f.RemediationSteps) {
            $remCell += & $esc $f.RemediationSteps
        }
        if ($f.RemediationUrl) {
            $remCell += "<br><a class=`"remediation-link`" href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`">Open in Admin Portal</a>"
        }
        [void]$html.AppendLine("<td>$remCell</td>")
        [void]$html.AppendLine('</tr>')

        if ($f.Status -in @('FAIL', 'WARN')) {
            $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
            if ($affectedHtml) {
                [void]$html.AppendLine("<tr class=`"finding-extra`" data-status=`"$statusLabel`" data-severity=`"$($f.Severity)`"><td colspan=`"7`">$affectedHtml</td></tr>")
            }
        }
    }

    [void]$html.AppendLine('</tbody></table></div>')

    # JavaScript for filtering
    [void]$html.AppendLine('<script>')
    [void]$html.AppendLine('function filterFindings(s){')
    [void]$html.AppendLine('document.querySelectorAll(".filters button").forEach(b=>{b.classList.remove("active");if(b.textContent.toLowerCase().includes(s.toLowerCase())||s==="all"&&b.textContent==="All")b.classList.add("active")});')
    [void]$html.AppendLine('document.querySelectorAll("#findings-table tbody tr").forEach(r=>{r.style.display=s==="all"||r.dataset.status===s?"":"none"})}')
    [void]$html.AppendLine('</script>')

    # Footer
    [void]$html.AppendLine("<div class=`"footer`">Generated by Guerrilla v$moduleVersion | Infiltration Audit | $timestampStr<br>By Jim Tyler, Microsoft MVP | <a href=`"https://github.com/jimrtyler`">GitHub</a> | <a href=`"https://linkedin.com/in/jamestyler`">LinkedIn</a> | <a href=`"https://youtube.com/@jimrtyler`">YouTube</a></div>")
    [void]$html.AppendLine('</div></body></html>')

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
}
