# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Shared report sections so the per-scan AD report, the GWS report, and the unified Campaign report
# all surface the same things consistently. Each returns an HTML fragment (or '') and styles itself
# with theme CSS variables, so it drops into any of the three report themes unchanged.

# Maps a maturity level (1-5) to a theme colour var. Worst is red, best is sage.
function Get-GuerrillaMaturityLevelColor {
    param($Level)
    switch ([int]$Level) {
        1 { 'var(--dark-red)' }
        2 { 'var(--deep-orange)' }
        3 { 'var(--gold)' }
        4 { 'var(--olive)' }
        5 { 'var(--sage)' }
        default { 'var(--dim)' }
    }
}

# Security Maturity (CMMI 1-5) section. Returns '' if maturity can't be computed.
function Get-GuerrillaMaturitySectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc
    )

    $maturity = $null
    try { $maturity = Get-GuerrillaMaturity -Findings $Findings } catch { }
    if (-not ($maturity -and $maturity.OverallLevel)) { return '' }

    $lvl   = [int]$maturity.OverallLevel
    $c     = Get-GuerrillaMaturityLevelColor $lvl
    $label = & $Esc ([string]$maturity.OverallLabel)

    $catRows = ''
    foreach ($k in ($maturity.CategoryLevels.Keys | Sort-Object { [int]$maturity.CategoryLevels[$_].Level })) {
        $cl = $maturity.CategoryLevels[$k]
        $cc = Get-GuerrillaMaturityLevelColor ([int]$cl.Level)
        $lvlCell = if ([int]$cl.Level -eq 0) { 'n/a' } else { "Level $([int]$cl.Level)" }
        $catRows += "<tr><td>$(& $Esc ([string]$cl.Category))</td><td style='color:$cc;font-weight:700'>$lvlCell</td><td>$(& $Esc ([string]$cl.Label))</td></tr>"
    }
    $blockerHtml = ''
    if ($maturity.NextLevel) {
        $bl = (@($maturity.NextLevelBlockers | Select-Object -First 8 | ForEach-Object { "<li>$(& $Esc ([string]$_))</li>" }) -join '')
        if ($bl) { $blockerHtml = "<p>To reach <strong>Level $([int]$maturity.NextLevel)</strong>, address:</p><ul style='margin:4px 0 8px 20px'>$bl</ul>" }
    }

    return @"
<style>
  .mat-sec { background: var(--surface-alt, var(--surface)); border: 1px solid var(--border); border-left: 4px solid $c;
             border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px; }
  .mat-sec h3 { margin-top: 0; }
  .mat-tbl { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.85em; }
  .mat-tbl th, .mat-tbl td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
  .mat-tbl th { opacity: 0.7; text-transform: uppercase; letter-spacing: 1px; font-size: 0.8em; }
</style>
<h2>Security Maturity</h2>
<div class="mat-sec">
  <h3 style="color:$c">Overall maturity: Level $lvl of 5 &mdash; $label</h3>
  <p>The lowest unmet control anchors the rating (CMMI-style scale: 1 Initial to 5 Optimized), so a single critical exposure caps the score until it is resolved.</p>
  $blockerHtml
  <table class="mat-tbl"><thead><tr><th>Category</th><th>Level</th><th>Maturity</th></tr></thead><tbody>$catRows</tbody></table>
</div>
"@
}

# Shared gather: collect the renderable attack chains from the ADPATH-001/002 findings.
# ADPATH-001 carries its rich objects under Details.Paths; ADPATH-002 under Details.Chains — read
# BOTH. Filter $null explicitly (an absent property wrapped with @() yields @($null) whose .Count is
# 1, which would otherwise defeat the AffectedItems fallback). Exclude Expected (by-design Tier-0
# service-account) paths — they're tracked by ADTIER-001, not escalation findings. Dedup by path.
function Get-GuerrillaAttackChainData {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings)

    $pathFails = @($Findings | Where-Object { $_.CheckId -in @('ADPATH-001', 'ADPATH-002') -and $_.Status -eq 'FAIL' })
    $map = [ordered]@{}
    foreach ($pf in $pathFails) {
        $rich = @(@($pf.Details.Paths) + @($pf.Details.Chains) | Where-Object { $null -ne $_ })
        if ($rich.Count -gt 0) {
            foreach ($c in $rich) {
                if ($c.Expected) { continue }
                $p = "$($c.Path)"
                if (-not $p -or $map.Contains($p)) { continue }
                $len = if ($c.Length) { [int]$c.Length } else { ([regex]::Matches($p, '==>').Count + 1) }
                $map[$p] = [PSCustomObject]@{ Path = $p; NonPriv = (-not $c.SourceIsPrivileged); Length = $len }
            }
        } else {
            foreach ($p in @($pf.Details.AffectedItems | Where-Object { $null -ne $_ })) {
                $ps = "$p"
                if (-not $ps -or $map.Contains($ps)) { continue }
                $map[$ps] = [PSCustomObject]@{ Path = $ps; NonPriv = $true; Length = ([regex]::Matches($ps, '==>').Count + 1) }
            }
        }
    }
    return @($map.Values)
}

# Attack Paths to Tier-0 section, rendered from the ADPATH-001/002 findings' chain detail.
# -OmitIfAbsent returns '' when there are no attack-path findings at all (e.g. a GWS-only report or
# a multi-theater report with no AD theater); otherwise it emits a coverage note when none are found.
function Get-GuerrillaAttackPathSectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [switch]$OmitIfAbsent
    )

    $pathFindings = @($Findings | Where-Object { $_.CheckId -in @('ADPATH-001', 'ADPATH-002') })
    if ($pathFindings.Count -eq 0 -and $OmitIfAbsent) { return '' }

    $chains = @((Get-GuerrillaAttackChainData -Findings $Findings) | Sort-Object `
        @{ Expression = { if ($_.NonPriv) { 0 } else { 1 } } }, `
        @{ Expression = { -1 * ([int]($_.Length ?? 0)) } })

    $css = @"
<style>
  .ap-note { color: var(--dim); font-size: 0.85em; margin: 4px 0 12px; }
  .ap-list { list-style: none; margin: 0 0 24px; padding: 0; }
  .ap-item { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--deep-orange);
             border-radius: 0 4px 4px 0; padding: 10px 14px; margin-bottom: 8px; }
  .ap-item.priv { border-left-color: var(--amber); }
  .ap-path { font-size: 0.9em; color: var(--parchment); word-break: break-word; }
  .ap-meta { font-size: 0.72em; color: var(--dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
  .ap-box { background: var(--surface-alt, var(--surface)); border: 1px solid var(--border); border-left: 4px solid var(--olive);
            border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px; }
</style>
"@

    if ($chains.Count -eq 0) {
        $ran = @($pathFindings | Where-Object Status -in @('PASS', 'FAIL')).Count -gt 0
        $msg = if ($ran) {
            'No escalation paths to Tier-0 were found in the collected ACL scope. Deep low-privilege chains require full-domain ACL collection &mdash; re-run with <code>-FullDomainAcl</code> to widen coverage.'
        } else {
            'Attack-path analysis was not run. Enable the <code>ACLDelegation</code> + <code>PrivilegedAccounts</code> categories (or <code>All</code>), and add <code>-FullDomainAcl</code> for deep transitive chains.'
        }
        return "$css<h2>Attack Paths to Tier-0</h2><div class=`"ap-box`"><p>$msg</p></div>"
    }

    $npCount = @($chains | Where-Object NonPriv).Count
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("$css<h2>Attack Paths to Tier-0</h2><p class=`"ap-note`">$($chains.Count) escalation path(s) reaching Tier-0 &mdash; $npCount from NON-privileged principals (shown first, highest risk). Each arrow is a control or membership edge an attacker can traverse.</p><ul class=`"ap-list`">")
    foreach ($c in $chains) {
        $cls = if ($c.NonPriv) { 'ap-item' } else { 'ap-item priv' }
        $meta = @()
        if ($c.Length) { $meta += "$([int]$c.Length) hop$(if ([int]$c.Length -ne 1) { 's' })" }
        $meta += if ($c.NonPriv) { 'non-privileged source' } else { 'already-privileged source' }
        [void]$sb.Append("<li class=`"$cls`"><div class=`"ap-path`">$(& $Esc $c.Path)</div><div class=`"ap-meta`">$(($meta) -join ' &middot; ')</div></li>")
    }
    [void]$sb.Append('</ul>')
    return $sb.ToString()
}

# Attack-Path Cartography: a native in-report SVG node-link map of the escalation routes to Tier-0,
# laid out left-to-right by longest-path rank. Built purely from the ADPATH chain Path strings already
# in findings (no extra data plumbing), so it renders self-contained in any report — no external tool.
# Returns '' when there are no attack-path chains. A self-contained, in-report attack-path map.
function Get-GuerrillaCartographyHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [int]$MaxChains = 25
    )

    # Same gather as the attack-path list: reads Details.Paths (ADPATH-001) + Details.Chains
    # (ADPATH-002), filters $null, excludes by-design Expected paths.
    $chainList = @(Get-GuerrillaAttackChainData -Findings $Findings)
    if ($chainList.Count -eq 0) { return '' }
    $truncated = $false
    if ($chainList.Count -gt $MaxChains) { $truncated = $true; $chainList = @($chainList | Select-Object -First $MaxChains) }

    # Parse each chain "A --[edge]--> B  ==>  B --[edge]--> C  =>  reaches ..." into nodes + edges.
    $nodes = [ordered]@{}
    $edges = [System.Collections.Generic.List[object]]::new()
    $edgeSeen = [System.Collections.Generic.HashSet[string]]::new()
    $tier0Re = '(?i)(domain admins|enterprise admins|schema admins|^administrators$|administrators \(tier)'
    $ensure = { param($n) if (-not $nodes.Contains($n)) { $nodes[$n] = @{ IsTier0 = $false; NonPrivSource = $false; IsSource = $false; IsTarget = $false } } }

    foreach ($ch in $chainList) {
        $core = ($ch.Path -replace '\s*=>\s*reaches.*$', '').Trim()
        $hops = @($core -split '\s*==>\s*')
        $firstFrom = $null; $lastTo = $null
        foreach ($h in $hops) {
            if ($h -match '^(.*?)\s+--\[(.*?)\]-->\s+(.*)$') {
                $from = $Matches[1].Trim(); $tech = $Matches[2].Trim(); $to = $Matches[3].Trim()
                if (-not $from -or -not $to) { continue }
                & $ensure $from; & $ensure $to
                if (-not $firstFrom) { $firstFrom = $from }
                $lastTo = $to
                $k = "$from|$to|$tech"
                if ($edgeSeen.Add($k)) { $edges.Add([PSCustomObject]@{ From = $from; To = $to; Tech = $tech }) }
            }
        }
        if ($firstFrom) { $nodes[$firstFrom].IsSource = $true; if ($ch.NonPriv) { $nodes[$firstFrom].NonPrivSource = $true } }
        if ($lastTo) { $nodes[$lastTo].IsTarget = $true }
    }
    if ($edges.Count -eq 0) { return '' }

    $toSet = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($e in $edges) { [void]$toSet.Add($e.To) }
    foreach ($n in @($nodes.Keys)) {
        if ($n -match $tier0Re -or $nodes[$n].IsTarget) { $nodes[$n].IsTier0 = $true }
        if (-not $toSet.Contains($n)) { $nodes[$n].IsSource = $true }
    }

    # Longest-path rank from sources (DAG; chains are acyclic and depth-bounded).
    $rank = @{}
    foreach ($n in $nodes.Keys) { $rank[$n] = 0 }
    for ($i = 0; $i -lt $nodes.Count; $i++) {
        $changed = $false
        foreach ($e in $edges) { if ($rank[$e.To] -lt $rank[$e.From] + 1) { $rank[$e.To] = $rank[$e.From] + 1; $changed = $true } }
        if (-not $changed) { break }
    }
    $maxRank = 0; foreach ($v in $rank.Values) { if ($v -gt $maxRank) { $maxRank = $v } }
    foreach ($n in @($nodes.Keys)) { if ($nodes[$n].IsTier0) { $rank[$n] = $maxRank } }  # targets on the right

    # Layout
    $nodeW = 168; $nodeH = 34; $colGap = 74; $rowGap = 22
    $colW = $nodeW + $colGap
    $byRank = @{}
    foreach ($n in $nodes.Keys) { $r = $rank[$n]; if (-not $byRank.ContainsKey($r)) { $byRank[$r] = [System.Collections.Generic.List[string]]::new() }; $byRank[$r].Add($n) }
    $pos = @{}; $maxRows = 1
    foreach ($r in ($byRank.Keys | Sort-Object)) {
        $list = $byRank[$r]
        if ($list.Count -gt $maxRows) { $maxRows = $list.Count }
        for ($j = 0; $j -lt $list.Count; $j++) { $pos[$list[$j]] = @{ X = (20 + $r * $colW); Y = (50 + $j * ($nodeH + $rowGap)) } }
    }
    $svgW = 40 + ($maxRank + 1) * $colW
    $svgH = 60 + $maxRows * ($nodeH + $rowGap) + 10
    $trunc = { param($s) if ("$s".Length -gt 22) { "$s".Substring(0, 21) + [char]0x2026 } else { "$s" } }
    $half = $nodeH / 2

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<h2>Attack-Path Cartography</h2>')
    [void]$sb.Append("<p class=`"ap-note`">Visual map of escalation routes to Tier-0. <span style='color:var(--deep-orange)'>&#9873; Red</span> = non-privileged start, <span style='color:var(--amber)'>amber</span> = already-privileged, <span style='color:var(--gold)'>&#9733; gold</span> = Tier-0 objective. Follow the arrows left to right.$(if ($truncated) { " Showing the first $MaxChains paths." })</p>")
    [void]$sb.Append("<div style='overflow-x:auto;border:1px solid var(--border);border-radius:4px;background:var(--surface);padding:8px;margin-bottom:24px'>")
    [void]$sb.Append("<svg viewBox='0 0 $svgW $svgH' width='$svgW' height='$svgH' style='max-width:100%;height:auto;font-family:var(--font-body,sans-serif)' xmlns='http://www.w3.org/2000/svg'>")
    [void]$sb.Append("<defs><marker id='ggarrow' markerWidth='9' markerHeight='9' refX='7' refY='3' orient='auto'><path d='M0,0 L7,3 L0,6 Z' fill='var(--dim)'/></marker></defs>")

    foreach ($e in $edges) {
        $a = $pos[$e.From]; $b = $pos[$e.To]
        if (-not $a -or -not $b) { continue }
        $x1 = $a.X + $nodeW; $y1 = $a.Y + $half; $x2 = $b.X; $y2 = $b.Y + $half; $mx = ($x1 + $x2) / 2
        [void]$sb.Append("<path d='M $x1 $y1 C $mx $y1 $mx $y2 $x2 $y2' fill='none' stroke='var(--dim)' stroke-width='1.5' marker-end='url(#ggarrow)' opacity='0.75'/>")
        [void]$sb.Append("<text x='$mx' y='$(($y1 + $y2) / 2 - 4)' text-anchor='middle' font-size='9' fill='var(--gold)'>$(& $Esc (& $trunc $e.Tech))</text>")
    }
    foreach ($n in $nodes.Keys) {
        $p = $pos[$n]; if (-not $p) { continue }
        $meta = $nodes[$n]
        $border = if ($meta.IsTier0) { 'var(--gold)' } elseif ($meta.NonPrivSource) { 'var(--deep-orange)' } elseif ($meta.IsSource) { 'var(--amber)' } else { 'var(--olive)' }
        $fill = if ($meta.IsTier0) { 'rgba(201,168,76,0.18)' } else { 'var(--surface-alt,var(--surface))' }
        $weight = if ($meta.IsTier0) { '700' } else { '400' }
        $icon = if ($meta.IsTier0) { [char]0x2605 + ' ' } elseif ($meta.NonPrivSource) { [char]0x2691 + ' ' } else { '' }
        [void]$sb.Append("<g><title>$(& $Esc $n)</title>")
        [void]$sb.Append("<rect x='$($p.X)' y='$($p.Y)' width='$nodeW' height='$nodeH' rx='4' fill='$fill' stroke='$border' stroke-width='2'/>")
        [void]$sb.Append("<text x='$($p.X + $nodeW / 2)' y='$($p.Y + $half + 4)' text-anchor='middle' font-size='11' font-weight='$weight' fill='var(--parchment)'>$(& $Esc ($icon + (& $trunc $n)))</text>")
        [void]$sb.Append('</g>')
    }
    [void]$sb.Append('</svg></div>')
    return $sb.ToString()
}

# Indicators of Exposure — a Purple-Knight-style ranked view of the estate's actual exposures, derived
# from the FAIL/WARN findings: each is a named, severity-scored indicator with its blast radius (affected
# count). Theme-var styled; returns '' when there are no open exposures. Theater-agnostic.
function Get-GuerrillaIndicatorsOfExposureHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [int]$Top = 12
    )

    $open = @($Findings | Where-Object { $_.Status -in @('FAIL', 'WARN') })
    if ($open.Count -eq 0) { return '' }

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $affectedOf = {
        param($f)
        $d = $f.Details
        if ($d.AffectedItems) { return @($d.AffectedItems).Count }
        if ($null -ne $d.ChainCount) { return [int]$d.ChainCount }
        if ($null -ne $d.PathCount) { return [int]$d.PathCount }
        return 1
    }

    $ind = foreach ($f in $open) {
        [PSCustomObject]@{
            Name     = "$($f.CheckName)"
            CheckId  = "$($f.CheckId)"
            Category = "$($f.Category)"
            Severity = "$($f.Severity)"
            Status   = "$($f.Status)"
            Affected = (& $affectedOf $f)
            Evidence = "$($f.CurrentValue)"
        }
    }
    $ranked = @($ind | Sort-Object `
        @{ Expression = { $sevRank["$($_.Severity)"] ?? 5 } }, `
        @{ Expression = { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } }, `
        @{ Expression = { -1 * [int]$_.Affected } }, `
        Name)

    $crit = @($open | Where-Object Severity -eq 'Critical').Count
    $high = @($open | Where-Object Severity -eq 'High').Count
    $med  = @($open | Where-Object Severity -eq 'Medium').Count
    $low  = @($open | Where-Object Severity -eq 'Low').Count

    $shown = @($ranked | Select-Object -First $Top)
    $more = $ranked.Count - $shown.Count
    $trunc = { param($s) if ("$s".Length -gt 140) { "$s".Substring(0, 138) + [char]0x2026 } else { "$s" } }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(@"
<style>
  .ioe-sum { display:flex; flex-wrap:wrap; gap:8px; margin:4px 0 12px; }
  .ioe-chip { border:1px solid var(--border); border-radius:4px; padding:4px 10px; font-size:0.8em; }
  .ioe-list { list-style:none; margin:0 0 24px; padding:0; }
  .ioe-item { display:flex; gap:12px; align-items:flex-start; background:var(--surface); border:1px solid var(--border);
              border-left:4px solid var(--dim); border-radius:0 4px 4px 0; padding:10px 14px; margin-bottom:8px; }
  .ioe-item.sev-critical { border-left-color:var(--critical); }
  .ioe-item.sev-high { border-left-color:var(--high); }
  .ioe-item.sev-medium { border-left-color:var(--medium); }
  .ioe-item.sev-low { border-left-color:var(--low); }
  .ioe-sev { flex:0 0 64px; font-size:0.68em; font-weight:700; letter-spacing:1px; text-transform:uppercase; padding-top:2px; }
  .ioe-name { font-size:0.92em; color:var(--parchment); font-weight:700; }
  .ioe-meta { font-size:0.72em; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin:2px 0; }
  .ioe-ev { font-size:0.82em; color:var(--text); word-break:break-word; }
</style>
<h2>Indicators of Exposure</h2>
<p class="ioe-note" style="color:var(--dim);font-size:0.85em;margin:4px 0 8px">$($open.Count) open exposure(s), ranked by severity and blast radius.</p>
<div class="ioe-sum">
  <span class="ioe-chip" style="color:var(--critical)">Critical: $crit</span>
  <span class="ioe-chip" style="color:var(--high)">High: $high</span>
  <span class="ioe-chip" style="color:var(--medium)">Medium: $med</span>
  <span class="ioe-chip" style="color:var(--low)">Low: $low</span>
</div>
<ul class="ioe-list">
"@)
    foreach ($i in $shown) {
        $sevClass = 'sev-' + ("$($i.Severity)").ToLower()
        $sevColor = switch ("$($i.Severity)") { 'Critical' { 'var(--critical)' } 'High' { 'var(--high)' } 'Medium' { 'var(--medium)' } 'Low' { 'var(--low)' } default { 'var(--dim)' } }
        $aff = if ($i.Affected -gt 1) { " &middot; $($i.Affected) affected" } else { '' }
        $warn = if ($i.Status -eq 'WARN') { ' &middot; warning' } else { '' }
        [void]$sb.Append("<li class=`"ioe-item $sevClass`"><div class=`"ioe-sev`" style=`"color:$sevColor`">$(& $Esc $i.Severity)</div><div><div class=`"ioe-name`">$(& $Esc $i.Name)</div><div class=`"ioe-meta`">$(& $Esc $i.Category) &middot; $(& $Esc $i.CheckId)$aff$warn</div><div class=`"ioe-ev`">$(& $Esc (& $trunc $i.Evidence))</div></div></li>")
    }
    [void]$sb.Append('</ul>')
    if ($more -gt 0) { [void]$sb.Append("<p class=`"ioe-note`" style=`"color:var(--dim);font-size:0.8em;margin-top:-16px`">+ $more more exposure(s) in the detailed findings below.</p>") }
    return $sb.ToString()
}

# Renders a finding's affected accounts/objects (from its Details hashtable) as one or more
# labeled BULLETED lists. Prefers the explicit AffectedItems/AffectedLabel convention; otherwise
# auto-detects any Details entry that is a non-empty array of scalars (strings/valuetypes) — e.g.
# ActiveSuperAdmins, StaleAdmins — and labels it by splitting the camelCase key. Caps each list at
# 25 items, appending a "+N more" bullet beyond that. HTML-encodes every item. Returns '' when there
# is nothing to render. Shared so the AD / Entra / GWS / Campaign reports all surface affected entities
# the same way.
function Get-GuerrillaReportAffectedHtml {
    param([hashtable]$Details)
    if (-not $Details -or $Details.Count -eq 0) { return '' }

    $pairs = [System.Collections.Generic.List[object]]::new()
    if ($Details.ContainsKey('AffectedItems')) {
        $lbl = if ($Details.AffectedLabel) { [string]$Details.AffectedLabel } else { 'Affected items' }
        $pairs.Add(@{ Label = $lbl; Items = @($Details.AffectedItems) })
    } else {
        foreach ($k in $Details.Keys) {
            if ($k -in @('AffectedItems', 'AffectedLabel')) { continue }
            $v = $Details[$k]
            if ($v -is [string] -or $v -is [valuetype]) { continue }
            if ($v -is [System.Collections.IEnumerable]) {
                $arr = @($v)
                if ($arr.Count -eq 0) { continue }
                $scalar = $true
                foreach ($el in $arr) {
                    if (-not ($el -is [string] -or $el -is [valuetype])) { $scalar = $false; break }
                }
                if (-not $scalar) { continue }
                $label = ($k -creplace '([a-z0-9])([A-Z])', '$1 $2')
                $pairs.Add(@{ Label = $label; Items = $arr })
            }
        }
    }

    $out = [System.Text.StringBuilder]::new()
    foreach ($p in $pairs) {
        $items = @($p.Items)
        if ($items.Count -eq 0) { continue }
        $cap = 25
        $shown = @($items | Select-Object -First $cap)
        $lbl = [System.Web.HttpUtility]::HtmlEncode([string]$p.Label)
        [void]$out.Append("<div class=`"affected`"><span class=`"affected-label`">$lbl ($($items.Count)):</span><ul class=`"affected-items`">")
        foreach ($it in $shown) {
            [void]$out.Append("<li>$([System.Web.HttpUtility]::HtmlEncode([string]$it))</li>")
        }
        if ($items.Count -gt $cap) {
            [void]$out.Append("<li class=`"more`">+$($items.Count - $cap) more</li>")
        }
        [void]$out.Append('</ul></div>')
    }
    return $out.ToString()
}

# Interactive findings filter — a live filter bar (status + severity buttons + text search)
# plus the client-side script that shows/hides any <tr class="gg-row" data-status data-sev data-text>.
# Returns the bar + <style> + <script>; the host report tags its finding rows with those attributes.
function Get-GuerrillaFindingsFilterHtml {
    [CmdletBinding()]
    param([string[]]$Statuses = @('FAIL', 'WARN', 'PASS', 'SKIP'),
          [string[]]$Severities = @('Critical', 'High', 'Medium', 'Low'))

    $statusBtns = '<button class="gg-btn active" data-f="status" data-v="all">All</button>' +
        (($Statuses | ForEach-Object { "<button class=`"gg-btn`" data-f=`"status`" data-v=`"$_`">$_</button>" }) -join '')
    $sevBtns = '<button class="gg-btn active" data-f="sev" data-v="all">All</button>' +
        (($Severities | ForEach-Object { "<button class=`"gg-btn`" data-f=`"sev`" data-v=`"$_`">$_</button>" }) -join '')

    @"
<style>
  .gg-filter { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin:16px 0; padding:10px 12px;
               background:var(--surface); border:1px solid var(--border); border-radius:4px; }
  .gg-filter .gg-lbl { font-size:0.72em; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin-right:2px; }
  .gg-btn { background:transparent; border:1px solid var(--border); border-radius:3px; padding:3px 10px;
            color:var(--text); cursor:pointer; font-family:inherit; font-size:0.78em; }
  .gg-btn:hover { background:rgba(168,181,139,0.1); }
  .gg-btn.active { background:rgba(168,181,139,0.2); border-color:var(--olive); color:var(--parchment); }
  .gg-search { flex:1 1 180px; min-width:140px; background:var(--bg); border:1px solid var(--border); border-radius:3px;
               padding:4px 8px; color:var(--text); font-family:inherit; font-size:0.82em; }
  .gg-empty { color:var(--dim); font-size:0.85em; font-style:italic; margin:8px 0; display:none; }
  @media print { .gg-filter { display:none; } }
</style>
<div class="gg-filter" id="ggFilter">
  <span class="gg-lbl">Status</span>$statusBtns
  <span class="gg-lbl" style="margin-left:8px">Severity</span>$sevBtns
  <input type="text" id="ggSearch" class="gg-search" placeholder="Search findings (id, name, value)...">
</div>
<div class="gg-empty" id="ggEmpty">No findings match the current filter.</div>
<script>
document.addEventListener('DOMContentLoaded', function () {
  var bar = document.getElementById('ggFilter'); if (!bar) return;
  var state = { status: 'all', sev: 'all', q: '' };
  function apply() {
    var q = state.q.toLowerCase(), shown = 0;
    document.querySelectorAll('tr.gg-row').forEach(function (r) {
      var okS = state.status === 'all' || (r.getAttribute('data-status') || '').toUpperCase() === state.status.toUpperCase();
      var okV = state.sev === 'all' || (r.getAttribute('data-sev') || '').toUpperCase() === state.sev.toUpperCase();
      var okQ = q === '' || (r.getAttribute('data-text') || '').indexOf(q) >= 0;
      var vis = okS && okV && okQ; r.style.display = vis ? '' : 'none'; if (vis) shown++;
    });
    var active = state.status !== 'all' || state.sev !== 'all' || q !== '';
    if (active) { document.querySelectorAll('details.cat-detail').forEach(function (d) { d.open = true; }); }
    var e = document.getElementById('ggEmpty'); if (e) { e.style.display = (shown === 0) ? 'block' : 'none'; }
  }
  bar.querySelectorAll('button[data-f]').forEach(function (b) {
    b.addEventListener('click', function () {
      var t = b.getAttribute('data-f'); state[t] = b.getAttribute('data-v');
      bar.querySelectorAll('button[data-f="' + t + '"]').forEach(function (x) { x.classList.remove('active'); });
      b.classList.add('active'); apply();
    });
  });
  var s = document.getElementById('ggSearch'); if (s) { s.addEventListener('input', function () { state.q = s.value; apply(); }); }
});
</script>
"@
}
