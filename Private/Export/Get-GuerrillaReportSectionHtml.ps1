# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
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
        $catRows += "<tr><td>$(& $Esc ([string]$cl.Category))</td><td style='color:$cc;font-weight:700'>Level $([int]$cl.Level)</td><td>$(& $Esc ([string]$cl.Label))</td></tr>"
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

    $pathFails = @($pathFindings | Where-Object Status -eq 'FAIL')
    $chainMap = [ordered]@{}
    foreach ($pf in $pathFails) {
        $rich = @($pf.Details.Chains)
        if ($rich.Count -gt 0) {
            foreach ($cc in $rich) {
                $p = "$($cc.Path)"
                if ($p -and -not $chainMap.Contains($p)) {
                    $chainMap[$p] = [PSCustomObject]@{ Path = $p; NonPriv = (-not $cc.SourceIsPrivileged); Length = $cc.Length }
                }
            }
        } else {
            foreach ($p in @($pf.Details.AffectedItems)) {
                $ps = "$p"
                if ($ps -and -not $chainMap.Contains($ps)) {
                    $chainMap[$ps] = [PSCustomObject]@{ Path = $ps; NonPriv = $true; Length = $null }
                }
            }
        }
    }
    $chains = @($chainMap.Values | Sort-Object `
        @{ Expression = { if ($_.NonPriv) { 0 } else { 1 } } }, `
        @{ Expression = { -1 * ([int]($_.Length ?? 0)) } })

    $css = @"
<style>
  .ap-note { color: var(--dim); font-size: 0.85em; margin: 4px 0 12px; }
  .ap-list { list-style: none; margin: 0 0 24px; padding: 0; }
  .ap-item { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--fail);
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
