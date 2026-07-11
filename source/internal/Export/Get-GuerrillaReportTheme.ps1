# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Report theming engine. A "style" maps to (a) a palette of CSS custom properties
# that every HTML exporter references by the SAME variable names, and (b) a
# lexicon flag deciding whether the tactical "guerrilla" score labels
# (FORTRESS / EXPOSED FLANK / OVERRUN) are kept or replaced with plain,
# risk-based infosec language. The Guerrilla / Jim Tyler footer attribution is
# never themed away — it is emitted by every exporter regardless of style.

function Get-GuerrillaReportTheme {
    [CmdletBinding()]
    param(
        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional'
    )

    $mono = "'Fira Code', 'JetBrains Mono', Consolas, 'Courier New', monospace"
    $sans = "'Segoe UI', 'Helvetica Neue', Arial, system-ui, sans-serif"

    switch ($Style) {
        'Professional' {
            # Light / white corporate theme, plain language, sans-serif body.
            return @{
                Name        = 'Professional'
                PlainLabels = $true
                Vars        = [ordered]@{
                    'font-body'    = $sans
                    'bg'           = '#ffffff'; 'surface' = '#f8fafc'; 'surface-alt' = '#eef2f7'; 'border' = '#d8dee9'
                    'text'         = '#1e293b'; 'text-muted' = '#64748b'
                    'olive'        = '#0f766e'; 'amber' = '#c2620f'; 'sage' = '#15803d'
                    'parchment'    = '#0f172a'; 'gold' = '#b7791f'; 'dim' = '#64748b'
                    'deep-orange'  = '#c2410c'; 'dark-red' = '#b91c1c'
                    'critical'     = '#b91c1c'; 'high' = '#c2410c'; 'medium' = '#b45309'
                    'low'          = '#15803d'; 'clean' = '#15803d'
                    'pass'         = '#15803d'; 'fail' = '#b91c1c'; 'warn' = '#b45309'; 'skip' = '#94a3b8'; 'info' = '#1d4ed8'
                }
            }
        }
        'Slate' {
            # Modern dark dashboard theme, plain language, sans-serif body.
            return @{
                Name        = 'Slate'
                PlainLabels = $true
                Vars        = [ordered]@{
                    'font-body'    = $sans
                    'bg'           = '#0f172a'; 'surface' = '#1e293b'; 'surface-alt' = '#28364a'; 'border' = '#334155'
                    'text'         = '#e2e8f0'; 'text-muted' = '#94a3b8'
                    'olive'        = '#38bdf8'; 'amber' = '#f59e0b'; 'sage' = '#22c55e'
                    'parchment'    = '#f1f5f9'; 'gold' = '#eab308'; 'dim' = '#64748b'
                    'deep-orange'  = '#f97316'; 'dark-red' = '#ef4444'
                    'critical'     = '#ef4444'; 'high' = '#f97316'; 'medium' = '#eab308'
                    'low'          = '#22c55e'; 'clean' = '#22c55e'
                    'pass'         = '#22c55e'; 'fail' = '#ef4444'; 'warn' = '#eab308'; 'skip' = '#64748b'; 'info' = '#38bdf8'
                }
            }
        }
        default {
            # Guerrilla — the original tactical theme. Values match the legacy inline
            # :root blocks so existing reports render identically.
            return @{
                Name        = 'Guerrilla'
                PlainLabels = $false
                Vars        = [ordered]@{
                    'font-body'    = $mono
                    'bg'           = '#1a1f16'; 'surface' = '#242b1e'; 'surface-alt' = '#2d3526'; 'border' = '#3d4a35'
                    'text'         = '#d4c9a8'; 'text-muted' = '#8a8468'
                    'olive'        = '#a8b58b'; 'amber' = '#d4883a'; 'sage' = '#6b9b6b'
                    'parchment'    = '#d4c4a0'; 'gold' = '#c9a84c'; 'dim' = '#6b6b5a'
                    'deep-orange'  = '#c75c2e'; 'dark-red' = '#8b2500'
                    'critical'     = '#c75c2e'; 'high' = '#d4883a'; 'medium' = '#c9a84c'
                    'low'          = '#6b9b6b'; 'clean' = '#4a7a4a'
                    'pass'         = '#4a7a4a'; 'fail' = '#c75c2e'; 'warn' = '#c9a84c'; 'skip' = '#6b6b5a'; 'info' = '#a8b58b'
                }
            }
        }
    }
}

# Emit the <style>-inner CSS for a theme: the :root custom-property block (which
# every exporter's existing CSS references) plus the shared white-label classes.
# Drop-in replacement for the legacy hardcoded ":root { ... }" block.
function Get-GuerrillaReportThemeStyleBlock {
    [CmdletBinding()]
    param(
        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional'
    )

    $theme = Get-GuerrillaReportTheme -Style $Style
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('  :root {')
    foreach ($k in $theme.Vars.Keys) {
        [void]$sb.Append(" --$k`: $($theme.Vars[$k]);")
    }
    [void]$sb.AppendLine(' }')

    # White-label header / confidentiality-banner styling (theme-independent;
    # references the same custom properties so it adapts to every palette).
    [void]$sb.AppendLine(@'
  .wl-banner { background: var(--dark-red); color: #fff; text-align: center;
    padding: 6px 12px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
    font-size: 0.78em; margin: 0 0 20px 0; border-radius: 4px; }
  .wl-header { display: flex; align-items: center; gap: 16px; margin-bottom: 20px;
    padding-bottom: 16px; border-bottom: 1px solid var(--border); }
  .wl-header img { max-height: 56px; max-width: 220px; object-fit: contain; }
  .wl-firm { font-size: 1.15em; font-weight: 700; color: var(--parchment); letter-spacing: 0.5px; }
  .wl-meta { font-size: 0.82em; color: var(--text-muted); margin-top: 2px; }
'@)
    return $sb.ToString()
}

# Resolve the score label for an exporter. Plain themes get risk-based language;
# the Guerrilla theme keeps whatever tactical label the caller already computed.
function Resolve-GuerrillaReportScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Score,
        [ValidateSet('Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Professional',
        [string]$Fallback = ''
    )

    $theme = Get-GuerrillaReportTheme -Style $Style
    if (-not $theme.PlainLabels) { return $Fallback }

    if ($Score -ge 90) { return 'Secure' }
    if ($Score -ge 75) { return 'Hardened' }
    if ($Score -ge 60) { return 'Moderate Risk' }
    if ($Score -ge 40) { return 'Elevated Risk' }
    if ($Score -ge 20) { return 'High Risk' }
    return 'Critical Risk'
}

# Extract a normalized branding hashtable from a loaded config (the `branding`
# section of config.json). Returns $null when no branding is configured.
function Get-GuerrillaBranding {
    [CmdletBinding()]
    param($Config)

    if (-not $Config) { return $null }
    $b = $Config.branding
    if (-not $b) { return $null }

    $out = @{}
    foreach ($k in 'FirmName', 'LogoPath', 'ConsultantName', 'ConsultantEmail', 'ClientName', 'Confidentiality') {
        $v = $null
        if ($b -is [System.Collections.IDictionary]) { $v = $b[$k] }
        elseif ($b.PSObject.Properties[$k]) { $v = $b.$k }
        if ($v) { $out[$k] = [string]$v }
    }
    if ($out.Count -eq 0) { return $null }
    return $out
}

# Build the white-label banner + header HTML from a branding hashtable. Returns a
# hashtable with Banner and Header strings (either may be empty). Keys honoured:
# FirmName, LogoPath, ConsultantName, ConsultantEmail, ClientName, Confidentiality.
function Get-GuerrillaReportBrandingHtml {
    [CmdletBinding()]
    param([hashtable]$Branding)

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $result = @{ Banner = ''; Header = '' }
    if (-not $Branding -or $Branding.Count -eq 0) { return $result }

    $firm    = [string]($Branding.FirmName ?? '')
    $logo    = [string]($Branding.LogoPath ?? '')
    $name    = [string]($Branding.ConsultantName ?? '')
    $email   = [string]($Branding.ConsultantEmail ?? '')
    $client  = [string]($Branding.ClientName ?? '')
    $conf    = [string]($Branding.Confidentiality ?? '')

    if ($conf) {
        $result.Banner = "<div class=`"wl-banner`">$(& $esc $conf)</div>"
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($logo) { $parts.Add("<img src=`"$(& $esc $logo)`" alt=`"`">") }

    $textParts = [System.Collections.Generic.List[string]]::new()
    if ($firm) { $textParts.Add("<div class=`"wl-firm`">$(& $esc $firm)</div>") }
    if ($name) {
        $by = "Prepared by $(& $esc $name)"
        if ($email) { $by += " &middot; $(& $esc $email)" }
        $textParts.Add("<div class=`"wl-meta`">$by</div>")
    }
    if ($client) { $textParts.Add("<div class=`"wl-meta`">Prepared for $(& $esc $client)</div>") }

    if ($textParts.Count -gt 0) {
        $parts.Add("<div>$($textParts -join '')</div>")
    }

    if ($parts.Count -gt 0) {
        $result.Header = "<div class=`"wl-header`">$($parts -join '')</div>"
    }
    return $result
}
