# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Pure comparator for Microsoft Entra Connect (formerly Azure AD Connect) sync-client
# version currency. Given an installed version string and a minimum-safe baseline, it
# returns whether the installed build is current (>= baseline) or outdated (< baseline).
# Offline-testable; no Graph or registry calls — those live in the EIDFED-013 logic
# function. Discipline mirrors Resolve-EidscaControl: when the version cannot be parsed
# (null / malformed) the comparator NEVER claims "current"; it reports IsAssessable = $false
# so the caller surfaces a Not-Assessed / WARN finding rather than a false PASS.

# ── MINIMUM-SAFE BASELINE (DATA — bump this when Microsoft ships a newer build) ──
# Microsoft Entra Connect 2.6.79.0 shipped undisclosed security fixes with an
# "update fast" advisory. Running below this build = unpatched Tier-0 hybrid component.
# Update this constant whenever a newer security build is released by Microsoft.
$script:EntraConnectMinimumSafeVersion = '2.6.79.0'

function Test-EntraConnectVersionCurrent {
    [CmdletBinding()]
    param(
        # The Entra Connect build read from the server (e.g. '2.6.79.0'). May be null/malformed.
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$InstalledVersion,

        # The minimum-safe baseline. Defaults to the module constant so callers can omit it.
        [Parameter(Position = 1)]
        [string]$MinimumSafeVersion = $script:EntraConnectMinimumSafeVersion
    )

    $result = [ordered]@{
        InstalledVersion   = $InstalledVersion
        MinimumSafeVersion = $MinimumSafeVersion
        IsAssessable       = $false   # could we parse a real version? (false => never PASS)
        IsCurrent          = $false   # only meaningful when IsAssessable is $true
        Comparison         = $null    # -1 outdated, 0 equal, 1 newer; $null when not assessable
    }

    $parsedInstalled = $null
    $parsedBaseline  = $null

    # [version] is strict about format; normalise/guard so malformed input can't crash us.
    $installedOk = -not [string]::IsNullOrWhiteSpace($InstalledVersion) -and
                   [version]::TryParse($InstalledVersion.Trim(), [ref]$parsedInstalled)
    $baselineOk  = -not [string]::IsNullOrWhiteSpace($MinimumSafeVersion) -and
                   [version]::TryParse($MinimumSafeVersion.Trim(), [ref]$parsedBaseline)

    if (-not $installedOk -or -not $baselineOk) {
        # Honesty rule: an unreadable version is NOT compliance. Leave IsAssessable = $false.
        return [PSCustomObject]$result
    }

    $cmp = $parsedInstalled.CompareTo($parsedBaseline)
    $result.IsAssessable = $true
    $result.Comparison   = $cmp
    $result.IsCurrent    = $cmp -ge 0   # equal or newer than the baseline is current

    return [PSCustomObject]$result
}
