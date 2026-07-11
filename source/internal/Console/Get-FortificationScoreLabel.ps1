# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-FortificationScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Score
    )

    if ($Score -ge 90) { return 'FORTRESS' }
    if ($Score -ge 75) { return 'HARDENED POSITION' }
    if ($Score -ge 60) { return 'CONTESTED PERIMETER' }
    if ($Score -ge 40) { return 'EXPOSED FLANK' }
    if ($Score -ge 20) { return 'BREACHABLE' }
    return 'UNFORTIFIED'
}
