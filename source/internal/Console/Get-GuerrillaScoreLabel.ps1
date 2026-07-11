# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$Score
    )

    $result = switch ($true) {
        ($Score -ge 90) { @{ Label = 'FORTRESS';          Color = 'Sage' }; break }
        ($Score -ge 75) { @{ Label = 'DEFENDED POSITION'; Color = 'Sage' }; break }
        ($Score -ge 60) { @{ Label = 'CONTESTED GROUND';  Color = 'Gold' }; break }
        ($Score -ge 40) { @{ Label = 'EXPOSED FLANK';     Color = 'Amber' }; break }
        ($Score -ge 20) { @{ Label = 'UNDER SIEGE';       Color = 'DeepOrange' }; break }
        default         { @{ Label = 'OVERRUN';           Color = 'DarkRed' } }
    }

    return $result
}
