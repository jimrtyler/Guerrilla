# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-GuerrillaText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [ValidateSet('Olive', 'Amber', 'Sage', 'Parchment', 'Gold', 'Dim', 'DeepOrange', 'DarkRed', 'White', 'Reset')]
        [string]$Color = 'Olive',

        [switch]$NoNewline,
        [switch]$Bold
    )

    # Respect NO_COLOR convention
    if ($env:NO_COLOR) {
        if ($NoNewline) { Write-Host $Text -NoNewline }
        else { Write-Host $Text }
        return
    }

    $esc = [char]0x1b
    $colorCodes = @{
        Olive      = '38;5;143'
        Amber      = '38;5;208'
        Sage       = '38;5;108'
        Parchment  = '38;5;223'
        Gold       = '38;5;179'
        Dim        = '38;5;240'
        DeepOrange = '38;5;166'
        DarkRed    = '38;5;124'
        White      = '38;5;255'
        Reset      = '0'
    }

    $code = $colorCodes[$Color]
    $boldPrefix = if ($Bold) { '1;' } else { '' }
    $ansi = "$esc[${boldPrefix}${code}m"
    $reset = "$esc[0m"

    if ($NoNewline) {
        Write-Host "${ansi}${Text}${reset}" -NoNewline
    } else {
        Write-Host "${ansi}${Text}${reset}"
    }
}
