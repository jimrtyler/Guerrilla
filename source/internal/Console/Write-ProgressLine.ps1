# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-ProgressLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SCANNING', 'ENRICHING', 'ANALYZING', 'REPORTING', 'SIGNALING', 'INFO', 'AUDITING', 'FORTIFYING', 'RECON', 'INFILTRATE', 'CAMPAIGN', 'WIRETAP')]
        [string]$Phase,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Detail
    )

    # Test mode renders a zeroed timestamp so demo/sample console output is deterministic.
    $utcNow = if ($script:GuerrillaTestMode) { '0000' } else { [datetime]::UtcNow.ToString('HHmm') }

    $phaseColor = switch ($Phase) {
        'SCANNING'  { 'Olive' }
        'ENRICHING' { 'Gold' }
        'ANALYZING' { 'Amber' }
        'REPORTING' { 'Sage' }
        'SIGNALING'  { 'Parchment' }
        'INFO'       { 'Dim' }
        'AUDITING'   { 'Sage' }
        'FORTIFYING' { 'Gold' }
        'RECON'      { 'Olive' }
        'INFILTRATE' { 'Amber' }
        'CAMPAIGN'   { 'Parchment' }
        'WIRETAP'    { 'Amber' }
    }

    Write-GuerrillaText "  [$utcNow UTC] " -Color Dim -NoNewline
    Write-GuerrillaText ('{0,-10}' -f $Phase) -Color $phaseColor -NoNewline
    Write-GuerrillaText " > " -Color Dim -NoNewline
    Write-GuerrillaText $Message -Color Olive -NoNewline

    if ($Detail) {
        Write-GuerrillaText " $Detail" -Color Gold
    } else {
        Write-Host ''
    }
}
