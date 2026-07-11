# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-OperationHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Operation,

        [string]$Mode,
        [string]$Target,
        [int]$DaysBack
    )

    # Test mode renders a zeroed time so demo/sample console output is deterministic.
    $utcNow = if ($script:GuerrillaTestMode) { '0000' } else { [datetime]::UtcNow.ToString('HHmm') }
    $dateStr = [datetime]::UtcNow.ToString('yyyy-MM-dd')

    Write-Host ''
    Write-GuerrillaText ('=' * 62) -Color Dim
    Write-GuerrillaText "  OPERATION: " -Color Dim -NoNewline
    Write-GuerrillaText $Operation -Color Parchment -Bold
    if ($Mode) {
        Write-GuerrillaText "  Mode: " -Color Dim -NoNewline
        Write-GuerrillaText $Mode -Color Gold -NoNewline
        if ($DaysBack) {
            Write-GuerrillaText "  |  Lookback: " -Color Dim -NoNewline
            Write-GuerrillaText "$DaysBack days" -Color Gold
        } else {
            Write-Host ''
        }
    }
    if ($Target) {
        Write-GuerrillaText "  Target: " -Color Dim -NoNewline
        Write-GuerrillaText $Target -Color Olive
    }
    Write-GuerrillaText "  $dateStr  $utcNow UTC" -Color Dim
    Write-GuerrillaText ('=' * 62) -Color Dim
}
