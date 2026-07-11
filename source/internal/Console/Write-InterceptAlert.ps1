# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-InterceptAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$NewThreats
    )

    if ($NewThreats.Count -eq 0) { return }

    Write-Host ''
    Write-GuerrillaText ('!' * 62) -Color Amber
    Write-GuerrillaText '  !! INTERCEPT: NEW COMPROMISES DETECTED !!' -Color Amber -Bold
    Write-GuerrillaText ('!' * 62) -Color Amber

    foreach ($p in $NewThreats) {
        $levelColor = switch ($p.ThreatLevel) {
            'CRITICAL' { 'DarkRed' }
            'HIGH'     { 'DeepOrange' }
            'MEDIUM'   { 'Amber' }
            default    { 'Gold' }
        }

        Write-GuerrillaText "    >> " -Color Amber -NoNewline
        Write-GuerrillaText $p.Email -Color White -Bold -NoNewline
        Write-GuerrillaText "  (score: " -Color Dim -NoNewline
        Write-GuerrillaText ('{0:N0}' -f $p.ThreatScore) -Color $levelColor -NoNewline
        Write-GuerrillaText ", " -Color Dim -NoNewline
        Write-GuerrillaText $p.ThreatLevel -Color $levelColor -NoNewline
        Write-GuerrillaText ")" -Color Dim

        foreach ($ind in $p.Indicators) {
            Write-GuerrillaText "       - $ind" -Color Olive
        }
    }
}
