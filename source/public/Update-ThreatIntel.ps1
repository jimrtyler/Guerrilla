# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Update-ThreatIntel {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param(
        [switch]$Force
    )

    if (-not $PSCmdlet.ShouldProcess('Threat intelligence data files', 'Update from upstream sources')) {
        return
    }

    Write-GuerrillaText 'Updating threat intelligence data...' -Color Olive

    $result = Update-ThreatIntelData -Force:$Force

    if ($result.Updated) {
        Write-GuerrillaText 'Threat intel data updated successfully.' -Color Sage
        if ($result.Errors.Count -gt 0) {
            Write-GuerrillaText "Some sources had errors:" -Color Amber
            foreach ($err in $result.Errors) {
                Write-GuerrillaText "  - $err" -Color Amber
            }
        }
        Write-GuerrillaText 'Reload the module to apply: Import-Module Guerrilla -Force' -Color Dim
    } else {
        Write-GuerrillaText "No update needed: $($result.Reason)" -Color Dim
    }

    [PSCustomObject]@{
        Updated = $result.Updated
        Reason  = $result.Reason
        Errors  = $result.Errors
    }
}
