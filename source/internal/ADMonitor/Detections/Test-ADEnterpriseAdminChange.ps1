# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADEnterpriseAdminChange {
    [CmdletBinding()]
    param(
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    $eaChange = $GroupChanges | Where-Object { $_.Group -eq 'Enterprise Admins' } | Select-Object -First 1
    if (-not $eaChange) { return @() }
    if ($eaChange.Added.Count -eq 0 -and $eaChange.Removed.Count -eq 0) { return @() }

    $details = [System.Collections.Generic.List[string]]::new()

    if ($eaChange.Added.Count -gt 0) {
        $details.Add("Added to Enterprise Admins: $($eaChange.Added -join ', ')")
    }
    if ($eaChange.Removed.Count -gt 0) {
        $details.Add("Removed from Enterprise Admins: $($eaChange.Removed -join ', ')")
    }

    $detailStr = $details -join ' | '
    $detectionId = "adEnterpriseAdminChange_$(($eaChange.Added + $eaChange.Removed | Sort-Object) -join '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'Enterprise Admins Membership Change'
        DetectionType = 'adEnterpriseAdminChange'
        Description   = "ENTERPRISE ADMINS CHANGE - $detailStr"
        Details       = @{
            Group   = 'Enterprise Admins'
            Added   = @($eaChange.Added)
            Removed = @($eaChange.Removed)
        }
        Count         = $eaChange.Added.Count + $eaChange.Removed.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
