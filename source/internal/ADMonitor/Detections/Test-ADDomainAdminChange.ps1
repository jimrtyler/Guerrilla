# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADDomainAdminChange {
    [CmdletBinding()]
    param(
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    $daChange = $GroupChanges | Where-Object { $_.Group -eq 'Domain Admins' } | Select-Object -First 1
    if (-not $daChange) { return @() }
    if ($daChange.Added.Count -eq 0 -and $daChange.Removed.Count -eq 0) { return @() }

    $details = [System.Collections.Generic.List[string]]::new()

    if ($daChange.Added.Count -gt 0) {
        $details.Add("Added to Domain Admins: $($daChange.Added -join ', ')")
    }
    if ($daChange.Removed.Count -gt 0) {
        $details.Add("Removed from Domain Admins: $($daChange.Removed -join ', ')")
    }

    $detailStr = $details -join ' | '
    $detectionId = "adDomainAdminChange_$(($daChange.Added + $daChange.Removed | Sort-Object) -join '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'Domain Admins Membership Change'
        DetectionType = 'adDomainAdminChange'
        Description   = "DOMAIN ADMINS CHANGE - $detailStr"
        Details       = @{
            Group   = 'Domain Admins'
            Added   = @($daChange.Added)
            Removed = @($daChange.Removed)
        }
        Count         = $daChange.Added.Count + $daChange.Removed.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
