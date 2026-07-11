# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADGPOLinkChange {
    [CmdletBinding()]
    param(
        [array]$GPOLinkChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($GPOLinkChanges.Count -eq 0) { return @() }

    foreach ($change in $GPOLinkChanges) {
        $detectionId = "adGPOLinkChange_$($change.GUID)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "GPO Link Change: $($change.Name)"
            DetectionType = 'adGPOLinkChange'
            Description   = "GPO LINK CHANGE - GPO '$($change.Name)' link configuration modified"
            Details       = @{
                GUID = $change.GUID
                Name = $change.Name
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
