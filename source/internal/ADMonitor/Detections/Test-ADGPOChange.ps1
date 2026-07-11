# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADGPOChange {
    [CmdletBinding()]
    param(
        [array]$GPOChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($GPOChanges.Count -eq 0) { return @() }

    foreach ($change in $GPOChanges) {
        $description = switch ($change.ChangeType) {
            'Added'    { "New GPO created: $($change.Name) ($($change.GUID))" }
            'Modified' { "GPO content modified: $($change.Name) (v$($change.PreviousVersion) -> v$($change.CurrentVersion))" }
            'Removed'  { "GPO deleted: $($change.Name) ($($change.GUID))" }
            default    { $change.Details }
        }

        $detectionId = "adGPOModification_$($change.GUID)_$($change.ChangeType)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "GPO $($change.ChangeType): $($change.Name)"
            DetectionType = 'adGPOModification'
            Description   = "GPO MODIFICATION - $description"
            Details       = @{
                GUID            = $change.GUID
                Name            = $change.Name
                ChangeType      = $change.ChangeType
                PreviousVersion = if ($change.ContainsKey('PreviousVersion')) { $change.PreviousVersion } else { $null }
                CurrentVersion  = if ($change.ContainsKey('CurrentVersion')) { $change.CurrentVersion } else { $null }
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
