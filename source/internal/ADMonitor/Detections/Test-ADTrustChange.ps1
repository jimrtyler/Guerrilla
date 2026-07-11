# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADTrustChange {
    [CmdletBinding()]
    param(
        [array]$TrustChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($TrustChanges.Count -eq 0) { return @() }

    foreach ($change in $TrustChanges) {
        $description = switch ($change.ChangeType) {
            'Added'    { "New trust relationship: $($change.Name) ($($change.Direction), $($change.Type))" }
            'Modified' { "Trust modified: $($change.Details)" }
            'Removed'  { "Trust removed: $($change.Name)" }
            default    { $change.Details }
        }

        # New trusts are especially concerning
        $detectionType = if ($change.ChangeType -eq 'Added') { 'adNewTrust' } else { 'adTrustModified' }

        $detectionId = "adTrustChange_$($change.Name -replace '\.', '_')_$($change.ChangeType)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Trust $($change.ChangeType): $($change.Name)"
            DetectionType = $detectionType
            Description   = "TRUST CHANGE - $description"
            Details       = @{
                Name       = $change.Name
                ChangeType = $change.ChangeType
                Direction  = $change.Direction
                Type       = $change.Type
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
