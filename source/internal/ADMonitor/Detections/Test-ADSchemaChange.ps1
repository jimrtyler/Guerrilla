# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADSchemaChange {
    [CmdletBinding()]
    param(
        [array]$SchemaChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($SchemaChanges.Count -eq 0) { return @() }

    foreach ($change in $SchemaChanges) {
        $prevVersion = if ($change.ContainsKey('PreviousVersion')) { $change.PreviousVersion } else { 'unknown' }
        $currentVersion = if ($change.ContainsKey('CurrentVersion')) { $change.CurrentVersion } else { 'unknown' }

        $detectionId = "adSchemaChange_${prevVersion}_to_${currentVersion}"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = 'AD Schema Version Changed'
            DetectionType = 'adSchemaChange'
            Description   = "SCHEMA CHANGE - Active Directory schema version changed from $prevVersion to $currentVersion. Schema modifications are irreversible and affect all domain controllers. This may indicate a forest upgrade or unauthorized schema extension."
            Details       = @{
                PreviousVersion = $prevVersion
                CurrentVersion  = $currentVersion
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
