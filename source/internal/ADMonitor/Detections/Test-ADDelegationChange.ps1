# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADDelegationChange {
    [CmdletBinding()]
    param(
        [array]$DelegationChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($DelegationChanges.Count -eq 0) { return @() }

    foreach ($change in $DelegationChanges) {
        $ouDN = $change.OUDN
        $shortOU = if ($ouDN -match '^(OU=[^,]+)') { $Matches[1] } else { $ouDN }
        $entryCount = if ($change.ContainsKey('Entries')) { $change.Entries.Count } else { 0 }

        $description = switch ($change.ChangeType) {
            'Added'    { "New delegation permissions on $shortOU ($entryCount entries)" }
            'Modified' { "Delegation permissions modified on $shortOU" }
            default    { $change.Details }
        }

        # Check for particularly dangerous delegations
        $dangerousEntries = @()
        if ($change.ContainsKey('Entries')) {
            $dangerousEntries = @($change.Entries | Where-Object {
                $_.rights -match 'GenericAll|WriteDacl|WriteOwner'
            })
        }

        if ($dangerousEntries.Count -gt 0) {
            $description += " WARNING: $($dangerousEntries.Count) entry(ies) grant GenericAll/WriteDacl/WriteOwner"
        }

        $detectionId = "adDelegationChange_$($ouDN -replace '[=,\s]', '_')_$($change.ChangeType)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Delegation Change: $shortOU"
            DetectionType = 'adDelegationChange'
            Description   = "DELEGATION CHANGE - $description"
            Details       = @{
                OUDN       = $ouDN
                ChangeType = $change.ChangeType
                Entries    = if ($change.ContainsKey('Entries')) { @($change.Entries) } else { @() }
                DangerousCount = $dangerousEntries.Count
            }
            Count         = [Math]::Max(1, $entryCount)
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
