# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Append a scan-history entry to a monitoring theater's prior history and return it as a
# proper array. Used by Invoke-Surveillance / Invoke-Wiretap.
#
# This exists because the previous inline idiom — `@($state.scanHistory) += @{...}` —
# crashed every run after the first (MON-4): a single-entry history reloads from JSON in a
# shape where the `+=` performs a hashtable-key merge and throws "Item has already been
# added". Building with a List and explicitly handling a single-dictionary (collapsed)
# prior value avoids the merge entirely and always yields an array.
function Add-ScanHistoryEntry {
    [CmdletBinding()]
    param(
        # $state.scanHistory from a loaded theater state: may be an array of entries, a
        # single hashtable (if a 1-element array collapsed on serialization), or $null.
        $ExistingHistory,

        [Parameter(Mandatory)]
        [hashtable]$Entry
    )

    $list = [System.Collections.Generic.List[object]]::new()
    if ($ExistingHistory) {
        if ($ExistingHistory -is [System.Collections.IDictionary]) {
            [void]$list.Add($ExistingHistory)
        } else {
            foreach ($h in @($ExistingHistory)) { [void]$list.Add($h) }
        }
    }
    [void]$list.Add($Entry)
    return @($list)
}
