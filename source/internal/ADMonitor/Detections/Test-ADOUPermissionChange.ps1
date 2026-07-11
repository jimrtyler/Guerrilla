# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADOUPermissionChange {
    [CmdletBinding()]
    param(
        [array]$ACLChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($ACLChanges.Count -eq 0) { return @() }

    # Filter to OU-related ACL changes (not AdminSDHolder, not domain root)
    $ouChanges = @($ACLChanges | Where-Object {
        $_.ObjectDN -ne 'AdminSDHolder' -and (
            ($_.ContainsKey('ObjectDN') -and $_.ObjectDN -match 'OU=') -or
            ($_.ContainsKey('ObjectName') -and $_.ObjectName -match 'OU=')
        )
    })

    if ($ouChanges.Count -eq 0) { return @() }

    # Group by object
    $byObject = @{}
    foreach ($change in $ouChanges) {
        $key = if ($change.ContainsKey('ObjectName')) { $change.ObjectName } else { $change.ObjectDN }
        if (-not $byObject.ContainsKey($key)) {
            $byObject[$key] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $byObject[$key].Add($change)
    }

    foreach ($objName in $byObject.Keys) {
        $objChanges = @($byObject[$objName])
        $detectionId = "adOUPermissionChange_$($objName -replace '[=,\s\\\/]', '_')"

        $changeDescriptions = @($objChanges | ForEach-Object {
            $identity = if ($_.ContainsKey('Identity')) { $_.Identity } else { 'Unknown' }
            $rights = if ($_.ContainsKey('Rights')) { $_.Rights } else { '' }
            "$($_.ChangeType): $identity ($rights)"
        })

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "OU Permission Change: $objName"
            DetectionType = 'adOUPermissionChange'
            Description   = "OU PERMISSION CHANGE - ACL modified on '$objName': $($changeDescriptions -join '; ')"
            Details       = @{
                ObjectName = $objName
                Changes    = @($objChanges)
            }
            Count         = $objChanges.Count
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
