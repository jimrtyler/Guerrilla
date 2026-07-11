# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADDCSyncPermission {
    [CmdletBinding()]
    param(
        [array]$ACLChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($ACLChanges.Count -eq 0) { return @() }

    # DCSync requires these rights on the domain root:
    # DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    # DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
    # DS-Replication-Get-Changes-In-Filtered-Set: 89e95b76-444d-4c62-991a-0facbeda640c
    $dcsyncGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',    # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',    # DS-Replication-Get-Changes-All
        '89e95b76-444d-4c62-991a-0facbeda640c'      # DS-Replication-Get-Changes-In-Filtered-Set
    )

    $dcsyncGuidNames = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c'  = 'DS-Replication-Get-Changes-In-Filtered-Set'
    }

    $addedACEs = @($ACLChanges | Where-Object { $_.ChangeType -eq 'Added' })

    foreach ($ace in $addedACEs) {
        $rights = if ($ace.ContainsKey('Rights')) { $ace.Rights } else { '' }
        $objectType = if ($ace.ContainsKey('objectType')) { $ace.objectType } else { '' }

        # Check for replication rights
        $isDCSync = $false
        $grantedRight = ''

        if ($rights -match 'ExtendedRight|GenericAll') {
            foreach ($guid in $dcsyncGuids) {
                if ($objectType -eq $guid -or $objectType -eq "DS-Replication-Get-Changes" -or
                    $objectType -eq "DS-Replication-Get-Changes-All") {
                    $isDCSync = $true
                    $grantedRight = if ($dcsyncGuidNames.ContainsKey($objectType)) { $dcsyncGuidNames[$objectType] } else { $objectType }
                    break
                }
            }

            # GenericAll grants all extended rights including DCSync
            if (-not $isDCSync -and $rights -match 'GenericAll' -and (-not $objectType -or $objectType -eq '')) {
                $isDCSync = $true
                $grantedRight = 'GenericAll (includes all replication rights)'
            }
        }

        if ($isDCSync) {
            $identity = if ($ace.ContainsKey('Identity')) { $ace.Identity } else { 'Unknown' }
            $detectionId = "adDCSyncPermission_$($identity -replace '[\\\/\s]', '_')"

            $indicators.Add([PSCustomObject]@{
                DetectionId   = $detectionId
                DetectionName = "DCSync Permission Granted to $identity"
                DetectionType = 'adDCSyncPermission'
                Description   = "DCSYNC PERMISSION - Replication rights granted to '$identity': $grantedRight"
                Details       = @{
                    Identity    = $identity
                    Rights      = $rights
                    ObjectType  = $objectType
                    GrantedRight = $grantedRight
                    ObjectDN    = if ($ace.ContainsKey('ObjectDN')) { $ace.ObjectDN } else { '' }
                }
                Count         = 1
                Score         = 0
                Severity      = ''
            })
        }
    }

    return @($indicators)
}
