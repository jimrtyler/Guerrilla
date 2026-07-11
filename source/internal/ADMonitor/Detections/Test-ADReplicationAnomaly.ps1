# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADReplicationAnomaly {
    [CmdletBinding()]
    param(
        [array]$ACLChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($ACLChanges.Count -eq 0) { return @() }

    # Detect when replication-related permissions are granted to non-standard accounts
    # This overlaps with DCSync but catches broader replication anomalies
    $replicationGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',    # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',    # DS-Replication-Get-Changes-All
        '89e95b76-444d-4c62-991a-0facbeda640c',     # DS-Replication-Get-Changes-In-Filtered-Set
        '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2',    # DS-Replication-Manage-Topology
        '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'     # DS-Replication-Synchronize
    )

    $replicationGuidNames = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c'  = 'DS-Replication-Get-Changes-In-Filtered-Set'
        '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'  = 'DS-Replication-Manage-Topology'
        '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'  = 'DS-Replication-Synchronize'
    }

    # Standard accounts that should have replication rights
    $expectedReplicationAccounts = @(
        'Domain Controllers', 'Enterprise Domain Controllers',
        'ENTERPRISE DOMAIN CONTROLLERS', 'SYSTEM',
        'S-1-5-18', 'S-1-5-9'
    )

    $addedACEs = @($ACLChanges | Where-Object { $_.ChangeType -eq 'Added' })

    $replicationChanges = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ace in $addedACEs) {
        $rights = if ($ace.ContainsKey('Rights')) { $ace.Rights } else { '' }
        $objectType = if ($ace.ContainsKey('objectType')) { $ace.objectType } else { '' }
        $identity = if ($ace.ContainsKey('Identity')) { $ace.Identity } else { '' }

        if ($rights -notmatch 'ExtendedRight|GenericAll') { continue }

        $isReplication = $false
        $grantedRight = ''

        foreach ($guid in $replicationGuids) {
            if ($objectType -eq $guid) {
                $isReplication = $true
                $grantedRight = if ($replicationGuidNames.ContainsKey($guid)) { $replicationGuidNames[$guid] } else { $guid }
                break
            }
        }

        if (-not $isReplication) { continue }

        # Skip expected replication accounts
        $isExpected = $false
        foreach ($expected in $expectedReplicationAccounts) {
            if ($identity -eq $expected -or $identity -like "*\$expected" -or $identity -match "$expected$") {
                $isExpected = $true
                break
            }
        }
        if ($isExpected) { continue }

        $replicationChanges.Add(@{
            Identity    = $identity
            Right       = $grantedRight
            ObjectDN    = if ($ace.ContainsKey('ObjectDN')) { $ace.ObjectDN } else { '' }
        })
    }

    if ($replicationChanges.Count -eq 0) { return @() }

    $identities = @($replicationChanges | ForEach-Object { $_.Identity } | Sort-Object -Unique)
    $detectionId = "adReplicationAnomaly_$(($identities -join '_') -replace '[\\\/\s]', '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'Replication Permission Anomaly'
        DetectionType = 'adReplicationAnomaly'
        Description   = "REPLICATION ANOMALY - Replication rights granted to non-standard account(s): $($identities -join ', '). This may indicate DCSync attack preparation or unauthorized replication topology changes."
        Details       = @{
            Changes = @($replicationChanges)
        }
        Count         = $replicationChanges.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
