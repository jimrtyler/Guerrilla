# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADAdminSDHolderChange {
    [CmdletBinding()]
    param(
        [bool]$AdminSDHolderChanged = $false,
        [array]$ACLChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $AdminSDHolderChanged) { return @() }

    $adminSDChanges = @($ACLChanges | Where-Object { $_.ObjectDN -eq 'AdminSDHolder' })

    $addedACEs = @($adminSDChanges | Where-Object { $_.ChangeType -eq 'Added' })
    $removedACEs = @($adminSDChanges | Where-Object { $_.ChangeType -eq 'Removed' })

    $details = [System.Collections.Generic.List[string]]::new()
    foreach ($ace in $addedACEs) {
        $details.Add("ACE added: $($ace.Identity) ($($ace.Rights))")
    }
    foreach ($ace in $removedACEs) {
        $details.Add("ACE removed: $($ace.Identity) ($($ace.Rights))")
    }

    $detailStr = if ($details.Count -gt 0) {
        $details -join ' | '
    } else {
        'AdminSDHolder security descriptor modified'
    }

    $detectionId = "adAdminSDHolderChange_$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'AdminSDHolder ACL Modification'
        DetectionType = 'adAdminSDHolderChange'
        Description   = "ADMINSDHOLDER CHANGE - $detailStr"
        Details       = @{
            AddedACEs   = @($addedACEs | ForEach-Object { @{ Identity = $_.Identity; Rights = $_.Rights } })
            RemovedACEs = @($removedACEs | ForEach-Object { @{ Identity = $_.Identity; Rights = $_.Rights } })
        }
        Count         = $addedACEs.Count + $removedACEs.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
