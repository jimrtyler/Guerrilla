# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraAdminUnitChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Administrative unit activities
    $auActivities = @(
        'Add administrative unit'
        'Update administrative unit'
        'Delete administrative unit'
        'Add member to administrative unit'
        'Remove member from administrative unit'
        'Add scoped-role member to administrative unit'
        'Remove scoped-role member from administrative unit'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isAuChange = $false

        foreach ($aa in $auActivities) {
            if ($activity -match [regex]::Escape($aa)) {
                $isAuChange = $true
                break
            }
        }

        if (-not $isAuChange) { continue }

        # Extract admin unit and member details
        $adminUnitName = ''
        $memberName = ''
        $roleName = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'AdministrativeUnit') {
                $adminUnitName = $resource.DisplayName
            } elseif ($resource.Type -eq 'User') {
                $memberName = $resource.UserPrincipalName
                if (-not $memberName) { $memberName = $resource.DisplayName }
            } elseif ($resource.Type -eq 'Role') {
                $roleName = $resource.DisplayName
            }
            # Fallback — first resource with a display name
            if (-not $adminUnitName -and $resource.DisplayName) {
                $adminUnitName = $resource.DisplayName
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            AdminUnitName = $adminUnitName
            MemberName    = $memberName
            RoleName      = $roleName
            Category      = $event.Category
        })
    }

    return @($results)
}
