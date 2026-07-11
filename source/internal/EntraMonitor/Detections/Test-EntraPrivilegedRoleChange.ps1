# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraPrivilegedRoleChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Activity display names that indicate role assignment changes
    $roleActivities = @(
        'Add member to role'
        'Add eligible member to role'
        'Add scoped member to role'
        'Remove member from role'
        'Remove eligible member from role'
        'Add member to role in PIM requested (permanent)'
        'Add member to role in PIM requested (timebound)'
        'Add member to role completed (PIM activation)'
    )

    # Sensitive directory role keywords
    $sensitiveRoleKeywords = @(
        'Admin'
        'Administrator'
        'Privileged'
        'Security'
        'Compliance'
        'Exchange'
        'SharePoint'
        'Intune'
        'Authentication'
        'Helpdesk'
        'Password'
        'Billing'
        'License'
        'User Account'
        'Application'
        'Cloud App'
        'Conditional Access'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isRoleActivity = $false
        foreach ($ra in $roleActivities) {
            if ($activity -match [regex]::Escape($ra)) {
                $isRoleActivity = $true
                break
            }
        }
        # Also catch category-based role changes
        if (-not $isRoleActivity -and $event.Category -eq 'RoleManagement') {
            $isRoleActivity = $true
        }
        if (-not $isRoleActivity) { continue }

        # Extract role name from target resources
        $roleName = ''
        $targetUser = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'Role') {
                $roleName = $resource.DisplayName
            }
            if ($resource.Type -eq 'User') {
                $targetUser = $resource.UserPrincipalName
                if (-not $targetUser) { $targetUser = $resource.DisplayName }
            }
            # Check modified properties for role name
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -eq 'Role.DisplayName' -and $prop.NewValue) {
                    $roleName = $prop.NewValue -replace '"', ''
                }
            }
        }

        # Determine if this is a sensitive role
        $isSensitive = $false
        foreach ($keyword in $sensitiveRoleKeywords) {
            if ($roleName -match $keyword) {
                $isSensitive = $true
                break
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            RoleName      = $roleName
            TargetUser    = $targetUser
            IsSensitive   = $isSensitive
            Category      = $event.Category
            CorrelationId = $event.CorrelationId
        })
    }

    return @($results)
}
