# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraSubscriptionPermChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Azure subscription / RBAC change activities
    $subscriptionActivities = @(
        'Add role assignment'
        'Remove role assignment'
        'Add eligible role assignment'
        'Remove eligible role assignment'
        'Create role assignment request'
        'Add owner to application'
        'Remove owner from application'
        'Add owner to service principal'
        'Remove owner from service principal'
        'Add member to group'
        'Remove member from group'
        'Add owner to group'
        'Remove owner from group'
    )

    # Sensitive group/role keywords for subscription access
    $sensitiveKeywords = @(
        'Owner'
        'Contributor'
        'User Access Administrator'
        'Key Vault'
        'Security Admin'
        'Subscription'
        'Management Group'
        'Resource Group'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isSubscriptionPerm = $false

        foreach ($sa in $subscriptionActivities) {
            if ($activity -match [regex]::Escape($sa)) {
                $isSubscriptionPerm = $true
                break
            }
        }

        if (-not $isSubscriptionPerm) { continue }

        # Extract target details
        $targetName = ''
        $targetType = ''
        $roleName = ''
        $memberName = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'Role') {
                $roleName = $resource.DisplayName
            } elseif ($resource.Type -eq 'User') {
                $memberName = $resource.UserPrincipalName
                if (-not $memberName) { $memberName = $resource.DisplayName }
            } elseif ($resource.Type -eq 'Group') {
                $targetName = $resource.DisplayName
                $targetType = 'Group'
            } elseif ($resource.Type -in @('Application', 'ServicePrincipal')) {
                $targetName = $resource.DisplayName
                $targetType = $resource.Type
            }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -eq 'Role.DisplayName' -and $prop.NewValue) {
                    $roleName = $prop.NewValue -replace '"', ''
                }
            }
        }

        # Check if this involves sensitive roles/groups
        $isSensitive = $false
        $checkStr = "$roleName $targetName $activity"
        foreach ($keyword in $sensitiveKeywords) {
            if ($checkStr -match $keyword) {
                $isSensitive = $true
                break
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp   = $event.Timestamp
            Activity    = $activity
            Result      = $event.Result
            InitiatedBy = $initiator
            RoleName    = $roleName
            TargetName  = $targetName
            TargetType  = $targetType
            MemberName  = $memberName
            IsSensitive = $isSensitive
            Category    = $event.Category
        })
    }

    return @($results)
}
