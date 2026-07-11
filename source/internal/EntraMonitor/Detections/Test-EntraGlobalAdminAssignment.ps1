# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraGlobalAdminAssignment {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Activity names for role membership changes
    $roleActivities = @(
        'Add member to role'
        'Add eligible member to role'
        'Add scoped member to role'
        'Add member to role in PIM requested (permanent)'
        'Add member to role in PIM requested (timebound)'
        'Add member to role completed (PIM activation)'
    )

    # Global Administrator role identifiers
    $globalAdminPatterns = @(
        'Global Administrator'
        'Company Administrator'
        '62e90394-69f5-4237-9190-012177145e10'  # well-known Global Admin role template ID
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
        if (-not $isRoleActivity -and $event.Category -ne 'RoleManagement') { continue }
        if (-not $isRoleActivity) { continue }

        # Check if the role is Global Administrator
        $isGlobalAdmin = $false
        $roleName = ''
        $targetUser = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'Role') {
                $roleName = $resource.DisplayName
                # Check by display name
                foreach ($pattern in $globalAdminPatterns) {
                    if ($roleName -match [regex]::Escape($pattern) -or $resource.Id -eq $pattern) {
                        $isGlobalAdmin = $true
                        break
                    }
                }
            }
            if ($resource.Type -eq 'User') {
                $targetUser = $resource.UserPrincipalName
                if (-not $targetUser) { $targetUser = $resource.DisplayName }
            }
            # Check modified properties for role template ID
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -eq 'Role.TemplateId' -and $prop.NewValue) {
                    $templateId = $prop.NewValue -replace '"', ''
                    if ($templateId -eq '62e90394-69f5-4237-9190-012177145e10') {
                        $isGlobalAdmin = $true
                    }
                }
                if ($prop.DisplayName -eq 'Role.DisplayName' -and $prop.NewValue) {
                    $checkName = $prop.NewValue -replace '"', ''
                    foreach ($pattern in $globalAdminPatterns) {
                        if ($checkName -match [regex]::Escape($pattern)) {
                            $isGlobalAdmin = $true
                            $roleName = $checkName
                            break
                        }
                    }
                }
            }
        }

        if (-not $isGlobalAdmin) { continue }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            RoleName      = $roleName
            TargetUser    = $targetUser
            Category      = $event.Category
            CorrelationId = $event.CorrelationId
        })
    }

    return @($results)
}
