# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-AdminAction {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Admin role assignment event names
    $roleEvents = @(
        'ASSIGN_ROLE'
        'ADD_PRIVILEGE'
        'GRANT_ADMIN_PRIVILEGE'
    )

    # Sensitive role keywords
    $sensitiveRoles = @(
        'super_admin'
        '_ADMIN_ROLE'
        'ADMIN'
        'DELEGATED_ADMIN'
        'RESELLER_ADMIN'
        'HELP_DESK_ADMIN'
        'SERVICE_ADMIN'
        'USER_MANAGEMENT_ADMIN'
        'GROUPS_ADMIN'
        'MOBILE_ADMIN'
    )

    foreach ($event in $AdminEvents) {
        $eventName = $event.EventName
        if ($eventName -notin $roleEvents) { continue }

        $roleName = $event.Params['ROLE_NAME'] ?? $event.Params['PRIVILEGE_NAME'] ?? ''
        $targetUser = $event.Params['USER_EMAIL'] ?? $event.Params['TARGET_USER'] ?? ''

        $isSensitive = $false
        foreach ($keyword in $sensitiveRoles) {
            if ($roleName -match $keyword) {
                $isSensitive = $true
                break
            }
        }

        if (-not $isSensitive) { continue }

        $results.Add([PSCustomObject]@{
            Timestamp  = $event.Timestamp
            User       = $event.User
            EventName  = $eventName
            IpAddress  = $event.IpAddress
            RoleName   = $roleName
            TargetUser = $targetUser
            Params     = $event.Params
        })
    }

    return @($results)
}
