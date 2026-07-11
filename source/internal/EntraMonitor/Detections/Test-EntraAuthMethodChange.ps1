# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraAuthMethodChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Authentication method activities
    $authMethodActivities = @(
        'User registered security info'
        'User deleted security info'
        'User registered all required security info'
        'Admin registered security info'
        'Admin deleted security info'
        'User updated security info'
        'Admin updated security info'
        'Register security info'
        'Delete security info'
        'Update security info'
        'Add strong authentication phone app detail'
        'Delete strong authentication phone app detail'
        'Update strong authentication phone app detail'
        'User started security info registration'
        'Admin reset user password'
        'Change user password'
        'Reset user password'
        'Set force change user password'
        'Update StsRefreshTokenValidFrom Timestamp'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isAuthMethod = $false

        foreach ($ama in $authMethodActivities) {
            if ($activity -match [regex]::Escape($ama)) {
                $isAuthMethod = $true
                break
            }
        }

        if (-not $isAuthMethod) { continue }

        # Extract target user and method details
        $targetUser = ''
        $methodType = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'User') {
                $targetUser = $resource.UserPrincipalName
                if (-not $targetUser) { $targetUser = $resource.DisplayName }
            }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -match 'StrongAuthentication|AuthenticationMethod|PhoneNumber|FidoDevice') {
                    $methodType = $prop.DisplayName
                }
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $isAdminAction = $activity -match 'Admin|Reset user password|Set force change'

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            TargetUser    = $targetUser
            MethodType    = $methodType
            IsAdminAction = $isAdminAction
            Category      = $event.Category
        })
    }

    return @($results)
}
