# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraAppPermissionGrant {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Activities related to OAuth2 permission grants
    $permActivities = @(
        'Add delegated permission grant'
        'Add app role assignment grant to user'
        'Add app role assignment to service principal'
        'Consent to application'
        'Add OAuth2PermissionGrant'
        'Update OAuth2PermissionGrant'
        'Add application permission grant'
    )

    # High-privilege permission scopes to flag
    $highPrivScopes = @(
        'Mail.ReadWrite'
        'Mail.Send'
        'Files.ReadWrite.All'
        'Directory.ReadWrite.All'
        'RoleManagement.ReadWrite.Directory'
        'AppRoleAssignment.ReadWrite.All'
        'User.ReadWrite.All'
        'Group.ReadWrite.All'
        'Application.ReadWrite.All'
        'Sites.ReadWrite.All'
        'MailboxSettings.ReadWrite'
        'full_access_as_app'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isPermGrant = $false

        foreach ($pa in $permActivities) {
            if ($activity -match [regex]::Escape($pa)) {
                $isPermGrant = $true
                break
            }
        }

        if (-not $isPermGrant) { continue }

        # Extract app and permission details
        $appName = ''
        $scopes = ''
        $consentType = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.DisplayName) { $appName = $resource.DisplayName }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -eq 'Scope' -or $prop.DisplayName -eq 'DelegatedPermissionGrant.Scope') {
                    $scopes = $prop.NewValue -replace '"', ''
                }
                if ($prop.DisplayName -eq 'ConsentType') {
                    $consentType = $prop.NewValue -replace '"', ''
                }
            }
        }

        # Check if any high-privilege scopes are granted
        $isHighPrivilege = $false
        if ($scopes) {
            $grantedScopes = $scopes -split '\s+'
            foreach ($scope in $grantedScopes) {
                foreach ($hps in $highPrivScopes) {
                    if ($scope -match [regex]::Escape($hps)) {
                        $isHighPrivilege = $true
                        break
                    }
                }
                if ($isHighPrivilege) { break }
            }
        }
        # Admin consent is always high privilege
        if ($consentType -eq 'AllPrincipals') { $isHighPrivilege = $true }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp       = $event.Timestamp
            Activity        = $activity
            Result          = $event.Result
            InitiatedBy     = $initiator
            AppName         = $appName
            Scopes          = $scopes
            ConsentType     = $consentType
            IsHighPrivilege = $isHighPrivilege
            Category        = $event.Category
            CorrelationId   = $event.CorrelationId
        })
    }

    return @($results)
}
