# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraGuestInvitation {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Guest invitation activities
    $guestActivities = @(
        'Invite external user'
        'Redeem external user invite'
        'Add user'
        'Bulk invite users'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isGuest = $false

        foreach ($ga in $guestActivities) {
            if ($activity -match [regex]::Escape($ga)) {
                $isGuest = $true
                break
            }
        }

        # For 'Add user' — only flag if it's a guest user type
        if ($activity -eq 'Add user') {
            $isGuestType = $false
            foreach ($resource in $event.TargetResources) {
                foreach ($prop in $resource.ModifiedProperties) {
                    if ($prop.DisplayName -eq 'UserType' -and $prop.NewValue -match 'Guest') {
                        $isGuestType = $true
                    }
                    if ($prop.DisplayName -eq 'CreationType' -and $prop.NewValue -match 'Invitation') {
                        $isGuestType = $true
                    }
                }
            }
            if (-not $isGuestType) { $isGuest = $false }
        }

        if (-not $isGuest) { continue }

        # Extract invited user details
        $invitedUser = ''
        $invitedEmail = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'User') {
                $invitedUser = $resource.DisplayName
                $invitedEmail = $resource.UserPrincipalName
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp    = $event.Timestamp
            Activity     = $activity
            Result       = $event.Result
            InitiatedBy  = $initiator
            InvitedUser  = $invitedUser
            InvitedEmail = $invitedEmail
            Category     = $event.Category
        })
    }

    return @($results)
}
