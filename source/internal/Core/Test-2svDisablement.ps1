# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-2svDisablement {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $AdminEvents) {
        if ($event.EventName -ne 'TURN_OFF_2_STEP_VERIFICATION') { continue }

        $targetUser = $event.Params['USER_EMAIL'] ?? $event.Params['TARGET_USER'] ?? ''
        $actor = $event.User

        # Only flag when admin disables 2SV for another user (not self-service)
        $isAdminAction = -not [string]::Equals($actor, $targetUser, [StringComparison]::OrdinalIgnoreCase)

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            User          = $actor
            EventName     = $event.EventName
            IpAddress     = $event.IpAddress
            TargetUser    = $targetUser
            IsAdminAction = $isAdminAction
            Params        = $event.Params
        })
    }

    return @($results)
}
