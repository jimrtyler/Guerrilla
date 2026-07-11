# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-UserSuspension {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $suspensionEvents = @(
        'SUSPEND_USER'
        'DELETE_USER'
        'UNDELETE_USER'
    )

    foreach ($event in $AdminEvents) {
        if ($event.EventName -notin $suspensionEvents) { continue }

        $targetUser = $event.Params['USER_EMAIL'] ?? $event.Params['TARGET_USER'] ?? ''

        $results.Add([PSCustomObject]@{
            Timestamp  = $event.Timestamp
            User       = $event.User
            EventName  = $event.EventName
            IpAddress  = $event.IpAddress
            TargetUser = $targetUser
            Action     = $event.EventName
            Params     = $event.Params
        })
    }

    return @($results)
}
