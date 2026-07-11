# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-DriveExternalSharing {
    [CmdletBinding()]
    param(
        [hashtable[]]$DriveEvents = @(),

        [string]$InternalDomain = ''
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $sharingEvents = @(
        'change_acl_editors'
        'change_user_access'
        'change_document_access_scope'
        'change_document_visibility'
    )

    foreach ($event in $DriveEvents) {
        $eventName = $event.EventName
        if ($eventName -notin $sharingEvents) { continue }

        $targetUser = $event.Params['target_user'] ?? $event.Params['TARGET_USER'] ?? ''
        $visibility = $event.Params['visibility'] ?? $event.Params['new_value'] ?? ''
        $docTitle = $event.Params['doc_title'] ?? $event.Params['DOCUMENT_TITLE'] ?? ''

        $isExternal = $false

        # Check if shared to external user
        if ($targetUser -and $InternalDomain) {
            if ($targetUser -notmatch [regex]::Escape($InternalDomain) -and $targetUser -match '@') {
                $isExternal = $true
            }
        }

        # Check if visibility changed to public/anyone
        if ($visibility -match 'people_with_link|anyone|public|external') {
            $isExternal = $true
        }

        if (-not $isExternal) { continue }

        $results.Add([PSCustomObject]@{
            Timestamp   = $event.Timestamp
            User        = $event.User
            EventName   = $eventName
            IpAddress   = $event.IpAddress
            TargetUser  = $targetUser
            Visibility  = $visibility
            DocTitle    = $docTitle
            Params      = $event.Params
        })
    }

    return @($results)
}
