# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-DomainWideDelegation {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $delegationEvents = @(
        'AUTHORIZE_API_CLIENT_ACCESS'
        'CHANGE_API_CLIENT_ACCESS'
    )

    # Dangerous scope patterns that indicate domain-wide delegation
    $dangerousScopes = @(
        'https://mail.google.com'
        'https://www.googleapis.com/auth/gmail'
        'https://www.googleapis.com/auth/drive'
        'https://www.googleapis.com/auth/admin'
        'https://www.googleapis.com/auth/calendar'
        'https://www.googleapis.com/auth/contacts'
        'https://www.googleapis.com/auth/cloud-platform'
    )

    foreach ($event in $AdminEvents) {
        if ($event.EventName -notin $delegationEvents) { continue }

        $clientId = $event.Params['API_CLIENT_NAME'] ?? $event.Params['CLIENT_ID'] ?? ''
        $scopes = $event.Params['API_SCOPES'] ?? $event.Params['SCOPES'] ?? ''

        $hasDangerousScope = $false
        $matchedScopes = @()

        if ($scopes) {
            $scopeStr = if ($scopes -is [array]) { $scopes -join ',' } else { $scopes.ToString() }
            foreach ($ds in $dangerousScopes) {
                if ($scopeStr -match [regex]::Escape($ds)) {
                    $hasDangerousScope = $true
                    $matchedScopes += $ds
                }
            }
        }

        $results.Add([PSCustomObject]@{
            Timestamp         = $event.Timestamp
            User              = $event.User
            EventName         = $event.EventName
            IpAddress         = $event.IpAddress
            ClientId          = $clientId
            Scopes            = $scopes
            HasDangerousScope = $hasDangerousScope
            MatchedScopes     = $matchedScopes
            Params            = $event.Params
        })
    }

    return @($results)
}
