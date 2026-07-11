# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraLeakedCredential {
    [CmdletBinding()]
    param(
        [hashtable[]]$RiskDetections = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $RiskDetections) {
        if ($event.RiskEventType -ne 'leakedCredentials') { continue }

        $results.Add([PSCustomObject]@{
            Timestamp           = $event.Timestamp
            UserPrincipalName   = $event.UserPrincipalName
            RiskLevel           = $event.RiskLevel
            RiskState           = $event.RiskState
            RiskDetail          = $event.RiskDetail
            IpAddress           = $event.IpAddress
            Location            = $event.Location
            Source              = $event.Source
            DetectionTimingType = $event.DetectionTimingType
        })
    }

    return @($results)
}
