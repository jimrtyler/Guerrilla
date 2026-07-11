# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraRiskDetections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [switch]$Quiet
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()

    $startIso = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "activityDateTime ge $startIso"

    if (-not $Quiet) { Write-Verbose "Fetching risk detections since $startIso" }

    $rawEvents = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
        -Uri '/identityProtection/riskDetections' `
        -QueryParameters @{ '$filter' = $filter; '$top' = '999' } `
        -Paginate `
        -Quiet:$Quiet

    if (-not $rawEvents) { return @($results) }

    foreach ($event in @($rawEvents)) {
        $location = @{
            City    = $event.location.city ?? ''
            State   = $event.location.state ?? ''
            Country = $event.location.countryOrRegion ?? ''
        }

        $results.Add(@{
            Timestamp           = $event.activityDateTime
            UserPrincipalName   = $event.userPrincipalName ?? ''
            UserId              = $event.userId ?? ''
            RiskEventType       = $event.riskEventType ?? ''
            RiskLevel           = $event.riskLevel ?? 'none'
            RiskState           = $event.riskState ?? 'none'
            RiskDetail          = $event.riskDetail ?? ''
            IpAddress           = $event.ipAddress ?? ''
            Location            = $location
            Source              = $event.source ?? ''
            DetectionTimingType = $event.detectionTimingType ?? ''
            Activity            = $event.activity ?? ''
            AdditionalInfo      = $event.additionalInfo ?? ''
        })
    }

    return @($results)
}
