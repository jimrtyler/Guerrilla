# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraSignInEvents {
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
    $filter = "createdDateTime ge $startIso"

    if (-not $Quiet) { Write-Verbose "Fetching sign-in events since $startIso" }

    $rawEvents = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
        -Uri '/auditLogs/signIns' `
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

        $deviceDetail = @{
            DeviceId        = $event.deviceDetail.deviceId ?? ''
            DisplayName     = $event.deviceDetail.displayName ?? ''
            OperatingSystem = $event.deviceDetail.operatingSystem ?? ''
            Browser         = $event.deviceDetail.browser ?? ''
            IsCompliant     = $event.deviceDetail.isCompliant
            IsManaged       = $event.deviceDetail.isManaged
            TrustType       = $event.deviceDetail.trustType ?? ''
        }

        $riskLevel = $event.riskLevelDuringSignIn ?? 'none'
        $riskState = $event.riskState ?? 'none'

        $caStatuses = @()
        if ($event.conditionalAccessStatus) {
            $caStatuses = @($event.conditionalAccessStatus)
        }
        if ($event.appliedConditionalAccessPolicies) {
            $caStatuses = @($event.appliedConditionalAccessPolicies | ForEach-Object {
                @{
                    DisplayName = $_.displayName ?? ''
                    Result      = $_.result ?? ''
                }
            })
        }

        $results.Add(@{
            Timestamp               = $event.createdDateTime
            UserPrincipalName       = $event.userPrincipalName ?? ''
            UserId                  = $event.userId ?? ''
            AppDisplayName          = $event.appDisplayName ?? ''
            IpAddress               = $event.ipAddress ?? ''
            Location                = $location
            RiskLevelDuringSignIn   = $riskLevel
            RiskState               = $riskState
            DeviceDetail            = $deviceDetail
            ClientAppUsed           = $event.clientAppUsed ?? ''
            ConditionalAccessStatus = $caStatuses
            IsInteractive           = [bool]$event.isInteractive
            ResourceDisplayName     = $event.resourceDisplayName ?? ''
            Status                  = @{
                ErrorCode      = $event.status.errorCode
                FailureReason  = $event.status.failureReason ?? ''
                AdditionalInfo = $event.status.additionalDetails ?? ''
            }
        })
    }

    return @($results)
}
