# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraDirectoryAudits {
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

    if (-not $Quiet) { Write-Verbose "Fetching directory audits since $startIso" }

    $rawEvents = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
        -Uri '/auditLogs/directoryAudits' `
        -QueryParameters @{ '$filter' = $filter; '$top' = '999' } `
        -Paginate `
        -Quiet:$Quiet

    if (-not $rawEvents) { return @($results) }

    foreach ($event in @($rawEvents)) {
        # Parse initiatedBy — can be user or app
        $initiatedBy = @{
            UserPrincipalName = ''
            UserId            = ''
            AppDisplayName    = ''
            AppId             = ''
        }
        if ($event.initiatedBy.user) {
            $initiatedBy.UserPrincipalName = $event.initiatedBy.user.userPrincipalName ?? ''
            $initiatedBy.UserId = $event.initiatedBy.user.id ?? ''
        }
        if ($event.initiatedBy.app) {
            $initiatedBy.AppDisplayName = $event.initiatedBy.app.displayName ?? ''
            $initiatedBy.AppId = $event.initiatedBy.app.appId ?? ''
        }

        # Parse target resources
        $targetResources = @()
        if ($event.targetResources) {
            $targetResources = @($event.targetResources | ForEach-Object {
                @{
                    Id                = $_.id ?? ''
                    DisplayName       = $_.displayName ?? ''
                    Type              = $_.type ?? ''
                    UserPrincipalName = $_.userPrincipalName ?? ''
                    ModifiedProperties = @(
                        if ($_.modifiedProperties) {
                            $_.modifiedProperties | ForEach-Object {
                                @{
                                    DisplayName = $_.displayName ?? ''
                                    OldValue    = $_.oldValue ?? ''
                                    NewValue    = $_.newValue ?? ''
                                }
                            }
                        }
                    )
                }
            })
        }

        # Parse additional details
        $additionalDetails = @{}
        if ($event.additionalDetails) {
            foreach ($detail in @($event.additionalDetails)) {
                if ($detail.key) {
                    $additionalDetails[$detail.key] = $detail.value ?? ''
                }
            }
        }

        $results.Add(@{
            Timestamp           = $event.activityDateTime
            Category            = $event.category ?? ''
            ActivityDisplayName = $event.activityDisplayName ?? ''
            Result              = $event.result ?? ''
            ResultReason        = $event.resultReason ?? ''
            InitiatedBy         = $initiatedBy
            TargetResources     = $targetResources
            AdditionalDetails   = $additionalDetails
            CorrelationId       = $event.correlationId ?? ''
            LoggedByService     = $event.loggedByService ?? ''
            OperationType       = $event.operationType ?? ''
        })
    }

    return @($results)
}
