# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraServicePrincipalCred {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Activities related to service principal credential changes
    $spCredActivities = @(
        'Add service principal credentials'
        'Update service principal credentials'
        'Remove service principal credentials'
        'Add service principal'
        'Add app role assignment to service principal'
        'Add delegated permission grant'
        'Add application credentials'
        'Update application credentials'
        'Update application - Certificates and secrets management'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isSpCred = $false

        foreach ($spa in $spCredActivities) {
            if ($activity -match [regex]::Escape($spa)) {
                $isSpCred = $true
                break
            }
        }

        # Also catch credential additions by checking modified properties
        if (-not $isSpCred -and $event.Category -eq 'ApplicationManagement') {
            foreach ($resource in $event.TargetResources) {
                foreach ($prop in $resource.ModifiedProperties) {
                    if ($prop.DisplayName -match 'KeyCredentials|PasswordCredentials|Credential') {
                        $isSpCred = $true
                        break
                    }
                }
                if ($isSpCred) { break }
            }
        }

        if (-not $isSpCred) { continue }

        # Extract service principal / app details
        $appName = ''
        $appId = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -in @('ServicePrincipal', 'Application')) {
                $appName = $resource.DisplayName
                $appId = $resource.Id
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            AppName       = $appName
            AppId         = $appId
            Category      = $event.Category
            CorrelationId = $event.CorrelationId
        })
    }

    return @($results)
}
