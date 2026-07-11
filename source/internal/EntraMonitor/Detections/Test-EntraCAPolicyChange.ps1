# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraCAPolicyChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Conditional Access policy activities
    $caActivities = @(
        'Add conditional access policy'
        'Update conditional access policy'
        'Delete conditional access policy'
        'Add named location'
        'Update named location'
        'Delete named location'
        'Add authentication context'
        'Update authentication context'
        'Delete authentication context'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isCA = $false

        foreach ($ca in $caActivities) {
            if ($activity -match [regex]::Escape($ca)) {
                $isCA = $true
                break
            }
        }

        # Also catch by category
        if (-not $isCA -and $event.Category -eq 'Policy' -and $activity -match 'conditional|named location') {
            $isCA = $true
        }

        if (-not $isCA) { continue }

        # Extract policy details from target resources
        $policyName = ''
        $policyState = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.DisplayName) { $policyName = $resource.DisplayName }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -eq 'State' -or $prop.DisplayName -eq 'IsEnabled') {
                    $policyState = $prop.NewValue -replace '"', ''
                }
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $isDisabling = $activity -match 'Delete' -or $policyState -match 'disabled|false'

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            PolicyName    = $policyName
            PolicyState   = $policyState
            IsDisabling   = $isDisabling
            Category      = $event.Category
            CorrelationId = $event.CorrelationId
        })
    }

    return @($results)
}
