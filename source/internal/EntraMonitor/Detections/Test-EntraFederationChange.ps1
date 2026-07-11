# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraFederationChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Federation and domain trust activities
    $federationActivities = @(
        'Set domain authentication'
        'Set federation settings on domain'
        'Add unverified domain'
        'Add verified domain'
        'Remove domain'
        'Update domain'
        'Set DirSyncEnabled flag'
        'Set Company DirSync feature'
        'Verify domain'
        'Set company information'
        'Set partner information on company'
        'Add partner to company'
        'Remove partner from company'
        'Set domain federation settings'
        'Set DirSync feature'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isFederation = $false

        foreach ($fa in $federationActivities) {
            if ($activity -match [regex]::Escape($fa)) {
                $isFederation = $true
                break
            }
        }

        # Also match by category
        if (-not $isFederation -and $event.Category -eq 'DirectoryManagement') {
            if ($activity -match 'domain|federation|dirsync|partner|company') {
                $isFederation = $true
            }
        }

        if (-not $isFederation) { continue }

        # Extract domain name from target resources
        $domainName = ''
        $settingChanged = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.DisplayName) { $domainName = $resource.DisplayName }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -match 'FederationBrandName|AuthenticationType|IssuerUri|PassiveLogOnUri') {
                    $settingChanged = $prop.DisplayName
                }
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp      = $event.Timestamp
            Activity       = $activity
            Result         = $event.Result
            InitiatedBy    = $initiator
            DomainName     = $domainName
            SettingChanged = $settingChanged
            Category       = $event.Category
            CorrelationId  = $event.CorrelationId
        })
    }

    return @($results)
}
