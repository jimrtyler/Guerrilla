# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365EDiscoverySearch {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Activities indicating search creation or execution
    $creationActivities = @(
        'SearchCreated', 'New-ComplianceSearch', 'New-ComplianceSearchAction',
        'Start-ComplianceSearch', 'SearchStarted'
    )

    $executionActivities = @(
        'SearchStarted', 'Start-ComplianceSearch', 'SearchExported',
        'SearchPreviewed', 'SearchCompleted'
    )

    # Broad scope search indicators
    $broadScopePatterns = @(
        'All mailboxes'
        'All sites'
        'ExchangeLocation.*All'
        'SharePointLocation.*All'
    )

    foreach ($event in $Events) {
        $activity = $event.Activity ?? ''
        $searchName = $event.TargetName ?? ''
        $isBroadScope = $false
        $searchQuery = ''
        $searchLocations = ''

        # Extract search details from modified properties
        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''

            if ($propName -match 'ContentMatchQuery|SearchQuery|Query') {
                $searchQuery = $newVal -replace '"', ''
            }

            if ($propName -match 'ExchangeLocation|SharePointLocation|PublicFolderLocation') {
                $searchLocations = $newVal -replace '"', ''

                # Check for broad scope
                foreach ($pattern in $broadScopePatterns) {
                    if ($newVal -match $pattern) {
                        $isBroadScope = $true
                        break
                    }
                }
            }
        }

        # Classify as creation vs execution
        $isCreation = $false
        $isExecution = $false

        foreach ($creationAct in $creationActivities) {
            if ($activity -match [regex]::Escape($creationAct)) {
                $isCreation = $true
                break
            }
        }
        foreach ($execAct in $executionActivities) {
            if ($activity -match [regex]::Escape($execAct)) {
                $isExecution = $true
                break
            }
        }

        # Sensitive search query patterns
        $sensitiveQueryPatterns = @(
            'password', 'credential', 'secret', 'confidential', 'SSN',
            'credit card', 'bank account', 'salary', 'merger', 'acquisition',
            'termination', 'legal hold', 'attorney', 'privileged'
        )

        $hasSensitiveQuery = $false
        foreach ($pattern in $sensitiveQueryPatterns) {
            if ($searchQuery -match $pattern) {
                $hasSensitiveQuery = $true
                break
            }
        }

        # Severity assessment
        $severity = if ($isBroadScope -and $isExecution) { 'Critical' }
                    elseif ($isBroadScope) { 'High' }
                    elseif ($isExecution) { 'High' }
                    elseif ($hasSensitiveQuery) { 'High' }
                    elseif ($isCreation) { 'Medium' }
                    else { 'Low' }

        $description = "eDiscovery search '$searchName' $activity by $($event.Actor)"
        if ($isBroadScope) { $description += ' (BROAD SCOPE: all locations)' }
        if ($hasSensitiveQuery) { $description += ' (sensitive query terms detected)' }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365EDiscoverySearch'
            Description   = $description
            Details       = @{
                SearchName        = $searchName
                Activity          = $activity
                SearchQuery       = $searchQuery
                SearchLocations   = $searchLocations
                IsBroadScope      = $isBroadScope
                HasSensitiveQuery = $hasSensitiveQuery
                IsCreation        = $isCreation
                IsExecution       = $isExecution
                ModifiedProps     = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
