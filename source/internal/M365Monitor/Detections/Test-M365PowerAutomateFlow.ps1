# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365PowerAutomateFlow {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @(),

        [string[]]$ExternalConnectorPatterns = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Default external connector patterns
    $defaultExternalPatterns = @(
        'Dropbox'
        'Google\s*Drive'
        'Box\.com|Box\s'
        'Gmail'
        'Yahoo'
        'Outlook\.com|Hotmail'
        'SMTP|SendGrid|Mailgun|Twilio'
        'HTTP|Webhook|REST'
        'FTP|SFTP'
        'AWS\s*S3'
        'Azure\s*Blob'
        'Slack'
        'Discord'
        'Telegram'
        'OneDrive\s*for\s*Business.*personal'
        'RSS'
        'Twitter|X\s'
        'LinkedIn'
    )

    $allPatterns = $defaultExternalPatterns + $ExternalConnectorPatterns

    foreach ($event in $Events) {
        $activity = $event.Activity ?? ''
        $flowName = $event.TargetName ?? ''
        $hasExternalConnector = $false
        $externalConnectors = [System.Collections.Generic.List[string]]::new()
        $flowDetails = [System.Collections.Generic.List[string]]::new()

        # Check modified properties for connector information
        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''

            # Check for connector references in flow definition
            if ($propName -match 'ConnectionReferences|Triggers|Actions|Connectors|Definition') {
                foreach ($pattern in $allPatterns) {
                    if ($newVal -match $pattern) {
                        $hasExternalConnector = $true
                        $matchedConnector = $Matches[0]
                        if (-not $externalConnectors.Contains($matchedConnector)) {
                            $externalConnectors.Add($matchedConnector)
                        }
                    }
                }
            }

            # Flow name or description might indicate purpose
            if ($propName -match 'DisplayName|Name|Description') {
                $flowDetails.Add("$propName = $newVal")
            }
        }

        # Check flow name for suspicious patterns
        $suspiciousNamePatterns = @(
            'backup.*email', 'forward.*email', 'copy.*file', 'sync.*external',
            'export.*data', 'download.*all', 'archive.*mail', 'mirror.*content'
        )

        $hasSuspiciousName = $false
        foreach ($pattern in $suspiciousNamePatterns) {
            if ($flowName -match $pattern) {
                $hasSuspiciousName = $true
                $flowDetails.Add("Suspicious flow name pattern: $pattern")
                break
            }
        }

        # Determine if this is a creation vs modification
        $isCreation = $activity -match 'Create|New|Created'
        $isModification = $activity -match 'Edit|Set|Modified|Updated'

        # Severity assessment
        $severity = if ($hasExternalConnector -and $isCreation) { 'High' }
                    elseif ($hasExternalConnector) { 'Medium' }
                    elseif ($hasSuspiciousName) { 'Medium' }
                    elseif ($isCreation) { 'Low' }
                    else { 'Low' }

        $description = "Power Automate flow '$flowName' $activity by $($event.Actor)"
        if ($hasExternalConnector) {
            $description += " (external connectors: $($externalConnectors -join ', '))"
        }
        if ($hasSuspiciousName) {
            $description += ' (suspicious name pattern)'
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365PowerAutomateFlow'
            Description   = $description
            Details       = @{
                FlowName             = $flowName
                Activity             = $activity
                IsCreation           = $isCreation
                IsModification       = $isModification
                HasExternalConnector = $hasExternalConnector
                ExternalConnectors   = @($externalConnectors)
                HasSuspiciousName    = $hasSuspiciousName
                FlowNotes            = @($flowDetails)
                ModifiedProps        = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
