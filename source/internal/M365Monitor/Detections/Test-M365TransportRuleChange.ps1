# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365TransportRuleChange {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # High-risk operation patterns
    $highRiskPatterns = @(
        'New-TransportRule'
        'Remove-TransportRule'
        'Disable-TransportRule'
    )

    foreach ($event in $Events) {
        $operationType = $event.OperationType ?? $event.Activity ?? ''
        $ruleName = $event.TargetName ?? ''

        # Determine severity based on operation type
        $severity = if ($operationType -in $highRiskPatterns -or
                        $event.Activity -match 'New-TransportRule|Remove-TransportRule|Disable-TransportRule') {
            'High'
        } elseif ($operationType -match 'Set-TransportRule|Enable-TransportRule') {
            'Medium'
        } else {
            'Low'
        }

        # Check for suspicious modification patterns
        $suspiciousModification = $false
        $modificationDetails = [System.Collections.Generic.List[string]]::new()

        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''

            # Redirect/forward actions in transport rules
            if ($propName -match 'RedirectMessageTo|CopyTo|BlindCopyTo|AddToRecipients') {
                $suspiciousModification = $true
                $modificationDetails.Add("$propName set to: $newVal")
            }

            # Delete message actions
            if ($propName -match 'DeleteMessage|Quarantine|RejectMessage') {
                $suspiciousModification = $true
                $modificationDetails.Add("$propName enabled: $newVal")
            }

            # Header manipulation
            if ($propName -match 'SetHeaderName|SetHeaderValue|RemoveHeader|SetSCL') {
                $suspiciousModification = $true
                $modificationDetails.Add("Header manipulation: $propName = $newVal")
            }

            # Broad scope conditions
            if ($propName -match 'FromScope|SentToScope' -and $newVal -match 'InOrganization|NotInOrganization') {
                $modificationDetails.Add("Scope: $propName = $newVal")
            }
        }

        if ($suspiciousModification) {
            $severity = 'High'
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365TransportRuleChange'
            Description   = "Transport rule '$ruleName' $operationType by $($event.Actor)"
            Details       = @{
                Activity          = $event.Activity
                OperationType     = $operationType
                TargetName        = $ruleName
                ModifiedProps     = $event.ModifiedProps
                Suspicious        = $suspiciousModification
                ModificationNotes = @($modificationDetails)
            }
            Severity      = $severity
        })
    }

    return @($results)
}
