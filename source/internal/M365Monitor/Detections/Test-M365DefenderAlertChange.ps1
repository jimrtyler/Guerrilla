# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365DefenderAlertChange {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # High-risk operations
    $disablePatterns = @(
        'Disable-ProtectionAlert'
        'Remove-ProtectionAlert'
        'Disable-AntiPhishPolicy'
        'Remove-AntiPhishPolicy'
        'Disable-SafeAttachmentPolicy'
        'Remove-SafeAttachmentPolicy'
        'Disable-SafeLinksPolicy'
        'Remove-SafeLinksPolicy'
        'Disable-AlertPolicy'
        'Remove-AlertPolicy'
    )

    foreach ($event in $Events) {
        $operationType = $event.OperationType ?? $event.Activity ?? ''
        $policyName = $event.TargetName ?? ''
        $isDisabled = $false
        $isRemoved = $false
        $severityDowngraded = $false
        $notificationsDisabled = $false
        $changeDetails = [System.Collections.Generic.List[string]]::new()

        # Check for disable/remove operations
        foreach ($pattern in $disablePatterns) {
            if ($operationType -match [regex]::Escape($pattern) -or $event.Activity -match [regex]::Escape($pattern)) {
                if ($pattern -match 'Remove') {
                    $isRemoved = $true
                    $changeDetails.Add("Alert policy removed: $operationType")
                } else {
                    $isDisabled = $true
                    $changeDetails.Add("Alert policy disabled: $operationType")
                }
                break
            }
        }

        # Analyze property changes
        if (-not $isDisabled -and -not $isRemoved) {
            foreach ($prop in $event.ModifiedProps) {
                $propName = $prop.Name ?? ''
                $newVal = $prop.NewValue ?? ''
                $oldVal = $prop.OldValue ?? ''

                # Policy enabled/disabled state
                if ($propName -match 'IsEnabled|Enabled|IsActive|State') {
                    $cleanNew = ($newVal -replace '"', '').Trim()
                    $cleanOld = ($oldVal -replace '"', '').Trim()

                    if ($cleanNew -match 'false|False|disabled|Disabled|inactive' -and
                        $cleanOld -match 'true|True|enabled|Enabled|active') {
                        $isDisabled = $true
                        $changeDetails.Add("Policy disabled: $propName changed from '$cleanOld' to '$cleanNew'")
                    }
                }

                # Severity downgrade
                if ($propName -match 'Severity|ThreatSeverity|AlertSeverity') {
                    $severityOrder = @{ 'Informational' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Critical' = 4 }
                    $cleanNew = ($newVal -replace '"', '').Trim()
                    $cleanOld = ($oldVal -replace '"', '').Trim()

                    $oldSev = 0; $newSev = 0
                    foreach ($sev in $severityOrder.Keys) {
                        if ($cleanOld -match $sev) { $oldSev = $severityOrder[$sev] }
                        if ($cleanNew -match $sev) { $newSev = $severityOrder[$sev] }
                    }

                    if ($newSev -lt $oldSev) {
                        $severityDowngraded = $true
                        $changeDetails.Add("Severity downgraded: $propName from '$cleanOld' to '$cleanNew'")
                    }
                }

                # Notification settings
                if ($propName -match 'NotifyUser|EmailNotification|NotificationEnabled|AggregationType') {
                    $cleanNew = ($newVal -replace '"', '').Trim()
                    $cleanOld = ($oldVal -replace '"', '').Trim()

                    if ($cleanNew -match 'false|False|disabled|None' -and
                        $cleanOld -match 'true|True|enabled') {
                        $notificationsDisabled = $true
                        $changeDetails.Add("Notifications disabled: $propName = '$cleanNew'")
                    }
                }

                # Scope/filter reduction
                if ($propName -match 'Filter|Scope|TargetedUsers|TargetedDomains|ExcludedUsers|ExcludedDomains') {
                    $changeDetails.Add("Scope modified: $propName changed")
                }

                # Protection action weakened
                if ($propName -match 'Action|PhishThresholdLevel|BulkThreshold|SpamAction') {
                    $cleanNew = ($newVal -replace '"', '').Trim()
                    if ($cleanNew -match 'Allow|NoAction|Deliver|MoveToJunk' -and
                        $cleanOld -match 'Block|Quarantine|Delete|Reject') {
                        $changeDetails.Add("Protection action weakened: $propName from '$cleanOld' to '$cleanNew'")
                    }
                }
            }
        }

        $isDisabling = $isRemoved -or $isDisabled

        # Severity assessment
        $severity = if ($isRemoved) { 'Critical' }
                    elseif ($isDisabled) { 'High' }
                    elseif ($severityDowngraded -and $notificationsDisabled) { 'High' }
                    elseif ($severityDowngraded -or $notificationsDisabled) { 'Medium' }
                    else { 'Low' }

        $description = if ($isRemoved) {
            "Defender alert policy '$policyName' REMOVED by $($event.Actor)"
        } elseif ($isDisabled) {
            "Defender alert policy '$policyName' DISABLED by $($event.Actor)"
        } elseif ($severityDowngraded) {
            "Defender alert policy '$policyName' severity downgraded by $($event.Actor)"
        } else {
            "Defender alert policy '$policyName' modified by $($event.Actor)"
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365DefenderAlertChange'
            Description   = $description
            Details       = @{
                PolicyName            = $policyName
                OperationType         = $operationType
                IsDisabling           = $isDisabling
                IsRemoved             = $isRemoved
                SeverityDowngraded    = $severityDowngraded
                NotificationsDisabled = $notificationsDisabled
                ChangeNotes           = @($changeDetails)
                ModifiedProps         = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
