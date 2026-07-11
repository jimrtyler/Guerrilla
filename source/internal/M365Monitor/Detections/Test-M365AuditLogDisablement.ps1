# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365AuditLogDisablement {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Property patterns that indicate audit weakening
    $auditDisableProperties = @(
        'UnifiedAuditLogIngestionEnabled'
        'AuditDisabled'
        'AuditEnabled'
        'AuditLogAgeLimit'
        'AdminAuditLogEnabled'
        'AdminAuditLogCmdlets'
        'AdminAuditLogParameters'
        'AdminAuditLogAgeLimit'
        'MailboxAuditLogEnabled'
        'AuditAdmin'
        'AuditDelegate'
        'AuditOwner'
        'AuditBypassEnabled'
    )

    foreach ($event in $Events) {
        $activity = $event.Activity ?? ''
        $operationType = $event.OperationType ?? $activity
        $targetName = $event.TargetName ?? ''
        $auditDisabled = $false
        $auditReduced = $false
        $bypassAdded = $false
        $affectedScope = 'unknown'
        $changeDetails = [System.Collections.Generic.List[string]]::new()

        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''
            $oldVal = $prop.OldValue ?? ''
            $cleanNew = ($newVal -replace '"', '').Trim()
            $cleanOld = ($oldVal -replace '"', '').Trim()

            # Unified audit log disabled at organization level
            if ($propName -eq 'UnifiedAuditLogIngestionEnabled') {
                if ($cleanNew -match 'false|False|0') {
                    $auditDisabled = $true
                    $affectedScope = 'Organization'
                    $changeDetails.Add('CRITICAL: Unified Audit Log ingestion DISABLED for entire organization')
                }
            }

            # AuditDisabled flag set to true (inverse logic: true = auditing off)
            if ($propName -eq 'AuditDisabled') {
                if ($cleanNew -match 'true|True|1') {
                    $auditDisabled = $true
                    $affectedScope = 'Organization'
                    $changeDetails.Add('CRITICAL: Organization audit logging DISABLED')
                }
            }

            # AuditEnabled flag set to false (per-mailbox)
            if ($propName -eq 'AuditEnabled') {
                if ($cleanNew -match 'false|False|0' -and $cleanOld -match 'true|True|1') {
                    $auditDisabled = $true
                    $affectedScope = "Mailbox: $targetName"
                    $changeDetails.Add("Mailbox audit logging DISABLED for: $targetName")
                }
            }

            # AdminAuditLogEnabled = False
            if ($propName -eq 'AdminAuditLogEnabled') {
                if ($cleanNew -match 'false|False|0') {
                    $auditDisabled = $true
                    $affectedScope = 'Admin Audit'
                    $changeDetails.Add('CRITICAL: Admin audit logging DISABLED')
                }
            }

            # MailboxAuditLogEnabled = False
            if ($propName -eq 'MailboxAuditLogEnabled') {
                if ($cleanNew -match 'false|False|0') {
                    $auditDisabled = $true
                    $affectedScope = "Mailbox: $targetName"
                    $changeDetails.Add("Mailbox audit log DISABLED for: $targetName")
                }
            }

            # Audit log age limit reduced (anti-forensics)
            if ($propName -match 'AuditLogAgeLimit|AdminAuditLogAgeLimit') {
                try {
                    $newDays = if ($cleanNew -match '^(\d+)\.') { [int]$Matches[1] }
                               elseif ($cleanNew -match '^\d+$') { [int]$cleanNew }
                               else { -1 }
                    $oldDays = if ($cleanOld -match '^(\d+)\.') { [int]$Matches[1] }
                               elseif ($cleanOld -match '^\d+$') { [int]$cleanOld }
                               else { -1 }
                    if ($newDays -ge 0 -and $oldDays -gt 0 -and $newDays -lt $oldDays) {
                        $auditReduced = $true
                        $changeDetails.Add("Audit retention reduced from $oldDays to $newDays days")
                    } else {
                        $changeDetails.Add("Audit log age limit changed: '$cleanOld' -> '$cleanNew'")
                    }
                } catch {
                    $changeDetails.Add("Audit log age limit changed: '$cleanOld' -> '$cleanNew'")
                }
            }

            # Audit scope reduction (fewer cmdlets/parameters audited)
            if ($propName -match 'AdminAuditLogCmdlets|AdminAuditLogParameters|AdminAuditLogExcludedCmdlets') {
                if ($cleanOld -eq '*' -and $cleanNew -ne '*') {
                    $auditReduced = $true
                    $changeDetails.Add("Audit scope narrowed: $propName changed from wildcard to '$cleanNew'")
                } elseif (-not $cleanNew -or $cleanNew -eq '' -or $cleanNew -eq '""') {
                    $auditReduced = $true
                    $changeDetails.Add("Audit scope cleared: $propName was '$cleanOld'")
                } else {
                    $changeDetails.Add("Admin audit log filter modified: $propName changed")
                }
            }

            # Mailbox audit actions reduced
            if ($propName -match '^AuditAdmin$|^AuditDelegate$|^AuditOwner$') {
                if ($cleanOld -and $cleanNew) {
                    $oldActions = @($cleanOld -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $newActions = @($cleanNew -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    if ($newActions.Count -lt $oldActions.Count) {
                        $auditReduced = $true
                        $removed = @($oldActions | Where-Object { $_ -notin $newActions })
                        $changeDetails.Add("Audit actions reduced on $propName, removed: $($removed -join ', ')")
                    }
                } elseif ($cleanOld -and (-not $cleanNew -or $cleanNew -eq '')) {
                    $auditReduced = $true
                    $changeDetails.Add("All $propName audit actions removed (was: $cleanOld)")
                }
            }

            # Audit bypass association
            if ($propName -match 'AuditBypassEnabled|BypassAudit|BypassEnabled') {
                if ($cleanNew -match 'true|True|1') {
                    $bypassAdded = $true
                    $changeDetails.Add("Audit bypass enabled for mailbox: $targetName")
                }
            }
        }

        # Check the operation name if no property-level match
        if ($operationType -match 'Set-MailboxAuditBypassAssociation') {
            $bypassAdded = $true
            if ($changeDetails.Count -eq 0) {
                $changeDetails.Add("Mailbox audit bypass association modified for: $targetName")
            }
        }

        # Also check activity name directly for audit disable signals
        if (-not $auditDisabled -and -not $auditReduced -and -not $bypassAdded) {
            if ($activity -match 'DisableAudit|disable.*audit|AuditDisabled|UnifiedAuditLog.*disable') {
                $auditDisabled = $true
                $affectedScope = 'Organization'
                $changeDetails.Add("Audit logging disabled via: $activity")
            }
        }

        # Only report if there is an actual audit-related change
        if (-not $auditDisabled -and -not $auditReduced -and -not $bypassAdded -and $changeDetails.Count -eq 0) {
            $isAuditRelated = $false
            foreach ($auditProp in $auditDisableProperties) {
                foreach ($prop in $event.ModifiedProps) {
                    if (($prop.Name ?? '') -match $auditProp) {
                        $isAuditRelated = $true
                        break
                    }
                }
                if ($isAuditRelated) { break }
            }

            if (-not $isAuditRelated -and $activity -notmatch 'audit|AdminAuditLog') {
                continue
            }

            $changeDetails.Add("Audit configuration modified: $activity")
        }

        # Severity assessment -- audit log disablement is always critical or high
        $severity = if ($auditDisabled) { 'Critical' }
                    elseif ($bypassAdded) { 'Critical' }
                    elseif ($auditReduced) { 'High' }
                    else { 'High' }

        $description = if ($auditDisabled) {
            "CRITICAL: Audit logging DISABLED ($affectedScope) by $($event.Actor)"
        } elseif ($bypassAdded) {
            "AUDIT BYPASS ADDED: '$targetName' exempted from audit logging by $($event.Actor)"
        } elseif ($auditReduced) {
            "AUDIT SCOPE REDUCED: $operationType on '$targetName' by $($event.Actor)"
        } else {
            "Audit log configuration changed: $operationType on '$targetName' by $($event.Actor)"
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365AuditLogDisablement'
            Description   = $description
            Details       = @{
                OperationType = $operationType
                TargetName    = $targetName
                AuditDisabled = $auditDisabled
                AuditReduced  = $auditReduced
                BypassAdded   = $bypassAdded
                AffectedScope = $affectedScope
                ChangeNotes   = @($changeDetails)
                ModifiedProps = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
