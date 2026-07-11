# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-M365AuditEvents {
    <#
    .SYNOPSIS
        Collects M365 audit events from Microsoft Graph for security monitoring.

    .DESCRIPTION
        Uses Invoke-GraphApi to fetch directory audit logs, sign-in logs, and security alerts
        filtered by M365 service categories including Exchange, SharePoint/OneDrive, Teams,
        Defender, and Power Platform.

        Fast mode: Exchange transport/forwarding rules + audit log status changes only.
        Full mode: All M365 service categories.

    .PARAMETER AccessToken
        Microsoft Graph access token.

    .PARAMETER StartTime
        Start time for event collection window.

    .PARAMETER ScanMode
        Fast or Full scan mode.

    .PARAMETER Quiet
        Suppress progress output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode = 'Fast',

        [switch]$Quiet
    )

    $result = @{
        ExchangeTransportRules   = [System.Collections.Generic.List[PSCustomObject]]::new()
        ExchangeForwardingRules  = [System.Collections.Generic.List[PSCustomObject]]::new()
        EDiscoverySearches       = [System.Collections.Generic.List[PSCustomObject]]::new()
        DLPPolicyChanges         = [System.Collections.Generic.List[PSCustomObject]]::new()
        SharePointSharingChanges = [System.Collections.Generic.List[PSCustomObject]]::new()
        SharePointFileOperations = [System.Collections.Generic.List[PSCustomObject]]::new()
        TeamsAccessChanges       = [System.Collections.Generic.List[PSCustomObject]]::new()
        DefenderAlertChanges     = [System.Collections.Generic.List[PSCustomObject]]::new()
        PowerPlatformFlows       = [System.Collections.Generic.List[PSCustomObject]]::new()
        AuditLogChanges          = [System.Collections.Generic.List[PSCustomObject]]::new()
        SecurityAlerts           = [System.Collections.Generic.List[PSCustomObject]]::new()
        Errors                   = @{}
    }

    $filterDate = $StartTime.ToString('yyyy-MM-ddTHH:mm:ssZ')

    # ── Exchange Transport Rule Changes ──────────────────────────────────
    if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Exchange transport rules' }

    try {
        $transportRuleActivities = @(
            'New-TransportRule'
            'Set-TransportRule'
            'Remove-TransportRule'
            'Enable-TransportRule'
            'Disable-TransportRule'
        )

        $auditLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
            -Uri '/auditLogs/directoryAudits' `
            -QueryParameters @{
                '$filter' = "activityDateTime ge $filterDate and loggedByService eq 'Exchange'"
                '$top'    = '999'
                '$orderby' = 'activityDateTime desc'
            } `
            -Paginate -Quiet:$Quiet

        if ($auditLogs) {
            foreach ($log in $auditLogs) {
                $activity = $log.activityDisplayName
                $operationName = $log.operationType ?? $activity

                # Transport rule operations
                if ($activity -match 'TransportRule|transport rule|mail flow rule' -or
                    $operationName -in $transportRuleActivities) {
                    $result.ExchangeTransportRules.Add([PSCustomObject]@{
                        Timestamp     = $log.activityDateTime
                        Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                        ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                        Activity      = $activity
                        OperationType = $operationName
                        Result        = $log.result
                        TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                        TargetId      = ($log.targetResources | Select-Object -First 1).id ?? ''
                        ModifiedProps = @($log.targetResources | ForEach-Object {
                            $_.modifiedProperties | ForEach-Object {
                                @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                            }
                        })
                        RawLog        = $log
                    })
                }

                # Forwarding rule operations
                if ($activity -match 'forwarding|inbox rule|Set-Mailbox.*Forward|redirect' -or
                    $operationName -match 'New-InboxRule|Set-InboxRule|Set-Mailbox') {
                    $result.ExchangeForwardingRules.Add([PSCustomObject]@{
                        Timestamp     = $log.activityDateTime
                        Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                        ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                        Activity      = $activity
                        OperationType = $operationName
                        Result        = $log.result
                        TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                        TargetId      = ($log.targetResources | Select-Object -First 1).id ?? ''
                        ModifiedProps = @($log.targetResources | ForEach-Object {
                            $_.modifiedProperties | ForEach-Object {
                                @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                            }
                        })
                        RawLog        = $log
                    })
                }

                # Audit log status changes
                if ($activity -match 'audit|unified audit|AdminAuditLog' -or
                    $operationName -match 'Set-AdminAuditLogConfig|Set-OrganizationConfig.*AuditDisabled') {
                    $result.AuditLogChanges.Add([PSCustomObject]@{
                        Timestamp     = $log.activityDateTime
                        Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                        ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                        Activity      = $activity
                        OperationType = $operationName
                        Result        = $log.result
                        TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                        ModifiedProps = @($log.targetResources | ForEach-Object {
                            $_.modifiedProperties | ForEach-Object {
                                @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                            }
                        })
                        RawLog        = $log
                    })
                }
            }
        }

        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Exchange transport rules' `
                -Detail "$($result.ExchangeTransportRules.Count) transport, $($result.ExchangeForwardingRules.Count) forwarding, $($result.AuditLogChanges.Count) audit config"
        }
    } catch {
        $result.Errors['ExchangeAudit'] = $_.Exception.Message
        Write-Verbose "Exchange audit log fetch failed: $_"
    }

    # ── Fast mode stops here with just Exchange + audit log ──────────────
    if ($ScanMode -eq 'Full') {

        # ── Exchange Mailbox Forwarding (via management activity API patterns) ──
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Mailbox forwarding rules (server-side)' }

        try {
            # Query for mailbox configuration changes that set forwarding
            $mailboxLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate and loggedByService eq 'Exchange' and activityDisplayName eq 'Set-Mailbox'"
                    '$top'    = '500'
                } `
                -Paginate -Quiet:$Quiet

            if ($mailboxLogs) {
                foreach ($log in $mailboxLogs) {
                    $modProps = @($log.targetResources | ForEach-Object {
                        $_.modifiedProperties | Where-Object {
                            $_.displayName -match 'ForwardingSmtpAddress|ForwardingAddress|DeliverToMailboxAndForward'
                        }
                    })

                    if ($modProps.Count -gt 0) {
                        $result.ExchangeForwardingRules.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = 'Set-Mailbox (Forwarding)'
                            OperationType = 'Set-Mailbox'
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            TargetId      = ($log.targetResources | Select-Object -First 1).id ?? ''
                            ModifiedProps = @($modProps | ForEach-Object {
                                @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                            })
                            RawLog        = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'Mailbox forwarding' -Detail "$($result.ExchangeForwardingRules.Count) total"
            }
        } catch {
            $result.Errors['MailboxForwarding'] = $_.Exception.Message
            Write-Verbose "Mailbox forwarding fetch failed: $_"
        }

        # ── eDiscovery / Compliance Search ───────────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'eDiscovery compliance searches' }

        try {
            $complianceLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate and loggedByService eq 'Core Directory'"
                    '$top'    = '500'
                } `
                -Paginate -Quiet:$Quiet

            if ($complianceLogs) {
                foreach ($log in $complianceLogs) {
                    if ($log.activityDisplayName -match 'eDiscovery|ComplianceSearch|content search|SearchCreated|SearchStarted') {
                        $result.EDiscoverySearches.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = $log.activityDisplayName
                            OperationType = $log.operationType ?? ''
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            ModifiedProps = @($log.targetResources | ForEach-Object {
                                $_.modifiedProperties | ForEach-Object {
                                    @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                                }
                            })
                            RawLog        = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'eDiscovery searches' -Detail "$($result.EDiscoverySearches.Count) found"
            }
        } catch {
            $result.Errors['eDiscovery'] = $_.Exception.Message
            Write-Verbose "eDiscovery search fetch failed: $_"
        }

        # ── DLP Policy Changes ───────────────────────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'DLP policy changes' }

        try {
            $dlpLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate"
                    '$top'    = '500'
                } `
                -Paginate -Quiet:$Quiet

            if ($dlpLogs) {
                foreach ($log in $dlpLogs) {
                    if ($log.activityDisplayName -match 'DLP|DataLossPrevent|DlpPolicy|DlpRule|DlpCompliancePolicy') {
                        $result.DLPPolicyChanges.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = $log.activityDisplayName
                            OperationType = $log.operationType ?? ''
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            ModifiedProps = @($log.targetResources | ForEach-Object {
                                $_.modifiedProperties | ForEach-Object {
                                    @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                                }
                            })
                            RawLog        = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'DLP policy changes' -Detail "$($result.DLPPolicyChanges.Count) found"
            }
        } catch {
            $result.Errors['DLPPolicy'] = $_.Exception.Message
            Write-Verbose "DLP policy fetch failed: $_"
        }

        # ── SharePoint External Sharing Changes ──────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'SharePoint external sharing changes' }

        try {
            $spLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate and loggedByService eq 'SharePoint'"
                    '$top'    = '999'
                } `
                -Paginate -Quiet:$Quiet

            if ($spLogs) {
                foreach ($log in $spLogs) {
                    $activity = $log.activityDisplayName

                    # Sharing policy changes
                    if ($activity -match 'sharing|SharingPolicy|external.*access|anonymous.*link|guest.*access|SharingCapability') {
                        $result.SharePointSharingChanges.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = $activity
                            OperationType = $log.operationType ?? ''
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            ModifiedProps = @($log.targetResources | ForEach-Object {
                                $_.modifiedProperties | ForEach-Object {
                                    @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                                }
                            })
                            RawLog        = $log
                        })
                    }

                    # Bulk file operations (download, copy, move, sync)
                    if ($activity -match 'FileDownloaded|FilePreviewed|FileModified|FileSyncDownload|FileAccessed|FileCopied|FileMoved') {
                        $result.SharePointFileOperations.Add([PSCustomObject]@{
                            Timestamp  = $log.activityDateTime
                            Actor      = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId    = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity   = $activity
                            TargetName = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            TargetId   = ($log.targetResources | Select-Object -First 1).id ?? ''
                            RawLog     = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'SharePoint changes' `
                    -Detail "$($result.SharePointSharingChanges.Count) sharing, $($result.SharePointFileOperations.Count) file ops"
            }
        } catch {
            $result.Errors['SharePoint'] = $_.Exception.Message
            Write-Verbose "SharePoint audit fetch failed: $_"
        }

        # ── Teams External Access Changes ────────────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Teams external access changes' }

        try {
            $teamsLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate and loggedByService eq 'Teams'"
                    '$top'    = '500'
                } `
                -Paginate -Quiet:$Quiet

            if ($teamsLogs) {
                foreach ($log in $teamsLogs) {
                    if ($log.activityDisplayName -match 'external.*access|guest.*access|federation|AllowedDomains|BlockedDomains|TeamsGuestAccess|TeamsExternalAccess|TeamsMeetingPolicy') {
                        $result.TeamsAccessChanges.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = $log.activityDisplayName
                            OperationType = $log.operationType ?? ''
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            ModifiedProps = @($log.targetResources | ForEach-Object {
                                $_.modifiedProperties | ForEach-Object {
                                    @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                                }
                            })
                            RawLog        = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'Teams access changes' -Detail "$($result.TeamsAccessChanges.Count) found"
            }
        } catch {
            $result.Errors['TeamsAccess'] = $_.Exception.Message
            Write-Verbose "Teams access fetch failed: $_"
        }

        # ── Defender Alert Policy Changes ────────────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Defender alert policy changes' }

        try {
            # Fetch audit logs related to Defender/Security policy changes
            $defenderLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate"
                    '$top'    = '500'
                } `
                -Paginate -Quiet:$Quiet

            if ($defenderLogs) {
                foreach ($log in $defenderLogs) {
                    if ($log.activityDisplayName -match 'AlertPolicy|alert.*policy|ProtectionAlert|threat.*policy|SafeAttach|SafeLink|AntiPhish|Defender') {
                        $result.DefenderAlertChanges.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = $log.activityDisplayName
                            OperationType = $log.operationType ?? ''
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            ModifiedProps = @($log.targetResources | ForEach-Object {
                                $_.modifiedProperties | ForEach-Object {
                                    @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                                }
                            })
                            RawLog        = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'Defender alert changes' -Detail "$($result.DefenderAlertChanges.Count) found"
            }
        } catch {
            $result.Errors['DefenderAlerts'] = $_.Exception.Message
            Write-Verbose "Defender alert fetch failed: $_"
        }

        # ── Power Platform / Power Automate Flows ────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Power Automate flow creation' }

        try {
            $powerLogs = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/auditLogs/directoryAudits' `
                -QueryParameters @{
                    '$filter' = "activityDateTime ge $filterDate and loggedByService eq 'Power Platform'"
                    '$top'    = '500'
                } `
                -Paginate -Quiet:$Quiet

            if ($powerLogs) {
                foreach ($log in $powerLogs) {
                    if ($log.activityDisplayName -match 'CreateFlow|EditFlow|flow.*created|flow.*modified|Power.*Automate|LogicApp') {
                        $result.PowerPlatformFlows.Add([PSCustomObject]@{
                            Timestamp     = $log.activityDateTime
                            Actor         = $log.initiatedBy.user.userPrincipalName ?? $log.initiatedBy.app.displayName ?? 'Unknown'
                            ActorId       = $log.initiatedBy.user.id ?? $log.initiatedBy.app.appId ?? ''
                            Activity      = $log.activityDisplayName
                            OperationType = $log.operationType ?? ''
                            Result        = $log.result
                            TargetName    = ($log.targetResources | Select-Object -First 1).displayName ?? ''
                            ModifiedProps = @($log.targetResources | ForEach-Object {
                                $_.modifiedProperties | ForEach-Object {
                                    @{ Name = $_.displayName; OldValue = $_.oldValue; NewValue = $_.newValue }
                                }
                            })
                            RawLog        = $log
                        })
                    }
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'Power Automate flows' -Detail "$($result.PowerPlatformFlows.Count) found"
            }
        } catch {
            $result.Errors['PowerPlatform'] = $_.Exception.Message
            Write-Verbose "Power Platform fetch failed: $_"
        }

        # ── Security Alerts (Defender alerts_v2) ─────────────────────────
        if (-not $Quiet) { Write-ProgressLine -Phase SCANNING -Message 'Security alerts (Defender)' }

        try {
            $alerts = Invoke-GraphApi -AccessToken $AccessToken -ReturnNullOnError `
                -Uri '/security/alerts_v2' `
                -QueryParameters @{
                    '$filter' = "createdDateTime ge $filterDate"
                    '$top'    = '999'
                    '$orderby' = 'createdDateTime desc'
                } `
                -Paginate -Quiet:$Quiet

            if ($alerts) {
                foreach ($alert in $alerts) {
                    $result.SecurityAlerts.Add([PSCustomObject]@{
                        Timestamp    = $alert.createdDateTime
                        AlertId      = $alert.id
                        Title        = $alert.title
                        Description  = $alert.description
                        Severity     = $alert.severity
                        Status       = $alert.status
                        Category     = $alert.category
                        Source        = $alert.detectionSource ?? $alert.serviceSource ?? ''
                        ThreatName   = $alert.threatDisplayName ?? ''
                        UserStates   = @($alert.evidence | Where-Object { $_.'@odata.type' -match 'user' } | ForEach-Object {
                            @{
                                UserPrincipalName = $_.userAccount.accountName ?? ''
                                DomainName        = $_.userAccount.domainName ?? ''
                            }
                        })
                        RawAlert     = $alert
                    })
                }
            }
            if (-not $Quiet) {
                Write-ProgressLine -Phase SCANNING -Message 'Security alerts' -Detail "$($result.SecurityAlerts.Count) found"
            }
        } catch {
            $result.Errors['SecurityAlerts'] = $_.Exception.Message
            Write-Verbose "Security alerts fetch failed: $_"
        }
    }

    return $result
}
