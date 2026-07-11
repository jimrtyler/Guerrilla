# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-Signal {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$ScanResult,

        [ValidateSet('SendGrid', 'Mailgun', 'Twilio', 'Teams', 'Slack', 'Webhook', 'PagerDuty', 'Pushover', 'Syslog', 'EventLog', 'All')]
        [string[]]$Provider,

        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')]
        [string]$MinimumThreatLevel,

        [bool]$NewOnly = $true,
        [switch]$IncludeHtmlReport,
        [switch]$DryRun,
        [switch]$Force,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,
        [Alias('MissionConfig')]
        [string]$ConfigFile
    )

    process {
        $validTypes = @(
            'Guerrilla.ScanResult'
            'Guerrilla.SurveillanceResult'
            'Guerrilla.WatchtowerResult'
            'Guerrilla.WiretapResult'
        )
        $isValid = $false
        if ($ScanResult) {
            foreach ($typeName in $ScanResult.PSObject.TypeNames) {
                if ($typeName -in $validTypes) { $isValid = $true; break }
            }
        }
        if (-not $isValid) {
            Write-Warning 'Send-Signal requires a Guerrilla result object. Pipe from Invoke-Recon, Invoke-Surveillance, Invoke-Watchtower, or Invoke-Wiretap.'
            return
        }

        # Normalize property access: all result types use NewThreats and FlaggedUsers/FlaggedEntities/FlaggedChanges
        if (-not $ScanResult.PSObject.Properties['FlaggedUsers']) {
            $flaggedProp = $ScanResult.PSObject.Properties['FlaggedEntities'] ?? $ScanResult.PSObject.Properties['FlaggedChanges']
            if ($flaggedProp) {
                $ScanResult | Add-Member -NotePropertyName 'FlaggedUsers' -NotePropertyValue $flaggedProp.Value -Force
            }
        }

        # Load config
        $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
        $config = $null
        if (Test-Path $cfgPath) {
            $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
        }

        # --- Resolve alerting credentials from vault via mission config ---
        if ($ConfigFile) {
            $missionCfg = Read-MissionConfig -Path $ConfigFile
            $vaultName = $missionCfg.VaultName

            # Resolve alerting channel credentials from vault and inject into config
            if ($missionCfg.Alerting -and $missionCfg.Alerting.channels -and $config) {
                if (-not $config.alerting) { $config.alerting = @{ enabled = $true; providers = @{} } }
                if (-not $config.alerting.providers) { $config.alerting.providers = @{} }
                $config.alerting.enabled = $true

                foreach ($channel in $missionCfg.Alerting.channels) {
                    if ($channel.vaultKey) {
                        try {
                            $credValue = Get-GuerrillaCredential -VaultKey $channel.vaultKey -VaultName $vaultName

                            switch ($channel.type) {
                                'teams' {
                                    if (-not $config.alerting.providers.teams) { $config.alerting.providers.teams = @{} }
                                    $config.alerting.providers.teams.enabled = $true
                                    $config.alerting.providers.teams.webhookUrl = $credValue
                                }
                                'slack' {
                                    if (-not $config.alerting.providers.slack) { $config.alerting.providers.slack = @{} }
                                    $config.alerting.providers.slack.enabled = $true
                                    $config.alerting.providers.slack.webhookUrl = $credValue
                                }
                                'webhook' {
                                    if (-not $config.alerting.providers.webhook) { $config.alerting.providers.webhook = @{} }
                                    $config.alerting.providers.webhook.enabled = $true
                                    $config.alerting.providers.webhook.url = $credValue
                                }
                                'pagerduty' {
                                    if (-not $config.alerting.providers.pagerduty) { $config.alerting.providers.pagerduty = @{} }
                                    $config.alerting.providers.pagerduty.enabled = $true
                                    $config.alerting.providers.pagerduty.routingKey = $credValue
                                }
                                'email' {
                                    # Email credential from vault is JSON with apiKey, fromEmail, toEmails, and optionally provider/domain
                                    try {
                                        $emailCfg = $credValue | ConvertFrom-Json -AsHashtable
                                        $emailProvider = if ($emailCfg.provider -eq 'mailgun') { 'mailgun' } else { 'sendgrid' }

                                        if ($emailProvider -eq 'mailgun') {
                                            if (-not $config.alerting.providers.mailgun) { $config.alerting.providers.mailgun = @{} }
                                            $config.alerting.providers.mailgun.enabled = $true
                                            foreach ($k in $emailCfg.Keys) { $config.alerting.providers.mailgun[$k] = $emailCfg[$k] }
                                            # Ensure domain is set — fall back to from address domain
                                            if (-not $config.alerting.providers.mailgun.domain -and $emailCfg.fromEmail -match '@(.+)$') {
                                                $config.alerting.providers.mailgun.domain = $Matches[1]
                                            }
                                        } else {
                                            if (-not $config.alerting.providers.sendgrid) { $config.alerting.providers.sendgrid = @{} }
                                            $config.alerting.providers.sendgrid.enabled = $true
                                            foreach ($k in $emailCfg.Keys) { $config.alerting.providers.sendgrid[$k] = $emailCfg[$k] }
                                        }
                                    } catch {
                                        Write-Warning "Failed to parse email credential from vault: $_"
                                    }
                                }
                                'sms' {
                                    # SMS/Twilio credential from vault is expected to be JSON
                                    try {
                                        $smsCfg = $credValue | ConvertFrom-Json -AsHashtable
                                        if (-not $config.alerting.providers.twilio) { $config.alerting.providers.twilio = @{} }
                                        $config.alerting.providers.twilio.enabled = $true
                                        foreach ($k in $smsCfg.Keys) { $config.alerting.providers.twilio[$k] = $smsCfg[$k] }
                                    } catch {
                                        Write-Warning "Failed to parse SMS credential from vault: $_"
                                    }
                                }
                                'pushover' {
                                    # Pushover credential from vault is JSON with apiToken, userKey
                                    try {
                                        $pushCfg = $credValue | ConvertFrom-Json -AsHashtable
                                        if (-not $config.alerting.providers.pushover) { $config.alerting.providers.pushover = @{} }
                                        $config.alerting.providers.pushover.enabled = $true
                                        foreach ($k in $pushCfg.Keys) { $config.alerting.providers.pushover[$k] = $pushCfg[$k] }
                                    } catch {
                                        Write-Warning "Failed to parse Pushover credential from vault: $_"
                                    }
                                }
                            }
                        } catch {
                            Write-Warning "Failed to resolve alerting credential '$($channel.vaultKey)' from vault: $_"
                        }
                    }
                }
            }
        }

        if (-not $config -or -not $config.alerting) {
            Write-Warning 'No alerting configuration found. Run Set-Safehouse to configure alert providers.'
            return
        }

        if (-not $config.alerting.enabled -and -not $Force) {
            Write-Verbose 'Alerting is disabled in config. Use -Force to override.'
            return
        }

        # Determine global minimum level
        $minLevel = if ($MinimumThreatLevel) { $MinimumThreatLevel }
                    elseif ($config.alerting.minimumThreatLevel) { $config.alerting.minimumThreatLevel }
                    else { 'HIGH' }

        $levelOrder = @{ 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
        $minOrdinal = $levelOrder[$minLevel]

        # Select threats to alert on
        $threats = if ($NewOnly -and -not $Force) { $ScanResult.NewThreats } else { $ScanResult.FlaggedUsers }

        # Normalize heterogeneous result shapes: monitor results (Watchtower /
        # Surveillance / Wiretap) expose .Severity, while user-threat results
        # expose .ThreatLevel. Map Severity -> ThreatLevel so level filtering and
        # the downstream formatting/subject logic work for every supported type.
        $threats = @($threats | ForEach-Object {
            if ($_ -and -not $_.ThreatLevel -and $_.Severity) {
                $_ | Add-Member -NotePropertyName ThreatLevel -NotePropertyValue ([string]$_.Severity).ToUpper() -Force -PassThru
            } else {
                $_
            }
        })
        # ContainsKey guard: indexing a hashtable with a $null key throws
        # ("array index evaluated to null"), which previously aborted the whole
        # send when an item had neither ThreatLevel nor Severity.
        $threats = @($threats | Where-Object {
            $_.ThreatLevel -and
            $levelOrder.ContainsKey([string]$_.ThreatLevel) -and
            $levelOrder[[string]$_.ThreatLevel] -ge $minOrdinal
        })

        if ($threats.Count -eq 0) {
            Write-Verbose "No threats at $minLevel or above to alert on."
            return [PSCustomObject]@{
                PSTypeName = 'Guerrilla.AlertResult'
                Sent       = $false
                Reason     = "No threats at $minLevel or above"
                Results    = @()
            }
        }

        # --- Alert deduplication ---
        $suppressionHours = $config.alerting.suppression.windowHours ?? 24
        if (-not $Force -and $config.alerting.suppression.enabled) {
            $dedupResults = @()
            $unsuppressed = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($t in $threats) {
                $dedup = Get-AlertDeduplication -Threat $t -SuppressionHours $suppressionHours
                if ($dedup.IsSuppressed) {
                    Write-Verbose "Suppressed duplicate alert for $($dedup.Email) ($($dedup.ThreatLevel))"
                } else {
                    $unsuppressed.Add($t)
                    $dedupResults += $dedup
                }
            }
            if ($unsuppressed.Count -eq 0) {
                Write-Verbose "All $($threats.Count) threat(s) suppressed by deduplication."
                return [PSCustomObject]@{
                    PSTypeName = 'Guerrilla.AlertResult'
                    Sent       = $false
                    Reason     = "All threats suppressed (within ${suppressionHours}h window)"
                    Results    = @()
                }
            }
            $threats = @($unsuppressed)
        }

        # Format content
        $htmlContent = Format-SignalContent -ScanResult $ScanResult -Format Html -Threats $threats
        $textContent = Format-SignalContent -ScanResult $ScanResult -Format Text -Threats $threats
        $smsContent  = Format-SignalContent -ScanResult $ScanResult -Format Sms -Threats $threats

        $critCount = @($threats | Where-Object ThreatLevel -eq 'CRITICAL').Count
        $highCount = @($threats | Where-Object ThreatLevel -eq 'HIGH').Count
        $subject = "[Guerrilla] $($threats.Count) threat(s) detected"
        if ($critCount -gt 0) { $subject += " - $critCount CRITICAL" }
        if ($highCount -gt 0) { $subject += " - $highCount HIGH" }

        if ($DryRun) {
            Write-GuerrillaText '=== DRY RUN - No signals sent ===' -Color Amber
            Write-GuerrillaText "Subject: $subject" -Color Olive
            Write-GuerrillaText "Threats: $($threats.Count)" -Color Olive
            Write-Host ''
            Write-GuerrillaText '--- Text Content ---' -Color Parchment
            Write-Host $textContent
            Write-Host ''
            Write-GuerrillaText '--- SMS Content ---' -Color Parchment
            Write-Host $smsContent
            return [PSCustomObject]@{
                PSTypeName = 'Guerrilla.AlertResult'
                Sent       = $false
                Reason     = 'DryRun'
                Results    = @()
            }
        }

        # Determine which providers to use
        $enabledProviders = @()
        if (-not $Provider -or 'All' -in $Provider) {
            if ($config.alerting.providers.sendgrid.enabled)  { $enabledProviders += 'SendGrid' }
            if ($config.alerting.providers.mailgun.enabled)   { $enabledProviders += 'Mailgun' }
            if ($config.alerting.providers.twilio.enabled)    { $enabledProviders += 'Twilio' }
            if ($config.alerting.providers.teams.enabled)     { $enabledProviders += 'Teams' }
            if ($config.alerting.providers.slack.enabled)     { $enabledProviders += 'Slack' }
            if ($config.alerting.providers.webhook.enabled)   { $enabledProviders += 'Webhook' }
            if ($config.alerting.providers.pagerduty.enabled) { $enabledProviders += 'PagerDuty' }
            if ($config.alerting.providers.pushover.enabled)  { $enabledProviders += 'Pushover' }
            if ($config.alerting.providers.syslog.enabled)    { $enabledProviders += 'Syslog' }
            if ($config.alerting.providers.eventlog.enabled)  { $enabledProviders += 'EventLog' }
        } else {
            $enabledProviders = $Provider
        }

        if ($enabledProviders.Count -eq 0) {
            Write-Warning 'No alert providers are enabled. Configure providers with Set-Safehouse.'
            return [PSCustomObject]@{
                PSTypeName = 'Guerrilla.AlertResult'
                Sent       = $false
                Reason     = 'No providers enabled'
                Results    = @()
            }
        }

        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        # --- Helper: filter threats by per-provider threshold ---
        $filterThreats = {
            param($ProviderName, $AllThreats)
            $provConfig = $config.alerting.providers[$ProviderName.ToLower()]
            if ($provConfig -and $provConfig.minimumThreatLevel) {
                $provMin = $levelOrder[$provConfig.minimumThreatLevel] ?? $minOrdinal
                @($AllThreats | Where-Object { $levelOrder[$_.ThreatLevel] -ge $provMin })
            } else {
                $AllThreats
            }
        }

        # SendGrid
        if ('SendGrid' -in $enabledProviders) {
            $provThreats = & $filterThreats 'sendgrid' $threats
            if ($provThreats.Count -gt 0) {
                $sg = $config.alerting.providers.sendgrid
                if ($sg.apiKey -and $sg.fromEmail -and $sg.toEmails.Count -gt 0) {
                    $result = Send-SignalSendGrid `
                        -ApiKey $sg.apiKey `
                        -FromEmail $sg.fromEmail `
                        -ToEmails $sg.toEmails `
                        -Subject $subject `
                        -HtmlBody $htmlContent `
                        -TextBody $textContent `
                        -FromName ($sg.fromName ?? 'Guerrilla Signals')
                    $allResults.Add($result)
                    Write-Verbose "SendGrid: $($result.Message)"
                } else {
                    Write-Warning 'SendGrid enabled but missing apiKey, fromEmail, or toEmails.'
                }
            }
        }

        # Mailgun
        if ('Mailgun' -in $enabledProviders) {
            $provThreats = & $filterThreats 'mailgun' $threats
            if ($provThreats.Count -gt 0) {
                $mg = $config.alerting.providers.mailgun
                if ($mg.apiKey -and $mg.domain -and $mg.fromEmail -and $mg.toEmails.Count -gt 0) {
                    $result = Send-SignalMailgun `
                        -ApiKey $mg.apiKey `
                        -Domain $mg.domain `
                        -FromEmail $mg.fromEmail `
                        -ToEmails $mg.toEmails `
                        -Subject $subject `
                        -HtmlBody $htmlContent `
                        -TextBody $textContent
                    $allResults.Add($result)
                    Write-Verbose "Mailgun: $($result.Message)"
                } else {
                    Write-Warning 'Mailgun enabled but missing apiKey, domain, fromEmail, or toEmails.'
                }
            }
        }

        # Twilio SMS
        if ('Twilio' -in $enabledProviders) {
            $provThreats = & $filterThreats 'twilio' $threats
            if ($provThreats.Count -gt 0) {
                $tw = $config.alerting.providers.twilio
                if ($tw.accountSid -and $tw.authToken -and $tw.fromNumber -and $tw.toNumbers.Count -gt 0) {
                    $results = Send-SignalTwilio `
                        -AccountSid $tw.accountSid `
                        -AuthToken $tw.authToken `
                        -FromNumber $tw.fromNumber `
                        -ToNumbers $tw.toNumbers `
                        -MessageBody $smsContent
                    foreach ($r in $results) { $allResults.Add($r) }
                    Write-Verbose "Twilio: $($results.Count) SMS sent"
                } else {
                    Write-Warning 'Twilio enabled but missing accountSid, authToken, fromNumber, or toNumbers.'
                }
            }
        }

        # Teams
        if ('Teams' -in $enabledProviders) {
            $provThreats = & $filterThreats 'teams' $threats
            if ($provThreats.Count -gt 0) {
                $tm = $config.alerting.providers.teams
                if ($tm.webhookUrl) {
                    $result = Send-SignalTeams `
                        -WebhookUrl $tm.webhookUrl `
                        -Subject $subject `
                        -Threats $provThreats
                    $allResults.Add($result)
                    Write-Verbose "Teams: $($result.Message)"
                } else {
                    Write-Warning 'Teams enabled but missing webhookUrl.'
                }
            }
        }

        # Slack
        if ('Slack' -in $enabledProviders) {
            $provThreats = & $filterThreats 'slack' $threats
            if ($provThreats.Count -gt 0) {
                $sl = $config.alerting.providers.slack
                if ($sl.webhookUrl) {
                    $result = Send-SignalSlack `
                        -WebhookUrl $sl.webhookUrl `
                        -Subject $subject `
                        -Threats $provThreats `
                        -TextBody $textContent
                    $allResults.Add($result)
                    Write-Verbose "Slack: $($result.Message)"
                } else {
                    Write-Warning 'Slack enabled but missing webhookUrl.'
                }
            }
        }

        # Generic Webhook (SIEM)
        if ('Webhook' -in $enabledProviders) {
            $provThreats = & $filterThreats 'webhook' $threats
            if ($provThreats.Count -gt 0) {
                $wh = $config.alerting.providers.webhook
                if ($wh.url) {
                    $whHeaders = @{}
                    if ($wh.headers) {
                        foreach ($key in $wh.headers.Keys) { $whHeaders[$key] = $wh.headers[$key] }
                    }
                    $result = Send-SignalWebhook `
                        -WebhookUrl $wh.url `
                        -Threats $provThreats `
                        -ScanResult $ScanResult `
                        -Headers $whHeaders `
                        -AuthToken ($wh.authToken ?? '')
                    $allResults.Add($result)
                    Write-Verbose "Webhook: $($result.Message)"
                } else {
                    Write-Warning 'Webhook enabled but missing url.'
                }
            }
        }

        # PagerDuty
        if ('PagerDuty' -in $enabledProviders) {
            $provThreats = & $filterThreats 'pagerduty' $threats
            if ($provThreats.Count -gt 0) {
                $pd = $config.alerting.providers.pagerduty
                if ($pd.routingKey) {
                    $result = Send-SignalPagerDuty `
                        -RoutingKey $pd.routingKey `
                        -Subject $subject `
                        -Threats $provThreats
                    $allResults.Add($result)
                    Write-Verbose "PagerDuty: $($result.Message)"
                } else {
                    Write-Warning 'PagerDuty enabled but missing routingKey.'
                }
            }
        }

        # Pushover
        if ('Pushover' -in $enabledProviders) {
            $provThreats = & $filterThreats 'pushover' $threats
            if ($provThreats.Count -gt 0) {
                $po = $config.alerting.providers.pushover
                if ($po.apiToken -and $po.userKey) {
                    # Map highest threat level to Pushover priority
                    $maxLevel = ($provThreats | Sort-Object { $levelOrder[$_.ThreatLevel] } -Descending | Select-Object -First 1).ThreatLevel
                    $pushPriority = switch ($maxLevel) {
                        'CRITICAL' { 2 }
                        'HIGH'     { 1 }
                        'MEDIUM'   { 0 }
                        'LOW'      { -1 }
                        default    { 0 }
                    }

                    # Build concise push message from threat summary
                    $critCount = @($provThreats | Where-Object ThreatLevel -eq 'CRITICAL').Count
                    $highCount = @($provThreats | Where-Object ThreatLevel -eq 'HIGH').Count
                    $pushLines = @("$($provThreats.Count) threat(s) detected")
                    if ($critCount) { $pushLines += "$critCount CRITICAL" }
                    if ($highCount) { $pushLines += "$highCount HIGH" }
                    $top3 = $provThreats | Sort-Object { $levelOrder[$_.ThreatLevel] } -Descending | Select-Object -First 3
                    foreach ($t in $top3) {
                        $id = if ($t.Email) { $t.Email } elseif ($t.Entity) { $t.Entity } else { $t.Description }
                        $pushLines += "<b>$($t.ThreatLevel)</b> $id"
                    }

                    $pushParams = @{
                        ApiToken = $po.apiToken
                        UserKey  = $po.userKey
                        Message  = ($pushLines -join "`n")
                        Title    = $subject
                        Priority = $pushPriority
                    }
                    if ($po.sound)  { $pushParams['Sound'] = $po.sound }
                    if ($pushPriority -eq 2) {
                        $pushParams['Retry']  = $po.retry ?? 60
                        $pushParams['Expire'] = $po.expire ?? 3600
                    }

                    $result = Send-SignalPushover @pushParams
                    $allResults.Add($result)
                    Write-Verbose "Pushover: $($result.Message)"
                } else {
                    Write-Warning 'Pushover enabled but missing apiToken or userKey.'
                }
            }
        }

        # Syslog
        if ('Syslog' -in $enabledProviders) {
            $provThreats = & $filterThreats 'syslog' $threats
            if ($provThreats.Count -gt 0) {
                $sy = $config.alerting.providers.syslog
                if ($sy.server) {
                    $result = Send-SignalSyslog `
                        -Server $sy.server `
                        -Port ($sy.port ?? 514) `
                        -Protocol ($sy.protocol ?? 'UDP') `
                        -Format ($sy.format ?? 'CEF') `
                        -Threats $provThreats `
                        -Subject $subject `
                        -Facility ($sy.facility ?? 1)
                    $allResults.Add($result)
                    Write-Verbose "Syslog: $($result.Message)"
                } else {
                    Write-Warning 'Syslog enabled but missing server.'
                }
            }
        }

        # EventLog
        if ('EventLog' -in $enabledProviders) {
            $provThreats = & $filterThreats 'eventlog' $threats
            if ($provThreats.Count -gt 0) {
                $el = $config.alerting.providers.eventlog
                $result = Send-SignalEventLog `
                    -Threats $provThreats `
                    -Subject $subject `
                    -Source ($el.source ?? 'Guerrilla') `
                    -LogName ($el.logName ?? 'Application')
                $allResults.Add($result)
                Write-Verbose "EventLog: $($result.Message)"
            }
        }

        $anySuccess = @($allResults | Where-Object Success).Count -gt 0

        # --- Save dedup history for successfully sent alerts ---
        if ($anySuccess -and $config.alerting.suppression.enabled) {
            foreach ($t in $threats) {
                $dedup = Get-AlertDeduplication -Threat $t -SuppressionHours $suppressionHours
                Save-AlertHistory -DedupKey $dedup.DedupKey -Email $dedup.Email -ThreatLevel $dedup.ThreatLevel
            }
        }

        # --- Trigger escalation check ---
        if ($config.alerting.escalation.enabled) {
            try {
                $escResult = Invoke-AlertEscalation -Config $config -ScanResult $ScanResult
                if ($escResult.Escalated -gt 0) {
                    $allResults.Add($escResult)
                    Write-Verbose "Escalation: $($escResult.Message)"
                }
            } catch {
                Write-Verbose "Escalation check failed: $_"
            }
        }

        return [PSCustomObject]@{
            PSTypeName = 'Guerrilla.AlertResult'
            Sent       = $anySuccess
            Reason     = if ($anySuccess) { 'Alerts dispatched' } else { 'All providers failed' }
            Results    = @($allResults)
        }
    }
}
