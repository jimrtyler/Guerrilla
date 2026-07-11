# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-AlertEscalation {
    <#
    .SYNOPSIS
        Checks for unresolved alerts that should be escalated and re-dispatches them.
    .DESCRIPTION
        Reads the alert history, finds alerts older than the escalation window that
        haven't been resolved, and re-dispatches them via the escalation provider list
        with an [ESCALATED] subject prefix.
    .PARAMETER Config
        The full Guerrilla config hashtable.
    .PARAMETER ScanResult
        The current scan result (used to verify threats are still active).
    .PARAMETER Force
        Force escalation even if window hasn't elapsed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [PSCustomObject]$ScanResult,

        [switch]$Force
    )

    $escalation = $Config.alerting.escalation
    if (-not $escalation -or -not $escalation.enabled) {
        Write-Verbose 'Escalation is not enabled.'
        return [PSCustomObject]@{
            Provider = 'Escalation'
            Success  = $false
            Message  = 'Escalation not enabled'
            Error    = $null
            Escalated = 0
        }
    }

    $windowMinutes = $escalation.windowMinutes ?? 120
    $threshold = $escalation.threshold ?? 'HIGH'
    $escalationProviders = @($escalation.providers ?? @())

    if ($escalationProviders.Count -eq 0) {
        Write-Verbose 'No escalation providers configured.'
        return [PSCustomObject]@{
            Provider = 'Escalation'
            Success  = $false
            Message  = 'No escalation providers configured'
            Error    = $null
            Escalated = 0
        }
    }

    $levelOrder = @{ 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
    $minOrdinal = $levelOrder[$threshold] ?? 3

    # Load alert history
    $dataDir = Get-GuerrillaDataRoot
    $historyPath = Join-Path $dataDir 'alert-history.json'
    $history = @{}
    if (Test-Path $historyPath) {
        try {
            $history = Get-Content -Path $historyPath -Raw | ConvertFrom-Json -AsHashtable
            if ($history -isnot [hashtable]) { $history = @{} }
        } catch { $history = @{} }
    }

    if ($history.Count -eq 0) {
        return [PSCustomObject]@{
            Provider = 'Escalation'
            Success  = $true
            Message  = 'No alert history to escalate'
            Error    = $null
            Escalated = 0
        }
    }

    # Find alerts older than escalation window that are still active threats
    $escalationCutoff = [datetime]::UtcNow.AddMinutes(-$windowMinutes)

    # Get current active threat emails for cross-reference
    $activeThreats = @{}
    $flagged = $ScanResult.FlaggedUsers ?? $ScanResult.FlaggedEntities ?? $ScanResult.FlaggedChanges ?? @()
    foreach ($t in $flagged) {
        $email = $t.Email ?? $t.UserPrincipalName ?? ''
        if ($email) { $activeThreats[$email] = $t }
    }

    $threatsToEscalate = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($key in $history.Keys) {
        $entry = $history[$key]
        $entryTime = [datetime]::MinValue
        try { $entryTime = [datetime]::Parse($entry.timestamp) } catch { continue }

        # Must be older than escalation window
        if (-not $Force -and $entryTime -gt $escalationCutoff) { continue }

        # Must meet severity threshold
        $entryOrdinal = $levelOrder[$entry.threatLevel] ?? 0
        if ($entryOrdinal -lt $minOrdinal) { continue }

        # Must still be an active threat
        $entryEmail = $entry.email ?? ''
        if ($activeThreats.ContainsKey($entryEmail)) {
            $threatsToEscalate.Add($activeThreats[$entryEmail])
        }
    }

    if ($threatsToEscalate.Count -eq 0) {
        return [PSCustomObject]@{
            Provider  = 'Escalation'
            Success   = $true
            Message   = 'No threats require escalation'
            Error     = $null
            Escalated = 0
        }
    }

    # Dispatch via escalation providers
    $subject = "[ESCALATED] [Guerrilla] $($threatsToEscalate.Count) unresolved threat(s)"
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    $htmlContent = Format-SignalContent -ScanResult $ScanResult -Format Html -Threats $threatsToEscalate
    $textContent = Format-SignalContent -ScanResult $ScanResult -Format Text -Threats $threatsToEscalate

    foreach ($prov in $escalationProviders) {
        switch ($prov) {
            'SendGrid' {
                $sg = $Config.alerting.providers.sendgrid
                if ($sg.apiKey -and $sg.fromEmail -and $sg.toEmails.Count -gt 0) {
                    $r = Send-SignalSendGrid -ApiKey $sg.apiKey -FromEmail $sg.fromEmail `
                        -ToEmails $sg.toEmails -Subject $subject -HtmlBody $htmlContent -TextBody $textContent `
                        -FromName ($sg.fromName ?? 'Guerrilla Escalation')
                    $allResults.Add($r)
                }
            }
            'Teams' {
                $tm = $Config.alerting.providers.teams
                if ($tm.webhookUrl) {
                    $r = Send-SignalTeams -WebhookUrl $tm.webhookUrl -Subject $subject -Threats @($threatsToEscalate)
                    $allResults.Add($r)
                }
            }
            'Slack' {
                $sl = $Config.alerting.providers.slack
                if ($sl.webhookUrl) {
                    $r = Send-SignalSlack -WebhookUrl $sl.webhookUrl -Subject $subject -Threats @($threatsToEscalate) -TextBody $textContent
                    $allResults.Add($r)
                }
            }
            'PagerDuty' {
                $pd = $Config.alerting.providers.pagerduty
                if ($pd.routingKey) {
                    $r = Send-SignalPagerDuty -RoutingKey $pd.routingKey -Subject $subject -Threats @($threatsToEscalate)
                    $allResults.Add($r)
                }
            }
            'Webhook' {
                $wh = $Config.alerting.providers.webhook
                if ($wh.url) {
                    $whHeaders = @{}
                    if ($wh.headers) { foreach ($k in $wh.headers.Keys) { $whHeaders[$k] = $wh.headers[$k] } }
                    $r = Send-SignalWebhook -WebhookUrl $wh.url -Threats @($threatsToEscalate) -ScanResult $ScanResult -Headers $whHeaders -AuthToken ($wh.authToken ?? '')
                    $allResults.Add($r)
                }
            }
        }
    }

    $anySuccess = @($allResults | Where-Object Success).Count -gt 0
    return [PSCustomObject]@{
        Provider  = 'Escalation'
        Success   = $anySuccess
        Message   = "Escalation: $($threatsToEscalate.Count) threat(s) escalated via $($allResults.Count) provider(s)"
        Error     = if (-not $anySuccess -and $allResults.Count -gt 0) { ($allResults | Where-Object { -not $_.Success } | Select-Object -First 1).Error } else { $null }
        Escalated = $threatsToEscalate.Count
        Details   = @($allResults)
    }
}
