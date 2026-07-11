# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalDigest {
    <#
    .SYNOPSIS
        Sends an aggregated digest report of recent threat activity.
    .DESCRIPTION
        Reads recent state files, aggregates threat counts and scores, computes deltas
        from the previous digest, and dispatches a summary via configured providers.
    .PARAMETER Period
        Digest period: Daily or Weekly. Default: Daily.
    .PARAMETER Providers
        Specific providers to dispatch the digest through. If not specified, uses
        providers listed in config alerting.digest.providers.
    .PARAMETER ConfigPath
        Override config file path.
    .PARAMETER Force
        Bypass the digest interval check and send immediately.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Daily', 'Weekly')]
        [string]$Period = 'Daily',

        [string[]]$Providers,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,
        [switch]$Force
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if (Test-Path $cfgPath) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
    }

    if (-not $config) {
        Write-Warning 'No configuration found. Run Set-Safehouse first.'
        return [PSCustomObject]@{
            Provider = 'Digest'
            Success  = $false
            Message  = 'No config'
            Error    = 'Configuration not found'
        }
    }

    $dataDir = Get-GuerrillaDataRoot
    $digestHistoryPath = Join-Path $dataDir 'digest-history.json'

    # Check if digest interval has elapsed
    if (-not $Force -and (Test-Path $digestHistoryPath)) {
        $history = Get-Content -Path $digestHistoryPath -Raw | ConvertFrom-Json -AsHashtable
        $lastSent = if ($history.lastSent) { [datetime]::Parse($history.lastSent) } else { [datetime]::MinValue }
        $intervalHours = if ($Period -eq 'Weekly') { 168 } else { 24 }
        $nextDue = $lastSent.AddHours($intervalHours)

        if ([datetime]::UtcNow -lt $nextDue) {
            Write-Verbose "Digest not due until $($nextDue.ToString('o')). Use -Force to override."
            return [PSCustomObject]@{
                Provider = 'Digest'
                Success  = $false
                Message  = "Digest not due until $($nextDue.ToString('yyyy-MM-dd HH:mm')) UTC"
                Error    = $null
            }
        }
    }

    # Collect state files
    $stateFiles = @()
    if (Test-Path $dataDir) {
        $stateFiles = @(Get-ChildItem -Path $dataDir -Filter '*.state.json' -ErrorAction SilentlyContinue)
    }

    # Determine time window
    $windowHours = if ($Period -eq 'Weekly') { 168 } else { 24 }
    $cutoff = [datetime]::UtcNow.AddHours(-$windowHours)

    # Aggregate data from state files
    $totalScans = 0
    $totalThreats = 0
    $criticalTotal = 0
    $highTotal = 0
    $mediumTotal = 0
    $lowTotal = 0
    $theatersActive = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($file in $stateFiles) {
        try {
            $state = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -AsHashtable
            $stateTime = if ($state.timestamp) { [datetime]::Parse($state.timestamp) } else { $file.LastWriteTimeUtc }

            if ($stateTime -lt $cutoff) { continue }

            $totalScans++
            if ($state.theater) { $theatersActive.Add($state.theater) | Out-Null }

            $criticalTotal += ($state.criticalCount ?? 0)
            $highTotal     += ($state.highCount ?? 0)
            $mediumTotal   += ($state.mediumCount ?? 0)
            $lowTotal      += ($state.lowCount ?? 0)
            $totalThreats  += ($state.criticalCount ?? 0) + ($state.highCount ?? 0) + ($state.mediumCount ?? 0) + ($state.lowCount ?? 0)
        } catch {
            Write-Verbose "Failed to parse state file $($file.Name): $_"
        }
    }

    # Load previous digest for delta
    $previousThreats = 0
    if (Test-Path $digestHistoryPath) {
        try {
            $prevDigest = Get-Content -Path $digestHistoryPath -Raw | ConvertFrom-Json -AsHashtable
            $previousThreats = $prevDigest.totalThreats ?? 0
        } catch { }
    }

    $delta = $totalThreats - $previousThreats
    $trend = if ($delta -gt 0) { "+$delta" } elseif ($delta -lt 0) { "$delta" } else { 'no change' }

    # Build digest content
    $subject = "[Guerrilla] $Period Digest - $totalThreats threat(s) ($trend)"

    $textBody = @"
Guerrilla $Period Security Digest
========================================

Period: Last $windowHours hours
Scans completed: $totalScans
Theaters active: $($theatersActive.Count) ($($theatersActive -join ', '))

Threat Summary:
  CRITICAL: $criticalTotal
  HIGH:     $highTotal
  MEDIUM:   $mediumTotal
  LOW:      $lowTotal
  TOTAL:    $totalThreats ($trend from previous digest)

Generated: $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC
Guerrilla v2.1.0
"@

    $htmlBody = @"
<html><body style="font-family:Consolas,monospace;background:#1a1a1a;color:#ffd7af;padding:20px;">
<h2 style="color:#afaf5f;">Guerrilla $Period Digest</h2>
<p>Period: Last $windowHours hours | Scans: $totalScans | Theaters: $($theatersActive -join ', ')</p>
<table style="border-collapse:collapse;margin:10px 0;">
<tr><td style="color:#af0000;padding:4px 12px;">CRITICAL</td><td style="color:#fff;padding:4px 12px;">$criticalTotal</td></tr>
<tr><td style="color:#d75f00;padding:4px 12px;">HIGH</td><td style="color:#fff;padding:4px 12px;">$highTotal</td></tr>
<tr><td style="color:#ff8700;padding:4px 12px;">MEDIUM</td><td style="color:#fff;padding:4px 12px;">$mediumTotal</td></tr>
<tr><td style="color:#d7af5f;padding:4px 12px;">LOW</td><td style="color:#fff;padding:4px 12px;">$lowTotal</td></tr>
<tr style="border-top:1px solid #585858;"><td style="color:#afaf5f;padding:4px 12px;font-weight:bold;">TOTAL</td><td style="color:#fff;padding:4px 12px;font-weight:bold;">$totalThreats ($trend)</td></tr>
</table>
<p style="color:#585858;font-size:0.85em;">Generated $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC | Guerrilla v2.1.0</p>
</body></html>
"@

    # Determine providers
    $digestProviders = if ($Providers) {
        $Providers
    } elseif ($config.alerting.digest.providers) {
        @($config.alerting.digest.providers)
    } else {
        # Fall back to all enabled providers
        $ep = @()
        if ($config.alerting.providers.sendgrid.enabled)  { $ep += 'SendGrid' }
        if ($config.alerting.providers.teams.enabled)      { $ep += 'Teams' }
        if ($config.alerting.providers.slack.enabled)       { $ep += 'Slack' }
        if ($config.alerting.providers.webhook.enabled)     { $ep += 'Webhook' }
        $ep
    }

    if ($digestProviders.Count -eq 0) {
        Write-Warning 'No digest providers configured.'
        return [PSCustomObject]@{
            Provider = 'Digest'
            Success  = $false
            Message  = 'No digest providers configured'
            Error    = $null
        }
    }

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($prov in $digestProviders) {
        switch ($prov) {
            'SendGrid' {
                $sg = $config.alerting.providers.sendgrid
                if ($sg.apiKey -and $sg.fromEmail -and $sg.toEmails.Count -gt 0) {
                    $r = Send-SignalSendGrid -ApiKey $sg.apiKey -FromEmail $sg.fromEmail `
                        -ToEmails $sg.toEmails -Subject $subject -HtmlBody $htmlBody -TextBody $textBody `
                        -FromName ($sg.fromName ?? 'Guerrilla Digest')
                    $allResults.Add($r)
                }
            }
            'Teams' {
                $tm = $config.alerting.providers.teams
                if ($tm.webhookUrl) {
                    # Build a minimal threat-like object for Teams formatting
                    $digestThreat = [PSCustomObject]@{
                        Email       = 'Digest Summary'
                        ThreatLevel = if ($criticalTotal -gt 0) { 'CRITICAL' } elseif ($highTotal -gt 0) { 'HIGH' } else { 'MEDIUM' }
                        ThreatScore = $totalThreats
                        Indicators  = @("$criticalTotal critical, $highTotal high, $mediumTotal medium, $lowTotal low ($trend)")
                    }
                    $r = Send-SignalTeams -WebhookUrl $tm.webhookUrl -Subject $subject -Threats @($digestThreat)
                    $allResults.Add($r)
                }
            }
            'Slack' {
                $sl = $config.alerting.providers.slack
                if ($sl.webhookUrl) {
                    $digestThreat = [PSCustomObject]@{
                        Email       = 'Digest Summary'
                        ThreatLevel = if ($criticalTotal -gt 0) { 'CRITICAL' } elseif ($highTotal -gt 0) { 'HIGH' } else { 'MEDIUM' }
                        ThreatScore = $totalThreats
                        Indicators  = @("$criticalTotal critical, $highTotal high, $mediumTotal medium, $lowTotal low ($trend)")
                    }
                    $r = Send-SignalSlack -WebhookUrl $sl.webhookUrl -Subject $subject -Threats @($digestThreat) -TextBody $textBody
                    $allResults.Add($r)
                }
            }
            'Webhook' {
                $wh = $config.alerting.providers.webhook
                if ($wh.url) {
                    $whHeaders = @{}
                    if ($wh.headers) { foreach ($key in $wh.headers.Keys) { $whHeaders[$key] = $wh.headers[$key] } }
                    $digestPayload = [PSCustomObject]@{
                        Email       = 'Digest Summary'
                        ThreatLevel = if ($criticalTotal -gt 0) { 'CRITICAL' } elseif ($highTotal -gt 0) { 'HIGH' } else { 'MEDIUM' }
                        ThreatScore = $totalThreats
                        Indicators  = @("$criticalTotal critical, $highTotal high, $mediumTotal medium, $lowTotal low ($trend)")
                    }
                    $digestScanResult = [PSCustomObject]@{
                        PSTypeName    = 'Guerrilla.DigestResult'
                        ScanId        = "digest-$([datetime]::UtcNow.ToString('yyyyMMddHHmmss'))"
                        Timestamp     = [datetime]::UtcNow
                        CriticalCount = $criticalTotal
                        HighCount     = $highTotal
                        MediumCount   = $mediumTotal
                        LowCount      = $lowTotal
                        FlaggedUsers  = @($digestPayload)
                    }
                    $r = Send-SignalWebhook -WebhookUrl $wh.url -Threats @($digestPayload) -ScanResult $digestScanResult -Headers $whHeaders -AuthToken ($wh.authToken ?? '')
                    $allResults.Add($r)
                }
            }
        }
    }

    # Save digest history
    $digestState = @{
        lastSent      = [datetime]::UtcNow.ToString('o')
        period        = $Period
        totalThreats  = $totalThreats
        criticalCount = $criticalTotal
        highCount     = $highTotal
        mediumCount   = $mediumTotal
        lowCount      = $lowTotal
        scansIncluded = $totalScans
    }

    if (-not (Test-Path $dataDir)) { New-Item -Path $dataDir -ItemType Directory -Force | Out-Null }
    $digestState | ConvertTo-Json -Depth 5 | Set-Content -Path $digestHistoryPath -Encoding UTF8

    $anySuccess = @($allResults | Where-Object Success).Count -gt 0
    return [PSCustomObject]@{
        Provider = 'Digest'
        Success  = $anySuccess
        Message  = "Digest ($Period): $(@($allResults | Where-Object Success).Count)/$($allResults.Count) providers dispatched - $totalThreats threats ($trend)"
        Error    = if (-not $anySuccess -and $allResults.Count -gt 0) { ($allResults | Where-Object { -not $_.Success } | Select-Object -First 1).Error } else { $null }
        Details  = @($allResults)
    }
}
