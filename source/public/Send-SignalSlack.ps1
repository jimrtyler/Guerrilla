# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalSlack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebhookUrl,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [string]$TextBody
    )

    # Build Slack Block Kit payload
    $blocks = @(
        @{
            type = 'header'
            text = @{ type = 'plain_text'; text = $Subject; emoji = $true }
        }
        @{ type = 'divider' }
    )

    foreach ($t in ($Threats | Sort-Object -Property ThreatScore -Descending | Select-Object -First 10)) {
        $levelEmoji = switch ($t.ThreatLevel) {
            'CRITICAL' { ':red_circle:' }
            'HIGH'     { ':large_orange_circle:' }
            'MEDIUM'   { ':large_yellow_circle:' }
            default    { ':white_circle:' }
        }

        $indicators = if ($t.Indicators.Count -gt 0) {
            ($t.Indicators | Select-Object -First 3 | ForEach-Object { "  - $_" }) -join "`n"
        } else { '  - No specific indicators' }

        $blocks += @{
            type = 'section'
            text = @{
                type = 'mrkdwn'
                text = "$levelEmoji *$($t.Email)* — $($t.ThreatLevel) (Score: $($t.ThreatScore.ToString('N0')))`n$indicators"
            }
        }
    }

    if ($Threats.Count -gt 10) {
        $blocks += @{
            type = 'context'
            elements = @(@{ type = 'mrkdwn'; text = "_...and $($Threats.Count - 10) more threats_" })
        }
    }

    $body = @{
        blocks = $blocks
        text   = $TextBody ?? $Subject  # Fallback for notifications
    } | ConvertTo-Json -Depth 20 -Compress

    try {
        Invoke-RestMethod -TimeoutSec 30 -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'Slack'
            Success  = $true
            Message  = "Slack webhook sent ($($Threats.Count) threat(s))"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            Invoke-RestMethod -TimeoutSec 30 -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'Slack'
                Success  = $true
                Message  = "Slack webhook sent on retry ($($Threats.Count) threat(s))"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Slack'
                Success  = $false
                Message  = 'Failed to send Slack webhook'
                Error    = $_.Exception.Message
            }
        }
    }
}
