# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalTeams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebhookUrl,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [string]$ScanSummary
    )

    # Build Adaptive Card payload
    $facts = foreach ($t in ($Threats | Sort-Object -Property ThreatScore -Descending | Select-Object -First 10)) {
        @{
            title = $t.Email
            value = "$($t.ThreatLevel) (Score: $($t.ThreatScore.ToString('N0')))"
        }
    }

    $body = @{
        type = 'message'
        attachments = @(
            @{
                contentType = 'application/vnd.microsoft.card.adaptive'
                contentUrl  = $null
                content     = @{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type      = 'AdaptiveCard'
                    version   = '1.4'
                    body      = @(
                        @{
                            type   = 'TextBlock'
                            text   = $Subject
                            weight = 'Bolder'
                            size   = 'Medium'
                            color  = 'Attention'
                        }
                        @{
                            type = 'FactSet'
                            facts = $facts
                        }
                    )
                }
            }
        )
    } | ConvertTo-Json -Depth 20 -Compress

    try {
        Invoke-RestMethod -TimeoutSec 30 -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'Teams'
            Success  = $true
            Message  = "Teams webhook sent ($($Threats.Count) threat(s))"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            Invoke-RestMethod -TimeoutSec 30 -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'Teams'
                Success  = $true
                Message  = "Teams webhook sent on retry ($($Threats.Count) threat(s))"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Teams'
                Success  = $false
                Message  = 'Failed to send Teams webhook'
                Error    = $_.Exception.Message
            }
        }
    }
}
