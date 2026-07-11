# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalSendGrid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$FromEmail,

        [Parameter(Mandatory)]
        [string[]]$ToEmails,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$HtmlBody,

        [string]$TextBody,
        [string]$FromName = 'Guerrilla Signals'
    )

    $personalizations = @(@{
        to = @($ToEmails | ForEach-Object { @{ email = $_ } })
    })

    $content = @(@{ type = 'text/html'; value = $HtmlBody })
    if ($TextBody) {
        $content = @(@{ type = 'text/plain'; value = $TextBody }) + $content
    }

    $body = @{
        personalizations = $personalizations
        from             = @{ email = $FromEmail; name = $FromName }
        subject          = $Subject
        content          = $content
    } | ConvertTo-Json -Depth 10

    $headers = @{
        Authorization  = "Bearer $ApiKey"
        'Content-Type' = 'application/json'
    }

    try {
        $null = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://api.sendgrid.com/v3/mail/send' `
            -Method Post -Headers $headers -Body $body -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'SendGrid'
            Success  = $true
            Message  = "Email sent to $($ToEmails -join ', ')"
            Error    = $null
        }
    } catch {
        # Retry once
        Start-Sleep -Seconds 3
        try {
            $null = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://api.sendgrid.com/v3/mail/send' `
                -Method Post -Headers $headers -Body $body -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'SendGrid'
                Success  = $true
                Message  = "Email sent to $($ToEmails -join ', ') (on retry)"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'SendGrid'
                Success  = $false
                Message  = "Failed to send email"
                Error    = $_.Exception.Message
            }
        }
    }
}
