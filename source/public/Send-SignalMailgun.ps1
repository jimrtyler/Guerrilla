# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalMailgun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$FromEmail,

        [Parameter(Mandatory)]
        [string[]]$ToEmails,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$HtmlBody,

        [string]$TextBody
    )

    $uri = "https://api.mailgun.net/v3/$Domain/messages"
    $credential = [System.Management.Automation.PSCredential]::new(
        'api',
        ($ApiKey | ConvertTo-SecureString -AsPlainText -Force)
    )

    $form = @{
        from    = $FromEmail
        to      = $ToEmails -join ', '
        subject = $Subject
        html    = $HtmlBody
    }
    if ($TextBody) { $form['text'] = $TextBody }

    try {
        $response = Invoke-RestMethod -TimeoutSec 30 -Uri $uri -Method Post `
            -Authentication Basic -Credential $credential `
            -Form $form -ErrorAction Stop

        return [PSCustomObject]@{
            Provider = 'Mailgun'
            Success  = $true
            Message  = "Email sent: $($response.id ?? 'OK')"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            $response = Invoke-RestMethod -TimeoutSec 30 -Uri $uri -Method Post `
                -Authentication Basic -Credential $credential `
                -Form $form -ErrorAction Stop

            return [PSCustomObject]@{
                Provider = 'Mailgun'
                Success  = $true
                Message  = "Email sent on retry: $($response.id ?? 'OK')"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Mailgun'
                Success  = $false
                Message  = 'Failed to send email'
                Error    = $_.Exception.Message
            }
        }
    }
}
