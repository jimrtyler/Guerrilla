# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalSyslog {
    <#
    .SYNOPSIS
        Sends threat alerts to a syslog server in CEF or LEEF format.
    .DESCRIPTION
        Formats Guerrilla threat data as CEF (Common Event Format) or LEEF (Log Event Extended Format)
        messages and sends them to a syslog server via UDP or TCP.
    .PARAMETER Server
        Syslog server hostname or IP address.
    .PARAMETER Port
        Syslog server port. Default: 514.
    .PARAMETER Protocol
        Transport protocol: UDP or TCP. Default: UDP.
    .PARAMETER Format
        Message format: CEF or LEEF. Default: CEF.
    .PARAMETER Threats
        Array of threat objects to send.
    .PARAMETER Subject
        Alert subject line for the syslog header.
    .PARAMETER Facility
        Syslog facility code (0-23). Default: 1 (user-level).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Server,

        [int]$Port = 514,

        [ValidateSet('UDP', 'TCP')]
        [string]$Protocol = 'UDP',

        [ValidateSet('CEF', 'LEEF')]
        [string]$Format = 'CEF',

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [string]$Subject = '[Guerrilla] Threat Detection',

        [ValidateRange(0, 23)]
        [int]$Facility = 1
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($threat in $Threats) {
        # Map threat level to syslog severity
        $syslogSeverity = switch ($threat.ThreatLevel) {
            'CRITICAL' { 2 }  # Critical
            'HIGH'     { 3 }  # Error
            'MEDIUM'   { 4 }  # Warning
            'LOW'      { 6 }  # Informational
            default    { 6 }
        }

        $priority = ($Facility * 8) + $syslogSeverity
        $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $hostname = [System.Net.Dns]::GetHostName()

        # Escape values destined for CEF/LEEF fields. Indicator text can carry
        # attacker-influenced strings (user agents, OAuth app names) — flatten
        # CR/LF/tab so a crafted value cannot split the syslog message or inject
        # LEEF fields (tab is the LEEF delimiter), and escape the format
        # metacharacters: backslash first, then '=' (extension values) and '|'
        # (header fields).
        $sanitize = { param($s) "$s" -replace '\\', '\\' -replace '[\r\n\t]+', ' ' -replace '=', '\=' -replace '\|', '_' }
        $email = & $sanitize ($threat.Email ?? $threat.UserPrincipalName ?? 'unknown')
        $indicators = & $sanitize ($threat.Indicators -join '; ')
        $score = [int]($threat.ThreatScore ?? 0)

        if ($Format -eq 'CEF') {
            # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            $cefSeverity = switch ($threat.ThreatLevel) {
                'CRITICAL' { 10 }
                'HIGH'     { 7 }
                'MEDIUM'   { 4 }
                'LOW'      { 1 }
                default    { 0 }
            }
            $sigId = "PSG-$($threat.ThreatLevel)"
            $name = "$($threat.ThreatLevel) threat: $email" -replace '\|', '_'
            $extension = "src=$email suser=$email cs1=$indicators cs1Label=Indicators cn1=$score cn1Label=ThreatScore"
            $message = "<$priority>$timestamp $hostname CEF:0|Guerrilla|ThreatDetection|2.1.0|$sigId|$name|$cefSeverity|$extension"
        } else {
            # LEEF:Version|Vendor|Product|Version|EventID|Extension
            $eventId = "PSG-$($threat.ThreatLevel)"
            $extension = "src=$email`tsuser=$email`tsev=$($threat.ThreatLevel)`tThreatScore=$score`tIndicators=$indicators"
            $message = "<$priority>$timestamp $hostname LEEF:2.0|Guerrilla|ThreatDetection|2.1.0|$eventId|$extension"
        }

        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($message)

            if ($Protocol -eq 'UDP') {
                $client = [System.Net.Sockets.UdpClient]::new()
                try {
                    $client.Send($bytes, $bytes.Length, $Server, $Port) | Out-Null
                } finally {
                    $client.Close()
                }
            } else {
                $client = [System.Net.Sockets.TcpClient]::new()
                try {
                    $client.Connect($Server, $Port)
                    $stream = $client.GetStream()
                    # TCP syslog: append newline as message delimiter
                    $tcpBytes = [System.Text.Encoding]::UTF8.GetBytes("$message`n")
                    $stream.Write($tcpBytes, 0, $tcpBytes.Length)
                    $stream.Flush()
                } finally {
                    $client.Close()
                }
            }

            $results.Add([PSCustomObject]@{
                Provider = 'Syslog'
                Success  = $true
                Message  = "Syslog $Format/$Protocol sent to ${Server}:${Port} for $email"
                Error    = $null
            })
        } catch {
            $results.Add([PSCustomObject]@{
                Provider = 'Syslog'
                Success  = $false
                Message  = "Failed to send syslog to ${Server}:${Port} for $email"
                Error    = $_.Exception.Message
            })
        }
    }

    # Return aggregate result
    $anySuccess = @($results | Where-Object Success).Count -gt 0
    return [PSCustomObject]@{
        Provider = 'Syslog'
        Success  = $anySuccess
        Message  = "Syslog: $(@($results | Where-Object Success).Count)/$($results.Count) messages sent via $Format/$Protocol to ${Server}:${Port}"
        Error    = if (-not $anySuccess) { ($results | Where-Object { -not $_.Success } | Select-Object -First 1).Error } else { $null }
        Details  = @($results)
    }
}
