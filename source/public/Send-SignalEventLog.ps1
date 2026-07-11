# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EventLogSourceExists {
    <#
    .SYNOPSIS
        Wrapper for [System.Diagnostics.EventLog]::SourceExists() to enable mocking in tests.
    #>
    [CmdletBinding()]
    param([string]$Source)
    [System.Diagnostics.EventLog]::SourceExists($Source)
}

function Register-EventLogSource {
    <#
    .SYNOPSIS
        Wrapper for [System.Diagnostics.EventLog]::CreateEventSource() to enable mocking in tests.
    #>
    [CmdletBinding()]
    param([string]$Source, [string]$LogName)
    [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
}

function Send-SignalEventLog {
    <#
    .SYNOPSIS
        Writes threat alerts to the Windows Event Log.
    .DESCRIPTION
        Creates Guerrilla events in the Windows Application event log. Requires the event
        source to be registered (needs admin elevation for first-time setup). Gracefully
        skips if not elevated and source doesn't exist.
    .PARAMETER Threats
        Array of threat objects to write as events.
    .PARAMETER Subject
        Alert subject line used in the event message.
    .PARAMETER Source
        Event log source name. Default: 'Guerrilla'.
    .PARAMETER LogName
        Event log name. Default: 'Application'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [string]$Subject = '[Guerrilla] Threat Detection',

        [string]$Source = 'Guerrilla',
        [string]$LogName = 'Application'
    )

    # Event IDs: 1000=CRITICAL, 1001=HIGH, 1002=MEDIUM, 1003=LOW, 1100=SCAN_COMPLETE
    $eventIdMap = @{
        'CRITICAL' = 1000
        'HIGH'     = 1001
        'MEDIUM'   = 1002
        'LOW'      = 1003
    }

    $entryTypeMap = @{
        'CRITICAL' = 'Error'
        'HIGH'     = 'Error'
        'MEDIUM'   = 'Warning'
        'LOW'      = 'Information'
    }

    # Ensure event source exists
    $sourceExists = $false
    try {
        $sourceExists = Test-EventLogSourceExists -Source $Source
    } catch {
        # SourceExists can throw if not elevated
        Write-Verbose "Cannot check event source (may need elevation): $_"
    }

    if (-not $sourceExists) {
        try {
            Register-EventLogSource -Source $Source -LogName $LogName
            $sourceExists = $true
            Write-Verbose "Created event log source '$Source' in '$LogName'"
        } catch {
            Write-Warning "Cannot create event log source '$Source'. Run as Administrator once to register, or use a different alert provider."
            return [PSCustomObject]@{
                Provider = 'EventLog'
                Success  = $false
                Message  = 'Event log source not registered (requires elevation)'
                Error    = $_.Exception.Message
            }
        }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($threat in $Threats) {
        $level = $threat.ThreatLevel ?? 'LOW'
        $eventId = $eventIdMap[$level] ?? 1003
        $entryType = $entryTypeMap[$level] ?? 'Information'

        $email = $threat.Email ?? $threat.UserPrincipalName ?? 'unknown'
        $indicators = ($threat.Indicators -join "`r`n  - ")
        $score = [int]($threat.ThreatScore ?? 0)

        $message = @"
$Subject

Identity: $email
Threat Level: $level
Threat Score: $score
Indicators:
  - $indicators

Source: Guerrilla v2.1.0
Timestamp: $([datetime]::UtcNow.ToString('o'))
"@

        try {
            Write-EventLog -LogName $LogName -Source $Source -EventId $eventId `
                -EntryType $entryType -Message $message -ErrorAction Stop

            $results.Add([PSCustomObject]@{
                Provider = 'EventLog'
                Success  = $true
                Message  = "Event $eventId written for $email ($level)"
                Error    = $null
            })
        } catch {
            $results.Add([PSCustomObject]@{
                Provider = 'EventLog'
                Success  = $false
                Message  = "Failed to write event for $email"
                Error    = $_.Exception.Message
            })
        }
    }

    $anySuccess = @($results | Where-Object Success).Count -gt 0
    return [PSCustomObject]@{
        Provider = 'EventLog'
        Success  = $anySuccess
        Message  = "EventLog: $(@($results | Where-Object Success).Count)/$($results.Count) events written"
        Error    = if (-not $anySuccess) { ($results | Where-Object { -not $_.Success } | Select-Object -First 1).Error } else { $null }
        Details  = @($results)
    }
}
