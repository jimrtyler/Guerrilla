# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-GuerrillaGuiAsync {
    <#
    .SYNOPSIS
        Runs a scriptblock on a background runspace and posts its result back to the
        WPF UI thread via Dispatcher.
    .DESCRIPTION
        Used to drive long-running cmdlets (Invoke-Reconnaissance, Invoke-Campaign,
        etc.) without freezing the GUI. The Action runs in its own runspace with the
        PSGuerrilla module imported and any caller-supplied parameters available as
        $args. OnLog (optional) receives Verbose / Information streams; OnComplete
        gets the final return value; OnError gets the terminating error if any.

        Returns a handle the caller can hold to call Stop / IsCompleted on.

        NOTE: This is intentionally simple — no runspace pool, one runspace per call,
        and a 100ms polling loop on a DispatcherTimer to drain output streams. Good
        enough for the GUI's one-scan-at-a-time model; not appropriate for batch
        parallelism.
    .PARAMETER ModulePath
        Path to the .psd1 to Import-Module in the runspace. Required because the
        runspace starts clean (no inherited module state).
    .PARAMETER Action
        Scriptblock to execute. Use $using:variableName to capture from the caller's
        scope.
    .PARAMETER Dispatcher
        The WPF UI thread dispatcher (typically $window.Dispatcher).
    .PARAMETER OnLog
        Scriptblock invoked on the UI thread for each Verbose / Information line.
        Receives the message string as $args[0].
    .PARAMETER OnComplete
        Scriptblock invoked on the UI thread when Action returns. Receives the
        return value as $args[0].
    .PARAMETER OnError
        Scriptblock invoked on the UI thread when Action throws. Receives the
        ErrorRecord as $args[0].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ModulePath,
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)]$Dispatcher,
        # Arguments splatted positionally onto the Action scriptblock. Use this
        # instead of closure capture for anything Action needs — closures don't
        # survive the runspace boundary cleanly.
        [object[]]$Arguments = @(),
        [scriptblock]$OnLog,
        [scriptblock]$OnComplete,
        [scriptblock]$OnError
    )

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $iss.ImportPSModule([string[]]@($ModulePath))

    $ps = [PowerShell]::Create($iss)
    [void]$ps.AddScript({
        param($Action, $ArgArray)
        $VerbosePreference = 'Continue'
        try {
            & $Action @ArgArray
        } catch {
            throw
        }
    })
    [void]$ps.AddArgument($Action)
    [void]$ps.AddArgument($Arguments)

    # Capture all output streams in one buffer so the polling timer can drain them.
    # BeginInvoke's two-arg overload needs typed PSDataCollection<T>s — passing $null
    # for the input throws "Cannot find an overload" because the generic type can't
    # be inferred. Hand it an empty (completed) input collection instead.
    $inputColl  = New-Object System.Management.Automation.PSDataCollection[PSObject]
    $inputColl.Complete()
    $output     = New-Object System.Management.Automation.PSDataCollection[PSObject]
    $handle     = $ps.BeginInvoke($inputColl, $output)

    $state = [PSCustomObject]@{
        PowerShell      = $ps
        Handle          = $handle
        Output          = $output
        LastVerboseIdx  = 0
        LastInfoIdx     = 0
        LastWarnIdx     = 0
        LineBuffer      = ''
        StartTime       = [datetime]::Now
        LastOutputTime  = [datetime]::Now
        Timer           = $null
        Completed       = $false
    }

    # DispatcherTimer ticks on the UI thread — safe to mutate WPF controls from inside.
    # The handler MUST be a closure: without GetNewClosure() the tick fires after this
    # function has returned, $state/$OnLog/$OnComplete/$OnError no longer resolve, and
    # the completion callback can never run.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({
        # Drain new output into the log. Write-ProgressLine emits each progress line as
        # several `Write-Host -NoNewline` fragments carrying ANSI colour codes, so we
        # strip the escapes and reassemble fragments into whole lines before logging.
        if ($OnLog) {
            try {
                $ansi = "$([char]27)\[[0-9;]*m"

                # Verbose stream — each record is already a complete line.
                $vstream = $state.PowerShell.Streams.Verbose
                while ($state.LastVerboseIdx -lt $vstream.Count) {
                    $msg = ($vstream[$state.LastVerboseIdx].Message -replace $ansi, '').TrimEnd()
                    if ($msg) { & $OnLog $msg; $state.LastOutputTime = [datetime]::Now }
                    $state.LastVerboseIdx++
                }

                # Warning stream — surface these too (e.g. "GeoIP lookup failed").
                $wstream = $state.PowerShell.Streams.Warning
                while ($state.LastWarnIdx -lt $wstream.Count) {
                    $msg = ($wstream[$state.LastWarnIdx].Message -replace $ansi, '').TrimEnd()
                    if ($msg) { & $OnLog "WARNING: $msg"; $state.LastOutputTime = [datetime]::Now }
                    $state.LastWarnIdx++
                }

                # Information stream (Write-Host / Write-ProgressLine). Reassemble the
                # -NoNewline fragments that together form one progress line.
                $istream = $state.PowerShell.Streams.Information
                while ($state.LastInfoIdx -lt $istream.Count) {
                    $md = $istream[$state.LastInfoIdx].MessageData
                    if ($md -is [System.Management.Automation.HostInformationMessage]) {
                        $text = $md.Message; $noNewline = $md.NoNewline
                    } else {
                        $text = "$md"; $noNewline = $false
                    }
                    $state.LineBuffer += ($text -replace $ansi, '')
                    if (-not $noNewline) {
                        $line = $state.LineBuffer.TrimEnd()
                        $state.LineBuffer = ''
                        if ($line) { & $OnLog $line; $state.LastOutputTime = [datetime]::Now }
                    }
                    $state.LastInfoIdx++
                }

                # Heartbeat — long phases (e.g. AD object collection) can emit nothing
                # for tens of seconds. Reassure the user the scan is alive rather than hung.
                if (-not $state.Handle.IsCompleted) {
                    if (([datetime]::Now - $state.LastOutputTime).TotalSeconds -ge 5) {
                        $elapsed = [int]([datetime]::Now - $state.StartTime).TotalSeconds
                        & $OnLog "  ... still working (${elapsed}s elapsed)"
                        $state.LastOutputTime = [datetime]::Now
                    }
                }
            } catch {
                # Don't crash the GUI on a logging hiccup
            }
        }

        if ($state.Handle.IsCompleted -and -not $state.Completed) {
            $state.Completed = $true
            $state.Timer.Stop()
            try {
                $state.PowerShell.EndInvoke($state.Handle)
                # Results land in the explicit output collection passed to BeginInvoke —
                # with that overload EndInvoke's own return value is always empty.
                $result = @($state.Output)

                # Surface non-terminating errors in the log, but don't let them
                # discard a successful result — a single Write-Error mid-scan must
                # not make the whole run look failed.
                $errStream = $state.PowerShell.Streams.Error
                if ($errStream.Count -gt 0 -and $OnLog) {
                    foreach ($e in $errStream) {
                        try { & $OnLog "ERROR: $e" } catch { }
                    }
                }

                # A buggy callback must never escape the DispatcherTimer tick — an
                # unhandled exception here surfaces as a raw console error and can wedge
                # the window. Guard every callback invocation and downgrade failures to
                # warnings instead.
                if ($state.PowerShell.HadErrors -and $result.Count -eq 0) {
                    $firstErr = if ($errStream.Count -gt 0) { $errStream[0] } else { 'Scan failed without error detail' }
                    if ($OnError) { try { & $OnError $firstErr } catch { Write-Warning "OnError callback failed: $_" } }
                } elseif ($OnComplete) {
                    try { & $OnComplete $result } catch { Write-Warning "OnComplete callback failed: $_" }
                }
            } catch {
                if ($OnError) { try { & $OnError $_ } catch { Write-Warning "OnError callback failed: $_" } }
            } finally {
                $state.PowerShell.Dispose()
            }
        }
    }.GetNewClosure())

    $state.Timer = $timer
    $timer.Start()

    return $state
}

function Stop-GuerrillaGuiAsync {
    <#
    .SYNOPSIS
        Cancels a running async job returned by Invoke-GuerrillaGuiAsync.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    if ($State.Completed) { return }
    try {
        if ($State.Timer) { $State.Timer.Stop() }
        if ($State.PowerShell) {
            $State.PowerShell.Stop()
            $State.PowerShell.Dispose()
        }
    } catch { }
    $State.Completed = $true
}
