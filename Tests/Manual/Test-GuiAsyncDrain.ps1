# Manual headless test for Invoke-GuerrillaGuiAsync stream draining.
# Drives the async helper through a real WPF Dispatcher with an action that emits
# the same fragmented ANSI Write-Host progress lines, verbose, warnings, a silent
# stretch (heartbeat), and a final result — exactly what a real scan produces.
# Run:  pwsh -NoProfile -STA -File Tests\Manual\Test-GuiAsyncDrain.ps1
[CmdletBinding()]
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot '..\..\PSGuerrilla.psd1')
)

Add-Type -AssemblyName WindowsBase
$ModulePath = (Resolve-Path $ModulePath).Path
Import-Module $ModulePath -Force

$script:logs = [System.Collections.Generic.List[string]]::new()
$script:done = '<unset>'

# An action that mimics Write-ProgressLine output: several Write-Host -NoNewline
# fragments with ANSI codes that should reassemble into one clean log line.
$action = {
    $e = [char]27
    Write-Host "  $e[38;5;240m[1750 UTC] $e[0m" -NoNewline
    Write-Host "$e[38;5;143mRECON     $e[0m" -NoNewline
    Write-Host "$e[38;5;240m > $e[0m" -NoNewline
    Write-Host "$e[38;5;143mConnecting to Active Directory$e[0m"
    Write-Verbose 'collecting users'
    Write-Warning 'GeoIP lookup failed'
    Start-Sleep -Seconds 7    # silent stretch -> heartbeat should fire
    Write-Host "$e[38;5;143mEvaluating security checks$e[0m"
    'SCAN-RESULT'
}

# Build the callbacks HERE, in the test's own script scope, so they resolve
# $script:logs / $script:done when the DispatcherTimer invokes them later. Pass
# them as parameters into the module-scope block (Invoke-GuerrillaGuiAsync is a
# private function, only reachable via & (Get-Module ...)).
$onLog      = { param($m) $script:logs.Add($m) }
$onComplete = { param($r) $script:done = "OK: $r"; [System.Windows.Threading.Dispatcher]::ExitAllFrames() }
$onError    = { param($e) $script:done = "ERR: $e"; [System.Windows.Threading.Dispatcher]::ExitAllFrames() }

& (Get-Module PSGuerrilla) {
    param($ModulePath, $Action, $Dispatcher, $OnLog, $OnComplete, $OnError)
    Invoke-GuerrillaGuiAsync `
        -ModulePath  $ModulePath `
        -Action      $Action `
        -Dispatcher  $Dispatcher `
        -OnLog       $OnLog `
        -OnComplete  $OnComplete `
        -OnError     $OnError
} $ModulePath $action ([System.Windows.Threading.Dispatcher]::CurrentDispatcher) $onLog $onComplete $onError | Out-Null

# Safety net so the test can never hang CI.
$safety = New-Object System.Windows.Threading.DispatcherTimer
$safety.Interval = [TimeSpan]::FromSeconds(45)
$safety.Add_Tick({ $script:done = 'TIMEOUT'; [System.Windows.Threading.Dispatcher]::ExitAllFrames() })
$safety.Start()
[System.Windows.Threading.Dispatcher]::Run()

Write-Host ''
Write-Host "RESULT: $script:done"
Write-Host '--- LOG PANE (as the GUI renders it) ---'
$script:logs | ForEach-Object { Write-Host "  | $_" }

# Assertions
$ok = $true
if ($script:done -ne 'OK: SCAN-RESULT') { Write-Host "FAIL: expected completion, got '$script:done'"; $ok = $false }
if (-not ($script:logs | Where-Object { $_ -match 'Connecting to Active Directory' })) { Write-Host 'FAIL: reassembled progress line missing'; $ok = $false }
if ($script:logs | Where-Object { $_ -match "$([char]27)\[" }) { Write-Host 'FAIL: ANSI codes leaked into log'; $ok = $false }
if (-not ($script:logs | Where-Object { $_ -match 'WARNING: GeoIP' })) { Write-Host 'FAIL: warning not surfaced'; $ok = $false }
if (-not ($script:logs | Where-Object { $_ -match 'still working' })) { Write-Host 'FAIL: heartbeat missing'; $ok = $false }
Write-Host ''
Write-Host $(if ($ok) { 'ALL CHECKS PASSED' } else { 'CHECKS FAILED' })
exit $(if ($ok) { 0 } else { 1 })
