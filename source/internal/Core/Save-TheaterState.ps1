# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Save-TheaterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'ad', 'm365', 'workspace')]
        [string]$Theater,

        [Parameter(Mandatory)]
        [hashtable]$State,

        [string]$ConfigPath
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $stateDir = Split-Path $cfgPath -Parent
    $statePath = Join-Path $stateDir "$Theater-state.json"

    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }

    # Trim scan history to max 100 entries
    if ($State.scanHistory -and $State.scanHistory.Count -gt 100) {
        $State.scanHistory = @($State.scanHistory | Select-Object -Last 100)
    }

    try {
        # Atomic write: stage to a sibling temp file, then rename — same pattern as
        # Save-OperationState. Avoids leaving a half-written state file on disk if
        # the process is killed mid-serialization.
        $tempPath = "$statePath.tmp"
        $State | ConvertTo-Json -Depth 10 | Set-Content -Path $tempPath -Encoding UTF8 -ErrorAction Stop
        Move-Item -Path $tempPath -Destination $statePath -Force -ErrorAction Stop
        Write-Verbose "$Theater state saved to $statePath"
    } catch {
        Write-Warning "Failed to save $Theater state file: $_"
        if ($tempPath -and (Test-Path $tempPath)) {
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
