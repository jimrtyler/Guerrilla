# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Initialize-SpectreCapability {
    <#
    .SYNOPSIS
        Detects PwshSpectreConsole availability and caches the result.
    .DESCRIPTION
        Checks if PwshSpectreConsole is installed and importable. Sets $script:HasSpectre
        to $true if available, $false otherwise. Honors PSGUERRILLA_NO_SPECTRE env var
        to force fallback even when the module is installed.
    #>
    [CmdletBinding()]
    param()

    # Allow explicit opt-out
    if ($env:PSGUERRILLA_NO_SPECTRE) {
        $script:HasSpectre = $false
        return
    }

    # Respect NO_COLOR — Spectre output is pointless without color
    if ($env:NO_COLOR) {
        $script:HasSpectre = $false
        return
    }

    $script:HasSpectre = $false

    try {
        $available = Get-Module -ListAvailable -Name PwshSpectreConsole -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($available) {
            Import-Module PwshSpectreConsole -ErrorAction Stop -Global
            $script:HasSpectre = $true
        }
    } catch {
        Write-Verbose "PwshSpectreConsole import failed: $_"
        $script:HasSpectre = $false
    }

    # Cache guerrilla theme colors as Spectre.Console.Color objects for reuse
    if ($script:HasSpectre) {
        $script:SpectreColors = @{
            Olive      = [Spectre.Console.Color]::new(175, 175, 95)
            Amber      = [Spectre.Console.Color]::new(255, 135, 0)
            Sage       = [Spectre.Console.Color]::new(135, 175, 135)
            Parchment  = [Spectre.Console.Color]::new(255, 215, 175)
            Gold       = [Spectre.Console.Color]::new(215, 175, 95)
            DeepOrange = [Spectre.Console.Color]::new(215, 95, 0)
            DarkRed    = [Spectre.Console.Color]::new(175, 0, 0)
            Dim        = [Spectre.Console.Color]::new(88, 88, 88)
            White      = [Spectre.Console.Color]::new(255, 255, 255)
        }
    }
}
