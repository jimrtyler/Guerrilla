# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Show-Guerrilla {
    <#
    .SYNOPSIS
        Opens the Guerrilla operations GUI — a WPF window for managing credentials,
        running scans, viewing reports, and configuring continuous monitoring.

    .DESCRIPTION
        Show-Guerrilla wraps the most common operational paths in a single tabbed
        Windows GUI:

          * Operations — run any theater's scan with category selection, live log,
            and automatic report open on completion.
          * Safehouse  — list, remove, rotate, and test stored credentials. Export
            metadata for documentation.
          * Patrol     — view and manage scheduled-task patrols (continuous
            monitoring).
          * Signals    — manage alert providers (Teams, Slack, webhook, PagerDuty,
            Pushover, email, SMS, Syslog, Event Log) and global alerting settings;
            send a synthetic test alert through any provider.
          * Reports    — browse HTML reports, open in browser, convert to PDF.
          * Settings   — edit runtime config (profile, alert level, output dir).
          * Inspector  — browse and read the source of every scan, check, and helper
            function in the module, filtered by area or searched by name.
          * Branding   — white-label report fields (firm, logo, consultant, client,
            confidentiality). The Guerrilla / Jim Tyler footer attribution is kept.

        The GUI is a wrapper around the existing public cmdlets — every action it
        takes is the equivalent of running Set-Safehouse / Invoke-Reconnaissance /
        Register-Patrol / etc. from a prompt. The CLI continues to work and stays
        the source of truth for anything the GUI doesn't yet cover.

        Windows only. The CLI cmdlets remain cross-platform.

    .PARAMETER VaultName
        SecretManagement vault name. Default: Guerrilla.

    .PARAMETER ConfigPath
        Path to the runtime config.json. Default: per-user data dir + /Guerrilla/config.json.
        Alias: RuntimeConfig.

    .PARAMETER StartOn
        Which tab to open on launch. One of: Operations, Safehouse, Patrol, Signals,
        Reports, Settings, Source, Branding. Default: Operations.

    .PARAMETER KeepConsole
        Keep the host console visible; by default it is hidden while the GUI is open
        and restored on close.

    .EXAMPLE
        Show-Guerrilla
        # Opens the GUI on the Operations tab against the default vault.

    .EXAMPLE
        Show-Guerrilla -StartOn Reports
        # Opens directly to the Reports browser.

    .EXAMPLE
        Show-Guerrilla -VaultName 'Guerrilla-DR'
        # Opens against a non-default vault (useful for multi-tenant or DR setups).
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'Guerrilla',

        [Alias('RuntimeConfig')]
        [string]$ConfigPath,

        [ValidateSet('Operations', 'Safehouse', 'Patrol', 'Signals', 'Reports', 'Settings', 'Source', 'Branding')]
        [string]$StartOn = 'Operations',

        [switch]$KeepConsole
    )

    # Windows-only guard. WPF doesn't exist on macOS/Linux — point users at the CLI.
    $onWindows = if (Test-Path variable:IsWindows) { $IsWindows } else { $true }
    if (-not $onWindows) {
        throw 'Show-Guerrilla requires Windows (WPF). On macOS/Linux, use the CLI cmdlets: Set-Safehouse, Invoke-Reconnaissance, Invoke-Fortification, Invoke-Infiltration, Invoke-Campaign, Register-Patrol.'
    }

    # WPF needs a single-threaded apartment; without this guard ShowDialog fails
    # with an opaque InvalidOperationException under pwsh -MTA.
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'Show-Guerrilla requires an STA thread (WPF). Start PowerShell without -MTA — pwsh defaults to STA on Windows — and retry.'
    }

    # The runspace inside Invoke-GuerrillaGuiAsync needs to know where to import
    # Guerrilla from. Resolve the .psd1 next to this loaded module.
    $manifestPath = $null
    $loadedModule = Get-Module -Name Guerrilla -ErrorAction SilentlyContinue
    if ($loadedModule -and $loadedModule.Path) {
        $manifestPath = if ($loadedModule.Path -like '*.psd1') {
            $loadedModule.Path
        } else {
            Join-Path (Split-Path -Parent $loadedModule.Path) 'Guerrilla.psd1'
        }
    }
    if (-not $manifestPath -or -not (Test-Path $manifestPath)) {
        # Fallback: look two levels up from this script (Public\Show-Guerrilla.ps1 -> module root)
        $candidate = Resolve-Path (Join-Path $PSScriptRoot '..\Guerrilla.psd1') -ErrorAction SilentlyContinue
        if ($candidate) { $manifestPath = $candidate.Path }
    }
    if (-not $manifestPath -or -not (Test-Path $manifestPath)) {
        throw "Could not resolve the Guerrilla manifest path. The GUI's background runspace needs it to import the module. Try Import-Module Guerrilla -Force then retry."
    }

    # Hide the host PowerShell console while the GUI is open so the experience reads
    # as a standalone desktop app. Restore it on close (try/finally) so launching from
    # an interactive prompt leaves the console exactly as it was found. A no-console
    # host (e.g. some IDE/runspace launches) returns IntPtr.Zero — skip gracefully.
    Add-Type -Name NativeConsole -Namespace PSG -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
"@ -ErrorAction SilentlyContinue

    $consoleHandle = [PSG.NativeConsole]::GetConsoleWindow()
    if (-not $KeepConsole -and $consoleHandle -ne [IntPtr]::Zero) {
        [void][PSG.NativeConsole]::ShowWindow($consoleHandle, 0)  # 0 = SW_HIDE
    }

    try {
        Show-GuerrillaWindow `
            -VaultName  $VaultName `
            -ConfigPath $ConfigPath `
            -StartOn    $StartOn `
            -ModulePath $manifestPath
    } finally {
        if (-not $KeepConsole -and $consoleHandle -ne [IntPtr]::Zero) {
            [void][PSG.NativeConsole]::ShowWindow($consoleHandle, 5)  # 5 = SW_SHOW
        }
    }
}
