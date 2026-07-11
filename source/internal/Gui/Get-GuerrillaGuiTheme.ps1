# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaGuiTheme {
    <#
    .SYNOPSIS
        Returns WPF Color + SolidColorBrush hashtables for the GUI, derived from the
        same RGB palette used by the existing HTML reports and console output.
    .DESCRIPTION
        The module-level $script:Palette stores PSStyle ANSI escape sequences (strings)
        which can't be bound to WPF brushes directly. This helper exposes the equivalent
        [System.Windows.Media.Color] + SolidColorBrush instances for XAML and code-behind
        to consume. Extra "Background", "Panel", "Border" entries fill in the surface
        colors the original console palette didn't need but a window UI does.
    #>
    [CmdletBinding()]
    param()

    Add-Type -AssemblyName PresentationCore -ErrorAction SilentlyContinue

    # Light, modern, clean enterprise palette. Keys keep their original names so the
    # XAML code-behind (status lines, banners, dynamically-built checkboxes) keeps
    # working unchanged — only the underlying hex moved from the dark scheme to light.
    $rgb = @{
        Amber      = @(0x25, 0x63, 0xEB)  # accent, primary buttons (now blue)
        Khaki      = @(0x64, 0x74, 0x8B)  # secondary text
        Gray       = @(0x94, 0xA3, 0xB8)  # muted / disabled text
        Sage       = @(0x16, 0xA3, 0x4A)  # success / PASS
        Parchment  = @(0x1F, 0x29, 0x33)  # primary text on light surfaces
        Gold       = @(0xD9, 0x77, 0x06)  # warnings / highlights
        Red        = @(0xDC, 0x26, 0x26)  # failures / critical
        # Surface colors (not in the console palette — needed for a window UI)
        Background = @(0xF4, 0xF6, 0xF8)  # app / window background
        Panel      = @(0xFF, 0xFF, 0xFF)  # nav rail / card surfaces
        Border     = @(0xE2, 0xE8, 0xF0)  # subtle separators
        Hover      = @(0xED, 0xF1, 0xF6)  # button hover / raised surface
    }

    $colors  = @{}
    $brushes = @{}
    foreach ($key in $rgb.Keys) {
        $c = [System.Windows.Media.Color]::FromRgb($rgb[$key][0], $rgb[$key][1], $rgb[$key][2])
        $colors[$key]  = $c
        $brushes[$key] = [System.Windows.Media.SolidColorBrush]::new($c)
        $brushes[$key].Freeze()
    }

    return @{
        Colors  = $colors
        Brushes = $brushes
    }
}
