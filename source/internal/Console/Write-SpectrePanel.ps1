# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-SpectrePanel {
    <#
    .SYNOPSIS
        Renders a themed panel using Spectre.Console when available, falling back to box-drawing characters.
    .PARAMETER Content
        The text content inside the panel.
    .PARAMETER Title
        Optional panel title text.
    .PARAMETER BorderColor
        Guerrilla color name for the border. Default: 'Olive'.
    .PARAMETER ContentColor
        Guerrilla color name for the content text. Default: 'Parchment'.
    .PARAMETER Width
        Panel width. Default: 64.
    .PARAMETER Expand
        Expand panel to fill available width.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string[]]$Content,

        [string]$Title,
        [string]$BorderColor = 'Olive',
        [string]$ContentColor = 'Parchment',
        [int]$Width = 64,
        [switch]$Expand
    )

    if ($script:HasSpectre) {
        Write-SpectrePanelEnhanced @PSBoundParameters
    } else {
        Write-SpectrePanelFallback @PSBoundParameters
    }
}

function Write-SpectrePanelEnhanced {
    [CmdletBinding()]
    param(
        [string[]]$Content,
        [string]$Title,
        [string]$BorderColor = 'Olive',
        [string]$ContentColor = 'Parchment',
        [int]$Width = 64,
        [switch]$Expand
    )

    $bColor = $script:SpectreColors[$BorderColor] ?? $script:SpectreColors.Olive
    $cColor = $script:SpectreColors[$ContentColor] ?? $script:SpectreColors.Parchment

    $contentText = ($Content | ForEach-Object { [Spectre.Console.Markup]::Escape($_) }) -join "`n"
    $markup = [Spectre.Console.Markup]::new("[$($cColor.ToMarkup())]$contentText[/]")

    $panel = [Spectre.Console.Panel]::new($markup)
    $panel.Border = [Spectre.Console.BoxBorder]::Double
    $panel.BorderStyle = [Spectre.Console.Style]::new($bColor)
    $panel.Padding = [Spectre.Console.Padding]::new(2, 0, 2, 0)

    if ($Title) {
        $escapedTitle = [Spectre.Console.Markup]::Escape($Title)
        $panel.Header = [Spectre.Console.PanelHeader]::new("[$($cColor.ToMarkup()) bold]$escapedTitle[/]")
        $panel.Header.Alignment = [Spectre.Console.Justify]::Center
    }

    if ($Expand) {
        $panel.Expand = $true
    } elseif ($Width -gt 0) {
        $panel.Width = $Width
    }

    [Spectre.Console.AnsiConsole]::Write($panel)
}

function Write-SpectrePanelFallback {
    [CmdletBinding()]
    param(
        [string[]]$Content,
        [string]$Title,
        [string]$BorderColor = 'Olive',
        [string]$ContentColor = 'Parchment',
        [int]$Width = 64,
        [switch]$Expand
    )

    $innerWidth = $Width - 4  # account for border + padding
    $borderChar = [char]0x2550  # ═

    # Top border
    Write-GuerrillaText "  $([char]0x2554)$([string]::new($borderChar, $innerWidth + 2))$([char]0x2557)" -Color $BorderColor

    # Title line if provided
    if ($Title) {
        $titlePad = $innerWidth - $Title.Length
        $leftPad = [Math]::Floor($titlePad / 2)
        $rightPad = $titlePad - $leftPad
        Write-GuerrillaText "  $([char]0x2551)" -Color $BorderColor -NoNewline
        Write-GuerrillaText "$(' ' * ($leftPad + 1))$Title$(' ' * ($rightPad + 1))" -Color $ContentColor -NoNewline
        Write-GuerrillaText "$([char]0x2551)" -Color $BorderColor
    }

    # Content lines
    foreach ($line in $Content) {
        $displayLine = if ($line.Length -gt $innerWidth) { $line.Substring(0, $innerWidth - 3) + '...' } else { $line }
        $pad = $innerWidth - $displayLine.Length
        Write-GuerrillaText "  $([char]0x2551) " -Color $BorderColor -NoNewline
        Write-GuerrillaText "$displayLine$(' ' * $pad) " -Color $ContentColor -NoNewline
        Write-GuerrillaText "$([char]0x2551)" -Color $BorderColor
    }

    # Bottom border
    Write-GuerrillaText "  $([char]0x255A)$([string]::new($borderChar, $innerWidth + 2))$([char]0x255D)" -Color $BorderColor
}
