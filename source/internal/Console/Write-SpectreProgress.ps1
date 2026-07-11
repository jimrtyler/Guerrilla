# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-SpectreProgress {
    <#
    .SYNOPSIS
        Renders a themed progress bar using Spectre.Console when available, falling back to Write-ProgressLine.
    .PARAMETER Activity
        The activity description.
    .PARAMETER Status
        Current status text.
    .PARAMETER PercentComplete
        Progress percentage (0-100).
    .PARAMETER Phase
        Phase tag for fallback output (e.g., 'SCANNING', 'AUDITING').
    .PARAMETER Color
        Guerrilla color for the progress bar. Default: 'Olive'.
    .PARAMETER Complete
        Mark the progress as complete (100%).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Activity,

        [string]$Status = '',
        [int]$PercentComplete = -1,
        [string]$Phase = 'INFO',
        [string]$Color = 'Olive',
        [switch]$Complete
    )

    if ($Complete) { $PercentComplete = 100 }

    if ($script:HasSpectre -and $PercentComplete -ge 0) {
        Write-SpectreProgressEnhanced -Activity $Activity -Status $Status -PercentComplete $PercentComplete -Color $Color
    } else {
        # Use existing progress line system
        $displayText = if ($Status) { "$Activity - $Status" } else { $Activity }
        Write-ProgressLine -Phase $Phase -Message $displayText
    }
}

function Write-SpectreProgressEnhanced {
    [CmdletBinding()]
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [string]$Color = 'Olive'
    )

    $barColor = $script:SpectreColors[$Color] ?? $script:SpectreColors.Olive
    $dimColor = $script:SpectreColors.Dim

    # Build a simple inline progress bar since we're not in a progress context
    $barWidth = 30
    $filled = [Math]::Round($PercentComplete / 100 * $barWidth)
    $empty = $barWidth - $filled

    $escapedActivity = [Spectre.Console.Markup]::Escape($Activity)
    $escapedStatus = if ($Status) { [Spectre.Console.Markup]::Escape($Status) } else { '' }

    $filledBar = [string]::new([char]0x2588, $filled)
    $emptyBar = [string]::new([char]0x2591, $empty)

    $markup = "[$($barColor.ToMarkup()) bold]$escapedActivity[/] " +
              "[$($barColor.ToMarkup())]$filledBar[/]" +
              "[$($dimColor.ToMarkup())]$emptyBar[/] " +
              "[$($dimColor.ToMarkup())]${PercentComplete}%[/]"

    if ($escapedStatus) {
        $markup += " [$($dimColor.ToMarkup())]$escapedStatus[/]"
    }

    [Spectre.Console.AnsiConsole]::MarkupLine("  $markup")
}
