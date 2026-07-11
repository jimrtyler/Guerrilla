# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-SpectreBarChart {
    <#
    .SYNOPSIS
        Renders a themed bar chart using Spectre.Console when available, falling back to block characters.
    .PARAMETER Items
        Array of hashtables: @{ Label = 'Name'; Value = 42; Color = 'Olive' }
    .PARAMETER Title
        Optional chart title.
    .PARAMETER MaxBarWidth
        Maximum width of bars in fallback mode. Default: 30.
    .PARAMETER ShowValues
        Show numeric values next to labels. Default: $true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Items,

        [string]$Title,
        [int]$MaxBarWidth = 30,
        [bool]$ShowValues = $true
    )

    # Filter to items with values > 0
    $activeItems = @($Items | Where-Object { $_.Value -gt 0 })
    if ($activeItems.Count -eq 0) { return }

    if ($script:HasSpectre) {
        # Fall back to the text renderer if the Spectre call path fails (e.g. a future
        # Spectre.Console version moves/renames a method) rather than spamming errors.
        try {
            Write-SpectreBarChartEnhanced -Items $activeItems -Title $Title
        } catch {
            Write-Verbose "Spectre bar chart failed, using text fallback: $_"
            Write-SpectreBarChartFallback -Items $activeItems -Title $Title -MaxBarWidth $MaxBarWidth -ShowValues $ShowValues
        }
    } else {
        Write-SpectreBarChartFallback -Items $activeItems -Title $Title -MaxBarWidth $MaxBarWidth -ShowValues $ShowValues
    }
}

function Write-SpectreBarChartEnhanced {
    [CmdletBinding()]
    param(
        [hashtable[]]$Items,
        [string]$Title
    )

    $chart = [Spectre.Console.BarChart]::new()

    if ($Title) {
        $chart.Label = "[bold $($script:SpectreColors.Parchment.ToMarkup())]$([Spectre.Console.Markup]::Escape($Title))[/]"
    }

    $chart.Width = 60

    foreach ($item in $Items) {
        $color = $script:SpectreColors[$item.Color] ?? $script:SpectreColors.Olive
        $label = [Spectre.Console.Markup]::Escape($item.Label)
        # AddItem is a C# extension method — PowerShell can't call it as an instance
        # method ($chart.AddItem(...) throws "does not contain a method named 'AddItem'"),
        # so invoke it on the static extension class.
        [void][Spectre.Console.BarChartExtensions]::AddItem($chart, $label, [double]$item.Value, $color)
    }

    [Spectre.Console.AnsiConsole]::Write($chart)
}

function Write-SpectreBarChartFallback {
    [CmdletBinding()]
    param(
        [hashtable[]]$Items,
        [string]$Title,
        [int]$MaxBarWidth = 30,
        [bool]$ShowValues = $true
    )

    if ($Title) {
        Write-GuerrillaText "  $Title" -Color Parchment
    }

    $maxValue = ($Items | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
    $maxValue = [Math]::Max(1, $maxValue)

    foreach ($item in $Items) {
        $barLen = [Math]::Max(1, [Math]::Round($item.Value / $maxValue * $MaxBarWidth))
        $bar = [string]::new([char]0x2588, $barLen)
        $color = $item.Color ?? 'Olive'

        Write-GuerrillaText ('  {0,-12}' -f $item.Label) -Color $color -NoNewline
        if ($ShowValues) {
            Write-GuerrillaText ('{0,4}' -f $item.Value) -Color White -NoNewline
            Write-GuerrillaText "  $bar" -Color $color
        } else {
            Write-GuerrillaText "  $bar" -Color $color
        }
    }
}
