# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-SpectreTable {
    <#
    .SYNOPSIS
        Renders a themed table using Spectre.Console when available, falling back to box-drawing characters.
    .PARAMETER Title
        Optional table title.
    .PARAMETER Columns
        Array of column definition hashtables: @{ Name = 'Col'; Color = 'Olive'; Alignment = 'Left' }
    .PARAMETER Rows
        Array of row arrays. Each row is an array of cell values (strings).
    .PARAMETER RowColors
        Optional array of guerrilla color names, one per row. Colors the entire row.
    .PARAMETER BorderColor
        Guerrilla color name for the table border. Default: 'Dim'.
    .PARAMETER HideBorder
        Suppress the table border entirely.
    #>
    [CmdletBinding()]
    param(
        [string]$Title,

        [Parameter(Mandatory)]
        [hashtable[]]$Columns,

        [Parameter(Mandatory)]
        [array[]]$Rows,

        [string[]]$RowColors,
        [string]$BorderColor = 'Dim',
        [switch]$HideBorder
    )

    if ($script:HasSpectre) {
        # Fall back to the box-drawing renderer if the Spectre call path fails (e.g. a
        # future Spectre.Console version moves/renames a method) instead of spamming errors.
        try {
            Write-SpectreTableEnhanced @PSBoundParameters
        } catch {
            Write-Verbose "Spectre table failed, using text fallback: $_"
            Write-SpectreTableFallback @PSBoundParameters
        }
    } else {
        Write-SpectreTableFallback @PSBoundParameters
    }
}

function Write-SpectreTableEnhanced {
    [CmdletBinding()]
    param(
        [string]$Title,
        [hashtable[]]$Columns,
        [array[]]$Rows,
        [string[]]$RowColors,
        [string]$BorderColor = 'Dim',
        [switch]$HideBorder
    )

    $table = [Spectre.Console.Table]::new()

    if ($HideBorder) {
        $table.Border = [Spectre.Console.TableBorder]::None
    } else {
        $table.Border = [Spectre.Console.TableBorder]::Rounded
        # BorderColor is an extension method that isn't callable from PowerShell (and isn't
        # in TableExtensions in current Spectre.Console) — set the BorderStyle directly.
        $table.BorderStyle = [Spectre.Console.Style]::new($script:SpectreColors[$BorderColor] ?? $script:SpectreColors.Dim)
    }

    if ($Title) {
        $titleMarkup = "[bold $($script:SpectreColors.Olive.ToMarkup())]$([Spectre.Console.Markup]::Escape($Title))[/]"
        $table.Title = [Spectre.Console.TableTitle]::new($titleMarkup)
    }

    foreach ($col in $Columns) {
        $colColor = $script:SpectreColors[$col.Color] ?? $script:SpectreColors.Olive
        $colMarkup = "[$($colColor.ToMarkup()) bold]$([Spectre.Console.Markup]::Escape($col.Name))[/]"
        $tableCol = [Spectre.Console.TableColumn]::new($colMarkup)

        if ($col.Alignment -eq 'Right') {
            $tableCol.Alignment = [Spectre.Console.Justify]::Right
        } elseif ($col.Alignment -eq 'Center') {
            $tableCol.Alignment = [Spectre.Console.Justify]::Center
        }

        $table.AddColumn($tableCol)
    }

    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        $rowColor = if ($RowColors -and $i -lt $RowColors.Count -and $RowColors[$i]) {
            $script:SpectreColors[$RowColors[$i]] ?? $script:SpectreColors.Parchment
        } else {
            $script:SpectreColors.Parchment
        }

        $cells = @()
        for ($j = 0; $j -lt $row.Count; $j++) {
            $cellText = [Spectre.Console.Markup]::Escape([string]$row[$j])
            # Use column color for first column, row color for data
            if ($j -eq 0) {
                $colColor = $script:SpectreColors[$Columns[$j].Color] ?? $script:SpectreColors.Olive
                $cells += [Spectre.Console.Markup]::new("[$($colColor.ToMarkup())]$cellText[/]")
            } else {
                $cells += [Spectre.Console.Markup]::new("[$($rowColor.ToMarkup())]$cellText[/]")
            }
        }

        # AddRow is a C# extension method — call it on the static extension class and pass
        # the cells as a typed IRenderable[] so the overload resolves.
        [void][Spectre.Console.TableExtensions]::AddRow($table, [Spectre.Console.Rendering.IRenderable[]]$cells)
    }

    [Spectre.Console.AnsiConsole]::Write($table)
}

function Write-SpectreTableFallback {
    [CmdletBinding()]
    param(
        [string]$Title,
        [hashtable[]]$Columns,
        [array[]]$Rows,
        [string[]]$RowColors,
        [string]$BorderColor = 'Dim',
        [switch]$HideBorder
    )

    # Calculate column widths
    $widths = @()
    for ($j = 0; $j -lt $Columns.Count; $j++) {
        $maxWidth = $Columns[$j].Name.Length
        foreach ($row in $Rows) {
            if ($j -lt $row.Count) {
                $cellLen = ([string]$row[$j]).Length
                if ($cellLen -gt $maxWidth) { $maxWidth = $cellLen }
            }
        }
        $widths += [Math]::Min($maxWidth, 50)
    }

    if (-not $HideBorder) {
        # Top border
        $topLine = '  ' + [char]0x250C  # ┌
        for ($j = 0; $j -lt $widths.Count; $j++) {
            $topLine += [string]::new([char]0x2500, $widths[$j] + 2)  # ─
            $topLine += if ($j -lt $widths.Count - 1) { [char]0x252C } else { [char]0x2510 }  # ┬ or ┐
        }
        Write-GuerrillaText $topLine -Color $BorderColor
    }

    # Header row
    $headerLine = '  ' + $(if (-not $HideBorder) { [char]0x2502 + ' ' } else { '  ' })
    for ($j = 0; $j -lt $Columns.Count; $j++) {
        $padded = if ($Columns[$j].Alignment -eq 'Right') {
            $Columns[$j].Name.PadLeft($widths[$j])
        } else {
            $Columns[$j].Name.PadRight($widths[$j])
        }
        Write-GuerrillaText $headerLine -Color $BorderColor -NoNewline
        Write-GuerrillaText $padded -Color ($Columns[$j].Color ?? 'Olive') -NoNewline
        $headerLine = if (-not $HideBorder) { ' ' + [char]0x2502 + ' ' } else { '  ' }
    }
    if (-not $HideBorder) {
        Write-GuerrillaText " $([char]0x2502)" -Color $BorderColor
    } else {
        Write-Host ''
    }

    if (-not $HideBorder) {
        # Separator
        $sepLine = '  ' + [char]0x251C  # ├
        for ($j = 0; $j -lt $widths.Count; $j++) {
            $sepLine += [string]::new([char]0x2500, $widths[$j] + 2)  # ─
            $sepLine += if ($j -lt $widths.Count - 1) { [char]0x253C } else { [char]0x2524 }  # ┼ or ┤
        }
        Write-GuerrillaText $sepLine -Color $BorderColor
    }

    # Data rows
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        $rowColor = if ($RowColors -and $i -lt $RowColors.Count -and $RowColors[$i]) { $RowColors[$i] } else { 'Parchment' }

        $prefix = '  ' + $(if (-not $HideBorder) { [char]0x2502 + ' ' } else { '  ' })
        for ($j = 0; $j -lt $Columns.Count; $j++) {
            $cellText = if ($j -lt $row.Count) { [string]$row[$j] } else { '' }
            $padded = if ($Columns[$j].Alignment -eq 'Right') {
                $cellText.PadLeft($widths[$j])
            } else {
                $cellText.PadRight($widths[$j])
            }
            # Truncate if too long
            if ($padded.Length -gt $widths[$j]) {
                $padded = $padded.Substring(0, $widths[$j] - 3) + '...'
            }

            Write-GuerrillaText $prefix -Color $BorderColor -NoNewline
            $cellColor = if ($j -eq 0) { $Columns[$j].Color ?? 'Olive' } else { $rowColor }
            Write-GuerrillaText $padded -Color $cellColor -NoNewline
            $prefix = if (-not $HideBorder) { ' ' + [char]0x2502 + ' ' } else { '  ' }
        }
        if (-not $HideBorder) {
            Write-GuerrillaText " $([char]0x2502)" -Color $BorderColor
        } else {
            Write-Host ''
        }
    }

    if (-not $HideBorder) {
        # Bottom border
        $botLine = '  ' + [char]0x2514  # └
        for ($j = 0; $j -lt $widths.Count; $j++) {
            $botLine += [string]::new([char]0x2500, $widths[$j] + 2)  # ─
            $botLine += if ($j -lt $widths.Count - 1) { [char]0x2534 } else { [char]0x2518 }  # ┴ or ┘
        }
        Write-GuerrillaText $botLine -Color $BorderColor
    }
}
