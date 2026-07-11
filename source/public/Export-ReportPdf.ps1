# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ReportPdf {
    <#
    .SYNOPSIS
        Converts an HTML report to PDF via Edge or Chrome headless mode.
    .DESCRIPTION
        Takes an existing HTML report file and converts it to PDF using Microsoft Edge
        or Google Chrome in headless mode. Falls back gracefully with an error message
        if neither browser is available.

        Detection order: Edge → Chrome → Chromium.
    .PARAMETER HtmlPath
        Path to the HTML file to convert.
    .PARAMETER OutputPath
        Path for the PDF output. Default: same as input with .pdf extension.
    .PARAMETER BrowserPath
        Override path to the browser executable.
    .EXAMPLE
        Export-ReportPdf -HtmlPath ./Guerrilla-Executive-Summary.html
    .EXAMPLE
        Export-ExecutiveSummary -OutputPath ./summary.html; Export-ReportPdf -HtmlPath ./summary.html -OutputPath ./summary.pdf
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HtmlPath,

        [string]$OutputPath,
        [string]$BrowserPath
    )

    if (-not (Test-Path $HtmlPath)) {
        Write-Warning "HTML file not found: $HtmlPath"
        return [PSCustomObject]@{ Success = $false; Message = "File not found: $HtmlPath"; Path = $null }
    }

    $resolvedHtml = (Resolve-Path $HtmlPath).Path
    if (-not $OutputPath) {
        $OutputPath = [System.IO.Path]::ChangeExtension($resolvedHtml, '.pdf')
    }

    # Find browser
    if (-not $BrowserPath) {
        $candidates = @(
            # Microsoft Edge
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
            "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
            # Google Chrome
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
            # Linux/macOS
            '/usr/bin/microsoft-edge'
            '/usr/bin/google-chrome'
            '/usr/bin/chromium-browser'
            '/usr/bin/chromium'
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
            '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
        )

        foreach ($candidate in $candidates) {
            if (Test-Path $candidate) {
                $BrowserPath = $candidate
                break
            }
        }
    }

    if (-not $BrowserPath) {
        $msg = 'PDF export requires Microsoft Edge or Google Chrome. Install one and retry, or use the HTML report with print-friendly CSS (@media print).'
        Write-Warning $msg
        return [PSCustomObject]@{ Success = $false; Message = $msg; Path = $null }
    }

    Write-Verbose "Using browser: $BrowserPath"
    Write-Verbose "Converting: $resolvedHtml -> $OutputPath"

    $fileUri = "file:///$($resolvedHtml -replace '\\', '/')"

    $arguments = @(
        '--headless'
        "--print-to-pdf=$OutputPath"
        '--no-margins'
        '--disable-gpu'
        '--no-sandbox'
        '--disable-extensions'
        '--disable-dev-shm-usage'
        $fileUri
    )

    try {
        Start-Process -FilePath $BrowserPath -ArgumentList $arguments -NoNewWindow -Wait -ErrorAction Stop

        # Give it a moment to write the file (timeout = 30 seconds)
        $timeoutMs = 30000
        $elapsedMs = 0
        while (-not (Test-Path $OutputPath) -and $elapsedMs -lt $timeoutMs) {
            Start-Sleep -Milliseconds 500
            $elapsedMs += 500
        }

        if (Test-Path $OutputPath) {
            $fileSize = (Get-Item $OutputPath).Length
            return [PSCustomObject]@{
                PSTypeName = 'Guerrilla.PdfExport'
                Success    = $true
                Path       = (Resolve-Path $OutputPath).Path
                Message    = "PDF exported to $OutputPath ($([Math]::Round($fileSize / 1KB, 1)) KB)"
                FileSize   = $fileSize
                Browser    = [System.IO.Path]::GetFileName($BrowserPath)
            }
        } else {
            return [PSCustomObject]@{
                PSTypeName = 'Guerrilla.PdfExport'
                Success    = $false
                Message    = "PDF generation completed but output file not found at $OutputPath"
                Path       = $null
            }
        }
    } catch {
        return [PSCustomObject]@{
            PSTypeName = 'Guerrilla.PdfExport'
            Success    = $false
            Message    = "PDF export failed: $_"
            Path       = $null
        }
    }
}
