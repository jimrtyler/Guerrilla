# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-Dashboard {
    <#
    .SYNOPSIS
        Generates a unified HTML dashboard across all theaters.
    .DESCRIPTION
        Produces a single-file HTML dashboard with the Guerrilla Score ring at top,
        theater-specific cards with mini-scores, and a consolidated findings table.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER ScanResults
        Array of scan result objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Dashboard.html
    .PARAMETER OrganizationName
        Organization name for the report header.
    .EXAMPLE
        Export-Dashboard -OrganizationName 'Springfield USD'
    .EXAMPLE
        Export-Dashboard -OutputPath ./dashboard.html
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [PSCustomObject[]]$ScanResults,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization'
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Dashboard.html' }

    $dataDir = Get-GuerrillaDataRoot

    # Load findings if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    # Load scan results if not provided
    if (-not $ScanResults -or $ScanResults.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.state.json' -ErrorAction SilentlyContinue)) {
                try { $ScanResults += (Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    # Calculate Guerrilla Score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings -ScanResults $ScanResults } catch { }
    if (-not $scoreResult) {
        $scoreResult = [PSCustomObject]@{ Score = 0; Label = 'N/A'; Components = $null }
    }

    # Generate the HTML
    $null = Export-DashboardHtml `
        -ScoreResult $scoreResult `
        -Findings $Findings `
        -ScanResults $ScanResults `
        -OutputPath $OutputPath `
        -OrganizationName $OrganizationName

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.Dashboard'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Dashboard exported to $OutputPath"
        Score      = $scoreResult.Score
        Label      = $scoreResult.Label
    }
}
