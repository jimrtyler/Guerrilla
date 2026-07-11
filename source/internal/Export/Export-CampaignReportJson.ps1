# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-CampaignReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $moduleVersion = '2.0.0'
    try {
        $manifestPath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'Guerrilla.psd1'
        if (Test-Path $manifestPath) {
            $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction SilentlyContinue
            if ($manifest.ModuleVersion) { $moduleVersion = $manifest.ModuleVersion }
        }
    } catch { }

    $output = @{
        schemaVersion = 1
        generator     = "Guerrilla v$moduleVersion"
        scanId        = $Result.ScanId
        scanStart     = $Result.ScanStart.ToString('o')
        scanEnd       = $Result.ScanEnd.ToString('o')
        durationSec   = [Math]::Round($Result.Duration.TotalSeconds, 1)
        theaters      = $Result.Theaters
        summary       = @{
            overallScore   = $Result.OverallScore
            scoreLabel     = $Result.ScoreLabel
            totalFindings  = $Result.Findings.Count
            passCount      = @($Result.Findings | Where-Object Status -eq 'PASS').Count
            failCount      = @($Result.Findings | Where-Object Status -eq 'FAIL').Count
            warnCount      = @($Result.Findings | Where-Object Status -eq 'WARN').Count
            skipCount      = @($Result.Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
        }
        theaterScores = @{}
        categoryScores = $Result.CategoryScores
        findings      = @($Result.Findings | ForEach-Object {
            @{
                theater          = $_.Theater ?? ''
                checkId          = $_.CheckId
                checkName        = $_.CheckName
                category         = $_.Category
                subcategory      = $_.Subcategory
                severity         = $_.Severity
                status           = $_.Status
                description      = $_.Description
                currentValue     = $_.CurrentValue
                recommendedValue = $_.RecommendedValue
                remediationSteps = $_.RemediationSteps
                remediationUrl   = $_.RemediationUrl
                compliance       = @{
                    nistSp80053  = @($_.Compliance.NistSp80053)
                    mitreAttack  = @($_.Compliance.MitreAttack)
                    cisBenchmark = @($_.Compliance.CisBenchmark)
                    cisM365      = @($_.Compliance.CisM365 ?? @())
                    cisAzure     = @($_.Compliance.CisAzure ?? @())
                    cisAd        = @($_.Compliance.CisAd ?? @())
                    anssi        = @($_.Compliance.Anssi ?? @())
                    nsaAsd       = @($_.Compliance.NsaAsd ?? @())
                }
                details          = $_.Details
                timestamp        = $_.Timestamp.ToString('o')
            }
        })
    }

    # Build theater scores
    foreach ($ts in $Result.TheaterScores.GetEnumerator()) {
        $output.theaterScores[$ts.Key] = @{
            score        = $ts.Value.Score
            scoreLabel   = $ts.Value.ScoreLabel
            findingCount = $ts.Value.FindingCount
            passCount    = $ts.Value.PassCount
            failCount    = $ts.Value.FailCount
            warnCount    = $ts.Value.WarnCount
            skipCount    = $ts.Value.SkipCount
        }
    }

    $output | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
}
