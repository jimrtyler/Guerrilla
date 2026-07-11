# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-InfiltrationReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $findings = $Result.Findings
    $score = $Result.Score
    $failFindings = @($findings | Where-Object Status -eq 'FAIL')

    $report = @{
        metadata = @{
            scanId       = $Result.ScanId
            timestamp    = $Result.ScanStart.ToString('o')
            tenantId     = $Result.TenantId
            generator    = 'Guerrilla'
            reportType   = 'Entra ID / Azure / M365 Infiltration Audit'
            version      = '2.0.0'
            duration     = $Result.Duration.ToString()
            categories   = @($Result.Categories)
        }
        summary = @{
            overallScore   = $score.OverallScore
            scoreLabel     = Get-FortificationScoreLabel -Score $score.OverallScore
            totalChecks    = $findings.Count
            passCount      = @($findings | Where-Object Status -eq 'PASS').Count
            failCount      = $failFindings.Count
            warnCount      = @($findings | Where-Object Status -eq 'WARN').Count
            skipCount      = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
            criticalCount  = @($failFindings | Where-Object Severity -eq 'Critical').Count
            highCount      = @($failFindings | Where-Object Severity -eq 'High').Count
            mediumCount    = @($failFindings | Where-Object Severity -eq 'Medium').Count
            lowCount       = @($failFindings | Where-Object Severity -eq 'Low').Count
            categoryScores = $score.CategoryScores
        }
        findings = @($findings | ForEach-Object {
            @{
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
                    nistSp80053  = @($_.Compliance.NistSp80053 ?? @())
                    mitreAttack  = @($_.Compliance.MitreAttack ?? @())
                    cisBenchmark = @($_.Compliance.CisBenchmark ?? @())
                    cisM365      = @($_.Compliance.CisM365 ?? @())
                    cisAzure     = @($_.Compliance.CisAzure ?? @())
                    anssi        = @($_.Compliance.Anssi ?? @())
                    nsaAsd       = @($_.Compliance.NsaAsd ?? @())
                    cisAd        = @($_.Compliance.CisAd ?? @())
                }
                details          = $_.Details
                timestamp        = $_.Timestamp.ToString('o')
            }
        })
        dataErrors = $Result.DataErrors
    }

    $report | ConvertTo-Json -Depth 15 | Set-Content -Path $OutputPath -Encoding UTF8
}
