# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ReconnaissanceReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [string]$DomainName = '',
        [string]$ScanId = '',
        [hashtable]$Delta,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')

    $report = @{
        metadata = @{
            scanId       = $ScanId
            timestamp    = [datetime]::UtcNow.ToString('o')
            domain       = $DomainName
            generator    = 'Guerrilla'
            reportType   = 'AD Reconnaissance'
            version      = '2.0.0'
        }
        summary = @{
            overallScore   = $OverallScore
            scoreLabel     = $ScoreLabel
            totalChecks    = $Findings.Count
            passCount      = @($Findings | Where-Object Status -eq 'PASS').Count
            failCount      = $failFindings.Count
            warnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
            skipCount      = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
            criticalCount  = @($failFindings | Where-Object Severity -eq 'Critical').Count
            highCount      = @($failFindings | Where-Object Severity -eq 'High').Count
            mediumCount    = @($failFindings | Where-Object Severity -eq 'Medium').Count
            lowCount       = @($failFindings | Where-Object Severity -eq 'Low').Count
            categoryScores = $CategoryScores
        }
        findings = @($Findings | ForEach-Object {
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
                compliance       = @{
                    nistSp80053  = @($_.Compliance.NistSp80053 ?? @())
                    mitreAttack  = @($_.Compliance.MitreAttack ?? @())
                    cisBenchmark = @($_.Compliance.CisBenchmark ?? @())
                    anssi        = @($_.Compliance.Anssi ?? @())
                    nsaAsd       = @($_.Compliance.NsaAsd ?? @())
                    cisAd        = @($_.Compliance.CisAd ?? @())
                }
                details          = $_.Details
                timestamp        = $_.Timestamp.ToString('o')
            }
        })
    }

    if ($Delta) {
        $report['delta'] = $Delta
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $FilePath -Encoding UTF8
}
