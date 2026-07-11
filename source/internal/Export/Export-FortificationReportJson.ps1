# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-FortificationReportJson {
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

        [string]$TenantDomain = '',
        [string]$ScanId = '',
        [hashtable]$Delta,
        [string]$FilePath
    )

    $report = @{
        scanId         = $ScanId
        timestamp      = [datetime]::UtcNow.ToString('o')
        tenantDomain   = $TenantDomain
        overallScore   = $OverallScore
        scoreLabel     = $ScoreLabel
        categoryScores = $CategoryScores
        summary        = @{
            totalChecks   = $Findings.Count
            passCount     = @($Findings | Where-Object Status -eq 'PASS').Count
            failCount     = @($Findings | Where-Object Status -eq 'FAIL').Count
            warnCount     = @($Findings | Where-Object Status -eq 'WARN').Count
            skipCount     = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
            criticalCount = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
            highCount     = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
            mediumCount   = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Medium' }).Count
            lowCount      = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Low' }).Count
        }
        findings       = @($Findings | ForEach-Object {
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
                orgUnitPath      = $_.OrgUnitPath
                remediationUrl   = $_.RemediationUrl
                remediationSteps = $_.RemediationSteps
                compliance       = $_.Compliance
                details          = $_.Details
            }
        })
        delta          = $Delta
    }

    $json = $report | ConvertTo-Json -Depth 10

    if ($FilePath) {
        $json | Set-Content -Path $FilePath -Encoding UTF8
    }

    return $json
}
