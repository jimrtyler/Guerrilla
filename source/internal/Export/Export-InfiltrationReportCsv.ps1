# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-InfiltrationReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $rows = foreach ($f in $Result.Findings) {
        [PSCustomObject]@{
            CheckId            = $f.CheckId
            CheckName          = $f.CheckName
            Category           = $f.Category
            Subcategory        = $f.Subcategory
            Severity           = $f.Severity
            Status             = $f.Status
            CurrentValue       = $f.CurrentValue
            RecommendedValue   = $f.RecommendedValue
            RemediationSteps   = $f.RemediationSteps
            RemediationUrl     = $f.RemediationUrl
            NIST_Controls      = ($f.Compliance.NistSp80053 -join '; ')
            MITRE_Techniques   = ($f.Compliance.MitreAttack -join '; ')
            CIS_Benchmarks     = ($f.Compliance.CisBenchmark -join '; ')
            CIS_M365           = (($f.Compliance.CisM365 ?? @()) -join '; ')
            CIS_Azure          = (($f.Compliance.CisAzure ?? @()) -join '; ')
            ANSSI_Rules        = (($f.Compliance.Anssi ?? @()) -join '; ')
            NSA_ASD_Guidance   = (($f.Compliance.NsaAsd ?? @()) -join '; ')
            CIS_AD_Benchmarks  = (($f.Compliance.CisAd ?? @()) -join '; ')
            Timestamp          = $f.Timestamp.ToString('o')
        }
    }

    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
