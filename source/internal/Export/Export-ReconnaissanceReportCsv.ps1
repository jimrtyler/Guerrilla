# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ReconnaissanceReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($f in $Findings) {
        [PSCustomObject]@{
            CheckId           = $f.CheckId
            CheckName         = $f.CheckName
            Category          = $f.Category
            Subcategory       = $f.Subcategory
            Severity          = $f.Severity
            Status            = $f.Status
            CurrentValue      = $f.CurrentValue
            RecommendedValue  = $f.RecommendedValue
            OrgUnitPath       = $f.OrgUnitPath
            RemediationSteps  = $f.RemediationSteps
            NIST_Controls     = ($f.Compliance.NistSp80053 -join '; ')
            MITRE_Techniques  = ($f.Compliance.MitreAttack -join '; ')
            CIS_Benchmarks    = ($f.Compliance.CisBenchmark -join '; ')
            ANSSI_Rules       = (($f.Compliance.Anssi ?? @()) -join '; ')
            NSA_ASD_Guidance  = (($f.Compliance.NsaAsd ?? @()) -join '; ')
            CIS_AD_Benchmarks = (($f.Compliance.CisAd ?? @()) -join '; ')
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
