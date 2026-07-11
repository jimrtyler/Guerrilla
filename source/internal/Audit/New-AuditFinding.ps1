# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function New-AuditFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CheckDefinition,

        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'FAIL', 'WARN', 'ERROR', 'SKIP')]
        [string]$Status,

        [string]$CurrentValue = '',
        [string]$OrgUnitPath = '/',
        [hashtable]$Details = @{}
    )

    [PSCustomObject]@{
        PSTypeName       = 'Guerrilla.AuditFinding'
        CheckId          = $CheckDefinition.id
        CheckName        = $CheckDefinition.name
        Category         = $CheckDefinition._categoryName ?? ''
        Subcategory      = $CheckDefinition.subcategory ?? ''
        Severity         = $CheckDefinition.severity
        ZeroTrustPillar  = $CheckDefinition.zeroTrustPillar
        ZeroTrustWeight  = $CheckDefinition.zeroTrustWeight ?? 0
        Status           = $Status
        Description      = $CheckDefinition.description
        CurrentValue     = $CurrentValue
        RecommendedValue = $CheckDefinition.recommendedValue ?? ''
        OrgUnitPath      = $OrgUnitPath
        RemediationUrl   = $CheckDefinition.remediationUrl ?? ''
        RemediationSteps = $CheckDefinition.remediationSteps ?? ''
        ReferenceUrl     = $CheckDefinition.referenceUrl ?? ''
        ReferenceTitle   = $CheckDefinition.referenceTitle ?? ''
        Compliance       = @{
            NistSp80053  = @($CheckDefinition.compliance.nistSp80053 ?? @())
            MitreAttack  = @($CheckDefinition.compliance.mitreAttack ?? @())
            CisBenchmark = @($CheckDefinition.compliance.cisBenchmark ?? @())
            Anssi        = @($CheckDefinition.compliance.anssi ?? @())
            NsaAsd       = @($CheckDefinition.compliance.nsaAsd ?? @())
            CisAd        = @($CheckDefinition.compliance.cisAd ?? @())
            CisM365      = @($CheckDefinition.compliance.cisM365 ?? @())
            CisAzure     = @($CheckDefinition.compliance.cisAzure ?? @())
            Scuba        = @($CheckDefinition.compliance.scuba ?? @())
            Eidsca       = @($CheckDefinition.compliance.eidsca ?? @())
        }
        Details          = $Details
        Timestamp        = [datetime]::UtcNow
    }
}
