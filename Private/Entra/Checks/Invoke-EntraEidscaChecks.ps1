# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# EIDSCA (Entra ID Security Config Analyzer) check dispatcher. Unlike the per-ID Test-Infiltration*
# checks, EIDSCA is data-driven: it evaluates the catalog in Data/AuditChecks/EidscaChecks.json against
# the raw Graph policy objects our collectors already store. Each control -> one finding, tagged
# compliance.eidsca so it flows through Get-ComplianceCrosswalk -Framework EIDSCA. Honest by design:
# any control whose source object/property wasn't collected returns SKIP ("Not Assessed"), never PASS.

function Invoke-EntraEidscaChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $catalogPath = Join-Path $script:ModuleRoot 'Data/AuditChecks/EidscaChecks.json'
    if (-not (Test-Path $catalogPath)) {
        Write-Warning "EIDSCA catalog not found at $catalogPath"
        return @()
    }
    $catalog = Get-Content -Path $catalogPath -Raw | ConvertFrom-Json -AsHashtable

    # The raw Graph objects EIDSCA controls read — all collected by Get-EntraAuthMethodsData /
    # Get-EntraTenantData. Missing pieces simply yield SKIP downstream (Not Assessed).
    $am = $AuditData.AuthMethods
    $sources = @{
        AuthorizationPolicy       = $am.AuthorizationPolicy
        AuthMethodsPolicy         = $am.AuthMethodsPolicy
        MethodConfigurations      = @($am.MethodConfigurations)
        DirectorySettings         = @($am.DirectorySettings)
        AdminConsentRequestPolicy = $AuditData.TenantConfig.AdminConsentRequestPolicy
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($check in $catalog.checks) {
        $check['_categoryName'] = $catalog.categoryName
        try {
            $r = Resolve-EidscaControl -Control $check -Sources $sources
            $cv = switch ($r.Status) {
                'SKIP' { 'Not Assessed — required Entra policy/setting was not collected (connect the needed scope/module)' }
                'PASS' { "Compliant (observed: $($r.Actual))" }
                default { "Non-compliant (observed: $($r.Actual); expected: $($check.recommendedValue))" }
            }
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status $r.Status -CurrentValue $cv))
        } catch {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' -CurrentValue "Check failed: $_"))
        }
    }
    return @($findings)
}
