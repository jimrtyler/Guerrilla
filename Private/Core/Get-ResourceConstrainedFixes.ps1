# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ResourceConstrainedFixes {
    <#
    .SYNOPSIS
        Filters audit findings to free or low-cost remediation actions only.
    .DESCRIPTION
        Reads RemediationCosts.json and filters findings to those with Free or Low
        cost tiers. Returns findings sorted by impact (severity weight) descending.
    .PARAMETER Findings
        Array of audit finding objects.
    .PARAMETER MaxCostTier
        Maximum cost tier to include. Default: Low. Options: Free, Low, Medium.
    .PARAMETER RemediationData
        Pre-loaded remediation cost data. If not provided, loads from Data/RemediationCosts.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [ValidateSet('Free', 'Low', 'Medium')]
        [string]$MaxCostTier = 'Low',

        [hashtable]$RemediationData
    )

    if (-not $RemediationData) {
        $remPath = Join-Path $script:ModuleRoot 'Data/RemediationCosts.json'
        if (Test-Path $remPath) {
            $RemediationData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
        } else {
            Write-Warning "RemediationCosts.json not found at $remPath"
            return @()
        }
    }

    $tierOrder = @{ 'Free' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Enterprise' = 4 }
    $maxTierIndex = $tierOrder[$MaxCostTier] ?? 1

    $severityWeights = @{
        'Critical' = 10
        'High'     = 6
        'Medium'   = 3
        'Low'      = 1
        'Info'     = 0
    }

    $effortHours = @{
        'Minimal' = 0.25
        'Low'     = 1
        'Medium'  = 4
        'High'    = 16
        'Major'   = 80
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($finding in $Findings) {
        if ($finding.Status -notin @('FAIL', 'WARN')) { continue }

        $checkId = $finding.CheckId ?? $finding.Id ?? ''
        $prefix = if ($checkId -match '^([A-Z0-9]+)-') { $Matches[1] } else { '' }

        # Look up cost: specific override first, then category default
        $costInfo = $null
        if ($RemediationData.overrides.$checkId) {
            $costInfo = $RemediationData.overrides.$checkId
        } elseif ($RemediationData.categoryDefaults.$prefix) {
            $costInfo = $RemediationData.categoryDefaults.$prefix
        }

        if (-not $costInfo) { continue }

        $checkTier = $costInfo.costTier ?? 'Medium'
        $checkTierIndex = $tierOrder[$checkTier] ?? 2

        if ($checkTierIndex -gt $maxTierIndex) { continue }

        $severity = $finding.Severity ?? 'Medium'
        $weight = $severityWeights[$severity] ?? 3
        $statusMult = if ($finding.Status -eq 'WARN') { 0.5 } else { 1.0 }
        $impact = $weight * $statusMult

        $effort = $costInfo.effort ?? 'Medium'
        $hours = $effortHours[$effort] ?? 4

        $results.Add([PSCustomObject]@{
            PSTypeName       = 'Guerrilla.ResourceConstrainedFix'
            CheckId          = $checkId
            CheckName        = $finding.Name ?? $finding.CheckName ?? $checkId
            Description      = $finding.Description ?? ''
            Severity         = $severity
            Status           = $finding.Status
            CostTier         = $checkTier
            Effort           = $effort
            EstimatedHours   = $hours
            Impact           = $impact
            ImpactPerHour    = if ($hours -gt 0) { [Math]::Round($impact / $hours, 2) } else { $impact }
            Category         = $finding.Category ?? $prefix
            RemediationSteps = $finding.RemediationSteps ?? $costInfo.notes ?? ''
        })
    }

    return @($results | Sort-Object -Property Impact -Descending)
}
