# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraConditionalAccessData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        # When set (a representative user's object ID), run the live CA what-if attack-scenario matrix
        # against the tenant via the Graph evaluate API. Left empty, EIDCA-015 falls back to inference.
        [string]$WhatIfUserId,

        [switch]$Quiet
    )

    $data = @{
        Policies       = @()
        NamedLocations = @()
        WhatIf         = @()
        Errors         = @{}
    }

    # ── Conditional Access Policies ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Conditional Access policies'
    }
    try {
        $data.Policies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identity/conditionalAccess/policies' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Policies'] = $_.Exception.Message
        Write-Warning "Failed to collect CA policies: $($_.Exception.Message)"
    }

    # ── Named Locations ───────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting named locations'
    }
    try {
        $data.NamedLocations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identity/conditionalAccess/namedLocations' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['NamedLocations'] = $_.Exception.Message
        Write-Warning "Failed to collect named locations: $($_.Exception.Message)"
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Collected $($data.Policies.Count) CA policies, $($data.NamedLocations.Count) named locations"
    }

    # ── Live CA what-if attack-scenario simulation (only when a representative user is supplied) ──
    if ($WhatIfUserId) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Running Conditional Access what-if attack scenarios'
        }
        $wf = [System.Collections.Generic.List[object]]::new()
        foreach ($s in (Get-CAAttackScenario)) {
            try {
                $p = @{ UserId = $WhatIfUserId; AccessToken = $AccessToken; IncludeApplications = @('All') } + $s.Params
                $r = Test-GuerrillaConditionalAccess @p
                $v = Resolve-CAScenarioVerdict -Result $r.Result -Expect $s.Expect
                $wf.Add(@{ Key = $s.Key; Name = $s.Name; Severity = $s.Severity; Result = $r.Result; Expect = @($s.Expect); Verdict = $v; AppliedPolicies = @($r.AppliedPolicies) })
            } catch {
                $wf.Add(@{ Key = $s.Key; Name = $s.Name; Severity = $s.Severity; Result = 'Unknown'; Expect = @($s.Expect); Verdict = 'SKIP'; AppliedPolicies = @() })
            }
        }
        $data.WhatIf = @($wf)
    }

    return $data
}
