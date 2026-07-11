# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Conditional Access what-if (Maester parity M2): the pure normalizer (Graph evaluate response -> verdict),
# the scenario grader, and EIDCA-015 grading live what-if results — with honest SKIP/Not-Assessed when the
# beta API gives nothing usable. The live Graph POST is validated separately on a tenant. Run:
#   pwsh -File Tests/verify-ca-whatif.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

# Synthetic evaluate-response policy objects (mirror the Graph shapes the normalizer tolerates).
$polBlock = [pscustomobject]@{ displayName = 'Block legacy'; policyApplies = $true; grantControls = [pscustomobject]@{ builtInControls = @('block') } }
$polMfa   = [pscustomobject]@{ displayName = 'Require MFA';  policyApplies = $true; grantControls = [pscustomobject]@{ builtInControls = @('mfa') } }
$polMfaEnforced = [pscustomobject]@{ displayName = 'MFA (enforced shape)'; policyApplies = $true; enforcedGrantControls = @('Mfa') }
$polGrantOnly = [pscustomobject]@{ displayName = 'Grant'; policyApplies = $true; grantControls = [pscustomobject]@{ builtInControls = @('passwordChange') } }
$polNoControls = [pscustomobject]@{ displayName = 'applies but unknown controls'; policyApplies = $true }

$out = & $mod {
    param($block, $mfa, $mfaEnf, $pw, $noctrl)
    $r = @{}
    # ── Normalizer ──
    $r.Block      = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @($block)).Result
    $r.Mfa        = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @($mfa)).Result
    $r.MfaEnf     = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @($mfaEnf)).Result
    $r.BlockWins  = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @($mfa, $block)).Result   # block precedence
    $r.PwChange   = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @($pw)).Result
    $r.NotApplied = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @()).Result
    $r.NullUnknown = (ConvertTo-CAWhatIfVerdict -AppliedPolicies $null).Result
    $r.AppliesNoCtrl = (ConvertTo-CAWhatIfVerdict -AppliedPolicies @($noctrl)).Result      # applies but no known control -> Unknown
    # ── Grader ──
    $r.GradePass = Resolve-CAScenarioVerdict -Result 'Block' -Expect @('Block', 'MfaRequired')
    $r.GradeFail = Resolve-CAScenarioVerdict -Result 'Grant' -Expect @('Block', 'MfaRequired')
    $r.GradeSkip = Resolve-CAScenarioVerdict -Result 'Unknown' -Expect @('Block')           # Unknown -> Not Assessed
    # ── Scenario catalog ──
    $r.ScenarioCount = (Get-CAAttackScenario).Count
    $r.HasLegacy = ((Get-CAAttackScenario) | Where-Object Key -eq 'legacy-auth').Count -eq 1
    $r
} $polBlock $polMfa $polMfaEnforced $polGrantOnly $polNoControls

Add-R 'normalizer: block'                 ($out.Block -eq 'Block') $out.Block
Add-R 'normalizer: mfa'                    ($out.Mfa -eq 'MfaRequired') $out.Mfa
Add-R 'normalizer: enforcedGrantControls'  ($out.MfaEnf -eq 'MfaRequired') $out.MfaEnf
Add-R 'normalizer: block beats mfa'        ($out.BlockWins -eq 'Block') $out.BlockWins
Add-R 'normalizer: passwordChange'         ($out.PwChange -eq 'PasswordChangeRequired') $out.PwChange
Add-R 'normalizer: none applied'           ($out.NotApplied -eq 'NotApplied') $out.NotApplied
Add-R 'normalizer: null -> Unknown'        ($out.NullUnknown -eq 'Unknown') $out.NullUnknown
Add-R 'normalizer: applies+no ctrl->Unknown' ($out.AppliesNoCtrl -eq 'Unknown') $out.AppliesNoCtrl
Add-R 'grader: in-expected -> PASS'        ($out.GradePass -eq 'PASS') $out.GradePass
Add-R 'grader: not-expected -> FAIL'       ($out.GradeFail -eq 'FAIL') $out.GradeFail
Add-R 'grader: Unknown -> SKIP'            ($out.GradeSkip -eq 'SKIP') $out.GradeSkip
Add-R 'scenario catalog has scenarios'     ($out.ScenarioCount -ge 4) "n=$($out.ScenarioCount)"
Add-R 'scenario catalog has legacy-auth'   ($out.HasLegacy) ''

# Cmdlet is exported
Add-R 'Test-GuerrillaConditionalAccess exported' ([bool](Get-Command Test-GuerrillaConditionalAccess -EA SilentlyContinue)) ''

# ── EIDCA-015 grading of live what-if results (offline; no Graph) ──
function New-CDef($id) { @{ id = $id; name = "$id"; severity = 'High'; _categoryName = 'Conditional Access'; description = 'd'; compliance = @{} } }
$eidca = & $mod {
    param($cd)
    $r = @{}
    # All scenarios protected -> PASS
    $allPass = @{ ConditionalAccess = @{ Policies = @(); WhatIf = @(
        @{ Key='legacy-auth'; Name='Legacy'; Severity='High'; Result='Block'; Verdict='PASS' }
        @{ Key='no-mfa'; Name='No MFA'; Severity='High'; Result='MfaRequired'; Verdict='PASS' }
    ) } }
    $r.AllPass = (Test-InfiltrationEIDCA015 -AuditData $allPass -CheckDefinition $cd).Status
    # One scenario unprotected -> FAIL
    $oneFail = @{ ConditionalAccess = @{ Policies=@(); WhatIf = @(
        @{ Key='legacy-auth'; Name='Legacy'; Severity='High'; Result='Grant'; Verdict='FAIL' }
        @{ Key='no-mfa'; Name='No MFA'; Severity='High'; Result='MfaRequired'; Verdict='PASS' }
    ) } }
    $f = Test-InfiltrationEIDCA015 -AuditData $oneFail -CheckDefinition $cd
    $r.OneFailStatus = $f.Status
    $r.OneFailLive = ($f.Details.Mode -eq 'LiveWhatIf')
    $r.OneFailNamesLegacy = ($f.CurrentValue -match 'Legacy')
    # No what-if + no policies -> SKIP (Not Assessed), never PASS
    $r.NoData = (Test-InfiltrationEIDCA015 -AuditData @{ ConditionalAccess = @{ Policies=@(); WhatIf=@() } } -CheckDefinition $cd).Status
    $r
} (New-CDef 'EIDCA-015')

Add-R 'EIDCA-015 live all-pass -> PASS'    ($eidca.AllPass -eq 'PASS') $eidca.AllPass
Add-R 'EIDCA-015 live one-fail -> FAIL'    ($eidca.OneFailStatus -eq 'FAIL') $eidca.OneFailStatus
Add-R 'EIDCA-015 marks LiveWhatIf mode'    ($eidca.OneFailLive) ''
Add-R 'EIDCA-015 names unprotected scenario' ($eidca.OneFailNamesLegacy) ''
Add-R 'EIDCA-015 no data -> SKIP (not PASS)' ($eidca.NoData -eq 'SKIP') $eidca.NoData

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($x in $results) {
    $mark = if ($x.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($x.Name)"; if ($x.Detail) { $line += "  ($($x.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
