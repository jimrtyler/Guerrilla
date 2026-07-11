# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Pure logic for Conditional Access "what-if" simulation: normalize the Graph evaluate response into a
# single verdict, the canned attack-scenario catalog, and the scenario grader. No Graph calls here — the
# live POST lives in Test-GuerrillaConditionalAccess. Offline-testable. The CA evaluate API is BETA, so
# any unrecognised/empty response normalizes to 'Unknown' -> the grader returns SKIP (Not Assessed),
# never a false PASS.

# Reduce the applied-policy set returned by /identity/conditionalAccess/evaluate to one outcome.
function ConvertTo-CAWhatIfVerdict {
    [CmdletBinding()]
    param([AllowNull()]$AppliedPolicies)

    if ($null -eq $AppliedPolicies) { return @{ Result = 'Unknown'; AppliedPolicies = @() } }
    $policies = @($AppliedPolicies)
    if ($policies.Count -eq 0) { return @{ Result = 'NotApplied'; AppliedPolicies = @() } }

    $controls = [System.Collections.Generic.List[string]]::new()
    $names = [System.Collections.Generic.List[string]]::new()
    $sawAny = $false
    foreach ($p in $policies) {
        $names.Add("$(($p.displayName ?? $p.name ?? $p.id))")
        # The evaluate response carries the policy's grant controls; tolerate the known shapes.
        $c = @()
        if ($p.grantControls.builtInControls) { $c += @($p.grantControls.builtInControls); $sawAny = $true }
        if ($p.enforcedGrantControls)         { $c += @($p.enforcedGrantControls);         $sawAny = $true }
        foreach ($x in $c) { if ($x) { $controls.Add("$x".ToLower()) } }
    }

    # If policies applied but NONE exposed a grant-control field we recognise, we can't say what they do.
    if (-not $sawAny) { return @{ Result = 'Unknown'; AppliedPolicies = @($names) } }

    $set = @($controls)
    $result =
        if ($set -contains 'block') { 'Block' }
        elseif ($set -contains 'mfa') { 'MfaRequired' }
        elseif ($set -contains 'compliantdevice' -or $set -contains 'domainjoineddevice') { 'CompliantDeviceRequired' }
        elseif ($set -contains 'passwordchange') { 'PasswordChangeRequired' }
        else { 'Grant' }
    return @{ Result = $result; AppliedPolicies = @($names) }
}

# Canned attack scenarios the simulation grades a tenant against. Each: scenario params for the evaluate
# call + the set of outcomes that count as "protected".
function Get-CAAttackScenario {
    @(
        [PSCustomObject]@{ Key = 'legacy-auth';     Name = 'Legacy authentication client'; Severity = 'High'
            Params = @{ ClientAppType = 'exchangeActiveSync' }; Expect = @('Block') }
        [PSCustomObject]@{ Key = 'no-mfa';          Name = 'Cloud app sign-in without MFA'; Severity = 'High'
            Params = @{}; Expect = @('Block', 'MfaRequired', 'CompliantDeviceRequired') }
        [PSCustomObject]@{ Key = 'high-signin-risk'; Name = 'High sign-in risk'; Severity = 'High'
            Params = @{ SignInRiskLevel = 'High' }; Expect = @('Block', 'MfaRequired') }
        [PSCustomObject]@{ Key = 'high-user-risk';  Name = 'High user risk'; Severity = 'High'
            Params = @{ UserRiskLevel = 'High' }; Expect = @('Block', 'MfaRequired', 'PasswordChangeRequired') }
        [PSCustomObject]@{ Key = 'unmanaged-device'; Name = 'Unmanaged device sign-in'; Severity = 'Medium'
            Params = @{ DevicePlatform = 'windows' }; Expect = @('Block', 'MfaRequired', 'CompliantDeviceRequired') }
    )
}

# Grade one scenario result against its expected outcomes. Unknown -> SKIP (Not Assessed).
function Resolve-CAScenarioVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Result,
        [Parameter(Mandatory)][string[]]$Expect
    )
    if ($Result -eq 'Unknown') { return 'SKIP' }
    if ($Result -in $Expect) { return 'PASS' }
    return 'FAIL'
}
