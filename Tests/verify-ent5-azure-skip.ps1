# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# ENT-5: Azure IAM checks must distinguish "no ARM access / no subscriptions" (a clear
# actionable SKIP) from "no resources of this type found" (a WARN when subscriptions DO
# exist). Run: pwsh -File Tests\verify-ent5-azure-skip.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

# Run AZIAM-004 (Key Vaults) under three IAM-data states.
function Run-AZIAM004($iam) {
    & $mod {
        param($IamData)
        $defs = Get-AuditCategoryDefinitions -Category 'AzureIAMChecks'
        $check = $defs.checks | Where-Object id -eq 'AZIAM-004'
        Test-InfiltrationAZIAM004 -AuditData @{ AzureIAM = $IamData } -CheckDefinition $check
    } $iam
}

# 1) ARM errored (no access) -> SKIP mentioning Reader at root management group
$errored = @{ Subscriptions = @(); KeyVaults = @(); Errors = @{ Subscriptions = 'AuthorizationFailed' } }
$f1 = Run-AZIAM004 $errored
Add-R 'ARM-errored => SKIP' ($f1.Status -eq 'SKIP') ("status=$($f1.Status)")
Add-R 'ARM-errored => Reader/root-MG guidance' ($f1.CurrentValue -match 'Reader role at the root management group') ''

# 2) Zero subscriptions (no error) -> SKIP "no accessible Azure subscriptions"
$zeroSubs = @{ Subscriptions = @(); KeyVaults = @(); Errors = @{} }
$f2 = Run-AZIAM004 $zeroSubs
Add-R 'Zero-subs => SKIP' ($f2.Status -eq 'SKIP') ("status=$($f2.Status)")
Add-R 'Zero-subs => "no accessible Azure subscriptions"' ($f2.CurrentValue -match 'No accessible Azure subscriptions') ''

# 3) Subscriptions present but no Key Vaults -> WARN "No Key Vaults found" (genuine empty)
$subsNoVaults = @{ Subscriptions = @(@{ subscriptionId = 'sub-1' }); KeyVaults = @(); Errors = @{} }
$f3 = Run-AZIAM004 $subsNoVaults
Add-R 'Subs-but-no-vaults => WARN (not SKIP)' ($f3.Status -eq 'WARN') ("status=$($f3.Status)")
Add-R 'Subs-but-no-vaults => "No Key Vaults found"' ($f3.CurrentValue -match 'No Key Vaults found') ''

# 4) Missing IAM data entirely -> SKIP "ARM was not queried"
$f4 = Run-AZIAM004 $null
Add-R 'No IAM data => SKIP "not queried"' ($f4.Status -eq 'SKIP' -and $f4.CurrentValue -match 'was not queried') ("status=$($f4.Status)")

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($r.Name)"; if ($r.Detail) { $line += "  ($($r.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
