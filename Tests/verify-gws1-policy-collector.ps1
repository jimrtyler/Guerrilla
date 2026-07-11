# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1: verifies the Cloud Identity Policy collector indexes policies by setting type,
# the lookup helper returns the right values, and the collector degrades gracefully (returns
# $null) when the cloud-identity scope isn't delegated. Run: pwsh -File Tests\verify-gws1-policy-collector.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

# ── Happy path: token works, API returns policies (incl. a duplicated type per OU) ──
$out = & $mod {
    function Get-GoogleAccessToken { param($ServiceAccountKeyPath, $AdminEmail, $Scopes) 'fake-token' }
    function Invoke-GoogleAdminApi {
        param($AccessToken, $Uri, [switch]$Paginate, $ItemsProperty, [switch]$Quiet)
        @(
            [PSCustomObject]@{ setting = @{ type = 'settings/gmail.auto_forwarding'; value = @{ enableAutoForwarding = $false } }; policyQuery = @{ orgUnit = 'orgUnits/root' } }
            [PSCustomObject]@{ setting = @{ type = 'settings/gmail.auto_forwarding'; value = @{ enableAutoForwarding = $true } };  policyQuery = @{ orgUnit = 'orgUnits/sales' } }
            [PSCustomObject]@{ setting = @{ type = 'settings/drive_and_docs.external_sharing'; value = @{ externalSharingMode = 'ALLOWED' } } }
            [PSCustomObject]@{ setting = @{ type = 'settings/rule.dlp'; value = @{ ruleName = 'SSN block' } } }
            [PSCustomObject]@{ value = @{ orphan = $true } }   # malformed (no setting) — must be skipped
        )
    }
    $p = Get-GoogleCloudIdentityPolicies -ServiceAccountKeyPath 'x' -AdminEmail 'a@b.org'
    [PSCustomObject]@{
        Count   = $p.Count
        Types   = @($p.ByType.Keys)
        FwdCount  = @(Get-GooglePolicySetting -Policies $p -Type 'gmail.auto_forwarding').Count
        DriveMode = @(Get-GooglePolicySetting -Policies $p -Type 'drive_and_docs.external_sharing')[0].externalSharingMode
        Missing   = @(Get-GooglePolicySetting -Policies $p -Type 'meet.safety_access')
    }
}

Add-R 'Collector returns all policies'        ($out.Count -eq 5) ("count=$($out.Count)")
Add-R 'settings/ prefix stripped + indexed'   ($out.Types -contains 'gmail.auto_forwarding' -and $out.Types -contains 'drive_and_docs.external_sharing' -and $out.Types -contains 'rule.dlp') ("types=$($out.Types -join ', ')")
Add-R 'Malformed policy (no setting) excluded' (-not ($out.Types -contains '')) ''
Add-R 'Lookup returns per-OU values (2 for fwd)' ($out.FwdCount -eq 2) ("fwd=$($out.FwdCount)")
Add-R 'Lookup reads value field'              ($out.DriveMode -eq 'ALLOWED') ("mode=$($out.DriveMode)")
Add-R 'Missing type -> empty (check would SKIP)' ($out.Missing.Count -eq 0) ("missing=$($out.Missing.Count)")

# ── Graceful degradation: scope not delegated -> token throws -> $null ──
$deg = & $mod {
    function Get-GoogleAccessToken { param($ServiceAccountKeyPath, $AdminEmail, $Scopes) throw 'unauthorized_client' }
    function Invoke-GoogleAdminApi { param($AccessToken, $Uri, [switch]$Paginate, $ItemsProperty, [switch]$Quiet) throw 'should not be called' }
    Get-GoogleCloudIdentityPolicies -ServiceAccountKeyPath 'x' -AdminEmail 'a@b.org'
}
Add-R 'Non-delegated tenant -> collector returns $null' ($null -eq $deg) ("deg=$deg")
Add-R 'Helper on $null is safe (-> empty)' ((& $mod { Get-GooglePolicySetting -Policies $null -Type 'gmail.auto_forwarding' }).Count -eq 0) ''

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
