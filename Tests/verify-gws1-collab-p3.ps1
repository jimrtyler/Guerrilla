# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 Collaboration Phase 3: verifies the two net-new Meet safety checks read real Cloud
# Identity policy values and grade correctly. Both are booleans where true = secure, graded
# weakest-OU-wins (WARN if false in any targeted OU). Covers per check: secure (true) -> PASS,
# insecure (false) -> WARN, multi-OU weakest-wins -> WARN, and unavailable -> SKIP.
# Run: pwsh -File Tests/verify-gws1-collab-p3.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$out = & $mod {
    # Build a CloudIdentityPolicies object: type -> array of value objects. Real policy values
    # are PSCustomObjects (ConvertFrom-Json), so cast hashtable fixtures to match.
    function New-Pol([hashtable]$map) {
        $byType = @{}
        foreach ($k in $map.Keys) {
            $lst = [System.Collections.Generic.List[object]]::new()
            foreach ($v in @($map[$k])) {
                $val = if ($v -is [hashtable]) { [PSCustomObject]$v } else { $v }
                $lst.Add([PSCustomObject]@{ setting = [PSCustomObject]@{ type = "settings/$k"; value = $val } })
            }
            $byType[$k] = $lst
        }
        [PSCustomObject]@{ All = @(); ByType = $byType; Count = 0 }
    }
    $def = @{ id = 'COLLAB-XXX'; name = 'x'; severity = 'Low'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}

    # ── COLLAB-011: Meet External Participant Labeling (enableExternalLabel; true=secure) ──
    $r.C011_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_external_participants' = @{ enableExternalLabel = $true } }) }) 'Test-FortificationCOLLAB011'
    $r.C011_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_external_participants' = @{ enableExternalLabel = $false } }) }) 'Test-FortificationCOLLAB011'
    # multi-OU weakest-wins: one OU off -> WARN
    $r.C011_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_external_participants' = @(@{ enableExternalLabel = $true }, @{ enableExternalLabel = $false }) }) }) 'Test-FortificationCOLLAB011'

    # ── COLLAB-012: Meet Host Management (enableHostManagement; true=secure) ──
    $r.C012_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_host_management' = @{ enableHostManagement = $true } }) }) 'Test-FortificationCOLLAB012'
    $r.C012_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_host_management' = @{ enableHostManagement = $false } }) }) 'Test-FortificationCOLLAB012'
    # multi-OU weakest-wins: one OU off -> WARN
    $r.C012_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_host_management' = @(@{ enableHostManagement = $true }, @{ enableHostManagement = $false }) }) }) 'Test-FortificationCOLLAB012'

    # ── Unavailable API -> SKIP ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip011 = St $none 'Test-FortificationCOLLAB011'
    $r.Skip012 = St $none 'Test-FortificationCOLLAB012'

    $r
}

Add-R 'COLLAB-011 label on -> PASS'           ($out.C011_pass -eq 'PASS') ("got=$($out.C011_pass)")
Add-R 'COLLAB-011 label off -> WARN'          ($out.C011_warn -eq 'WARN') ("got=$($out.C011_warn)")
Add-R 'COLLAB-011 weakest OU (off) -> WARN'   ($out.C011_weak -eq 'WARN') ("got=$($out.C011_weak)")
Add-R 'COLLAB-012 host mgmt on -> PASS'       ($out.C012_pass -eq 'PASS') ("got=$($out.C012_pass)")
Add-R 'COLLAB-012 host mgmt off -> WARN'      ($out.C012_warn -eq 'WARN') ("got=$($out.C012_warn)")
Add-R 'COLLAB-012 weakest OU (off) -> WARN'   ($out.C012_weak -eq 'WARN') ("got=$($out.C012_weak)")
Add-R 'Unavailable -> SKIP (011/012)'         ($out.Skip011 -eq 'SKIP' -and $out.Skip012 -eq 'SKIP') ("$($out.Skip011)/$($out.Skip012)")

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
