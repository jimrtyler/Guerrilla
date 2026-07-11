# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#Requires -Version 7.0
<#
.SYNOPSIS
    Regression tests for core fixes surfaced by live-environment validation (v2.9.1):
    AD-1 (Resolve-ADSid caches), AD-2 (New-TierBleedFinding empty collection).
#>

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
Import-Module (Join-Path $PSScriptRoot '..' 'source' 'Guerrilla.psd1') -Force

# Gather everything inside module scope (private functions + $script: caches), then
# assert in script scope where the test helper is visible.
$r = & (Get-Module Guerrilla) {
    $def = @{ id = 'ADTIER-002'; name = 'x'; severity = 'High'; _categoryName = 'TierZero' }
    $hit = [pscustomobject]@{ Group = 'Domain Admins'; SamAccountName = 'svc_veeam'; MatchedKeyword = 'veeam' }

    # MON-4: simulate the monitoring scan-history lifecycle that crashed on run #2.
    $mon4 = @{}
    try {
        # Run 1: no prior state -> 1 entry
        $h1 = Add-ScanHistoryEntry -ExistingHistory $null -Entry @{ scanId = '1'; timestamp = 't1'; highCount = 2 }
        # Round-trip through the same JSON save/load the cmdlets use, then run 2.
        $reloaded = (@{ scanHistory = $h1 } | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable)
        $h2 = Add-ScanHistoryEntry -ExistingHistory $reloaded.scanHistory -Entry @{ scanId = '2'; timestamp = 't2'; highCount = 3 }
        # Collapsed-object case (a 1-element array that serialized as a bare object)
        $collapsed = (@{ scanHistory = @{ scanId = '1'; timestamp = 't1'; highCount = 2 } } | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable)
        $h3 = Add-ScanHistoryEntry -ExistingHistory $collapsed.scanHistory -Entry @{ scanId = '2'; timestamp = 't2'; highCount = 3 }
        $mon4 = @{ Run1 = @($h1).Count; Run2 = @($h2).Count; Collapsed = @($h3).Count; Threw = $false }
    } catch {
        $mon4 = @{ Run1 = 0; Run2 = 0; Collapsed = 0; Threw = $true; Err = "$_" }
    }

    # ADPATH: attack-path engine (Get-ADAttackPath + Test-ReconADPATH001)
    $adpathDef = @{ id = 'ADPATH-001'; name = 'Escalation Paths'; severity = 'Critical'; _categoryName = 'Attack Paths' }
    $aclMock = @{ DangerousACEs = @(
            @{ IdentityReference = 'CORP\HelpDesk'; IdentitySID = 'S-1-5-21-1-2-3-1111'; ActiveDirectoryRights = 'WriteDacl'; ObjectName = 'Domain Root'; ObjectType = $null; IsInherited = $false }
            @{ IdentityReference = 'CORP\svc_app'; IdentitySID = 'S-1-5-21-1-2-3-2222'; ActiveDirectoryRights = 'GenericAll'; ObjectName = 'AdminSDHolder'; ObjectType = $null; IsInherited = $false }
        ) }
    $privMock = @{ PrivilegedGroups = @{ 'Domain Admins' = @(
                @{ SamAccountName = 'Administrator'; SID = 'S-1-5-21-1-2-3-500'; IsGroup = $false }
                @{ SamAccountName = 'ServerAdmins'; SID = 'S-1-5-21-1-2-3-1234'; IsGroup = $true }
            ) } }
    $cleanPriv = @{ PrivilegedGroups = @{ 'Domain Admins' = @(@{ SamAccountName = 'Administrator'; IsGroup = $false }) } }
    $adWithPaths = @{ ACLs = $aclMock; PrivilegedAccounts = $privMock }
    $adpathAll = @((Get-ADAttackPath -AuditData $adWithPaths).Paths)
    $adpath = @{
        Count    = $adpathAll.Count
        NonPriv  = @($adpathAll | Where-Object { -not $_.SourceIsPrivileged }).Count
        Critical = @($adpathAll | Where-Object { $_.Severity -eq 'Critical' }).Count
        Nesting  = @($adpathAll | Where-Object { $_.PathType -eq 'Group nesting' }).Count
        Fail     = (Test-ReconADPATH001 -AuditData $adWithPaths -CheckDefinition $adpathDef).Status
        Pass     = (Test-ReconADPATH001 -AuditData @{ ACLs = @{ DangerousACEs = @() }; PrivilegedAccounts = $cleanPriv } -CheckDefinition $adpathDef).Status
        Skip     = (Test-ReconADPATH001 -AuditData @{} -CheckDefinition $adpathDef).Status
    }

    @{
        SidCacheInit = ($null -ne $script:SidCache)
        AdPath       = $adpath
        WkSids       = $script:WellKnownSids.Count
        WkRids       = $script:WellKnownRids.Count
        Sys          = (Resolve-ADSid -SidString 'S-1-5-18')
        Admins       = (Resolve-ADSid -SidString 'S-1-5-32-544')
        Dom512       = (Resolve-ADSid -SidString 'S-1-5-21-1-2-3-512')
        TierEmpty    = (New-TierBleedFinding -CheckDefinition $def -Hits @() -ProductLabel 'Veeam').Status
        TierHit      = (New-TierBleedFinding -CheckDefinition $def -Hits @($hit) -ProductLabel 'Veeam').Status
        Mon4         = $mon4
    }
}

$pass = 0; $fail = 0
function Test-Case { param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host "  [PASS] $Name" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "  [FAIL] $Name" -ForegroundColor Red; $script:fail++ }
}

Write-Host "`n  Core fix regression tests`n  =========================" -ForegroundColor Cyan
Test-Case 'AD-1: $script:SidCache is initialized'        $r.SidCacheInit
Test-Case 'AD-1: WellKnownSids populated'                ($r.WkSids -gt 0)
Test-Case 'AD-1: WellKnownRids populated'                ($r.WkRids -gt 0)
Test-Case 'AD-1: Resolve-ADSid S-1-5-18 -> SYSTEM'       ($r.Sys -eq 'SYSTEM')
Test-Case 'AD-1: Resolve-ADSid builtin admins'           ($r.Admins -eq 'Administrators')
Test-Case 'AD-1: Resolve-ADSid domain RID 512'           ($r.Dom512 -eq 'Domain Admins')
Test-Case 'AD-2: New-TierBleedFinding @() -> PASS'       ($r.TierEmpty -eq 'PASS')
Test-Case 'AD-2: New-TierBleedFinding with a hit -> FAIL' ($r.TierHit -eq 'FAIL')
Test-Case 'MON-4: scan-history second run does not throw' (-not $r.Mon4.Threw)
Test-Case 'MON-4: run 1 -> 1 entry'                       ($r.Mon4.Run1 -eq 1)
Test-Case 'MON-4: run 2 (after JSON round-trip) -> 2'     ($r.Mon4.Run2 -eq 2)
Test-Case 'MON-4: collapsed single-object history -> 2'  ($r.Mon4.Collapsed -eq 2)
Test-Case 'ADPATH: 3 paths derived (2 control + 1 nesting)' ($r.AdPath.Count -eq 3)
Test-Case 'ADPATH: all 3 from non-privileged sources'    ($r.AdPath.NonPriv -eq 3)
Test-Case 'ADPATH: 2 Critical (object control)'          ($r.AdPath.Critical -eq 2)
Test-Case 'ADPATH: 1 group-nesting pivot'                ($r.AdPath.Nesting -eq 1)
Test-Case 'ADPATH: check FAILs when paths exist'         ($r.AdPath.Fail -eq 'FAIL')
Test-Case 'ADPATH: check PASSes with no dangerous ACEs'  ($r.AdPath.Pass -eq 'PASS')
Test-Case 'ADPATH: check SKIPs when no ACL data'         ($r.AdPath.Skip -eq 'SKIP')

Write-Host "`n  Summary: $pass passed, $fail failed`n" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
Write-Host "  RESULT: ALL CHECKS PASSED" -ForegroundColor Green
