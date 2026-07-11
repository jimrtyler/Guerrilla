# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Regression for the v2.10.1 ADPATH-001 false-positive report: the engine must NOT
# report default infrastructure/admin principals (DC groups, Enterprise DCs, RODCs,
# Schema Admins) as escalation paths, must flag Azure AD Connect MSOL_* accounts as
# Expected (out of the non-privileged count), and must keep genuine custom paths.
# Run: pwsh -File Tests\verify-adpath-fix.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$dom = 'S-1-5-21-1111111111-2222222222-3333333333'
$ace = {
    param($name, $sid, $rights, $obj, $otype)
    [PSCustomObject]@{ IdentityReference = $name; IdentitySID = $sid; ActiveDirectoryRights = $rights
        ObjectName = $obj; ObjectType = $otype; ObjectTypeGUID = $null; IsInherited = $false }
}

$audit = @{
    ACLs = @{ DangerousACEs = @(
        # --- default principals that legitimately hold control: must be EXCLUDED ---
        (& $ace 'CONTOSO\Domain Controllers'                   "$dom-516" 'ExtendedRight' 'Domain Root' 'DS-Replication-Get-Changes-All')
        (& $ace 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS' 'S-1-5-9'  'ExtendedRight' 'Domain Root' 'DS-Replication-Get-Changes')
        (& $ace 'CONTOSO\Enterprise Read-only Domain Controllers' "$dom-498" 'ExtendedRight' 'Domain Root' 'DS-Replication-Get-Changes')
        (& $ace 'CONTOSO\Schema Admins'                        "$dom-518" 'WriteDacl'     'Schema Container' $null)
        # localized name but RID 516 — SID match must still exclude it
        (& $ace 'CONTOSO\Contrôleurs de domaine'             "$dom-516" 'ExtendedRight' 'Domain Root' 'DS-Replication-Get-Changes')
        # --- Azure AD Connect sync account: real DCSync but EXPECTED ---
        (& $ace 'CONTOSO\MSOL_a1b2c3d4e5f6'                    "$dom-1145" 'ExtendedRight' 'Domain Root' 'DS-Replication-Get-Changes-All')
        # --- genuine custom escalation paths: must be KEPT, non-privileged ---
        (& $ace 'CONTOSO\Exchange Recipient Administrators'    "$dom-1146" 'GenericAll'    'Domain Root' $null)
        (& $ace 'CONTOSO\HelpDesk'                             "$dom-1147" 'WriteDacl'     'AdminSDHolder' $null)
    ) }
    PrivilegedAccounts = @{ PrivilegedGroups = @{
        'Domain Admins'   = @(@{ IsGroup = $false; SamAccountName = 'Administrator'; SID = "$dom-500" })
        'Server Operators' = @(@{ IsGroup = $true; SamAccountName = 'ItTech';   SID = "$dom-1200" })   # genuine nesting
        'Print Operators'  = @(@{ IsGroup = $true; SamAccountName = 'OMTeacher'; SID = "$dom-1201" })  # genuine nesting
    } }
}

# Run the engine + the check inside module scope.
$res = & $mod {
    param($AuditData)
    $a = Get-ADAttackPath -AuditData $AuditData
    $defs = Get-AuditCategoryDefinitions -Category 'ADAttackPathChecks'
    $check = $defs.checks | Where-Object id -eq 'ADPATH-001'
    $finding = Test-ReconADPATH001 -AuditData $AuditData -CheckDefinition $check
    [PSCustomObject]@{ Paths = $a.Paths; Finding = $finding }
} $audit

$paths = @($res.Paths)
$f = $res.Finding
$sources = @($paths | ForEach-Object { $_.Source })
$genuine = @($paths | Where-Object { -not $_.Expected })
$nonPriv = @($genuine | Where-Object { -not $_.SourceIsPrivileged })
$expected = @($paths | Where-Object { $_.Expected })

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

Add-R 'Domain Controllers (516) excluded'        (-not ($sources -match 'Domain Controllers')) ''
Add-R 'Enterprise Domain Controllers excluded'   (-not ($sources -match 'ENTERPRISE DOMAIN CONTROLLERS')) ''
Add-R 'Enterprise RODC (498) excluded'           (-not ($sources -match 'Read-only Domain Controllers')) ''
Add-R 'Schema Admins (518) excluded'             (-not ($sources -match 'Schema Admins')) ''
Add-R 'Localized DC name excluded by SID'        (-not ($sources -match 'Contrôleurs')) ''
Add-R 'MSOL flagged Expected'                    ($expected.Count -eq 1 -and $expected[0].Source -match 'MSOL_') ("expected: " + ($expected | ForEach-Object Source))
Add-R 'MSOL marked SourceIsPrivileged'           ($expected.Count -eq 1 -and $expected[0].SourceIsPrivileged) ''
Add-R 'Exchange Recipient Administrators kept'   ($sources -match 'Exchange Recipient Administrators') ''
Add-R 'HelpDesk kept'                            ($sources -match 'HelpDesk') ''
Add-R 'ItTech nesting kept'                      ($sources -contains 'ItTech') ''
Add-R 'OMTeacher nesting kept'                   ($sources -contains 'OMTeacher') ''
Add-R 'Genuine path count == 4'                  ($genuine.Count -eq 4) ("genuine=$($genuine.Count): " + ($genuine.Source -join ', '))
Add-R 'NonPrivileged genuine == 4'               ($nonPriv.Count -eq 4) ("nonpriv=$($nonPriv.Count)")
Add-R 'Check FAIL'                               ($f.Status -eq 'FAIL') ("status=$($f.Status)")
Add-R 'Check PathCount(genuine) == 4'            ($f.Details.PathCount -eq 4) ("pathcount=$($f.Details.PathCount)")
Add-R 'Check NonPrivilegedCount == 4'            ($f.Details.NonPrivilegedCount -eq 4) ("nonpriv=$($f.Details.NonPrivilegedCount)")
Add-R 'Check ExpectedCount == 1'                 ($f.Details.ExpectedCount -eq 1) ("expected=$($f.Details.ExpectedCount)")
Add-R 'Headline does not lead with a built-in'   ($f.CurrentValue -notmatch '^\d+ escalation.*(Domain Controllers|Schema Admins|ENTERPRISE)') ''
Add-R 'Headline mentions expected service acct'  ($f.CurrentValue -match 'expected service-account') ''

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($r.Name)"
    if ($r.Detail) { $line += "  ($($r.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  Headline: $($f.CurrentValue.Substring(0, [Math]::Min(160, $f.CurrentValue.Length)))..."
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
