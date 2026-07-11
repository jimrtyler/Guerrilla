# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Full-domain ACL collector: Test-AceGrantsDangerousControl (pure dangerous-ACE predicate) and the
# emitted ACE shape (ObjectClass + ObjectSID + ObjectName) that lets the transitive engine form
# deep chains and the BloodHound export key targets by SID. The live LDAP sweep itself is
# Windows/AD-only; this validates the offline contract that matters. Run:
#   pwsh -File Tests/verify-fulldomain-acl.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

# ── Private-scope tests: predicate + collector wiring + engine integration ──
$out = & $mod {
    $r = @{}
    $G = @{
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Member'
        '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    }
    $T = { param($rights, $guid, $act) Test-AceGrantsDangerousControl -Rights $rights -ObjectTypeGuid $guid -AccessControlType ($act ?? 'Allow') -DangerousGuids $G }

    $r.GenericAll      = (& $T 'GenericAll' $null $null) -eq $true
    $r.WriteDacl       = (& $T 'WriteDacl' $null $null) -eq $true
    $r.WriteOwner      = (& $T 'WriteOwner' $null $null) -eq $true
    $r.GenericWrite    = (& $T 'GenericWrite' $null $null) -eq $true
    $r.ReadIsSafe      = (& $T 'ReadProperty, GenericRead' $null $null) -eq $false
    $r.AllExtRights    = (& $T 'ExtendedRight' $null $null) -eq $true          # no GUID = all rights
    $r.DangerousExt    = (& $T 'ExtendedRight' '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' $null) -eq $true
    $r.BenignExt       = (& $T 'ExtendedRight' '00000000-0000-0000-0000-000000000099' $null) -eq $false
    $r.MemberWrite     = (& $T 'WriteProperty' 'bf9679c0-0de6-11d0-a285-00aa003049e2' $null) -eq $true
    $r.BenignPropWrite = (& $T 'WriteProperty' '00000000-0000-0000-0000-000000000099' $null) -eq $false
    $r.DenyIsSafe      = (& $T 'GenericAll' $null 'Deny') -eq $false

    # Collector is dot-sourced and present
    $r.CollectorPresent = [bool](Get-Command Get-ADFullDomainAcl -ErrorAction SilentlyContinue)

    # ── Integration: a full-domain ACE (with ObjectClass=group + ObjectSID) forms a 2-hop chain ──
    # low-priv HelpDesk --GenericAll--> CORP-Helpdesk-Admins --MemberOf--> Domain Admins
    $fdAce = [PSCustomObject]@{
        IdentityReference = 'CORP\HelpDesk'; IdentitySID = 'S-1-5-21-1-2-3-1234'
        ActiveDirectoryRights = 'GenericAll'; ObjectType = $null
        ObjectClass = 'group'; ObjectName = 'CORP-Helpdesk-Admins'
        ObjectSID = 'S-1-5-21-1-2-3-1300'; Source = 'FullDomain'
    }
    $audit = @{
        ACLs = @{ DangerousACEs = @($fdAce); FullDomainScanned = $true }
        PrivilegedAccounts = @{ PrivilegedGroups = @{
            'Domain Admins' = @(
                [PSCustomObject]@{ IsGroup = $true;  SamAccountName = 'CORP-Helpdesk-Admins'; SID = 'S-1-5-21-1-2-3-1300' }
            )
        } }
    }
    $tp = Get-ADTransitiveAttackPath -AuditData $audit
    $chain = @($tp.Paths | Where-Object { $_.Source -eq 'CORP\HelpDesk' })
    $r.ChainForms     = ($tp.DataAvailable -and $chain.Count -eq 1)
    $r.ChainIsMultiHop = ($chain.Count -eq 1 -and $chain[0].Length -eq 2)
    $r.ChainReachesDA  = ($chain.Count -eq 1 -and $chain[0].ReachesTier0 -match 'domain admins')

    # ── Regression guard: WITHOUT ObjectClass the target is not a group node, so NO chain forms ──
    # (this is exactly the bug the new collector fixes by emitting ObjectClass)
    $fdAceNoClass = [PSCustomObject]@{
        IdentityReference = 'CORP\HelpDesk'; IdentitySID = 'S-1-5-21-1-2-3-1234'
        ActiveDirectoryRights = 'GenericAll'; ObjectName = 'CORP-Helpdesk-Admins'
    }
    $audit2 = @{
        ACLs = @{ DangerousACEs = @($fdAceNoClass) }
        PrivilegedAccounts = $audit.PrivilegedAccounts
    }
    $tp2 = Get-ADTransitiveAttackPath -AuditData $audit2
    $r.NoClassNoChain = (@($tp2.Paths | Where-Object { $_.Source -eq 'CORP\HelpDesk' }).Count -eq 0)

    $r
}

foreach ($k in $out.Keys) { Add-R $k $out[$k] '' }

# ── Public-scope: BloodHound export keys the full-domain target node by its SID ──
$bhAudit = @{
    ACLs = @{ DangerousACEs = @(
        [PSCustomObject]@{
            IdentityReference = 'CORP\HelpDesk'; IdentitySID = 'S-1-5-21-1-2-3-1234'
            ActiveDirectoryRights = 'GenericAll'; ObjectClass = 'group'
            ObjectName = 'CORP-Helpdesk-Admins'; ObjectSID = 'S-1-5-21-1-2-3-1300'; Source = 'FullDomain'
        }
    ) }
}
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-fd-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".json")
try {
    $res = Export-BloodHoundData -AuditData $bhAudit -OutputPath $tmp
    $json = Get-Content $tmp -Raw | ConvertFrom-Json
    $tgt = @($json.graph.nodes | Where-Object { $_.id -eq 'S-1-5-21-1-2-3-1300' })
    Add-R 'BH target node keyed by ObjectSID' ($tgt.Count -eq 1) ("got=$($tgt.Count)")
    $edge = @($json.graph.edges | Where-Object { $_.start.value -eq 'S-1-5-21-1-2-3-1234' -and $_.end.value -eq 'S-1-5-21-1-2-3-1300' -and $_.kind -eq 'GenericAll' })
    Add-R 'BH GenericAll edge principal->target SID' ($edge.Count -eq 1) ("got=$($edge.Count)")
}
finally { Remove-Item $tmp -ErrorAction SilentlyContinue }

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
