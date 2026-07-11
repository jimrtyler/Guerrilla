# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Transitive attack-path engine: Resolve-AttackPathGraph (pure BFS shortest-path, multi-hop,
# cycle-safe, depth-bounded) and Get-ADTransitiveAttackPath (builds the AD graph from recon
# data and chains control + membership edges to Tier-0). Run: pwsh -File Tests/verify-transitive-attackpath.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$out = & $mod {
    $r = @{}

    # ── Pure resolver ──
    # 3-hop chain A->B->C->T
    $adj = @{ 'A' = @(@{To='B';Edge='ctrl'}); 'B' = @(@{To='C';Edge='ctrl'}); 'C' = @(@{To='T';Edge='memberOf'}) }
    $p = Resolve-AttackPathGraph -Adjacency $adj -Targets @{ 'T'='Tier0' } -Sources @('A')
    $r.ThreeHopFound  = (@($p).Count -eq 1)
    $r.ThreeHopLen    = (@($p)[0].Length)

    # shortest path wins (A->T direct AND A->B->T)
    $adj2 = @{ 'A' = @(@{To='B';Edge='x'}, @{To='T';Edge='x'}); 'B' = @(@{To='T';Edge='x'}) }
    $r.ShortestLen = (@(Resolve-AttackPathGraph -Adjacency $adj2 -Targets @{'T'='t'} -Sources @('A'))[0].Length)

    # no path
    $r.NoPath = (@(Resolve-AttackPathGraph -Adjacency @{ 'X'=@(@{To='Y';Edge='x'}) } -Targets @{'T'='t'} -Sources @('X')).Count -eq 0)

    # cycle-safe (P<->Q, no target)
    $r.CycleSafe = (@(Resolve-AttackPathGraph -Adjacency @{ 'P'=@(@{To='Q';Edge='x'}); 'Q'=@(@{To='P';Edge='x'}) } -Targets @{'T'='t'} -Sources @('P')).Count -eq 0)

    # depth cap (chain length 3, MaxDepth 2 -> no result)
    $r.DepthCap = (@(Resolve-AttackPathGraph -Adjacency $adj -Targets @{'T'='t'} -Sources @('A') -MaxDepth 2).Count -eq 0)

    # source that is itself a target -> skipped
    $r.TargetSourceSkipped = (@(Resolve-AttackPathGraph -Adjacency $adj -Targets @{'A'='t'} -Sources @('A')).Count -eq 0)

    # ── Wrapper: build graph from synthetic recon data ──
    $audit = @{
        ACLs = @{ DangerousACEs = @(
            # non-priv principal controls an ARBITRARY group (full-domain-collector-style edge)
            [PSCustomObject]@{ IdentityReference = 'CORP\HelpDesk'; IdentitySID = 'S-1-5-21-1-2-3-1147'; ObjectName = 'CORP-Admins'; ObjectClass = 'group'; ActiveDirectoryRights = 'GenericAll' }
            # non-priv principal directly controls a Tier-0 object (1-hop)
            [PSCustomObject]@{ IdentityReference = 'CORP\AppTeam'; IdentitySID = 'S-1-5-21-1-2-3-1148'; ObjectName = 'AdminSDHolder'; ActiveDirectoryRights = 'WriteDacl' }
            # default principal (RID 516) controlling Domain Root -> must be excluded
            [PSCustomObject]@{ IdentityReference = 'CORP\Domain Controllers'; IdentitySID = 'S-1-5-21-1-2-3-516'; ObjectName = 'Domain Root'; ActiveDirectoryRights = 'ExtendedRight' }
        ) }
        PrivilegedAccounts = @{ PrivilegedGroups = @{
            'Domain Admins' = @(
                [PSCustomObject]@{ IsGroup = $true;  SamAccountName = 'CORP-Admins'; SID = 'S-1-5-21-1-2-3-1200' }  # nested group in DA
                [PSCustomObject]@{ IsGroup = $false; SamAccountName = 'Administrator'; SID = 'S-1-5-21-1-2-3-500' }
            )
        } }
    }
    $res = Get-ADTransitiveAttackPath -AuditData $audit
    $r.DataAvail = $res.DataAvailable
    $paths = @($res.Paths)
    $r.PathCount = $paths.Count
    # HelpDesk -> CORP-Admins -> Domain Admins (2-hop transitive)
    $hd = @($paths | Where-Object { $_.Source -match 'HelpDesk' })
    $r.HelpDeskTransitive = ($hd.Count -eq 1 -and $hd[0].Length -eq 2 -and $hd[0].PathType -eq 'Transitive' -and $hd[0].ReachesTier0 -match 'domain admins')
    $r.HelpDeskNotPriv    = ($hd.Count -eq 1 -and -not $hd[0].SourceIsPrivileged)
    # AppTeam -> AdminSDHolder (1-hop object control)
    $at = @($paths | Where-Object { $_.Source -match 'AppTeam' })
    $r.AppTeamOneHop = ($at.Count -eq 1 -and $at[0].Length -eq 1)
    # default principal excluded as a source
    $r.DefaultExcluded = (@($paths | Where-Object { $_.Source -match 'Domain Controllers' }).Count -eq 0)

    # DataAvailable false on empty input
    $r.EmptyNotCollected = ((Get-ADTransitiveAttackPath -AuditData @{}).DataAvailable -eq $false)

    $r
}

Add-R 'Resolver: 3-hop chain found'             ($out.ThreeHopFound) ""
Add-R 'Resolver: 3-hop length = 3'              ($out.ThreeHopLen -eq 3) ("got=$($out.ThreeHopLen)")
Add-R 'Resolver: shortest path wins (len 1)'    ($out.ShortestLen -eq 1) ("got=$($out.ShortestLen)")
Add-R 'Resolver: no path -> empty'              ($out.NoPath) ""
Add-R 'Resolver: cycle-safe (terminates)'       ($out.CycleSafe) ""
Add-R 'Resolver: depth cap honored'             ($out.DepthCap) ""
Add-R 'Resolver: target-as-source skipped'      ($out.TargetSourceSkipped) ""
Add-R 'Wrapper: data available'                 ($out.DataAvail) ""
Add-R 'Wrapper: HelpDesk 2-hop TRANSITIVE -> DA' ($out.HelpDeskTransitive) ""
Add-R 'Wrapper: HelpDesk flagged non-privileged' ($out.HelpDeskNotPriv) ""
Add-R 'Wrapper: AppTeam 1-hop object control'   ($out.AppTeamOneHop) ""
Add-R 'Wrapper: default principal excluded'     ($out.DefaultExcluded) ""
Add-R 'Wrapper: empty input -> DataAvailable false' ($out.EmptyNotCollected) ""

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
