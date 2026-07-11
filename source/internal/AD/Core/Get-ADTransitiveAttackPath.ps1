# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Transitive attack-path engine. Where Get-ADAttackPath (ADPATH-001) reports single-hop
# control of a Tier-0 object, this chains control + group-membership edges of ARBITRARY
# length to find the shortest path from a non-privileged principal to Tier-0:
#   HelpDesk --[WriteDacl]--> CORP-Admins --[MemberOf]--> Domain Admins
# The graph is directed and every edge points "toward more privilege": A -> B means
# controlling (or being) A lets an attacker reach B's position. BFS gives the shortest chain.
#
# Path DEPTH is bounded by the collected ACL coverage: today Guerrilla collects ACLs on the
# six critical Tier-0 objects only, so most chains are 1 hop. The full-domain ACL collector
# (roadmap, live-gated) populates control edges over arbitrary objects and unlocks deep chains;
# this engine consumes them unchanged. The resolver below is validated for arbitrary depth.

function Resolve-AttackPathGraph {
    <#
    .SYNOPSIS
        Pure transitive shortest-path resolver over a directed privilege graph.
    .DESCRIPTION
        BFS from each source to the nearest Tier-0 target. Returns one shortest chain per source
        (fewest hops). Cycle-safe (visited set) and depth-bounded (MaxDepth).
    .PARAMETER Adjacency
        Hashtable: nodeKey -> @( @{ To=<nodeKey>; Edge=<label>; Technique=<text> }, ... ).
    .PARAMETER Targets
        Hashtable: nodeKey -> <target label>. Reaching any of these completes a path.
    .PARAMETER Sources
        Node keys to compute paths FROM (targets among them are skipped).
    .PARAMETER MaxDepth
        Maximum chain length to search. Default 10.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Adjacency = @{},
        [hashtable]$Targets = @{},
        [string[]]$Sources = @(),
        [int]$MaxDepth = 10
    )
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($src in (@($Sources) | Select-Object -Unique)) {
        if (-not $src -or $Targets.ContainsKey($src)) { continue }
        $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [void]$visited.Add($src)
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue([PSCustomObject]@{ Node = $src; Hops = @() })
        $found = $null
        while ($queue.Count -gt 0 -and -not $found) {
            $cur = $queue.Dequeue()
            if (@($cur.Hops).Count -ge $MaxDepth) { continue }
            foreach ($edge in @($Adjacency[$cur.Node])) {
                $to = [string]$edge.To
                if (-not $to) { continue }
                $newHops = @($cur.Hops) + @([PSCustomObject]@{ From = $cur.Node; To = $to; Edge = "$($edge.Edge)"; Technique = "$($edge.Technique)" })
                if ($Targets.ContainsKey($to)) {
                    $found = [PSCustomObject]@{ Source = $src; Target = $to; TargetLabel = $Targets[$to]; Hops = @($newHops); Length = @($newHops).Count }
                    break
                }
                if ($visited.Add($to)) {
                    $queue.Enqueue([PSCustomObject]@{ Node = $to; Hops = @($newHops) })
                }
            }
        }
        if ($found) { $results.Add($found) }
    }
    return @($results)
}

function Get-ADTransitiveAttackPath {
    <#
    .SYNOPSIS
        Builds the AD privilege graph from collected recon data and returns transitive paths to Tier-0.
    .DESCRIPTION
        Edge sources: dangerous ACEs (principal -> controlled object) and privileged-group
        membership (member -> group). Targets: the six critical Tier-0 objects + the Tier-0 groups.
        Default/by-design principals are excluded as path sources. Returns { DataAvailable; Paths }.
    #>
    [CmdletBinding()]
    param([hashtable]$AuditData)

    $notCollected = [PSCustomObject]@{ DataAvailable = $false; Paths = @() }
    $acl  = $AuditData.ACLs
    $priv = $AuditData.PrivilegedAccounts
    $haveAcl  = [bool]($acl -and (-not ($acl -is [System.Collections.IDictionary]) -or $acl.Contains('DangerousACEs')))
    $havePriv = [bool]($priv -and $priv.PrivilegedGroups)
    if (-not $haveAcl -and -not $havePriv) { return $notCollected }

    # Final-hop impact per critical Tier-0 object (reused intent from Get-ADAttackPath).
    $impactByObject = @{
        'domain root'             = 'the domain (DCSync every hash) — Domain Admin equivalent'
        'adminsdholder'           = 'all protected groups via SDProp — persistent Tier-0 control'
        'domain controllers ou'   = 'every Domain Controller (malicious GPO -> SYSTEM)'
        'gpo container'           = 'any host where a controlled GPO is linked'
        'configuration container' = 'the forest configuration partition — forest compromise'
        'schema container'        = 'the AD schema — forest-wide persistent control'
    }
    $tier0Groups = @('domain admins', 'enterprise admins', 'schema admins', 'administrators')

    $norm = { param($s) (("$s" -split '\\')[-1]).Trim().ToLower() }

    $adjacency = @{}
    $addEdge = {
        param($from, $to, $edge, $tech)
        if (-not $adjacency.ContainsKey($from)) { $adjacency[$from] = [System.Collections.Generic.List[object]]::new() }
        $adjacency[$from].Add(@{ To = $to; Edge = $edge; Technique = $tech })
    }

    $targets = @{}
    foreach ($o in $impactByObject.Keys) { $targets["obj:$o"] = $impactByObject[$o] }
    foreach ($g in $tier0Groups) { $targets["grp:$g"] = "$g (Tier-0 group)" }

    # Privileged membership: which principals are already Tier-0 (to flag non-privileged sources).
    $privSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $privNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $sourceSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $displayOf = @{}

    # ── Control edges from dangerous ACEs ──
    if ($haveAcl) {
        foreach ($ace in @($acl.DangerousACEs)) {
            $principal = "$($ace.IdentityReference ?? $ace.IdentitySID)"
            if (-not $principal) { continue }
            $sid = "$($ace.IdentitySID)"
            if (Test-DefaultControlPrincipal -Sid $sid -IdentityReference $principal) { continue }
            $right = if ($ace.ObjectType -and "$($ace.ActiveDirectoryRights)" -match 'ExtendedRight|WriteProperty') { "$($ace.ObjectType)" } else { "$($ace.ActiveDirectoryRights)" }
            $objName = (& $norm $ace.ObjectName)
            $fromKey = "prn:$(& $norm $principal)"
            $displayOf[$fromKey] = $principal
            if ($impactByObject.ContainsKey($objName)) {
                $toKey = "obj:$objName"
            } elseif ("$($ace.ObjectClass)" -match '(?i)group') {
                $toKey = "grp:$objName"          # control over an (arbitrary) group — full-domain-collector edge
            } else {
                $toKey = "node:$objName"          # control over some other object
            }
            & $addEdge $fromKey $toKey $right $null
            [void]$sourceSet.Add($fromKey)
        }
    }

    # ── Membership edges (member -> group); Tier-0 groups are targets ──
    if ($havePriv) {
        foreach ($entry in $priv.PrivilegedGroups.GetEnumerator()) {
            $gName = (& $norm $entry.Key)
            foreach ($m in @($entry.Value)) {
                $sam = "$($m.SamAccountName)"
                if (-not $sam) { continue }
                if ($m.SID) { [void]$privSids.Add("$($m.SID)") }
                [void]$privNames.Add((& $norm $sam))
                $mKey = if ($m.IsGroup) { "grp:$(& $norm $sam)" } else { "prn:$(& $norm $sam)" }
                $displayOf[$mKey] = $sam
                & $addEdge $mKey "grp:$gName" 'MemberOf' "member of $($entry.Key)"
                # A nested non-default group is itself an escalation surface -> consider it a source.
                if ($m.IsGroup -and -not (Test-DefaultControlPrincipal -Sid "$($m.SID)" -IdentityReference $sam)) {
                    [void]$sourceSet.Add($mKey)
                }
            }
        }
    }

    if ($sourceSet.Count -eq 0) { return [PSCustomObject]@{ DataAvailable = $true; Paths = @() } }

    $raw = Resolve-AttackPathGraph -Adjacency $adjacency -Targets $targets -Sources @($sourceSet)

    $paths = foreach ($r in $raw) {
        $srcKey = $r.Source
        $srcName = $displayOf[$srcKey] ?? ($srcKey -replace '^(prn|grp|obj|node):', '')
        $isPriv = ($privSids.Count -gt 0 -and $false) -or $privNames.Contains(($srcName -split '\\')[-1].ToLower()) -or (Test-DefaultPrivilegedPrincipal -Sid '' -IdentityReference $srcName)
        $chain = @($r.Hops | ForEach-Object {
            $f = $displayOf[$_.From] ?? ($_.From -replace '^(prn|grp|obj|node):', '')
            $t = $displayOf[$_.To] ?? ($_.To -replace '^(prn|grp|obj|node):', '')
            "$f --[$($_.Edge)]--> $t"
        }) -join '  ==>  '
        [PSCustomObject]@{
            PSTypeName         = 'Guerrilla.TransitiveAttackPath'
            Source             = $srcName
            SourceIsPrivileged = [bool]$isPriv
            Length             = $r.Length
            ReachesTier0       = $r.TargetLabel
            Hops               = $r.Hops
            PathType           = if ($r.Length -gt 1) { 'Transitive' } else { 'Object control' }
            Severity           = 'Critical'
            Path               = "$chain  =>  reaches $($r.TargetLabel)"
        }
    }

    # Non-privileged sources first, then by shortest chain.
    $sorted = @($paths | Sort-Object `
        @{ Expression = { if ($_.SourceIsPrivileged) { 1 } else { 0 } } }, `
        @{ Expression = { $_.Length } }, `
        Source)
    return [PSCustomObject]@{ DataAvailable = $true; Paths = $sorted }
}
