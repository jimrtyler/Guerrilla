# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-BloodHoundData {
    <#
    .SYNOPSIS
        Exports Guerrilla's collected Active Directory graph to a BloodHound OpenGraph file.

    .DESCRIPTION
        Turns the privileged-group membership and dangerous-ACL data Guerrilla already collects
        into a BloodHound CE OpenGraph import (nodes + edges) so an operator can pathfind the
        full attack surface in BloodHound. Edges use BloodHound's NATIVE kinds (GenericAll,
        WriteDacl, WriteOwner, GenericWrite, AllExtendedRights, GetChanges, GetChangesAll,
        MemberOf), and nodes carry their SID as objectid, so the import overlays cleanly with
        native SharpHound data and BloodHound's built-in path queries work over it.

        Unlike the in-report attack-path engine, this export includes the FULL graph (it does NOT
        drop by-design / default principals) — BloodHound performs its own reachability analysis,
        so it needs the complete edge set.

        Output is the OpenGraph shape:
          { "metadata": { "source_kind": "Guerrilla" },
            "graph": { "nodes": [ { id, kinds, properties } ],
                       "edges": [ { start:{value}, end:{value}, kind, properties } ] } }

        Note: depth/coverage tracks Guerrilla's ACL collection — today the six critical Tier-0
        objects plus privileged-group membership. The full-domain ACL collector (roadmap) widens
        the exported edge set; this exporter consumes it unchanged.

    .PARAMETER AuditData
        The collected reconnaissance data (hashtable with ACLs.DangerousACEs and
        PrivilegedAccounts.PrivilegedGroups).

    .PARAMETER OutputPath
        Destination .json path. Default: ./Guerrilla-BloodHound.json.

    .EXAMPLE
        Export-BloodHoundData -AuditData $reconData -OutputPath .\corp-bh.json
        # Then in BloodHound CE: Administration > File Ingest > upload corp-bh.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OutputPath = (Join-Path (Get-Location) 'Guerrilla-BloodHound.json')
    )

    $nodes = @{}   # id -> node object (dedup by id)
    $edges = [System.Collections.Generic.List[object]]::new()
    $edgeSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $idFor = { param($name, $sid) if ($sid) { "$sid".ToUpper() } else { ("NAME:" + ("$name").Trim().ToUpper()) } }

    # Derive the domain SID from any domain-relative member/principal SID we hold, so well-known
    # privileged groups (whose own SID isn't on the membership key) can be keyed by their real SID
    # and overlay SharpHound's nodes instead of landing as parallel NAME:<group> nodes.
    $domainSid = $null
    $sidPool = @()
    if ($AuditData.PrivilegedAccounts.PrivilegedGroups) {
        foreach ($e in $AuditData.PrivilegedAccounts.PrivilegedGroups.GetEnumerator()) {
            foreach ($m in @($e.Value)) { if ($m.SID) { $sidPool += "$($m.SID)" } }
        }
    }
    foreach ($ace in @($AuditData.ACLs.DangerousACEs)) { if ($ace.IdentitySID) { $sidPool += "$($ace.IdentitySID)" }; if ($ace.ObjectSID) { $sidPool += "$($ace.ObjectSID)" } }
    foreach ($s in $sidPool) { if ("$s" -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { $domainSid = $Matches[1]; break } }

    # Built-in alias SIDs (constant) + domain-relative well-known RIDs.
    $builtinAlias = @{
        'administrators' = 'S-1-5-32-544'; 'account operators' = 'S-1-5-32-548'; 'server operators' = 'S-1-5-32-549'
        'print operators' = 'S-1-5-32-550'; 'backup operators' = 'S-1-5-32-551'; 'remote desktop users' = 'S-1-5-32-555'
        'network configuration operators' = 'S-1-5-32-556'; 'pre-windows 2000 compatible access' = 'S-1-5-32-554'
    }
    $wellKnownRid = @{
        'domain admins' = 512; 'enterprise admins' = 519; 'schema admins' = 518; 'domain controllers' = 516
        'cert publishers' = 517; 'group policy creator owners' = 520; 'read-only domain controllers' = 521
        'enterprise read-only domain controllers' = 498; 'key admins' = 526; 'enterprise key admins' = 527
        'administrator' = 500; 'krbtgt' = 502
    }
    $resolveWellKnownSid = {
        param($name)
        $n = ("$name" -split '\\')[-1].Trim().ToLower()
        if ($builtinAlias.ContainsKey($n)) { return $builtinAlias[$n] }
        if ($domainSid -and $wellKnownRid.ContainsKey($n)) { return "$domainSid-$($wellKnownRid[$n])" }
        return $null
    }

    $kindForObject = {
        param($objClass, $objName)
        $oc = "$objClass".ToLower(); $on = "$objName".ToLower()
        if ($oc -match 'group') { return 'Group' }
        if ($oc -match 'computer') { return 'Computer' }
        if ($oc -match 'user') { return 'User' }
        if ($oc -match 'organizationalunit' -or $on -match ' ou$|controllers ou') { return 'OU' }
        if ($oc -match 'grouppolicy' -or $on -match 'gpo|policies') { return 'GPO' }
        if ($on -eq 'domain root' -or $oc -match 'domaindns') { return 'Domain' }
        return 'Base'
    }
    $kindForMember = { param($isGroup, $sam) if ($isGroup) { 'Group' } elseif ("$sam" -match '\$$') { 'Computer' } else { 'User' } }

    $addNode = {
        param($id, $name, $kind, $sid)
        if (-not $id) { return }
        if (-not $nodes.ContainsKey($id)) {
            $props = @{ name = ("$name").ToUpper() }
            if ($sid) { $props['objectid'] = "$sid".ToUpper() }
            $nodes[$id] = [PSCustomObject]@{ id = $id; kinds = @($kind, 'Base'); properties = $props }
        }
    }
    $addEdge = {
        param($startId, $endId, $kind)
        if (-not $startId -or -not $endId -or $startId -eq $endId) { return }
        $k = "$startId|$endId|$kind"
        if (-not $edgeSeen.Add($k)) { return }
        $edges.Add([PSCustomObject]@{
            start      = @{ value = $startId }
            end        = @{ value = $endId }
            kind       = $kind
            properties = @{ source = 'Guerrilla' }
        })
    }

    # ── Membership edges (member -> group, kind MemberOf) ──
    if ($AuditData.PrivilegedAccounts -and $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        foreach ($entry in $AuditData.PrivilegedAccounts.PrivilegedGroups.GetEnumerator()) {
            $gName = "$($entry.Key)"
            # Resolve the group's real SID where it's a well-known privileged group, so the node
            # overlays SharpHound's SID-keyed equivalent instead of a parallel NAME: node.
            $gSid = (& $resolveWellKnownSid $gName)
            $gId = (& $idFor $gName $gSid)
            & $addNode $gId $gName 'Group' $gSid
            foreach ($m in @($entry.Value)) {
                $sam = "$($m.SamAccountName)"
                if (-not $sam) { continue }
                # Member SID if present, else resolve well-known (covers nested built-in groups).
                $mSid = if ($m.SID) { "$($m.SID)" } else { (& $resolveWellKnownSid $sam) }
                $mId = (& $idFor $sam $mSid)
                & $addNode $mId $sam (& $kindForMember $m.IsGroup $sam) $mSid
                & $addEdge $mId $gId 'MemberOf'
            }
        }
    }

    # ── Control edges from dangerous ACEs (principal -> object) ──
    $acl = $AuditData.ACLs
    $haveAcl = [bool]($acl -and (-not ($acl -is [System.Collections.IDictionary]) -or $acl.Contains('DangerousACEs')))
    if ($haveAcl) {
        foreach ($ace in @($acl.DangerousACEs)) {
            $principal = "$($ace.IdentityReference)"
            $pSid = "$($ace.IdentitySID)"
            if (-not $principal -and -not $pSid) { continue }
            $pName = ($principal -split '\\')[-1]
            $pId = (& $idFor $pName $pSid)
            & $addNode $pId $pName 'Base' $pSid

            $objName = "$($ace.ObjectName)"
            $objSid = "$($ace.ObjectSID)"
            $oId = (& $idFor $objName $objSid)
            & $addNode $oId $objName (& $kindForObject $ace.ObjectClass $objName) $objSid

            # Map the AD right to a native BloodHound edge kind.
            $r = "$($ace.ActiveDirectoryRights)"; $ot = "$($ace.ObjectType)"
            $kind =
                if ($ot -match '1131f6ad' -or $r -match 'Get-Changes-All|GetChangesAll') { 'GetChangesAll' }
                elseif ($ot -match '1131f6aa' -or $r -match 'Get-Changes|GetChanges') { 'GetChanges' }
                elseif ($r -match '(?i)GenericAll') { 'GenericAll' }
                elseif ($r -match '(?i)WriteDacl') { 'WriteDacl' }
                elseif ($r -match '(?i)WriteOwner') { 'WriteOwner' }
                elseif ($r -match '(?i)GenericWrite') { 'GenericWrite' }
                elseif ($r -match '(?i)ExtendedRight') { 'AllExtendedRights' }
                elseif ($r -match '(?i)WriteProperty') { 'GenericWrite' }
                else { 'GenericAll' }
            & $addEdge $pId $oId $kind
        }
    }

    $payload = [PSCustomObject]@{
        metadata = @{ source_kind = 'Guerrilla'; generated_by = 'Guerrilla'; version = 1 }
        graph    = [PSCustomObject]@{
            nodes = @($nodes.Values)
            edges = @($edges)
        }
    }

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.BloodHoundExport'
        Path       = $OutputPath
        NodeCount  = @($nodes.Values).Count
        EdgeCount  = @($edges).Count
        Format     = 'BloodHound OpenGraph'
        Message    = "BloodHound OpenGraph written to $OutputPath ($(@($nodes.Values).Count) nodes, $(@($edges).Count) edges). Import via BloodHound CE > Administration > File Ingest."
    }
}
