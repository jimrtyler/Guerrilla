# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Export-BloodHoundData: emits a BloodHound OpenGraph file (nodes + edges) from collected
# recon data, using BloodHound native edge kinds. Run: pwsh -File Tests/verify-bloodhound-export.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$audit = @{
    ACLs = @{ DangerousACEs = @(
        [PSCustomObject]@{ IdentityReference = 'CORP\HelpDesk'; IdentitySID = 'S-1-5-21-1-2-3-1147'; ObjectName = 'CORP-Admins'; ObjectClass = 'group'; ActiveDirectoryRights = 'GenericAll' }
        [PSCustomObject]@{ IdentityReference = 'CORP\AppTeam'; IdentitySID = 'S-1-5-21-1-2-3-1148'; ObjectName = 'AdminSDHolder'; ActiveDirectoryRights = 'WriteDacl' }
        # replication right -> DCSync component (GetChangesAll)
        [PSCustomObject]@{ IdentityReference = 'CORP\SyncSvc'; IdentitySID = 'S-1-5-21-1-2-3-1149'; ObjectName = 'Domain Root'; ObjectClass = 'domainDNS'; ActiveDirectoryRights = 'ExtendedRight'; ObjectType = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }
    ) }
    PrivilegedAccounts = @{ PrivilegedGroups = @{
        'Domain Admins' = @(
            [PSCustomObject]@{ IsGroup = $true;  SamAccountName = 'CORP-Admins'; SID = 'S-1-5-21-1-2-3-1200' }
            [PSCustomObject]@{ IsGroup = $false; SamAccountName = 'Administrator'; SID = 'S-1-5-21-1-2-3-500' }
        )
    } }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-bh-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".json")
try {
    $res = Export-BloodHoundData -AuditData $audit -OutputPath $tmp
    Add-R 'returns Path + counts'          ($res.Path -eq $tmp -and $res.NodeCount -gt 0 -and $res.EdgeCount -gt 0) ("n=$($res.NodeCount) e=$($res.EdgeCount)")
    Add-R 'file written'                   (Test-Path $tmp) ""

    $json = Get-Content $tmp -Raw | ConvertFrom-Json
    Add-R 'valid JSON parses'              ($null -ne $json) ""
    Add-R 'metadata.source_kind set'       ($json.metadata.source_kind -eq 'Guerrilla') ("got=$($json.metadata.source_kind)")
    Add-R 'graph.nodes present'            (@($json.graph.nodes).Count -gt 0) ("n=$(@($json.graph.nodes).Count)")
    Add-R 'graph.edges present'            (@($json.graph.edges).Count -gt 0) ("e=$(@($json.graph.edges).Count)")

    # Node objectid is the SID, kinds include Base
    $hd = @($json.graph.nodes | Where-Object { $_.id -eq 'S-1-5-21-1-2-3-1147' })
    Add-R 'HelpDesk node keyed by SID'     ($hd.Count -eq 1 -and ($hd[0].kinds -contains 'Base')) ""

    # Control edge: HelpDesk -> CORP-Admins with native kind GenericAll
    $e1 = @($json.graph.edges | Where-Object { $_.start.value -eq 'S-1-5-21-1-2-3-1147' -and $_.kind -eq 'GenericAll' })
    Add-R 'GenericAll edge HelpDesk->group' ($e1.Count -eq 1) ("got=$($e1.Count)")

    # WriteDacl edge AppTeam -> AdminSDHolder
    $e2 = @($json.graph.edges | Where-Object { $_.start.value -eq 'S-1-5-21-1-2-3-1148' -and $_.kind -eq 'WriteDacl' })
    Add-R 'WriteDacl edge present'         ($e2.Count -eq 1) ("got=$($e2.Count)")

    # Replication right mapped to GetChangesAll (DCSync component)
    $e3 = @($json.graph.edges | Where-Object { $_.start.value -eq 'S-1-5-21-1-2-3-1149' -and $_.kind -eq 'GetChangesAll' })
    Add-R 'replication -> GetChangesAll'   ($e3.Count -eq 1) ("got=$($e3.Count)")

    # MemberOf edge: CORP-Admins -> Domain Admins (group keyed by name)
    $e4 = @($json.graph.edges | Where-Object { $_.start.value -eq 'S-1-5-21-1-2-3-1200' -and $_.kind -eq 'MemberOf' })
    Add-R 'MemberOf edge member->group'    ($e4.Count -eq 1) ("got=$($e4.Count)")

    # Edges carry provenance
    Add-R 'edges tagged source=Guerrilla' (@($json.graph.edges | Where-Object { $_.properties.source -eq 'Guerrilla' }).Count -eq @($json.graph.edges).Count) ""

    # Well-known group name -> real SID so the node overlays SharpHound instead of a parallel NAME: node.
    # Member SIDs are S-1-5-21-1-2-3-* so the domain SID derives to S-1-5-21-1-2-3; Domain Admins -> -512.
    $da = @($json.graph.nodes | Where-Object { $_.id -eq 'S-1-5-21-1-2-3-512' })
    Add-R 'Domain Admins keyed by real SID (-512)' ($da.Count -eq 1) ("got=$($da.Count)")
    Add-R 'no NAME:DOMAIN ADMINS node'             (@($json.graph.nodes | Where-Object { $_.id -eq 'NAME:DOMAIN ADMINS' }).Count -eq 0) ""
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
