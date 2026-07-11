# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# AD attack-path analysis. Turns the flat "dangerous ACE" findings into named
# privilege-escalation PATHS to Tier-0, with the concrete takeover technique each edge
# enables. Two edge classes today, both from already-collected data:
#   1. Object control — non-default control of a Tier-0 object (Domain root, AdminSDHolder,
#      the DC OU, the GPO/Config/Schema containers); a one-hop path to Domain Admin equiv.
#   2. Group nesting — a non-default group nested inside a Tier-0 group is an escalation
#      pivot (controlling it / being added to it confers the Tier-0 group's privileges).
#
# CRITICAL: default infrastructure/admin principals (the DC groups, Enterprise DCs, RODCs,
# Schema Admins, etc.) legitimately hold replication/control rights on Tier-0 objects by
# AD design — they must NOT be reported as escalation paths. We exclude them by well-known
# SID/RID (locale-proof). Azure AD Connect sync accounts (MSOL_*) hold real DCSync rights
# but by design and are already tracked by ADTIER-001, so they are flagged Expected and
# kept out of the "non-privileged, highest-risk" count rather than surfaced as surprises.
#
# NOTE: full domain-wide transitive CONTROL chaining (low-priv user -> GenericWrite group
# -> ... -> DA) needs a full-domain ACL collector, which Guerrilla does not yet run (it
# reads ACLs on the 6 critical objects only). That deeper traversal is the next roadmap
# increment; this engine is structured so additional edge sources can feed straight in.

function Test-DefaultControlPrincipal {
    # True for built-in/default principals that are SUPPOSED to hold control or replication
    # rights over Tier-0 objects, so the engine must NOT report them as escalation paths.
    # Matched by well-known SID / domain-relative RID first (locale-proof), name as fallback.
    # This is the allowlist the DCSync checks' Test-SafeAdminSid was missing.
    [CmdletBinding()]
    param([string]$Sid, [string]$IdentityReference)

    $exactSids = @(
        'S-1-5-18'      # SYSTEM
        'S-1-5-10'      # SELF / PRINCIPAL SELF
        'S-1-5-9'       # Enterprise Domain Controllers
        'S-1-5-32-544'  # BUILTIN\Administrators
    )
    if ($Sid -and ($Sid -in $exactSids)) { return $true }

    # Domain-relative RIDs: Domain Admins 512, Enterprise Admins 519, Schema Admins 518,
    # Domain Controllers 516, Cert Publishers 517, Read-Only DCs 521, Enterprise RODC 498,
    # krbtgt 502. All legitimately hold control/replication over Tier-0 objects by design.
    if ($Sid -match '-(498|502|512|516|517|518|519|521)$') { return $true }

    $names = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Domain Controllers', 'Enterprise Domain Controllers',
        'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers',
        'SYSTEM', 'Cert Publishers'
    )
    foreach ($n in $names) {
        if ($IdentityReference -eq $n -or $IdentityReference -like "*\$n") { return $true }
    }
    return $false
}

function Test-DefaultPrivilegedPrincipal {
    # Superset of Test-DefaultControlPrincipal used only to set SourceIsPrivileged: also
    # covers the built-in operator groups (Account/Server/Print/Backup Operators), which
    # are privileged-by-default even though they are not part of the control allowlist.
    [CmdletBinding()]
    param([string]$Sid, [string]$IdentityReference)

    if (Test-DefaultControlPrincipal -Sid $Sid -IdentityReference $IdentityReference) { return $true }
    if ($Sid -and ($Sid -in @('S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551'))) { return $true }
    foreach ($n in @('Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators')) {
        if ($IdentityReference -eq $n -or $IdentityReference -like "*\$n") { return $true }
    }
    return $false
}

function Test-ExpectedSyncAccount {
    # Azure AD Connect / Entra Connect on-prem sync accounts are provisioned with real
    # DCSync rights BY DESIGN and are named MSOL_<12 hex> (AD Connect) or AAD_<...> (older).
    # They are expected Tier-0 service accounts (ADTIER-001 tracks them), not surprise paths.
    [CmdletBinding()]
    param([string]$IdentityReference)
    return [bool]($IdentityReference -match '(^|\\)(MSOL_[0-9a-fA-F]{12}|MSOL_|AAD_)')
}

function Get-ADAttackPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    # Returns { DataAvailable; Paths }. DataAvailable distinguishes "ACL data not collected"
    # (caller SKIPs) from "collected, zero paths" (caller PASSes) — an explicit flag avoids
    # the PowerShell `$null -eq @()` ambiguity that an empty-array return would introduce.
    $notCollected = [PSCustomObject]@{ DataAvailable = $false; Paths = @() }

    $acl = $AuditData.ACLs
    $priv = $AuditData.PrivilegedAccounts
    $haveAcl = [bool]($acl -and (-not ($acl -is [System.Collections.IDictionary]) -or $acl.Contains('DangerousACEs')))
    $havePriv = [bool]($priv -and $priv.PrivilegedGroups)
    if (-not $haveAcl -and -not $havePriv) { return $notCollected }

    # Per Tier-0 object: what controlling it actually gets the attacker.
    $impactByObject = @{
        'Domain Root'            = @{ Target = 'the domain (every credential, incl. krbtgt)'; Severity = 'Critical'
            Impact = 'grant themselves DCSync replication rights and extract every domain hash — Domain Admin equivalent' }
        'AdminSDHolder'          = @{ Target = 'all protected groups (Domain/Enterprise/Schema Admins, etc.)'; Severity = 'Critical'
            Impact = 'write an attacker ACE that SDProp propagates to every protected (adminCount=1) object within ~60 min — persistent Tier-0 control' }
        'Domain Controllers OU'  = @{ Target = 'every Domain Controller'; Severity = 'Critical'
            Impact = 'link a malicious GPO to the DC OU and execute code as SYSTEM on every DC — Domain Admin' }
        'GPO Container'          = @{ Target = 'any host where a controlled GPO is linked'; Severity = 'High'
            Impact = 'create or modify Group Policy Objects and execute code wherever they are linked' }
        'Configuration Container' = @{ Target = 'the forest configuration partition'; Severity = 'Critical'
            Impact = 'modify forest-wide configuration (sites, services, AD CS) — forest compromise' }
        'Schema Container'       = @{ Target = 'the AD schema'; Severity = 'Critical'
            Impact = 'modify the schema (defaultSecurityDescriptor) for forest-wide, persistent control' }
    }

    # Build a fast lookup of which principals are already inside a privileged group, so a
    # path from a NON-privileged principal (the genuinely dangerous case) can be flagged.
    $privSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $privNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($AuditData.PrivilegedAccounts -and $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        foreach ($grp in $AuditData.PrivilegedAccounts.PrivilegedGroups.Values) {
            foreach ($m in @($grp)) {
                if ($m.SID) { [void]$privSids.Add([string]$m.SID) }
                if ($m.SamAccountName) { [void]$privNames.Add([string]$m.SamAccountName) }
            }
        }
    }

    $paths = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($ace in @($acl.DangerousACEs)) {
        $objName = [string]$ace.ObjectName
        $map = $impactByObject[$objName]
        if (-not $map) { continue }   # an ACE on something we don't model an impact for

        $principal = [string]($ace.IdentityReference ?? $ace.IdentitySID ?? 'Unknown')
        $sid = [string]($ace.IdentitySID ?? '')

        # Skip default infrastructure/admin principals that hold this control by design
        # (DC groups, Enterprise DCs, RODCs, Schema Admins, DA/EA, SYSTEM, Administrators).
        # These are NOT attack paths — flagging them was the v2.10.1 false-positive bug.
        if (Test-DefaultControlPrincipal -Sid $sid -IdentityReference $principal) { continue }

        # Prefer the friendly extended-right name (e.g. DS-Replication-Get-Changes) over
        # the raw rights flags when this is a specific extended right.
        $right = if ($ace.ObjectType -and "$($ace.ActiveDirectoryRights)" -match 'ExtendedRight|WriteProperty') {
            [string]$ace.ObjectType
        } else {
            [string]$ace.ActiveDirectoryRights
        }

        # Dedup on principal + object + right.
        $key = "$principal|$objName|$right"
        if (-not $seen.Add($key)) { continue }

        $isExpected = Test-ExpectedSyncAccount -IdentityReference $principal
        # SourceIsPrivileged: a member of a Tier-0 group, OR a default privileged principal,
        # OR an expected Tier-0 sync account. Anything left as $false is a genuinely
        # non-privileged principal — the highest-risk case the headline counts.
        $alreadyPrivileged = $isExpected `
            -or (Test-DefaultPrivilegedPrincipal -Sid $sid -IdentityReference $principal) `
            -or ($sid -and $privSids.Contains($sid)) `
            -or $privNames.Contains(($principal -split '\\')[-1])

        $technique = if ($isExpected) {
            "is an Azure AD Connect / Entra Connect sync account with by-design DCSync rights (tracked by ADTIER-001) — protect it as Tier-0, but it is not a surprise escalation path"
        } else { $map.Impact }

        $paths.Add([PSCustomObject]@{
            PSTypeName         = 'Guerrilla.AttackPath'
            Source             = $principal
            SourceSID          = $sid
            SourceIsPrivileged = [bool]$alreadyPrivileged
            Expected           = [bool]$isExpected
            Edge               = $right
            Inherited          = [bool]$ace.IsInherited
            TargetObject       = $objName
            ReachesTier0       = $map.Target
            Technique          = $technique
            Severity           = $map.Severity
            PathType           = 'Object control'
            # One-line, human-readable path.
            Path               = "$principal --[$right]--> $objName  =>  can $($map.Impact)"
        })
    }

    # Group-nesting pivots: a NON-default group nested inside a Tier-0 group is an
    # escalation pivot — anyone who can add a principal to it (or controls its membership)
    # inherits the Tier-0 group's privileges. Nested groups in Tier-0 are a well-known
    # anti-pattern; the well-known Tier-0/default groups themselves are expected and excluded.
    if ($havePriv) {
        $wellKnownTier0 = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators')
        foreach ($entry in $priv.PrivilegedGroups.GetEnumerator()) {
            $t0Group = [string]$entry.Key
            foreach ($m in @($entry.Value)) {
                if (-not $m.IsGroup) { continue }
                $gName = [string]$m.SamAccountName
                $gSid = [string]($m.SID ?? '')
                if (-not $gName -or ($wellKnownTier0 -contains $gName)) { continue }
                # Don't flag a default principal nested in Tier-0 (by design).
                if (Test-DefaultControlPrincipal -Sid $gSid -IdentityReference $gName) { continue }
                $key = "nest|$gName|$t0Group"
                if (-not $seen.Add($key)) { continue }
                $paths.Add([PSCustomObject]@{
                    PSTypeName         = 'Guerrilla.AttackPath'
                    Source             = $gName
                    SourceSID          = $gSid
                    SourceIsPrivileged = $false   # the pivot group itself IS the escalation surface
                    Expected           = $false
                    Edge               = 'MemberOf (nesting)'
                    Inherited          = $false
                    TargetObject       = $t0Group
                    ReachesTier0       = "$t0Group (privileged group)"
                    Technique          = "is nested inside $t0Group, so any principal added to it — or anyone who controls its membership — gains $t0Group privileges"
                    Severity           = 'High'
                    PathType           = 'Group nesting'
                    Path               = "$gName --[nested member of]--> $t0Group  =>  controlling $gName confers $t0Group privileges"
                })
            }
        }
    }

    # Order: genuine non-privileged (highest risk) first, then genuine privileged, then
    # expected service-account paths last. Within each, highest severity first.
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $sorted = @($paths | Sort-Object `
        @{ Expression = { if ($_.Expected) { 1 } else { 0 } } }, `
        @{ Expression = { if ($_.SourceIsPrivileged) { 1 } else { 0 } } }, `
        @{ Expression = { $sevRank[$_.Severity] ?? 4 } }, `
        Source)
    return [PSCustomObject]@{ DataAvailable = $true; Paths = $sorted }
}
