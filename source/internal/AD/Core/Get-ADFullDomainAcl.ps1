# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Full-domain ACL collector. Where Get-ADObjectACLs reads the six critical Tier-0 objects,
# this sweeps EVERY group/user/computer/gMSA in the domain and emits the dangerous, non-default
# control ACEs across the whole population. That is what turns shallow one-hop findings into deep
# low-priv -> ... -> Domain Admins chains: a principal with GenericAll/WriteDacl/WriteOwner over a
# group that sits anywhere in the Tier-0 membership closure now produces a real transitive path.
#
# Critically, every emitted ACE carries ObjectClass + ObjectSID + ObjectName so the transitive
# engine classifies the target as a group (grp:) node and the BloodHound export keys it by SID.
# The record shape is a superset of Get-ADObjectACLs' DangerousACEs, so both consumers ingest it
# unchanged.
#
# Performance: one paged LDAP query pulls nTSecurityDescriptor in binary form for the whole
# population; each DACL is parsed from bytes (no per-object DirectoryEntry bind). Opt-in and
# MaxObjects-capped because on a large domain this is the heaviest read Guerrilla performs.

# Pure predicate: does this ACE grant dangerous control? Mirrors Get-ADObjectACLs exactly so the
# full-domain sweep and the critical-object pass agree on what "dangerous" means. Testable offline.
function Test-AceGrantsDangerousControl {
    [CmdletBinding()]
    param(
        [string]$Rights,
        [string]$ObjectTypeGuid,
        [string]$AccessControlType = 'Allow',
        [hashtable]$DangerousGuids = @{}
    )
    if ($AccessControlType -ne 'Allow') { return $false }

    foreach ($dr in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')) {
        if ($Rights -match $dr) { return $true }
    }
    # WriteProperty on a dangerous attribute (e.g. member, msDS-KeyCredentialLink via GUID)
    if ($Rights -match 'WriteProperty' -and $ObjectTypeGuid -and $DangerousGuids.ContainsKey($ObjectTypeGuid)) {
        return $true
    }
    # ExtendedRight: dangerous if it is a known dangerous right, or if no GUID (all rights granted)
    if ($Rights -match 'ExtendedRight') {
        if ($ObjectTypeGuid -and $DangerousGuids.ContainsKey($ObjectTypeGuid)) { return $true }
        if (-not $ObjectTypeGuid) { return $true }
    }
    return $false
}

function Get-ADFullDomainAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        # Safety cap on objects scanned. Truncation is reported, never silent.
        [int]$MaxObjects = 50000,

        [switch]$Quiet
    )

    $result = @{
        DangerousACEs  = @()
        ObjectsScanned = 0
        Truncated      = $false
        Error          = $null
    }

    # Well-known GUIDs for dangerous extended rights / properties (matches Get-ADObjectACLs,
    # plus member-write and key-credential-link, the two highest-value full-domain edges).
    $dangerousGuids = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Member'                  # WriteProperty member = AddMember
        'bf967a68-0de6-11d0-a285-00aa003049e2' = 'Self-Membership'
        'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'Validated-SPN'
        '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'msDS-KeyCredentialLink'  # shadow-credentials
    }

    # Default / structural principals to ignore (matches Get-ADObjectACLs).
    $defaultIgnorePatterns = @(
        'Domain Admins', 'Enterprise Admins', 'SYSTEM',
        'BUILTIN\Administrators', 'Administrators',
        'S-1-5-18'
    )
    # Structural principal SIDs that are never an escalation source.
    $skipPrincipalSids = @(
        'S-1-5-18',   # SYSTEM
        'S-1-5-10',   # SELF
        'S-1-3-0',    # CREATOR OWNER
        'S-1-3-1',    # CREATOR GROUP
        'S-1-5-32-544' # BUILTIN\Administrators
    )

    $sidCache = @{}
    $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN

    Write-Verbose 'Full-domain ACL sweep: querying nTSecurityDescriptor for all groups/users/computers/gMSAs...'
    try {
        # Include organizationalUnit — OU delegation (full-control / WriteDacl / WriteOwner on an OU,
        # i.e. control of every child object) is the classic escalation surface and would otherwise be
        # invisible to the sweep. OUs have no objectSid, which is fine: they key by DN downstream.
        $objects = @(Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(|(objectCategory=group)(objectCategory=person)(objectCategory=computer)(objectCategory=msDS-GroupManagedServiceAccount)(objectCategory=organizationalUnit))' `
            -Properties @('ntsecuritydescriptor', 'objectsid', 'samaccountname', 'objectclass', 'distinguishedname', 'name') `
            -PageSize 1000)
    } catch {
        $result.Error = "Full-domain ACL query failed: $_"
        Write-Warning $result.Error
        return $result
    }

    $aces = [System.Collections.Generic.List[hashtable]]::new()
    $count = 0

    foreach ($obj in $objects) {
        if ($count -ge $MaxObjects) {
            $result.Truncated = $true
            break
        }
        $count++

        if (-not $Quiet -and ($count % 2500 -eq 0)) {
            Write-ProgressLine -Phase RECON -Message 'Full-domain ACL sweep' -Detail "$count objects scanned, $($aces.Count) dangerous ACE(s)"
        }

        $sdBytes = $obj['ntsecuritydescriptor']
        if (-not ($sdBytes -is [byte[]])) { continue }

        $objSid = "$($obj['objectsid'])"
        $objSam = "$($obj['samaccountname'])"
        $objDN  = "$($obj['distinguishedname'])"
        $ocRaw  = $obj['objectclass']
        # objectClass is multi-valued (top, ..., <mostSpecific>); the last entry is the leaf class.
        $objClass = if ($ocRaw -is [System.Array]) { "$($ocRaw[-1])" } else { "$ocRaw" }
        # OUs have no sAMAccountName — name them by their 'name' attribute, else the leftmost RDN.
        $objName = if ($objSam) { $objSam }
                   elseif ($obj['name']) { "$($obj['name'])" }
                   elseif ($objDN) { (($objDN -split ',', 2)[0] -replace '^(?i)(OU|CN)=', '') }
                   else { '' }

        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        try {
            $sd.SetSecurityDescriptorBinaryForm($sdBytes)
            $rules = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        } catch {
            Write-Verbose "Could not parse SD for $objDN`: $_"
            continue
        }

        foreach ($rule in $rules) {
            if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }

            $pSid = $rule.IdentityReference.Value
            if (-not $pSid) { continue }

            # Skip self-ACEs (an object having rights over itself) and structural principals.
            if ($pSid -eq $objSid) { continue }
            if ($skipPrincipalSids -contains $pSid) { continue }
            # Skip Domain Admins / Enterprise Admins by RID (already-Tier-0 grantees aren't escalation).
            if ($pSid -match '-512$|-519$') { continue }

            $objectTypeGuid = if ($rule.ObjectType -and $rule.ObjectType.ToString() -ne '00000000-0000-0000-0000-000000000000') {
                $rule.ObjectType.ToString()
            } else { $null }

            $rights = $rule.ActiveDirectoryRights.ToString()
            if (-not (Test-AceGrantsDangerousControl -Rights $rights -ObjectTypeGuid $objectTypeGuid -AccessControlType 'Allow' -DangerousGuids $dangerousGuids)) {
                continue
            }

            # Resolve the principal SID -> name (cached; only for the few dangerous ACEs we keep).
            if (-not $sidCache.ContainsKey($pSid)) {
                $sidCache[$pSid] = Resolve-ADSid -SidString $pSid -SearchRoot $searchRoot
            }
            $resolved = $sidCache[$pSid]

            # Skip default/named principals (e.g. resolved to "Domain Admins").
            $isDefault = $false
            foreach ($pattern in $defaultIgnorePatterns) {
                if ($resolved -eq $pattern -or $resolved -like "*\$pattern") { $isDefault = $true; break }
            }
            if ($isDefault) { continue }

            $objectTypeName = if ($objectTypeGuid -and $dangerousGuids.ContainsKey($objectTypeGuid)) {
                $dangerousGuids[$objectTypeGuid]
            } elseif ($objectTypeGuid) { $objectTypeGuid } else { $null }

            $aces.Add(@{
                IdentityReference     = $resolved
                IdentitySID           = $pSid
                ActiveDirectoryRights = $rights
                AccessControlType     = 'Allow'
                ObjectType            = $objectTypeName
                ObjectTypeGUID        = $objectTypeGuid
                ObjectClass           = $objClass        # NEW: lets the engine classify group targets
                ObjectName            = $objName         # sAMAccountName, or OU/container name
                ObjectSID             = $objSid          # NEW: lets BloodHound key the target by SID
                ObjectDN              = $objDN
                IsInherited           = $rule.IsInherited
                Source                = 'FullDomain'
            })
        }
    }

    $result.DangerousACEs  = @($aces)
    $result.ObjectsScanned = $count
    Write-Verbose "Full-domain ACL sweep complete: $count objects, $($aces.Count) dangerous non-default ACE(s)$(if ($result.Truncated) { " (TRUNCATED at MaxObjects=$MaxObjects)" })."
    return $result
}
