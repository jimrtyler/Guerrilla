# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Resolve-ADSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SidString,

        [System.DirectoryServices.DirectoryEntry]$SearchRoot
    )

    # Belt-and-suspenders: ensure the module-scope caches/tables exist even if the
    # .psm1 bootstrap didn't run (e.g. the function dot-sourced in isolation by a test).
    if ($null -eq $script:SidCache)      { $script:SidCache = @{} }
    if ($null -eq $script:WellKnownSids) { $script:WellKnownSids = @{} }
    if ($null -eq $script:WellKnownRids) { $script:WellKnownRids = @{} }

    # Check cache first
    if ($script:SidCache.ContainsKey($SidString)) {
        return $script:SidCache[$SidString]
    }

    # Check well-known SIDs
    if ($script:WellKnownSids.ContainsKey($SidString)) {
        $name = $script:WellKnownSids[$SidString]
        $script:SidCache[$SidString] = $name
        return $name
    }

    # Check domain-relative well-known RIDs (only meaningful for S-1-5-21-<domain>-<RID>;
    # gating on the domain-SID prefix avoids a raw RID colliding with a builtin's last segment).
    $sidParts = $SidString -split '-'
    if ($SidString -like 'S-1-5-21-*' -and $sidParts.Count -ge 5) {
        $rid = [int]$sidParts[-1]
        if ($script:WellKnownRids.ContainsKey($rid)) {
            $name = $script:WellKnownRids[$rid]
            $script:SidCache[$SidString] = $name
            return $name
        }
    }

    # Try .NET translation
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $account = $sid.Translate([System.Security.Principal.NTAccount])
        $name = $account.Value
        $script:SidCache[$SidString] = $name
        return $name
    } catch {
        # Fall through to LDAP lookup
    }

    # Try LDAP lookup
    if ($SearchRoot) {
        try {
            # SecurityIdentifier has no GetSidBytes(); use GetBinaryForm (the old call threw silently).
            $__sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
            $sidBytes = New-Object byte[] $__sid.BinaryLength
            $__sid.GetBinaryForm($sidBytes, 0)
            $escapedSid = ($sidBytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''

            $results = @(Invoke-LdapQuery -SearchRoot $SearchRoot `
                -Filter "(objectSid=$escapedSid)" `
                -Properties @('samaccountname', 'distinguishedname', 'objectclass') `
                -SizeLimit 1)

            if ($results.Count -gt 0) {
                $name = $results[0].samaccountname ?? $results[0].distinguishedname ?? $SidString
                $script:SidCache[$SidString] = $name
                return $name
            }
        } catch {
            Write-Verbose "LDAP SID lookup failed for $SidString`: $_"
        }
    }

    # Cache the unresolved SID to avoid repeated lookups
    $script:SidCache[$SidString] = $SidString
    return $SidString
}

function Clear-ADSidCache {
    [CmdletBinding()]
    param()
    $script:SidCache = @{}
}
