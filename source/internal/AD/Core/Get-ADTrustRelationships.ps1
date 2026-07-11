# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADTrustRelationships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    # ── Trust direction mapping ───────────────────────────────────────
    $trustDirectionMap = @{
        0 = 'Disabled'
        1 = 'Inbound'
        2 = 'Outbound'
        3 = 'Bidirectional'
    }

    # ── Trust type mapping ────────────────────────────────────────────
    $trustTypeMap = @{
        1 = 'Downlevel'     # NTLM (Windows NT 4.0 and earlier)
        2 = 'Uplevel'       # Kerberos (Active Directory)
        3 = 'MIT'           # Non-Windows Kerberos realm
        4 = 'DCE'           # Distributed Computing Environment
    }

    # ── Trust attribute flags ─────────────────────────────────────────
    # 0x0001 = NON_TRANSITIVE
    # 0x0002 = UPLEVEL_ONLY
    # 0x0004 = QUARANTINED_DOMAIN (SID filtering enabled)
    # 0x0008 = FOREST_TRANSITIVE
    # 0x0010 = CROSS_ORGANIZATION (selective authentication)
    # 0x0020 = WITHIN_FOREST
    # 0x0040 = TREAT_AS_EXTERNAL
    # 0x0080 = USES_RC4_ENCRYPTION
    # 0x0200 = CROSS_ORGANIZATION_NO_TGT_DELEGATION
    # 0x0400 = PIM_TRUST
    # 0x0800 = CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION

    $domainDN = $Connection.DomainDN

    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Enumerating trust relationships'
    }

    # ── Query trusted domain objects ──────────────────────────────────
    $trustFilter = '(objectClass=trustedDomain)'
    $trustProperties = @(
        'cn', 'flatName', 'trustPartner', 'distinguishedName',
        'trustDirection', 'trustType', 'trustAttributes',
        'securityIdentifier', 'objectSid',
        'whenCreated', 'whenChanged'
    )

    $trustResults = @()
    try {
        $systemContainerDN = "CN=System,$domainDN"
        $systemRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $systemContainerDN
        $trustResults = Invoke-LdapQuery -SearchRoot $systemRoot `
            -Filter $trustFilter `
            -Properties $trustProperties `
            -Scope OneLevel
    } catch {
        # Fail loud: a failed enumeration must not be returned as "no trusts" — that
        # would let every trust check score PASS on data we never saw. The caller's
        # try/catch records this in Errors['TrustRelationships'] so the checks report
        # Not Assessed instead. (Genuinely zero trusts returns @() further down.)
        throw "Failed to enumerate trust relationships: $_"
    }

    Write-Verbose "Found $($trustResults.Count) trust relationship(s)"

    if ($trustResults.Count -eq 0) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'No trust relationships found'
        }
        return @()
    }

    # ── Build trust result objects ────────────────────────────────────
    $trusts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($trust in $trustResults) {
        $trustPartner = if ($trust.ContainsKey('trustpartner')) { $trust['trustpartner'] }
                        elseif ($trust.ContainsKey('cn')) { $trust['cn'] }
                        else { '' }
        $flatName     = if ($trust.ContainsKey('flatname')) { $trust['flatname'] } else { '' }

        # Trust direction
        $trustDirInt = if ($trust.ContainsKey('trustdirection')) { [int]$trust['trustdirection'] } else { 0 }
        $trustDirStr = if ($trustDirectionMap.ContainsKey($trustDirInt)) {
            $trustDirectionMap[$trustDirInt]
        } else {
            "Unknown ($trustDirInt)"
        }

        # Trust type
        $trustTypeInt = if ($trust.ContainsKey('trusttype')) { [int]$trust['trusttype'] } else { 0 }
        $trustTypeStr = if ($trustTypeMap.ContainsKey($trustTypeInt)) {
            $trustTypeMap[$trustTypeInt]
        } else {
            "Unknown ($trustTypeInt)"
        }

        # Trust attributes (bitmask)
        $trustAttribs = if ($trust.ContainsKey('trustattributes')) { [int]$trust['trustattributes'] } else { 0 }

        # Decode attribute flags
        $isNonTransitive      = ($trustAttribs -band 0x0001) -ne 0
        $isQuarantined        = ($trustAttribs -band 0x0004) -ne 0   # SID filtering
        $isForestTransitive   = ($trustAttribs -band 0x0008) -ne 0
        $isCrossOrganization  = ($trustAttribs -band 0x0010) -ne 0   # Selective authentication
        $isWithinForest       = ($trustAttribs -band 0x0020) -ne 0
        $isTreatAsExternal    = ($trustAttribs -band 0x0040) -ne 0
        $usesRC4              = ($trustAttribs -band 0x0080) -ne 0
        $noTgtDelegation      = ($trustAttribs -band 0x0200) -ne 0
        $isPimTrust           = ($trustAttribs -band 0x0400) -ne 0
        $enableTgtDelegation  = ($trustAttribs -band 0x0800) -ne 0

        # Transitivity: a trust is transitive unless NON_TRANSITIVE is set
        $isTransitive = -not $isNonTransitive

        # SID filtering: QUARANTINED_DOMAIN flag means SID filtering is enabled.
        # For external trusts, SID filtering is on by default. For forest trusts it depends on the flag.
        $sidFilteringEnabled = $isQuarantined

        # SID History: generally the inverse of SID filtering for cross-domain trusts,
        # but only meaningful when SID filtering could be applied
        $sidHistoryEnabled = -not $isQuarantined

        # Azure AD trust detection: look for common indicators
        $isAzureAD = $false
        if ($trustPartner -match '\.windows\.net$' -or
            $trustPartner -match 'microsoftonline\.com$' -or
            $trustPartner -match 'AzureAD$' -or
            $flatName -match '^AzureAD' -or
            $flatName -match '^AAD') {
            $isAzureAD = $true
        }

        # Security identifier of the trusted domain
        $trustSid = ''
        if ($trust.ContainsKey('securityidentifier')) {
            $sidValue = $trust['securityidentifier']
            if ($sidValue -is [byte[]]) {
                try {
                    $trustSid = (New-Object System.Security.Principal.SecurityIdentifier($sidValue, 0)).Value
                } catch {
                    Write-Verbose "Failed to parse trust SID for $trustPartner`: $_"
                }
            } elseif ($sidValue -is [string]) {
                $trustSid = $sidValue
            }
        }

        $trustObj = @{
            TrustPartner            = $trustPartner
            FlatName                = $flatName
            TrustDirection          = $trustDirStr
            TrustDirectionInt       = $trustDirInt
            TrustType               = $trustTypeStr
            TrustTypeInt            = $trustTypeInt
            TrustAttributes         = $trustAttribs
            IsTransitive            = $isTransitive
            SIDFilteringEnabled     = $sidFilteringEnabled
            SelectiveAuthentication = $isCrossOrganization
            ForestTransitive        = $isForestTransitive
            WithinForest            = $isWithinForest
            TreatAsExternal         = $isTreatAsExternal
            UsesRC4Encryption       = $usesRC4
            NoTGTDelegation         = $noTgtDelegation
            PIMTrust                = $isPimTrust
            EnableTGTDelegation     = $enableTgtDelegation
            SIDHistoryEnabled       = $sidHistoryEnabled
            IsAzureAD               = $isAzureAD
            TrustSID                = $trustSid
            WhenCreated             = if ($trust.ContainsKey('whencreated')) { $trust['whencreated'] } else { $null }
            WhenChanged             = if ($trust.ContainsKey('whenchanged')) { $trust['whenchanged'] } else { $null }
            DistinguishedName       = if ($trust.ContainsKey('distinguishedname')) { $trust['distinguishedname'] } else { '' }
        }

        $trusts.Add($trustObj)
    }

    # ── Summary ───────────────────────────────────────────────────────
    if (-not $Quiet) {
        $inbound  = @($trusts | Where-Object { $_.TrustDirection -eq 'Inbound' }).Count
        $outbound = @($trusts | Where-Object { $_.TrustDirection -eq 'Outbound' }).Count
        $bidir    = @($trusts | Where-Object { $_.TrustDirection -eq 'Bidirectional' }).Count
        $forestTr = @($trusts | Where-Object { $_.ForestTransitive }).Count

        $summary = "Found $($trusts.Count) trust(s): $bidir bidirectional, $inbound inbound, $outbound outbound"
        if ($forestTr -gt 0) {
            $summary += ", $forestTr forest"
        }
        Write-ProgressLine -Phase AUDITING -Message $summary
    }

    return @($trusts)
}
