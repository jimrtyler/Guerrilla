# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Get-ADUserRightsAssignment
# -------------------------------------------------------------------------------
# Parses the Domain Controllers OU GPO security templates (GptTmpl.inf) from
# SYSVOL and extracts the interactive- and remote-interactive-logon User Rights
# Assignments. Feeds:
#   ADPRIV-026 (local logon on DCs) <- SeInteractiveLogonRight
#   ADPRIV-027 (RDP on DCs)         <- SeRemoteInteractiveLogonRight
#
# Honesty contract (project rule #1):
#   * Always reads the Default Domain Controllers Policy GUID template, plus any
#     additional GPOs linked to the Domain Controllers OU when that data is
#     available from the GroupPolicies collector.
#   * If NO GptTmpl.inf could be read at all, the right's value is left $null so
#     the dependent check returns SKIP ("Not Assessed") — never a false PASS on
#     an unreadable template.
#   * Each [Privilege Rights] value is a comma-separated list of *<SID> entries;
#     SIDs are resolved with Resolve-ADSid and compared against an expected
#     Tier-0 admin allow-list. Any non-Tier-0 principal => FAIL.
#
# References: MITRE ATT&CK T1078.002 (Valid Accounts: Domain Accounts),
# T1021.001 (Remote Services: RDP); ANSSI rule "dc_inappropriate_logon_rights";
# CIS Microsoft Windows Server benchmark (User Rights Assignment on DCs).
# -------------------------------------------------------------------------------
function Get-ADUserRightsAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    # Default Domain Controllers Policy — fixed, well-known GUID.
    $defaultDCPolicyGuid = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'

    # DNS domain name (contoso.com) for the SYSVOL UNC path.
    $domainDNS = ($Connection.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    $result = @{
        # $null = "template not read" → SKIP. @() = "read, no principals" (only
        # happens if the section is empty, which is itself notable) — treated as
        # "no one holds the right".
        InteractiveLogon       = $null   # SeInteractiveLogonRight  (local logon)
        RemoteInteractiveLogon = $null   # SeRemoteInteractiveLogonRight (RDP)
        TemplatesRead          = [System.Collections.Generic.List[string]]::new()  # .Add() below; @() is fixed-size and throws
        Errors                 = @{}
    }

    # ── Build candidate GptTmpl.inf paths ─────────────────────────────────────
    $sysvolBase = "\\$domainDNS\SYSVOL\$domainDNS\Policies"
    $candidateGuids = [System.Collections.Generic.List[string]]::new()
    [void]$candidateGuids.Add($defaultDCPolicyGuid)

    # If the GroupPolicies collector recorded GPOs linked to the DC OU, parse
    # those templates too (best-effort).
    if ($Connection.ContainsKey('DCOULinkedGpoGuids')) {
        foreach ($g in @($Connection.DCOULinkedGpoGuids)) {
            if ([string]::IsNullOrWhiteSpace($g)) { continue }
            $norm = if ($g -match '^\{') { $g } else { "{$g}" }
            if (-not $candidateGuids.Contains($norm)) { [void]$candidateGuids.Add($norm) }
        }
    }

    # Expected Tier-0 administrative principals that legitimately hold logon
    # rights on domain controllers. Compared case-insensitively against the
    # resolved account names AND raw SIDs (well-known SIDs / RIDs).
    $expectedTier0Names = @(
        'Administrators', 'BUILTIN\Administrators',
        'Domain Admins', 'Enterprise Admins',
        'Backup Operators', 'BUILTIN\Backup Operators',
        'Server Operators', 'BUILTIN\Server Operators',
        'Print Operators', 'BUILTIN\Print Operators',
        'Account Operators', 'BUILTIN\Account Operators',
        'ENTERPRISE DOMAIN CONTROLLERS'
    )
    $expectedTier0Sids = @(
        'S-1-5-32-544',  # Administrators
        'S-1-5-32-551',  # Backup Operators
        'S-1-5-32-549',  # Server Operators
        'S-1-5-32-550',  # Print Operators
        'S-1-5-32-548',  # Account Operators
        'S-1-5-9'        # Enterprise Domain Controllers
    )
    # Domain-relative RIDs that are expected (Domain Admins 512, Enterprise Admins 519).
    $expectedTier0Rids = @('512', '519')

    $searchRoot = $null
    try { $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN } catch { }

    # Helper: classify a *<SID> token from a [Privilege Rights] line.
    $classifyPrincipal = {
        param([string]$Token)

        $token = $Token.Trim()
        if ([string]::IsNullOrWhiteSpace($token)) { return $null }
        # Tokens are prefixed with '*' when they are SIDs; bare names are rare.
        $isSid = $token.StartsWith('*')
        $raw   = if ($isSid) { $token.Substring(1) } else { $token }

        $resolvedName = $raw
        $isExpected   = $false

        if ($isSid) {
            # Well-known SID match
            if ($expectedTier0Sids -contains $raw) { $isExpected = $true }
            # Domain-relative RID match
            if (-not $isExpected -and $raw -match '-(\d+)$' -and ($expectedTier0Rids -contains $Matches[1])) {
                $isExpected = $true
            }
            # Resolve to a friendly name for reporting / name-based allow-list.
            try { $resolvedName = Resolve-ADSid -SidString $raw -SearchRoot $searchRoot } catch { $resolvedName = $raw }
        } else {
            $resolvedName = $raw
        }

        if (-not $isExpected) {
            $shortName = ($resolvedName -split '\\')[-1]
            foreach ($exp in $expectedTier0Names) {
                $expShort = ($exp -split '\\')[-1]
                if ($resolvedName -ieq $exp -or $shortName -ieq $expShort) { $isExpected = $true; break }
            }
        }

        return @{
            Sid        = if ($isSid) { $raw } else { '' }
            Name       = $resolvedName
            IsExpected = $isExpected
        }
    }

    # Helper: parse one GptTmpl.inf, return a hashtable of right => @(principals).
    $parseTemplate = {
        param([string]$Path)

        $rights = @{}
        $lines = $null
        try {
            $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
        } catch {
            return $null   # could not read
        }

        $inPrivSection = $false
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^\[(.+)\]$') {
                $inPrivSection = ($Matches[1] -ieq 'Privilege Rights')
                continue
            }
            if (-not $inPrivSection) { continue }
            if ($trimmed -notmatch '=') { continue }

            $idx = $trimmed.IndexOf('=')
            $name = $trimmed.Substring(0, $idx).Trim()
            $valuePart = $trimmed.Substring($idx + 1).Trim()

            if ($name -ieq 'SeInteractiveLogonRight' -or $name -ieq 'SeRemoteInteractiveLogonRight') {
                $principals = [System.Collections.Generic.List[hashtable]]::new()
                foreach ($tok in ($valuePart -split ',')) {
                    $cls = & $classifyPrincipal $tok
                    if ($null -ne $cls) { $principals.Add($cls) }
                }
                $rights[$name] = @($principals)
            }
        }
        return $rights
    }

    # ── Parse each candidate template ─────────────────────────────────────────
    $mergedInteractive = $null
    $mergedRemote      = $null
    $anyTemplateRead   = $false

    foreach ($guid in $candidateGuids) {
        # Build the UNC path by concatenation. Join-Path mis-parses a leading
        # "\\host\share" as a drive on non-Windows hosts; string-building is
        # both portable and works against the real \\<domain>\SYSVOL path on a DC.
        $path = "$sysvolBase\$guid\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        $exists = $false
        try { $exists = Test-Path -LiteralPath $path -ErrorAction Stop } catch { $exists = $false }
        if (-not $exists) {
            Write-Verbose "GptTmpl.inf not found: $path"
            continue
        }

        $parsed = & $parseTemplate $path
        if ($null -eq $parsed) {
            $result.Errors[$guid] = "Could not read $path"
            continue
        }

        $anyTemplateRead = $true
        [void]$result.TemplatesRead.Add($guid)

        if ($parsed.ContainsKey('SeInteractiveLogonRight')) {
            if ($null -eq $mergedInteractive) { $mergedInteractive = [System.Collections.Generic.List[hashtable]]::new() }
            foreach ($p in @($parsed['SeInteractiveLogonRight'])) { $mergedInteractive.Add($p) }
        }
        if ($parsed.ContainsKey('SeRemoteInteractiveLogonRight')) {
            if ($null -eq $mergedRemote) { $mergedRemote = [System.Collections.Generic.List[hashtable]]::new() }
            foreach ($p in @($parsed['SeRemoteInteractiveLogonRight'])) { $mergedRemote.Add($p) }
        }
    }

    if (-not $anyTemplateRead) {
        # No template readable at all → leave both rights $null so checks SKIP.
        $result.Errors['Summary'] = "No Domain Controllers OU GptTmpl.inf could be read under $sysvolBase (insufficient SYSVOL access or not run against the domain)."
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'User Rights Assignment: no DC-OU security template readable (ADPRIV-026/027 will Not-Assess)'
        }
        $result.TemplatesRead = @($result.TemplatesRead)
        return $result
    }

    # Convert merged lists (which may legitimately be empty if the section was
    # present-but-blank) to arrays. $null stays $null → SKIP for that one right.
    if ($null -ne $mergedInteractive) { $result.InteractiveLogon       = @($mergedInteractive) }
    if ($null -ne $mergedRemote)      { $result.RemoteInteractiveLogon = @($mergedRemote) }
    $result.TemplatesRead = @($result.TemplatesRead)

    if (-not $Quiet) {
        $ic = if ($null -eq $result.InteractiveLogon) { 'n/a' } else { @($result.InteractiveLogon).Count }
        $rc = if ($null -eq $result.RemoteInteractiveLogon) { 'n/a' } else { @($result.RemoteInteractiveLogon).Count }
        Write-ProgressLine -Phase RECON -Message "User Rights Assignment parsed from $($result.TemplatesRead.Count) template(s): InteractiveLogon=$ic principal(s), RDP=$rc principal(s)"
    }

    return $result
}
