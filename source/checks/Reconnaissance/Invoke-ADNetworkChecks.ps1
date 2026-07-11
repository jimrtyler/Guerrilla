# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADNetworkChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADNetworkChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Recon$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# Helper: parse a [Registry Values] DWORD entry's numeric value.
# GptTmpl writes DWORDs as "4,<decimal>" but admins occasionally enter "0x<hex>".
# [Convert]::ToInt32 doesn't accept the 0x prefix in the (string,int) overload, so
# strip it. Wrap in try/catch — pathological values shouldn't take a check down.
function ConvertTo-PolicyRegInt {
    param($Entry)
    if (-not $Entry) { return $null }
    $raw = "$($Entry.Value)".Trim()
    if (-not $raw) { return $null }
    if ($raw -match '^0x([0-9a-fA-F]+)$') {
        try { return [int]([Convert]::ToInt32($Matches[1], 16)) } catch { return $null }
    }
    if ($raw -match '^-?\d+$') {
        try { return [int]$raw } catch { return $null }
    }
    return $null
}

# Helper: read a DWORD from DefaultDCPolicy registry values
function Get-DCPolicyReg {
    param(
        [hashtable]$NetworkConfig,
        [string]$KeyPath
    )
    if (-not $NetworkConfig.DefaultDCPolicy) { return $null }
    return ConvertTo-PolicyRegInt -Entry $NetworkConfig.DefaultDCPolicy.Registry[$KeyPath]
}

function Get-DDPolicyReg {
    param(
        [hashtable]$NetworkConfig,
        [string]$KeyPath
    )
    if (-not $NetworkConfig.DefaultDomainPolicy) { return $null }
    return ConvertTo-PolicyRegInt -Entry $NetworkConfig.DefaultDomainPolicy.Registry[$KeyPath]
}

# Helper: read a service start type from either Default Domain Policy or Default DC Policy.
function Get-PolicyServiceStart {
    param(
        [hashtable]$NetworkConfig,
        [string]$ServiceName,
        [ValidateSet('DDP', 'DDCP')]
        [string]$Source
    )
    $section = if ($Source -eq 'DDP') { $NetworkConfig.DefaultDomainPolicy } else { $NetworkConfig.DefaultDCPolicy }
    if (-not $section) { return $null }
    $svc = $section.Services[$ServiceName]
    if (-not $svc) { return $null }
    return [int]$svc.StartType
}

# Helper: produce a SKIP finding when the network config payload is unavailable.
function New-NetworkSkipFinding {
    param(
        [hashtable]$CheckDefinition,
        [string]$Reason
    )
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' -CurrentValue $Reason
}

# ── ADNET-001: LDAP Signing Required on DCs ────────────────────────────────
function Test-ReconADNET001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Network policy data not available (SYSVOL unreadable or collection skipped).'
    }
    if (-not $net.DefaultDCPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Controllers Policy GptTmpl.inf not readable.'
    }

    $val = Get-DCPolicyReg -NetworkConfig $net `
        -KeyPath 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'

    if ($null -eq $val) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'LDAPServerIntegrity not set in Default Domain Controllers Policy (DC default may apply, but it is not policy-enforced)' `
            -Details @{ ConfiguredValue = $null; RequiredValue = 2 }
    }
    if ($val -eq 2) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Default Domain Controllers Policy requires LDAP signing (LDAPServerIntegrity = 2)' `
            -Details @{ ConfiguredValue = 2 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Controllers Policy sets LDAPServerIntegrity = $val (0 = None, 1 = Negotiate; should be 2 = Require)" `
        -Details @{ ConfiguredValue = $val; RequiredValue = 2 }
}

# ── ADNET-002: LDAP Channel Binding Enforced on DCs ────────────────────────
function Test-ReconADNET002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDCPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Controllers Policy not readable from SYSVOL.'
    }
    $val = Get-DCPolicyReg -NetworkConfig $net `
        -KeyPath 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
    if ($null -eq $val) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'LdapEnforceChannelBinding not set in Default Domain Controllers Policy' `
            -Details @{ ConfiguredValue = $null; RequiredValue = 2 }
    }
    if ($val -eq 2) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Default Domain Controllers Policy enforces LDAP channel binding (LdapEnforceChannelBinding = 2)' `
            -Details @{ ConfiguredValue = 2 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Controllers Policy sets LdapEnforceChannelBinding = $val (0 = Never, 1 = When supported; should be 2 = Always)" `
        -Details @{ ConfiguredValue = $val; RequiredValue = 2 }
}

# ── ADNET-003: SMB Server Signing Required ─────────────────────────────────
function Test-ReconADNET003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDomainPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Policy not readable from SYSVOL.'
    }
    $val = Get-DDPolicyReg -NetworkConfig $net `
        -KeyPath 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
    if ($null -eq $val) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'RequireSecuritySignature (LanManServer) not set in Default Domain Policy' `
            -Details @{ ConfiguredValue = $null; RequiredValue = 1 }
    }
    if ($val -eq 1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Default Domain Policy requires SMB server signing' `
            -Details @{ ConfiguredValue = 1 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Policy sets LanManServer\RequireSecuritySignature = $val (should be 1)" `
        -Details @{ ConfiguredValue = $val; RequiredValue = 1 }
}

# ── ADNET-004: SMB Client Signing Required ─────────────────────────────────
function Test-ReconADNET004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDomainPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Policy not readable from SYSVOL.'
    }
    $val = Get-DDPolicyReg -NetworkConfig $net `
        -KeyPath 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'
    if ($null -eq $val) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'RequireSecuritySignature (LanmanWorkstation) not set in Default Domain Policy' `
            -Details @{ ConfiguredValue = $null; RequiredValue = 1 }
    }
    if ($val -eq 1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Default Domain Policy requires SMB client signing' `
            -Details @{ ConfiguredValue = 1 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Policy sets LanmanWorkstation\RequireSecuritySignature = $val (should be 1)" `
        -Details @{ ConfiguredValue = $val; RequiredValue = 1 }
}

# ── ADNET-005: LLMNR Disabled ──────────────────────────────────────────────
# Note: the LLMNR control is delivered via an administrative template, which writes
# to Registry.pol (binary PReg format) rather than GptTmpl.inf. This MVP collector
# does not parse Registry.pol, so we can confirm a PASS only if an admin has set
# the same value via the security-settings [Registry Values] section (uncommon).
# Absence from GptTmpl.inf does NOT prove the mitigation is missing — but it does
# mean we couldn't verify, which is worth a WARN.
function Test-ReconADNET005 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDomainPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Policy not readable from SYSVOL.'
    }
    $val = Get-DDPolicyReg -NetworkConfig $net `
        -KeyPath 'MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
    if ($null -eq $val) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'LLMNR EnableMulticast not in GptTmpl.inf. The administrative-template path (Registry.pol) is not parsed by this MVP — verify directly: gpresult /h or registry key HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast on a member host.' `
            -Details @{ ConfiguredValue = $null; RequiredValue = 0; Caveat = 'Registry.pol not parsed in MVP' }
    }
    if ($val -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'LLMNR disabled via Default Domain Policy security settings (EnableMulticast = 0)' `
            -Details @{ ConfiguredValue = 0 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Policy sets DNSClient\EnableMulticast = $val (should be 0 to disable LLMNR)" `
        -Details @{ ConfiguredValue = $val; RequiredValue = 0 }
}

# ── ADNET-006: NetBIOS over TCP/IP Configuration ───────────────────────────
function Test-ReconADNET006 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    # No reliable signal in GPO security settings for NBT — it's interface-specific.
    # Surface the gap so the auditor knows to check DHCP/imaging.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'NetBIOS over TCP/IP cannot be disabled via standard GPO security settings; verify out-of-band (DHCP option 1, registry GPO, or imaging baseline)' `
        -Details @{ Note = 'Per-interface registry under Tcpip\Parameters\Interfaces\<GUID>\NetbiosOptions; not detectable from SYSVOL alone' }
}

# ── ADNET-007: IPv6 mitm6 Mitigation ───────────────────────────────────────
function Test-ReconADNET007 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDomainPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Policy not readable from SYSVOL.'
    }
    $val = Get-DDPolicyReg -NetworkConfig $net `
        -KeyPath 'MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents'
    if ($null -eq $val) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'DisabledComponents not in GptTmpl.inf. This is typically set via administrative template (Registry.pol) which the MVP does not parse — verify directly: registry HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents on a member host. Either set it to 0xFF if IPv6 is unused, or confirm RA Guard / DHCPv6 Guard at the switching layer.' `
            -Details @{ ConfiguredValue = $null; Caveat = 'Registry.pol not parsed in MVP' }
    }
    # 0xFF (255) = disable all components; 0x20 = prefer IPv4 over IPv6 (weaker); 0x0 = default
    if ($val -eq 0xFF) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'IPv6 components disabled via GPO (DisabledComponents = 0xFF) — mitm6 attack vector blocked' `
            -Details @{ ConfiguredValue = '0xFF' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue ("IPv6 DisabledComponents = $val (decimal). Not fully disabled. Confirm RA Guard / DHCPv6 Guard at the switching layer, or set to 0xFF if IPv6 is unused.") `
        -Details @{ ConfiguredValue = $val }
}

# ── ADNET-008: WPAD Auto-Discovery Disabled ────────────────────────────────
function Test-ReconADNET008 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDomainPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Policy not readable from SYSVOL.'
    }
    $wpadSvcStart = Get-PolicyServiceStart -NetworkConfig $net -ServiceName 'WinHttpAutoProxySvc' -Source 'DDP'
    if ($wpadSvcStart -eq 4) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'WinHttpAutoProxySvc disabled by Default Domain Policy (no WPAD lookups will occur)' `
            -Details @{ ServiceStartType = 4 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'WinHttpAutoProxySvc not disabled by Default Domain Policy. Verify the DNS GlobalQueryBlockList contains "wpad" out-of-band: dnscmd /Info /GlobalQueryBlockList' `
        -Details @{ ServiceStartType = $wpadSvcStart }
}

# ── ADNET-009: Print Spooler Service on Domain Controllers ─────────────────
function Test-ReconADNET009 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDCPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Controllers Policy not readable from SYSVOL.'
    }
    $spoolerStart = Get-PolicyServiceStart -NetworkConfig $net -ServiceName 'Spooler' -Source 'DDCP'
    if ($spoolerStart -eq 4) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Print Spooler disabled by Default Domain Controllers Policy (PrinterBug coercion neutralized at DCs)' `
            -Details @{ ServiceStartType = 4 }
    }
    if ($null -eq $spoolerStart) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Print Spooler is not explicitly disabled by Default Domain Controllers Policy — relies on per-DC manual disable, which drifts' `
            -Details @{ ServiceStartType = $null; RequiredStartType = 4 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Controllers Policy sets Spooler StartType = $spoolerStart (2 = Auto, 3 = Manual; should be 4 = Disabled)" `
        -Details @{ ServiceStartType = $spoolerStart; RequiredStartType = 4 }
}

# ── ADNET-010: WebClient Service Default State ─────────────────────────────
function Test-ReconADNET010 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if (-not $net -or -not $net.DefaultDomainPolicy) {
        return New-NetworkSkipFinding -CheckDefinition $CheckDefinition `
            -Reason 'Default Domain Policy not readable from SYSVOL.'
    }
    $webclientStart = Get-PolicyServiceStart -NetworkConfig $net -ServiceName 'WebClient' -Source 'DDP'
    if ($webclientStart -eq 4) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'WebClient (WebDAV redirector) disabled by Default Domain Policy — workstation HTTP coercion path closed' `
            -Details @{ ServiceStartType = 4 }
    }
    if ($null -eq $webclientStart) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'WebClient service not explicitly disabled by Default Domain Policy. On-demand start (Windows default) — coercion via UNC-with-hostname-@-port still possible from workstations.' `
            -Details @{ ServiceStartType = $null; RecommendedStartType = 4 }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Default Domain Policy sets WebClient StartType = $webclientStart (should be 4 = Disabled for non-WebDAV environments)" `
        -Details @{ ServiceStartType = $webclientStart; RecommendedStartType = 4 }
}
