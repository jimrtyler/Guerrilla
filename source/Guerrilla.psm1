$script:ModuleRoot = $PSScriptRoot

function Get-GuerrillaDataRoot {
    <#
    .SYNOPSIS
        Returns the per-user data root directory for Guerrilla on the current OS.
    .DESCRIPTION
        Windows : $env:APPDATA\Guerrilla
        macOS   : ~/Library/Application Support/Guerrilla
        Linux   : $XDG_CONFIG_HOME/Guerrilla, falling back to ~/.config/Guerrilla

        Previously the module hardcoded $env:APPDATA everywhere, which is $null on
        non-Windows — Join-Path silently returned a relative path and config/state
        ended up in the current working directory instead of a user-data location.
    #>
    [CmdletBinding()]
    param()

    # $IsWindows is automatic in PowerShell 6+. Be defensive in case anyone ever
    # imports this from Windows PowerShell 5.1 (where the var is undefined and
    # everything is Windows anyway).
    $onWindows = if (Test-Path variable:IsWindows) { $IsWindows } else { $true }

    $newRoot = if ($onWindows) {
        Join-Path $env:APPDATA 'Guerrilla'
    } elseif ($IsMacOS) {
        Join-Path $HOME 'Library/Application Support/Guerrilla'
    } else {
        $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' }
        Join-Path $base 'Guerrilla'
    }

    # Back-compat: the module was renamed PSGuerrilla -> Guerrilla. If this install
    # predates the rename, carry the old per-user data (reports, config, patrol state)
    # forward exactly once — when the new root does not yet exist but the old one does.
    # Idempotent: after the first migration the new root exists and this is skipped.
    if (-not (Test-Path $newRoot)) {
        $oldRoot = Join-Path (Split-Path $newRoot -Parent) 'PSGuerrilla'
        if ((Test-Path $oldRoot) -and @(Get-ChildItem -LiteralPath $oldRoot -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            try {
                Copy-Item -LiteralPath $oldRoot -Destination $newRoot -Recurse -Force -ErrorAction Stop
                Write-Verbose "Migrated Guerrilla data from $oldRoot to $newRoot (post-rename)."
            } catch {
                Write-Verbose "Guerrilla data migration from $oldRoot failed: $($_.Exception.Message)"
            }
        }
    }
    return $newRoot
}

# Helper used during module bootstrap to turn "10.0.0.0/16" into the
# { Network = uint32; Mask = uint32 } pair that all the IP classification
# code expects. Replaces three near-identical inline blocks that used to
# live below.
function ConvertTo-ParsedCidr {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $null }
    try {
        $ipBytes = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        $prefix = [int]$parts[1]
        $ipUint = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
        $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
        return @{ Network = $ipUint -band $mask; Mask = $mask }
    } catch {
        return $null
    }
}

# Load data files into script-scoped variables
$script:CloudIpRanges = Get-Content -Path (Join-Path $ModuleRoot 'Data/CloudIpRanges.json') -Raw | ConvertFrom-Json
$script:KnownAttackerIps = Get-Content -Path (Join-Path $ModuleRoot 'Data/KnownAttackerIps.json') -Raw | ConvertFrom-Json
$script:SuspiciousCountries = Get-Content -Path (Join-Path $ModuleRoot 'Data/SuspiciousCountries.json') -Raw | ConvertFrom-Json
$script:VpnTorProxies = Get-Content -Path (Join-Path $ModuleRoot 'Data/VpnTorProxies.json') -Raw | ConvertFrom-Json

# Pre-parse CIDR ranges into uint32 network/mask pairs for fast bitwise matching
$script:ParsedProviderNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:CloudProviderClasses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:AttackerIpSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

# Parse the providers structure (v2.0.0 format with metadata)
$providerData = if ($script:CloudIpRanges.providers) { $script:CloudIpRanges.providers } else { $script:CloudIpRanges }

foreach ($providerName in ($providerData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) {
    [void]$script:CloudProviderClasses.Add($providerName)
    foreach ($cidr in $providerData.$providerName) {
        $parsed = ConvertTo-ParsedCidr -Cidr $cidr
        if ($parsed) {
            $parsed.Provider = $providerName
            $script:ParsedProviderNetworks.Add($parsed)
        } else {
            Write-Verbose "Skipping invalid CIDR: $cidr ($providerName)"
        }
    }
}

# Backward compat: ParsedAwsNetworks and ParsedCloudNetworks still available
$script:ParsedAwsNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:ParsedCloudNetworks = [System.Collections.Generic.List[hashtable]]::new()
foreach ($entry in $script:ParsedProviderNetworks) {
    if ($entry.Provider -eq 'aws') {
        $script:ParsedAwsNetworks.Add($entry)
    } else {
        $script:ParsedCloudNetworks.Add($entry)
    }
}

# Parse VPN/Tor/Proxy CIDRs
$script:ParsedVpnNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:ParsedProxyNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:TorExitNodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:VpnProviderNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

if ($script:VpnTorProxies) {
    foreach ($cidr in $script:VpnTorProxies.vpn_provider_cidrs) {
        $parsed = ConvertTo-ParsedCidr -Cidr $cidr
        if ($parsed) { $script:ParsedVpnNetworks.Add($parsed) }
    }
    foreach ($cidr in $script:VpnTorProxies.proxy_service_cidrs) {
        $parsed = ConvertTo-ParsedCidr -Cidr $cidr
        if ($parsed) { $script:ParsedProxyNetworks.Add($parsed) }
    }
    foreach ($ip in $script:VpnTorProxies.tor_exit_nodes) {
        [void]$script:TorExitNodes.Add($ip)
    }
    foreach ($name in $script:VpnTorProxies.vpn_provider_names) {
        [void]$script:VpnProviderNames.Add($name)
    }
}

foreach ($entry in $script:KnownAttackerIps.ips) {
    [void]$script:AttackerIpSet.Add($entry.address)
}

# Config path
$script:ConfigPath = Join-Path (Get-GuerrillaDataRoot) 'config.json'

# Dot-source internal engine helpers and the theater checks (recursive over the
# source tree). internal/ holds the collectors and engine; checks/ holds the
# per-theater Invoke-*Checks files. Both are loaded before public so the exported
# cmdlets can call them.
foreach ($dir in 'internal', 'checks') {
    foreach ($file in Get-ChildItem -Path (Join-Path $ModuleRoot $dir) -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue) {
        . $file.FullName
    }
}

# Dot-source public functions (the exported cmdlets)
foreach ($file in Get-ChildItem -Path (Join-Path $ModuleRoot 'public') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue) {
    . $file.FullName
}

# IP classification cache (reset per module load)
$script:IpClassCache = @{}
$script:GeoCache = @{}

# Test-mode flag (reset per module load). When true, the console timestamp helpers
# (Write-ProgressLine / Write-OperationHeader) render zeroed times so -TestMode demo
# output is deterministic. The audit cmdlets set it per run (self-healing).
$script:GuerrillaTestMode = $false

# SID-resolution caches/tables (reset per module load). Resolve-ADSid references all
# three; without these the AD ACL/DCSync/GPO-delegation collectors throw
# "You cannot call a method on a null-valued expression" and silently return empty.
$script:SidCache = @{}

$script:WellKnownSids = @{
    'S-1-0-0'      = 'NULL';                       'S-1-1-0'      = 'Everyone'
    'S-1-2-0'      = 'Local';                      'S-1-3-0'      = 'Creator Owner'
    'S-1-3-1'      = 'Creator Group';              'S-1-5-2'      = 'Network'
    'S-1-5-4'      = 'Interactive';                'S-1-5-6'      = 'Service'
    'S-1-5-7'      = 'Anonymous';                  'S-1-5-9'      = 'Enterprise Domain Controllers'
    'S-1-5-10'     = 'Principal Self';             'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-13'     = 'Terminal Server Users';      'S-1-5-18'     = 'SYSTEM'
    'S-1-5-19'     = 'Local Service';              'S-1-5-20'     = 'Network Service'
    'S-1-5-32-544' = 'Administrators';             'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests';                     'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators';           'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators';           'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'Remote Desktop Users';       'S-1-5-32-557' = 'Incoming Forest Trust Builders'
    'S-1-5-32-562' = 'Distributed COM Users';      'S-1-5-32-568' = 'IIS_IUSRS'
    'S-1-5-32-569' = 'Cryptographic Operators';    'S-1-5-32-573' = 'Event Log Readers'
    'S-1-5-32-578' = 'Hyper-V Administrators';     'S-1-5-32-579' = 'Access Control Assistance Operators'
    'S-1-5-32-580' = 'Remote Management Users'
}

# Domain-RELATIVE RIDs (last sub-authority of a domain SID, S-1-5-21-...-RID)
$script:WellKnownRids = @{
    500 = 'Administrator';  501 = 'Guest';                     502 = 'krbtgt'
    512 = 'Domain Admins';  513 = 'Domain Users';              514 = 'Domain Guests'
    515 = 'Domain Computers'; 516 = 'Domain Controllers';      517 = 'Cert Publishers'
    518 = 'Schema Admins';  519 = 'Enterprise Admins';         520 = 'Group Policy Creator Owners'
    521 = 'Read-only Domain Controllers'; 522 = 'Cloneable Domain Controllers'
    525 = 'Protected Users'; 526 = 'Key Admins';               527 = 'Enterprise Key Admins'
    553 = 'RAS and IAS Servers'
}

# --- Color palette ---
# Defined once in module scope so per-file color blocks all point at the same
# palette. Change a shade here and every cmdlet picks it up automatically.
$script:Palette = @{
    Amber     = $PSStyle.Foreground.FromRgb(0xC6, 0x7A, 0x1F)
    Khaki     = $PSStyle.Foreground.FromRgb(0xB8, 0xA9, 0x7E)
    Gray      = $PSStyle.Foreground.FromRgb(0x8B, 0x8B, 0x7A)
    Sage      = $PSStyle.Foreground.FromRgb(0x6B, 0x8E, 0x6B)
    Parchment = $PSStyle.Foreground.FromRgb(0xF5, 0xF0, 0xE6)
    Gold      = $PSStyle.Foreground.FromRgb(0xD4, 0xA8, 0x43)
    Red       = $PSStyle.Foreground.FromRgb(0xCC, 0x55, 0x55)
    Reset     = $PSStyle.Reset
}

# --- Spectre.Console capability detection ---
Initialize-SpectreCapability

# --- Config migration from PSRecon ---
Initialize-ConfigMigration

# --- Banner on import ---
Write-GuerrillaBanner

# --- Backward-compatibility aliases ---
$aliasMap = @{
    # PSRecon -> Guerrilla rename aliases
    'Invoke-GoogleRecon'           = 'Invoke-Recon'
    'Get-ReconAlerts'              = 'Get-DeadDrop'
    'Send-ReconAlert'              = 'Send-Signal'
    'Send-ReconAlertSendGrid'      = 'Send-SignalSendGrid'
    'Send-ReconAlertMailgun'       = 'Send-SignalMailgun'
    'Send-ReconAlertTwilio'        = 'Send-SignalTwilio'
    'Set-ReconConfig'              = 'Set-Safehouse'
    'Get-ReconConfig'              = 'Get-Safehouse'
    'Register-ReconScheduledTask'  = 'Register-Patrol'
    'Unregister-ReconScheduledTask' = 'Unregister-Patrol'
    'Get-ReconScheduledTask'       = 'Get-Patrol'

    # Theater-disambiguating aliases — Invoke-Recon and Invoke-Reconnaissance
    # are easily confused (different theaters). These names make the intent
    # obvious at the call site.
    'Invoke-WorkspaceRecon'        = 'Invoke-Recon'           # Google Workspace user-behavior recon
    'Invoke-ADRecon'               = 'Invoke-Reconnaissance'  # Active Directory configuration audit
    'Invoke-CloudRecon'            = 'Invoke-Infiltration'    # Entra ID / Azure / Intune / M365 audit
}

foreach ($old in $aliasMap.Keys) {
    $new = $aliasMap[$old]
    Set-Alias -Name $old -Value $new -Scope Script
    Export-ModuleMember -Alias $old
}

# Pester test hatch: Tests\Helpers\TestHelpers.psm1 sets PSGUERRILLA_TEST=1 before
# Import-Module so existing tests can call private functions directly without
# having to wrap every assertion in `InModuleScope Guerrilla { ... }`. New tests
# should prefer InModuleScope and avoid relying on this. End-user code must NOT
# set this variable — it intentionally widens the public API surface.
if ($env:PSGUERRILLA_TEST -eq '1') {
    Export-ModuleMember -Function *
}
