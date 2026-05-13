$ModuleRoot = $PSScriptRoot

# Load data files into script-scoped variables
$script:CloudIpRanges = Get-Content -Path (Join-Path $ModuleRoot 'Data/CloudIpRanges.json') -Raw | ConvertFrom-Json
$script:KnownAttackerIps = Get-Content -Path (Join-Path $ModuleRoot 'Data/KnownAttackerIps.json') -Raw | ConvertFrom-Json
$script:SuspiciousCountries = Get-Content -Path (Join-Path $ModuleRoot 'Data/SuspiciousCountries.json') -Raw | ConvertFrom-Json
$script:VpnTorProxies = Get-Content -Path (Join-Path $ModuleRoot 'Data/VpnTorProxies.json') -Raw | ConvertFrom-Json

# Pre-parse CIDR ranges into uint32 network/mask pairs for fast bitwise matching
# Each entry: @{ Network = [uint32]; Mask = [uint32]; Provider = [string] }
$script:ParsedProviderNetworks = [System.Collections.Generic.List[hashtable]]::new()
$script:CloudProviderClasses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:AttackerIpSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

# Parse the providers structure (v2.0.0 format with metadata)
$providerData = if ($script:CloudIpRanges.providers) { $script:CloudIpRanges.providers } else { $script:CloudIpRanges }

foreach ($providerName in ($providerData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) {
    [void]$script:CloudProviderClasses.Add($providerName)
    foreach ($cidr in $providerData.$providerName) {
        $parts = $cidr -split '/'
        try {
            $ipBytes = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
            $prefix = [int]$parts[1]
            $ipUint = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
            $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
            $network = $ipUint -band $mask
            $script:ParsedProviderNetworks.Add(@{ Network = $network; Mask = $mask; Provider = $providerName })
        } catch {
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
        $parts = $cidr -split '/'
        try {
            $ipBytes = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
            $prefix = [int]$parts[1]
            $ipUint = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
            $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
            $network = $ipUint -band $mask
            $script:ParsedVpnNetworks.Add(@{ Network = $network; Mask = $mask })
        } catch { }
    }
    foreach ($cidr in $script:VpnTorProxies.proxy_service_cidrs) {
        $parts = $cidr -split '/'
        try {
            $ipBytes = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
            $prefix = [int]$parts[1]
            $ipUint = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
            $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
            $network = $ipUint -band $mask
            $script:ParsedProxyNetworks.Add(@{ Network = $network; Mask = $mask })
        } catch { }
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
$script:ConfigPath = Join-Path $env:APPDATA 'PSGuerrilla/config.json'

# Dot-source private functions (recursive to pick up subdirectories)
foreach ($file in Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue) {
    . $file.FullName
}

# Dot-source public functions
foreach ($file in Get-ChildItem -Path (Join-Path $ModuleRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue) {
    . $file.FullName
}

# IP classification cache (reset per module load)
$script:IpClassCache = @{}
$script:GeoCache = @{}

# --- Spectre.Console capability detection ---
Initialize-SpectreCapability

# --- Config migration from PSRecon ---
Initialize-ConfigMigration

# --- Banner on import ---
Write-GuerrillaBanner

# --- Backward-compatibility aliases ---
$script:DeprecationWarned = @{}

$aliasMap = @{
    # PSRecon -> PSGuerrilla rename aliases
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

# Test mode: export all functions (including private) for unit testing
if ($env:PSGUERRILLA_TEST -eq '1') {
    Export-ModuleMember -Function *
}
