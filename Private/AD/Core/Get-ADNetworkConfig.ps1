# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADNetworkConfig {
    <#
    .SYNOPSIS
        Collects domain-wide network-layer security policy from SYSVOL.
    .DESCRIPTION
        Reads the security-settings INI (GptTmpl.inf) from the Default Domain Policy
        and Default Domain Controllers Policy in SYSVOL. Parses [Registry Values] and
        [Service General Setting] sections to surface the settings that govern the
        NTLM-relay, LLMNR/NetBIOS poisoning, and IPv6/mitm6 attack chains.

        Custom GPOs that override these defaults are NOT walked in this MVP — auditors
        who use non-default GPOs to set these values will see this collector report
        "Not configured" and should rely on the verbose Details payload to investigate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        SysvolReadable         = $false
        DefaultDomainPolicy    = $null
        DefaultDCPolicy        = $null
        Errors                 = @()
    }

    # Derive DNS domain name from the DN, e.g. "DC=contoso,DC=com" -> "contoso.com"
    $domainDns = ($Connection.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()
    if (-not $domainDns) {
        $result.Errors += 'Could not derive DNS domain name from connection.'
        return $result
    }

    # Well-known GUIDs for the two default GPOs that ship with every AD domain
    $ddpGuid  = '{31B2F340-016D-11D2-945F-00C04FB984F9}'  # Default Domain Policy
    $ddcpGuid = '{6AC1786C-016F-11D2-945F-00C04fB984F9}'  # Default Domain Controllers Policy

    $sysvolRoot = "\\$domainDns\SYSVOL\$domainDns\Policies"
    $gptRelative = 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'

    Write-Verbose "Reading default-policy security settings from $sysvolRoot"

    foreach ($spec in @(
        @{ Key = 'DefaultDomainPolicy'; Guid = $ddpGuid;  Label = 'Default Domain Policy' }
        @{ Key = 'DefaultDCPolicy';     Guid = $ddcpGuid; Label = 'Default Domain Controllers Policy' }
    )) {
        $path = Join-Path (Join-Path $sysvolRoot $spec.Guid) $gptRelative
        try {
            if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
                $result.Errors += "$($spec.Label): GptTmpl.inf not found at $path (policy has no security-settings section, or insufficient SYSVOL access)."
                continue
            }
            $result.SysvolReadable = $true
            $content = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
            $result[$spec.Key] = ConvertFrom-GptTmpl -Content $content
        } catch {
            $result.Errors += "$($spec.Label): $($_.Exception.Message)"
        }
    }

    return $result
}

function ConvertFrom-GptTmpl {
    <#
    .SYNOPSIS
        Parses the INI-style GptTmpl.inf content into a structured hashtable.
    .DESCRIPTION
        GptTmpl.inf is a Microsoft security-template INI. Sections of interest:
            [Registry Values]      key=type,value     (type 4 = REG_DWORD)
            [Service General Setting]  ServiceName,StartType,"AclDescriptor"
            [System Access]        key = value

        Returns:
            @{
                Registry = @{ '<full key path>' = @{ Type=int; Value=string } }
                Services = @{ '<service>' = @{ StartType=int; Acl=string } }
                SystemAccess = @{ '<key>' = '<value>' }
            }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $parsed = @{
        Registry     = @{}
        Services     = @{}
        SystemAccess = @{}
    }

    $currentSection = $null
    # Strip a UTF-16 BOM if present (Windows secedit emits these as UTF-16 LE)
    $Content = $Content -replace "^﻿", ''

    foreach ($rawLine in ($Content -split "\r?\n")) {
        $line = $rawLine.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith(';')) { continue }
        if ($line.StartsWith('#')) { continue }

        if ($line -match '^\[(.+)\]$') {
            $currentSection = $Matches[1].Trim()
            continue
        }

        switch -Regex ($currentSection) {
            '^Registry Values$' {
                # key=type,value   (value may contain commas inside quotes)
                if ($line -match '^([^=]+?)\s*=\s*(\d+)\s*,\s*(.*)$') {
                    $key = $Matches[1].Trim()
                    $type = [int]$Matches[2]
                    $val = $Matches[3].Trim()
                    $parsed.Registry[$key] = @{ Type = $type; Value = $val }
                }
            }
            '^Service General Setting$' {
                # ServiceName,StartType,"AclDescriptor"
                if ($line -match '^([^,]+?)\s*,\s*(\d+)\s*,?\s*(.*)$') {
                    $svc = $Matches[1].Trim()
                    $start = [int]$Matches[2]
                    $acl = $Matches[3].Trim().Trim('"')
                    $parsed.Services[$svc] = @{ StartType = $start; Acl = $acl }
                }
            }
            '^System Access$' {
                if ($line -match '^([^=]+?)\s*=\s*(.*)$') {
                    $parsed.SystemAccess[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            default { }
        }
    }

    return $parsed
}
