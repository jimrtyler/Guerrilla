# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-LdapQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$SearchRoot,

        [Parameter(Mandatory)]
        [string]$Filter,

        [string[]]$Properties = @('distinguishedName'),

        [System.DirectoryServices.SearchScope]$Scope = 'Subtree',

        [int]$PageSize = 1000,

        [int]$SizeLimit = 0,

        [switch]$RawResults
    )

    $searcher = [System.DirectoryServices.DirectorySearcher]::new($SearchRoot)
    $searcher.Filter = $Filter
    $searcher.SearchScope = $Scope
    $searcher.PageSize = $PageSize
    if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }

    # Request security descriptors in binary form for ACL analysis
    $needsSD = $Properties -contains 'ntsecuritydescriptor' -or $Properties -contains 'ntSecurityDescriptor'
    if ($needsSD) {
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor
                                  [System.DirectoryServices.SecurityMasks]::Owner -bor
                                  [System.DirectoryServices.SecurityMasks]::Group
    }

    foreach ($prop in $Properties) {
        [void]$searcher.PropertiesToLoad.Add($prop.ToLower())
    }

    try {
        $searchResults = $searcher.FindAll()
    } catch {
        # A missing container (e.g. no AD CS / Enterprise CA, or an empty DNS partition)
        # is a legitimate state, not a failure — surface it quietly so clean domains don't
        # emit alarming warnings. The downstream check still SKIPs the same way.
        if ($_.Exception.Message -match 'no such object|0x80072030') {
            Write-Verbose "LDAP query found no matching container/object for: $Filter — $_"
        } else {
            Write-Warning "LDAP query failed: $Filter — $_"
        }
        return @()
    }

    if ($RawResults) {
        return $searchResults
    }

    $output = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($result in $searchResults) {
        $obj = @{}
        foreach ($propName in $result.Properties.PropertyNames) {
            $values = $result.Properties[$propName]
            if ($values.Count -eq 1) {
                $obj[$propName] = Convert-LdapValue -Name $propName -Value $values[0]
            } elseif ($values.Count -gt 1) {
                $obj[$propName] = @(foreach ($v in $values) { Convert-LdapValue -Name $propName -Value $v })
            }
        }
        $output.Add($obj)
    }

    $searchResults.Dispose()
    $searcher.Dispose()

    return @($output)
}

function Convert-LdapValue {
    [CmdletBinding()]
    param(
        [string]$Name,
        [object]$Value
    )

    if ($null -eq $Value) { return $null }

    $nameLower = $Name.ToLower()

    # Byte arrays: SIDs, GUIDs, security descriptors
    if ($Value -is [byte[]]) {
        switch -Wildcard ($nameLower) {
            'objectsid'         { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value }
            'objectguid'        { return ([guid]$Value).ToString() }
            'securityidentifier' { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value }
            'msds-generationid' { return [BitConverter]::ToString($Value) }
            'sidhistory'        {
                try { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value }
                catch { return [BitConverter]::ToString($Value) }
            }
            'ntsecuritydescriptor' { return $Value }  # Keep raw for ACL parsing
            'msds-allowedtoactonbehalfofotheridentity' { return $Value }  # Raw SD
            default             { return [BitConverter]::ToString($Value) }
        }
    }

    # Large integers (timestamps, password ages)
    if ($Value -is [System.Int64] -or $Value -is [long]) {
        switch -Wildcard ($nameLower) {
            'pwdlastset'         { return Convert-FileTimeToDateTime $Value }
            'lastlogontimestamp'  { return Convert-FileTimeToDateTime $Value }
            'lastlogon'          { return Convert-FileTimeToDateTime $Value }
            'accountexpires'     { return Convert-FileTimeToDateTime $Value }
            'badpasswordtime'    { return Convert-FileTimeToDateTime $Value }
            'lockouttime'        { return Convert-FileTimeToDateTime $Value }
            'msds-lastsuccessfulinteractivelogontime' { return Convert-FileTimeToDateTime $Value }
            'maxpwdage'          { return Convert-ADTimeSpan $Value }
            'minpwdage'          { return Convert-ADTimeSpan $Value }
            'lockoutduration'    { return Convert-ADTimeSpan $Value }
            'lockoutobservationwindow' { return Convert-ADTimeSpan $Value }
            'forcelogoff'        { return Convert-ADTimeSpan $Value }
            default              { return $Value }
        }
    }

    # COM objects (IADsLargeInteger)
    if ($Value -is [System.__ComObject]) {
        try {
            $adsLargeInt = [System.Runtime.InteropServices.Marshal]::GetObjectForIUnknown(
                [System.Runtime.InteropServices.Marshal]::GetIUnknownForObject($Value)
            )
            $highPart = $adsLargeInt.GetType().InvokeMember('HighPart', 'GetProperty', $null, $adsLargeInt, $null)
            $lowPart  = $adsLargeInt.GetType().InvokeMember('LowPart', 'GetProperty', $null, $adsLargeInt, $null)
            $int64Val = ([int64]$highPart -shl 32) -bor [uint32]$lowPart

            switch -Wildcard ($nameLower) {
                'pwdlastset'         { return Convert-FileTimeToDateTime $int64Val }
                'lastlogontimestamp'  { return Convert-FileTimeToDateTime $int64Val }
                'lastlogon'          { return Convert-FileTimeToDateTime $int64Val }
                'accountexpires'     { return Convert-FileTimeToDateTime $int64Val }
                'maxpwdage'          { return Convert-ADTimeSpan $int64Val }
                'minpwdage'          { return Convert-ADTimeSpan $int64Val }
                'lockoutduration'    { return Convert-ADTimeSpan $int64Val }
                'lockoutobservationwindow' { return Convert-ADTimeSpan $int64Val }
                default              { return $int64Val }
            }
        } catch {
            return $Value.ToString()
        }
    }

    return $Value
}

function Convert-FileTimeToDateTime {
    [CmdletBinding()]
    param([long]$FileTime)

    if ($FileTime -le 0 -or $FileTime -eq [long]::MaxValue -or $FileTime -eq 0x7FFFFFFFFFFFFFFF) {
        return $null  # Never / not set
    }
    try {
        return [datetime]::FromFileTimeUtc($FileTime)
    } catch {
        return $null
    }
}

function Convert-ADTimeSpan {
    [CmdletBinding()]
    param([long]$Value)

    if ($Value -eq 0 -or $Value -eq [long]::MinValue -or $Value -eq [long]::MaxValue) {
        return [timespan]::Zero
    }
    # AD stores time spans as negative 100-nanosecond intervals
    try {
        return [timespan]::FromTicks([Math]::Abs($Value))
    } catch {
        return [timespan]::Zero
    }
}

function Get-UACFlags {
    [CmdletBinding()]
    param([int]$UserAccountControl)

    @{
        SCRIPT                         = ($UserAccountControl -band 0x0001) -ne 0
        ACCOUNTDISABLE                 = ($UserAccountControl -band 0x0002) -ne 0
        HOMEDIR_REQUIRED               = ($UserAccountControl -band 0x0008) -ne 0
        LOCKOUT                        = ($UserAccountControl -band 0x0010) -ne 0
        PASSWD_NOTREQD                 = ($UserAccountControl -band 0x0020) -ne 0
        PASSWD_CANT_CHANGE             = ($UserAccountControl -band 0x0040) -ne 0
        ENCRYPTED_TEXT_PWD_ALLOWED     = ($UserAccountControl -band 0x0080) -ne 0
        NORMAL_ACCOUNT                 = ($UserAccountControl -band 0x0200) -ne 0
        INTERDOMAIN_TRUST_ACCOUNT      = ($UserAccountControl -band 0x0800) -ne 0
        WORKSTATION_TRUST_ACCOUNT      = ($UserAccountControl -band 0x1000) -ne 0
        SERVER_TRUST_ACCOUNT           = ($UserAccountControl -band 0x2000) -ne 0
        DONT_EXPIRE_PASSWORD           = ($UserAccountControl -band 0x10000) -ne 0
        MNS_LOGON_ACCOUNT              = ($UserAccountControl -band 0x20000) -ne 0
        SMARTCARD_REQUIRED             = ($UserAccountControl -band 0x40000) -ne 0
        TRUSTED_FOR_DELEGATION         = ($UserAccountControl -band 0x80000) -ne 0
        NOT_DELEGATED                  = ($UserAccountControl -band 0x100000) -ne 0
        USE_DES_KEY_ONLY               = ($UserAccountControl -band 0x200000) -ne 0
        DONT_REQ_PREAUTH               = ($UserAccountControl -band 0x400000) -ne 0
        PASSWORD_EXPIRED               = ($UserAccountControl -band 0x800000) -ne 0
        TRUSTED_TO_AUTH_FOR_DELEGATION = ($UserAccountControl -band 0x1000000) -ne 0
        PARTIAL_SECRETS_ACCOUNT        = ($UserAccountControl -band 0x04000000) -ne 0
    }
}
