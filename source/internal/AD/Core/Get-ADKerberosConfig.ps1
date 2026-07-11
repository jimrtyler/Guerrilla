# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADKerberosConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        KerberoastableAccounts    = @()
        ASREPRoastableAccounts    = @()
        UnconstrainedDelegation   = @()
        ConstrainedDelegation     = @()
        RBCD                      = @()
        ProtocolTransition        = @()
        EncryptionTypes           = @{}
        KerberosPolicy            = @{}
    }

    $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN

    # ── Kerberoastable Accounts ───────────────────────────────────────────────
    # User accounts (not computers, not disabled) with SPNs set
    Write-Verbose 'Querying Kerberoastable accounts (users with SPNs)...'
    try {
        $kerberoastable = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties @('samaccountname', 'distinguishedname', 'serviceprincipalname', 'pwdlastset', 'admincount', 'useraccountcontrol', 'msds-supportedencryptiontypes')

        $kerbList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($acct in $kerberoastable) {
            $spns = $acct['serviceprincipalname']
            if ($spns -isnot [array]) { $spns = @($spns) }

            $kerbList.Add(@{
                SamAccountName      = $acct['samaccountname'] ?? ''
                DN                  = $acct['distinguishedname'] ?? ''
                SPNs                = @($spns)
                PwdLastSet          = $acct['pwdlastset']
                AdminCount          = [int]($acct['admincount'] ?? 0)
                UserAccountControl  = [int]($acct['useraccountcontrol'] ?? 0)
                EncryptionTypes     = [int]($acct['msds-supportedencryptiontypes'] ?? 0)
            })
        }

        $result.KerberoastableAccounts = @($kerbList)
        Write-Verbose "Found $($kerbList.Count) Kerberoastable account(s)."
    } catch {
        Write-Warning "Failed to query Kerberoastable accounts: $_"
    }

    # ── AS-REP Roastable Accounts ─────────────────────────────────────────────
    # Users with DONT_REQ_PREAUTH (0x400000 = 4194304)
    Write-Verbose 'Querying AS-REP roastable accounts (DONT_REQ_PREAUTH)...'
    try {
        $asrepAccounts = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' `
            -Properties @('samaccountname', 'distinguishedname', 'useraccountcontrol', 'pwdlastset', 'admincount')

        $asrepList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($acct in $asrepAccounts) {
            $asrepList.Add(@{
                SamAccountName     = $acct['samaccountname'] ?? ''
                DN                 = $acct['distinguishedname'] ?? ''
                UserAccountControl = [int]($acct['useraccountcontrol'] ?? 0)
                PwdLastSet         = $acct['pwdlastset']
                AdminCount         = [int]($acct['admincount'] ?? 0)
            })
        }

        $result.ASREPRoastableAccounts = @($asrepList)
        Write-Verbose "Found $($asrepList.Count) AS-REP roastable account(s)."
    } catch {
        Write-Warning "Failed to query AS-REP roastable accounts: $_"
    }

    # ── Unconstrained Delegation ──────────────────────────────────────────────
    # TRUSTED_FOR_DELEGATION (0x80000 = 524288), excluding DCs (SERVER_TRUST_ACCOUNT 0x2000)
    Write-Verbose 'Querying unconstrained delegation objects...'
    try {
        $unconstrainedAll = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' `
            -Properties @('samaccountname', 'distinguishedname', 'objectclass', 'useraccountcontrol', 'dnshostname')

        $unconstrainedList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($obj in $unconstrainedAll) {
            $objClasses = $obj['objectclass']
            if ($objClasses -isnot [array]) { $objClasses = @($objClasses) }

            $unconstrainedList.Add(@{
                SamAccountName     = $obj['samaccountname'] ?? ''
                DN                 = $obj['distinguishedname'] ?? ''
                ObjectClass        = $objClasses
                UserAccountControl = [int]($obj['useraccountcontrol'] ?? 0)
                DnsHostName        = $obj['dnshostname'] ?? ''
            })
        }

        $result.UnconstrainedDelegation = @($unconstrainedList)
        Write-Verbose "Found $($unconstrainedList.Count) unconstrained delegation object(s) (excluding DCs)."
    } catch {
        Write-Warning "Failed to query unconstrained delegation: $_"
    }

    # ── Constrained Delegation ────────────────────────────────────────────────
    # Objects with msDS-AllowedToDelegateTo populated
    Write-Verbose 'Querying constrained delegation objects...'
    try {
        $constrained = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(msDS-AllowedToDelegateTo=*)' `
            -Properties @('samaccountname', 'distinguishedname', 'objectclass', 'useraccountcontrol', 'msds-allowedtodelegateto')

        $constrainedList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($obj in $constrained) {
            $allowedTo = $obj['msds-allowedtodelegateto']
            if ($allowedTo -isnot [array]) { $allowedTo = @($allowedTo) }
            $objClasses = $obj['objectclass']
            if ($objClasses -isnot [array]) { $objClasses = @($objClasses) }

            $constrainedList.Add(@{
                SamAccountName         = $obj['samaccountname'] ?? ''
                DN                     = $obj['distinguishedname'] ?? ''
                ObjectClass            = $objClasses
                UserAccountControl     = [int]($obj['useraccountcontrol'] ?? 0)
                AllowedToDelegateTo    = @($allowedTo)
            })
        }

        $result.ConstrainedDelegation = @($constrainedList)
        Write-Verbose "Found $($constrainedList.Count) constrained delegation object(s)."
    } catch {
        Write-Warning "Failed to query constrained delegation: $_"
    }

    # ── Resource-Based Constrained Delegation (RBCD) ──────────────────────────
    # Objects with msDS-AllowedToActOnBehalfOfOtherIdentity populated
    Write-Verbose 'Querying resource-based constrained delegation objects...'
    try {
        $rbcd = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
            -Properties @('samaccountname', 'distinguishedname', 'objectclass', 'msds-allowedtoactonbehalfofotheridentity')

        $rbcdList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($obj in $rbcd) {
            $rawSD = $obj['msds-allowedtoactonbehalfofotheridentity']
            $allowedPrincipals = @()

            # Parse the security descriptor to extract allowed principals
            if ($rawSD -is [byte[]]) {
                try {
                    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sd.SetSecurityDescriptorBinaryForm($rawSD)
                    $rules = $sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                    $allowedPrincipals = @(foreach ($rule in $rules) {
                        $sidStr = $rule.IdentityReference.Value
                        $resolved = Resolve-ADSid -SidString $sidStr -SearchRoot $searchRoot
                        @{
                            SID      = $sidStr
                            Identity = $resolved
                            Rights   = $rule.ActiveDirectoryRights.ToString()
                        }
                    })
                } catch {
                    Write-Verbose "Could not parse RBCD descriptor for $($obj['distinguishedname']): $_"
                }
            }

            $objClasses = $obj['objectclass']
            if ($objClasses -isnot [array]) { $objClasses = @($objClasses) }

            $rbcdList.Add(@{
                SamAccountName    = $obj['samaccountname'] ?? ''
                DN                = $obj['distinguishedname'] ?? ''
                ObjectClass       = $objClasses
                AllowedPrincipals = $allowedPrincipals
            })
        }

        $result.RBCD = @($rbcdList)
        Write-Verbose "Found $($rbcdList.Count) RBCD object(s)."
    } catch {
        Write-Warning "Failed to query RBCD: $_"
    }

    # ── Protocol Transition ───────────────────────────────────────────────────
    # TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000 = 16777216)
    Write-Verbose 'Querying protocol transition (T2A4D) objects...'
    try {
        $t2a4d = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)' `
            -Properties @('samaccountname', 'distinguishedname', 'objectclass', 'useraccountcontrol', 'msds-allowedtodelegateto')

        $t2a4dList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($obj in $t2a4d) {
            $allowedTo = $obj['msds-allowedtodelegateto']
            if ($null -ne $allowedTo -and $allowedTo -isnot [array]) { $allowedTo = @($allowedTo) }
            $objClasses = $obj['objectclass']
            if ($objClasses -isnot [array]) { $objClasses = @($objClasses) }

            $t2a4dList.Add(@{
                SamAccountName      = $obj['samaccountname'] ?? ''
                DN                  = $obj['distinguishedname'] ?? ''
                ObjectClass         = $objClasses
                UserAccountControl  = [int]($obj['useraccountcontrol'] ?? 0)
                AllowedToDelegateTo = @($allowedTo ?? @())
            })
        }

        $result.ProtocolTransition = @($t2a4dList)
        Write-Verbose "Found $($t2a4dList.Count) protocol transition object(s)."
    } catch {
        Write-Warning "Failed to query protocol transition objects: $_"
    }

    # ── Encryption Types on Domain Controllers ────────────────────────────────
    Write-Verbose 'Analyzing msDS-SupportedEncryptionTypes across domain controllers...'
    try {
        $dcResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
            -Properties @('samaccountname', 'distinguishedname', 'msds-supportedencryptiontypes', 'operatingsystem')

        $encTypeFlags = @{
            1  = 'DES-CBC-CRC'
            2  = 'DES-CBC-MD5'
            4  = 'RC4-HMAC'
            8  = 'AES128-CTS-HMAC-SHA1'
            16 = 'AES256-CTS-HMAC-SHA1'
        }

        $dcEncTypes = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($dc in $dcResults) {
            $encVal = [int]($dc['msds-supportedencryptiontypes'] ?? 0)
            $supported = [System.Collections.Generic.List[string]]::new()

            foreach ($flag in $encTypeFlags.GetEnumerator()) {
                if ($encVal -band $flag.Key) {
                    $supported.Add($flag.Value)
                }
            }

            $dcEncTypes.Add(@{
                SamAccountName     = $dc['samaccountname'] ?? ''
                DN                 = $dc['distinguishedname'] ?? ''
                OperatingSystem    = $dc['operatingsystem'] ?? ''
                EncryptionTypeValue = $encVal
                SupportedTypes     = @($supported)
                HasDES             = ($encVal -band 3) -ne 0
                HasRC4             = ($encVal -band 4) -ne 0
                HasAES             = ($encVal -band 24) -ne 0
            })
        }

        # Build summary
        $desCount  = @($dcEncTypes | Where-Object { $_.HasDES }).Count
        $rc4Count  = @($dcEncTypes | Where-Object { $_.HasRC4 }).Count
        $aesCount  = @($dcEncTypes | Where-Object { $_.HasAES }).Count
        $totalDCs  = $dcEncTypes.Count

        $result.EncryptionTypes = @{
            DomainControllers = @($dcEncTypes)
            Summary           = @{
                TotalDCs       = $totalDCs
                DESEnabled     = $desCount
                RC4Enabled     = $rc4Count
                AESEnabled     = $aesCount
            }
        }

        Write-Verbose "DC encryption analysis: $totalDCs DCs, DES=$desCount, RC4=$rc4Count, AES=$aesCount."
    } catch {
        Write-Warning "Failed to analyze DC encryption types: $_"
    }

    # ── Kerberos Policy from Default Domain Policy SYSVOL ─────────────────────
    Write-Verbose 'Attempting to read Kerberos policy from domain GPO SYSVOL...'
    try {
        # The Default Domain Policy is always {31B2F340-016D-11D2-945F-00C04FB984F9}
        $defaultGPOGuid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'

        # Derive the FQDN from the DomainDN
        $domainFqdn = ($Connection.DomainDN -replace ',DC=', '.' -replace '^DC=', '')

        $kerbInfPath = "\\$domainFqdn\SYSVOL\$domainFqdn\Policies\$defaultGPOGuid\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

        if (Test-Path -LiteralPath $kerbInfPath -ErrorAction SilentlyContinue) {
            $infContent = Get-Content -LiteralPath $kerbInfPath -ErrorAction Stop
            $inKerberosSection = $false
            $kerbPolicy = @{}

            foreach ($line in $infContent) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^\[(.+)\]$') {
                    $inKerberosSection = ($Matches[1] -eq 'Kerberos Policy')
                    continue
                }
                if ($inKerberosSection -and $trimmed -match '^(.+?)\s*=\s*(.+)$') {
                    $key = $Matches[1].Trim()
                    $val = $Matches[2].Trim()
                    switch ($key) {
                        'MaxTicketAge'  { $kerbPolicy['MaxTicketAge']  = [int]$val }
                        'MaxRenewAge'   { $kerbPolicy['MaxRenewAge']   = [int]$val }
                        'MaxServiceAge' { $kerbPolicy['MaxServiceAge'] = [int]$val }
                        'MaxClockSkew'  { $kerbPolicy['MaxClockSkew']  = [int]$val }
                        'TicketValidateClient' { $kerbPolicy['TicketValidateClient'] = [int]$val }
                    }
                }
            }

            $result.KerberosPolicy = $kerbPolicy
            Write-Verbose "Kerberos policy loaded: MaxTicketAge=$($kerbPolicy['MaxTicketAge'] ?? 'N/A')h, MaxClockSkew=$($kerbPolicy['MaxClockSkew'] ?? 'N/A')min."
        } else {
            Write-Verbose "SYSVOL Kerberos policy file not accessible: $kerbInfPath"
            $result.KerberosPolicy = @{ Error = 'SYSVOL not accessible' }
        }
    } catch {
        Write-Verbose "Failed to read Kerberos policy from SYSVOL: $_"
        $result.KerberosPolicy = @{ Error = "Failed: $_" }
    }

    return $result
}
