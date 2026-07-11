# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADPasswordPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        DefaultPolicy             = $null
        FineGrainedPolicies       = @()
        UsersPasswordNeverExpires = @()
        LAPSDeployed              = $false
        LAPSType                  = 'None'
        LAPSComputers             = 0
        TotalComputers            = 0
        BitLockerKeys             = 0
    }

    # ── Default Domain Password Policy ────────────────────────────────────────
    Write-Verbose 'Reading default domain password policy from domain root object...'
    try {
        $domainRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        # @(...) forces array context — Base-scope queries return a single hashtable
        # that PowerShell would otherwise unwrap, breaking the .Count / [0] access below.
        $domainProps = @(Invoke-LdapQuery -SearchRoot $domainRoot `
            -Filter '(objectClass=domainDNS)' `
            -Properties @(
                'minPwdLength', 'pwdProperties', 'pwdHistoryLength',
                'maxPwdAge', 'minPwdAge', 'lockoutThreshold',
                'lockoutDuration', 'lockOutObservationWindow'
            ) `
            -Scope Base)

        if ($domainProps.Count -gt 0) {
            $dp = $domainProps[0]
            $pwdProps = [int]($dp['pwdproperties'] ?? 0)

            $result.DefaultPolicy = @{
                MinPasswordLength      = [int]($dp['minpwdlength'] ?? 0)
                PasswordComplexity     = ($pwdProps -band 1) -ne 0
                PasswordHistoryCount   = [int]($dp['pwdhistorylength'] ?? 0)
                MaxPasswordAge         = $dp['maxpwdage'] ?? [timespan]::Zero
                MinPasswordAge         = $dp['minpwdage'] ?? [timespan]::Zero
                LockoutThreshold       = [int]($dp['lockoutthreshold'] ?? 0)
                LockoutDuration        = $dp['lockoutduration'] ?? [timespan]::Zero
                LockoutObservationWindow = $dp['lockoutobservationwindow'] ?? [timespan]::Zero
                ReversibleEncryption   = ($pwdProps -band 16) -ne 0
            }

            if (-not $Quiet) {
                Write-Verbose ("Default policy: MinLen={0}, Complexity={1}, History={2}, MaxAge={3:g}, LockoutThreshold={4}" -f `
                    $result.DefaultPolicy.MinPasswordLength,
                    $result.DefaultPolicy.PasswordComplexity,
                    $result.DefaultPolicy.PasswordHistoryCount,
                    $result.DefaultPolicy.MaxPasswordAge,
                    $result.DefaultPolicy.LockoutThreshold)
            }
        } else {
            Write-Warning 'Could not read default domain password policy.'
        }
    } catch {
        Write-Warning "Failed to read default domain password policy: $_"
    }

    # ── Fine-Grained Password Policies (FGPPs) ───────────────────────────────
    Write-Verbose 'Querying fine-grained password policies (msDS-PasswordSettings)...'
    try {
        $psoContainerDN = "CN=Password Settings Container,CN=System,$($Connection.DomainDN)"
        $psoRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $psoContainerDN

        $fgpps = Invoke-LdapQuery -SearchRoot $psoRoot `
            -Filter '(objectClass=msDS-PasswordSettings)' `
            -Properties @(
                'name', 'distinguishedName', 'msDS-PasswordSettingsPrecedence',
                'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled',
                'msDS-PasswordHistoryLength', 'msDS-MaximumPasswordAge',
                'msDS-MinimumPasswordAge', 'msDS-LockoutThreshold',
                'msDS-LockoutDuration', 'msDS-LockoutObservationWindow',
                'msDS-PasswordReversibleEncryptionEnabled', 'msDS-PSOAppliesTo'
            )

        $fgppList = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($pso in $fgpps) {
            $appliesTo = $pso['msds-psoappliedto'] ?? $pso['msds-psoappliesTo'] ?? $pso['msds-psoapplies'] ?? @()
            # Normalize AppliesTo to an array
            if ($appliesTo -isnot [array]) { $appliesTo = @($appliesTo) }

            $fgpp = @{
                Name                   = $pso['name'] ?? ''
                DN                     = $pso['distinguishedname'] ?? ''
                Precedence             = [int]($pso['msds-passwordsettingsprecedence'] ?? 0)
                MinPasswordLength      = [int]($pso['msds-minimumpasswordlength'] ?? 0)
                PasswordComplexity     = [bool]($pso['msds-passwordcomplexityenabled'] ?? $false)
                PasswordHistoryCount   = [int]($pso['msds-passwordhistorylength'] ?? 0)
                MaxPasswordAge         = $pso['msds-maximumpasswordage'] ?? [timespan]::Zero
                MinPasswordAge         = $pso['msds-minimumpasswordage'] ?? [timespan]::Zero
                LockoutThreshold       = [int]($pso['msds-lockoutthreshold'] ?? 0)
                LockoutDuration        = $pso['msds-lockoutduration'] ?? [timespan]::Zero
                LockoutObservationWindow = $pso['msds-lockoutobservationwindow'] ?? [timespan]::Zero
                ReversibleEncryption   = [bool]($pso['msds-passwordreversibleencryptionenabled'] ?? $false)
                AppliesTo              = @($appliesTo)
            }
            $fgppList.Add($fgpp)
        }

        $result.FineGrainedPolicies = @($fgppList)
        Write-Verbose "Found $($fgppList.Count) fine-grained password policy(ies)."
    } catch {
        Write-Verbose "Fine-grained password policy query failed (may not exist or insufficient permissions): $_"
    }

    # ── Users with Password Never Expires ─────────────────────────────────────
    Write-Verbose 'Querying users with DONT_EXPIRE_PASSWORD flag...'
    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $neverExpireUsers = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' `
            -Properties @('samaccountname', 'distinguishedname', 'useraccountcontrol', 'pwdlastset', 'admincount')

        $neverExpireList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($user in $neverExpireUsers) {
            $neverExpireList.Add(@{
                SamAccountName     = $user['samaccountname'] ?? ''
                DN                 = $user['distinguishedname'] ?? ''
                UserAccountControl = [int]($user['useraccountcontrol'] ?? 0)
                PwdLastSet         = $user['pwdlastset']
                AdminCount         = [int]($user['admincount'] ?? 0)
            })
        }

        $result.UsersPasswordNeverExpires = @($neverExpireList)
        Write-Verbose "Found $($neverExpireList.Count) user(s) with password-never-expires."
    } catch {
        Write-Warning "Failed to query users with password-never-expires: $_"
    }

    # ── LAPS Deployment Check ─────────────────────────────────────────────────
    Write-Verbose 'Checking LAPS deployment in schema...'
    try {
        $schemaRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.SchemaDN

        $hasLegacyLAPS = $false
        $hasWindowsLAPS = $false

        # Check for legacy LAPS (ms-Mcs-AdmPwd)
        $legacyCheck = @(Invoke-LdapQuery -SearchRoot $schemaRoot `
            -Filter '(&(objectClass=attributeSchema)(lDAPDisplayName=ms-Mcs-AdmPwd))' `
            -Properties @('lDAPDisplayName') `
            -SizeLimit 1)
        if ($legacyCheck.Count -gt 0) {
            $hasLegacyLAPS = $true
            Write-Verbose 'Legacy LAPS schema attribute (ms-Mcs-AdmPwd) found.'
        }

        # Check for Windows LAPS (msLAPS-Password)
        $windowsCheck = @(Invoke-LdapQuery -SearchRoot $schemaRoot `
            -Filter '(&(objectClass=attributeSchema)(lDAPDisplayName=msLAPS-Password))' `
            -Properties @('lDAPDisplayName') `
            -SizeLimit 1)
        if ($windowsCheck.Count -gt 0) {
            $hasWindowsLAPS = $true
            Write-Verbose 'Windows LAPS schema attribute (msLAPS-Password) found.'
        }

        $result.LAPSDeployed = $hasLegacyLAPS -or $hasWindowsLAPS
        $result.LAPSType = if ($hasLegacyLAPS -and $hasWindowsLAPS) { 'Both' }
                           elseif ($hasLegacyLAPS) { 'Legacy' }
                           elseif ($hasWindowsLAPS) { 'Windows' }
                           else { 'None' }

        Write-Verbose "LAPS deployment: $($result.LAPSType)"
    } catch {
        Write-Warning "Failed to check LAPS schema attributes: $_"
    }

    # ── LAPS Computer Coverage & Total Computers ──────────────────────────────
    Write-Verbose 'Counting computers with LAPS passwords and total computer objects...'
    try {
        $compRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN

        # Count all computers excluding domain controllers (SERVER_TRUST_ACCOUNT = 0x2000 = 8192)
        $allComputers = Invoke-LdapQuery -SearchRoot $compRoot `
            -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' `
            -Properties @('distinguishedname')
        $result.TotalComputers = $allComputers.Count

        # Count computers with LAPS passwords based on what is deployed
        $lapsCount = 0
        if ($hasLegacyLAPS) {
            $legacyLaps = Invoke-LdapQuery -SearchRoot $compRoot `
                -Filter '(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))' `
                -Properties @('distinguishedname')
            $lapsCount += $legacyLaps.Count
        }
        if ($hasWindowsLAPS) {
            $windowsLaps = Invoke-LdapQuery -SearchRoot $compRoot `
                -Filter '(&(objectCategory=computer)(msLAPS-Password=*))' `
                -Properties @('distinguishedname')
            # Avoid double-counting if a computer has both
            if ($hasLegacyLAPS) {
                $legacyDNs = [System.Collections.Generic.HashSet[string]]::new(
                    [StringComparer]::OrdinalIgnoreCase
                )
                foreach ($c in $legacyLaps) { [void]$legacyDNs.Add($c['distinguishedname']) }
                foreach ($c in $windowsLaps) {
                    if (-not $legacyDNs.Contains($c['distinguishedname'])) {
                        $lapsCount++
                    }
                }
            } else {
                $lapsCount += $windowsLaps.Count
            }
        }
        $result.LAPSComputers = $lapsCount

        Write-Verbose "LAPS coverage: $lapsCount of $($result.TotalComputers) computers."
    } catch {
        Write-Warning "Failed to count LAPS computers: $_"
    }

    # ── BitLocker Recovery Keys in AD ─────────────────────────────────────────
    Write-Verbose 'Counting BitLocker recovery keys stored in AD...'
    try {
        $blRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $bitlockerKeys = Invoke-LdapQuery -SearchRoot $blRoot `
            -Filter '(objectClass=msFVE-RecoveryInformation)' `
            -Properties @('distinguishedname')
        $result.BitLockerKeys = $bitlockerKeys.Count
        Write-Verbose "Found $($bitlockerKeys.Count) BitLocker recovery key(s) in AD."
    } catch {
        Write-Warning "Failed to count BitLocker recovery keys: $_"
    }

    return $result
}
