# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADTierZeroSignals {
    <#
    .SYNOPSIS
        Collects AD signals relevant to Tier-0 hygiene checks.
    .DESCRIPTION
        Specifically:
          * MSOL_ accounts (Azure AD Connect default-named sync identity)
          * Generic Tier-0-relevant object metadata that the privileged-group
            collector doesn't already gather (creation time, OU placement)

        The privileged-group memberships themselves are already collected by
        Get-ADPrivilegedMembers and reused — this collector only adds what's
        missing for tier-bleed scanning.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        MsolAccounts = @()
        Errors       = @{}
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $msolResults = @(Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectClass=user)(sAMAccountName=MSOL_*))' `
            -Properties @(
                'sAMAccountName', 'distinguishedName', 'displayName', 'description',
                'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'userAccountControl',
                'objectSid'
            ))

        foreach ($u in $msolResults) {
            $pwdLastSet = $u['pwdlastset']
            $pwdAgeDays = $null
            if ($pwdLastSet -is [datetime]) {
                $pwdAgeDays = [Math]::Floor(([datetime]::UtcNow - $pwdLastSet).TotalDays)
            } elseif ($pwdLastSet -is [long] -or $pwdLastSet -is [int64]) {
                if ($pwdLastSet -gt 0) {
                    try {
                        $pwdAgeDays = [Math]::Floor(([datetime]::UtcNow - [datetime]::FromFileTimeUtc($pwdLastSet)).TotalDays)
                    } catch { }
                }
            }

            $result.MsolAccounts += [PSCustomObject]@{
                SamAccountName    = $u['samaccountname'] ?? ''
                DistinguishedName = $u['distinguishedname'] ?? ''
                DisplayName       = $u['displayname'] ?? ''
                Description       = $u['description'] ?? ''
                WhenCreated       = $u['whencreated']
                PasswordAgeDays   = $pwdAgeDays
                LastLogonTimestamp = $u['lastlogontimestamp']
                UserAccountControl = [int]($u['useraccountcontrol'] ?? 0)
            }
        }
    } catch {
        Write-Warning "MSOL_ account discovery failed: $_"
        $result.Errors['MsolAccounts'] = $_.Exception.Message
    }

    return $result
}
