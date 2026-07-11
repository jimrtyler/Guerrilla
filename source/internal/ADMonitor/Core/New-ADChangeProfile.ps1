# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function New-ADChangeProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Changes,

        [hashtable]$DetectionConfig = @{},

        [hashtable]$DetectionFilter = @{},

        [string]$DomainName = ''
    )

    # Helper: check if a detection signal is enabled in the filter
    function Test-DetectionEnabled([string]$SignalKey) {
        if (-not $DetectionFilter -or $DetectionFilter.Count -eq 0) { return $true }
        return $DetectionFilter[$SignalKey] -ne $false
    }

    $profile = [PSCustomObject]@{
        PSTypeName   = 'Guerrilla.ADChangeProfile'
        DomainName   = $DomainName
        ThreatLevel  = 'Clean'
        ThreatScore  = 0.0
        Indicators   = [System.Collections.Generic.List[PSCustomObject]]::new()
        GroupChanges        = $Changes.GroupChanges
        GPOChanges          = $Changes.GPOChanges
        GPOLinkChanges      = $Changes.GPOLinkChanges
        TrustChanges        = $Changes.TrustChanges
        ACLChanges          = $Changes.ACLChanges
        AdminSDHolderChanged = $Changes.AdminSDHolderChanged
        KrbtgtChanged       = $Changes.KrbtgtChanged
        CertTemplateChanges = $Changes.CertTemplateChanges
        DelegationChanges   = $Changes.DelegationChanges
        DNSChanges          = $Changes.DNSChanges
        SchemaChanges       = $Changes.SchemaChanges
        NewComputers        = $Changes.NewComputers
        NewServiceAccounts  = $Changes.NewServiceAccounts
        PasswordChanges     = $Changes.PasswordChanges
    }

    # ── Run each detection function against the change data ────────────

    # Privileged group changes
    if (Test-DetectionEnabled 'privilegedGroupChanges') {
        $privGroupResult = Test-ADPrivilegedGroupChange -GroupChanges $Changes.GroupChanges
        foreach ($indicator in $privGroupResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Domain Admins specifically
    if (Test-DetectionEnabled 'domainAdminsChanges') {
        $daResult = Test-ADDomainAdminChange -GroupChanges $Changes.GroupChanges
        foreach ($indicator in $daResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Enterprise Admins specifically
    if (Test-DetectionEnabled 'enterpriseAdminsChanges') {
        $eaResult = Test-ADEnterpriseAdminChange -GroupChanges $Changes.GroupChanges
        foreach ($indicator in $eaResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # AdminSDHolder ACL
    if (Test-DetectionEnabled 'adminSdHolderAcl') {
        $adminSDResult = Test-ADAdminSDHolderChange -AdminSDHolderChanged $Changes.AdminSDHolderChanged -ACLChanges $Changes.ACLChanges
        foreach ($indicator in $adminSDResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # GPO modifications
    if (Test-DetectionEnabled 'gpoChanges') {
        $gpoResult = Test-ADGPOChange -GPOChanges $Changes.GPOChanges
        foreach ($indicator in $gpoResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # GPO link changes
    if (Test-DetectionEnabled 'gpoLinkChanges') {
        $gpoLinkResult = Test-ADGPOLinkChange -GPOLinkChanges $Changes.GPOLinkChanges
        foreach ($indicator in $gpoLinkResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Trust changes
    if (Test-DetectionEnabled 'trustChanges') {
        $trustResult = Test-ADTrustChange -TrustChanges $Changes.TrustChanges
        foreach ($indicator in $trustResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # DCSync permission detection
    if (Test-DetectionEnabled 'dcSyncPermissions') {
        $dcsyncResult = Test-ADDCSyncPermission -ACLChanges $Changes.ACLChanges
        foreach ($indicator in $dcsyncResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # krbtgt password change
    if (Test-DetectionEnabled 'krbtgtChanges') {
        $krbtgtResult = Test-ADKrbtgtChange -KrbtgtChanged $Changes.KrbtgtChanged
        foreach ($indicator in $krbtgtResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Service account creation
    if (Test-DetectionEnabled 'serviceAccountCreation') {
        $svcResult = Test-ADServiceAccountCreation -NewServiceAccounts $Changes.NewServiceAccounts
        foreach ($indicator in $svcResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Sensitive password changes
    if (Test-DetectionEnabled 'sensitivePasswordChanges') {
        $pwdResult = Test-ADSensitivePasswordChange -PasswordChanges $Changes.PasswordChanges -GroupChanges $Changes.GroupChanges
        foreach ($indicator in $pwdResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Computer account creation
    if (Test-DetectionEnabled 'computerAccountCreation') {
        $compResult = Test-ADComputerAccountCreation -NewComputers $Changes.NewComputers
        foreach ($indicator in $compResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Certificate template changes
    if (Test-DetectionEnabled 'certTemplateChanges') {
        $certResult = Test-ADCertTemplateChange -CertTemplateChanges $Changes.CertTemplateChanges
        foreach ($indicator in $certResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Certificate enrollment anomaly
    if (Test-DetectionEnabled 'certEnrollmentAnomalies') {
        $certEnrollResult = Test-ADCertEnrollmentAnomaly -CertTemplateChanges $Changes.CertTemplateChanges
        foreach ($indicator in $certEnrollResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Delegation changes
    if (Test-DetectionEnabled 'delegationChanges') {
        $delegResult = Test-ADDelegationChange -DelegationChanges $Changes.DelegationChanges
        foreach ($indicator in $delegResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # OU permission changes
    if (Test-DetectionEnabled 'ouPermissionChanges') {
        $ouResult = Test-ADOUPermissionChange -ACLChanges $Changes.ACLChanges
        foreach ($indicator in $ouResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # DNS record changes
    if (Test-DetectionEnabled 'dnsRecordChanges') {
        $dnsResult = Test-ADDnsRecordChange -DNSChanges $Changes.DNSChanges
        foreach ($indicator in $dnsResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Schema changes
    if (Test-DetectionEnabled 'schemaChanges') {
        $schemaResult = Test-ADSchemaChange -SchemaChanges $Changes.SchemaChanges
        foreach ($indicator in $schemaResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # Replication anomaly
    if (Test-DetectionEnabled 'replicationAnomalies') {
        $replResult = Test-ADReplicationAnomaly -ACLChanges $Changes.ACLChanges
        foreach ($indicator in $replResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # LDAP query anomaly
    if (Test-DetectionEnabled 'ldapAnomalies') {
        $ldapResult = Test-ADLdapQueryAnomaly -RecentlyChanged @($Changes.RecentlyChanged)
        foreach ($indicator in $ldapResult) {
            $profile.Indicators.Add($indicator)
        }
    }

    # ── Score the profile ──────────────────────────────────────────────
    $weights = if ($DetectionConfig.Count -gt 0) { $DetectionConfig } else { $null }
    $profile = Get-ADMonitorThreatScore -Profile $profile -Weights $weights

    return $profile
}
