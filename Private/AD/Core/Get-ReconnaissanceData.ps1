# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ReconnaissanceData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [string[]]$Categories = @('All'),

        [int]$InactiveDays = 90,

        [int]$PasswordAgeDays = 365,

        [string]$NtdsPath,

        [string]$WeakPasswordList,

        [switch]$Quiet
    )

    # ── Category-to-data-source mapping ──────────────────────────────────
    $categoryDataNeeds = @{
        DomainForest        = @('DomainInfo', 'DomainControllers')
        Trusts              = @('TrustRelationships')
        PrivilegedAccounts  = @('PrivilegedMembers', 'DomainInfo')
        PasswordPolicy      = @('PasswordPolicies', 'DomainInfo')
        Kerberos            = @('KerberosConfig')
        ACLDelegation       = @('ObjectACLs', 'PrivilegedMembers')
        GroupPolicy         = @('GroupPolicyObjects')
        LogonScripts        = @('LogonScripts')
        CertificateServices = @('CertificateServices')
        StaleObjects        = @('StaleObjects')
        Network             = @('NetworkConfig')
    }

    # Resolve which data sources are required
    $requiredSources = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    if ($Categories -contains 'All') {
        foreach ($sources in $categoryDataNeeds.Values) {
            foreach ($s in $sources) { [void]$requiredSources.Add($s) }
        }
    } else {
        foreach ($cat in $Categories) {
            if ($categoryDataNeeds.ContainsKey($cat)) {
                foreach ($s in $categoryDataNeeds[$cat]) {
                    [void]$requiredSources.Add($s)
                }
            }
        }
    }

    # Always collect module availability
    [void]$requiredSources.Add('ModuleAvailability')

    # ── Initialize result hashtable ──────────────────────────────────────
    $data = @{
        Domain              = $null
        DomainControllers   = $null
        Trusts              = $null
        PrivilegedAccounts  = $null
        PasswordPolicies    = $null
        Kerberos            = $null
        ACLs                = $null
        GroupPolicies       = $null
        LogonScripts        = $null
        CertificateServices = $null
        StaleObjects        = $null
        Network             = $null
        ModuleAvailability  = $null
        Connection          = $Connection
        Errors              = @{}
    }

    # Helper: determine whether a data source is needed
    $needsSource = { param([string]$Name) $requiredSources.Contains($Name) }

    # ── 1. Module Availability ───────────────────────────────────────────
    if (& $needsSource 'ModuleAvailability') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Checking module availability'
        }
        try {
            $data.ModuleAvailability = Test-ADModuleAvailability
        } catch {
            $data.Errors['ModuleAvailability'] = $_.Exception.Message
            $data.ModuleAvailability = @{
                ActiveDirectory = $false
                GroupPolicy     = $false
                DSInternals     = $false
                PSPKI           = $false
            }
        }
    }

    # ── 2. Domain Information ────────────────────────────────────────────
    if (& $needsSource 'DomainInfo') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting domain information'
        }
        try {
            $data.Domain = Get-ADDomainInfo -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect domain information: $_"
            $data.Errors['DomainInfo'] = $_.Exception.Message
        }
    }

    # ── 3. Domain Controllers ────────────────────────────────────────────
    if (& $needsSource 'DomainControllers') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Enumerating domain controllers'
        }
        try {
            $data.DomainControllers = Get-ADDomainControllers -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to enumerate domain controllers: $_"
            $data.Errors['DomainControllers'] = $_.Exception.Message
        }
    }

    # ── 4. Trust Relationships ───────────────────────────────────────────
    if (& $needsSource 'TrustRelationships') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting trust relationships'
        }
        try {
            $data.Trusts = Get-ADTrustRelationships -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect trust relationships: $_"
            $data.Errors['TrustRelationships'] = $_.Exception.Message
        }
    }

    # ── 5. Privileged Members ────────────────────────────────────────────
    if (& $needsSource 'PrivilegedMembers') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Enumerating privileged group members'
        }
        try {
            $data.PrivilegedAccounts = Get-ADPrivilegedMembers -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to enumerate privileged members: $_"
            $data.Errors['PrivilegedMembers'] = $_.Exception.Message
        }
    }

    # ── 6. Password Policies ────────────────────────────────────────────
    if (& $needsSource 'PasswordPolicies') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting password policies'
        }
        try {
            $data.PasswordPolicies = Get-ADPasswordPolicies -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect password policies: $_"
            $data.Errors['PasswordPolicies'] = $_.Exception.Message
        }
    }

    # ── 7. Kerberos Configuration ────────────────────────────────────────
    if (& $needsSource 'KerberosConfig') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Analyzing Kerberos configuration'
        }
        try {
            $data.Kerberos = Get-ADKerberosConfig -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to analyze Kerberos configuration: $_"
            $data.Errors['KerberosConfig'] = $_.Exception.Message
        }
    }

    # ── 8. Object ACLs / Delegation ──────────────────────────────────────
    if (& $needsSource 'ObjectACLs') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Auditing object ACLs and delegation'
        }
        try {
            $data.ACLs = Get-ADObjectACLs -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to audit object ACLs: $_"
            $data.Errors['ObjectACLs'] = $_.Exception.Message
        }
    }

    # ── 9. Group Policy Objects ──────────────────────────────────────────
    if (& $needsSource 'GroupPolicyObjects') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting Group Policy Objects'
        }
        try {
            $data.GroupPolicies = Get-ADGroupPolicyObjects -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect Group Policy Objects: $_"
            $data.Errors['GroupPolicyObjects'] = $_.Exception.Message
        }
    }

    # ── 10. Logon Scripts ────────────────────────────────────────────────
    if (& $needsSource 'LogonScripts') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Analyzing logon scripts'
        }
        try {
            $data.LogonScripts = Get-ADLogonScripts -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to analyze logon scripts: $_"
            $data.Errors['LogonScripts'] = $_.Exception.Message
        }
    }

    # ── 11. Certificate Services (AD CS) ─────────────────────────────────
    if (& $needsSource 'CertificateServices') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Enumerating AD Certificate Services'
        }
        try {
            $data.CertificateServices = Get-ADCertificateServices -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to enumerate Certificate Services: $_"
            $data.Errors['CertificateServices'] = $_.Exception.Message
        }
    }

    # ── 12. Network policy (relay-precondition surface) ──────────────────
    if (& $needsSource 'NetworkConfig') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Reading network-layer policy from SYSVOL'
        }
        try {
            $data.Network = Get-ADNetworkConfig -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to read network policy from SYSVOL: $_"
            $data.Errors['NetworkConfig'] = $_.Exception.Message
        }
    }

    # ── 13. Stale Objects ────────────────────────────────────────────────
    if (& $needsSource 'StaleObjects') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Identifying stale and abandoned objects'
        }
        try {
            $data.StaleObjects = Get-ADStaleObjects `
                -Connection $Connection `
                -InactiveDays $InactiveDays `
                -PasswordAgeDays $PasswordAgeDays `
                -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to identify stale objects: $_"
            $data.Errors['StaleObjects'] = $_.Exception.Message
        }
    }

    # ── Summary ──────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $collectedCount = 0
        $nullKeys = [System.Collections.Generic.List[string]]::new()

        foreach ($key in @('Domain', 'DomainControllers', 'Trusts', 'PrivilegedAccounts',
                           'PasswordPolicies', 'Kerberos', 'ACLs', 'GroupPolicies',
                           'LogonScripts', 'CertificateServices', 'StaleObjects', 'Network')) {
            if ($null -ne $data[$key]) {
                $collectedCount++
            } elseif ($requiredSources.Count -gt 0) {
                # Only track as missing if it was actually requested
                $sourceMapping = @{
                    Domain             = 'DomainInfo'
                    DomainControllers  = 'DomainControllers'
                    Trusts             = 'TrustRelationships'
                    PrivilegedAccounts = 'PrivilegedMembers'
                    PasswordPolicies   = 'PasswordPolicies'
                    Kerberos           = 'KerberosConfig'
                    ACLs               = 'ObjectACLs'
                    GroupPolicies      = 'GroupPolicyObjects'
                    LogonScripts       = 'LogonScripts'
                    CertificateServices = 'CertificateServices'
                    StaleObjects       = 'StaleObjects'
                    Network            = 'NetworkConfig'
                }
                if ($sourceMapping.ContainsKey($key) -and $requiredSources.Contains($sourceMapping[$key])) {
                    $nullKeys.Add($key)
                }
            }
        }

        $errorCount = $data.Errors.Count
        $domainName = if ($data.Domain) { $data.Domain.DomainName } else { 'unknown' }

        $summary = "Reconnaissance complete for $domainName`: $collectedCount data source(s) collected"
        if ($errorCount -gt 0) {
            $summary += ", $errorCount error(s)"
        }
        if ($nullKeys.Count -gt 0) {
            $summary += " (missing: $($nullKeys -join ', '))"
        }
        Write-ProgressLine -Phase RECON -Message $summary
    }

    return $data
}
