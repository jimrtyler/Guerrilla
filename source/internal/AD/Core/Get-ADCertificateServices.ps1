# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADCertificateServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        CertificateAuthorities = @()
        CertificateTemplates   = @()
        PKIObjects             = @()
        NTAuthCertificates     = $null
        OIDObjects             = @()
        Errors                 = @{}
    }

    $configDN = $Connection.ConfigDN
    $pkiServicesDN = "CN=Public Key Services,CN=Services,$configDN"

    # Well-known EKU OIDs for reference
    $ekuMap = @{
        '2.5.29.37.0'                = 'Any Purpose'
        '1.3.6.1.5.5.7.3.2'         = 'Client Authentication'
        '1.3.6.1.4.1.311.20.2.2'    = 'Smart Card Logon'
        '1.3.6.1.5.2.3.4'           = 'PKINIT Client Authentication'
        '1.3.6.1.4.1.311.20.2.1'    = 'Certificate Request Agent'
        '1.3.6.1.5.5.7.3.1'         = 'Server Authentication'
        '1.3.6.1.5.5.7.3.4'         = 'Secure Email'
        '1.3.6.1.4.1.311.10.3.4'    = 'Encrypting File System'
        '1.3.6.1.4.1.311.54.1.2'    = 'Remote Desktop Authentication'
    }

    # Enrollment right GUIDs
    $enrollGuid      = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid  = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    # ── Helper: Parse security descriptor for enrollment permissions ─────
    function Get-EnrollmentPermissions {
        param([byte[]]$SecurityDescriptorBytes, [System.DirectoryServices.DirectoryEntry]$LookupRoot)

        $permissions = [System.Collections.Generic.List[hashtable]]::new()
        if ($null -eq $SecurityDescriptorBytes -or $SecurityDescriptorBytes.Count -eq 0) {
            return @($permissions)
        }

        try {
            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sd.SetSecurityDescriptorBinaryForm($SecurityDescriptorBytes)

            foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $sidString = $ace.IdentityReference.Value
                $identity = Resolve-ADSid -SidString $sidString -SearchRoot $LookupRoot

                # Check for Enroll extended right
                if ($ace.ObjectType -and $ace.ObjectType.ToString().ToLower() -eq $enrollGuid) {
                    $permissions.Add(@{
                        Identity = $identity
                        SID      = $sidString
                        Right    = 'Enroll'
                    })
                }

                # Check for AutoEnroll extended right
                if ($ace.ObjectType -and $ace.ObjectType.ToString().ToLower() -eq $autoEnrollGuid) {
                    $permissions.Add(@{
                        Identity = $identity
                        SID      = $sidString
                        Right    = 'AutoEnroll'
                    })
                }

                # Check for GenericAll / Full Control
                $genericAllMask = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                if (($ace.ActiveDirectoryRights -band $genericAllMask) -eq $genericAllMask) {
                    $permissions.Add(@{
                        Identity = $identity
                        SID      = $sidString
                        Right    = 'FullControl'
                    })
                }

                # Check for WriteDacl / WriteOwner (dangerous permissions for ESC4/ESC5)
                $writeDaclMask  = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                $writeOwnerMask = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
                if (($ace.ActiveDirectoryRights -band $writeDaclMask) -eq $writeDaclMask) {
                    $permissions.Add(@{
                        Identity = $identity
                        SID      = $sidString
                        Right    = 'WriteDacl'
                    })
                }
                if (($ace.ActiveDirectoryRights -band $writeOwnerMask) -eq $writeOwnerMask) {
                    $permissions.Add(@{
                        Identity = $identity
                        SID      = $sidString
                        Right    = 'WriteOwner'
                    })
                }

                # Check for WriteProperty (can modify template attributes - ESC4)
                $writePropertyMask = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                if (($ace.ActiveDirectoryRights -band $writePropertyMask) -eq $writePropertyMask) {
                    # Only flag WriteProperty on all properties (ObjectType = Guid.Empty)
                    if ($null -eq $ace.ObjectType -or $ace.ObjectType -eq [guid]::Empty) {
                        $permissions.Add(@{
                            Identity = $identity
                            SID      = $sidString
                            Right    = 'WriteAllProperties'
                        })
                    }
                }
            }
        } catch {
            Write-Verbose "Failed to parse security descriptor: $_"
        }

        return @($permissions)
    }

    # ── Helper: Resolve EKU OID to friendly name ────────────────────────
    function Resolve-EkuOid {
        param([string]$Oid)
        if ($ekuMap.ContainsKey($Oid)) { return $ekuMap[$Oid] }
        return $Oid
    }

    # ── 1. Certificate Authorities ──────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Enumerating Certificate Authorities'
    }

    try {
        $enrollmentServicesDN = "CN=Enrollment Services,$pkiServicesDN"
        $caRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $enrollmentServicesDN
        $caResults = Invoke-LdapQuery -SearchRoot $caRoot `
            -Filter '(objectClass=pKIEnrollmentService)' `
            -Properties @(
                'cn', 'distinguishedName', 'dNSHostName',
                'cACertificate', 'cACertificateDN', 'flags',
                'certificateTemplates', 'whenCreated', 'whenChanged'
            ) `
            -Scope OneLevel

        $caList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($ca in $caResults) {
            $templates = @()
            if ($ca.ContainsKey('certificatetemplates')) {
                $templates = if ($ca['certificatetemplates'] -is [array]) {
                    @($ca['certificatetemplates'])
                } else {
                    @($ca['certificatetemplates'])
                }
            }

            $caObj = @{
                Name                = $ca['cn'] ?? ''
                DN                  = $ca['distinguishedname'] ?? ''
                DNSHostName         = if ($ca.ContainsKey('dnshostname')) { $ca['dnshostname'] } else { '' }
                CACertificate       = if ($ca.ContainsKey('cacertificate')) { $ca['cacertificate'] } else { $null }
                CACertificateDN     = if ($ca.ContainsKey('cacertificatedn')) { $ca['cacertificatedn'] } else { '' }
                Flags               = if ($ca.ContainsKey('flags')) { [int]$ca['flags'] } else { 0 }
                CertificateTemplates = $templates
                WhenCreated         = if ($ca.ContainsKey('whencreated')) { $ca['whencreated'] } else { $null }
                WhenChanged         = if ($ca.ContainsKey('whenchanged')) { $ca['whenchanged'] } else { $null }
            }
            $caList.Add($caObj)
        }

        $result.CertificateAuthorities = @($caList)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($caList.Count) Certificate Authority(ies)"
        }
    } catch {
        Write-Verbose "Failed to enumerate Certificate Authorities: $_"
        $result.Errors['CertificateAuthorities'] = $_.Exception.Message
    }

    # Build set of published template names for IsPublished check
    $publishedTemplates = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($ca in $result.CertificateAuthorities) {
        foreach ($tmpl in $ca.CertificateTemplates) {
            [void]$publishedTemplates.Add($tmpl)
        }
    }

    # ── 2. Certificate Templates ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Enumerating certificate templates'
    }

    try {
        $templatesDN = "CN=Certificate Templates,$pkiServicesDN"
        $tmplRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $templatesDN
        $lookupRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN

        $tmplResults = Invoke-LdapQuery -SearchRoot $tmplRoot `
            -Filter '(objectClass=pKICertificateTemplate)' `
            -Properties @(
                'cn', 'displayName', 'distinguishedName',
                'msPKI-Cert-Template-OID',
                'msPKI-Template-Schema-Version',
                'msPKI-Certificate-Name-Flag',
                'msPKI-Enrollment-Flag',
                'pKIExtendedKeyUsage',
                'msPKI-Certificate-Application-Policy',
                'msPKI-RA-Signature',
                'pKIExpirationPeriod', 'pKIOverlapPeriod',
                'ntSecurityDescriptor',
                'whenCreated', 'whenChanged'
            ) `
            -Scope OneLevel

        $templateList = [System.Collections.Generic.List[hashtable]]::new()
        $tmplCount = 0

        foreach ($tmpl in $tmplResults) {
            $tmplCount++
            if (-not $Quiet -and ($tmplCount % 50 -eq 0)) {
                Write-ProgressLine -Phase RECON -Message 'Processing templates' `
                    -Detail "$tmplCount / $($tmplResults.Count)"
            }

            $name = $tmpl['cn'] ?? ''

            # Certificate Name Flag (critical for ESC1)
            $certNameFlag = 0
            if ($tmpl.ContainsKey('mspki-certificate-name-flag')) {
                $certNameFlag = [int]$tmpl['mspki-certificate-name-flag']
            }
            $enrolleeSuppliesSubject = ($certNameFlag -band 0x1) -ne 0

            # Enrollment Flag
            $enrollmentFlag = 0
            if ($tmpl.ContainsKey('mspki-enrollment-flag')) {
                $enrollmentFlag = [int]$tmpl['mspki-enrollment-flag']
            }

            # Schema Version
            $schemaVersion = 0
            if ($tmpl.ContainsKey('mspki-template-schema-version')) {
                $schemaVersion = [int]$tmpl['mspki-template-schema-version']
            }

            # Extended Key Usage OIDs
            $ekuOids = @()
            if ($tmpl.ContainsKey('pkiextendedkeyusage')) {
                $raw = $tmpl['pkiextendedkeyusage']
                $ekuOids = if ($raw -is [array]) { @($raw) } else { @($raw) }
            }
            $ekuResolved = @($ekuOids | ForEach-Object { @{ OID = $_; Name = (Resolve-EkuOid $_) } })

            # Determine if template allows authentication
            # Any Purpose (empty EKU array or 2.5.29.37.0), Client Auth, Smart Card Logon, PKINIT
            $authenticationOids = @(
                '2.5.29.37.0',
                '1.3.6.1.5.5.7.3.2',
                '1.3.6.1.4.1.311.20.2.2',
                '1.3.6.1.5.2.3.4'
            )
            $allowsAuthentication = ($ekuOids.Count -eq 0) -or
                                    ($ekuOids | Where-Object { $_ -in $authenticationOids }).Count -gt 0

            # Application Policies
            $appPolicies = @()
            if ($tmpl.ContainsKey('mspki-certificate-application-policy')) {
                $raw = $tmpl['mspki-certificate-application-policy']
                $appPolicies = if ($raw -is [array]) { @($raw) } else { @($raw) }
            }

            # RA Signatures Required (0 means no manager approval - relevant for ESC1)
            $raSignatures = 0
            if ($tmpl.ContainsKey('mspki-ra-signature')) {
                $raSignatures = [int]$tmpl['mspki-ra-signature']
            }

            # Parse security descriptor for enrollment permissions
            $enrollmentPermissions = @()
            if ($tmpl.ContainsKey('ntsecuritydescriptor') -and $tmpl['ntsecuritydescriptor'] -is [byte[]]) {
                $enrollmentPermissions = Get-EnrollmentPermissions `
                    -SecurityDescriptorBytes $tmpl['ntsecuritydescriptor'] `
                    -LookupRoot $lookupRoot
            }

            # OID
            $oid = ''
            if ($tmpl.ContainsKey('mspki-cert-template-oid')) {
                $oid = $tmpl['mspki-cert-template-oid']
            }

            $tmplObj = @{
                Name                    = $name
                DisplayName             = if ($tmpl.ContainsKey('displayname')) { $tmpl['displayname'] } else { $name }
                DN                      = $tmpl['distinguishedname'] ?? ''
                OID                     = $oid
                SchemaVersion           = $schemaVersion
                CertificateNameFlag     = $certNameFlag
                EnrolleeSuppliesSubject = $enrolleeSuppliesSubject
                EnrollmentFlag          = $enrollmentFlag
                ExtendedKeyUsage        = $ekuResolved
                ExtendedKeyUsageOIDs    = $ekuOids
                AllowsAuthentication    = $allowsAuthentication
                ApplicationPolicies     = $appPolicies
                RASignaturesRequired    = $raSignatures
                EnrollmentPermissions   = $enrollmentPermissions
                IsPublished             = $publishedTemplates.Contains($name)
                WhenCreated             = if ($tmpl.ContainsKey('whencreated')) { $tmpl['whencreated'] } else { $null }
                WhenChanged             = if ($tmpl.ContainsKey('whenchanged')) { $tmpl['whenchanged'] } else { $null }
            }
            $templateList.Add($tmplObj)
        }

        $result.CertificateTemplates = @($templateList)

        if (-not $Quiet) {
            $publishedCount = @($templateList | Where-Object { $_.IsPublished }).Count
            Write-ProgressLine -Phase RECON -Message "Found $($templateList.Count) certificate template(s)" `
                -Detail "($publishedCount published)"
        }
    } catch {
        Write-Verbose "Failed to enumerate certificate templates: $_"
        $result.Errors['CertificateTemplates'] = $_.Exception.Message
    }

    # ── 3. PKI Objects and ACLs (for ESC5) ──────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Auditing PKI container ACLs'
    }

    try {
        $pkiRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $pkiServicesDN
        $lookupRoot2 = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN

        $pkiObjects = Invoke-LdapQuery -SearchRoot $pkiRoot `
            -Filter '(objectClass=*)' `
            -Properties @('cn', 'distinguishedName', 'objectClass', 'ntSecurityDescriptor') `
            -Scope OneLevel

        $pkiList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($pkiObj in $pkiObjects) {
            $objClass = $pkiObj['objectclass']
            if ($objClass -is [array]) { $objClass = $objClass[-1] }

            $permissions = @()
            if ($pkiObj.ContainsKey('ntsecuritydescriptor') -and $pkiObj['ntsecuritydescriptor'] -is [byte[]]) {
                $permissions = Get-EnrollmentPermissions `
                    -SecurityDescriptorBytes $pkiObj['ntsecuritydescriptor'] `
                    -LookupRoot $lookupRoot2
            }

            $pkiList.Add(@{
                Name        = $pkiObj['cn'] ?? ''
                DN          = $pkiObj['distinguishedname'] ?? ''
                ObjectClass = $objClass ?? ''
                Permissions = $permissions
            })
        }

        $result.PKIObjects = @($pkiList)
    } catch {
        Write-Verbose "Failed to audit PKI container ACLs: $_"
        $result.Errors['PKIObjects'] = $_.Exception.Message
    }

    # ── 4. NTAuthCertificates ───────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Reading NTAuthCertificates'
    }

    try {
        $ntauthDN = "CN=NTAuthCertificates,$pkiServicesDN"
        $ntauthRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $ntauthDN
        $ntauthResults = @(Invoke-LdapQuery -SearchRoot $ntauthRoot `
            -Filter '(objectClass=certificationAuthority)' `
            -Properties @('cn', 'distinguishedName', 'cACertificate', 'whenCreated', 'whenChanged') `
            -Scope Base)

        if ($ntauthResults.Count -gt 0) {
            $ntauth = $ntauthResults[0]
            $caCerts = @()
            if ($ntauth.ContainsKey('cacertificate')) {
                $raw = $ntauth['cacertificate']
                $caCerts = if ($raw -is [array]) { @($raw) } else { @($raw) }
            }

            $result.NTAuthCertificates = @{
                DN              = $ntauth['distinguishedname'] ?? ''
                CACertificates  = $caCerts
                CertificateCount = $caCerts.Count
                WhenCreated     = if ($ntauth.ContainsKey('whencreated')) { $ntauth['whencreated'] } else { $null }
                WhenChanged     = if ($ntauth.ContainsKey('whenchanged')) { $ntauth['whenchanged'] } else { $null }
            }
        }
    } catch {
        Write-Verbose "NTAuthCertificates not found or not accessible: $_"
        # Not an error — may not exist in environments without AD CS
    }

    # ── 5. OID Objects (for ESC13 issuance policy links) ────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Checking OID issuance policy links'
    }

    try {
        $oidContainerDN = "CN=OID,$pkiServicesDN"
        $oidRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $oidContainerDN
        $oidResults = Invoke-LdapQuery -SearchRoot $oidRoot `
            -Filter '(objectClass=msPKI-Enterprise-Oid)' `
            -Properties @(
                'cn', 'distinguishedName', 'displayName',
                'msPKI-Cert-Template-OID',
                'msDS-OIDToGroupLink',
                'flags'
            ) `
            -Scope OneLevel

        $oidList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($oidObj in $oidResults) {
            $groupLink = $null
            if ($oidObj.ContainsKey('msds-oidtogrouplink')) {
                $groupLink = $oidObj['msds-oidtogrouplink']
            }

            $oidEntry = @{
                Name          = $oidObj['cn'] ?? ''
                DisplayName   = if ($oidObj.ContainsKey('displayname')) { $oidObj['displayname'] } else { '' }
                DN            = $oidObj['distinguishedname'] ?? ''
                OID           = if ($oidObj.ContainsKey('mspki-cert-template-oid')) { $oidObj['mspki-cert-template-oid'] } else { '' }
                GroupLink     = $groupLink
                HasGroupLink  = ($null -ne $groupLink -and $groupLink -ne '')
                Flags         = if ($oidObj.ContainsKey('flags')) { [int]$oidObj['flags'] } else { 0 }
            }
            $oidList.Add($oidEntry)
        }

        $result.OIDObjects = @($oidList)

        $linkedCount = @($oidList | Where-Object { $_.HasGroupLink }).Count
        if (-not $Quiet -and $linkedCount -gt 0) {
            Write-ProgressLine -Phase RECON -Message "Found $linkedCount OID(s) with group links (ESC13 potential)"
        }
    } catch {
        Write-Verbose "OID container not accessible: $_"
        # Not an error — may not exist
    }

    # ── Summary ─────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $summary = "AD CS collection complete: $($result.CertificateAuthorities.Count) CA(s), " +
                   "$($result.CertificateTemplates.Count) template(s)"
        if ($result.Errors.Count -gt 0) {
            $summary += " ($($result.Errors.Count) error(s))"
        }
        Write-ProgressLine -Phase RECON -Message $summary
    }

    return $result
}
