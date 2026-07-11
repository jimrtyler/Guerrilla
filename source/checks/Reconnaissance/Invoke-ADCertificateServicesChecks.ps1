# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADCertificateServicesChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADCertificateServicesChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Recon$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ============================================================================
# Helper: Well-known low-privileged SIDs that indicate dangerous enrollment
# ============================================================================
function Test-IsLowPrivilegedSID {
    param([string]$SID)

    # Well-known SIDs that represent low-privileged / broad groups
    $lowPrivSIDs = @(
        'S-1-1-0'   # Everyone
        'S-1-5-7'   # Anonymous
        'S-1-5-11'  # Authenticated Users
    )

    if ($SID -in $lowPrivSIDs) { return $true }

    # Domain Users (RID 513) and Domain Computers (RID 515)
    if ($SID -match '-513$' -or $SID -match '-515$') { return $true }

    return $false
}

# ============================================================================
# Helper: Get low-privileged enrollment ACEs from a template
# ============================================================================
function Get-LowPrivEnrollmentACEs {
    param([array]$EnrollmentPermissions)

    if (-not $EnrollmentPermissions -or $EnrollmentPermissions.Count -eq 0) { return @() }

    $dangerousACEs = @($EnrollmentPermissions | Where-Object {
        ($_.Right -eq 'Enroll' -or $_.Right -eq 'AutoEnroll' -or $_.Right -eq 'FullControl') -and
        (Test-IsLowPrivilegedSID -SID $_.SID)
    })

    return $dangerousACEs
}

# ============================================================================
# Helper: Get dangerous write ACEs on an object (for ESC4/ESC5)
# ============================================================================
function Get-DangerousWriteACEs {
    param([array]$Permissions)

    if (-not $Permissions -or $Permissions.Count -eq 0) { return @() }

    $writeRights = @('WriteDacl', 'WriteOwner', 'FullControl', 'WriteAllProperties')

    $dangerousACEs = @($Permissions | Where-Object {
        ($_.Right -in $writeRights) -and
        (Test-IsLowPrivilegedSID -SID $_.SID)
    })

    return $dangerousACEs
}

# ============================================================================
# Helper: Check if a template has authentication-capable EKU
# ============================================================================
function Test-HasAuthenticationEKU {
    param([array]$EKUOIDs)

    $authOIDs = @(
        '1.3.6.1.5.5.7.3.2'          # Client Authentication
        '1.3.6.1.4.1.311.20.2.2'     # Smart Card Logon
        '1.3.6.1.5.2.3.4'            # PKINIT Client Authentication
        '2.5.29.37.0'                 # Any Purpose
    )

    # No EKU means the cert can be used for anything (SubCA equivalent)
    if (-not $EKUOIDs -or $EKUOIDs.Count -eq 0) { return $true }

    foreach ($oid in $EKUOIDs) {
        if ($oid -in $authOIDs) { return $true }
    }

    return $false
}

# ── ADCS-001: CA Server Inventory ──────────────────────────────────────────
function Test-ReconADCS001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $cas = @($adcs.CertificateAuthorities)
    if ($cas.Count -eq 0 -or ($cas.Count -eq 1 -and $null -eq $cas[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Certificate Authorities found in the environment'
    }

    $caSummary = @($cas | ForEach-Object {
        $templateCount = 0
        if ($_.CertificateTemplates) { $templateCount = @($_.CertificateTemplates).Count }
        @{
            Name              = $_.Name
            DNSHostName       = $_.DNSHostName
            DN                = $_.DN
            Flags             = $_.Flags
            PublishedTemplates = $templateCount
        }
    })

    $totalTemplatesPublished = ($caSummary | Measure-Object -Property PublishedTemplates -Sum).Sum

    $currentValue = "$($cas.Count) Certificate Authority(ies) found publishing $totalTemplatesPublished template(s) total"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            TotalCAs                = $cas.Count
            TotalPublishedTemplates = $totalTemplatesPublished
            CASummary               = $caSummary
        }
}

# ── ADCS-002: ESC1 - Enrollee Supplies SAN ─────────────────────────────────
function Test-ReconADCS002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        # Skip unpublished templates
        if (-not $tmpl.IsPublished) { continue }

        # ESC1 requires: enrollee supplies subject (SAN flag)
        if (-not $tmpl.EnrolleeSuppliesSubject) { continue }

        # ESC1 requires: authentication EKU (Client Auth, Smart Card Logon, Any Purpose, or empty)
        $ekuOIDs = @($tmpl.ExtendedKeyUsageOIDs)
        if (-not (Test-HasAuthenticationEKU -EKUOIDs $ekuOIDs)) { continue }

        # ESC1 requires: manager approval not required
        if ($tmpl.RASignaturesRequired -gt 0) { continue }

        # ESC1 requires: low-privileged users can enroll
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -eq 0) { continue }

        $principals = @($lowPrivACEs | ForEach-Object { $_.Identity } | Sort-Object -Unique)

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            EnrollablePrincipals = $principals
            EKUs               = @($tmpl.ExtendedKeyUsage | ForEach-Object { $_.Name })
            SchemaVersion      = $tmpl.SchemaVersion
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) vulnerable to ESC1: $($templateNames -join ', '). " +
            'These templates allow enrollees to specify a SAN, have authentication EKUs, and permit low-privileged enrollment'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No published templates vulnerable to ESC1 (enrollee-supplied SAN with authentication EKU and low-privileged enrollment)' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-003: ESC2 - Any Purpose / No EKU ─────────────────────────────────
function Test-ReconADCS003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }

        $ekuOIDs = @($tmpl.ExtendedKeyUsageOIDs)
        $hasAnyPurpose = '2.5.29.37.0' -in $ekuOIDs
        $hasNoEKU = $ekuOIDs.Count -eq 0

        if (-not $hasAnyPurpose -and -not $hasNoEKU) { continue }

        # Must allow low-privileged enrollment
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -eq 0) { continue }

        # Skip if manager approval required
        if ($tmpl.RASignaturesRequired -gt 0) { continue }

        $principals = @($lowPrivACEs | ForEach-Object { $_.Identity } | Sort-Object -Unique)
        $reason = if ($hasAnyPurpose) { 'Any Purpose EKU (2.5.29.37.0)' } else { 'No EKU defined (SubCA equivalent)' }

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            Reason             = $reason
            EnrollablePrincipals = $principals
            SchemaVersion      = $tmpl.SchemaVersion
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) vulnerable to ESC2: $($templateNames -join ', '). " +
            'These templates have Any Purpose EKU or no EKU and permit low-privileged enrollment'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No published templates vulnerable to ESC2 (Any Purpose EKU or no EKU with low-privileged enrollment)' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-004: ESC3 Condition 1 - Certificate Request Agent ────────────────
function Test-ReconADCS004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    # Certificate Request Agent EKU OID
    $requestAgentOID = '1.3.6.1.4.1.311.20.2.1'

    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }

        $ekuOIDs = @($tmpl.ExtendedKeyUsageOIDs)
        if ($requestAgentOID -notin $ekuOIDs) { continue }

        # Must allow low-privileged enrollment
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -eq 0) { continue }

        $principals = @($lowPrivACEs | ForEach-Object { $_.Identity } | Sort-Object -Unique)

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            EnrollablePrincipals = $principals
            SchemaVersion      = $tmpl.SchemaVersion
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) vulnerable to ESC3 Condition 1: $($templateNames -join ', '). " +
            'These templates have the Certificate Request Agent EKU and allow low-privileged enrollment'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No published templates with Certificate Request Agent EKU enrollable by low-privileged users' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-005: ESC3 Condition 2 - Enrollment Agent Co-signing ──────────────
function Test-ReconADCS005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    # Certificate Request Agent application policy OID
    $requestAgentOID = '1.3.6.1.4.1.311.20.2.1'

    # Find templates that require an enrollment agent signature and have authentication EKU
    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }

        # Must require at least one RA signature (enrollment agent co-signing)
        if ($tmpl.RASignaturesRequired -lt 1) { continue }

        # Check if the application policy requires Certificate Request Agent
        $appPolicies = @($tmpl.ApplicationPolicies)
        $requiresRequestAgent = $requestAgentOID -in $appPolicies

        if (-not $requiresRequestAgent) { continue }

        # Must have authentication EKU
        $ekuOIDs = @($tmpl.ExtendedKeyUsageOIDs)
        if (-not (Test-HasAuthenticationEKU -EKUOIDs $ekuOIDs)) { continue }

        $ekuNames = @($tmpl.ExtendedKeyUsage | ForEach-Object { $_.Name })

        $vulnerableTemplates.Add(@{
            TemplateName          = $tmpl.Name
            DisplayName           = $tmpl.DisplayName
            RASignaturesRequired  = $tmpl.RASignaturesRequired
            EKUs                  = $ekuNames
            SchemaVersion         = $tmpl.SchemaVersion
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) vulnerable to ESC3 Condition 2: $($templateNames -join ', '). " +
            'These templates require enrollment agent co-signing and have authentication EKUs, enabling on-behalf-of enrollment for any user'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No published templates with enrollment agent co-signing and authentication EKU found' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-006: ESC4 - Vulnerable Certificate Template ACLs ─────────────────
function Test-ReconADCS006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        # Check all templates, not just published ones, since write access could publish them
        $dangerousACEs = Get-DangerousWriteACEs -Permissions $tmpl.EnrollmentPermissions
        if ($dangerousACEs.Count -eq 0) { continue }

        $principals = @($dangerousACEs | ForEach-Object {
            "$($_.Identity) ($($_.Right))"
        } | Sort-Object -Unique)

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            IsPublished        = $tmpl.IsPublished
            DangerousACEs      = @($dangerousACEs | ForEach-Object {
                @{ Identity = $_.Identity; SID = $_.SID; Right = $_.Right }
            })
            PrincipalSummary   = $principals
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) vulnerable to ESC4 (write ACL abuse): $($templateNames -join ', '). " +
            'Low-privileged principals have write permissions that could modify these templates to create exploitable conditions'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No certificate templates with dangerous write ACLs for low-privileged principals' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-007: ESC4 - Vulnerable Certificate Template Ownership ────────────
function Test-ReconADCS007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    # Check for templates where the Owner permission is held by a low-privileged principal.
    # The data collector reports WriteOwner in EnrollmentPermissions when low-priv users hold it.
    # We also check for explicit Owner entries if available.
    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        $permissions = @($tmpl.EnrollmentPermissions)
        if ($permissions.Count -eq 0) { continue }

        # Look for WriteOwner or FullControl ACEs from low-privileged principals
        # A principal with WriteOwner can take ownership and then modify the DACL
        $ownerACEs = @($permissions | Where-Object {
            ($_.Right -eq 'WriteOwner' -or $_.Right -eq 'FullControl') -and
            (Test-IsLowPrivilegedSID -SID $_.SID)
        })

        if ($ownerACEs.Count -eq 0) { continue }

        $principals = @($ownerACEs | ForEach-Object {
            "$($_.Identity) ($($_.Right))"
        } | Sort-Object -Unique)

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            IsPublished        = $tmpl.IsPublished
            OwnershipACEs      = @($ownerACEs | ForEach-Object {
                @{ Identity = $_.Identity; SID = $_.SID; Right = $_.Right }
            })
            PrincipalSummary   = $principals
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) with ownership vulnerability (ESC4): $($templateNames -join ', '). " +
            'Low-privileged principals can take ownership or already have ownership-level control over these templates'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No certificate templates with ownership vulnerabilities for low-privileged principals' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-008: ESC5 - Vulnerable PKI Object ACLs ──────────────────────────
function Test-ReconADCS008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $pkiObjects = @($adcs.PKIObjects)
    if ($pkiObjects.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No PKI container objects found for ACL analysis'
    }

    $vulnerableObjects = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($pkiObj in $pkiObjects) {
        $dangerousACEs = Get-DangerousWriteACEs -Permissions $pkiObj.Permissions
        if ($dangerousACEs.Count -eq 0) { continue }

        $principals = @($dangerousACEs | ForEach-Object {
            "$($_.Identity) ($($_.Right))"
        } | Sort-Object -Unique)

        $vulnerableObjects.Add(@{
            ObjectName       = $pkiObj.Name
            DN               = $pkiObj.DN
            ObjectClass      = $pkiObj.ObjectClass
            DangerousACEs    = @($dangerousACEs | ForEach-Object {
                @{ Identity = $_.Identity; SID = $_.SID; Right = $_.Right }
            })
            PrincipalSummary = $principals
        })
    }

    if ($vulnerableObjects.Count -gt 0) {
        $objectNames = @($vulnerableObjects | ForEach-Object { "$($_.ObjectName) ($($_.ObjectClass))" })
        $currentValue = "$($vulnerableObjects.Count) PKI object(s) vulnerable to ESC5: $($objectNames -join ', '). " +
            'Low-privileged principals have write permissions on PKI container objects that could enable rogue CA addition or enrollment manipulation'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableObjectCount = $vulnerableObjects.Count
                VulnerableObjects     = @($vulnerableObjects)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($pkiObjects.Count) PKI container object(s) have appropriate ACLs - no dangerous write permissions for low-privileged principals" `
        -Details @{ PKIObjectsChecked = $pkiObjects.Count }
}

# ── ADCS-009: ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag ─────────────────
function Test-ReconADCS009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $cas = @($adcs.CertificateAuthorities)
    if ($cas.Count -eq 0 -or ($cas.Count -eq 1 -and $null -eq $cas[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Certificate Authorities found'
    }

    # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 (262144)
    $editfSanFlag = 0x00040000

    $vulnerableCAs = [System.Collections.Generic.List[hashtable]]::new()
    $checkedCAs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ca in $cas) {
        $flags = [int]$ca.Flags
        $hasSanFlag = ($flags -band $editfSanFlag) -ne 0

        $caEntry = @{
            CAName      = $ca.Name
            DNSHostName = $ca.DNSHostName
            Flags       = $flags
            HasSANFlag  = $hasSanFlag
        }

        $checkedCAs.Add($caEntry)

        if ($hasSanFlag) {
            $vulnerableCAs.Add($caEntry)
        }
    }

    # EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) lives in the CA host's policy-module registry
    # (HKLM\...\CertSvc\Configuration\<CA>\PolicyModules\...\EditFlags) and is exposed only via the
    # CA's RPC interface — NOT via the LDAP pKIEnrollmentService 'flags' attribute read here (that is
    # a different flags field). A "not set" result from LDAP is therefore not evidence the flag is
    # off, so this cannot be assessed agentlessly: report Not Assessed rather than a false PASS.
    $caNames = @($checkedCAs | ForEach-Object { $_.CAName }) -join ', '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) cannot be determined via agentless LDAP for $($cas.Count) CA(s) ($caNames) — it is a CA-host policy-module registry flag. Not Assessed: verify with 'certutil -getreg policy\EditFlags' on each CA server, or run a CA-RPC-aware tool." `
        -Details @{ AllCAs = @($checkedCAs); NotAssessed = $true }
}

# ── ADCS-010: ESC7 - Vulnerable CA ACLs ──────────────────────────────────
function Test-ReconADCS010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $cas = @($adcs.CertificateAuthorities)
    if ($cas.Count -eq 0 -or ($cas.Count -eq 1 -and $null -eq $cas[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Certificate Authorities found'
    }

    # Check PKI objects for CA enrollment service objects with dangerous ACLs
    # ManageCA and ManageCertificates are exposed as WriteDacl/WriteOwner/FullControl
    # on the CA's enrollment service AD object
    $pkiObjects = @($adcs.PKIObjects)
    $vulnerableCAs = [System.Collections.Generic.List[hashtable]]::new()

    # Check the enrollment service objects in PKIObjects
    foreach ($pkiObj in $pkiObjects) {
        # Match enrollment service objects to known CAs
        $matchingCA = $cas | Where-Object { $_.Name -eq $pkiObj.Name }
        if (-not $matchingCA) { continue }

        $dangerousACEs = @()
        if ($pkiObj.Permissions) {
            $dangerousACEs = @($pkiObj.Permissions | Where-Object {
                ($_.Right -eq 'WriteDacl' -or $_.Right -eq 'WriteOwner' -or
                 $_.Right -eq 'FullControl' -or $_.Right -eq 'WriteAllProperties') -and
                (Test-IsLowPrivilegedSID -SID $_.SID)
            })
        }

        if ($dangerousACEs.Count -eq 0) { continue }

        $principals = @($dangerousACEs | ForEach-Object {
            "$($_.Identity) ($($_.Right))"
        } | Sort-Object -Unique)

        $vulnerableCAs.Add(@{
            CAName           = $pkiObj.Name
            DN               = $pkiObj.DN
            DangerousACEs    = @($dangerousACEs | ForEach-Object {
                @{ Identity = $_.Identity; SID = $_.SID; Right = $_.Right }
            })
            PrincipalSummary = $principals
        })
    }

    if ($vulnerableCAs.Count -gt 0) {
        $caNames = @($vulnerableCAs | ForEach-Object { $_.CAName })
        $currentValue = "$($vulnerableCAs.Count) CA(s) vulnerable to ESC7: $($caNames -join ', '). " +
            'Low-privileged principals have ManageCA or ManageCertificates-equivalent permissions that could enable CA configuration changes or pending request approval'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableCACount = $vulnerableCAs.Count
                VulnerableCAs     = @($vulnerableCAs)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No CA enrollment service objects have dangerous ACLs for low-privileged principals. Verify CA permissions manually with 'certutil -getacl' for full ManageCA/ManageCertificates audit" `
        -Details @{
            CAsChecked        = $cas.Count
            PKIObjectsChecked = $pkiObjects.Count
        }
}

# ── ADCS-011: ESC8 - NTLM Relay to HTTP Endpoints ────────────────────────
function Test-ReconADCS011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $cas = @($adcs.CertificateAuthorities)
    if ($cas.Count -eq 0 -or ($cas.Count -eq 1 -and $null -eq $cas[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Certificate Authorities found'
    }

    # HTTP enrollment endpoints cannot be fully detected via LDAP alone.
    # We report the CA hostnames and advise manual verification of IIS bindings.
    $caHostnames = @($cas | ForEach-Object { $_.DNSHostName } | Where-Object { $_ } | Sort-Object -Unique)

    if ($caHostnames.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'CA DNS hostnames not available. Manually verify that no HTTP-based enrollment endpoints (certsrv, CES) are configured on CA servers' `
            -Details @{ CAsChecked = $cas.Count }
    }

    # Report as WARN since we cannot confirm HTTP enrollment status via LDAP
    $currentValue = "$($caHostnames.Count) CA server(s) identified: $($caHostnames -join ', '). " +
        'Verify that no HTTP-based enrollment endpoints (certsrv/CES) are configured without HTTPS and Extended Protection for Authentication (EPA). ' +
        'Check IIS bindings on each CA server. HTTP enrollment enables NTLM relay attacks (ESC8)'

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            CAHostnames = $caHostnames
            Note        = 'HTTP enrollment endpoint detection requires direct IIS inspection on each CA server. LDAP-based detection is limited.'
        }
}

# ── ADCS-012: ESC9 - StrongCertificateBindingEnforcement ─────────────────
function Test-ReconADCS012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CertificateServices','GroupPolicyObjects') -Subject 'AD CS binding enforcement configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    # StrongCertificateBindingEnforcement is a registry value on DCs, not in AD LDAP.
    # Check GPO data if available.
    $gpoData = $AuditData.GroupPolicies
    $bindingValue = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'StrongCertificateBindingEnforcement' -or
                        $regPolicy.ValueName -eq 'strongcertificatebindingenforcement') {
                        $bindingValue = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $bindingValue) {
        # 0 = Disabled, 1 = Compatibility mode, 2 = Full enforcement
        $status = if ($bindingValue -eq 2) { 'PASS' }
                  elseif ($bindingValue -eq 1) { 'WARN' }
                  else { 'FAIL' }

        $valueLabel = switch ($bindingValue) {
            0 { 'Disabled (no enforcement)' }
            1 { 'Compatibility mode (partial enforcement)' }
            2 { 'Full enforcement mode' }
            default { "Unknown ($bindingValue)" }
        }

        $currentValue = "StrongCertificateBindingEnforcement: $bindingValue ($valueLabel)"
        if ($bindingValue -lt 2) {
            $currentValue += '. ESC9 and ESC10 attacks may be possible without full enforcement'
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue `
            -Details @{
                StrongCertificateBindingEnforcement = $bindingValue
                Description                         = $valueLabel
            }
    }

    # Check for templates with CT_FLAG_NO_SECURITY_EXTENSION (0x80000) in enrollment flag
    $noSecExtFlag = 0x80000
    $templatesWithNoSecExt = [System.Collections.Generic.List[string]]::new()

    $templates = @($adcs.CertificateTemplates)
    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }
        $enrollFlag = [int]$tmpl.EnrollmentFlag
        if (($enrollFlag -band $noSecExtFlag) -ne 0) {
            $templatesWithNoSecExt.Add($tmpl.Name)
        }
    }

    $details = @{
        Note = 'StrongCertificateBindingEnforcement registry value not found in GPO data. Check HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement on all DCs. Value should be 2.'
    }

    if ($templatesWithNoSecExt.Count -gt 0) {
        $details['TemplatesWithNoSecurityExtension'] = @($templatesWithNoSecExt)
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "StrongCertificateBindingEnforcement could not be verified from GPO data. Additionally, $($templatesWithNoSecExt.Count) published template(s) have CT_FLAG_NO_SECURITY_EXTENSION set: $($templatesWithNoSecExt -join ', '). Verify enforcement is set to 2 on all DCs" `
            -Details $details
    }

    # The binding value could not be read and no risky templates corroborate a
    # finding — this is genuinely unassessed (a registry value on the DCs that
    # GPO data didn't carry), not a soft WARN. Report Not Assessed so a secure
    # tenant isn't permanently flagged and PASS stays reachable when the value
    # is actually collected as 2.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'StrongCertificateBindingEnforcement could not be read from collected GPO data — Not Assessed. Provide the DC registry value (HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement; should be 2) to assess ESC9/ESC10 exposure' `
        -Details $details
}

# ── ADCS-013: ESC11 - RPC Relay Without Encryption ───────────────────────
function Test-ReconADCS013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $cas = @($adcs.CertificateAuthorities)
    if ($cas.Count -eq 0 -or ($cas.Count -eq 1 -and $null -eq $cas[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Certificate Authorities found'
    }

    # IF_ENFORCEENCRYPTICERTREQUEST cannot be directly verified via LDAP.
    # We can only advise manual verification on each CA server.
    $caHostnames = @($cas | ForEach-Object { $_.DNSHostName } | Where-Object { $_ } | Sort-Object -Unique)
    $caNames = @($cas | ForEach-Object { $_.Name })

    $currentValue = "$($cas.Count) CA(s) identified: $($caNames -join ', '). " +
        "Verify IF_ENFORCEENCRYPTICERTREQUEST flag is enabled on each CA using 'certutil -getreg CA\InterfaceFlags'. " +
        'Without this flag, the RPC enrollment interface is vulnerable to NTLM relay attacks (ESC11)'

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            CANames     = $caNames
            CAHostnames = $caHostnames
            Note        = 'IF_ENFORCEENCRYPTICERTREQUEST flag status cannot be determined via LDAP. Manual verification required on each CA server.'
        }
}

# ── ADCS-014: ESC13 - Issuance Policy OID Group Link ────────────────────
function Test-ReconADCS014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $oidObjects = @($adcs.OIDObjects)
    if ($oidObjects.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No OID objects found in PKI configuration'
    }

    # Find OIDs with group links (msDS-OIDToGroupLink populated)
    $linkedOIDs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($oidObj in $oidObjects) {
        if (-not $oidObj.HasGroupLink) { continue }

        # Determine which templates use this issuance policy OID
        $linkedTemplates = @()
        $templates = @($adcs.CertificateTemplates)
        foreach ($tmpl in $templates) {
            if (-not $tmpl.IsPublished) { continue }
            $appPolicies = @($tmpl.ApplicationPolicies)
            if ($oidObj.OID -in $appPolicies) {
                $linkedTemplates += $tmpl.Name
            }
        }

        $linkedOIDs.Add(@{
            OIDName      = $oidObj.Name
            DisplayName  = $oidObj.DisplayName
            OID          = $oidObj.OID
            GroupLink    = $oidObj.GroupLink
            DN           = $oidObj.DN
            LinkedTemplates = $linkedTemplates
        })
    }

    if ($linkedOIDs.Count -gt 0) {
        $oidNames = @($linkedOIDs | ForEach-Object { "$($_.OIDName) -> $($_.GroupLink)" })
        $currentValue = "$($linkedOIDs.Count) issuance policy OID(s) linked to security groups (ESC13): $($oidNames -join '; '). " +
            'Enrollees in templates using these issuance policies effectively gain group membership via the linked group'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                LinkedOIDCount = $linkedOIDs.Count
                LinkedOIDs     = @($linkedOIDs)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No issuance policy OIDs linked to security groups among $($oidObjects.Count) OID object(s)" `
        -Details @{ OIDObjectsChecked = $oidObjects.Count }
}

# ── ADCS-015: ESC15 - Application Policies in Schema v1 Templates ────────
function Test-ReconADCS015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    # Schema v1 templates do not enforce Application Policies from the template definition
    # This allows enrollees to add arbitrary EKUs to the certificate request
    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }

        # Only Schema v1 templates are affected
        if ([int]$tmpl.SchemaVersion -ne 1) { continue }

        # Check if low-privileged users can enroll
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -eq 0) { continue }

        $principals = @($lowPrivACEs | ForEach-Object { $_.Identity } | Sort-Object -Unique)

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            SchemaVersion      = $tmpl.SchemaVersion
            EKUs               = @($tmpl.ExtendedKeyUsage | ForEach-Object { $_.Name })
            EnrollablePrincipals = $principals
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) Schema v1 template(s) vulnerable to ESC15: $($templateNames -join ', '). " +
            'Schema v1 templates do not enforce Application Policies, allowing enrollees to add authentication EKUs to certificate requests'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    # Report count of v1 templates even if none are low-priv enrollable
    $v1Count = @($templates | Where-Object { [int]$_.SchemaVersion -eq 1 -and $_.IsPublished }).Count

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No published Schema v1 templates with low-privileged enrollment found ($v1Count published v1 template(s) total)" `
        -Details @{
            TemplatesChecked   = $templates.Count
            SchemaV1Published  = $v1Count
        }
}

# ── ADCS-016: ESC16 - UPN SAN Misconfiguration ──────────────────────────
function Test-ReconADCS016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    # CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    $upnSanFlag = 0x02000000

    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }

        $certNameFlag = [int]$tmpl.CertificateNameFlag

        # Check for enrollee supplies subject or UPN SAN requirement
        $hasEnrolleeSuppliesSubject = $tmpl.EnrolleeSuppliesSubject
        $hasUPNSan = ($certNameFlag -band $upnSanFlag) -ne 0

        if (-not $hasEnrolleeSuppliesSubject -and -not $hasUPNSan) { continue }

        # Must have authentication EKU
        $ekuOIDs = @($tmpl.ExtendedKeyUsageOIDs)
        if (-not (Test-HasAuthenticationEKU -EKUOIDs $ekuOIDs)) { continue }

        # Must allow low-privileged enrollment
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -eq 0) { continue }

        $principals = @($lowPrivACEs | ForEach-Object { $_.Identity } | Sort-Object -Unique)
        $flags = @()
        if ($hasEnrolleeSuppliesSubject) { $flags += 'ENROLLEE_SUPPLIES_SUBJECT' }
        if ($hasUPNSan) { $flags += 'SUBJECT_ALT_REQUIRE_UPN' }

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            NameFlags          = $flags
            EKUs               = @($tmpl.ExtendedKeyUsage | ForEach-Object { $_.Name })
            EnrollablePrincipals = $principals
            SchemaVersion      = $tmpl.SchemaVersion
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) potentially vulnerable to ESC16: $($templateNames -join ', '). " +
            'These templates allow UPN specification in the SAN with authentication EKUs. ' +
            'If StrongCertificateBindingEnforcement is not set to 2, UPN-based certificate mapping enables impersonation'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No published templates with UPN SAN misconfiguration and low-privileged enrollment found' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-017: EKEUwu - Extended Key Usage Abuse ─────────────────────────
function Test-ReconADCS017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found'
    }

    # EKEUwu targets templates where the EKU is not strictly enforced.
    # This includes: Schema v1 templates (EKU not enforced), templates with
    # Any Purpose EKU, templates with no EKU, and templates where application
    # policies can be overridden by the enrollee.
    $vulnerableTemplates = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }

        $ekuOIDs = @($tmpl.ExtendedKeyUsageOIDs)
        $schemaVersion = [int]$tmpl.SchemaVersion

        $isVulnerable = $false
        $reasons = [System.Collections.Generic.List[string]]::new()

        # Schema v1: EKU not enforced from template
        if ($schemaVersion -eq 1) {
            $isVulnerable = $true
            $reasons.Add('Schema v1 template - EKU not enforced by template')
        }

        # Any Purpose EKU
        if ('2.5.29.37.0' -in $ekuOIDs) {
            $isVulnerable = $true
            $reasons.Add('Any Purpose EKU allows certificate to be used for any purpose')
        }

        # No EKU (SubCA equivalent)
        if ($ekuOIDs.Count -eq 0) {
            $isVulnerable = $true
            $reasons.Add('No EKU defined - certificate can be used for any purpose (SubCA equivalent)')
        }

        if (-not $isVulnerable) { continue }

        # Must allow low-privileged enrollment
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -eq 0) { continue }

        # Skip if manager approval required
        if ($tmpl.RASignaturesRequired -gt 0) { continue }

        $principals = @($lowPrivACEs | ForEach-Object { $_.Identity } | Sort-Object -Unique)

        $vulnerableTemplates.Add(@{
            TemplateName       = $tmpl.Name
            DisplayName        = $tmpl.DisplayName
            SchemaVersion      = $schemaVersion
            Reasons            = @($reasons)
            EKUs               = @($tmpl.ExtendedKeyUsage | ForEach-Object { $_.Name })
            EnrollablePrincipals = $principals
        })
    }

    if ($vulnerableTemplates.Count -gt 0) {
        $templateNames = @($vulnerableTemplates | ForEach-Object { $_.TemplateName })
        $currentValue = "$($vulnerableTemplates.Count) template(s) vulnerable to EKU abuse: $($templateNames -join ', '). " +
            'These templates have configurations where the EKU can be influenced by the enrollee, allowing addition of authentication capabilities'

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                VulnerableTemplateCount = $vulnerableTemplates.Count
                VulnerableTemplates     = @($vulnerableTemplates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No published templates with exploitable EKU abuse patterns and low-privileged enrollment found' `
        -Details @{ TemplatesChecked = $templates.Count }
}

# ── ADCS-018: CA Auditing Configuration ──────────────────────────────────
function Test-ReconADCS018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $cas = @($adcs.CertificateAuthorities)
    if ($cas.Count -eq 0 -or ($cas.Count -eq 1 -and $null -eq $cas[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Certificate Authorities found'
    }

    # CA audit flags are typically stored in the registry and not directly exposed
    # in the AD enrollment service object via LDAP. The Flags attribute on the CA
    # object may contain some audit information but is not comprehensive.
    # Check if audit flag data is available via GPO or CA flags.

    # Audit flag bits (from certutil -getreg CA\AuditFilter):
    # 0x01 = Start/Stop
    # 0x02 = Backup/Restore
    # 0x04 = Certificate Issued
    # 0x08 = Certificate Denied/Failed
    # 0x10 = Certificate Revoked
    # 0x20 = CA Security Changed
    # 0x40 = Store/Retrieve Archived Key
    # 0x80 = CA Configuration Changed
    # All enabled = 0xFF (255)
    $fullAuditMask = 0x7F  # 127 = all seven standard categories

    $caNames = @($cas | ForEach-Object { $_.Name })
    $caHostnames = @($cas | ForEach-Object { $_.DNSHostName } | Where-Object { $_ } | Sort-Object -Unique)

    # Since CA audit flags cannot be reliably determined via LDAP alone,
    # report as WARN with manual verification guidance
    $currentValue = "$($cas.Count) CA(s) identified: $($caNames -join ', '). " +
        "CA audit configuration cannot be verified via LDAP. Run 'certutil -getreg CA\AuditFilter' on each CA server. " +
        'All audit categories should be enabled (AuditFilter = 0x7F or 127) for comprehensive logging of certificate issuance, revocation, and CA configuration changes'

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            CANames     = $caNames
            CAHostnames = $caHostnames
            Note        = 'CA AuditFilter registry value (HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\AuditFilter) must be checked directly on each CA server. Expected value: 0x7F (127) for all audit categories enabled.'
            ExpectedAuditFilter = $fullAuditMask
        }
}

# ── ADCS-019: Certificate Template Enumeration ──────────────────────────
function Test-ReconADCS019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'CertificateServices' -Subject 'AD CS configuration'
    if ($na) { return $na }

    $adcs = $AuditData.CertificateServices
    if (-not $adcs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ADCS data not available - no Certificate Services found'
    }

    $templates = @($adcs.CertificateTemplates)
    if ($templates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No certificate templates found in the environment'
    }

    $publishedCount = @($templates | Where-Object { $_.IsPublished }).Count
    $unpublishedCount = $templates.Count - $publishedCount

    # Schema version breakdown
    $v1Count = @($templates | Where-Object { [int]$_.SchemaVersion -eq 1 }).Count
    $v2Count = @($templates | Where-Object { [int]$_.SchemaVersion -eq 2 }).Count
    $v3Count = @($templates | Where-Object { [int]$_.SchemaVersion -eq 3 }).Count
    $v4Count = @($templates | Where-Object { [int]$_.SchemaVersion -ge 4 }).Count

    # Templates with authentication EKUs
    $authTemplateCount = @($templates | Where-Object {
        $_.IsPublished -and $_.AllowsAuthentication
    }).Count

    # Templates with enrollee-supplies-subject
    $sanTemplateCount = @($templates | Where-Object {
        $_.IsPublished -and $_.EnrolleeSuppliesSubject
    }).Count

    # Templates with low-privileged enrollment
    $lowPrivTemplateCount = 0
    foreach ($tmpl in $templates) {
        if (-not $tmpl.IsPublished) { continue }
        $lowPrivACEs = Get-LowPrivEnrollmentACEs -EnrollmentPermissions $tmpl.EnrollmentPermissions
        if ($lowPrivACEs.Count -gt 0) { $lowPrivTemplateCount++ }
    }

    $templateSummary = @($templates | Where-Object { $_.IsPublished } | ForEach-Object {
        @{
            Name          = $_.Name
            DisplayName   = $_.DisplayName
            SchemaVersion = $_.SchemaVersion
            EKUs          = @($_.ExtendedKeyUsage | ForEach-Object { $_.Name })
            AllowsAuth    = $_.AllowsAuthentication
            SuppliesSAN   = $_.EnrolleeSuppliesSubject
            RASignatures  = $_.RASignaturesRequired
        }
    })

    $currentValue = "$($templates.Count) certificate template(s) found: $publishedCount published, $unpublishedCount unpublished. " +
        "Schema versions: v1=$v1Count, v2=$v2Count, v3=$v3Count, v4+=$v4Count. " +
        "$authTemplateCount published template(s) allow authentication, $sanTemplateCount allow enrollee-supplied SAN, " +
        "$lowPrivTemplateCount enrollable by low-privileged users"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            TotalTemplates          = $templates.Count
            PublishedTemplates      = $publishedCount
            UnpublishedTemplates    = $unpublishedCount
            SchemaV1Count           = $v1Count
            SchemaV2Count           = $v2Count
            SchemaV3Count           = $v3Count
            SchemaV4PlusCount       = $v4Count
            AuthenticationTemplates = $authTemplateCount
            SANTemplates            = $sanTemplateCount
            LowPrivEnrollable       = $lowPrivTemplateCount
            PublishedTemplateSummary = $templateSummary
        }
}
