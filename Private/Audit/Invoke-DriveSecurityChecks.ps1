# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-DriveSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'DriveSecurityChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Fortification$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── DRIVE-001: External Sharing Defaults ──────────────────────────────────
function Test-FortificationDRIVE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Drive sharing settings are OU-level policies not fully exposed via Directory API
    # Check if OrgUnitPolicies contain Drive sharing configuration
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('OrgUnits', 'CloudIdentityPolicies') -Subject 'Drive external-sharing policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveExternalSharing) {
        $status = switch ($policy.driveExternalSharing) {
            'OFF'                { 'PASS' }
            'ALLOWLISTED_DOMAINS' { 'PASS' }
            'ON_WITH_WARNING'    { 'WARN' }
            'ON'                 { 'FAIL' }
            default              { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "External sharing policy: $($policy.driveExternalSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    # GWS-1: drive_and_docs.external_sharing { externalSharingMode=enum }. Grade WEAKEST-OU-WINS.
    # 'ALLOWED' is unrestricted external sharing (insecure) -> FAIL; restrictive values are better.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.external_sharing' -Field 'externalSharingMode')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.external_sharing policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $note = "External sharing mode: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    # Known-insecure: unrestricted external sharing.
    $insecure = @($vals | Where-Object { "$_" -match '(?i)^ALLOWED$' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Unrestricted external sharing permitted — $note" -OrgUnitPath $OrgUnitPath
    }
    # Known-restrictive values pass; anything unrecognized -> WARN (never PASS on unknown enum).
    $known = @($vals | Where-Object { "$_" -match '(?i)^(DISALLOWED|ALLOWED_WITH_WARNING|ALLOWLISTED_DOMAINS)$' })
    if ($known.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "External sharing restricted — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Unrecognized external sharing mode — verify intent — $note" -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-002: Link Sharing Default Settings ─────────────────────────────
function Test-FortificationDRIVE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Drive link-sharing policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.defaultLinkSharing) {
        $status = if ($policy.defaultLinkSharing -eq 'RESTRICTED') { 'PASS' }
                  elseif ($policy.defaultLinkSharing -eq 'DOMAIN') { 'WARN' }
                  else { 'FAIL' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Default link sharing: $($policy.defaultLinkSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Default link sharing setting not available via API. Verify in Admin Console that default is set to Restricted (specific people)' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'OU-level Drive link sharing defaults require manual verification in Admin Console' }
}

# ── DRIVE-003: Anyone With the Link Sharing Audit ────────────────────────
function Test-FortificationDRIVE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Drive anyone-with-link policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.anyoneWithLinkEnabled) {
        $status = if ($policy.anyoneWithLinkEnabled -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.anyoneWithLinkEnabled) {
            "'Anyone with the link' sharing is enabled - files can be exposed to the internet"
        } else {
            "'Anyone with the link' sharing is disabled"
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Verify in Admin Console that 'Anyone with the link' sharing is disabled or restricted to 'Domain users with the link'" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'This setting controls whether users can create public links accessible by anyone on the internet' }
}

# ── DRIVE-004: Shared Drive Creation Restrictions ────────────────────────
function Test-FortificationDRIVE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: drive_and_docs.shared_drive_creation { allowSharedDriveCreation=bool }.
    # Insecure (weaker) when shared-drive creation is unrestricted anywhere. Weakest-OU-wins.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.shared_drive_creation' -Field 'allowSharedDriveCreation')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.shared_drive_creation policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $allowed = @($vals | Where-Object { $_ -eq $true })
    if ($allowed.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Shared Drive creation unrestricted in $($allowed.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Shared Drive creation restricted' -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-005: Shared Drive Member Management ────────────────────────────
function Test-FortificationDRIVE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive member management settings not available via API. Verify in Admin Console that only managers can add members and change access levels' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Shared Drive member management policies are OU-level settings requiring manual verification' }
}

# ── DRIVE-006: Shared Drive External Sharing ─────────────────────────────
function Test-FortificationDRIVE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Shared Drive external-sharing policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.sharedDriveExternalSharing) {
        $status = if ($policy.sharedDriveExternalSharing -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.sharedDriveExternalSharing) {
            'External sharing on Shared Drives is enabled'
        } else {
            'External sharing on Shared Drives is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive external sharing settings not available via API. Verify in Admin Console > Apps > Drive > Sharing settings > Shared drive sharing' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Shared Drive external sharing is an OU-level policy requiring manual verification' }
}

# ── DRIVE-007: File Ownership Transfer Settings ──────────────────────────
function Test-FortificationDRIVE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'File ownership transfer settings not available via API. Verify in Admin Console that ownership transfer is restricted appropriately' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Ownership transfer policies are OU-level settings requiring manual verification' }
}

# ── DRIVE-008: Drive for Desktop Allowed/Blocked ─────────────────────────
function Test-FortificationDRIVE008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('OrgUnits', 'CloudIdentityPolicies') -Subject 'Drive for Desktop policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveForDesktopEnabled) {
        $status = if ($policy.driveForDesktopEnabled -eq $false) { 'PASS' }
                  else { 'WARN' }
        $currentValue = if ($policy.driveForDesktopEnabled) {
            'Drive for Desktop is enabled - files may be synced to local devices'
        } else {
            'Drive for Desktop is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    # GWS-1: drive_and_docs.drive_for_desktop { allowDriveForDesktop=bool; restrictToAuthorizedDevices=bool }.
    # Enabled allows local file sync; weaker when unrestricted to authorized devices. Weakest-OU-wins.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $allowVals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.drive_for_desktop' -Field 'allowDriveForDesktop')
    if ($allowVals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No drive_and_docs.drive_for_desktop policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $restrictVals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'drive_and_docs.drive_for_desktop' -Field 'restrictToAuthorizedDevices')
    $enabled = @($allowVals | Where-Object { $_ -eq $true })
    if ($enabled.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Drive for Desktop is disabled' -OrgUnitPath $OrgUnitPath
    }
    # Enabled somewhere. If every targeted policy restricts to authorized devices, that's the safer posture.
    $restrictedAll = ($restrictVals.Count -gt 0 -and @($restrictVals | Where-Object { $_ -ne $true }).Count -eq 0)
    if ($restrictedAll) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Drive for Desktop enabled but restricted to authorized devices ($($enabled.Count) of $($allowVals.Count) targeted policies)" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Drive for Desktop enabled without authorized-device restriction in $($enabled.Count) of $($allowVals.Count) targeted policy/policies — files may sync to unmanaged devices" `
        -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-009: Third-Party App Drive Access ──────────────────────────────
function Test-FortificationDRIVE009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth app inventory'
    if ($na) { return $na }

    # Check OAuthApps for apps with Drive scopes
    if ($AuditData.OAuthApps) {
        $driveScopes = @('drive', 'drive.file', 'drive.readonly', 'drive.metadata')
        $driveApps = [System.Collections.Generic.List[string]]::new()

        foreach ($event in $AuditData.OAuthApps) {
            $appName = $event.Params.app_name
            $scope = $event.Params.scope
            if ($scope) {
                foreach ($ds in $driveScopes) {
                    if ($scope -match $ds) {
                        if ($appName -and -not $driveApps.Contains($appName)) {
                            $driveApps.Add($appName)
                        }
                        break
                    }
                }
            }
        }

        if ($driveApps.Count -gt 0) {
            $status = if ($driveApps.Count -gt 10) { 'FAIL' }
                      elseif ($driveApps.Count -gt 5) { 'WARN' }
                      else { 'PASS' }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
                -CurrentValue "$($driveApps.Count) third-party app(s) have Drive access" `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ AppsWithDriveAccess = @($driveApps) }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No third-party apps with Drive access detected' `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'OAuth app data not available. Verify third-party app Drive access in Admin Console > Security > API controls' `
        -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-010: Drive DLP Rules Audit ─────────────────────────────────────
function Test-FortificationDRIVE010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: rule.dlp value objects { state=enum(ACTIVE/INACTIVE), action={ gmailAction|driveAction|alertCenterAction } }.
    # PASS if >= 1 ACTIVE rule whose action object is Drive-scoped (has a driveAction); WARN if none.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'rule.dlp')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No rule.dlp policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    # Count ACTIVE rules whose action object is Drive-scoped (anchored state match; action must have a driveAction).
    $activeDrive = @($vals | Where-Object {
        ($_.state -eq 'ACTIVE') -and
        $_.action -and
        ($_.action.PSObject.Properties.Name -contains 'driveAction')
    })
    if ($activeDrive.Count -ge 1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "$($activeDrive.Count) active Drive DLP rule(s) configured (of $($vals.Count) DLP rule(s))" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "No active Drive-scoped DLP rule found ($($vals.Count) DLP rule(s) present). Configure a Drive DLP rule in Admin Console > Security > Data protection > Manage rules" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'DLP rules should cover sensitive data types including PII, financial data, and health records' }
}

# ── DRIVE-011: Target Audience Settings ──────────────────────────────────
function Test-FortificationDRIVE011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Target audience settings not available via API. Verify in Admin Console > Directory > Target audiences that sharing suggestions are properly scoped' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Target audiences control suggested recipients when sharing files and should be configured to prevent accidental broad sharing' }
}

# ── DRIVE-012: Drive Add-ons Settings ────────────────────────────────────
function Test-FortificationDRIVE012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Drive add-ons settings not available via API. Verify in Admin Console > Apps > Drive > Add-ons that installation is restricted to approved add-ons' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Uncontrolled Drive add-ons can access file content and metadata' }
}

# ── DRIVE-013: Offline Access Settings ───────────────────────────────────
function Test-FortificationDRIVE013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'Drive offline-access policy'
    if ($na) { return $na }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveOfflineEnabled) {
        $status = if ($policy.driveOfflineEnabled -eq $false) { 'PASS' }
                  else { 'WARN' }
        $currentValue = if ($policy.driveOfflineEnabled) {
            'Offline access is enabled - files may be cached on local devices'
        } else {
            'Offline access is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Offline access setting not available via API. Verify in Admin Console > Apps > Drive > Features and Applications > Offline that offline access is controlled' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Offline access caches files locally and should be disabled on shared or unmanaged devices' }
}

# ── DRIVE-014: GWS.DRIVEDOCS.4.1 — Drive SDK API access disabled ───────────
function Test-FortificationDRIVE014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.drive_sdk' -Field 'enableDriveSdkApiAccess' -SecureValue $false -Status 'FAIL' `
        -BadMsg 'Drive SDK API access is enabled (third-party API read/write to Drive)' -GoodMsg 'Drive SDK API access is disabled'
}

# ── DRIVE-015: GWS.DRIVEDOCS.1.9 — External-file sharing warning enabled ───
function Test-FortificationDRIVE015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.external_file_warning' -Field 'highlightingEnabled' -SecureValue $true -Status 'WARN' `
        -BadMsg 'External-file sharing warning is off' -GoodMsg 'External-file sharing warning is on'
}

# ── DRIVE-016: GWS.DRIVEDOCS.3.1 — File security update enforced ───────────
function Test-FortificationDRIVE016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.file_security_update' -Field 'allowUsersToManageUpdate' -SecureValue $false -Status 'WARN' `
        -BadMsg 'Users are allowed to remove the file security update' -GoodMsg 'Users cannot remove the file security update'
}

# ── DRIVE-017: Default file access set to private to owner (GWS.DRIVEDOCS.1.8) ──
function Test-FortificationDRIVE017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyEnum -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'drive_and_docs.general_access_default' -Field 'defaultFileAccess' -CompliantValues @('PRIVATE_TO_OWNER') -Status 'FAIL' `
        -BadMsg 'Default file access is not private to owner' -GoodMsg 'Default file access is private to owner'
}
