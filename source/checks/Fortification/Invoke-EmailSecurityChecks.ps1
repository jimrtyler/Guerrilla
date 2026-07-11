# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
# Returns a qualifier for a sampled Gmail-settings PASS so a clean result on a SUBSET of
# mailboxes can't read as full coverage — auto-forwarding/exfil typically hides in a
# single compromised mailbox that a partial sample would miss. Empty string when the
# sample covered every active mailbox.
function Get-GmailSampleNote {
    [CmdletBinding()]
    param([hashtable]$AuditData, [int]$CheckedCount)

    $activeTotal = @($AuditData.Users | Where-Object { -not $_.suspended }).Count
    if ($activeTotal -gt $CheckedCount) {
        return " — SAMPLED $CheckedCount of $activeTotal active mailboxes; a compromised mailbox outside the sample would not be caught (raise -UserSampleSize for full coverage)"
    }
    return ''
}

function Invoke-EmailSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EmailSecurityChecks'
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

# ── EMAIL-001: SPF Record Validation ──────────────────────────────────────────
function Test-FortificationEMAIL001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'DnsRecords:' -Subject 'DNS records'
    if ($na) { return $na }

    if (-not $AuditData.DnsRecords -or $AuditData.DnsRecords.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DNS records available for analysis' -OrgUnitPath $OrgUnitPath
    }

    $failedDomains = [System.Collections.Generic.List[string]]::new()
    $warnDomains = [System.Collections.Generic.List[string]]::new()
    $passedDomains = [System.Collections.Generic.List[string]]::new()

    foreach ($domainName in $AuditData.DnsRecords.Keys) {
        $dns = $AuditData.DnsRecords[$domainName]
        if ($dns.SPF.Valid -eq $true) {
            # Check for weak qualifiers
            if ($dns.SPF.Record -match '\+all') {
                $failedDomains.Add("$domainName (+all permits any sender)")
            } elseif ($dns.SPF.Record -match '\?all') {
                $warnDomains.Add("$domainName (?all neutral policy)")
            } else {
                $passedDomains.Add($domainName)
            }
        } else {
            $detail = if ($dns.SPF.Details) { " ($($dns.SPF.Details))" } else { '' }
            $failedDomains.Add("$domainName$detail")
        }
    }

    $totalDomains = $AuditData.DnsRecords.Count
    $status = if ($failedDomains.Count -gt 0) { 'FAIL' }
              elseif ($warnDomains.Count -gt 0) { 'WARN' }
              else { 'PASS' }

    $currentValue = "$($passedDomains.Count) of $totalDomains domain(s) have valid SPF records"
    if ($failedDomains.Count -gt 0) {
        $currentValue += "; $($failedDomains.Count) failed"
    }
    if ($warnDomains.Count -gt 0) {
        $currentValue += "; $($warnDomains.Count) with warnings"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            PassedDomains = @($passedDomains)
            FailedDomains = @($failedDomains)
            WarnDomains   = @($warnDomains)
            TotalDomains  = $totalDomains
        }
}

# ── EMAIL-002: DKIM Signing Enabled ───────────────────────────────────────────
function Test-FortificationEMAIL002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'DnsRecords:' -Subject 'DNS records'
    if ($na) { return $na }

    if (-not $AuditData.DnsRecords -or $AuditData.DnsRecords.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DNS records available for analysis' -OrgUnitPath $OrgUnitPath
    }

    $failedDomains = [System.Collections.Generic.List[string]]::new()
    $passedDomains = [System.Collections.Generic.List[string]]::new()

    foreach ($domainName in $AuditData.DnsRecords.Keys) {
        $dns = $AuditData.DnsRecords[$domainName]
        if ($dns.DKIM.Valid -eq $true) {
            $passedDomains.Add($domainName)
        } else {
            $detail = if ($dns.DKIM.Details) { " ($($dns.DKIM.Details))" } else { '' }
            $failedDomains.Add("$domainName$detail")
        }
    }

    $totalDomains = $AuditData.DnsRecords.Count
    $status = if ($failedDomains.Count -gt 0) { 'FAIL' } else { 'PASS' }

    $currentValue = "$($passedDomains.Count) of $totalDomains domain(s) have valid DKIM records"
    if ($failedDomains.Count -gt 0) {
        $currentValue += "; $($failedDomains.Count) missing or invalid"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            PassedDomains = @($passedDomains)
            FailedDomains = @($failedDomains)
            TotalDomains  = $totalDomains
        }
}

# ── EMAIL-003: DMARC Policy Audit ─────────────────────────────────────────────
function Test-FortificationEMAIL003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'DnsRecords:' -Subject 'DNS records'
    if ($na) { return $na }

    if (-not $AuditData.DnsRecords -or $AuditData.DnsRecords.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DNS records available for analysis' -OrgUnitPath $OrgUnitPath
    }

    $failedDomains = [System.Collections.Generic.List[string]]::new()
    $warnDomains = [System.Collections.Generic.List[string]]::new()
    $passedDomains = [System.Collections.Generic.List[string]]::new()

    foreach ($domainName in $AuditData.DnsRecords.Keys) {
        $dns = $AuditData.DnsRecords[$domainName]
        if ($dns.DMARC.Valid -eq $true) {
            switch ($dns.DMARC.Policy) {
                'reject'     { $passedDomains.Add($domainName) }
                'quarantine' { $passedDomains.Add("$domainName (quarantine)") }
                'none'       { $warnDomains.Add("$domainName (policy=none, monitoring only)") }
                default      { $warnDomains.Add("$domainName (unknown policy)") }
            }
        } else {
            $detail = if ($dns.DMARC.Details) { " ($($dns.DMARC.Details))" } else { '' }
            $failedDomains.Add("$domainName$detail")
        }
    }

    $totalDomains = $AuditData.DnsRecords.Count
    $status = if ($failedDomains.Count -gt 0) { 'FAIL' }
              elseif ($warnDomains.Count -gt 0) { 'WARN' }
              else { 'PASS' }

    $currentValue = "$($passedDomains.Count) of $totalDomains domain(s) have enforcing DMARC policy"
    if ($failedDomains.Count -gt 0) {
        $currentValue += "; $($failedDomains.Count) missing DMARC"
    }
    if ($warnDomains.Count -gt 0) {
        $currentValue += "; $($warnDomains.Count) with non-enforcing policy"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            PassedDomains = @($passedDomains)
            FailedDomains = @($failedDomains)
            WarnDomains   = @($warnDomains)
            TotalDomains  = $totalDomains
        }
}

# ── EMAIL-004: MTA-STS Policy ─────────────────────────────────────────────────
function Test-FortificationEMAIL004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'DnsRecords:' -Subject 'DNS records'
    if ($na) { return $na }

    if (-not $AuditData.DnsRecords -or $AuditData.DnsRecords.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DNS records available for analysis' -OrgUnitPath $OrgUnitPath
    }

    $failedDomains = [System.Collections.Generic.List[string]]::new()
    $passedDomains = [System.Collections.Generic.List[string]]::new()

    foreach ($domainName in $AuditData.DnsRecords.Keys) {
        $dns = $AuditData.DnsRecords[$domainName]
        if ($dns.MTASTS.Valid -eq $true) {
            $passedDomains.Add($domainName)
        } else {
            $detail = if ($dns.MTASTS.Details) { " ($($dns.MTASTS.Details))" } else { '' }
            $failedDomains.Add("$domainName$detail")
        }
    }

    $totalDomains = $AuditData.DnsRecords.Count
    $status = if ($failedDomains.Count -gt 0) { 'WARN' } else { 'PASS' }

    $currentValue = "$($passedDomains.Count) of $totalDomains domain(s) have MTA-STS configured"
    if ($failedDomains.Count -gt 0) {
        $currentValue += "; $($failedDomains.Count) without MTA-STS"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            PassedDomains = @($passedDomains)
            FailedDomains = @($failedDomains)
            TotalDomains  = $totalDomains
        }
}

# ── EMAIL-005: TLS Enforcement ────────────────────────────────────────────────
function Test-FortificationEMAIL005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'TLS enforcement settings require manual verification. Verify in Admin Console > Apps > Gmail > Compliance > Secure transport (TLS) compliance' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'TLS compliance settings are OU-level policies not fully available via API' }
}

# ── EMAIL-006: Email Allowlist/Blocklist Review ───────────────────────────────
function Test-FortificationEMAIL006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Email allowlist and blocklist entries require manual review. Verify in Admin Console > Apps > Gmail > Spam, phishing and malware' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Allowlist/blocklist configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-007: Inbound Gateway Configuration ─────────────────────────────────
function Test-FortificationEMAIL007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Inbound gateway configuration requires manual verification. Verify in Admin Console > Apps > Gmail > Spam, phishing and malware > Inbound gateway' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Inbound gateway settings are OU-level policies not fully available via API' }
}

# ── EMAIL-008: Email Routing Rules Audit ──────────────────────────────────────
function Test-FortificationEMAIL008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Email routing rules require manual review. Verify in Admin Console > Apps > Gmail > Routing for unauthorized or suspicious entries' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Routing rule configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-009: Auto-Forwarding Policy ─────────────────────────────────────────
function Test-FortificationEMAIL009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'GmailSettings:' -Subject 'per-mailbox Gmail settings'
    if ($na) { return $na }

    if (-not $AuditData.GmailSettings -or $AuditData.GmailSettings.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Gmail settings data available' -OrgUnitPath $OrgUnitPath
    }

    $usersWithForwarding = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalUsers = 0

    foreach ($userEmail in $AuditData.GmailSettings.Keys) {
        $settings = $AuditData.GmailSettings[$userEmail]
        $totalUsers++

        if ($settings.autoForwarding -and $settings.autoForwarding.enabled -eq $true) {
            $usersWithForwarding.Add([PSCustomObject]@{
                User             = $userEmail
                ForwardingAddress = $settings.autoForwarding.emailAddress
            })
        }
    }

    if ($usersWithForwarding.Count -gt 0) {
        $forwardingDetails = @($usersWithForwarding | ForEach-Object {
            "$($_.User) -> $($_.ForwardingAddress)"
        })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($usersWithForwarding.Count) of $totalUsers user(s) have auto-forwarding enabled" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                UsersWithForwarding = $forwardingDetails
                TotalUsersChecked   = $totalUsers
            }
    }

    $sampleNote = Get-GmailSampleNote -AuditData $AuditData -CheckedCount $totalUsers
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No users have auto-forwarding enabled ($totalUsers users checked)$sampleNote" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalUsersChecked = $totalUsers }
}

# ── EMAIL-010: Delegate Access Settings ───────────────────────────────────────
function Test-FortificationEMAIL010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'GmailSettings:' -Subject 'per-mailbox Gmail settings'
    if ($na) { return $na }

    if (-not $AuditData.GmailSettings -or $AuditData.GmailSettings.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Gmail settings data available' -OrgUnitPath $OrgUnitPath
    }

    $usersWithDelegates = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalUsers = 0

    foreach ($userEmail in $AuditData.GmailSettings.Keys) {
        $settings = $AuditData.GmailSettings[$userEmail]
        $totalUsers++

        # Check for sendAs aliases that are not the user's own address
        if ($settings.sendAs) {
            $aliases = @($settings.sendAs | Where-Object {
                $_.sendAsEmail -and $_.sendAsEmail -ne $userEmail
            })
            if ($aliases.Count -gt 0) {
                $aliasAddresses = @($aliases | ForEach-Object { $_.sendAsEmail })
                $usersWithDelegates.Add([PSCustomObject]@{
                    User    = $userEmail
                    Aliases = $aliasAddresses
                })
            }
        }
    }

    if ($usersWithDelegates.Count -gt 0) {
        $delegateDetails = @($usersWithDelegates | ForEach-Object {
            "$($_.User): $($_.Aliases -join ', ')"
        })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($usersWithDelegates.Count) of $totalUsers user(s) have send-as aliases configured. Review for unauthorized delegates" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                UsersWithDelegates = $delegateDetails
                TotalUsersChecked  = $totalUsers
            }
    }

    $sampleNote = Get-GmailSampleNote -AuditData $AuditData -CheckedCount $totalUsers
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No send-as aliases found ($totalUsers users checked)$sampleNote" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalUsersChecked = $totalUsers }
}

# ── EMAIL-011: POP/IMAP Access Settings ───────────────────────────────────────
function Test-FortificationEMAIL011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'GmailSettings:' -Subject 'per-mailbox Gmail settings'
    if ($na) { return $na }

    if (-not $AuditData.GmailSettings -or $AuditData.GmailSettings.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Gmail settings data available' -OrgUnitPath $OrgUnitPath
    }

    $usersWithImap = [System.Collections.Generic.List[string]]::new()
    $usersWithPop = [System.Collections.Generic.List[string]]::new()
    $totalUsers = 0

    foreach ($userEmail in $AuditData.GmailSettings.Keys) {
        $settings = $AuditData.GmailSettings[$userEmail]
        $totalUsers++

        if ($settings.imap -and $settings.imap.enabled -eq $true) {
            $usersWithImap.Add($userEmail)
        }

        if ($settings.pop -and $settings.pop.accessWindow -and $settings.pop.accessWindow -ne 'disabled') {
            $usersWithPop.Add($userEmail)
        }
    }

    $totalLegacy = $usersWithImap.Count + $usersWithPop.Count
    if ($totalLegacy -gt 0) {
        $currentValue = ''
        if ($usersWithImap.Count -gt 0) {
            $currentValue += "$($usersWithImap.Count) user(s) with IMAP enabled"
        }
        if ($usersWithPop.Count -gt 0) {
            if ($currentValue) { $currentValue += '; ' }
            $currentValue += "$($usersWithPop.Count) user(s) with POP enabled"
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
            -Details @{
                UsersWithIMAP     = @($usersWithImap)
                UsersWithPOP      = @($usersWithPop)
                TotalUsersChecked = $totalUsers
            }
    }

    $sampleNote = Get-GmailSampleNote -AuditData $AuditData -CheckedCount $totalUsers
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "POP and IMAP disabled for all $totalUsers user(s) checked$sampleNote" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalUsersChecked = $totalUsers }
}

# ── EMAIL-012: Spam and Phishing Filter Settings ──────────────────────────────
function Test-FortificationEMAIL012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Spam and phishing filter settings require manual verification. Verify in Admin Console > Apps > Gmail > Spam, phishing and malware' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Spam/phishing filter configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-013: Enhanced Pre-Delivery Message Scanning ─────────────────────────
function Test-FortificationEMAIL013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.enhanced_pre_delivery_message_scanning { enableImprovedSuspiciousContentDetection=bool }.
    # Secure when enabled — weakest-OU-wins: FAIL if any targeted OU has it disabled.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'gmail.enhanced_pre_delivery_message_scanning' -Field 'enableImprovedSuspiciousContentDetection')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.enhanced_pre_delivery_message_scanning policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $disabled = @($vals | Where-Object { $_ -ne $true })
    if ($disabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Enhanced pre-delivery message scanning disabled in $($disabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Enhanced pre-delivery message scanning enabled ($($vals.Count) targeted policy/policies)" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-014: External Recipient Warning ─────────────────────────────────────
function Test-FortificationEMAIL014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'External recipient warning setting requires manual verification. Verify in Admin Console > Apps > Gmail > End User Access' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External recipient warning is an OU-level policy not fully available via API' }
}

# ── EMAIL-015: Attachment Safety Settings ─────────────────────────────────────
function Test-FortificationEMAIL015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.email_attachment_safety { applyFutureRecommendedSettingsAutomatically=bool }.
    # Secure when enabled (auto-applies Google's future recommended attachment protections) —
    # WARN (not FAIL) if any OU has it off, since the individual attachment controls may still be
    # configured manually; we only see the future-auto-apply toggle via this policy type.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'gmail.email_attachment_safety' -Field 'applyFutureRecommendedSettingsAutomatically')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.email_attachment_safety policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $disabled = @($vals | Where-Object { $_ -ne $true })
    if ($disabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Auto-apply of future recommended attachment-safety settings is off in $($disabled.Count) of $($vals.Count) targeted policy/policies — review individual attachment protections in Admin Console" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Future recommended attachment-safety settings auto-applied ($($vals.Count) targeted policy/policies)" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-016: Links and External Images Protection ───────────────────────────
function Test-FortificationEMAIL016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.links_and_external_images { enableShortenerScanning=bool; enableExternalImageScanning=bool }.
    # Secure when BOTH are true — weakest-OU-wins: FAIL if any OU has either protection off.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $shortener = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.links_and_external_images' -Field 'enableShortenerScanning')
    $images    = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.links_and_external_images' -Field 'enableExternalImageScanning')
    if ($shortener.Count -eq 0 -and $images.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.links_and_external_images policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $shortenerOff = @($shortener | Where-Object { $_ -ne $true })
    $imagesOff    = @($images | Where-Object { $_ -ne $true })
    $total = [Math]::Max($shortener.Count, $images.Count)
    if ($shortenerOff.Count -gt 0 -or $imagesOff.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Link/image protection incomplete (shortener scanning off in $($shortenerOff.Count), external-image scanning off in $($imagesOff.Count) of $total targeted policy/policies)" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Link shortener and external-image scanning both enabled ($total targeted policy/policies)" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-017: Spoofing and Authentication Protection ─────────────────────────
function Test-FortificationEMAIL017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.spoofing_and_authentication { detectDomainNameSpoofing=bool;
    # detectEmployeeNameSpoofing=bool; detectUnauthenticatedEmails=bool }. Secure when all true —
    # weakest-OU-wins: FAIL if any OU has any of the three protections off.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $domain = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.spoofing_and_authentication' -Field 'detectDomainNameSpoofing')
    $employee = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.spoofing_and_authentication' -Field 'detectEmployeeNameSpoofing')
    $unauth = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.spoofing_and_authentication' -Field 'detectUnauthenticatedEmails')
    if ($domain.Count -eq 0 -and $employee.Count -eq 0 -and $unauth.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.spoofing_and_authentication policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $domainOff = @($domain | Where-Object { $_ -ne $true })
    $employeeOff = @($employee | Where-Object { $_ -ne $true })
    $unauthOff = @($unauth | Where-Object { $_ -ne $true })
    $total = (@($domain.Count, $employee.Count, $unauth.Count) | Measure-Object -Maximum).Maximum
    if ($domainOff.Count -gt 0 -or $employeeOff.Count -gt 0 -or $unauthOff.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Spoofing/authentication protection incomplete (domain-spoof off in $($domainOff.Count), employee-spoof off in $($employeeOff.Count), unauthenticated-email off in $($unauthOff.Count) of $total targeted policy/policies)" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Domain-spoof, employee-spoof, and unauthenticated-email protections all enabled ($total targeted policy/policies)" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-018: Compliance Rules Audit ─────────────────────────────────────────
function Test-FortificationEMAIL018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.content_compliance { contentComplianceRules=[ rule, ... ] }. This is a
    # "control present?" check, not insecure-if-present: count configured content-compliance
    # rules across all returned policies. PASS if at least one rule exists; WARN if none.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.content_compliance')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.content_compliance policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $ruleCount = 0
    foreach ($v in $vals) {
        if ($v.PSObject.Properties.Name -contains 'contentComplianceRules') {
            $ruleCount += @($v.contentComplianceRules).Count
        }
    }
    if ($ruleCount -lt 1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No content compliance rules configured — verify in Admin Console > Apps > Gmail > Compliance > Content compliance' `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$ruleCount content compliance rule(s) configured across $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-019: DLP Rules Configuration ────────────────────────────────────────
function Test-FortificationEMAIL019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: rule.dlp value objects { state=ACTIVE|INACTIVE; action={ gmailAction?; driveAction?;
    # alertCenterAction? } }. Count rules that are ACTIVE (anchored — INACTIVE must not count) AND
    # Gmail-scoped (action has a gmailAction). PASS if at least one active Gmail DLP rule; WARN if none.
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
    $activeGmail = 0
    foreach ($v in $vals) {
        $props = $v.PSObject.Properties.Name
        if (($props -notcontains 'state') -or ($v.state -ne 'ACTIVE')) { continue }
        if ($props -notcontains 'action') { continue }
        $action = $v.action
        if ($null -ne $action -and ($action.PSObject.Properties.Name -contains 'gmailAction')) {
            $activeGmail++
        }
    }
    if ($activeGmail -lt 1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No active Gmail DLP rules configured — verify in Admin Console > Security > Data protection > Manage rules' `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$activeGmail active Gmail DLP rule(s) configured across $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-020: Gmail Confidential Mode ────────────────────────────────────────
function Test-FortificationEMAIL020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.confidential_mode { enableConfidentialMode=bool }. No single "secure"
    # direction — confidential mode is a legitimate DLP control but also a potential exfil
    # vector (Google-hosted message wrapper, expiry). Report state; WARN when enabled so an
    # auditor reviews who can use it, PASS when disabled. (Mirrors IMAP/POP "WARN if on".)
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.confidential_mode' -Field 'enableConfidentialMode')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.confidential_mode policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Gmail confidential mode enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies — confirm it aligns with your data-handling policy" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Gmail confidential mode disabled ($($vals.Count) targeted policy/policies)" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-021: S/MIME Settings ────────────────────────────────────────────────
function Test-FortificationEMAIL021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: gmail.enhanced_smime_encryption { allowUserToUploadCertificates=bool }. Letting
    # end users upload their own S/MIME certs is a weaker posture than admin-managed certs, so
    # WARN when allowed (legitimate in some orgs); PASS when restricted to admin-managed.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.enhanced_smime_encryption' -Field 'allowUserToUploadCertificates')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.enhanced_smime_encryption policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $userUpload = @($vals | Where-Object { $_ -eq $true })
    if ($userUpload.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Users may upload their own S/MIME certificates in $($userUpload.Count) of $($vals.Count) targeted policy/policies — prefer admin-managed certificates" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "S/MIME certificates are admin-managed (user upload disabled) across $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-022: Mail Forwarding Rule Enumeration ───────────────────────────────
function Test-FortificationEMAIL022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKeyPrefix 'GmailSettings:' -Subject 'per-mailbox Gmail settings'
    if ($na) { return $na }

    if (-not $AuditData.GmailSettings -or $AuditData.GmailSettings.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No Gmail settings data available' -OrgUnitPath $OrgUnitPath
    }

    $allForwardingRules = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalUsers = 0

    foreach ($userEmail in $AuditData.GmailSettings.Keys) {
        $settings = $AuditData.GmailSettings[$userEmail]
        $totalUsers++

        # Check auto-forwarding
        if ($settings.autoForwarding -and $settings.autoForwarding.enabled -eq $true) {
            $allForwardingRules.Add([PSCustomObject]@{
                User              = $userEmail
                Type              = 'AutoForwarding'
                ForwardingAddress = $settings.autoForwarding.emailAddress
            })
        }

        # Check filters with forwarding actions
        if ($settings.filters) {
            foreach ($filter in $settings.filters) {
                if ($filter.action -and $filter.action.forward) {
                    $allForwardingRules.Add([PSCustomObject]@{
                        User              = $userEmail
                        Type              = 'FilterForwarding'
                        ForwardingAddress = $filter.action.forward
                    })
                }
            }
        }

        # Check sendAs aliases with replyTo pointing externally
        if ($settings.sendAs) {
            foreach ($alias in $settings.sendAs) {
                if ($alias.sendAsEmail -and $alias.sendAsEmail -ne $userEmail) {
                    $allForwardingRules.Add([PSCustomObject]@{
                        User              = $userEmail
                        Type              = 'SendAsAlias'
                        ForwardingAddress = $alias.sendAsEmail
                    })
                }
            }
        }

        # Check forwarding addresses (registered but may not be active)
        if ($settings.forwardingAddresses) {
            foreach ($fwd in $settings.forwardingAddresses) {
                if ($fwd.forwardingEmail) {
                    $allForwardingRules.Add([PSCustomObject]@{
                        User              = $userEmail
                        Type              = 'RegisteredForwarding'
                        ForwardingAddress = $fwd.forwardingEmail
                    })
                }
            }
        }
    }

    if ($allForwardingRules.Count -gt 0) {
        $ruleDetails = @($allForwardingRules | ForEach-Object {
            "$($_.User) [$($_.Type)] -> $($_.ForwardingAddress)"
        })

        $autoCount = @($allForwardingRules | Where-Object { $_.Type -eq 'AutoForwarding' }).Count
        $filterCount = @($allForwardingRules | Where-Object { $_.Type -eq 'FilterForwarding' }).Count
        $aliasCount = @($allForwardingRules | Where-Object { $_.Type -eq 'SendAsAlias' }).Count
        $registeredCount = @($allForwardingRules | Where-Object { $_.Type -eq 'RegisteredForwarding' }).Count

        $summary = "$($allForwardingRules.Count) forwarding rule(s) found across $totalUsers user(s)"
        $breakdown = @()
        if ($autoCount -gt 0) { $breakdown += "$autoCount auto-forwarding" }
        if ($filterCount -gt 0) { $breakdown += "$filterCount filter-based" }
        if ($aliasCount -gt 0) { $breakdown += "$aliasCount send-as aliases" }
        if ($registeredCount -gt 0) { $breakdown += "$registeredCount registered addresses" }
        if ($breakdown.Count -gt 0) { $summary += " ($($breakdown -join '; '))" }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $summary -OrgUnitPath $OrgUnitPath `
            -Details @{
                ForwardingRules   = $ruleDetails
                AutoForwarding    = $autoCount
                FilterForwarding  = $filterCount
                SendAsAliases     = $aliasCount
                RegisteredAddresses = $registeredCount
                TotalUsersChecked = $totalUsers
            }
    }

    $sampleNote = Get-GmailSampleNote -AuditData $AuditData -CheckedCount $totalUsers
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No forwarding rules found ($totalUsers users checked)$sampleNote" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalUsersChecked = $totalUsers }
}

# ── EMAIL-023: GWS.GMAIL.12.1 — Per-user outbound gateways disabled ────────
function Test-FortificationEMAIL023 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'gmail.per_user_outbound_gateway' -Field 'allowUsersToUseExternalSmtpServers')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.per_user_outbound_gateway policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    # Secure when disabled (false). Weakest-OU-wins: FAIL if any OU allows external SMTP.
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Per-user outbound gateways (external SMTP routing) enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies — an exfiltration and spoofing path" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Per-user outbound gateways disabled in all $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-024: GWS.GMAIL.16.1 — Gmail Security Sandbox enabled ─────────────
function Test-FortificationEMAIL024 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    # Field name best-effort pending live confirmation; an unrecognized type/field
    # returns no values -> SKIP (Not Assessed), never a fabricated verdict.
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'gmail.security_sandbox' -Field 'enableVirtualExecution')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.security_sandbox policy returned for this tenant (setting may be edition-gated or the field name needs live confirmation) — Not Assessed' -OrgUnitPath $OrgUnitPath
    }
    # Secure when enabled (true). Weakest-OU-wins: FAIL if any OU has the sandbox off.
    $disabled = @($vals | Where-Object { $_ -ne $true })
    if ($disabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Security Sandbox (virtual attachment detonation) disabled in $($disabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Security Sandbox enabled in all $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# Shared single-boolean Cloud Identity policy check used by the GWS SCuBA config
# closes across Gmail/Drive/Admin. $SecureValue is the compliant boolean; any OU whose
# value differs (weakest-OU-wins) yields $Status. Absent policy => Not Assessed.
function Test-GwsPolicyBoolean {
    param(
        [hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath,
        [string]$Type, [string]$Field, [bool]$SecureValue, [string]$Status, [string]$BadMsg, [string]$GoodMsg
    )
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type $Type -Field $Field)
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "No $Type policy returned for this tenant" -OrgUnitPath $OrgUnitPath
    }
    $bad = @($vals | Where-Object { $_ -ne $SecureValue })
    if ($bad.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $Status `
            -CurrentValue "$BadMsg in $($bad.Count) of $($vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$GoodMsg in all $($vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-025: GWS.GMAIL.1.1 — Mail delegation disabled ────────────────────
function Test-FortificationEMAIL025 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'gmail.mail_delegation' -Field 'enableMailDelegation' -SecureValue $false -Status 'WARN' `
        -BadMsg 'Mail delegation is enabled' -GoodMsg 'Mail delegation is disabled'
}

# ── EMAIL-026: GWS.GMAIL.9.1 — POP and IMAP access disabled ────────────────
function Test-FortificationEMAIL026 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available' -OrgUnitPath $OrgUnitPath
    }
    $imap = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.imap_access' -Field 'enableImapAccess')
    $pop  = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.pop_access' -Field 'enablePopAccess')
    if ($imap.Count -eq 0 -and $pop.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail POP/IMAP access policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $imapOn = @($imap | Where-Object { $_ -eq $true }); $popOn = @($pop | Where-Object { $_ -eq $true })
    if ($imapOn.Count -gt 0 -or $popOn.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Legacy mail access enabled (IMAP on in $($imapOn.Count), POP on in $($popOn.Count) targeted policy/policies) — a modern-auth / MFA bypass" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'POP and IMAP access are disabled' -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-027: GWS.GMAIL.8.1 — User email/contacts import disabled ─────────
function Test-FortificationEMAIL027 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'gmail.user_email_uploads' -Field 'enableMailAndContactsImport' -SecureValue $false -Status 'WARN' `
        -BadMsg 'User email/contacts import is enabled' -GoodMsg 'User email/contacts import is disabled'
}

# ── EMAIL-028: GWS.GMAIL.10.1 — Workspace Sync for Outlook disabled ────────
function Test-FortificationEMAIL028 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'gmail.workspace_sync_for_outlook' -Field 'enableGoogleWorkspaceSyncForMicrosoftOutlook' -SecureValue $false -Status 'WARN' `
        -BadMsg 'Google Workspace Sync for Microsoft Outlook is enabled' -GoodMsg 'Google Workspace Sync for Microsoft Outlook is disabled'
}

# ── EMAIL-029: GWS.GMAIL.18.1 — Spam-override sender lists reviewed ────────
function Test-FortificationEMAIL029 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available' -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gmail.spam_override_lists' -Field 'senderDomainsFound')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No gmail.spam_override_lists policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    # senderDomainsFound truthy => approved-sender/override domains configured (spam bypass to review).
    $present = @($vals | Where-Object { $_ -eq $true })
    if ($present.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Spam-override sender lists are configured in $($present.Count) of $($vals.Count) targeted policy/policies — review that trusted-domain mail is not blanket-exempted from spam filtering" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No spam-override sender lists configured' -OrgUnitPath $OrgUnitPath
}

# ── Test-GwsPolicyEnum: shared scalar-enum policy check (mirrors Test-GwsPolicyBoolean) ──
function Test-GwsPolicyEnum {
    # Two directions, mirroring how the ScubaGoggles Rego evaluates enum settings:
    #   -CompliantValues    : PASS iff the value is IN this allow-list (bad = not in it).
    #   -NonCompliantValues : PASS iff the value is NOT IN this bad-list (bad = in it).
    # The bad-list form is required where the Rego fails on one specific value and passes
    # everything else (e.g. GWS.COMMONCONTROLS.16.2 fails only on serviceState == ENABLED);
    # an allow-list would wrongly fail an UNSPECIFIED value that the Rego passes.
    param(
        [hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath,
        [string]$Type, [string]$Field, [string[]]$CompliantValues, [string[]]$NonCompliantValues,
        [string]$Status, [string]$BadMsg, [string]$GoodMsg
    )
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type $Type -Field $Field)
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "No $Type policy returned for this tenant" -OrgUnitPath $OrgUnitPath
    }
    $bad = if ($NonCompliantValues) {
        @($vals | Where-Object { $_ -in $NonCompliantValues })
    } else {
        @($vals | Where-Object { $_ -notin $CompliantValues })
    }
    if ($bad.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $Status `
            -CurrentValue "$BadMsg in $($bad.Count) of $($vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$GoodMsg in all $($vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── EMAIL-030: Automatic email forwarding disabled (GWS.GMAIL.11.1) ──
function Test-FortificationEMAIL030 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'gmail.auto_forwarding' -Field 'enableAutoForwarding' -SecureValue $false -Status 'WARN' `
        -BadMsg 'Automatic email forwarding is enabled' -GoodMsg 'Automatic email forwarding is disabled'
}

# ── EMAIL-031: Enhanced pre-delivery message scanning enabled (GWS.GMAIL.15.1) ──
function Test-FortificationEMAIL031 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'gmail.enhanced_pre_delivery_message_scanning' -Field 'enableImprovedSuspiciousContentDetection' -SecureValue $true -Status 'FAIL' `
        -BadMsg 'Enhanced pre-delivery message scanning is not enabled' -GoodMsg 'Enhanced pre-delivery message scanning is enabled'
}
