# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
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

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Enhanced pre-delivery message scanning requires manual verification. Verify in Admin Console > Apps > Gmail > Spam, phishing and malware' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Pre-delivery scanning is an OU-level policy not fully available via API' }
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

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Attachment safety settings require manual verification. Verify in Admin Console > Apps > Gmail > Safety > Attachments' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Attachment safety configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-016: Links and External Images Protection ───────────────────────────
function Test-FortificationEMAIL016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Links and external images protection requires manual verification. Verify in Admin Console > Apps > Gmail > Safety > Links and external images' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Link/image protection configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-017: Spoofing and Authentication Protection ─────────────────────────
function Test-FortificationEMAIL017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Spoofing and authentication protection requires manual verification. Verify in Admin Console > Apps > Gmail > Safety > Spoofing and authentication' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Spoofing protection configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-018: Compliance Rules Audit ─────────────────────────────────────────
function Test-FortificationEMAIL018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Content compliance rules require manual review. Verify in Admin Console > Apps > Gmail > Compliance > Content compliance' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Content compliance configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-019: DLP Rules Configuration ────────────────────────────────────────
function Test-FortificationEMAIL019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'DLP rules configuration requires manual review. Verify in Admin Console > Security > Data protection > Manage rules' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'DLP rule configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-020: Gmail Confidential Mode ────────────────────────────────────────
function Test-FortificationEMAIL020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Gmail confidential mode settings require manual verification. Verify in Admin Console > Apps > Gmail > End User Access' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Confidential mode configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-021: S/MIME Settings ────────────────────────────────────────────────
function Test-FortificationEMAIL021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'S/MIME settings require manual verification. Verify in Admin Console > Apps > Gmail > End User Access > S/MIME' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'S/MIME configuration is an OU-level policy not fully available via API' }
}

# ── EMAIL-022: Mail Forwarding Rule Enumeration ───────────────────────────────
function Test-FortificationEMAIL022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

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
