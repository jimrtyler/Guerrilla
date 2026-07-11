# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADTrustChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADTrustChecks'
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

# ── ADTRUST-001: Trust Relationships Enumeration ─────────────────────────
function Test-ReconADTRUST001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts)
    if ($trusts.Count -eq 0 -or ($trusts.Count -eq 1 -and $null -eq $trusts[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    # Filter out null entries
    $trusts = @($trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    $inbound  = @($trusts | Where-Object { $_.TrustDirection -eq 'Inbound' }).Count
    $outbound = @($trusts | Where-Object { $_.TrustDirection -eq 'Outbound' }).Count
    $bidir    = @($trusts | Where-Object { $_.TrustDirection -eq 'Bidirectional' }).Count
    $forestTr = @($trusts | Where-Object { $_.ForestTransitive }).Count

    $trustSummary = @($trusts | ForEach-Object {
        @{
            TrustPartner   = $_.TrustPartner
            Direction      = $_.TrustDirection
            Type           = $_.TrustType
            IsTransitive   = $_.IsTransitive
            ForestTrust    = $_.ForestTransitive
            WithinForest   = $_.WithinForest
            SIDFiltering   = $_.SIDFilteringEnabled
            SelectiveAuth  = $_.SelectiveAuthentication
            IsAzureAD      = $_.IsAzureAD
            WhenCreated    = $_.WhenCreated
            WhenChanged    = $_.WhenChanged
        }
    })

    $currentValue = "$($trusts.Count) trust relationship(s) found: $bidir bidirectional, $inbound inbound, $outbound outbound"
    if ($forestTr -gt 0) {
        $currentValue += ", $forestTr forest transitive"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            TrustCount    = $trusts.Count
            Inbound       = $inbound
            Outbound      = $outbound
            Bidirectional = $bidir
            ForestTrusts  = $forestTr
            TrustSummary  = $trustSummary
        }
}

# ── ADTRUST-002: Trust Direction Analysis ─────────────────────────────────
function Test-ReconADTRUST002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    # Inbound and bidirectional trusts allow external users to authenticate into this domain
    $inboundTrusts = @($trusts | Where-Object {
        $_.TrustDirection -eq 'Inbound' -or $_.TrustDirection -eq 'Bidirectional'
    })

    if ($inboundTrusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($trusts.Count) trust(s) are outbound only - no inbound authentication paths" `
            -Details @{
                TotalTrusts       = $trusts.Count
                InboundTrustCount = 0
            }
    }

    $inboundDetails = @($inboundTrusts | ForEach-Object {
        @{
            TrustPartner = $_.TrustPartner
            Direction    = $_.TrustDirection
            Type         = $_.TrustType
            WithinForest = $_.WithinForest
            IsTransitive = $_.IsTransitive
        }
    })

    $partnerNames = @($inboundTrusts | ForEach-Object {
        "$($_.TrustPartner) ($($_.TrustDirection))"
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($inboundTrusts.Count) inbound/bidirectional trust(s) allow external authentication: $($partnerNames -join '; ')" `
        -Details @{
            InboundTrustCount   = $inboundTrusts.Count
            TotalTrusts         = $trusts.Count
            InboundTrustDetails = $inboundDetails
        }
}

# ── ADTRUST-003: Trust Transitivity Analysis ─────────────────────────────
function Test-ReconADTRUST003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    $transitiveTrusts = @($trusts | Where-Object { $_.IsTransitive -eq $true })

    if ($transitiveTrusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($trusts.Count) trust(s) are non-transitive" `
            -Details @{ TotalTrusts = $trusts.Count; TransitiveCount = 0 }
    }

    $transitiveDetails = @($transitiveTrusts | ForEach-Object {
        @{
            TrustPartner     = $_.TrustPartner
            Direction        = $_.TrustDirection
            Type             = $_.TrustType
            ForestTransitive = $_.ForestTransitive
            WithinForest     = $_.WithinForest
        }
    })

    $partnerNames = @($transitiveTrusts | ForEach-Object {
        "$($_.TrustPartner) ($($_.TrustDirection))"
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($transitiveTrusts.Count) transitive trust(s) extend authentication paths beyond direct partners: $($partnerNames -join '; ')" `
        -Details @{
            TransitiveCount        = $transitiveTrusts.Count
            TotalTrusts            = $trusts.Count
            TransitiveTrustDetails = $transitiveDetails
        }
}

# ── ADTRUST-004: SID Filtering Status ────────────────────────────────────
function Test-ReconADTRUST004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    # SID filtering should be enabled on all trusts except intra-forest trusts
    # (within-forest trusts inherently share the same security boundary)
    $externalTrusts = @($trusts | Where-Object { $_.WithinForest -ne $true })

    if ($externalTrusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'All trusts are intra-forest. SID filtering enforcement not applicable for within-forest trusts' `
            -Details @{ IntraForestOnly = $true; TotalTrusts = $trusts.Count }
    }

    $unfiltered = @($externalTrusts | Where-Object {
        $_.SIDFilteringEnabled -eq $false
    })

    if ($unfiltered.Count -gt 0) {
        $unfilteredDetails = @($unfiltered | ForEach-Object {
            @{
                TrustPartner    = $_.TrustPartner
                Direction       = $_.TrustDirection
                Type            = $_.TrustType
                SIDFiltering    = $_.SIDFilteringEnabled
                ForestTrust     = $_.ForestTransitive
                TrustAttributes = $_.TrustAttributes
            }
        })

        $partnerNames = @($unfiltered | ForEach-Object { $_.TrustPartner })

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($unfiltered.Count) external trust(s) lack SID filtering (quarantine): $($partnerNames -join ', '). Attackers in trusted domains can inject privileged SIDs" `
            -Details @{
                UnfilteredCount     = $unfiltered.Count
                TotalExternalTrusts = $externalTrusts.Count
                UnfilteredTrusts    = $unfilteredDetails
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "SID filtering enabled on all $($externalTrusts.Count) external trust(s)" `
        -Details @{ TotalExternalTrusts = $externalTrusts.Count }
}

# ── ADTRUST-005: SID History Abuse Detection ─────────────────────────────
function Test-ReconADTRUST005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    # Check external trusts where SID filtering is disabled, allowing SID history injection
    $externalTrusts = @($trusts | Where-Object { $_.WithinForest -ne $true })
    if ($externalTrusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'All trusts are intra-forest. SID history abuse via external trusts not applicable' `
            -Details @{ IntraForestOnly = $true }
    }

    $sidHistoryTrusts = @($externalTrusts | Where-Object {
        $_.SIDFilteringEnabled -eq $false
    })

    if ($sidHistoryTrusts.Count -gt 0) {
        $affectedDetails = @($sidHistoryTrusts | ForEach-Object {
            @{
                TrustPartner = $_.TrustPartner
                Direction    = $_.TrustDirection
                SIDFiltering = $_.SIDFilteringEnabled
                SIDHistory   = $_.SIDHistoryEnabled
            }
        })

        $partnerNames = @($sidHistoryTrusts | ForEach-Object { $_.TrustPartner })

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($sidHistoryTrusts.Count) external trust(s) have SID filtering disabled, allowing SID history injection: $($partnerNames -join ', ')" `
            -Details @{
                AffectedCount       = $sidHistoryTrusts.Count
                TotalExternalTrusts = $externalTrusts.Count
                AffectedTrusts      = $affectedDetails
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "SID history injection is blocked on all $($externalTrusts.Count) external trust(s) (SID filtering is active)" `
        -Details @{ TotalExternalTrusts = $externalTrusts.Count }
}

# ── ADTRUST-006: Selective Authentication Status ─────────────────────────
function Test-ReconADTRUST006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    # Selective authentication is not applicable to intra-forest trusts
    $externalTrusts = @($trusts | Where-Object { $_.WithinForest -ne $true })
    if ($externalTrusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'All trusts are intra-forest. Selective authentication is not applicable' `
            -Details @{ IntraForestOnly = $true; TotalTrusts = $trusts.Count }
    }

    $noSelectiveAuth = @($externalTrusts | Where-Object {
        $_.SelectiveAuthentication -ne $true
    })

    if ($noSelectiveAuth.Count -gt 0) {
        $affectedDetails = @($noSelectiveAuth | ForEach-Object {
            @{
                TrustPartner            = $_.TrustPartner
                Direction               = $_.TrustDirection
                Type                    = $_.TrustType
                SelectiveAuthentication = $_.SelectiveAuthentication
                ForestTrust             = $_.ForestTransitive
            }
        })

        $partnerNames = @($noSelectiveAuth | ForEach-Object { $_.TrustPartner })

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($noSelectiveAuth.Count) external trust(s) lack selective authentication: $($partnerNames -join ', '). All authenticated users from trusted domains can access any permitted resource" `
            -Details @{
                MissingSelectiveAuth = $noSelectiveAuth.Count
                TotalExternalTrusts  = $externalTrusts.Count
                AffectedTrusts       = $affectedDetails
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Selective authentication enabled on all $($externalTrusts.Count) external trust(s)" `
        -Details @{ TotalExternalTrusts = $externalTrusts.Count }
}

# ── ADTRUST-007: Azure AD Hybrid Trust Security ─────────────────────────
function Test-ReconADTRUST007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    $azureTrusts = @($trusts | Where-Object { $_.IsAzureAD -eq $true })

    if ($azureTrusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Azure AD trust relationships detected' `
            -Details @{
                AzureTrustCount = 0
                TotalTrusts     = $trusts.Count
                Note            = 'Azure AD Connect may still be present without creating a trust object. Check for AZUREADSSOACC computer account if hybrid identity is expected.'
            }
    }

    $azureDetails = @($azureTrusts | ForEach-Object {
        @{
            TrustPartner            = $_.TrustPartner
            FlatName                = $_.FlatName
            Direction               = $_.TrustDirection
            Type                    = $_.TrustType
            SelectiveAuthentication = $_.SelectiveAuthentication
            SIDFiltering            = $_.SIDFilteringEnabled
            WhenCreated             = $_.WhenCreated
            WhenChanged             = $_.WhenChanged
        }
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($azureTrusts.Count) Azure AD trust(s) detected. Verify Azure AD Connect is on a hardened Tier 0 server, PHS is preferred over PTA/federation, and cloud-only break-glass accounts are configured" `
        -Details @{
            AzureTrustCount   = $azureTrusts.Count
            AzureTrustDetails = $azureDetails
            TotalTrusts       = $trusts.Count
        }
}

# ── ADTRUST-008: Foreign Domain Trust Enumeration ────────────────────────
function Test-ReconADTRUST008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    # External trusts are those outside the forest (not within-forest, not forest-transitive)
    # Also flag MIT/realm trusts and TreatAsExternal trusts
    $foreignTrusts = @($trusts | Where-Object {
        (-not $_.WithinForest -and -not $_.ForestTransitive) -or
        $_.TreatAsExternal -eq $true -or
        $_.TrustType -eq 'MIT'
    })

    if ($foreignTrusts.Count -gt 0) {
        $trustDetails = @($foreignTrusts | ForEach-Object {
            @{
                TrustPartner            = $_.TrustPartner
                Direction               = $_.TrustDirection
                TrustType               = $_.TrustType
                IsTransitive            = $_.IsTransitive
                SIDFiltering            = $_.SIDFilteringEnabled
                SelectiveAuthentication = $_.SelectiveAuthentication
                TreatAsExternal         = $_.TreatAsExternal
                WhenCreated             = $_.WhenCreated
            }
        })

        $partnerNames = @($foreignTrusts | ForEach-Object {
            "$($_.TrustPartner) ($($_.TrustDirection), $($_.TrustType))"
        })

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($foreignTrusts.Count) foreign/external domain trust(s) detected: $($partnerNames -join '; '). Verify security agreements and review annually" `
            -Details @{
                ForeignTrustCount = $foreignTrusts.Count
                ForeignTrusts     = $trustDetails
                TotalTrusts       = $trusts.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No foreign/external domain trusts detected among $($trusts.Count) trust(s)" `
        -Details @{ TotalTrusts = $trusts.Count }
}

# ── ADTRUST-009: Orphaned Trust Detection ────────────────────────────────
function Test-ReconADTRUST009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    $now = [datetime]::UtcNow
    $staleThresholdDays = 365
    $orphanedTrusts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($trust in $trusts) {
        $isOrphaned = $false
        $reason = ''

        # Check if the trust partner name is empty or missing
        if ([string]::IsNullOrWhiteSpace($trust.TrustPartner)) {
            $isOrphaned = $true
            $reason = 'Trust partner name is empty or missing'
        }

        # Check if the trust SID is missing (may indicate the partner domain no longer exists)
        if (-not $isOrphaned -and [string]::IsNullOrWhiteSpace($trust.TrustSID)) {
            $isOrphaned = $true
            $reason = 'Trust SID is missing or unresolvable'
        }

        # Check if WhenChanged is very old (>365 days) suggesting the trust is stale
        if (-not $isOrphaned -and $trust.WhenChanged) {
            try {
                $whenChanged = if ($trust.WhenChanged -is [datetime]) {
                    $trust.WhenChanged
                } else {
                    [datetime]::Parse($trust.WhenChanged.ToString())
                }
                $daysSinceChange = ($now - $whenChanged).TotalDays
                if ($daysSinceChange -gt $staleThresholdDays) {
                    $isOrphaned = $true
                    $reason = "Trust object not modified in $([Math]::Round($daysSinceChange, 0)) days (>$staleThresholdDays days)"
                }
            } catch {
                Write-Verbose "Could not parse WhenChanged for trust $($trust.TrustPartner): $_"
            }
        }

        # Check if WhenChanged is null (no modification date available)
        if (-not $isOrphaned -and $null -eq $trust.WhenChanged) {
            $isOrphaned = $true
            $reason = 'WhenChanged attribute not available - trust age cannot be determined'
        }

        if ($isOrphaned) {
            $orphanedTrusts.Add(@{
                TrustPartner    = $trust.TrustPartner
                Direction       = $trust.TrustDirection
                TrustType       = $trust.TrustType
                TrustSID        = $trust.TrustSID
                WhenChanged     = $trust.WhenChanged
                Reason          = $reason
            })
        }
    }

    if ($orphanedTrusts.Count -gt 0) {
        $trustNames = @($orphanedTrusts | ForEach-Object {
            "$($_.TrustPartner) ($($_.Reason))"
        })

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($orphanedTrusts.Count) potentially orphaned trust(s) detected: $($trustNames -join '; ')" `
            -Details @{
                OrphanedTrustCount = $orphanedTrusts.Count
                OrphanedTrusts     = @($orphanedTrusts)
                ThresholdDays      = $staleThresholdDays
                TotalTrusts        = $trusts.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No orphaned trusts detected among $($trusts.Count) trust(s)" `
        -Details @{
            TotalTrusts   = $trusts.Count
            ThresholdDays = $staleThresholdDays
        }
}

# ── ADTRUST-010: Trust Key Age and Rotation ──────────────────────────────
function Test-ReconADTRUST010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0 }
    }

    $now = [datetime]::UtcNow
    $keyAgeThresholdDays = 180
    $staleTrustKeys = [System.Collections.Generic.List[hashtable]]::new()
    $healthyCount = 0
    $unknownCount = 0

    foreach ($trust in $trusts) {
        $whenChanged = $null

        if ($trust.WhenChanged) {
            try {
                $whenChanged = if ($trust.WhenChanged -is [datetime]) {
                    $trust.WhenChanged
                } else {
                    [datetime]::Parse($trust.WhenChanged.ToString())
                }
            } catch {
                Write-Verbose "Could not parse WhenChanged for trust $($trust.TrustPartner): $_"
            }
        }

        if ($null -eq $whenChanged) {
            $unknownCount++
            $staleTrustKeys.Add(@{
                TrustPartner    = $trust.TrustPartner
                Direction       = $trust.TrustDirection
                WhenChanged     = 'Unknown'
                DaysSinceChange = -1
            })
            continue
        }

        $daysSinceChange = ($now - $whenChanged).TotalDays
        if ($daysSinceChange -gt $keyAgeThresholdDays) {
            $staleTrustKeys.Add(@{
                TrustPartner    = $trust.TrustPartner
                Direction       = $trust.TrustDirection
                WhenChanged     = $whenChanged.ToString('yyyy-MM-dd')
                DaysSinceChange = [Math]::Round($daysSinceChange, 0)
            })
        } else {
            $healthyCount++
        }
    }

    if ($staleTrustKeys.Count -gt 0) {
        $partnerNames = @($staleTrustKeys | ForEach-Object {
            if ($_.DaysSinceChange -ge 0) {
                "$($_.TrustPartner) (last changed $($_.DaysSinceChange) days ago)"
            } else {
                "$($_.TrustPartner) (change date unknown)"
            }
        })

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($staleTrustKeys.Count) trust(s) not modified in over $keyAgeThresholdDays days (trust key may not have been rotated): $($partnerNames -join '; ')" `
            -Details @{
                StaleKeyCount  = $staleTrustKeys.Count
                HealthyCount   = $healthyCount
                UnknownCount   = $unknownCount
                ThresholdDays  = $keyAgeThresholdDays
                StaleTrustKeys = @($staleTrustKeys)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($trusts.Count) trust(s) have been modified within the last $keyAgeThresholdDays days" `
        -Details @{
            TrustCount    = $trusts.Count
            ThresholdDays = $keyAgeThresholdDays
        }
}

# ── ADTRUST-011: Trust Hierarchy Visualization ───────────────────────────
function Test-ReconADTRUST011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TrustRelationships' -Subject 'trust relationships'
    if ($na) { return $na }

    $trusts = @($AuditData.Trusts | Where-Object { $null -ne $_ })
    if ($trusts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No trust relationships found' `
            -Details @{ TrustCount = 0; Topology = 'Isolated' }
    }

    # Determine the current domain name for the topology map
    $domainName = ''
    if ($AuditData.Domain -and $AuditData.Domain.DomainName) {
        $domainName = $AuditData.Domain.DomainName
    } elseif ($AuditData.Connection -and $AuditData.Connection.DomainDN) {
        $domainName = ($AuditData.Connection.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()
    } else {
        $domainName = 'This Domain'
    }

    # Build text-based trust topology
    $topologyLines = [System.Collections.Generic.List[string]]::new()
    $topologyLines.Add("Trust Topology for: $domainName")
    $topologyLines.Add("$('=' * (22 + $domainName.Length))")

    foreach ($trust in $trusts) {
        $directionArrow = switch ($trust.TrustDirection) {
            'Inbound'       { '<--' }
            'Outbound'      { '-->' }
            'Bidirectional' { '<->' }
            default         { '---' }
        }

        $trustFlags = [System.Collections.Generic.List[string]]::new()
        if ($trust.ForestTransitive) { $trustFlags.Add('Forest') }
        elseif ($trust.WithinForest) { $trustFlags.Add('IntraForest') }
        else { $trustFlags.Add('External') }

        if ($trust.IsTransitive) { $trustFlags.Add('Transitive') }
        if ($trust.IsAzureAD) { $trustFlags.Add('AzureAD') }
        if (-not $trust.SIDFilteringEnabled -and -not $trust.WithinForest) { $trustFlags.Add('NO-SID-FILTER') }
        if (-not $trust.SelectiveAuthentication -and -not $trust.WithinForest) { $trustFlags.Add('NO-SELECTIVE-AUTH') }
        if ($trust.UsesRC4Encryption) { $trustFlags.Add('RC4') }

        $flagStr = if ($trustFlags.Count -gt 0) { " [$($trustFlags -join ', ')]" } else { '' }
        $topologyLines.Add("  $domainName $directionArrow $($trust.TrustPartner)$flagStr")
    }

    $topologyText = $topologyLines -join "`n"

    # Build structured topology data
    $topologyData = @($trusts | ForEach-Object {
        @{
            Source              = $domainName
            Target              = $_.TrustPartner
            FlatName            = $_.FlatName
            Direction           = $_.TrustDirection
            Type                = if ($_.ForestTransitive) { 'Forest' }
                                  elseif ($_.WithinForest) { 'IntraForest' }
                                  elseif ($_.IsAzureAD) { 'AzureAD' }
                                  else { 'External' }
            Transitive          = $_.IsTransitive
            SIDFiltering        = $_.SIDFilteringEnabled
            SelectiveAuth       = $_.SelectiveAuthentication
            UsesRC4             = $_.UsesRC4Encryption
            NoTGTDelegation     = $_.NoTGTDelegation
            PIMTrust            = $_.PIMTrust
            TrustSID            = $_.TrustSID
            WhenCreated         = $_.WhenCreated
            WhenChanged         = $_.WhenChanged
        }
    })

    # Compile summary statistics
    $directionCounts = @{
        Inbound       = @($trusts | Where-Object { $_.TrustDirection -eq 'Inbound' }).Count
        Outbound      = @($trusts | Where-Object { $_.TrustDirection -eq 'Outbound' }).Count
        Bidirectional = @($trusts | Where-Object { $_.TrustDirection -eq 'Bidirectional' }).Count
        Disabled      = @($trusts | Where-Object { $_.TrustDirection -eq 'Disabled' }).Count
    }

    $securitySummary = @{
        SIDFilteringEnabled  = @($trusts | Where-Object { $_.SIDFilteringEnabled }).Count
        SelectiveAuthEnabled = @($trusts | Where-Object { $_.SelectiveAuthentication }).Count
        TransitiveTrusts     = @($trusts | Where-Object { $_.IsTransitive }).Count
        RC4Trusts            = @($trusts | Where-Object { $_.UsesRC4Encryption }).Count
    }

    $currentValue = "Trust topology: $domainName has $($trusts.Count) trust relationship(s) - $($directionCounts.Bidirectional) bidirectional, $($directionCounts.Inbound) inbound, $($directionCounts.Outbound) outbound"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            DomainName      = $domainName
            TrustCount      = $trusts.Count
            DirectionCounts = $directionCounts
            SecuritySummary = $securitySummary
            TopologyText    = $topologyText
            TopologyData    = $topologyData
        }
}
