# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-AzureIAMChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'AzureIAMChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
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

# ── Shared: distinguish "no Azure ARM access" from "no resources" (ENT-5) ──────
# When Azure ARM is unreachable or NO subscription is accessible, every resource check
# should SKIP with one clear, actionable message — not emit a misleading
# "No X found in scanned subscriptions" WARN that implies a scan happened and found none.
# Returns a SKIP finding in that case, or $null when the IAM data is usable (>=1 sub).
function Get-AzureIAMUnavailableFinding {
    [CmdletBinding()]
    param($IamData, [hashtable]$CheckDefinition)

    if (-not $IamData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Azure Resource Manager was not queried (Azure IAM not in scope, or no app-only ARM token).'
    }
    if ($IamData.Errors -and $IamData.Errors['Subscriptions']) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "No Azure ARM access — could not list subscriptions ($($IamData.Errors['Subscriptions'])). Grant the app the Reader role at the root management group to audit Azure resources."
    }
    if (-not $IamData.Subscriptions -or $IamData.Subscriptions.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No accessible Azure subscriptions — grant the app the Reader role at the root management group to audit Azure resources.'
    }
    return $null
}

# ── AZIAM-001: Subscription Role Assignment Count ────────────────────────
function Test-InfiltrationAZIAM001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $assignments = $iamData.RoleAssignments
    $subscriptions = $iamData.Subscriptions
    $totalAssignments = $assignments.Count

    # Group assignments by subscription
    $perSub = @{}
    foreach ($a in $assignments) {
        $subId = $a._subscriptionId ?? 'Unknown'
        if (-not $perSub.ContainsKey($subId)) { $perSub[$subId] = 0 }
        $perSub[$subId]++
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$totalAssignments role assignments across $($subscriptions.Count) subscription(s)" `
        -Details @{
            TotalAssignments = $totalAssignments
            SubscriptionCount = $subscriptions.Count
            AssignmentsPerSubscription = @($perSub.GetEnumerator() | ForEach-Object {
                @{ SubscriptionId = $_.Key; AssignmentCount = $_.Value }
            })
        }
}

# ── AZIAM-002: Direct Resource-Level Assignments ────────────────────────
function Test-InfiltrationAZIAM002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $assignments = $iamData.RoleAssignments

    # Resource-level assignments have scopes deeper than /subscriptions/{id}
    # i.e., they contain more path segments beyond the subscription
    $resourceLevel = @($assignments | Where-Object {
        $scope = $_.properties.scope ?? ''
        # Subscription scope: /subscriptions/{guid}
        # Resource group scope: /subscriptions/{guid}/resourceGroups/{name}
        # Resource scope: /subscriptions/{guid}/resourceGroups/{name}/providers/...
        $segments = ($scope -split '/') | Where-Object { $_ }
        $segments.Count -gt 2
    })

    $directResourceAssignments = @($resourceLevel | Where-Object {
        $scope = $_.properties.scope ?? ''
        $segments = ($scope -split '/') | Where-Object { $_ }
        # More than 4 segments means it is at the individual resource level (not RG)
        $segments.Count -gt 4
    })

    $status = if ($directResourceAssignments.Count -eq 0) { 'PASS' }
              elseif ($directResourceAssignments.Count -le 10) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($directResourceAssignments.Count) direct resource-level role assignments found (non-inherited)" `
        -Details @{
            DirectResourceAssignments = $directResourceAssignments.Count
            TotalNonSubscriptionScope = $resourceLevel.Count
            Samples = @($directResourceAssignments | Select-Object -First 20 | ForEach-Object {
                @{
                    PrincipalId = $_.properties.principalId
                    RoleDefinitionId = $_.properties.roleDefinitionId
                    Scope = $_.properties.scope
                }
            })
        }
}

# ── AZIAM-003: Resource Group Level Permissions ─────────────────────────
function Test-InfiltrationAZIAM003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $assignments = $iamData.RoleAssignments

    # Resource group scoped assignments: /subscriptions/{id}/resourceGroups/{name}
    $rgAssignments = @($assignments | Where-Object {
        $scope = $_.properties.scope ?? ''
        $scope -match '/subscriptions/[^/]+/resourceGroups/[^/]+$'
    })

    # Group by resource group
    $rgGroups = @{}
    foreach ($a in $rgAssignments) {
        $rg = $a.properties.scope
        if (-not $rgGroups.ContainsKey($rg)) { $rgGroups[$rg] = 0 }
        $rgGroups[$rg]++
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($rgAssignments.Count) resource group-level assignments across $($rgGroups.Count) resource groups" `
        -Details @{
            RGAssignmentCount = $rgAssignments.Count
            ResourceGroupCount = $rgGroups.Count
            TopResourceGroups = @($rgGroups.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10 | ForEach-Object {
                @{ ResourceGroup = $_.Key; AssignmentCount = $_.Value }
            })
        }
}

# ── AZIAM-004: Key Vault Access ─────────────────────────────────────────
function Test-InfiltrationAZIAM004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $vaults = $iamData.KeyVaults
    if (-not $vaults -or $vaults.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Key Vaults found in scanned subscriptions' `
            -Details @{ VaultCount = 0 }
    }

    # Check vault properties
    $rbacEnabled = @($vaults | Where-Object { $_.properties.enableRbacAuthorization -eq $true })
    $softDeleteEnabled = @($vaults | Where-Object { $_.properties.enableSoftDelete -eq $true })
    $purgeProtected = @($vaults | Where-Object { $_.properties.enablePurgeProtection -eq $true })

    $status = if ($rbacEnabled.Count -eq $vaults.Count -and $purgeProtected.Count -eq $vaults.Count) { 'PASS' }
              elseif ($softDeleteEnabled.Count -eq $vaults.Count) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($vaults.Count) Key Vaults: $($rbacEnabled.Count) RBAC, $($softDeleteEnabled.Count) soft-delete, $($purgeProtected.Count) purge-protected" `
        -Details @{
            VaultCount = $vaults.Count
            RbacEnabled = $rbacEnabled.Count
            SoftDeleteEnabled = $softDeleteEnabled.Count
            PurgeProtected = $purgeProtected.Count
            Vaults = @($vaults | ForEach-Object {
                @{
                    Name = $_.name
                    Location = $_.location
                    EnableRbacAuthorization = $_.properties.enableRbacAuthorization
                    EnableSoftDelete = $_.properties.enableSoftDelete
                    EnablePurgeProtection = $_.properties.enablePurgeProtection
                }
            })
        }
}

# ── AZIAM-005: Storage Account Security ─────────────────────────────────
function Test-InfiltrationAZIAM005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $storageAccounts = $iamData.StorageAccounts
    if (-not $storageAccounts -or $storageAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No storage accounts found in scanned subscriptions' `
            -Details @{ StorageCount = 0 }
    }

    $httpsOnly = @($storageAccounts | Where-Object { $_.properties.supportsHttpsTrafficOnly -eq $true })
    $publicBlobDisabled = @($storageAccounts | Where-Object { $_.properties.allowBlobPublicAccess -ne $true })
    $tls12 = @($storageAccounts | Where-Object { $_.properties.minimumTlsVersion -eq 'TLS1_2' })

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($httpsOnly.Count -ne $storageAccounts.Count) { $issues.Add("$($storageAccounts.Count - $httpsOnly.Count) allow HTTP traffic") }
    if ($publicBlobDisabled.Count -ne $storageAccounts.Count) { $issues.Add("$($storageAccounts.Count - $publicBlobDisabled.Count) allow public blob access") }
    if ($tls12.Count -ne $storageAccounts.Count) { $issues.Add("$($storageAccounts.Count - $tls12.Count) not requiring TLS 1.2") }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -le 1) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if ($issues.Count -eq 0) {
        "$($storageAccounts.Count) storage accounts all enforce HTTPS, no public blob, TLS 1.2"
    } else {
        "$($storageAccounts.Count) storage accounts: $($issues -join '; ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            StorageCount = $storageAccounts.Count
            HttpsOnly = $httpsOnly.Count
            PublicBlobDisabled = $publicBlobDisabled.Count
            Tls12 = $tls12.Count
            Issues = @($issues)
            Accounts = @($storageAccounts | ForEach-Object {
                @{
                    Name = $_.name
                    SupportsHttpsOnly = $_.properties.supportsHttpsTrafficOnly
                    AllowBlobPublicAccess = $_.properties.allowBlobPublicAccess
                    MinimumTlsVersion = $_.properties.minimumTlsVersion
                }
            })
        }
}

# ── AZIAM-006: NSG Overly Permissive Rules ──────────────────────────────
function Test-InfiltrationAZIAM006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $nsgs = $iamData.NetworkSecurityGroups
    if (-not $nsgs -or $nsgs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Network Security Groups found in scanned subscriptions' `
            -Details @{ NSGCount = 0 }
    }

    $permissiveRules = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($nsg in $nsgs) {
        $rules = @($nsg.properties.securityRules)
        foreach ($rule in $rules) {
            $props = $rule.properties
            if ($props.access -ne 'Allow' -or $props.direction -ne 'Inbound') { continue }

            $isWideOpen = (
                ($props.sourceAddressPrefix -eq '*' -or $props.sourceAddressPrefix -eq '0.0.0.0/0' -or
                 $props.sourceAddressPrefix -eq 'Internet') -and
                ($props.destinationPortRange -eq '*' -or $props.destinationPortRange -eq '0-65535')
            )

            if ($isWideOpen) {
                $permissiveRules.Add([PSCustomObject]@{
                    NSGName = $nsg.name
                    RuleName = $rule.name
                    SourceAddress = $props.sourceAddressPrefix
                    DestinationPort = $props.destinationPortRange
                    Protocol = $props.protocol
                    Priority = $props.priority
                })
            }
        }
    }

    $status = if ($permissiveRules.Count -eq 0) { 'PASS' }
              elseif ($permissiveRules.Count -le 3) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($permissiveRules.Count) overly permissive NSG rules (any source, any port inbound) across $($nsgs.Count) NSGs" `
        -Details @{
            NSGCount = $nsgs.Count
            PermissiveRuleCount = $permissiveRules.Count
            PermissiveRules = @($permissiveRules | ForEach-Object {
                @{
                    NSGName = $_.NSGName
                    RuleName = $_.RuleName
                    SourceAddress = $_.SourceAddress
                    DestinationPort = $_.DestinationPort
                    Protocol = $_.Protocol
                    Priority = $_.Priority
                }
            })
        }
}

# ── AZIAM-007: Azure Policy Compliance ──────────────────────────────────
function Test-InfiltrationAZIAM007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $policyStates = $iamData.PolicyStates
    if (-not $policyStates -or $policyStates.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Azure Policy compliance data available' `
            -Details @{ PolicyDataAvailable = $false }
    }

    $totalNonCompliant = 0
    $totalResources = 0
    $summaries = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ps in $policyStates) {
        $summary = $ps.Summary
        if ($summary -and $summary.results) {
            $nonCompliant = $summary.results.nonCompliantResources ?? 0
            $total = $summary.results.totalResources ?? 0
            $totalNonCompliant += $nonCompliant
            $totalResources += $total
            $summaries.Add(@{
                SubscriptionId = $ps.SubscriptionId
                NonCompliantResources = $nonCompliant
                TotalResources = $total
            })
        }
    }

    $percentage = if ($totalResources -gt 0) { [Math]::Round(($totalNonCompliant / $totalResources) * 100, 1) } else { 0 }

    $status = if ($totalNonCompliant -eq 0) { 'PASS' }
              elseif ($percentage -le 10) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$totalNonCompliant non-compliant resources out of $totalResources total ($percentage%)" `
        -Details @{
            TotalNonCompliant = $totalNonCompliant
            TotalResources = $totalResources
            NonCompliancePercentage = $percentage
            PerSubscription = @($summaries)
        }
}

# ── AZIAM-008: Management Group Structure ───────────────────────────────
function Test-InfiltrationAZIAM008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $mgGroups = $iamData.ManagementGroups
    if (-not $mgGroups -or $mgGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No management groups found or accessible' `
            -Details @{ ManagementGroupCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($mgGroups.Count) management group(s) in hierarchy" `
        -Details @{
            ManagementGroupCount = $mgGroups.Count
            Groups = @($mgGroups | ForEach-Object {
                @{
                    Id = $_.id
                    Name = $_.name
                    DisplayName = $_.properties.displayName
                    TenantId = $_.properties.tenantId
                }
            })
        }
}

# ── AZIAM-009: Custom RBAC Role Definitions ─────────────────────────────
function Test-InfiltrationAZIAM009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $customRoles = $iamData.RoleDefinitions
    if (-not $customRoles -or $customRoles.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No custom RBAC role definitions found' `
            -Details @{ CustomRoleCount = 0 }
    }

    # Check for overly broad custom roles (wildcard actions)
    $broadRoles = @($customRoles | Where-Object {
        $actions = @($_.properties.permissions | ForEach-Object { $_.actions }) | ForEach-Object { $_ }
        $actions -contains '*'
    })

    $status = if ($broadRoles.Count -gt 0) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($customRoles.Count) custom RBAC roles ($($broadRoles.Count) with wildcard actions)" `
        -Details @{
            CustomRoleCount = $customRoles.Count
            BroadRoleCount = $broadRoles.Count
            Roles = @($customRoles | ForEach-Object {
                @{
                    Id = $_.id
                    RoleName = $_.properties.roleName
                    Description = $_.properties.description
                    AssignableScopes = @($_.properties.assignableScopes)
                }
            })
        }
}

# ── AZIAM-010: Resource Locks ───────────────────────────────────────────
function Test-InfiltrationAZIAM010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $iamData = $AuditData.AzureIAM
    $unavailable = Get-AzureIAMUnavailableFinding -IamData $iamData -CheckDefinition $CheckDefinition
    if ($unavailable) { return $unavailable }

    $locks = $iamData.ResourceLocks
    $subscriptions = $iamData.Subscriptions

    if (-not $locks -or $locks.Count -eq 0) {
        $status = if ($subscriptions.Count -gt 0) { 'WARN' } else { 'SKIP' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue 'No resource locks deployed across scanned subscriptions' `
            -Details @{
                LockCount = 0
                SubscriptionCount = $subscriptions.Count
            }
    }

    $deleteLocks = @($locks | Where-Object { $_.properties.level -eq 'CanNotDelete' })
    $readOnlyLocks = @($locks | Where-Object { $_.properties.level -eq 'ReadOnly' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($locks.Count) resource locks deployed ($($deleteLocks.Count) delete, $($readOnlyLocks.Count) read-only)" `
        -Details @{
            TotalLocks = $locks.Count
            DeleteLocks = $deleteLocks.Count
            ReadOnlyLocks = $readOnlyLocks.Count
            Locks = @($locks | ForEach-Object {
                @{
                    Id = $_.id
                    Name = $_.name
                    Level = $_.properties.level
                    Notes = $_.properties.notes
                }
            })
        }
}
