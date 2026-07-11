# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-AzureIAMData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        Subscriptions       = @()
        RoleAssignments     = @()
        RoleDefinitions     = @()
        ManagementGroups    = @()
        ResourceLocks       = @()
        KeyVaults           = @()
        StorageAccounts     = @()
        NetworkSecurityGroups = @()
        PolicyStates        = @()
        Errors              = @{}
    }

    # ── Subscriptions ─────────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Enumerating Azure subscriptions'
    }
    try {
        $data.Subscriptions = @(Invoke-AzureRMApi -AccessToken $AccessToken `
            -Uri '/subscriptions' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Subscriptions'] = $_.Exception.Message
        return $data
    }

    if ($data.Subscriptions.Count -eq 0) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFO -Message 'No Azure subscriptions found'
        }
        return $data
    }

    # ── Management Groups ─────────────────────────────────────────────────
    try {
        $data.ManagementGroups = @(Invoke-AzureRMApi -AccessToken $AccessToken `
            -Uri '/providers/Microsoft.Management/managementGroups' `
            -ApiVersion '2021-04-01' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['ManagementGroups'] = $_.Exception.Message
    }

    # ── Per-subscription data collection ──────────────────────────────────
    foreach ($sub in $data.Subscriptions) {
        $subId = $sub.subscriptionId
        $subName = $sub.displayName
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message "Scanning subscription: $subName"
        }

        # Role Assignments
        try {
            $assignments = @(Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments" `
                -Paginate -Quiet:$Quiet)
            foreach ($a in $assignments) {
                $a | Add-Member -NotePropertyName '_subscriptionId' -NotePropertyValue $subId -Force
                $a | Add-Member -NotePropertyName '_subscriptionName' -NotePropertyValue $subName -Force
            }
            $data.RoleAssignments += $assignments
        } catch {
            $data.Errors["RoleAssignments_$subId"] = $_.Exception.Message
        }

        # Custom Role Definitions
        try {
            $roles = @(Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions" `
                -QueryParameters @{ '$filter' = "type eq 'CustomRole'" } `
                -Paginate -Quiet:$Quiet)
            $data.RoleDefinitions += $roles
        } catch {
            $data.Errors["RoleDefinitions_$subId"] = $_.Exception.Message
        }

        # Resource Locks
        try {
            $locks = @(Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.Authorization/locks" `
                -ApiVersion '2016-09-01' -Paginate -Quiet:$Quiet)
            $data.ResourceLocks += $locks
        } catch {
            $data.Errors["Locks_$subId"] = $_.Exception.Message
        }

        # Key Vaults
        try {
            $vaults = @(Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.KeyVault/vaults" `
                -ApiVersion '2022-07-01' -Paginate -Quiet:$Quiet)
            $data.KeyVaults += $vaults
        } catch {
            $data.Errors["KeyVaults_$subId"] = $_.Exception.Message
        }

        # Storage Accounts
        try {
            $storage = @(Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.Storage/storageAccounts" `
                -ApiVersion '2022-09-01' -Paginate -Quiet:$Quiet)
            $data.StorageAccounts += $storage
        } catch {
            $data.Errors["Storage_$subId"] = $_.Exception.Message
        }

        # Network Security Groups
        try {
            $nsgs = @(Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.Network/networkSecurityGroups" `
                -ApiVersion '2023-04-01' -Paginate -Quiet:$Quiet)
            $data.NetworkSecurityGroups += $nsgs
        } catch {
            $data.Errors["NSGs_$subId"] = $_.Exception.Message
        }

        # Policy Compliance
        try {
            $policyStates = Invoke-AzureRMApi -AccessToken $AccessToken `
                -Uri "/subscriptions/$subId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize" `
                -ApiVersion '2019-10-01' -Method Post
            if ($policyStates) {
                $data.PolicyStates += @{ SubscriptionId = $subId; Summary = $policyStates }
            }
        } catch {
            $data.Errors["Policy_$subId"] = $_.Exception.Message
        }
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Azure: $($data.Subscriptions.Count) subscriptions, $($data.RoleAssignments.Count) role assignments"
    }

    return $data
}
