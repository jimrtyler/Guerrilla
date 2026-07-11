# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-EntraPIMData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        DirectoryRoles            = @()
        RoleAssignments           = @()
        RoleEligibilitySchedules  = @()
        RoleAssignmentSchedules   = @()
        RoleDefinitions           = @()
        PrivilegedUsers           = @()
        GlobalAdmins              = @()
        Errors                    = @{}
    }

    # ── Directory Role Definitions ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting directory role definitions'
    }
    try {
        $data.RoleDefinitions = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/roleManagement/directory/roleDefinitions' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['RoleDefinitions'] = $_.Exception.Message
    }

    # ── Active Role Assignments ───────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting active role assignments'
    }
    try {
        $data.RoleAssignments = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/roleManagement/directory/roleAssignments' `
            -QueryParameters @{ '$expand' = 'principal' } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['RoleAssignments'] = $_.Exception.Message
    }

    # ── Eligible Role Assignments (PIM) ───────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting PIM eligible role assignments'
    }
    try {
        # Query the eligibility *schedules* (definitions), not scheduleInstances:
        # standing eligible assignments can have 0 active instances while the
        # definition exists, which made EIDPIM-010 falsely report "PIM not
        # configured". Definitions expose the same principalId/roleDefinitionId
        # fields the downstream PIM checks read.
        $data.RoleEligibilitySchedules = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/roleManagement/directory/roleEligibilitySchedules' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['RoleEligibilitySchedules'] = $_.Exception.Message
    }

    # ── Role Assignment Schedule Instances (active PIM activations) ───────
    try {
        $data.RoleAssignmentSchedules = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/roleManagement/directory/roleAssignmentScheduleInstances' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['RoleAssignmentSchedules'] = $_.Exception.Message
    }

    # ── Global Administrator members ──────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Enumerating Global Administrators'
    }
    $globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    try {
        $data.GlobalAdmins = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri "/directoryRoles(roleTemplateId='$globalAdminTemplateId')/members" `
            -Paginate -Quiet:$Quiet)
    } catch {
        # Try alternate approach via role assignments
        try {
            $gaAssignments = @($data.RoleAssignments | Where-Object {
                $_.roleDefinitionId -eq $globalAdminTemplateId
            })
            $data.GlobalAdmins = @($gaAssignments | ForEach-Object { $_.principal })
        } catch {
            $data.Errors['GlobalAdmins'] = $_.Exception.Message
        }
    }

    # ── Collect privileged user details ────────────────────────────────────
    # Identify all unique principals with privileged roles
    $privilegedPrincipalIds = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    # Define privileged role template IDs
    $privilegedRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'  # SharePoint Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'  # Application Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7'  # Cloud Application Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
        'b0f54661-2d74-4c50-afa3-1ec803f12efe'  # Billing Administrator
        '966707d0-3269-4727-9be2-8c3a10f19b9d'  # Global Reader
        'fdd7a751-b60b-444a-984c-02652fe8fa1c'  # Groups Administrator
        '729827e3-9c14-49f7-bb1b-9608f156bbb8'  # Helpdesk Administrator
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Administrator
        'c4e39bd9-1100-46d3-8c65-fb160da0071f'  # Authentication Administrator
        '7698a772-787b-4ac8-901f-60d6b08affd2'  # Cloud Device Administrator
        '3a2c62db-5318-420d-8d74-23affee5d9d5'  # Intune Administrator
        '44367163-eba1-44c3-98af-f5787879f96a'  # Dynamics 365 Administrator
        '11648597-926c-4cf3-9c36-bcebb0ba8dcc'  # Power Platform Administrator
        '0526716b-113d-4c15-b2c8-68e3c22b9f80'  # Authentication Policy Administrator
    )

    foreach ($assignment in $data.RoleAssignments) {
        if ($assignment.roleDefinitionId -in $privilegedRoleIds) {
            if ($assignment.principalId) {
                [void]$privilegedPrincipalIds.Add($assignment.principalId)
            }
        }
    }

    # Fetch user details for privileged principals (batch)
    if ($privilegedPrincipalIds.Count -gt 0 -and -not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Collecting details for $($privilegedPrincipalIds.Count) privileged principals"
    }

    $privilegedUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($principalId in $privilegedPrincipalIds) {
        try {
            $user = Invoke-GraphApi -AccessToken $AccessToken `
                -Uri "/users/$principalId" `
                -QueryParameters @{
                    '$select' = 'id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,signInActivity,createdDateTime'
                }
            if ($user) {
                $privilegedUsers.Add($user)
            }
        } catch {
            # Principal might be a service principal or group, not a user
            Write-Verbose "Could not fetch user details for principal $principalId"
        }
    }
    $data.PrivilegedUsers = @($privilegedUsers)

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Found $($data.GlobalAdmins.Count) Global Admins, $($data.RoleAssignments.Count) role assignments"
    }

    return $data
}
