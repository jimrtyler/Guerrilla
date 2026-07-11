# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-IntuneData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        CompliancePolicies      = @()
        ComplianceSummary       = $null
        DeviceConfigurations    = @()
        ManagedDevices          = @()
        AppProtectionPolicies   = @()
        EnrollmentConfigurations = @()
        AutopilotProfiles       = @()
        DeviceManagementScripts = @()
        MobileApps              = @()
        DeviceCategories        = @()
        SecurityBaselines       = @()
        OperationApprovalPolicies = @()
        Errors                  = @{}
    }

    # ── Device Compliance Policies ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Intune compliance policies'
    }
    try {
        $data.CompliancePolicies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/deviceCompliancePolicies' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['CompliancePolicies'] = $_.Exception.Message
    }

    # ── Compliance Summary ────────────────────────────────────────────────
    try {
        $data.ComplianceSummary = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/deviceCompliancePolicyDeviceStateSummary'
    } catch {
        $data.Errors['ComplianceSummary'] = $_.Exception.Message
    }

    # ── Device Configuration Profiles ─────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting device configuration profiles'
    }
    try {
        # $expand=assignments is required — without it every profile has a null
        # .assignments and INTUNE-005 counts all profiles as unassigned (false FAIL).
        $data.DeviceConfigurations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/deviceConfigurations' `
            -QueryParameters @{ '$expand' = 'assignments' } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['DeviceConfigurations'] = $_.Exception.Message
    }

    # ── Managed Devices (summary — limit for large tenants) ──────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting managed device summary'
    }
    try {
        $data.ManagedDevices = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/managedDevices' `
            -QueryParameters @{
                '$select' = 'id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,managementAgent,enrolledDateTime,lastSyncDateTime'
                '$top'    = '999'
            } `
            -Paginate -MaxPages 5 -Quiet:$Quiet)
    } catch {
        $data.Errors['ManagedDevices'] = $_.Exception.Message
    }

    # ── App Protection Policies (MAM) ─────────────────────────────────────
    try {
        $data.AppProtectionPolicies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceAppManagement/managedAppPolicies' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AppProtectionPolicies'] = $_.Exception.Message
    }

    # ── Enrollment Configurations ─────────────────────────────────────────
    try {
        $data.EnrollmentConfigurations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/deviceEnrollmentConfigurations' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['EnrollmentConfigurations'] = $_.Exception.Message
    }

    # ── Autopilot Deployment Profiles ─────────────────────────────────────
    try {
        $data.AutopilotProfiles = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/windowsAutopilotDeploymentProfiles' `
            -Beta -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AutopilotProfiles'] = $_.Exception.Message
    }

    # ── PowerShell Scripts ────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting PowerShell script deployments'
    }
    try {
        $data.DeviceManagementScripts = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/deviceManagementScripts' `
            -Beta -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['DeviceManagementScripts'] = $_.Exception.Message
    }

    # ── Win32 Apps ────────────────────────────────────────────────────────
    try {
        $data.MobileApps = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceAppManagement/mobileApps' `
            -QueryParameters @{
                '$filter' = "isof('microsoft.graph.win32LobApp')"
            } `
            -Paginate -Quiet:$Quiet)
    } catch {
        # Filter might not be supported, try without
        try {
            $data.MobileApps = @(Invoke-GraphApi -AccessToken $AccessToken `
                -Uri '/deviceAppManagement/mobileApps' `
                -Paginate -MaxPages 3 -Quiet:$Quiet)
        } catch {
            $data.Errors['MobileApps'] = $_.Exception.Message
        }
    }

    # ── Device Categories ─────────────────────────────────────────────────
    try {
        $data.DeviceCategories = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/deviceCategories' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['DeviceCategories'] = $_.Exception.Message
    }

    # ── Security Baselines ────────────────────────────────────────────────
    try {
        $data.SecurityBaselines = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/templates' `
            -QueryParameters @{
                '$filter' = "templateType eq 'securityBaseline'"
            } `
            -Beta -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['SecurityBaselines'] = $_.Exception.Message
    }

    # ── Multi-Admin Approval Policies ──────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting multi-admin approval policies'
    }
    try {
        $data.OperationApprovalPolicies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/deviceManagement/operationApprovalPolicies' `
            -Beta -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['OperationApprovalPolicies'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Intune: $($data.CompliancePolicies.Count) compliance policies, $($data.DeviceConfigurations.Count) config profiles, $($data.ManagedDevices.Count) devices"
    }

    return $data
}
