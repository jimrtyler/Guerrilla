# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-InfiltrationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [string]$ArmAccessToken,

        # Copilot Studio agents live in Dataverse (per-environment audience). Discovery
        # token + a per-environment token factory; absent = agents Not Assessed (SKIP).
        [string]$DataverseGlobalToken,

        [scriptblock]$DataverseTokenFactory,

        [string[]]$Categories = @('All'),

        [hashtable]$ModuleAvailability,

        # Representative user object ID for live CA what-if simulation (EIDCA-015). Empty = inference.
        [string]$WhatIfUserId,

        [switch]$Quiet
    )

    # ── Category-to-data-source mapping ──────────────────────────────────
    $categoryDataNeeds = @{
        ConditionalAccess     = @('ConditionalAccess')
        AuthenticationMethods = @('AuthMethods')
        PIM                   = @('PIM', 'AuthMethods')
        Applications          = @('Applications')
        Federation            = @('Federation')
        Governance            = @('Governance')
        AIAgent               = @('AIAgents')
        TenantConfig          = @('TenantConfig')
        Eidsca                = @('AuthMethods', 'TenantConfig')
        AzureIAM              = @('AzureIAM')
        Intune                = @('Intune')
        M365Services          = @('M365Services')
    }

    # Resolve which data sources are required
    $requiredSources = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    if ($Categories -contains 'All') {
        foreach ($sources in $categoryDataNeeds.Values) {
            foreach ($s in $sources) { [void]$requiredSources.Add($s) }
        }
    } else {
        foreach ($cat in $Categories) {
            if ($categoryDataNeeds.ContainsKey($cat)) {
                foreach ($s in $categoryDataNeeds[$cat]) {
                    [void]$requiredSources.Add($s)
                }
            }
        }
    }

    [void]$requiredSources.Add('ModuleAvailability')

    # ── Initialize result hashtable ──────────────────────────────────────
    $data = @{
        ConditionalAccess = $null
        AuthMethods       = $null
        PIM               = $null
        Applications      = $null
        Federation        = $null
        Governance        = $null
        AIAgents          = $null
        TenantConfig      = $null
        AzureIAM          = $null
        Intune            = $null
        M365Services      = $null
        ModuleAvailability = $null
        Errors            = @{}
    }

    $needsSource = { param([string]$Name) $requiredSources.Contains($Name) }

    # ── 1. Module Availability ───────────────────────────────────────────
    if (& $needsSource 'ModuleAvailability') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Checking module availability'
        }
        $data.ModuleAvailability = if ($ModuleAvailability) {
            $ModuleAvailability
        } else {
            try { Test-GraphModuleAvailability } catch {
                $data.Errors['ModuleAvailability'] = $_.Exception.Message
                @{
                    MSALPS                   = $false
                    ExchangeOnlineManagement = $false
                    MicrosoftTeams           = $false
                    PnPPowerShell            = $false
                    PowerAppsAdmin           = $false
                    AzAccounts               = $false
                }
            }
        }
    }

    # ── 2. Conditional Access Data ───────────────────────────────────────
    if (& $needsSource 'ConditionalAccess') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Conditional Access data'
        }
        try {
            $data.ConditionalAccess = Get-EntraConditionalAccessData `
                -AccessToken $AccessToken -WhatIfUserId $WhatIfUserId -Quiet:$Quiet
        } catch {
            $data.Errors['ConditionalAccess'] = $_.Exception.Message
            $data.ConditionalAccess = @{ Policies = @(); NamedLocations = @(); Errors = @{} }
        }
    }

    # ── 3. Authentication Methods Data ───────────────────────────────────
    if (& $needsSource 'AuthMethods') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting authentication methods data'
        }
        try {
            $data.AuthMethods = Get-EntraAuthMethodsData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['AuthMethods'] = $_.Exception.Message
            $data.AuthMethods = @{
                AuthMethodsPolicy      = $null
                MethodConfigurations   = @()
                UserRegistrationDetails = @()
                Errors                 = @{}
            }
        }
    }

    # ── 4. PIM Data ──────────────────────────────────────────────────────
    if (& $needsSource 'PIM') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting privileged identity data'
        }
        try {
            $data.PIM = Get-EntraPIMData -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['PIM'] = $_.Exception.Message
            $data.PIM = @{
                RoleAssignments = @(); GlobalAdmins = @();
                PrivilegedUsers = @(); Errors = @{}
            }
        }
    }

    # ── 5. Applications Data ─────────────────────────────────────────────
    if (& $needsSource 'Applications') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting application and service principal data'
        }
        try {
            $data.Applications = Get-EntraApplicationData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Applications'] = $_.Exception.Message
            $data.Applications = @{
                AppRegistrations = @(); ServicePrincipals = @();
                ConsentGrants = @(); Errors = @{}
            }
        }
    }

    # ── 6. Federation Data ───────────────────────────────────────────────
    if (& $needsSource 'Federation') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting federation and hybrid identity data'
        }
        try {
            $data.Federation = Get-EntraFederationData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Federation'] = $_.Exception.Message
            $data.Federation = @{ Domains = @(); Errors = @{} }
        }
    }

    # ── 6b. Entra ID Governance (entitlement management) ─────────────────
    if (& $needsSource 'Governance') {
        try {
            $data.Governance = Get-EntraGovernanceData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Governance'] = $_.Exception.Message
            $data.Governance = @{ AccessPackages = @(); Catalogs = @(); AssignmentPolicies = @(); Errors = @{} }
        }
    }

    # ── 6c. Copilot Studio AI agents (Dataverse) ────────────────────────
    if (& $needsSource 'AIAgents') {
        try {
            $data.AIAgents = Get-PowerPlatformData `
                -GlobalDiscoToken $DataverseGlobalToken -TokenFactory $DataverseTokenFactory -Quiet:$Quiet
        } catch {
            $data.Errors['AIAgents'] = $_.Exception.Message
            $data.AIAgents = @{ Agents = @(); Environments = @(); Errors = @{} }
        }
    }

    # ── 7. Tenant Configuration Data ─────────────────────────────────────
    if (& $needsSource 'TenantConfig') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting tenant configuration data'
        }
        try {
            $data.TenantConfig = Get-EntraTenantData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['TenantConfig'] = $_.Exception.Message
            $data.TenantConfig = @{ Organization = $null; Errors = @{} }
        }
    }

    # ── 8. Azure IAM Data ────────────────────────────────────────────────
    if (& $needsSource 'AzureIAM') {
        if ($ArmAccessToken) {
            if (-not $Quiet) {
                Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Azure IAM and resource security data'
            }
            try {
                $data.AzureIAM = Get-AzureIAMData `
                    -AccessToken $ArmAccessToken -Quiet:$Quiet
            } catch {
                $data.Errors['AzureIAM'] = $_.Exception.Message
                $data.AzureIAM = @{ Subscriptions = @(); Errors = @{} }
            }
        } else {
            $data.Errors['AzureIAM'] = 'No ARM access token provided — Azure IAM checks skipped'
            $data.AzureIAM = @{ Subscriptions = @(); Errors = @{ Token = 'No ARM token' } }
        }
    }

    # ── 9. Intune Data ───────────────────────────────────────────────────
    if (& $needsSource 'Intune') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Intune endpoint management data'
        }
        try {
            $data.Intune = Get-IntuneData -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Intune'] = $_.Exception.Message
            $data.Intune = @{ CompliancePolicies = @(); Errors = @{} }
        }
    }

    # ── 10. M365 Services Data ───────────────────────────────────────────
    if (& $needsSource 'M365Services') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting M365 service configuration data'
        }
        try {
            $data.M365Services = Get-M365ServiceData `
                -AccessToken $AccessToken `
                -ModuleAvailability $data.ModuleAvailability `
                -Quiet:$Quiet
        } catch {
            $data.Errors['M365Services'] = $_.Exception.Message
            $data.M365Services = @{ Exchange = @{}; SharePoint = @{}; Teams = @{}; Errors = @{} }
        }
    }

    return $data
}
