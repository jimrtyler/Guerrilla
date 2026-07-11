# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-FortificationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$ServiceAccountKeyPath,

        [Parameter(Mandatory)]
        [string]$AdminEmail,

        [string[]]$Categories = @('All'),

        [int]$UserSampleSize = 500,

        [string]$TargetOU = '/',

        [switch]$Quiet,

        # Skip the per-user Gmail-settings crawl (the slow part — ~1.4s/user serial).
        # Directory, DNS, and OAuth collection still run; the Gmail-dependent EMAIL checks
        # SKIP cleanly. Intended for fast iteration on large tenants.
        [switch]$Quick
    )

    # ── Category-to-data-source mapping ──────────────────────────────────
    $categoryDataNeeds = @{
        Authentication   = @('Users', 'OrgUnits')
        EmailSecurity    = @('Domains', 'DnsRecords', 'GmailSettings', 'Users')
        DriveSecurity    = @('Users', 'OrgUnits')
        OAuthSecurity    = @('OAuthApps', 'DomainWideDelegation', 'Users')
        AdminManagement  = @('Users', 'Roles', 'RoleAssignments', 'Groups', 'OrgUnits')
        Collaboration    = @('OrgUnits', 'Groups')
        DeviceManagement = @('MobileDevices', 'ChromeDevices', 'ChromePolicies')
        LoggingAlerting  = @('AlertRules')
        # Sites/Classroom/Gemini checks read only CloudIdentityPolicies, which is collected
        # unconditionally below (step 16). 'Customer' is always added so the category still
        # resolves a data need and the tenant header populates. GeminiAuditSettings pulls the
        # admin audit log to infer the deep Gemini toggles that NO config API exposes
        # (GWS-GEMINI-002/003/004/005) — the same source ScubaGoggles derives them from.
        GwsService       = @('Customer', 'GeminiAuditSettings')
        Tradecraft       = @('DomainWideDelegation', 'Users', 'Roles', 'OAuthApps', 'Groups', 'GroupSettings')
    }

    # Resolve which data sources are required
    $requiredSources = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    if ($Categories -contains 'All') {
        # Collect every known data source
        foreach ($sources in $categoryDataNeeds.Values) {
            foreach ($s in $sources) { [void]$requiredSources.Add($s) }
        }
        # Also include tenant-level sources that are always needed
        [void]$requiredSources.Add('Customer')
    } else {
        foreach ($cat in $Categories) {
            if ($categoryDataNeeds.ContainsKey($cat)) {
                foreach ($s in $categoryDataNeeds[$cat]) {
                    [void]$requiredSources.Add($s)
                }
            }
        }
        [void]$requiredSources.Add('Customer')
    }

    # ── Initialize result hashtable ──────────────────────────────────────
    $data = @{
        Tenant              = @{
            CustomerId = ''
            Domain     = ''
            Domains    = @()
            OrgUnits   = @()
        }
        Users               = @()
        Groups              = @()
        GroupSettings        = @{}
        Roles               = @()
        RoleAssignments      = @()
        MobileDevices       = @()
        ChromeDevices       = @()
        DnsRecords          = @{}
        GmailSettings       = @{}
        OrgUnitPolicies     = @{ '/' = @{} }
        AlertRules          = @()
        ChromePolicies      = @()
        OAuthApps           = @()
        DomainWideDelegation = @()
        CloudIdentityPolicies = $null
        GeminiDerivedSettings = @{}
        Errors              = @{}
    }

    # Helper: determine whether a data source is needed
    $needsSource = { param([string]$Name) $requiredSources.Contains($Name) }

    # ── 1. Customer info ─────────────────────────────────────────────────
    if (& $needsSource 'Customer') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving tenant info'
        }
        try {
            $customer = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customers/my_customer' `
                -Quiet:$Quiet
            if ($customer) {
                $data.Tenant.CustomerId = $customer.id ?? $customer.customerId ?? ''
                $data.Tenant.Domain     = $customer.customerDomain ?? ''
            }
        } catch {
            $data.Errors['Customer'] = $_.Exception.Message
        }
    }

    # ── 2. Domains ───────────────────────────────────────────────────────
    if (& $needsSource 'Domains') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving verified domains'
        }
        try {
            $domainsResult = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains' `
                -Paginate `
                -ItemsProperty 'domains' `
                -Quiet:$Quiet
            $data.Tenant.Domains = @($domainsResult ?? @())
        } catch {
            $data.Errors['Domains'] = $_.Exception.Message
        }
    }

    # ── 3. OrgUnits ──────────────────────────────────────────────────────
    if (& $needsSource 'OrgUnits') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving organizational units'
        }
        try {
            $orgUnits = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits' `
                -QueryParameters @{ type = 'all' } `
                -Paginate `
                -ItemsProperty 'organizationUnits' `
                -Quiet:$Quiet
            $data.Tenant.OrgUnits = @($orgUnits ?? @())
        } catch {
            $data.Errors['OrgUnits'] = $_.Exception.Message
        }
    }

    # ── 4. Users ─────────────────────────────────────────────────────────
    if (& $needsSource 'Users') {
        $ouDetail = if ($TargetOU -and $TargetOU -ne '/') { $TargetOU } else { $null }
        if (-not $Quiet) {
            if ($ouDetail) {
                Write-ProgressLine -Phase AUDITING -Message 'Retrieving users' -Detail "OU: $ouDetail"
            } else {
                Write-ProgressLine -Phase AUDITING -Message 'Retrieving users'
            }
        }
        try {
            $userQueryParams = @{
                customer   = 'my_customer'
                maxResults = '500'
                projection = 'full'
                orderBy    = 'email'
            }
            if ($ouDetail) {
                $userQueryParams['query'] = "orgUnitPath='$TargetOU'"
            }
            $users = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/users' `
                -QueryParameters $userQueryParams `
                -Paginate `
                -ItemsProperty 'users' `
                -Quiet:$Quiet
            $data.Users = @($users ?? @())
        } catch {
            $data.Errors['Users'] = $_.Exception.Message
        }
    }

    # ── 5. Groups ────────────────────────────────────────────────────────
    if (& $needsSource 'Groups') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving groups'
        }
        try {
            $groups = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/groups' `
                -QueryParameters @{
                    customer   = 'my_customer'
                    maxResults = '200'
                } `
                -Paginate `
                -ItemsProperty 'groups' `
                -Quiet:$Quiet
            $data.Groups = @($groups ?? @())
        } catch {
            $data.Errors['Groups'] = $_.Exception.Message
        }
    }

    # ── Group exposure settings (per-group; gated by -Quick like the Gmail crawl) ──
    if (-not $Quick -and (& $needsSource 'GroupSettings')) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving group exposure settings' -Detail "($(@($data.Groups).Count) groups)"
        }
        try {
            $gs = Get-GoogleGroupSettings -ServiceAccountKeyPath $ServiceAccountKeyPath `
                -AdminEmail $AdminEmail -Groups @($data.Groups) -Quiet:$Quiet
            if ($null -ne $gs) { $data.GroupSettings = $gs }
        } catch {
            $data.Errors['GroupSettings'] = $_.Exception.Message
        }
    }

    # ── 6. Roles ─────────────────────────────────────────────────────────
    if (& $needsSource 'Roles') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving admin roles'
        }
        try {
            $roles = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles' `
                -Paginate `
                -ItemsProperty 'items' `
                -Quiet:$Quiet
            $data.Roles = @($roles ?? @())
        } catch {
            $data.Errors['Roles'] = $_.Exception.Message
        }
    }

    # ── 7. Role Assignments ──────────────────────────────────────────────
    if (& $needsSource 'RoleAssignments') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving role assignments'
        }
        try {
            $roleAssignments = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments' `
                -Paginate `
                -ItemsProperty 'items' `
                -Quiet:$Quiet
            $data.RoleAssignments = @($roleAssignments ?? @())
        } catch {
            $data.Errors['RoleAssignments'] = $_.Exception.Message
        }
    }

    # ── 8. Mobile Devices ────────────────────────────────────────────────
    if (& $needsSource 'MobileDevices') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving mobile devices'
        }
        try {
            $mobileDevices = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/mobile' `
                -QueryParameters @{ maxResults = '100' } `
                -Paginate `
                -ItemsProperty 'mobiledevices' `
                -Quiet:$Quiet
            $data.MobileDevices = @($mobileDevices ?? @())
        } catch {
            $data.Errors['MobileDevices'] = $_.Exception.Message
        }
    }

    # ── 9. Chrome Devices ────────────────────────────────────────────────
    if (& $needsSource 'ChromeDevices') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving Chrome OS devices'
        }
        try {
            $chromeDevices = Invoke-GoogleAdminApi `
                -AccessToken $AccessToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/chromeos' `
                -QueryParameters @{ maxResults = '100' } `
                -Paginate `
                -ItemsProperty 'chromeosdevices' `
                -Quiet:$Quiet
            $data.ChromeDevices = @($chromeDevices ?? @())
        } catch {
            $data.Errors['ChromeDevices'] = $_.Exception.Message
        }
    }

    # ── 10. DNS Records ──────────────────────────────────────────────────
    if (& $needsSource 'DnsRecords') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Checking DNS mail security records'
        }
        $domains = @($data.Tenant.Domains)
        foreach ($domainObj in $domains) {
            $domainName = if ($domainObj -is [string]) { $domainObj } else { $domainObj.domainName }
            if (-not $domainName) { continue }

            try {
                if (-not $Quiet) {
                    Write-ProgressLine -Phase AUDITING -Message 'Resolving DNS' -Detail $domainName
                }
                $dnsResult = Resolve-DomainMailSecurity -Domain $domainName
                $data.DnsRecords[$domainName] = $dnsResult
            } catch {
                $data.Errors["DnsRecords:$domainName"] = $_.Exception.Message
            }
        }
    }

    # ── 11. Gmail Settings (per-user sample) ─────────────────────────────
    # -Quick skips this entirely (it dominates wall-clock on large tenants); the
    # Gmail-dependent EMAIL checks then SKIP with "No Gmail settings data available".
    if (-not $Quick -and (& $needsSource 'GmailSettings')) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Sampling Gmail user settings'
        }

        # Select a sample of users up to $UserSampleSize
        $userPool = @($data.Users | Where-Object { $_ })
        $sampleUsers = if ($userPool.Count -le $UserSampleSize) {
            $userPool
        } else {
            # Random sample (not -First): inspecting the same directory-order prefix every
            # run skews coverage (often one OU) and would never reach a compromised mailbox
            # late in the list. Auto-forwarding exfil typically hides in a single account.
            @(Get-Random -InputObject $userPool -Count $UserSampleSize)
        }

        $userCount = 0
        foreach ($user in $sampleUsers) {
            $userEmail = $user.primaryEmail
            if (-not $userEmail) { continue }

            $userCount++
            if (-not $Quiet -and ($userCount % 50 -eq 0 -or $userCount -eq 1)) {
                Write-ProgressLine -Phase AUDITING `
                    -Message 'Gmail settings' `
                    -Detail "$userCount / $($sampleUsers.Count)"
            }

            try {
                # Get an impersonated token for this user's Gmail
                $gmailToken = Get-GoogleAccessToken `
                    -ServiceAccountKeyPath $ServiceAccountKeyPath `
                    -AdminEmail $AdminEmail `
                    -Scopes @('https://www.googleapis.com/auth/gmail.settings.basic') `
                    -ImpersonateUser $userEmail

                $userSettings = @{}
                $mailNotEnabled = $false

                # Auto-forwarding
                try {
                    $userSettings['autoForwarding'] = Invoke-GoogleAdminApi `
                        -AccessToken $gmailToken `
                        -Uri 'https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding' `
                        -Quiet:$Quiet
                } catch {
                    if ($_.Exception.Message -match 'Mail service not enabled') {
                        $mailNotEnabled = $true
                    }
                    $userSettings['autoForwarding'] = $null
                }

                if (-not $mailNotEnabled) {
                    # IMAP
                    try {
                        $userSettings['imap'] = Invoke-GoogleAdminApi `
                            -AccessToken $gmailToken `
                            -Uri 'https://gmail.googleapis.com/gmail/v1/users/me/settings/imap' `
                            -Quiet:$Quiet
                    } catch {
                        $userSettings['imap'] = $null
                    }

                    # POP
                    try {
                        $userSettings['pop'] = Invoke-GoogleAdminApi `
                            -AccessToken $gmailToken `
                            -Uri 'https://gmail.googleapis.com/gmail/v1/users/me/settings/pop' `
                            -Quiet:$Quiet
                    } catch {
                        $userSettings['pop'] = $null
                    }

                    # Send-As aliases
                    try {
                        $userSettings['sendAs'] = Invoke-GoogleAdminApi `
                            -AccessToken $gmailToken `
                            -Uri 'https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs' `
                            -Paginate `
                            -ItemsProperty 'sendAs' `
                            -Quiet:$Quiet
                    } catch {
                        $userSettings['sendAs'] = $null
                    }
                }

                $data.GmailSettings[$userEmail] = $userSettings
            } catch {
                $data.Errors["GmailSettings:$userEmail"] = $_.Exception.Message
            }
        }

        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING `
                -Message 'Gmail settings complete' `
                -Detail "$userCount users sampled"
        }
    }

    # ── 12. OAuth Token Grants (Reports API) ─────────────────────────────
    if (& $needsSource 'OAuthApps') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving OAuth token grants'
        }
        try {
            $reportsToken = Get-GoogleAccessToken `
                -ServiceAccountKeyPath $ServiceAccountKeyPath `
                -AdminEmail $AdminEmail `
                -Scopes @('https://www.googleapis.com/auth/admin.reports.audit.readonly')

            $oauthEvents = Invoke-GoogleReportsApi `
                -AccessToken $reportsToken `
                -ApplicationName 'token' `
                -StartTime ([datetime]::UtcNow.AddDays(-7)) `
                -Quiet:$Quiet

            $data.OAuthApps = @($oauthEvents ?? @())
        } catch {
            $data.Errors['OAuthApps'] = $_.Exception.Message
        }
    }

    # ── 12b. Gemini Deep Settings (inferred from admin audit log) ─────────
    # The Gemini Alpha-features / conversation-history / retention / sharing
    # toggles are exposed by NO Google config or policy API. The only
    # programmatic signal is the admin audit log: a CHANGE_APPLICATION_SETTING
    # event is written when an admin changes one. This is exactly how CISA
    # ScubaGoggles derives these settings. We replay those events and take the
    # most-recent value per setting. This is INFERENCE, not a config read, and
    # the checks label their verdicts accordingly. It shares ScubaGoggles' blind
    # spot: a setting never changed within the retention window produces no event
    # and is honestly SKIP'd — an absent value is never guessed into a pass.
    if (& $needsSource 'GeminiAuditSettings') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Inferring Gemini settings from admin audit log'
        }
        try {
            $reportsToken = Get-GoogleAccessToken `
                -ServiceAccountKeyPath $ServiceAccountKeyPath `
                -AdminEmail $AdminEmail `
                -Scopes @('https://www.googleapis.com/auth/admin.reports.audit.readonly')

            # Admin setting-change events. 180 days keeps us inside the admin audit
            # retention window; older changes are unknowable to us AND to ScubaGoggles.
            $adminEvents = Invoke-GoogleReportsApi `
                -AccessToken $reportsToken `
                -ApplicationName 'admin' `
                -StartTime ([datetime]::UtcNow.AddDays(-180)) `
                -Quiet:$Quiet

            $data.GeminiDerivedSettings = ConvertTo-GeminiDerivedSettings -Events @($adminEvents ?? @())
        } catch {
            $data.Errors['GeminiAuditSettings'] = $_.Exception.Message
        }
    }

    # ── 13. Domain-Wide Delegation ───────────────────────────────────────
    if (& $needsSource 'DomainWideDelegation') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving domain-wide delegation grants'
        }
        try {
            $dwdToken = Get-GoogleAccessToken `
                -ServiceAccountKeyPath $ServiceAccountKeyPath `
                -AdminEmail $AdminEmail `
                -Scopes @('https://www.googleapis.com/auth/admin.directory.domain.readonly')

            $dwdResult = Invoke-GoogleAdminApi `
                -AccessToken $dwdToken `
                -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domainwidedelegation' `
                -Paginate `
                -ItemsProperty 'items' `
                -Quiet:$Quiet

            $data.DomainWideDelegation = @($dwdResult ?? @())
        } catch {
            $data.Errors['DomainWideDelegation'] = $_.Exception.Message
        }
    }

    # ── 14. Alert Rules ──────────────────────────────────────────────────
    if (& $needsSource 'AlertRules') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving alert rules'
        }
        try {
            $alertToken = Get-GoogleAccessToken `
                -ServiceAccountKeyPath $ServiceAccountKeyPath `
                -AdminEmail $AdminEmail `
                -Scopes @('https://www.googleapis.com/auth/apps.alerts')

            $alertResult = Invoke-GoogleAdminApi `
                -AccessToken $alertToken `
                -Uri 'https://alertcenter.googleapis.com/v1beta1/alerts' `
                -Paginate `
                -ItemsProperty 'alerts' `
                -Quiet:$Quiet

            $data.AlertRules = @($alertResult ?? @())
        } catch {
            $data.Errors['AlertRules'] = $_.Exception.Message
        }
    }

    # ── 15. Chrome Policies ──────────────────────────────────────────────
    if (& $needsSource 'ChromePolicies') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Retrieving Chrome policies'
        }
        try {
            # Resolve the customer's ROOT org-unit id dynamically — Chrome policy resolution
            # targets an OU id, which is tenant-specific and must never be hardcoded. Top-level
            # OUs carry the root OU as their parentOrgUnitId (directory API prefixes it 'id:').
            $rootOuId = $null
            try {
                $ouToken = Get-GoogleAccessToken `
                    -ServiceAccountKeyPath $ServiceAccountKeyPath `
                    -AdminEmail $AdminEmail `
                    -Scopes @('https://www.googleapis.com/auth/admin.directory.orgunit.readonly')
                $ouResp = Invoke-GoogleAdminApi `
                    -AccessToken $ouToken `
                    -Uri 'https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits?type=children&orgUnitPath=/' `
                    -Quiet:$Quiet
                $rootOuId = (@($ouResp.organizationUnits)[0].parentOrgUnitId) -replace '^id:', ''
            } catch {
                Write-Verbose "Could not resolve root OU id for Chrome policies: $_"
            }

            if (-not $rootOuId) {
                Write-Verbose 'Skipping Chrome policy resolution — root org-unit id unavailable.'
            } else {
                $chromeToken = Get-GoogleAccessToken `
                    -ServiceAccountKeyPath $ServiceAccountKeyPath `
                    -AdminEmail $AdminEmail `
                    -Scopes @('https://www.googleapis.com/auth/chrome.management.policy.readonly')

                $chromeResult = Invoke-GoogleAdminApi `
                    -AccessToken $chromeToken `
                    -Uri 'https://chromepolicy.googleapis.com/v1/customers/my_customer/policies:resolve' `
                    -Method Post `
                    -Body @{
                        policyTargetKey = @{ targetResource = "orgunits/$rootOuId" }
                        pageSize        = 1000
                    } `
                    -Paginate `
                    -ItemsProperty 'resolvedPolicies' `
                    -Quiet:$Quiet

                $data.ChromePolicies = @($chromeResult ?? @())
            }
        } catch {
            $data.Errors['ChromePolicies'] = $_.Exception.Message
        }
    }

    # ── 16. Cloud Identity policies (Workspace settings) ─────────────────
    # Powers the Gmail / Drive / Auth / Chat / Meet / Calendar / DLP / service-status
    # checks that were previously "verify in Admin Console" placeholders. Best-effort and
    # self-isolating: Get-GoogleCloudIdentityPolicies returns $null (and the dependent
    # checks stay SKIP) on a tenant that hasn't delegated the cloud-identity scope.
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Retrieving Workspace policies (Cloud Identity)'
    }
    try {
        $data.CloudIdentityPolicies = Get-GoogleCloudIdentityPolicies `
            -ServiceAccountKeyPath $ServiceAccountKeyPath `
            -AdminEmail $AdminEmail `
            -Quiet:$Quiet
        if ($data.CloudIdentityPolicies -and -not $Quiet) {
            Write-ProgressLine -Phase INFO -Message "Collected $($data.CloudIdentityPolicies.Count) Workspace policies via Cloud Identity"
        } elseif (-not $data.CloudIdentityPolicies -and -not $Quiet) {
            Write-ProgressLine -Phase INFO -Message 'Cloud Identity Policy API not available — policy-backed checks will SKIP (grant the cloud-identity.policies.readonly DWD scope to enable)'
        }
    } catch {
        $data.Errors['CloudIdentityPolicies'] = $_.Exception.Message
    }

    # ── Summary ──────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $errorCount = $data.Errors.Count
        $summary = "Collection complete: $($data.Users.Count) users, " +
                   "$($data.Groups.Count) groups, " +
                   "$($data.Tenant.Domains.Count) domains"
        if ($errorCount -gt 0) {
            $summary += " ($errorCount errors)"
        }
        Write-ProgressLine -Phase AUDITING -Message $summary
    }

    return $data
}
