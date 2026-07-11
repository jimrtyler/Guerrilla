# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-Safehouse {
    <#
    .SYNOPSIS
        Tests live connectivity for all configured environments.
    .DESCRIPTION
        Validates stored credentials by authenticating and making minimal API
        calls to Google Workspace, Microsoft Graph, and Active Directory.
        Shows actionable remediation guidance for any failures.
    .PARAMETER ConfigFile
        Path to guerrilla-config.json to determine which environments to test.
    .PARAMETER VaultName
        Name of the SecretManagement vault. Default: Guerrilla.
    .EXAMPLE
        Test-Safehouse -ConfigFile .\guerrilla-config.json
    #>
    [CmdletBinding()]
    param(
        [Alias('MissionConfig')]
        [string]$ConfigFile,
        [string]$VaultName = 'Guerrilla'
    )

    # ── Colors ──────────────────────────────────────────────────────────────
    $amber = $script:Palette.Amber
    $green = $script:Palette.Sage
    $red   = $script:Palette.Red
    $white = $script:Palette.Parchment
    $khaki = $script:Palette.Khaki
    $reset = $PSStyle.Reset

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:passCount = 0
    $script:totalCount = 0

    # ── Resolve config ──────────────────────────────────────────────────────
    $missionCfg = $null
    $enabledEnvs = @{}
    if ($ConfigFile) {
        $missionCfg = Read-MissionConfig -Path $ConfigFile
        $enabledEnvs = $missionCfg.EnabledEnvironments
        $vaultName = $missionCfg.VaultName
    }

    # ── Helper: Write a test result line ────────────────────────────────────
    function Write-TestResult {
        param(
            [string]$Name,
            [string]$Status,
            [long]$ElapsedMs,
            [string]$Detail,
            [string]$Environment,
            [string[]]$Remediation
        )

        $statusColor = if ($Status -in @('CONNECTED', 'VALID', 'STORED', 'KERBEROS')) { $green } else { $red }
        $statusIcon  = if ($Status -in @('CONNECTED', 'VALID', 'STORED', 'KERBEROS')) { [char]0x2713 } else { [char]0x2717 }
        $elapsed     = "${ElapsedMs}ms"
        $nameShort   = if ($Name.Length -gt 24) { $Name.Substring(0, 21) + '...' } else { $Name }
        $detailShort = if ($Detail.Length -gt 30) { $Detail.Substring(0, 27) + '...' } else { $Detail }

        Write-Host "  ${statusColor}${statusIcon} $(($nameShort).PadRight(25)) $(($Status).PadRight(12)) $(($elapsed).PadRight(8)) ${detailShort}${reset}"

        if ($Remediation -and $Status -notin @('CONNECTED', 'VALID', 'STORED', 'KERBEROS')) {
            foreach ($fix in $Remediation) {
                Write-Host "    ${amber}$([char]0x21B3) ${fix}${reset}"
            }
        }

        $script:totalCount++
        if ($Status -in @('CONNECTED', 'VALID', 'STORED', 'KERBEROS')) { $script:passCount++ }

        $results.Add([PSCustomObject]@{
            Environment = $Environment
            Name        = $Name
            Status      = $Status
            Detail      = $Detail
            ElapsedMs   = $ElapsedMs
        })
    }

    # ── Header ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host "  ${white}SAFEHOUSE CONNECTIVITY TEST${reset}"
    Write-Host "  ${khaki}$("$([char]0x2500)" * 58)${reset}"

    # ════════════════════════════════════════════════════════════════════════
    # GOOGLE WORKSPACE
    # ════════════════════════════════════════════════════════════════════════
    $testGws = if ($missionCfg) { $enabledEnvs.ContainsKey('googleWorkspace') } else { $true }
    if ($testGws) {
        Write-Host ''
        Write-Host "  ${white}Google Workspace${reset}"

        $gwsRef = if ($missionCfg) { $missionCfg.Config.credentials.references.googleWorkspace } else { $null }
        $saVaultKey = if ($gwsRef) { $gwsRef.vaultKey } else { 'GUERRILLA_GWS_SA' }
        $adminEmailKey = "${saVaultKey}_ADMIN_EMAIL"

        # Step 1: Service Account JSON
        $saJson = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $saJson = Get-GuerrillaCredential -VaultKey $saVaultKey -VaultName $VaultName
            $sa = $saJson | ConvertFrom-Json
            $sw.Stop()
            Write-TestResult -Name 'Service Account JSON' -Status 'STORED' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail $sa.client_email -Environment 'Google Workspace'
        } catch {
            $sw.Stop()
            Write-TestResult -Name 'Service Account JSON' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Google Workspace' `
                -Remediation @('Run Set-Safehouse to store your service account key')
        }

        # Step 2: Admin Email
        $adminEmail = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $adminEmail = Get-GuerrillaCredential -VaultKey $adminEmailKey -VaultName $VaultName
            $sw.Stop()
            Write-TestResult -Name 'Admin Email' -Status 'STORED' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail $adminEmail -Environment 'Google Workspace'
        } catch {
            $sw.Stop()
            Write-TestResult -Name 'Admin Email' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Google Workspace' `
                -Remediation @(
                    'Run Set-Safehouse to store admin email'
                    'Must be a Super Admin in your Workspace domain'
                )
        }

        # Step 3: Authentication
        if ($saJson -and $adminEmail) {
            $tempSaPath = $null
            try {
                $tempSaPath = Join-Path ([System.IO.Path]::GetTempPath()) "guerrilla-test-sa-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
                $saJson | Set-Content -Path $tempSaPath -Encoding UTF8 -NoNewline

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $accessToken = Get-GoogleAccessToken -ServiceAccountKeyPath $tempSaPath `
                    -AdminEmail $adminEmail `
                    -Scopes @('https://www.googleapis.com/auth/admin.directory.user.readonly') `
                    -ForceRefresh
                $sw.Stop()

                Write-TestResult -Name 'Authentication' -Status 'CONNECTED' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail 'Token acquired' -Environment 'Google Workspace'

                # Step 4: API Access
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $userCheck = Invoke-GoogleAdminApi -AccessToken $accessToken `
                        -Uri 'https://admin.googleapis.com/admin/directory/v1/users' `
                        -QueryParameters @{ customer = 'my_customer'; maxResults = '1' } -Quiet
                    $sw.Stop()
                    $tenantDomain = if ($userCheck.users -and $userCheck.users[0].primaryEmail) {
                        ($userCheck.users[0].primaryEmail -split '@')[1]
                    } else { 'OK' }
                    Write-TestResult -Name 'API Access' -Status 'CONNECTED' -ElapsedMs $sw.ElapsedMilliseconds `
                        -Detail $tenantDomain -Environment 'Google Workspace'
                } catch {
                    $sw.Stop()
                    $errMsg = $_.Exception.Message
                    $fixes = @('Service account may be missing required scopes in domain-wide delegation')
                    if ($errMsg -match '403') {
                        $clientId = $null
                        try { $clientId = ($saJson | ConvertFrom-Json).client_id } catch {}
                        $fixes = @(
                            'Missing scopes in domain-wide delegation'
                            'admin.google.com > Security > API controls > Manage Domain Wide Delegation'
                        )
                        if ($clientId) { $fixes += "Client ID: $clientId" }
                        $fixes += 'Required scopes: admin.directory.*, gmail.*, apps.alerts, chrome.management.policy.readonly'
                    }
                    Write-TestResult -Name 'API Access' -Status 'FAILED' -ElapsedMs $sw.ElapsedMilliseconds `
                        -Detail ($errMsg.Substring(0, [Math]::Min(60, $errMsg.Length))) -Environment 'Google Workspace' `
                        -Remediation $fixes
                }
            } catch {
                $sw.Stop()
                $errMsg = "$($_.Exception.Message)"
                $fixes = @()

                if ($errMsg -match 'unauthorized_client') {
                    $clientId = $null
                    try { $clientId = ($saJson | ConvertFrom-Json).client_id } catch {}
                    $fixes = @(
                        'Domain-wide delegation not configured or not yet propagated'
                        'admin.google.com > Security > API controls > Manage Domain Wide Delegation'
                    )
                    if ($clientId) {
                        $fixes += "Add Client ID: $clientId with required OAuth scopes"
                    }
                    $fixes += 'Changes may take up to 1 hour to propagate'
                } elseif ($errMsg -match 'invalid_grant') {
                    $fixes = @(
                        'Verify admin email is a Super Admin in your Workspace domain'
                        'admin.google.com > Directory > Users > check admin role'
                    )
                } else {
                    $fixes = @("Error: $($errMsg.Substring(0, [Math]::Min(80, $errMsg.Length)))")
                }

                Write-TestResult -Name 'Authentication' -Status 'FAILED' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail 'Token request failed' -Environment 'Google Workspace' `
                    -Remediation $fixes
            } finally {
                if ($tempSaPath -and (Test-Path $tempSaPath)) {
                    Remove-Item -Path $tempSaPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # ════════════════════════════════════════════════════════════════════════
    # MICROSOFT CLOUD (Graph + ARM)
    # ════════════════════════════════════════════════════════════════════════
    $testCloud = if ($missionCfg) {
        $enabledEnvs.ContainsKey('entraAzure') -or $enabledEnvs.ContainsKey('m365') -or $enabledEnvs.ContainsKey('intune')
    } else { $true }

    if ($testCloud) {
        Write-Host ''
        Write-Host "  ${white}Microsoft Cloud${reset}"

        $graphRef = if ($missionCfg) { $missionCfg.Config.credentials.references.microsoftGraph } else { $null }
        $tenantKey  = if ($graphRef) { $graphRef.tenantIdVaultKey } else { 'GUERRILLA_GRAPH_TENANT' }
        $clientKey  = if ($graphRef) { $graphRef.clientIdVaultKey } else { 'GUERRILLA_GRAPH_CLIENTID' }
        $secretKey  = if ($graphRef) { $graphRef.vaultKey } else { 'GUERRILLA_GRAPH_SECRET' }

        # Step 1: Tenant ID
        $tenantId = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $tenantId = Get-GuerrillaCredential -VaultKey $tenantKey -VaultName $VaultName
            $sw.Stop()
            if ($tenantId -match '^[0-9a-fA-F]{8}-') {
                $display = $tenantId.Substring(0, 13) + '...'
                Write-TestResult -Name 'Tenant ID' -Status 'VALID' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail $display -Environment 'Microsoft Cloud'
            } else {
                Write-TestResult -Name 'Tenant ID' -Status 'INVALID' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail 'Not a valid GUID' -Environment 'Microsoft Cloud' `
                    -Remediation @('Azure Portal > Microsoft Entra ID > Overview > Tenant ID')
            }
        } catch {
            $sw.Stop()
            Write-TestResult -Name 'Tenant ID' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Microsoft Cloud' `
                -Remediation @('Run Set-Safehouse to store Tenant ID')
        }

        # Step 2: Client ID
        $clientId = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $clientId = Get-GuerrillaCredential -VaultKey $clientKey -VaultName $VaultName
            $sw.Stop()
            if ($clientId -match '^[0-9a-fA-F]{8}-') {
                $display = $clientId.Substring(0, 13) + '...'
                Write-TestResult -Name 'Client ID' -Status 'VALID' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail $display -Environment 'Microsoft Cloud'
            } else {
                Write-TestResult -Name 'Client ID' -Status 'INVALID' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail 'Not a valid GUID' -Environment 'Microsoft Cloud' `
                    -Remediation @('Azure Portal > App registrations > your app > Overview')
            }
        } catch {
            $sw.Stop()
            Write-TestResult -Name 'Client ID' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Microsoft Cloud' `
                -Remediation @('Run Set-Safehouse to store Client ID')
        }

        # Step 3: Client Secret
        $clientSecret = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $secretPlain = Get-GuerrillaCredential -VaultKey $secretKey -VaultName $VaultName
            $clientSecret = $secretPlain | ConvertTo-SecureString -AsPlainText -Force
            $sw.Stop()
            Write-TestResult -Name 'Client Secret' -Status 'STORED' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Microsoft Cloud'
        } catch {
            $sw.Stop()
            Write-TestResult -Name 'Client Secret' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Microsoft Cloud' `
                -Remediation @(
                    'Run Set-Safehouse to store client secret'
                    'Copy the VALUE, not the Secret ID'
                )
        }

        # Step 4: Authentication
        if ($tenantId -and $clientId -and $clientSecret) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $graphToken = $null
            try {
                $graphToken = Get-GraphAccessToken -TenantId $tenantId -ClientId $clientId `
                    -ClientSecret $clientSecret -ForceRefresh
                $sw.Stop()

                Write-TestResult -Name 'Authentication' -Status 'CONNECTED' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail 'Token acquired' -Environment 'Microsoft Cloud'

                # Step 5: API Access
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $org = Invoke-GraphApi -AccessToken $graphToken -Uri '/organization' -Quiet
                    $sw.Stop()
                    $orgName = if ($org.value -and $org.value[0].displayName) {
                        $org.value[0].displayName
                    } elseif ($org.displayName) {
                        $org.displayName
                    } else { 'OK' }
                    Write-TestResult -Name 'API Access' -Status 'CONNECTED' -ElapsedMs $sw.ElapsedMilliseconds `
                        -Detail $orgName -Environment 'Microsoft Cloud'
                } catch {
                    $sw.Stop()
                    $apiErr = "$($_.Exception.Message)"
                    $apiErrShort = if ($apiErr.Length -gt 60) { $apiErr.Substring(0, 57) + '...' } else { $apiErr }
                    Write-TestResult -Name 'API Access' -Status 'FAILED' -ElapsedMs $sw.ElapsedMilliseconds `
                        -Detail $apiErrShort -Environment 'Microsoft Cloud' `
                        -Remediation @(
                            'Add Application permissions (not Delegated) with admin consent:'
                            'Directory.Read.All, Policy.Read.All, Application.Read.All'
                            'RoleManagement.Read.All, Reports.Read.All, AuditLog.Read.All'
                            'DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All'
                            'DeviceManagementManagedDevices.Read.All'
                            'Azure Portal > App registrations > API permissions > Grant admin consent'
                        )
                }
            } catch {
                $sw.Stop()
                $errMsg = "$($_.Exception.Message)"
                $fixes = @()

                if ($errMsg -match 'invalid_client' -or $errMsg -match 'AADSTS7000215') {
                    $fixes = @(
                        'Invalid client secret — you may have stored the Secret ID instead of the Value'
                        'Azure Portal > App registrations > Certificates & secrets'
                        'Create a New client secret > copy the VALUE column'
                    )
                } elseif ($errMsg -match 'AADSTS90002' -or $errMsg -match 'not found') {
                    $fixes = @(
                        'Tenant not found — verify Tenant ID'
                        'Azure Portal > Microsoft Entra ID > Overview > Tenant ID'
                    )
                } elseif ($errMsg -match 'AADSTS700016') {
                    $fixes = @(
                        'Application not found — verify Client ID'
                        'Azure Portal > App registrations > your app > Overview'
                    )
                } else {
                    $fixes = @("Error: $($errMsg.Substring(0, [Math]::Min(100, $errMsg.Length)))")
                }

                Write-TestResult -Name 'Authentication' -Status 'FAILED' -ElapsedMs $sw.ElapsedMilliseconds `
                    -Detail 'Token request failed' -Environment 'Microsoft Cloud' `
                    -Remediation $fixes
            }
        }
    }

    # ════════════════════════════════════════════════════════════════════════
    # ACTIVE DIRECTORY
    # ════════════════════════════════════════════════════════════════════════
    $testAD = if ($missionCfg) { $enabledEnvs.ContainsKey('activeDirectory') } else { $true }
    if ($testAD) {
        Write-Host ''
        Write-Host "  ${white}Active Directory${reset}"

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $sw.Stop()
            Write-TestResult -Name 'Domain Connectivity' -Status 'CONNECTED' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail $domain.Name -Environment 'Active Directory'
        } catch {
            $sw.Stop()
            $errMsg = "$($_.Exception.Message)"
            $fixes = @()
            if ($errMsg -match 'not joined' -or $errMsg -match 'cannot contact') {
                $fixes = @('This machine is not joined to a domain or cannot reach a DC')
            } else {
                $fixes = @(
                    'Verify domain connectivity and Kerberos ticket'
                    'Run: klist to check your current tickets'
                )
            }
            Write-TestResult -Name 'Domain Connectivity' -Status 'FAILED' -ElapsedMs $sw.ElapsedMilliseconds `
                -Detail '' -Environment 'Active Directory' `
                -Remediation $fixes
        }
    }

    # ════════════════════════════════════════════════════════════════════════
    # ALERTING
    # ════════════════════════════════════════════════════════════════════════
    $testAlerting = $false
    $alertChannels = @()
    if ($missionCfg -and $missionCfg.Config.alerting -and $missionCfg.Config.alerting.channels) {
        $alertChannels = @($missionCfg.Config.alerting.channels)
        $testAlerting = $alertChannels.Count -gt 0
    }

    if ($testAlerting) {
        Write-Host ''
        Write-Host "  ${white}Alerting${reset}"

        foreach ($channel in $alertChannels) {
            if ($channel.type -eq 'pushover' -and $channel.vaultKey) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $pushCfgJson = Get-GuerrillaCredential -VaultKey $channel.vaultKey -VaultName $VaultName
                    $pushCfg = $pushCfgJson | ConvertFrom-Json
                    $sw.Stop()

                    if ($pushCfg.apiToken -and $pushCfg.userKey) {
                        $maskedUser = $pushCfg.userKey.Substring(0, [Math]::Min(6, $pushCfg.userKey.Length)) + '...'
                        Write-TestResult -Name 'Pushover Configuration' -Status 'VALID' -ElapsedMs $sw.ElapsedMilliseconds `
                            -Detail "User: $maskedUser" -Environment 'Alerting'

                        # Live push notification test
                        $swPush = [System.Diagnostics.Stopwatch]::StartNew()
                        try {
                            $sendResult = Send-SignalPushover `
                                -ApiToken $pushCfg.apiToken `
                                -UserKey $pushCfg.userKey `
                                -Message 'Safehouse signal test — push notifications operational.' `
                                -Title 'Guerrilla Signal Test' `
                                -Priority -1 `
                                -Sound 'pushover'
                            $swPush.Stop()

                            if ($sendResult.Success) {
                                Write-TestResult -Name 'Pushover Delivery' -Status 'CONNECTED' -ElapsedMs $swPush.ElapsedMilliseconds `
                                    -Detail 'Test notification sent' -Environment 'Alerting'
                            } else {
                                Write-TestResult -Name 'Pushover Delivery' -Status 'FAILED' -ElapsedMs $swPush.ElapsedMilliseconds `
                                    -Detail ($sendResult.Error ?? 'Unknown error') -Environment 'Alerting' `
                                    -Remediation @(
                                        'Verify your Pushover API token at pushover.net > Your Applications'
                                        'Verify your user key on the Pushover dashboard'
                                    )
                            }
                        } catch {
                            $swPush.Stop()
                            Write-TestResult -Name 'Pushover Delivery' -Status 'FAILED' -ElapsedMs $swPush.ElapsedMilliseconds `
                                -Detail $_.Exception.Message -Environment 'Alerting' `
                                -Remediation @(
                                    'Verify Pushover API token and user key'
                                    'Run Set-Safehouse -Force to reconfigure Pushover'
                                )
                        }
                    } else {
                        Write-TestResult -Name 'Pushover Configuration' -Status 'INVALID' -ElapsedMs $sw.ElapsedMilliseconds `
                            -Detail 'Missing apiToken or userKey' -Environment 'Alerting' `
                            -Remediation @('Re-run Set-Safehouse to configure Pushover')
                    }
                } catch {
                    $sw.Stop()
                    Write-TestResult -Name 'Pushover Configuration' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                        -Detail '' -Environment 'Alerting' `
                        -Remediation @('Run Set-Safehouse to configure Pushover alerting')
                }
            }
            if ($channel.type -eq 'email' -and $channel.vaultKey) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $emailCfgJson = Get-GuerrillaCredential -VaultKey $channel.vaultKey -VaultName $VaultName
                    $emailCfg = $emailCfgJson | ConvertFrom-Json
                    $sw.Stop()

                    if ($emailCfg.fromEmail -and $emailCfg.toEmails) {
                        $providerLabel = if ($emailCfg.provider) { $emailCfg.provider } else { 'email' }
                        Write-TestResult -Name 'Email Configuration' -Status 'VALID' -ElapsedMs $sw.ElapsedMilliseconds `
                            -Detail "$providerLabel — $($emailCfg.fromEmail)" -Environment 'Alerting'

                        # Live email delivery test
                        $swSend = [System.Diagnostics.Stopwatch]::StartNew()
                        try {
                            $testSubject = "Guerrilla Signal Test — $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
                            $testHtml = @"
<div style="font-family: Consolas, monospace; background: #1a1a1a; color: #c6a61f; padding: 24px; border: 1px solid #3a3a3a;">
<h2 style="margin-top:0; color: #f5f0e6;">SAFEHOUSE SIGNAL TEST</h2>
<p>Email delivery is operational.</p>
<p style="color: #8b8b7a; font-size: 12px;">Sent by Test-Safehouse at $(Get-Date -Format 'o')</p>
</div>
"@
                            if ($emailCfg.provider -eq 'mailgun') {
                                $mgDomain = if ($emailCfg.domain) { $emailCfg.domain }
                                            elseif ($emailCfg.fromEmail -match '@(.+)$') { $Matches[1] }
                                            else { $null }
                                if (-not $mgDomain) { throw 'Mailgun domain not configured' }
                                $sendResult = Send-SignalMailgun `
                                    -ApiKey $emailCfg.apiKey `
                                    -Domain $mgDomain `
                                    -FromEmail $emailCfg.fromEmail `
                                    -ToEmails @($emailCfg.toEmails) `
                                    -Subject $testSubject `
                                    -HtmlBody $testHtml
                            } else {
                                $sendResult = Send-SignalSendGrid `
                                    -ApiKey $emailCfg.apiKey `
                                    -FromEmail $emailCfg.fromEmail `
                                    -ToEmails @($emailCfg.toEmails) `
                                    -Subject $testSubject `
                                    -HtmlBody $testHtml
                            }
                            $swSend.Stop()

                            if ($sendResult.Success) {
                                Write-TestResult -Name 'Email Delivery' -Status 'CONNECTED' -ElapsedMs $swSend.ElapsedMilliseconds `
                                    -Detail "Test email sent to $($emailCfg.toEmails -join ', ')" -Environment 'Alerting'
                            } else {
                                Write-TestResult -Name 'Email Delivery' -Status 'FAILED' -ElapsedMs $swSend.ElapsedMilliseconds `
                                    -Detail ($sendResult.Error ?? 'Unknown error') -Environment 'Alerting' `
                                    -Remediation @(
                                        "Verify your $providerLabel API key is valid"
                                        "Check sending domain is verified in $providerLabel dashboard"
                                    )
                            }
                        } catch {
                            $swSend.Stop()
                            Write-TestResult -Name 'Email Delivery' -Status 'FAILED' -ElapsedMs $swSend.ElapsedMilliseconds `
                                -Detail $_.Exception.Message -Environment 'Alerting' `
                                -Remediation @(
                                    "Verify your $providerLabel API key and sending domain"
                                    "Run Set-Safehouse -Force to reconfigure email"
                                )
                        }
                    } else {
                        Write-TestResult -Name 'Email Configuration' -Status 'INVALID' -ElapsedMs $sw.ElapsedMilliseconds `
                            -Detail 'Missing fromEmail or toEmails' -Environment 'Alerting' `
                            -Remediation @('Re-run Set-Safehouse to configure email settings')
                    }
                } catch {
                    $sw.Stop()
                    Write-TestResult -Name 'Email Configuration' -Status 'MISSING' -ElapsedMs $sw.ElapsedMilliseconds `
                        -Detail '' -Environment 'Alerting' `
                        -Remediation @('Run Set-Safehouse to configure email alerting')
                }
            }
        }
    }

    # ── Summary ─────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host "  ${khaki}$("$([char]0x2500)" * 58)${reset}"
    $summaryColor = if ($script:passCount -eq $script:totalCount) { $green } else { $amber }
    Write-Host "  ${summaryColor}Result: $($script:passCount)/$($script:totalCount) checks passed${reset}"
    Write-Host ''

    # Return structured results
    return $results
}
