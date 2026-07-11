
# --- Module import helper ---

function Import-Guerrilla {
    $modulePath = (Resolve-Path (Join-Path $PSScriptRoot '../../source/Guerrilla.psm1')).Path
    $env:PSGUERRILLA_QUIET = '1'
    $env:PSGUERRILLA_TEST = '1'
    Import-Module $modulePath -Force -DisableNameChecking -Global
}

# --- Mock data factories ---

function New-MockLoginEvent {
    param(
        [string]$User = 'user@example.com',
        [string]$IpAddress = '1.2.3.4',
        [string]$EventName = 'login_success',
        [string]$LoginType = 'exchange',
        [string]$Timestamp = '2026-01-15T10:30:00.000Z',
        [string]$Source = 'login'
    )
    @{
        Timestamp = $Timestamp
        User      = $User
        EventName = $EventName
        IpAddress = $IpAddress
        Source    = $Source
        Params    = @{
            login_type = $LoginType
        }
    }
}

function New-MockTokenEvent {
    param(
        [string]$User = 'user@example.com',
        [string]$IpAddress = '1.2.3.4',
        [string]$EventName = 'authorize',
        [string]$AppName = 'SomeApp',
        [string]$Timestamp = '2026-01-15T10:30:00.000Z',
        [string]$Source = 'token'
    )
    @{
        Timestamp = $Timestamp
        User      = $User
        EventName = $EventName
        IpAddress = $IpAddress
        Source    = $Source
        Params    = @{
            app_name = $AppName
        }
    }
}

function New-MockAdminEvent {
    param(
        [string]$User = 'admin@example.com',
        [string]$EventName = 'CHANGE_PASSWORD',
        [string]$TargetUser = 'user@example.com',
        [string]$Timestamp = '2026-01-15T12:00:00.000Z'
    )
    @{
        Timestamp = $Timestamp
        User      = $User
        EventName = $EventName
        IpAddress = ''
        Source    = 'admin'
        Params    = @{
            USER_EMAIL = $TargetUser
        }
    }
}

function New-MockScanResult {
    param(
        [PSCustomObject[]]$FlaggedUsers = @(),
        [PSCustomObject[]]$NewThreats = @(),
        [int]$TotalUsersScanned = 100,
        [int]$TotalEventsAnalyzed = 5000
    )
    [PSCustomObject]@{
        PSTypeName          = 'Guerrilla.ScanResult'
        ScanId              = [guid]::NewGuid().ToString()
        Timestamp           = [datetime]::UtcNow
        DaysAnalyzed        = 30
        ScanMode            = 'Fast'
        TotalUsersScanned   = $TotalUsersScanned
        TotalEventsAnalyzed = $TotalEventsAnalyzed
        CriticalCount       = @($FlaggedUsers | Where-Object ThreatLevel -eq 'CRITICAL').Count
        HighCount           = @($FlaggedUsers | Where-Object ThreatLevel -eq 'HIGH').Count
        MediumCount         = @($FlaggedUsers | Where-Object ThreatLevel -eq 'MEDIUM').Count
        LowCount            = @($FlaggedUsers | Where-Object ThreatLevel -eq 'LOW').Count
        CleanCount          = $TotalUsersScanned - $FlaggedUsers.Count
        FlaggedUsers        = $FlaggedUsers
        NewThreats          = $NewThreats
        CsvReportPath       = $null
        HtmlReportPath      = $null
        JsonAlertPath       = $null
        AllProfiles         = @{}
    }
}

function New-MockUserProfile {
    param(
        [string]$Email = 'user@example.com',
        [string]$ThreatLevel = 'HIGH',
        [double]$ThreatScore = 60,
        [string[]]$Indicators = @('KNOWN ATTACKER IP - 1 login(s) from 1 known attacker IP(s)'),
        [bool]$IsKnownCompromised = $false,
        [bool]$WasRemediated = $false
    )
    [PSCustomObject]@{
        PSTypeName              = 'Guerrilla.UserProfile'
        Email                   = $Email
        ThreatLevel             = $ThreatLevel
        ThreatScore             = $ThreatScore
        IsKnownCompromised      = $IsKnownCompromised
        WasRemediated           = $WasRemediated
        Indicators              = $Indicators
        KnownAttackerIpLogins   = [System.Collections.Generic.List[PSCustomObject]]::new()
        CloudIpLogins           = [System.Collections.Generic.List[PSCustomObject]]::new()
        ReauthFromCloud         = [System.Collections.Generic.List[PSCustomObject]]::new()
        RiskyActions            = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousCountryLogins = [System.Collections.Generic.List[PSCustomObject]]::new()
        SuspiciousOAuthGrants   = [System.Collections.Generic.List[PSCustomObject]]::new()
        IpClassifications       = @{}
        TotalLoginEvents        = 10
        LoginEvents             = @()
        TokenEvents             = @()
        AccountEvents           = @()
    }
}

function New-MockConfig {
    param(
        [string]$OutputDir = (Join-Path $TestDrive 'Reports')
    )
    @{
        google = @{
            serviceAccountKeyPath = 'C:\fake\sa-key.json'
            adminEmail            = 'admin@example.com'
            defaultDaysBack       = 30
            defaultScanMode       = 'Fast'
        }
        output = @{
            directory    = $OutputDir
            generateCsv  = $true
            generateHtml = $true
            generateJson = $true
        }
        alerting = @{
            enabled            = $true
            minimumThreatLevel = 'HIGH'
            providers          = @{
                sendgrid = @{ enabled = $false; apiKey = ''; fromEmail = ''; fromName = 'Guerrilla Signals'; toEmails = @() }
                mailgun  = @{ enabled = $false; apiKey = ''; domain = ''; fromEmail = ''; toEmails = @() }
                twilio   = @{ enabled = $false; accountSid = ''; authToken = ''; fromNumber = ''; toNumbers = @() }
            }
        }
        detection = @{
            knownCompromisedUsers        = @()
            additionalAttackerIps        = @()
            additionalCloudCidrs         = @()
            additionalSuspiciousCountries = @()
        }
        scheduling = @{
            taskName        = 'Guerrilla-Patrol'
            intervalMinutes = 60
        }
    }
}

# --- Audit engine mock factories ---

function New-MockAuditFinding {
    param(
        [string]$CheckId = 'AUTH-001',
        [string]$CheckName = '2SV Enforcement',
        [string]$Category = 'Authentication',
        [string]$Subcategory = 'Multi-Factor Authentication',
        [string]$Severity = 'Critical',
        [string]$Status = 'FAIL',
        [string]$Description = 'Two-step verification is not enforced',
        [string]$CurrentValue = 'Not enforced',
        [string]$RecommendedValue = 'Enforced for all OUs',
        [string]$OrgUnitPath = '/',
        [string]$RemediationUrl = 'https://admin.google.com/ac/security/2sv',
        [string]$RemediationSteps = 'Enable 2SV enforcement',
        [hashtable]$Compliance = @{ NistSp80053 = @('IA-2(1)'); MitreAttack = @('T1078'); CisBenchmark = @('1.1') },
        [hashtable]$Details = @{}
    )
    [PSCustomObject]@{
        PSTypeName       = 'Guerrilla.AuditFinding'
        CheckId          = $CheckId
        CheckName        = $CheckName
        Category         = $Category
        Subcategory      = $Subcategory
        Severity         = $Severity
        Status           = $Status
        Description      = $Description
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        OrgUnitPath      = $OrgUnitPath
        RemediationUrl   = $RemediationUrl
        RemediationSteps = $RemediationSteps
        Compliance       = $Compliance
        Details          = $Details
        Timestamp        = [datetime]::UtcNow
    }
}

function New-MockAuditData {
    param(
        [string]$Domain = 'example.com',
        [int]$UserCount = 50,
        [int]$AdminCount = 3,
        [double]$TwoSvEnrollmentRate = 0.8
    )
    $users = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($i = 0; $i -lt $UserCount; $i++) {
        $isAdmin = $i -lt $AdminCount
        $enrolled = $i -lt [Math]::Floor($UserCount * $TwoSvEnrollmentRate)
        $users.Add([PSCustomObject]@{
            primaryEmail       = "user$i@$Domain"
            isAdmin            = $isAdmin
            suspended          = $false
            isEnrolledIn2Sv    = $enrolled
            isEnforcedIn2Sv    = $false
            lastLoginTime      = [datetime]::UtcNow.AddDays(-($i % 60)).ToString('o')
            creationTime       = '2025-01-01T00:00:00.000Z'
            orgUnitPath        = '/'
            agreedToTerms      = $true
            archived           = $false
            recoveryEmail      = if ($i % 3 -eq 0) { "recovery$i@gmail.com" } else { $null }
            recoveryPhone      = if ($i % 4 -eq 0) { '+1555000' + $i.ToString('D4') } else { $null }
        })
    }

    @{
        Tenant = @{
            CustomerId = 'C00000000'
            Domain     = $Domain
            Domains    = @([PSCustomObject]@{ domainName = $Domain; isPrimary = $true; verified = $true })
            OrgUnits   = @([PSCustomObject]@{ orgUnitPath = '/'; name = $Domain; parentOrgUnitPath = '' })
        }
        Users         = @($users)
        Groups        = @()
        Roles         = @()
        RoleAssignments = @()
        MobileDevices = @()
        ChromeDevices = @()
        DnsRecords    = @{
            $Domain = @{
                SPF   = @{ Record = "v=spf1 include:_spf.google.com ~all"; Valid = $true }
                DKIM  = @{ Record = ''; Valid = $false; Selector = 'google' }
                DMARC = @{ Record = ''; Valid = $false }
                MTASTS = @{ Record = ''; Valid = $false }
            }
        }
        GmailSettings = @{}
        OrgUnitPolicies = @{
            '/' = @{}
        }
        AlertRules    = @()
        ChromePolicies = @()
        OAuthApps     = @()
        DomainWideDelegation = @()
        Errors        = @{}
    }
}

function New-MockAuditResult {
    param(
        [PSCustomObject[]]$Findings = @(),
        [string]$Domain = 'example.com',
        [int]$OverallScore = 72,
        [string]$ScoreLabel = 'CONTESTED PERIMETER'
    )
    $critCount = @($Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'FAIL' }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq 'High' -and $_.Status -eq 'FAIL' }).Count
    $medCount  = @($Findings | Where-Object { $_.Severity -eq 'Medium' -and $_.Status -eq 'FAIL' }).Count
    $lowCount  = @($Findings | Where-Object { $_.Severity -eq 'Low' -and $_.Status -eq 'FAIL' }).Count
    [PSCustomObject]@{
        PSTypeName     = 'Guerrilla.AuditResult'
        ScanId         = [guid]::NewGuid().ToString()
        Timestamp      = [datetime]::UtcNow
        TenantDomain   = $Domain
        OverallScore   = $OverallScore
        ScoreLabel     = $ScoreLabel
        CategoryScores = @{}
        TotalChecks    = $Findings.Count
        PassCount      = @($Findings | Where-Object Status -eq 'PASS').Count
        FailCount      = @($Findings | Where-Object Status -eq 'FAIL').Count
        WarnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
        SkipCount      = @($Findings | Where-Object Status -eq 'SKIP').Count
        CriticalCount  = $critCount
        HighCount      = $highCount
        MediumCount    = $medCount
        LowCount       = $lowCount
        Findings       = $Findings
        Delta          = $null
        HtmlReportPath = $null
        CsvReportPath  = $null
        JsonReportPath = $null
    }
}

function New-MockCheckDefinition {
    param(
        [string]$Id = 'AUTH-001',
        [string]$Name = '2SV Enforcement',
        [string]$Severity = 'Critical',
        [string]$CategoryName = 'Authentication',
        [string]$Subcategory = 'Multi-Factor Authentication',
        [string]$Description = 'Two-step verification should be enforced',
        [string]$RecommendedValue = 'Enforced',
        [string]$RemediationUrl = 'https://admin.google.com/ac/security/2sv',
        [string]$RemediationSteps = 'Enable 2SV',
        [hashtable]$Compliance = @{ nistSp80053 = @('IA-2(1)'); mitreAttack = @('T1078'); cisBenchmark = @('1.1') }
    )
    @{
        id               = $Id
        name             = $Name
        severity         = $Severity
        _categoryName    = $CategoryName
        subcategory      = $Subcategory
        description      = $Description
        recommendedValue = $RecommendedValue
        remediationUrl   = $RemediationUrl
        remediationSteps = $RemediationSteps
        compliance       = $Compliance
    }
}

# --- Golden-fixture helpers (shared by the Pester suite and the publisher) ---

# Build the table-driven case list from the JSON fixtures under Tests/Fixtures/,
# pairing each fixture with the REAL check definition from Data/AuditChecks/.
function Get-GuerrillaFixtureCases {
    $repoRoot    = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $fixtureRoot = Join-Path $repoRoot 'Tests' 'Fixtures'
    $dataDir     = Join-Path $repoRoot 'source' 'Data' 'AuditChecks'

    $defIndex = @{}
    foreach ($file in Get-ChildItem -Path $dataDir -Filter *.json) {
        $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -AsHashtable
        foreach ($check in @($json.checks)) {
            if ($check.id) {
                $check['_categoryName'] = $json.categoryName
                $defIndex[$check.id] = $check
            }
        }
    }

    $theaterPrefix = @{
        AD              = 'Test-Recon'
        Entra           = 'Test-Infiltration'
        GoogleWorkspace = 'Test-Fortification'
    }

    $cases = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($file in Get-ChildItem -Path $fixtureRoot -Filter *.json -Recurse) {
        $raw    = Get-Content -Path $file.FullName -Raw
        $fx     = $raw | ConvertFrom-Json -AsHashtable
        $family = Split-Path (Split-Path $file.FullName -Parent) -Leaf

        # Most checks read nested data via hashtable indexing, so -AsHashtable is right.
        # But the Google CloudIdentity resolver (Resolve-GooglePolicyValue) inspects fields
        # via .PSObject.Properties, which only sees PSCustomObject members — matching the
        # live collector's shape. objectShape fixtures load as PSCustomObject, then coerce
        # the top level / Errors / CloudIdentityPolicies.ByType back to hashtables (which
        # ARE index-accessed) while leaving the policy value objects as PSCustomObjects.
        $auditData = $fx.auditData
        if ($fx.objectShape) {
            $auditData = ConvertTo-MixedAuditData ($raw | ConvertFrom-Json).auditData
        }

        # EIDSCA controls have no per-ID function; they all run through the data-driven
        # dispatcher Invoke-EntraEidscaChecks (which calls Resolve-EidscaControl per control).
        $fn = if ($fx.checkId -like 'EIDSCA-*') {
            'Invoke-EntraEidscaChecks'
        } else {
            "$($theaterPrefix[$family])$($fx.checkId -replace '-','')"
        }

        $cases.Add(@{
            CheckId        = $fx.checkId
            Scenario       = $fx.scenario
            ExpectedStatus = $fx.expectedStatus
            Description    = $fx.description
            Family         = $family
            FunctionName   = $fn
            AuditData      = $auditData
            Definition     = $defIndex[$fx.checkId]
            FixtureFile    = $file.Name
        })
    }
    $cases.ToArray()
}

# Coerce a PSCustomObject auditData into the production "mixed" shape: hashtable at the
# top level (so [hashtable]$AuditData binds), Errors and CloudIdentityPolicies.ByType as
# hashtables (index-accessed by the checks), with policy value objects left as
# PSCustomObjects (member-accessed by Resolve-GooglePolicyValue).
function ConvertTo-MixedAuditData {
    param($AuditDataObject)
    $ht = @{}
    foreach ($p in $AuditDataObject.PSObject.Properties) { $ht[$p.Name] = $p.Value }
    if ($ht.ContainsKey('Errors') -and $ht['Errors']) {
        $eh = @{}; foreach ($p in $ht['Errors'].PSObject.Properties) { $eh[$p.Name] = $p.Value }
        $ht['Errors'] = $eh
    }
    if ($ht.ContainsKey('CloudIdentityPolicies') -and $ht['CloudIdentityPolicies']) {
        $cip = @{}
        foreach ($p in $ht['CloudIdentityPolicies'].PSObject.Properties) { $cip[$p.Name] = $p.Value }
        if ($cip.ContainsKey('ByType') -and $cip['ByType']) {
            $bt = @{}; foreach ($p in $cip['ByType'].PSObject.Properties) { $bt[$p.Name] = $p.Value }
            $cip['ByType'] = $bt
        }
        $ht['CloudIdentityPolicies'] = $cip
    }
    # OrgUnitPolicies is index-accessed by OU path ($AuditData.OrgUnitPolicies[$OrgUnitPath]),
    # so it must be a hashtable even when the fixture loads as PSCustomObject.
    if ($ht.ContainsKey('OrgUnitPolicies') -and $ht['OrgUnitPolicies']) {
        $oup = @{}; foreach ($p in $ht['OrgUnitPolicies'].PSObject.Properties) { $oup[$p.Name] = $p.Value }
        $ht['OrgUnitPolicies'] = $oup
    }
    $ht
}

# Execute one fixture against its real check function inside the module scope and
# return the AuditFinding. Uses the module-call operator so it works with or
# without Pester loaded (the publisher runs outside Pester).
function Invoke-GuerrillaCheckFixture {
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$Definition,
        [Parameter(Mandatory)][string]$FunctionName
    )
    $mod = Get-Module Guerrilla
    if (-not $mod) { throw 'Guerrilla module is not imported; call Import-Guerrilla first.' }
    & $mod {
        param($AuditData, $Definition, $FunctionName)
        $cmd = Get-Command $FunctionName -ErrorAction SilentlyContinue
        if (-not $cmd) { throw "check function not found: $FunctionName" }
        # EIDSCA: the dispatcher evaluates the whole catalog and returns one finding per
        # control; pick the one matching this fixture's control id.
        if ($FunctionName -eq 'Invoke-EntraEidscaChecks') {
            $all = & $FunctionName -AuditData $AuditData
            return @($all | Where-Object { $_.CheckId -eq $Definition.id }) | Select-Object -First 1
        }
        & $FunctionName -AuditData $AuditData -CheckDefinition $Definition
    } $AuditData $Definition $FunctionName
}

Export-ModuleMember -Function *
