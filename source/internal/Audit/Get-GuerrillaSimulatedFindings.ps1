# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Test-mode support. Builds a full set of all-FAIL audit findings for a theater
# straight from the shipped check definitions, with no live connection or data
# collection. Used by the -TestMode switch on the scan cmdlets so an operator can
# preview a report (and verify branding / themes) without touching a real tenant.
# Findings are real Guerrilla.AuditFinding objects, so every downstream feature
# (scoring, branding, report styles, affected-accounts lists) works unchanged.

# Produce a realistic "bad" CurrentValue for a check based on its name/severity.
function Get-GuerrillaBadValue {
    [CmdletBinding()]
    param([hashtable]$Check)

    $name = ([string]$Check.name).ToLower()

    if ($name -match 'enabl|audit|log')       { return 'Disabled' }
    if ($name -match 'mfa|multi.factor')       { return 'Not enforced' }
    if ($name -match 'encrypt')                { return 'Disabled' }
    if ($name -match 'password.*length')       { return '4 characters' }
    if ($name -match 'password.*age')          { return 'Never expires' }
    if ($name -match 'password.*complex')      { return 'Not required' }
    if ($name -match 'password.*history')      { return '0 passwords remembered' }
    if ($name -match 'lockout')                { return 'No lockout configured' }
    if ($name -match 'expir')                  { return 'Never' }
    if ($name -match 'shar|external')          { return 'Anyone (no restrictions)' }
    if ($name -match 'forward')                { return 'Allowed to external' }
    if ($name -match 'guest|anonymous')        { return 'Unrestricted' }
    if ($name -match 'admin|privilege')        { return 'Excessive permissions found' }
    if ($name -match 'stale|inactive|orphan')  { return 'Multiple found' }
    if ($name -match 'sign|smb|ldap|ntlm')     { return 'Not required' }
    if ($name -match 'delegation')             { return 'Unconstrained' }
    if ($name -match 'kerberos|spn')           { return 'Weak encryption (RC4)' }
    if ($name -match 'cert|ca |adcs|esc\d')    { return 'Vulnerable configuration' }
    if ($name -match 'gpo|group policy')       { return 'Misconfigured' }
    if ($name -match 'trust')                  { return 'SID filtering disabled' }
    if ($name -match 'compliance|policy')      { return 'Non-compliant' }
    if ($name -match 'conditional access')     { return 'Not configured' }
    if ($name -match 'pim|role')               { return 'Permanent assignments found' }
    if ($name -match 'app|oauth|consent')      { return 'Unreviewed permissions' }
    if ($name -match 'federation')             { return 'Insecure configuration' }
    if ($name -match 'intune|endpoint|device') { return 'Not enrolled' }
    if ($name -match 'defender|threat')        { return 'Disabled' }
    if ($name -match 'retention')              { return '0 days' }
    if ($name -match 'dkim|dmarc|spf')         { return 'Not configured' }
    if ($name -match 'transport|rule')         { return 'Insecure rules found' }

    switch ($Check.severity) {
        'Critical' { return 'Not configured (critical risk)' }
        'High'     { return 'Disabled' }
        'Medium'   { return 'Default (insecure)' }
        default    { return 'Not configured' }
    }
}

function Get-GuerrillaSimulatedFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ActiveDirectory', 'GoogleWorkspace', 'EntraM365')]
        [string]$Theater
    )

    # Resolve the check-definition base names that make up each theater's full set.
    $defNames = switch ($Theater) {
        'GoogleWorkspace' {
            @('AuthenticationChecks', 'EmailSecurityChecks', 'DriveSecurityChecks', 'OAuthSecurityChecks',
              'AdminManagementChecks', 'CollaborationChecks', 'DeviceManagementChecks', 'LoggingAlertingChecks',
              'GoogleTradecraftChecks')
        }
        'EntraM365' {
            @('EntraAuthChecks', 'EntraCAChecks', 'EntraPIMChecks', 'EntraAppChecks', 'EntraFedChecks',
              'EntraTenantChecks', 'AzureIAMChecks', 'IntuneChecks', 'M365ExchangeChecks', 'M365SharePointChecks',
              'M365TeamsChecks', 'M365DefenderChecks', 'M365AuditChecks', 'M365PowerPlatformChecks')
        }
        'ActiveDirectory' {
            # Discover every AD check file (case-sensitive 'AD'/'TierZero' prefix so the
            # Google Workspace AdminManagementChecks.json is not captured).
            $dataDir = if ($script:ModuleRoot) { Join-Path $script:ModuleRoot 'Data/AuditChecks' }
                       else { Join-Path $PSScriptRoot '../../Data/AuditChecks' }
            @(Get-ChildItem -Path $dataDir -Filter '*.json' |
                Where-Object { $_.Name -cmatch '^(AD[A-Z]|TierZero)' } |
                ForEach-Object { $_.BaseName } |
                Sort-Object)
        }
    }

    # Fake accounts to populate the "affected accounts" list for checks that declare
    # an affectedLabel — so the affected-accounts feature is visible in a test report.
    $sampleAccounts = @(
        'jsmith@sample.org', 'akumar@sample.org', 'mchen@sample.org', 'rlopez@sample.org',
        'tokafor@sample.org', 'dwilson@sample.org', 'bnguyen@sample.org', 'pgarcia@sample.org'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($name in $defNames) {
        $defs = Get-AuditCategoryDefinitions -Category $name
        foreach ($check in $defs.checks) {
            $details = @{}
            if ($check.affectedLabel) {
                $idNum = [int]([regex]::Match([string]$check.id, '\d+').Value)
                $count = ($idNum % 5) + 3
                $details.AffectedItems = @($sampleAccounts | Select-Object -First $count)
                $details.AffectedLabel = $check.affectedLabel
            }
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'FAIL' `
                -CurrentValue (Get-GuerrillaBadValue -Check $check) -Details $details))
        }
    }

    return @($findings)
}
