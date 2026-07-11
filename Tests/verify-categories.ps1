# ______________________________________________________________________________
#
#  Guerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# ______________________________________________________________________________
#Requires -Version 7.0
<#
.SYNOPSIS
    Verifies all 7 category check functions (excluding Authentication) work correctly
    with mock audit data inside the Guerrilla module scope.

.DESCRIPTION
    Imports Guerrilla and exercises each Invoke-*Checks function with realistic mock
    data, then reports the number of findings and a pass/fail/warn/skip/error breakdown.
#>

$ErrorActionPreference = 'Stop'

# ── Import the module ────────────────────────────────────────────────────────
$modulePath = Join-Path $PSScriptRoot '..' 'source' 'Guerrilla.psd1'
$modulePath = (Resolve-Path $modulePath).Path
Write-Host "`n=== Importing Guerrilla from $modulePath ===" -ForegroundColor Cyan
Import-Module $modulePath -Force -ErrorAction Stop
Write-Host "Module imported successfully.`n" -ForegroundColor Green

# ── Build mock audit data ────────────────────────────────────────────────────
$mockAuditData = @{

    # -- Users -----------------------------------------------------------------
    Users = @(
        [PSCustomObject]@{
            primaryEmail    = 'admin1@testdomain.com'
            isAdmin         = $true
            isDelegatedAdmin = $false
            suspended       = $false
            archived        = $false
            lastLoginTime   = ([datetime]::UtcNow.AddDays(-2)).ToString('o')
            isEnrolledIn2Sv = $true
            is2SvEnforced   = $true
            creationTime    = '2023-01-15T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'admin2@testdomain.com'
            isAdmin         = $true
            isDelegatedAdmin = $false
            suspended       = $false
            archived        = $false
            lastLoginTime   = ([datetime]::UtcNow.AddDays(-5)).ToString('o')
            isEnrolledIn2Sv = $true
            is2SvEnforced   = $true
            creationTime    = '2023-02-01T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'admin3@testdomain.com'
            isAdmin         = $true
            isDelegatedAdmin = $false
            suspended       = $true   # suspended super admin
            archived        = $false
            lastLoginTime   = '2024-06-01T00:00:00Z'
            isEnrolledIn2Sv = $false
            is2SvEnforced   = $false
            creationTime    = '2023-03-01T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'user1@testdomain.com'
            isAdmin         = $false
            isDelegatedAdmin = $false
            suspended       = $false
            archived        = $false
            lastLoginTime   = ([datetime]::UtcNow.AddDays(-1)).ToString('o')
            isEnrolledIn2Sv = $true
            is2SvEnforced   = $false
            creationTime    = '2023-04-01T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'user2@testdomain.com'
            isAdmin         = $false
            isDelegatedAdmin = $false
            suspended       = $false
            archived        = $false
            lastLoginTime   = '2024-03-01T00:00:00Z'   # stale - >90 days ago
            isEnrolledIn2Sv = $false
            is2SvEnforced   = $false
            creationTime    = '2023-05-01T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'user3@testdomain.com'
            isAdmin         = $false
            isDelegatedAdmin = $true
            suspended       = $false
            archived        = $false
            lastLoginTime   = ([datetime]::UtcNow.AddDays(-10)).ToString('o')
            isEnrolledIn2Sv = $true
            is2SvEnforced   = $true
            creationTime    = '2023-06-01T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'suspended1@testdomain.com'
            isAdmin         = $false
            isDelegatedAdmin = $false
            suspended       = $true
            archived        = $false
            lastLoginTime   = '2024-01-01T00:00:00Z'
            isEnrolledIn2Sv = $false
            is2SvEnforced   = $false
            creationTime    = '2023-07-01T00:00:00Z'
        }
        [PSCustomObject]@{
            primaryEmail    = 'archived1@testdomain.com'
            isAdmin         = $false
            isDelegatedAdmin = $false
            suspended       = $false
            archived        = $true
            lastLoginTime   = '2023-12-01T00:00:00Z'
            isEnrolledIn2Sv = $false
            is2SvEnforced   = $false
            creationTime    = '2023-08-01T00:00:00Z'
        }
    )

    # -- Domains ---------------------------------------------------------------
    Domains = @(
        [PSCustomObject]@{ domainName = 'testdomain.com'; isPrimary = $true; verified = $true }
        [PSCustomObject]@{ domainName = 'secondary.com'; isPrimary = $false; verified = $true }
    )

    # -- DNS Records -----------------------------------------------------------
    DnsRecords = @{
        'testdomain.com' = @{
            SPF    = @{ Valid = $true; Record = 'v=spf1 include:_spf.google.com ~all'; Details = $null }
            DKIM   = @{ Valid = $true; Details = $null }
            DMARC  = @{ Valid = $true; Policy = 'reject'; Details = $null }
            MTASTS = @{ Valid = $true; Details = $null }
            MX     = @{ Valid = $true; Records = @('aspmx.l.google.com') }
        }
        'secondary.com' = @{
            SPF    = @{ Valid = $false; Record = $null; Details = 'No SPF record found' }
            DKIM   = @{ Valid = $false; Details = 'No DKIM record found' }
            DMARC  = @{ Valid = $true; Policy = 'none'; Details = $null }
            MTASTS = @{ Valid = $false; Details = 'No MTA-STS record found' }
            MX     = @{ Valid = $true; Records = @('aspmx.l.google.com') }
        }
    }

    # -- Groups ----------------------------------------------------------------
    Groups = @(
        [PSCustomObject]@{
            email               = 'engineering@testdomain.com'
            name                = 'Engineering'
            directMembersCount  = 15
            allowExternalMembers = $false
            whoCanJoin          = 'INVITED_CAN_JOIN'
        }
        [PSCustomObject]@{
            email               = 'partners@testdomain.com'
            name                = 'Partners'
            directMembersCount  = 5
            allowExternalMembers = $true
            whoCanJoin          = 'ANYONE_CAN_JOIN'
        }
        [PSCustomObject]@{
            email               = 'allstaff@testdomain.com'
            name                = 'All Staff'
            directMembersCount  = 50
            allowExternalMembers = $false
            whoCanJoin          = 'INVITED_CAN_JOIN'
        }
    )

    # -- Roles & Role Assignments ──────────────────────────────────────────────
    Roles = @(
        [PSCustomObject]@{ roleName = 'Super Admin'; roleId = '1'; isSuperAdminRole = $true; isSystemRole = $true }
        [PSCustomObject]@{ roleName = 'Groups Admin'; roleId = '2'; isSuperAdminRole = $false; isSystemRole = $true }
        [PSCustomObject]@{ roleName = 'User Management Admin'; roleId = '3'; isSuperAdminRole = $false; isSystemRole = $true }
        [PSCustomObject]@{ roleName = 'Help Desk Admin'; roleId = '4'; isSuperAdminRole = $false; isSystemRole = $true }
        [PSCustomObject]@{ roleName = 'Custom Security Reviewer'; roleId = '100'; isSuperAdminRole = $false; isSystemRole = $false }
    )

    RoleAssignments = @(
        [PSCustomObject]@{ roleAssignmentId = 'ra1'; roleId = '1'; assignedTo = 'admin1@testdomain.com' }
        [PSCustomObject]@{ roleAssignmentId = 'ra2'; roleId = '1'; assignedTo = 'admin2@testdomain.com' }
        [PSCustomObject]@{ roleAssignmentId = 'ra3'; roleId = '2'; assignedTo = 'user3@testdomain.com' }
        [PSCustomObject]@{ roleAssignmentId = 'ra4'; roleId = '100'; assignedTo = 'user1@testdomain.com' }
    )

    # -- Mobile Devices ────────────────────────────────────────────────────────
    MobileDevices = @(
        [PSCustomObject]@{ resourceId = 'md1'; status = 'APPROVED'; managementType = 'ADVANCED'; model = 'iPhone 15'; os = 'iOS 17' }
        [PSCustomObject]@{ resourceId = 'md2'; status = 'APPROVED'; managementType = 'BASIC'; model = 'Pixel 8'; os = 'Android 14' }
        [PSCustomObject]@{ resourceId = 'md3'; status = 'PENDING'; managementType = $null; model = 'Galaxy S24'; os = 'Android 14' }
    )

    # -- Chrome Devices ────────────────────────────────────────────────────────
    ChromeDevices = @(
        [PSCustomObject]@{ deviceId = 'cd1'; status = 'ACTIVE'; serialNumber = 'SN001'; model = 'Chromebook 14' }
        [PSCustomObject]@{ deviceId = 'cd2'; status = 'ACTIVE'; serialNumber = 'SN002'; model = 'Chromebook 15' }
        [PSCustomObject]@{ deviceId = 'cd3'; status = 'DEPROVISIONED'; serialNumber = 'SN003'; model = 'Chromebook 13' }
    )

    # -- Chrome Policies (for DEVICE-007 / DEVICE-008) ─────────────────────────
    ChromePolicies = @{
        'ExtensionInstallBlocklist' = @('*')
        'ExtensionInstallAllowlist' = @('abcdefghijklmnopqrstuvwxyz')
        'PasswordManagerEnabled'    = $false
        'SafeBrowsingEnabled'       = $true
    }

    # -- Gmail Settings (keyed by user email) ──────────────────────────────────
    GmailSettings = @{
        'admin1@testdomain.com' = @{
            autoForwarding = @{ enabled = $false; emailAddress = $null }
            sendAs = @(
                @{ sendAsEmail = 'admin1@testdomain.com'; isDefault = $true }
            )
            imap = @{ enabled = $false }
            pop  = @{ accessWindow = 'disabled' }
            filters = @()
            forwardingAddresses = @()
        }
        'user1@testdomain.com' = @{
            autoForwarding = @{ enabled = $true; emailAddress = 'personal@gmail.com' }
            sendAs = @(
                @{ sendAsEmail = 'user1@testdomain.com'; isDefault = $true }
                @{ sendAsEmail = 'alias@external.com'; isDefault = $false }
            )
            imap = @{ enabled = $true }
            pop  = @{ accessWindow = 'allMail' }
            filters = @(
                @{ id = 'f1'; criteria = @{ from = 'notifications@service.com' }; action = @{ forward = 'backup@external.com' } }
            )
            forwardingAddresses = @(
                @{ forwardingEmail = 'personal@gmail.com' }
            )
        }
        'user2@testdomain.com' = @{
            autoForwarding = @{ enabled = $false; emailAddress = $null }
            sendAs = @(
                @{ sendAsEmail = 'user2@testdomain.com'; isDefault = $true }
            )
            imap = @{ enabled = $false }
            pop  = @{ accessWindow = 'disabled' }
            filters = @()
            forwardingAddresses = @()
        }
    }

    # -- OAuth Apps (token grant events from Reports API) ──────────────────────
    OAuthApps = @(
        [PSCustomObject]@{
            Params = @{
                app_name = 'Slack'
                scope    = 'https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/gmail.readonly'
            }
        }
        [PSCustomObject]@{
            Params = @{
                app_name = 'Zoom'
                scope    = 'https://www.googleapis.com/auth/calendar'
            }
        }
        [PSCustomObject]@{
            Params = @{
                app_name = 'Trello'
                scope    = 'https://www.googleapis.com/auth/drive.readonly'
            }
        }
        [PSCustomObject]@{
            Params = @{
                app_name = 'SuspiciousApp'
                scope    = 'https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/gmail https://www.googleapis.com/auth/drive'
            }
        }
        [PSCustomObject]@{
            Params = @{
                app_name = 'HRTool'
                scope    = 'https://www.googleapis.com/auth/directory.readonly https://www.googleapis.com/auth/contacts'
            }
        }
        [PSCustomObject]@{
            Params = @{
                app_name = 'AnalyticsDashboard'
                scope    = 'https://www.googleapis.com/auth/drive.file'
            }
        }
    )

    # -- Domain-Wide Delegation ────────────────────────────────────────────────
    DomainWideDelegation = @(
        @{
            clientId = '112233445566'
            scopes   = @(
                'https://www.googleapis.com/auth/admin.directory.user.readonly'
                'https://www.googleapis.com/auth/gmail.readonly'
            )
        }
        @{
            clientId = '778899001122'
            scopes   = @(
                'https://www.googleapis.com/auth/calendar'
            )
        }
        @{
            clientId = '334455667788'
            scopes   = @(
                'https://www.googleapis.com/auth/admin.reports.audit.readonly'
            )
        }
    )

    # -- Alert Rules ───────────────────────────────────────────────────────────
    AlertRules = @(
        [PSCustomObject]@{ name = 'Suspicious Login Alert';   source = 'Login' }
        [PSCustomObject]@{ name = 'Drive External Share';     source = 'Drive' }
        [PSCustomObject]@{ name = 'Admin Role Change';        source = 'Admin' }
        [PSCustomObject]@{ name = 'Email Forwarding Rule';    source = 'Email' }
        [PSCustomObject]@{ name = 'OAuth Token Grant';        source = 'OAuth' }
        [PSCustomObject]@{ name = 'Bulk User Deletion';       source = 'Admin' }
    )

    # -- Tenant ────────────────────────────────────────────────────────────────
    Tenant = @{
        Domain   = 'testdomain.com'
        Edition  = 'enterprise'
        OrgUnits = @(
            @{ orgUnitPath = '/'; name = 'Root' }
            @{ orgUnitPath = '/Engineering'; name = 'Engineering' }
            @{ orgUnitPath = '/Sales'; name = 'Sales' }
            @{ orgUnitPath = '/HR'; name = 'HR' }
        )
    }

    # -- OrgUnitPolicies (for Drive/Collaboration checks) ──────────────────────
    OrgUnitPolicies = @{
        '/' = @{
            driveExternalSharing      = 'ON_WITH_WARNING'
            defaultLinkSharing        = 'RESTRICTED'
            anyoneWithLinkEnabled     = $true
            sharedDriveExternalSharing = $true
            driveForDesktopEnabled    = $true
            driveOfflineEnabled       = $true
            chatExternalEnabled       = $true
            calendarExternalSharing   = 'FREE_BUSY'
        }
    }

    # -- Errors (empty = no errors during collection) ──────────────────────────
    Errors = @{}
}


# ── Define categories to test ────────────────────────────────────────────────
$categories = @(
    @{ Name = 'Email Security';                 Function = 'Invoke-EmailSecurityChecks';     ExpectedCount = 22 }
    @{ Name = 'Drive Security';                 Function = 'Invoke-DriveSecurityChecks';     ExpectedCount = 13 }
    @{ Name = 'OAuth Security';                 Function = 'Invoke-OAuthSecurityChecks';     ExpectedCount = 10 }
    @{ Name = 'Admin Management';               Function = 'Invoke-AdminManagementChecks';   ExpectedCount = 16 }
    @{ Name = 'Collaboration';                  Function = 'Invoke-CollaborationChecks';     ExpectedCount = 12 }
    @{ Name = 'Device Management';              Function = 'Invoke-DeviceManagementChecks';  ExpectedCount = 11 }
    @{ Name = 'Logging & Alerting';             Function = 'Invoke-LoggingAlertingChecks';   ExpectedCount = 6  }
    @{ Name = 'Workspace Service (Sites/Classroom/Gemini)'; Function = 'Invoke-GwsServiceChecks'; ExpectedCount = 12 }
)


# ── Run each category inside module scope ────────────────────────────────────
$totalPass   = 0
$totalFail   = 0
$totalWarn   = 0
$totalSkip   = 0
$totalError  = 0
$totalFindings = 0
$allPassed   = $true

Write-Host ('-' * 90) -ForegroundColor DarkGray

foreach ($cat in $categories) {
    Write-Host "`n>>> Testing: $($cat.Name) ($($cat.Function))" -ForegroundColor Yellow

    try {
        $findings = & (Get-Module Guerrilla) {
            param($AuditData, $FuncName)
            & $FuncName -AuditData $AuditData
        } -AuditData $mockAuditData -FuncName $cat.Function

        $count = @($findings).Count

        # Status breakdown
        $pass  = @($findings | Where-Object { $_.Status -eq 'PASS'  }).Count
        $fail  = @($findings | Where-Object { $_.Status -eq 'FAIL'  }).Count
        $warn  = @($findings | Where-Object { $_.Status -eq 'WARN'  }).Count
        $skip  = @($findings | Where-Object { $_.Status -eq 'SKIP'  }).Count
        $err   = @($findings | Where-Object { $_.Status -eq 'ERROR' }).Count

        $totalPass   += $pass
        $totalFail   += $fail
        $totalWarn   += $warn
        $totalSkip   += $skip
        $totalError  += $err
        $totalFindings += $count

        # Count check
        $countOk = ($count -eq $cat.ExpectedCount)
        $countColor = if ($countOk) { 'Green' } else { 'Red' }
        $countLabel = if ($countOk) { 'OK' } else { "MISMATCH (expected $($cat.ExpectedCount))" }

        if (-not $countOk) { $allPassed = $false }
        if ($err -gt 0) { $allPassed = $false }

        Write-Host "    Findings: $count  [$countLabel]" -ForegroundColor $countColor
        Write-Host "    PASS=$pass  FAIL=$fail  WARN=$warn  SKIP=$skip  ERROR=$err"

        # Print individual findings
        foreach ($f in $findings) {
            $statusColor = switch ($f.Status) {
                'PASS'  { 'Green'  }
                'FAIL'  { 'Red'    }
                'WARN'  { 'DarkYellow' }
                'SKIP'  { 'Gray'   }
                'ERROR' { 'Magenta' }
                default { 'White'  }
            }
            $truncatedValue = if ($f.CurrentValue.Length -gt 80) {
                $f.CurrentValue.Substring(0, 77) + '...'
            } else {
                $f.CurrentValue
            }
            Write-Host "      [$($f.Status.PadRight(5))] $($f.CheckId): $truncatedValue" -ForegroundColor $statusColor
        }

    } catch {
        $allPassed = $false
        Write-Host "    EXCEPTION: $_" -ForegroundColor Red
        Write-Host "    $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    }
}


# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "`n$('=' * 90)" -ForegroundColor DarkGray
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "  Total findings:  $totalFindings"
Write-Host "  PASS:   $totalPass" -ForegroundColor Green
Write-Host "  FAIL:   $totalFail" -ForegroundColor Red
Write-Host "  WARN:   $totalWarn" -ForegroundColor DarkYellow
Write-Host "  SKIP:   $totalSkip" -ForegroundColor Gray
Write-Host "  ERROR:  $totalError" -ForegroundColor Magenta

if ($allPassed) {
    Write-Host "`n  RESULT: ALL CATEGORIES VERIFIED SUCCESSFULLY" -ForegroundColor Green
} else {
    Write-Host "`n  RESULT: ISSUES DETECTED - review output above" -ForegroundColor Red
}

Write-Host ""
