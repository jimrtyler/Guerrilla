# ─────────────────────────────────────────────────────────────────────────────
# Guerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Get-GuerrillaScoreCalculation' {
    Context 'Empty finding set' {
        It 'Never returns a perfect score when nothing was assessed' {
            $result = InModuleScope Guerrilla { Get-GuerrillaScoreCalculation -AuditFindings @() }
            $result.Components.Posture.Score | Should -Be 0
            $result.Components.Coverage.Score | Should -Be 0
            $result.ActivePlatforms.Count | Should -Be 0
            $result.Score | Should -BeLessThan 50
        }
    }

    Context 'Coverage requires actual assessment' {
        It 'Does not count an all-SKIP platform as active' {
            $findings = @(
                New-MockAuditFinding -CheckId 'EIDPIM-004' -Status 'SKIP' -Category 'Privileged Identity'
                New-MockAuditFinding -CheckId 'EIDPIM-005' -Status 'SKIP' -Category 'Privileged Identity'
                New-MockAuditFinding -CheckId 'AZIAM-005' -Status 'SKIP' -Category 'Azure IAM'
            )
            $result = InModuleScope Guerrilla { Get-GuerrillaScoreCalculation -AuditFindings $f } -Parameters @{ f = $findings }
            $result.ActivePlatforms | Should -Not -Contain 'Entra ID / M365'
            $result.Components.Coverage.Score | Should -Be 0
        }

        It 'Counts a platform with at least one PASS/FAIL/WARN finding as active' {
            $findings = @(
                New-MockAuditFinding -CheckId 'EIDPIM-004' -Status 'SKIP' -Category 'Privileged Identity'
                New-MockAuditFinding -CheckId 'EIDPIM-005' -Status 'FAIL' -Category 'Privileged Identity'
            )
            $result = InModuleScope Guerrilla { Get-GuerrillaScoreCalculation -AuditFindings $f } -Parameters @{ f = $findings }
            $result.ActivePlatforms | Should -Contain 'Entra ID / M365'
            $result.Components.Coverage.Score | Should -Be 33
        }

        It 'Credits only the assessed platform when another is all-SKIP' {
            $findings = @(
                New-MockAuditFinding -CheckId 'ADPRIV-001' -Status 'PASS' -Category 'AD Privileged Access'
                New-MockAuditFinding -CheckId 'EIDPIM-004' -Status 'SKIP' -Category 'Privileged Identity'
            )
            $result = InModuleScope Guerrilla { Get-GuerrillaScoreCalculation -AuditFindings $f } -Parameters @{ f = $findings }
            $result.ActivePlatforms | Should -Be @('Active Directory')
            $result.Components.Coverage.Score | Should -Be 33
        }
    }

    Context 'All-SKIP finding set' {
        It 'Yields zero posture — SKIPs are not evidence' {
            $findings = @(
                New-MockAuditFinding -CheckId 'EIDPIM-004' -Status 'SKIP' -Category 'Privileged Identity'
                New-MockAuditFinding -CheckId 'EIDPIM-005' -Status 'SKIP' -Category 'Privileged Identity'
            )
            $result = InModuleScope Guerrilla { Get-GuerrillaScoreCalculation -AuditFindings $f } -Parameters @{ f = $findings }
            $result.Components.Posture.Score | Should -Be 0
            $result.Score | Should -BeLessThan 50
        }
    }
}
