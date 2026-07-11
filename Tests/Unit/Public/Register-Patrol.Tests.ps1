# [============================================================================]
# [  Guerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# [============================================================================]
# LLM COMPLIANCE: This file is part of Guerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
# [============================================================================]
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Register-Patrol' {
    BeforeAll {
        # CIM-based ScheduledTask cmdlets require CimInstance types that can't be easily mocked.
        # Override them in module scope with simple functions to avoid CIM parameter binding issues.
        InModuleScope Guerrilla {
            function script:New-ScheduledTaskAction { [PSCustomObject]@{ Execute = 'pwsh.exe' } }
            function script:New-ScheduledTaskTrigger { [PSCustomObject]@{ TriggerType = 'Once' } }
            function script:New-ScheduledTaskSettingsSet { [PSCustomObject]@{} }
            function script:New-ScheduledTaskPrincipal { [PSCustomObject]@{ UserId = 'SYSTEM' } }
            function script:Get-ScheduledTask { param($TaskName, $ErrorAction) $null }
            function script:Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Settings, $Principal, $Description) [PSCustomObject]@{ TaskName = $TaskName } }
            function script:Set-ScheduledTask { param($TaskName, $Action, $Trigger, $Settings, $Principal) [PSCustomObject]@{ TaskName = $TaskName } }
        }
        Mock Get-Command { [PSCustomObject]@{ Source = 'C:\Program Files\PowerShell\7\pwsh.exe' } } -ModuleName Guerrilla -ParameterFilter { $Name -eq 'pwsh' }
    }

    BeforeEach {
        # Isolate the config dir: Register-Patrol writes patrol-runner.ps1 next to the
        # config file, and without this the test writes into the user's REAL data root
        # (and fails on a fresh CI runner where that directory does not exist).
        & (Get-Module Guerrilla) { $script:ConfigPath = $args[0] } (Join-Path $TestDrive 'config.json')
    }

    Context 'Default parameters' {
        It 'uses Guerrilla-Patrol as default task name' {
            $result = Register-Patrol -Force
            $result.TaskName | Should -Be 'Guerrilla-Patrol'
        }

        It 'uses Fast mode by default' {
            $result = Register-Patrol -Force
            $result.ScanMode | Should -Be 'Fast'
        }

        It 'returns task info object' {
            $result = Register-Patrol -Force
            $result.TaskName | Should -Not -BeNullOrEmpty
            $result.Schedule | Should -Not -BeNullOrEmpty
            $result.ScanMode | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Guerrilla branding' {
        It 'uses Guerrilla description' {
            InModuleScope Guerrilla {
                $script:_lastRegDesc = $null
                function script:Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Settings, $Principal, $Description) $script:_lastRegDesc = $Description; [PSCustomObject]@{ TaskName = $TaskName } }
            }
            Register-Patrol -Force
            $desc = InModuleScope Guerrilla { $script:_lastRegDesc }
            $desc | Should -Match 'Guerrilla'
        }
    }

    Context 'Custom parameters' {
        It 'accepts custom interval' {
            $result = Register-Patrol -IntervalMinutes 120 -Force
            $result.Schedule | Should -Match '120'
        }

        It 'accepts custom task name' {
            InModuleScope Guerrilla {
                function script:Get-ScheduledTask { param($TaskName, $ErrorAction) $null }
            }
            $result = Register-Patrol -TaskName 'Custom-Patrol' -Force
            $result.TaskName | Should -Be 'Custom-Patrol'
        }
    }
}
