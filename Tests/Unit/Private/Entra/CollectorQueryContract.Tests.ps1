# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Collector query-contract tests.
#
# These pin the *shape of the data the collectors fetch from Graph* — the one
# thing the golden-fixture harness structurally cannot check. Golden fixtures
# feed a hand-built $AuditData straight to a check function; the collector is
# never invoked, so a collector that queries the wrong endpoint (or omits an
# $expand) sails past every fixture while producing false verdicts on a live
# tenant. Each assertion below corresponds to a confirmed live verdict defect:
#
#   EIDTNT-005  false PASS   — container fetched, /default never collected
#   INTUNE-005  false FAIL   — deviceConfigurations fetched without $expand=assignments
#   EIDPIM-010  false FAIL   — scheduleInstances queried instead of schedules
#
# We mock Invoke-GraphApi and assert the exact URIs/parameters requested.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' '..' 'Helpers' 'TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Collector query contracts' {

    Context 'Get-EntraTenantData — cross-tenant access' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi {
                if ($Uri -like '*crossTenantAccessPolicy/default') {
                    return [pscustomobject]@{
                        b2bCollaborationInbound  = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'blocked'; targets = @() } }
                        b2bCollaborationOutbound = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'blocked'; targets = @() } }
                    }
                }
                if ($Uri -like '*crossTenantAccessPolicy') { return [pscustomobject]@{ id = 'default' } }
                return $null
            }
            $script:tenant = InModuleScope PSGuerrilla { Get-EntraTenantData -AccessToken 'x' -Quiet }
        }

        It 'fetches the /default cross-tenant access policy (not just the container)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/policies/crossTenantAccessPolicy/default'
            }
        }

        It 'exposes the default policy under .CrossTenantAccess.default so EIDTNT-005 can read b2bCollaboration*' {
            $tenant.CrossTenantAccess.default | Should -Not -BeNullOrEmpty
            $tenant.CrossTenantAccess.default.b2bCollaborationInbound | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-IntuneData — device configuration profiles' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi { return @() }
            InModuleScope PSGuerrilla { Get-IntuneData -AccessToken 'x' -Quiet } | Out-Null
        }

        It 'requests deviceConfigurations with $expand=assignments (else INTUNE-005 false-FAILs)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/deviceManagement/deviceConfigurations' -and
                $QueryParameters -and $QueryParameters['$expand'] -eq 'assignments'
            }
        }
    }

    Context 'Get-EntraPIMData — eligible role assignments' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi { return @() }
            InModuleScope PSGuerrilla { Get-EntraPIMData -AccessToken 'x' -Quiet } | Out-Null
        }

        It 'queries roleEligibilitySchedules (definitions), which carry standing eligibility' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/roleManagement/directory/roleEligibilitySchedules'
            }
        }

        It 'does NOT use roleEligibilityScheduleInstances for the eligibility source (0 instances => false "PIM not configured")' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 0 -Exactly -ParameterFilter {
                $Uri -eq '/roleManagement/directory/roleEligibilityScheduleInstances'
            }
        }
    }

    Context 'Get-EntraTenantData — partner delegated admin (GDAP) relationships' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi { return @() }
            InModuleScope PSGuerrilla { Get-EntraTenantData -AccessToken 'x' -Quiet } | Out-Null
        }

        It 'queries /tenantRelationships/delegatedAdminRelationships (else EIDTNT-015/016 never see partner access)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/tenantRelationships/delegatedAdminRelationships'
            }
        }

        It 'paginates the relationships list (a truncated first page would under-count partner grants)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/tenantRelationships/delegatedAdminRelationships' -and $Paginate
            }
        }
    }

    Context 'Get-EntraGovernanceData — entitlement management' {
        BeforeAll {
            Mock -ModuleName PSGuerrilla Invoke-GraphApi { return @() }
            InModuleScope PSGuerrilla { Get-EntraGovernanceData -AccessToken 'x' -Quiet } | Out-Null
        }

        It 'queries assignmentPolicies (the source EIDGOV-001..004 grade)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/identityGovernance/entitlementManagement/assignmentPolicies'
            }
        }

        It 'queries catalogs (EIDGOV-005) and access packages' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/identityGovernance/entitlementManagement/catalogs'
            }
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-GraphApi -Times 1 -Exactly -ParameterFilter {
                $Uri -eq '/identityGovernance/entitlementManagement/accessPackages'
            }
        }
    }

    Context 'Get-PowerPlatformData — Copilot Studio agents (Dataverse)' {
        BeforeAll {
            # Mock the two Dataverse stages: global discovery, then per-env bots query.
            Mock -ModuleName PSGuerrilla Invoke-RestMethod {
                if ($Uri -like '*globaldisco*discovery/v2.0/Instances*') {
                    return [pscustomobject]@{ value = @([pscustomobject]@{ ApiUrl = 'https://org1.api.crm.dynamics.com'; FriendlyName = 'Env1'; State = 0 }) }
                }
                if ($Uri -like '*/api/data/v9.2/bots*') {
                    return [pscustomobject]@{ value = @([pscustomobject]@{ botid = 'b1'; name = 'Agent'; accesscontrolpolicy = 'Team'; authenticationmode = 'Entra'; ismanaged = $false }) }
                }
                return [pscustomobject]@{ value = @() }
            }
            $script:pp = InModuleScope PSGuerrilla {
                Get-PowerPlatformData -GlobalDiscoToken 'gds' -TokenFactory { param($u) 'envtok' } -Quiet
            }
        }

        It 'discovers environments via the Global Discovery Service (State eq 0)' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -like '*globaldisco.crm.dynamics.com/api/discovery/v2.0/Instances*' -and $Uri -like '*State eq 0*'
            }
        }

        It 'queries the per-environment bots table for unmanaged agents' {
            Should -Invoke -ModuleName PSGuerrilla -Scope Context Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://org1.api.crm.dynamics.com/api/data/v9.2/bots*' -and $Uri -like '*ismanaged eq false*'
            }
        }

        It 'returns Not-Assessed (empty + Errors) when no auth context is supplied' {
            $r = InModuleScope PSGuerrilla { Get-PowerPlatformData }
            $r.Agents.Count | Should -Be 0
            $r.Errors['Agents'] | Should -Not -BeNullOrEmpty
        }
    }
}
