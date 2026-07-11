# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Get-ADReplicationHealth
# -------------------------------------------------------------------------------
# Collects AD replication health for ADDOM-007. Populates a hashtable consumed as
# $AuditData.Domain.ReplicationHealth:
#   @{ Partners = @(...); Failures = @(...); SingleDC = $bool; Source = '...' }
#
# Honesty contract (project rule #1):
#   * Prefers the ActiveDirectory module (Get-ADReplicationPartnerMetadata /
#     Get-ADReplicationFailure), guarded with Get-Command.
#   * A single-DC forest has NO replication partners. That is healthy, not
#     unknown — we return Failures=@() / SingleDC=$true so ADDOM-007 PASSes with
#     "single DC, no replication topology".
#   * If neither the AD module nor repadmin is usable, returns $null so
#     ADDOM-007 SKIPs ("Not Assessed") instead of falsely PASSing.
#
# References: MITRE ATT&CK T1207 (Rogue Domain Controller / replication abuse);
# CIS Microsoft AD benchmark (monitor replication health).
# -------------------------------------------------------------------------------
function Get-ADReplicationHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        # Number of DCs already enumerated (lets us recognise a single-DC forest
        # even when the AD module / repadmin can't be used).
        [int]$DomainControllerCount = 0,

        [switch]$Quiet
    )

    $server = $Connection.Server
    if (-not $server) {
        try { $server = $Connection.RootDSE.Properties['dnsHostName'][0].ToString() } catch { }
    }

    # ── Path 1: ActiveDirectory module ────────────────────────────────────────
    $haveADModule = $false
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
            Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false | Out-Null
            $haveADModule = (Get-Command -Name Get-ADReplicationPartnerMetadata -ErrorAction SilentlyContinue) -and
                            (Get-Command -Name Get-ADReplicationFailure -ErrorAction SilentlyContinue)
        }
    } catch {
        $haveADModule = $false
    }

    if ($haveADModule) {
        try {
            if (-not $Quiet) {
                Write-ProgressLine -Phase RECON -Message 'Reading replication partner metadata (ActiveDirectory module)'
            }

            $partners = @()
            $failures = @()

            $scopeArgs = @{ ErrorAction = 'Stop' }
            if ($server) { $scopeArgs['Target'] = $server } else { $scopeArgs['Target'] = $Connection.DomainDN; $scopeArgs['Scope'] = 'Domain' }

            try {
                $partners = @(Get-ADReplicationPartnerMetadata @scopeArgs |
                    ForEach-Object {
                        @{
                            Server               = $_.Server
                            Partner              = $_.Partner
                            LastReplicationResult = $_.LastReplicationResult
                            LastReplicationSuccess = $_.LastReplicationSuccess
                            ConsecutiveFailures  = $_.ConsecutiveReplicationFailures
                        }
                    })
            } catch {
                Write-Verbose "Get-ADReplicationPartnerMetadata failed: $_"
            }

            try {
                $failArgs = @{ ErrorAction = 'Stop' }
                if ($server) { $failArgs['Target'] = $server } else { $failArgs['Scope'] = 'Domain'; $failArgs['Target'] = $Connection.DomainDN }
                $failures = @(Get-ADReplicationFailure @failArgs |
                    ForEach-Object {
                        @{
                            Server       = $_.Server
                            Partner      = $_.Partner
                            FailureType  = "$($_.FailureType)"
                            FailureCount = $_.FailureCount
                            LastError    = $_.LastError
                        }
                    } | Where-Object { $_.FailureCount -gt 0 })
            } catch {
                Write-Verbose "Get-ADReplicationFailure failed: $_"
            }

            # Treat non-zero LastReplicationResult as a failure too.
            $partnerFailures = @($partners | Where-Object {
                $null -ne $_.LastReplicationResult -and [int]$_.LastReplicationResult -ne 0
            })

            $allFailures = @($failures) + @($partnerFailures | ForEach-Object {
                @{
                    Server      = $_.Server
                    Partner     = $_.Partner
                    FailureType = "LastReplicationResult=$($_.LastReplicationResult)"
                    FailureCount = $_.ConsecutiveFailures
                }
            })

            $singleDC = ($partners.Count -eq 0)

            if (-not $Quiet) {
                Write-ProgressLine -Phase RECON -Message ("Replication: {0} partner link(s), {1} failure(s){2}" -f `
                    $partners.Count, $allFailures.Count, $(if ($singleDC) { ' (single DC)' } else { '' }))
            }

            return @{
                Partners = @($partners)
                Failures = @($allFailures)
                SingleDC = $singleDC
                Source   = 'ActiveDirectory module'
            }
        } catch {
            Write-Verbose "ActiveDirectory replication collection failed: $_"
            # fall through to repadmin / single-DC inference
        }
    }

    # ── Path 2: repadmin /replsummary (if present) ────────────────────────────
    $repadmin = Get-Command -Name repadmin.exe -ErrorAction SilentlyContinue
    if (-not $repadmin) { $repadmin = Get-Command -Name repadmin -ErrorAction SilentlyContinue }
    if ($repadmin) {
        try {
            if (-not $Quiet) {
                Write-ProgressLine -Phase RECON -Message 'Reading replication summary (repadmin /replsummary)'
            }
            $raw = & $repadmin.Source '/replsummary' 2>$null
            $failures = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($line in @($raw)) {
                # repadmin marks failed deltas with a non-zero "fails/total" ratio.
                if ($line -match '^\s*(\S+)\s+(\d+)\s*/\s*(\d+)\s+(\d+)') {
                    $fails = [int]$Matches[2]
                    if ($fails -gt 0) {
                        $failures.Add(@{
                            Server       = $Matches[1]
                            FailureCount = $fails
                            FailureType  = 'repadmin /replsummary delta failure'
                        })
                    }
                }
            }
            return @{
                Partners = @()
                Failures = @($failures)
                SingleDC = ($DomainControllerCount -le 1)
                Source   = 'repadmin /replsummary'
            }
        } catch {
            Write-Verbose "repadmin replication collection failed: $_"
        }
    }

    # ── Path 3: single-DC inference (no tooling, but we know the DC count) ─────
    # If we positively know there is exactly one DC, there is no replication
    # topology to fail — that is a healthy state we CAN assert.
    if ($DomainControllerCount -eq 1) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Single domain controller detected — no replication topology to assess (healthy)'
        }
        return @{
            Partners = @()
            Failures = @()
            SingleDC = $true
            Source   = 'Single-DC inference (no replication partners)'
        }
    }

    # Neither tooling available and more than one DC (or unknown count): we cannot
    # honestly assess replication. Return $null so ADDOM-007 SKIPs.
    Write-Verbose 'No replication-health source available (ActiveDirectory module / repadmin); returning $null.'
    return $null
}
