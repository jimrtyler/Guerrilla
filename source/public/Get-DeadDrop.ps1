# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-DeadDrop {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$ScanResult,

        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')]
        [string]$MinimumThreatLevel,

        [switch]$NewOnly,

        [string[]]$User,

        [string]$IndicatorPattern,

        [datetime]$Since,

        [switch]$FromStateFile,

        [Alias('RuntimeConfig')]
        [string]$ConfigPath
    )

    process {
        $profiles = $null

        if ($FromStateFile) {
            $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
            $state = Get-OperationState -ConfigPath $cfgPath
            if (-not $state -or -not $state.alertedUsers) {
                Write-Warning 'No state file found or no alerted users in state.'
                return
            }

            # Return alerted users from state as lightweight objects
            $profiles = foreach ($email in $state.alertedUsers.Keys) {
                $u = $state.alertedUsers[$email]
                [PSCustomObject]@{
                    PSTypeName    = 'Guerrilla.UserProfile'
                    Email         = $email
                    ThreatLevel   = $u.lastThreatLevel
                    ThreatScore   = $u.lastThreatScore
                    FirstDetected = $u.firstDetected
                    LastAlerted   = $u.lastAlerted
                    AlertCount    = $u.alertCount
                }
            }
        } elseif ($ScanResult -and $ScanResult.PSObject.TypeNames -contains 'Guerrilla.ScanResult') {
            $profiles = if ($NewOnly) { $ScanResult.NewThreats } else { $ScanResult.FlaggedUsers }
        } else {
            Write-Warning 'Provide a Guerrilla.ScanResult via pipeline or use -FromStateFile.'
            return
        }

        if (-not $profiles) { return }

        # Filter by minimum threat level
        if ($MinimumThreatLevel) {
            $levelOrder = @{ 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
            $minOrdinal = $levelOrder[$MinimumThreatLevel]
            $profiles = @($profiles | Where-Object { $levelOrder[$_.ThreatLevel] -ge $minOrdinal })
        }

        # Filter by user (supports wildcards)
        if ($User) {
            $profiles = @($profiles | Where-Object {
                $email = $_.Email
                $User | Where-Object { $email -like $_ }
            })
        }

        # Filter by indicator pattern (regex)
        if ($IndicatorPattern) {
            $profiles = @($profiles | Where-Object {
                $_.Indicators | Where-Object { $_ -match $IndicatorPattern }
            })
        }

        # Filter by since
        if ($Since) {
            if ($FromStateFile) {
                $profiles = @($profiles | Where-Object {
                    $_.FirstDetected -and [datetime]::Parse($_.FirstDetected) -ge $Since
                })
            }
            # For pipeline data, all events are from the current scan so Since filtering is less relevant
        }

        return @($profiles)
    }
}
