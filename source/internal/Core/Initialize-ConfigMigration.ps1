# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Initialize-ConfigMigration {
    [CmdletBinding()]
    param()

    # PSRecon was Windows-only — no migration source can possibly exist on other OSes.
    $onWindows = if (Test-Path variable:IsWindows) { $IsWindows } else { $true }
    if (-not $onWindows) { return }

    $oldDir = Join-Path $env:APPDATA 'PSRecon'
    $newDir = Get-GuerrillaDataRoot

    # Skip if old dir doesn't exist or new dir already has config
    if (-not (Test-Path $oldDir)) { return }
    if (Test-Path (Join-Path $newDir 'config.json')) { return }

    # Migrate config and state files
    if (-not (Test-Path $newDir)) {
        New-Item -Path $newDir -ItemType Directory -Force | Out-Null
    }

    $filesToMigrate = @('config.json', 'state.json')
    foreach ($file in $filesToMigrate) {
        $oldPath = Join-Path $oldDir $file
        $newPath = Join-Path $newDir $file
        if (Test-Path $oldPath) {
            Copy-Item -Path $oldPath -Destination $newPath -Force
            Write-Verbose "Migrated $file from PSRecon to Guerrilla"
        }
    }

    # Update internal values in migrated config
    $newConfigPath = Join-Path $newDir 'config.json'
    if (Test-Path $newConfigPath) {
        try {
            $config = Get-Content -Path $newConfigPath -Raw | ConvertFrom-Json -AsHashtable

            # Update output directory if it pointed to old path
            if ($config.output -and $config.output.directory -and $config.output.directory -match 'PSRecon') {
                $config.output.directory = $config.output.directory -replace 'PSRecon', 'Guerrilla'
            }

            # Update scheduling task name if it was the old default
            if ($config.scheduling -and $config.scheduling.taskName -eq 'PSRecon-ScheduledScan') {
                $config.scheduling.taskName = 'Guerrilla-Patrol'
            }

            # Update sendgrid fromName if it was the old default
            if ($config.alerting -and $config.alerting.providers -and
                $config.alerting.providers.sendgrid -and
                $config.alerting.providers.sendgrid.fromName -eq 'PSRecon Alerts') {
                $config.alerting.providers.sendgrid.fromName = 'Guerrilla Signals'
            }

            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $newConfigPath -Encoding UTF8
            Write-Verbose "Updated migrated config with Guerrilla values"
        } catch {
            Write-Warning "Config migration: failed to update internal values: $_"
        }
    }

    # Copy Reports directory if it exists
    $oldReports = Join-Path $oldDir 'Reports'
    $newReports = Join-Path $newDir 'Reports'
    if ((Test-Path $oldReports) -and -not (Test-Path $newReports)) {
        Copy-Item -Path $oldReports -Destination $newReports -Recurse -Force
        Write-Verbose "Migrated Reports directory from PSRecon to Guerrilla"
    }

    Write-Host "Guerrilla: Migrated configuration from PSRecon. Old config preserved at $oldDir"
}
