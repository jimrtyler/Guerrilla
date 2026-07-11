# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Unregister-Patrol {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$TaskName = 'Guerrilla-Patrol',
        [switch]$Force
    )

    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Warning "Scheduled task '$TaskName' not found."
        return
    }

    $confirm = $Force -or $PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')
    if ($confirm) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task: $TaskName"
    }
}
