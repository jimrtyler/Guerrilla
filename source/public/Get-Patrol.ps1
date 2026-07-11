# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-Patrol {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'Guerrilla-Patrol'
    )

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Warning "Scheduled task '$TaskName' not found."
        return $null
    }

    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        TaskName       = $task.TaskName
        State          = $task.State
        Description    = $task.Description
        LastRunTime    = $info.LastRunTime
        LastResult     = $info.LastTaskResult
        NextRunTime    = $info.NextRunTime
        NumberOfMissed = $info.NumberOfMissedRuns
        Action         = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        Triggers       = ($task.Triggers | ForEach-Object { $_.ToString() }) -join '; '
    }
}
