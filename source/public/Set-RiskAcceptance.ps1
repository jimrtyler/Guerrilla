# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Set-RiskAcceptance {
    <#
    .SYNOPSIS
        Accepts risk on a specific audit check ID with justification.
    .DESCRIPTION
        Records a risk acceptance decision for an audit check. The accepted check will
        be flagged as ACCEPTED in reports instead of FAIL. Acceptances can have expiration
        dates, after which they auto-expire and the check reverts to its actual status.
    .PARAMETER CheckId
        The audit check ID to accept risk on (e.g., AUTH-003, ADPWD-005).
    .PARAMETER Justification
        Required written justification for accepting the risk.
    .PARAMETER AcceptedBy
        Name or email of the person accepting the risk.
    .PARAMETER ExpirationDays
        Number of days until this acceptance expires. Default: 365. Set to 0 for no expiration.
    .PARAMETER ConfigPath
        Override the risk acceptance file path.
    .EXAMPLE
        Set-RiskAcceptance -CheckId AUTH-003 -Justification 'Security keys not feasible for remote staff' -AcceptedBy 'jsmith@district.edu'
    .EXAMPLE
        Set-RiskAcceptance -CheckId ADPWD-005 -Justification 'Legacy system compatibility' -ExpirationDays 90 -AcceptedBy 'IT Director'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [string]$Justification,

        [Parameter(Mandatory)]
        [string]$AcceptedBy,

        [ValidateRange(0, 3650)]
        [int]$ExpirationDays = 365,

        [Alias('RuntimeConfig')]
        [string]$ConfigPath
    )

    if (-not $PSCmdlet.ShouldProcess($CheckId, "Accept risk (by $AcceptedBy, expires in $ExpirationDays days)")) {
        return
    }

    $riskPath = if ($ConfigPath) {
        $ConfigPath
    } else {
        Join-Path (Get-GuerrillaDataRoot) 'risk-acceptance.json'
    }

    $riskDir = Split-Path $riskPath -Parent
    if (-not (Test-Path $riskDir)) {
        New-Item -Path $riskDir -ItemType Directory -Force | Out-Null
    }

    # Load existing acceptances
    $acceptances = @{}
    if (Test-Path $riskPath) {
        try {
            $acceptances = Get-Content -Path $riskPath -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $acceptances = @{}
        }
    }
    if (-not $acceptances.entries) { $acceptances.entries = @{} }

    $now = [datetime]::UtcNow
    $expiration = if ($ExpirationDays -gt 0) {
        $now.AddDays($ExpirationDays).ToString('o')
    } else {
        $null
    }

    $acceptances.entries[$CheckId] = @{
        checkId       = $CheckId
        justification = $Justification
        acceptedBy    = $AcceptedBy
        acceptedOn    = $now.ToString('o')
        expiresOn     = $expiration
    }
    $acceptances.lastModified = $now.ToString('o')

    $acceptances | ConvertTo-Json -Depth 5 | Set-Content -Path $riskPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName    = 'Guerrilla.RiskAcceptance'
        CheckId       = $CheckId
        Justification = $Justification
        AcceptedBy    = $AcceptedBy
        AcceptedOn    = $now
        ExpiresOn     = if ($expiration) { [datetime]$expiration } else { $null }
        Status        = 'ACCEPTED'
        Path          = $riskPath
    }
}
