# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-WatchtowerReport {
    [CmdletBinding()]
    param(
        [int]$TotalChanges,
        [int]$CriticalCount,
        [int]$HighCount,
        [int]$MediumCount,
        [int]$LowCount,
        [PSCustomObject[]]$NewThreats = @(),
        [PSCustomObject[]]$FlaggedChanges = @(),
        [string]$DomainName = '',
        [string]$ScanMode = 'Fast',
        [PSCustomObject]$ChangeProfile
    )

    # Calculate Guerrilla Score
    $guerrillaScore = 100.0
    $guerrillaScore -= ($CriticalCount * 25)
    $guerrillaScore -= ($HighCount * 15)
    $guerrillaScore -= ($MediumCount * 8)
    $guerrillaScore -= ($LowCount * 3)
    $guerrillaScore = [Math]::Max(0, [Math]::Min(100, $guerrillaScore))
    $scoreInfo = Get-GuerrillaScoreLabel -Score $guerrillaScore

    $flaggedCount = $CriticalCount + $HighCount + $MediumCount + $LowCount

    # --- Header ---
    $headerContent = @('WATCHTOWER REPORT')
    if ($DomainName) { $headerContent += "Domain: $DomainName  |  Mode: $ScanMode" }
    $headerContent += ''
    $headerContent += "Guerrilla Score: $('{0,3:N0}' -f $guerrillaScore) / 100  $($scoreInfo.Label)"

    Write-Host ''
    Write-SpectrePanel -Content $headerContent -BorderColor Dim -ContentColor Parchment -Width 66
    Write-Host ''

    # Stats
    Write-GuerrillaText "  Total changes:     " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $TotalChanges) -Color White
    Write-GuerrillaText "  Flagged:           " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $flaggedCount) -Color White
    if ($NewThreats) {
        Write-GuerrillaText "  New threats:       " -Color Olive -NoNewline
        Write-GuerrillaText ('{0,6:N0}' -f $NewThreats.Count) -Color $(if ($NewThreats.Count -gt 0) { 'Amber' } else { 'Sage' })
    }
    Write-Host ''

    # --- Threat breakdown bar chart ---
    $threatItems = @()
    if ($CriticalCount -gt 0) { $threatItems += @{ Label = 'CRITICAL'; Value = $CriticalCount; Color = 'DarkRed' } }
    if ($HighCount -gt 0)     { $threatItems += @{ Label = 'HIGH';     Value = $HighCount;     Color = 'DeepOrange' } }
    if ($MediumCount -gt 0)   { $threatItems += @{ Label = 'MEDIUM';   Value = $MediumCount;   Color = 'Amber' } }
    if ($LowCount -gt 0)      { $threatItems += @{ Label = 'LOW';      Value = $LowCount;      Color = 'Gold' } }

    if ($threatItems.Count -gt 0) {
        Write-SpectreBarChart -Items $threatItems -Title 'Threat Breakdown'
    }

    if ($flaggedCount -eq 0) {
        Write-Host ''
        Write-GuerrillaText '  All clear. No suspicious changes detected in Active Directory.' -Color Sage
    }

    # --- New threats table ---
    if ($NewThreats -and $NewThreats.Count -gt 0) {
        Write-Host ''

        $newColumns = @(
            @{ Name = 'Score';     Color = 'Olive';  Alignment = 'Right' }
            @{ Name = 'Severity';  Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Detection'; Color = 'Olive';  Alignment = 'Left' }
        )

        $newRows = @()
        $newRowColors = @()
        foreach ($t in ($NewThreats | Select-Object -First 10)) {
            $levelColor = switch ($t.Severity) {
                'CRITICAL' { 'DarkRed' }
                'HIGH'     { 'DeepOrange' }
                'MEDIUM'   { 'Amber' }
                'LOW'      { 'Gold' }
                default    { 'Dim' }
            }
            $newRows += ,@(
                ('{0:N0}' -f $t.Score),
                $t.Severity,
                $t.DetectionName
            )
            $newRowColors += $levelColor
        }

        $newTitle = "New Threats: $($NewThreats.Count)"
        Write-SpectreTable -Title $newTitle -Columns $newColumns -Rows $newRows -RowColors $newRowColors -BorderColor Dim

        if ($NewThreats.Count -gt 10) {
            Write-GuerrillaText "    ... and $($NewThreats.Count - 10) more new threat(s)" -Color Dim
        }
    }

    # --- All flagged changes table ---
    if ($FlaggedChanges -and $FlaggedChanges.Count -gt 0) {
        Write-Host ''

        $severityOrder = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3 }
        $sorted = $FlaggedChanges | Sort-Object {
            if ($severityOrder.ContainsKey($_.Severity)) { $severityOrder[$_.Severity] } else { 99 }
        }

        $fcColumns = @(
            @{ Name = 'Score';     Color = 'Olive';  Alignment = 'Right' }
            @{ Name = 'Severity';  Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Detection'; Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Detail';    Color = 'Olive';  Alignment = 'Left' }
        )

        $fcRows = @()
        $fcRowColors = @()
        foreach ($c in $sorted) {
            $levelColor = switch ($c.Severity) {
                'CRITICAL' { 'DarkRed' }
                'HIGH'     { 'DeepOrange' }
                'MEDIUM'   { 'Amber' }
                'LOW'      { 'Gold' }
                default    { 'Dim' }
            }

            $newTag = if ($c.IsNew) { ' [NEW]' } else { '' }
            $desc = if ($c.Description) {
                $d = $c.Description
                if ($d.Length -gt 40) { $d = $d.Substring(0, 37) + '...' }
                $d
            } else { '' }

            $fcRows += ,@(
                ('{0:N0}' -f $c.Score),
                "$($c.Severity)$newTag",
                $c.DetectionName,
                $desc
            )
            $fcRowColors += $levelColor
        }

        Write-SpectreTable -Title 'All Flagged Changes' -Columns $fcColumns -Rows $fcRows -RowColors $fcRowColors -BorderColor Dim
    }

    # --- Change category tree ---
    if ($ChangeProfile) {
        $children = @()
        if ($ChangeProfile.GroupChanges.Count -gt 0)      { $children += @{ Label = "Group: $($ChangeProfile.GroupChanges.Count)";      Color = 'Olive' } }
        if ($ChangeProfile.GPOChanges.Count -gt 0)        { $children += @{ Label = "GPO: $($ChangeProfile.GPOChanges.Count)";          Color = 'Olive' } }
        if ($ChangeProfile.GPOLinkChanges.Count -gt 0)    { $children += @{ Label = "Links: $($ChangeProfile.GPOLinkChanges.Count)";    Color = 'Olive' } }
        if ($ChangeProfile.TrustChanges.Count -gt 0)      { $children += @{ Label = "Trust: $($ChangeProfile.TrustChanges.Count)";      Color = 'Amber' } }
        if ($ChangeProfile.ACLChanges.Count -gt 0)        { $children += @{ Label = "ACL: $($ChangeProfile.ACLChanges.Count)";          Color = 'Amber' } }
        if ($ChangeProfile.AdminSDHolderChanged)           { $children += @{ Label = 'AdminSDHolder: changed';                           Color = 'DarkRed' } }
        if ($ChangeProfile.KrbtgtChanged)                  { $children += @{ Label = 'krbtgt: changed';                                  Color = 'DarkRed' } }
        if ($ChangeProfile.CertTemplateChanges.Count -gt 0){ $children += @{ Label = "Cert: $($ChangeProfile.CertTemplateChanges.Count)"; Color = 'DeepOrange' } }
        if ($ChangeProfile.DelegationChanges.Count -gt 0) { $children += @{ Label = "Delegation: $($ChangeProfile.DelegationChanges.Count)"; Color = 'Amber' } }
        if ($ChangeProfile.DNSChanges.Count -gt 0)        { $children += @{ Label = "DNS: $($ChangeProfile.DNSChanges.Count)";          Color = 'Gold' } }
        if ($ChangeProfile.SchemaChanges.Count -gt 0)     { $children += @{ Label = "Schema: $($ChangeProfile.SchemaChanges.Count)";    Color = 'DarkRed' } }
        if ($ChangeProfile.NewComputers.Count -gt 0)      { $children += @{ Label = "New PCs: $($ChangeProfile.NewComputers.Count)";    Color = 'Gold' } }
        if ($ChangeProfile.NewServiceAccounts.Count -gt 0){ $children += @{ Label = "New Svc: $($ChangeProfile.NewServiceAccounts.Count)"; Color = 'Amber' } }

        if ($children.Count -gt 0) {
            Write-Host ''
            Write-SpectreTree -RootLabel 'Change Categories' -RootColor Parchment -Children $children -GuideColor Dim
        }
    }

    Write-Host ''
    Write-GuerrillaText ('=' * 62) -Color Dim
}
