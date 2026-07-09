# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-GuerrillaBanner {
    [CmdletBinding()]
    param()

    # Respect quiet/no-color env vars. GUERRILLA_QUIET is the current name;
    # PSGUERRILLA_QUIET is honored as a back-compat fallback (pre-rename name).
    if ($env:GUERRILLA_QUIET -or $env:PSGUERRILLA_QUIET) { return }

    # Skip the banner in non-interactive contexts (scheduled tasks, CI, piped
    # invocation) — printing a 5-line ASCII banner there is just noise that
    # ends up in scheduled-task log files or downstream pipelines.
    if (-not [Environment]::UserInteractive) { return }
    try {
        if ([Console]::IsOutputRedirected) { return }
    } catch {
        # Some hosts (ISE, custom hosts) don't expose [Console]; assume interactive.
    }

    # Read the version from the manifest so the banner can't drift from the
    # actual module version (it had: previous bug, banner said 2.1.0 while
    # ModuleVersion was 2.3.0).
    $version = try {
        (Import-PowerShellDataFile (Join-Path $script:ModuleRoot 'Guerrilla.psd1') -ErrorAction Stop).ModuleVersion
    } catch { 'unknown' }
    $awsCount = $script:ParsedAwsNetworks.Count
    $cloudCount = $script:ParsedCloudNetworks.Count
    $attackerCount = $script:AttackerIpSet.Count
    $countryCount = $script:SuspiciousCountries.codes.Count

    $configStatus = if (Test-Path $script:ConfigPath) { 'loaded' } else { 'not configured' }

    $bannerLines = @(
        '  ____  ____   ____                      _ _ _       '
        ' |  _ \/ ___| / ___|_   _  ___ _ __ _ __(_) | | __ _ '
        ' | |_) \___ \| |  _| | | |/ _ \ ''__| ''__| | | |/ _` |'
        ' |  __/ ___) | |_| | |_| |  __/ |  | |  | | | | (_| |'
        ' |_|   |____/ \____|\__,_|\___|_|  |_|  |_|_|_|\__,_|'
    )

    $spectreTag = if ($script:HasSpectre) { ' | Spectre: active' } else { '' }
    $infoLine1 = "v$version  |  Config: $configStatus$spectreTag"
    $infoLine2 = "By Jim Tyler, Microsoft MVP"
    $infoLine3 = "Intel: $awsCount AWS + $cloudCount cloud ranges | $attackerCount attacker IPs | $countryCount countries"

    if ($script:HasSpectre) {
        Write-Host ''
        Write-SpectrePanel -Content ($bannerLines + @('', "  $infoLine1", "  $infoLine2", "  $infoLine3")) `
            -BorderColor 'Olive' -ContentColor 'Parchment' -Width 66
        Write-Host ''
    } else {
        Write-Host ''
        foreach ($line in $bannerLines) {
            Write-GuerrillaText $line -Color Parchment
        }
        Write-Host ''
        Write-GuerrillaText "  v$version" -Color Dim -NoNewline
        Write-GuerrillaText '  |  ' -Color Dim -NoNewline
        Write-GuerrillaText "Config: " -Color Olive -NoNewline
        $configColor = if (Test-Path $script:ConfigPath) { 'Sage' } else { 'Amber' }
        Write-GuerrillaText $configStatus -Color $configColor
        Write-GuerrillaText "  By " -Color Dim -NoNewline
        Write-GuerrillaText "Jim Tyler" -Color Gold -NoNewline
        Write-GuerrillaText ", Microsoft MVP" -Color Dim
        Write-GuerrillaText "  Intel: " -Color Dim -NoNewline
        Write-GuerrillaText "$awsCount AWS" -Color Gold -NoNewline
        Write-GuerrillaText " + " -Color Dim -NoNewline
        Write-GuerrillaText "$cloudCount cloud" -Color Gold -NoNewline
        Write-GuerrillaText " ranges | " -Color Dim -NoNewline
        Write-GuerrillaText "$attackerCount attacker IPs" -Color Amber -NoNewline
        Write-GuerrillaText " | " -Color Dim -NoNewline
        Write-GuerrillaText "$countryCount countries" -Color Gold
        Write-Host ''
    }
}
