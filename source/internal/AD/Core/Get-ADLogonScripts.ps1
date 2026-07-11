# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADLogonScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        UserScripts          = @()
        NetlogonPath         = ''
        SysvolPath           = ''
        NetlogonFiles        = @()
        NetlogonPermissions  = $null
        SysvolPermissions    = $null
        ScriptAnalysis       = @()
        Errors               = @{}
    }

    $domainDN = $Connection.DomainDN
    $domainName = ($domainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    # ── 1. Query user logon scripts ─────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Querying user logon script assignments'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $scriptUsers = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=person)(objectClass=user)(scriptPath=*))' `
            -Properties @('samaccountname', 'scriptpath', 'distinguishedname')

        # Group by script path and count users per script
        $scriptGroups = @{}
        foreach ($user in $scriptUsers) {
            $scriptPath = ($user['scriptpath'] ?? '').Trim()
            if ([string]::IsNullOrWhiteSpace($scriptPath)) { continue }

            if (-not $scriptGroups.ContainsKey($scriptPath)) {
                $scriptGroups[$scriptPath] = 0
            }
            $scriptGroups[$scriptPath]++
        }

        $userScripts = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($kv in $scriptGroups.GetEnumerator()) {
            $userScripts.Add(@{
                ScriptPath = $kv.Key
                UserCount  = $kv.Value
            })
        }
        $result.UserScripts = @($userScripts | Sort-Object { $_.UserCount } -Descending)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($userScripts.Count) unique logon script(s)" `
                -Detail "referenced by $($scriptUsers.Count) user(s)"
        }
    } catch {
        Write-Warning "Failed to query user logon scripts: $_"
        $result.Errors['UserScripts'] = $_.Exception.Message
    }

    # ── 2. Determine share paths ────────────────────────────────────────
    $result.NetlogonPath = "\\$domainName\NETLOGON"
    $result.SysvolPath   = "\\$domainName\SYSVOL"

    # ── 3. Enumerate NETLOGON files ─────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Enumerating NETLOGON share contents'
    }

    try {
        $netlogonPath = $result.NetlogonPath
        if (Test-Path -LiteralPath $netlogonPath -ErrorAction SilentlyContinue) {
            $netlogonFiles = [System.Collections.Generic.List[hashtable]]::new()
            $fileItems = Get-ChildItem -LiteralPath $netlogonPath -Recurse -File -ErrorAction SilentlyContinue

            foreach ($file in $fileItems) {
                $netlogonFiles.Add(@{
                    Path          = $file.FullName
                    RelativePath  = $file.FullName.Substring($netlogonPath.Length).TrimStart('\')
                    Extension     = $file.Extension.ToLower()
                    Size          = $file.Length
                    LastWriteTime = $file.LastWriteTime
                })
            }
            $result.NetlogonFiles = @($netlogonFiles)

            if (-not $Quiet) {
                Write-ProgressLine -Phase RECON -Message "Found $($netlogonFiles.Count) file(s) in NETLOGON"
            }
        } else {
            Write-Verbose "NETLOGON share not accessible: $netlogonPath"
            $result.Errors['NetlogonFiles'] = "NETLOGON share not accessible at $netlogonPath"
        }
    } catch {
        Write-Verbose "Failed to enumerate NETLOGON files: $_"
        $result.Errors['NetlogonFiles'] = $_.Exception.Message
    }

    # ── 4. NETLOGON and SYSVOL permissions ──────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Reading share permissions'
    }

    try {
        if (Test-Path -LiteralPath $result.NetlogonPath -ErrorAction SilentlyContinue) {
            $netlogonAcl = Get-Acl -LiteralPath $result.NetlogonPath -ErrorAction SilentlyContinue
            if ($netlogonAcl) {
                $result.NetlogonPermissions = @{
                    Owner       = $netlogonAcl.Owner
                    AccessRules = @($netlogonAcl.Access | ForEach-Object {
                        @{
                            Identity    = $_.IdentityReference.Value
                            Rights      = $_.FileSystemRights.ToString()
                            AccessType  = $_.AccessControlType.ToString()
                            IsInherited = $_.IsInherited
                        }
                    })
                }
            }
        }
    } catch {
        Write-Verbose "Failed to read NETLOGON permissions: $_"
        $result.Errors['NetlogonPermissions'] = $_.Exception.Message
    }

    try {
        if (Test-Path -LiteralPath $result.SysvolPath -ErrorAction SilentlyContinue) {
            $sysvolAcl = Get-Acl -LiteralPath $result.SysvolPath -ErrorAction SilentlyContinue
            if ($sysvolAcl) {
                $result.SysvolPermissions = @{
                    Owner       = $sysvolAcl.Owner
                    AccessRules = @($sysvolAcl.Access | ForEach-Object {
                        @{
                            Identity    = $_.IdentityReference.Value
                            Rights      = $_.FileSystemRights.ToString()
                            AccessType  = $_.AccessControlType.ToString()
                            IsInherited = $_.IsInherited
                        }
                    })
                }
            }
        }
    } catch {
        Write-Verbose "Failed to read SYSVOL permissions: $_"
        $result.Errors['SysvolPermissions'] = $_.Exception.Message
    }

    # ── 5. Script content analysis ──────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Analyzing logon script contents'
    }

    # Extensions eligible for content analysis
    $scriptExtensions = @('.bat', '.cmd', '.vbs', '.ps1', '.js', '.wsf', '.kix')

    # LOLBin patterns
    $lolbinPatterns = @(
        @{ Name = 'certutil';           Pattern = '\bcertutil\b' }
        @{ Name = 'bitsadmin';          Pattern = '\bbitsadmin\b' }
        @{ Name = 'mshta';              Pattern = '\bmshta\b' }
        @{ Name = 'regsvr32';           Pattern = '\bregsvr32\b' }
        @{ Name = 'rundll32';           Pattern = '\brundll32\b' }
        @{ Name = 'wscript';            Pattern = '\bwscript\b' }
        @{ Name = 'cscript';            Pattern = '\bcscript\b' }
        @{ Name = 'msiexec';            Pattern = '\bmsiexec\b' }
        @{ Name = 'powershell -enc';    Pattern = 'powershell[^|\r\n]*-enc' }
        @{ Name = 'powershell -nop';    Pattern = 'powershell[^|\r\n]*-nop' }
        @{ Name = 'powershell downloadstring'; Pattern = 'powershell[^|\r\n]*downloadstring' }
        @{ Name = 'Invoke-WebRequest';  Pattern = '\bInvoke-WebRequest\b' }
        @{ Name = 'Invoke-Expression';  Pattern = '\bInvoke-Expression\b' }
        @{ Name = 'iex';               Pattern = '\biex\b' }
        @{ Name = 'Start-BitsTransfer'; Pattern = '\bStart-BitsTransfer\b' }
        @{ Name = 'cmd /c';            Pattern = '\bcmd\b[^|\r\n]*/c\b' }
        @{ Name = 'wget';              Pattern = '\bwget\b' }
        @{ Name = 'curl';              Pattern = '\bcurl\b' }
    )

    # Credential patterns
    $credentialPatterns = @(
        @{ Name = 'password=';                  Pattern = 'password\s*=' }
        @{ Name = 'passwd=';                    Pattern = 'passwd\s*=' }
        @{ Name = 'pwd=';                       Pattern = 'pwd\s*=' }
        @{ Name = '-Password with value';       Pattern = '-Password\s+[''\"]\S+' }
        @{ Name = 'ConvertTo-SecureString plaintext'; Pattern = 'ConvertTo-SecureString\s+-String' }
        @{ Name = 'net use /user:';             Pattern = 'net\s+use.*\/user:' }
        @{ Name = '/password:';                 Pattern = '/password:' }
        @{ Name = '-Credential PSCredential';   Pattern = '-Credential.*PSCredential' }
        @{ Name = 'connection string password'; Pattern = '(pwd|password)\s*=\s*[^;''"]+' }
    )

    # UNC path pattern
    $uncPathPattern = '\\\\[a-zA-Z0-9_.%-]+\\[a-zA-Z0-9$_.%-]+'

    # URL pattern
    $urlPattern = 'https?://[a-zA-Z0-9._%-]+(?:/[^\s''"]*)?'

    $maxFileSize = 1MB  # 1 MB limit to avoid memory issues
    $scriptAnalysis = [System.Collections.Generic.List[hashtable]]::new()

    # Gather all script files from NETLOGON for analysis
    $scriptFiles = @($result.NetlogonFiles | Where-Object {
        $_.Extension -in $scriptExtensions -and $_.Size -le $maxFileSize -and $_.Size -gt 0
    })

    $analyzed = 0
    foreach ($scriptFile in $scriptFiles) {
        $analyzed++
        if (-not $Quiet -and ($analyzed % 25 -eq 0 -or $analyzed -eq 1)) {
            Write-ProgressLine -Phase RECON -Message 'Analyzing script' `
                -Detail "$analyzed / $($scriptFiles.Count)"
        }

        $analysis = @{
            FilePath             = $scriptFile.Path
            RelativePath         = $scriptFile.RelativePath
            Extension            = $scriptFile.Extension
            Size                 = $scriptFile.Size
            LastWriteTime        = $scriptFile.LastWriteTime
            HardcodedCredentials = $false
            CredentialMatches    = @()
            PlaintextPasswords   = $false
            PasswordMatches      = @()
            LOLBinsUsage         = $false
            LOLBinsFound         = @()
            ExternalResources    = $false
            ExternalResourceList = @()
            WorldWritable        = $false
            UNCPaths             = @()
        }

        try {
            $content = [System.IO.File]::ReadAllText($scriptFile.Path)
            $lines = $content -split '\r?\n'

            # Check for credential patterns
            $credMatches = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($credPattern in $credentialPatterns) {
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match $credPattern.Pattern) {
                        $credMatches.Add(@{
                            Pattern    = $credPattern.Name
                            LineNumber = $i + 1
                            Line       = $lines[$i].Trim().Substring(0, [Math]::Min($lines[$i].Trim().Length, 200))
                        })
                    }
                }
            }
            if ($credMatches.Count -gt 0) {
                $analysis.HardcodedCredentials = $true
                $analysis.CredentialMatches = @($credMatches)
                $analysis.PlaintextPasswords = $true
                $analysis.PasswordMatches = @($credMatches)
            }

            # Check for LOLBins
            $lolbinsFound = [System.Collections.Generic.List[string]]::new()
            foreach ($lolbin in $lolbinPatterns) {
                if ($content -match $lolbin.Pattern) {
                    $lolbinsFound.Add($lolbin.Name)
                }
            }
            if ($lolbinsFound.Count -gt 0) {
                $analysis.LOLBinsUsage = $true
                $analysis.LOLBinsFound = @($lolbinsFound)
            }

            # Extract UNC paths
            $uncMatches = [regex]::Matches($content, $uncPathPattern)
            $uncPaths = @($uncMatches | ForEach-Object { $_.Value } | Sort-Object -Unique)
            $analysis.UNCPaths = $uncPaths

            # Extract URLs
            $urlMatches = [regex]::Matches($content, $urlPattern)
            $urls = @($urlMatches | ForEach-Object { $_.Value } | Sort-Object -Unique)

            # Determine external resources: UNC paths and URLs not pointing to domain controllers
            $externalResources = [System.Collections.Generic.List[string]]::new()
            foreach ($unc in $uncPaths) {
                # Extract the server portion from the UNC path
                if ($unc -match '^\\\\([^\\]+)') {
                    $server = $Matches[1].ToLower()
                    # Consider it external if it doesn't match the domain name or common domain patterns
                    if ($server -ne $domainName -and
                        $server -notmatch "^dc\d*\." -and
                        $server -notmatch "\.$([regex]::Escape($domainName))$" -and
                        $server -ne 'localhost' -and
                        $server -ne '127.0.0.1') {
                        $externalResources.Add($unc)
                    }
                }
            }
            foreach ($url in $urls) {
                $externalResources.Add($url)
            }
            if ($externalResources.Count -gt 0) {
                $analysis.ExternalResources = $true
                $analysis.ExternalResourceList = @($externalResources)
            }

            # Check if file is world-writable
            try {
                $fileAcl = Get-Acl -LiteralPath $scriptFile.Path -ErrorAction SilentlyContinue
                if ($fileAcl) {
                    foreach ($ace in $fileAcl.Access) {
                        $identity = $ace.IdentityReference.Value
                        $isWorldIdentity = $identity -match '\\Everyone$' -or
                                           $identity -eq 'Everyone' -or
                                           $identity -match '\\Users$' -or
                                           $identity -match 'BUILTIN\\Users' -or
                                           $identity -eq 'S-1-1-0' -or
                                           $identity -eq 'S-1-5-32-545'

                        if ($isWorldIdentity -and
                            $ace.AccessControlType -eq 'Allow' -and
                            (($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -or
                             ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -or
                             ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl))) {
                            $analysis.WorldWritable = $true
                            break
                        }
                    }
                }
            } catch {
                Write-Verbose "Failed to read ACL for script $($scriptFile.Path): $_"
            }
        } catch {
            Write-Verbose "Failed to analyze script $($scriptFile.Path): $_"
            $result.Errors["ScriptAnalysis:$($scriptFile.RelativePath)"] = $_.Exception.Message
        }

        $scriptAnalysis.Add($analysis)
    }

    $result.ScriptAnalysis = @($scriptAnalysis)

    # ── Summary ─────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $credCount = @($scriptAnalysis | Where-Object { $_.HardcodedCredentials }).Count
        $lolCount  = @($scriptAnalysis | Where-Object { $_.LOLBinsUsage }).Count
        $wwCount   = @($scriptAnalysis | Where-Object { $_.WorldWritable }).Count

        $summary = "Logon script analysis complete: $($scriptAnalysis.Count) script(s) analyzed"
        $details = @()
        if ($credCount -gt 0) { $details += "$credCount with credentials" }
        if ($lolCount -gt 0)  { $details += "$lolCount with LOLBins" }
        if ($wwCount -gt 0)   { $details += "$wwCount world-writable" }
        if ($details.Count -gt 0) {
            $summary += " ($($details -join ', '))"
        }
        Write-ProgressLine -Phase RECON -Message $summary
    }

    return $result
}
