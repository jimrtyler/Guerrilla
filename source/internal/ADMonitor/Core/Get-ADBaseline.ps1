# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CurrentData
    )

    $baseline = @{
        generatedAt   = [datetime]::UtcNow.ToString('o')
        scanMode      = $CurrentData.scanMode
        domainName    = $CurrentData.domainName
    }

    # ── Privileged group membership hashes ─────────────────────────────
    # Store both the sorted member list and a hash for quick comparison
    $groupBaseline = @{}
    foreach ($groupName in $CurrentData.privilegedGroups.Keys) {
        $members = @($CurrentData.privilegedGroups[$groupName] | Sort-Object)
        $memberHash = if ($members.Count -gt 0) {
            $joined = $members -join '|'
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
            $hashBytes = $sha.ComputeHash($bytes)
            [BitConverter]::ToString($hashBytes) -replace '-', ''
        } else { 'EMPTY' }

        $groupBaseline[$groupName] = @{
            members    = $members
            memberHash = $memberHash
            count      = $members.Count
        }
    }
    $baseline['privilegedGroups'] = $groupBaseline

    # ── AdminSDHolder ACL hash ─────────────────────────────────────────
    $aclEntries = @($CurrentData.adminSDHolderACL | ForEach-Object {
        "$($_.identity)|$($_.rights)|$($_.type)"
    } | Sort-Object)

    $baseline['adminSDHolderACL'] = @{
        entries  = @($CurrentData.adminSDHolderACL)
        aclHash  = if ($aclEntries.Count -gt 0) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $joined = $aclEntries -join '||'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
            $hashBytes = $sha.ComputeHash($bytes)
            [BitConverter]::ToString($hashBytes) -replace '-', ''
        } else { 'EMPTY' }
        count    = $aclEntries.Count
    }

    # ── krbtgt state ───────────────────────────────────────────────────
    $baseline['krbtgt'] = @{
        pwdLastSet  = $CurrentData.krbtgtPwdLastSet
        keyVersion  = $CurrentData.krbtgtKeyVersion
    }

    # ── Trust relationships ────────────────────────────────────────────
    $trustBaseline = @{}
    foreach ($trust in $CurrentData.trusts) {
        $trustKey = $trust.name.ToLower()
        $trustBaseline[$trustKey] = @{
            name             = $trust.name
            flatName         = $trust.flatName
            direction        = $trust.direction
            type             = $trust.type
            isTransitive     = $trust.isTransitive
            sidFiltering     = $trust.sidFiltering
            forestTransitive = $trust.forestTransitive
            trustAttributes  = $trust.trustAttributes
            trustSID         = $trust.trustSID
        }
    }
    $baseline['trusts'] = $trustBaseline

    # ── GPO Objects (Full mode) ────────────────────────────────────────
    $gpoBaseline = @{}
    foreach ($gpoGuid in $CurrentData.gpoObjects.Keys) {
        $gpo = $CurrentData.gpoObjects[$gpoGuid]
        $linkHash = ($gpo.linkedTo | ForEach-Object {
            "$($_.containerDN)|$($_.isEnabled)|$($_.isEnforced)"
        } | Sort-Object) -join '||'

        $gpoBaseline[$gpoGuid] = @{
            name          = $gpo.name
            whenChanged   = $gpo.whenChanged
            versionNumber = $gpo.versionNumber
            flags         = $gpo.flags
            isLinked      = $gpo.isLinked
            linkHash      = if ($linkHash) {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($linkHash)
                $hashBytes = $sha.ComputeHash($bytes)
                [BitConverter]::ToString($hashBytes) -replace '-', ''
            } else { 'EMPTY' }
            linkedTo      = @($gpo.linkedTo)
        }
    }
    $baseline['gpoObjects'] = $gpoBaseline

    # ── Sensitive ACLs (Full mode) ─────────────────────────────────────
    $aclBaseline = @{}
    foreach ($objName in $CurrentData.sensitiveAcls.Keys) {
        $objData = $CurrentData.sensitiveAcls[$objName]
        $aceStrings = @($objData.aces | ForEach-Object {
            "$($_.identity)|$($_.rights)|$($_.objectType)|$($_.objectDN)"
        } | Sort-Object)

        $aclBaseline[$objName] = @{
            objectDN = $objData.objectDN
            aces     = @($objData.aces)
            aceHash  = if ($aceStrings.Count -gt 0) {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $joined = $aceStrings -join '||'
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
                $hashBytes = $sha.ComputeHash($bytes)
                [BitConverter]::ToString($hashBytes) -replace '-', ''
            } else { 'EMPTY' }
            count    = $aceStrings.Count
        }
    }
    $baseline['sensitiveAcls'] = $aclBaseline

    # ── Certificate templates (Full mode) ──────────────────────────────
    $certBaseline = @{}
    foreach ($tmplName in $CurrentData.certTemplates.Keys) {
        $tmpl = $CurrentData.certTemplates[$tmplName]
        $certBaseline[$tmplName] = @{
            displayName             = $tmpl.displayName
            whenChanged             = $tmpl.whenChanged
            enrolleeSuppliesSubject = $tmpl.enrolleeSuppliesSubject
            allowsAuthentication    = $tmpl.allowsAuthentication
            isPublished             = $tmpl.isPublished
            schemaVersion           = $tmpl.schemaVersion
            enrollmentPermissions   = @($tmpl.enrollmentPermissions)
        }
    }
    $baseline['certTemplates'] = $certBaseline

    # ── Delegations (Full mode) ────────────────────────────────────────
    $delegationBaseline = @{}
    foreach ($ouDN in $CurrentData.delegations.Keys) {
        $entries = $CurrentData.delegations[$ouDN]
        $entryStrings = @($entries | ForEach-Object {
            "$($_.identity)|$($_.rights)|$($_.objectType)"
        } | Sort-Object)

        $delegationBaseline[$ouDN] = @{
            entries = @($entries)
            hash    = if ($entryStrings.Count -gt 0) {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $joined = $entryStrings -join '||'
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
                $hashBytes = $sha.ComputeHash($bytes)
                [BitConverter]::ToString($hashBytes) -replace '-', ''
            } else { 'EMPTY' }
            count   = $entryStrings.Count
        }
    }
    $baseline['delegations'] = $delegationBaseline

    # ── DNS records (Full mode) ────────────────────────────────────────
    $dnsSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rec in $CurrentData.dnsRecords) {
        [void]$dnsSet.Add("$($rec.zone)|$($rec.name)")
    }
    $baseline['dnsRecords'] = @{
        records = @($CurrentData.dnsRecords)
        recordSet = @($dnsSet | Sort-Object)
        count   = $dnsSet.Count
    }

    # ── Schema version (Full mode) ─────────────────────────────────────
    $baseline['schemaVersion'] = $CurrentData.schemaVersion

    return $baseline
}
