# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function ConvertTo-GeminiDerivedSettings {
    <#
    .SYNOPSIS
        Derive the current state of the deep Gemini admin settings from Google
        Admin audit-log events.

    .DESCRIPTION
        The Gemini Alpha-features, conversation-history, conversation-retention,
        and conversation-sharing settings are exposed by NO Google config or
        policy API. The only programmatic signal is the admin audit log: when an
        admin changes one of these settings, Google records a
        CHANGE_APPLICATION_SETTING event carrying the new value. This is exactly
        how CISA ScubaGoggles derives them. This function replays those events
        (as returned by Invoke-GoogleReportsApi) and returns the most-recent
        value per setting.

        HONESTY CONTRACT — this is INFERENCE, not a config read:
          * It can only see settings CHANGED within the audit-log retention
            window (~6 months). A setting never touched from its default emits no
            event, so it is (correctly) ABSENT from the output and the check
            SKIPs. ScubaGoggles has the identical blind spot.
          * Each returned value carries Timestamp + SettingName so the consuming
            check can label the verdict "inferred from audit-log", never assert
            it as ground truth.
          * The SETTING_NAME literals Google uses are matched by PATTERN below and
            are BEST-EFFORT pending one live-tenant confirmation. An unmatched
            setting, or a NEW_VALUE that cannot be interpreted, yields an ABSENT
            key (=> SKIP) — never a guessed verdict. That failure mode is safe:
            worst case we are back to the honest SKIP we shipped before.
    #>
    [CmdletBinding()]
    param(
        # Flat event list as returned by Invoke-GoogleReportsApi: hashtables with
        # EventName / Timestamp / Params (a name->value hashtable).
        [object[]]$Events = @()
    )

    # A setting-change event in the Google Admin audit log. Observed on a live
    # tenant (2026-07-07): generative-AI settings can fire under
    # CHANGE_CHROME_OS_USER_SETTING, not only *_APPLICATION_SETTING. Match ANY
    # create/change event whose name ends in _SETTING rather than a fixed list, so
    # the Workspace-Gemini event name (still unconfirmed) is caught whatever its
    # exact prefix. Over-matching here is harmless — the gen-AI scope AND the
    # per-setting sub-pattern below both still have to pass.
    $isSettingChange = { param($n) "$n" -match '(?i)(change|create).*_setting$' }

    # Scope to generative-AI settings. CRITICAL live finding (2026-07-07): Google
    # abbreviates the family as `gen_ai_*` (e.g. gen_ai_default_settings), which
    # contains NEITHER "gemini" NOR "generative" as a substring — the original
    # pattern silently matched nothing. Match gen_ai / genai / gemini / generative.
    $genAiScope = '(?i)gen.?ai|gemini|generative'

    # Value normalizers. Return $null to mean "recognized setting, but the value
    # is not interpretable" — the caller then treats the key as absent (SKIP).
    $onOff = {
        param($v)
        $s = "$v".Trim().ToLowerInvariant()
        if ($s -in @('true', 'on', 'enabled', 'enable', '1', 'allow', 'allowed')) { return 'on' }
        if ($s -in @('false', 'off', 'disabled', 'disable', '0', 'deny', 'denied', 'none')) { return 'off' }
        return $null
    }
    $months = {
        param($v)
        if ("$v" -match '(\d+)') { return [int]$Matches[1] }
        return $null
    }

    # Best-effort SETTING_NAME patterns. Isolated here so a single live-tenant
    # confirmation can correct any literal without touching the checks.
    $map = @(
        @{ Key = 'AlphaFeatures';       Pattern = 'alpha';                         Normalize = $onOff  }
        @{ Key = 'ConversationHistory'; Pattern = 'conversation.?history|history'; Normalize = $onOff  }
        @{ Key = 'RetentionMonths';     Pattern = 'retention';                     Normalize = $months }
        @{ Key = 'ConversationSharing'; Pattern = 'shar';                          Normalize = $onOff  }
    )

    $result = @{}

    # Setting-change events whose application OR setting name is Gemini/Gen-AI.
    $geminiEvents = @($Events | Where-Object {
        $_ -and $_.Params -and (& $isSettingChange $_.EventName) -and (
            ("$($_.Params['APPLICATION_NAME'])" -match $genAiScope) -or
            ("$($_.Params['SETTING_NAME'])"     -match $genAiScope)
        )
    })

    foreach ($m in $map) {
        $candidates = @($geminiEvents | Where-Object {
            "$($_.Params['SETTING_NAME'])" -match "(?i)$($m.Pattern)"
        })
        if ($candidates.Count -eq 0) { continue }

        # Most-recent event wins — that is the current state. Parse the ISO-8601
        # timestamp to sort chronologically (do not rely on string ordering).
        $latest = $candidates | Sort-Object -Property @{ Expression = {
            $dt = [datetime]::MinValue
            [void][datetime]::TryParse("$($_.Timestamp)", [ref]$dt)
            $dt
        } } | Select-Object -Last 1

        $raw = $latest.Params['NEW_VALUE']
        $norm = & $m.Normalize $raw
        if ($null -eq $norm) { continue }   # recognized setting, uninterpretable value -> SKIP

        $result[$m.Key] = @{
            Value       = $norm
            RawValue    = "$raw"
            SettingName = "$($latest.Params['SETTING_NAME'])"
            Timestamp   = "$($latest.Timestamp)"
        }
    }

    return $result
}

function Get-GeminiInferredDetails {
    <#
    .SYNOPSIS
        Build the standard Details block that labels a Gemini finding as inferred
        from the audit log (never a direct config read).
    #>
    [CmdletBinding()]
    param([hashtable]$Derived)

    return @{
        Confidence   = 'Inferred (audit-log)'
        DerivedValue = $Derived.Value
        RawValue     = $Derived.RawValue
        SettingName  = $Derived.SettingName
        DerivedFrom  = $Derived.Timestamp
        Source       = 'Google Admin Reports API setting-change event'
        Note         = 'Value inferred from the most recent admin setting-change event, not a direct config read (no config API exposes this Gemini setting). Absent a change event the setting is Not Assessed. Confirm in the Admin Console.'
    }
}
