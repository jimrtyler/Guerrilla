# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Proves the audit-log inference MECHANISM behind the Gemini deep-setting checks
# (GWS-GEMINI-002/003/004/005). The exact Google SETTING_NAME literals are
# best-effort pending live confirmation, but the mechanism this pins is fixed:
#   * most-recent change-event wins (that is the current state)
#   * on/off + month values normalize correctly
#   * an unrecognized setting or uninterpretable value yields NO key (=> SKIP),
#     never a guessed verdict — the safe fallback that keeps this honest.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' '..' 'Helpers' 'TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'ConvertTo-GeminiDerivedSettings' {

    It 'derives on/off and month values from Gemini setting-change events' {
        $r = InModuleScope PSGuerrilla {
            $e = @(
                @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini Alpha features';         NEW_VALUE='false' } }
                @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-05-02T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini conversation history';   NEW_VALUE='true'  } }
                @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-05-03T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini conversation retention'; NEW_VALUE='18'    } }
                @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-05-04T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini conversation sharing';   NEW_VALUE='false' } }
            )
            ConvertTo-GeminiDerivedSettings -Events $e
        }
        $r['AlphaFeatures'].Value       | Should -Be 'off'
        $r['ConversationHistory'].Value | Should -Be 'on'
        $r['RetentionMonths'].Value     | Should -Be 18
        $r['ConversationSharing'].Value | Should -Be 'off'
    }

    It 'takes the MOST RECENT event per setting as the current state' {
        $r = InModuleScope PSGuerrilla {
            $e = @(
                @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-01-01T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini Alpha features'; NEW_VALUE='true'  } }
                @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-06-01T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini Alpha features'; NEW_VALUE='false' } }
            )
            ConvertTo-GeminiDerivedSettings -Events $e
        }
        $r['AlphaFeatures'].Value     | Should -Be 'off'
        $r['AlphaFeatures'].Timestamp | Should -Be '2026-06-01T10:00:00.000Z'
    }

    It 'omits a setting whose value cannot be interpreted (=> check SKIPs, no guess)' {
        $r = InModuleScope PSGuerrilla {
            $e = @( @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Gemini for Workspace'; SETTING_NAME='Gemini Alpha features'; NEW_VALUE='purple' } } )
            ConvertTo-GeminiDerivedSettings -Events $e
        }
        $r.ContainsKey('AlphaFeatures') | Should -BeFalse
    }

    It 'matches Google''s real gen_ai_* naming under CHANGE_CHROME_OS_USER_SETTING (live 2026-07-07)' {
        # Live finding: gen-AI settings use SETTING_NAME=gen_ai_* (no "gemini"/"generative"
        # substring) and can fire under CHANGE_CHROME_OS_USER_SETTING. The derivation must
        # still catch a targeted setting under that naming/event.
        $r = InModuleScope PSGuerrilla {
            $e = @( @{ EventName='CHANGE_CHROME_OS_USER_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ SETTING_NAME='gen_ai_alpha_features'; NEW_VALUE='false' } } )
            ConvertTo-GeminiDerivedSettings -Events $e
        }
        $r['AlphaFeatures'].Value | Should -Be 'off'
    }

    It 'does NOT fabricate a verdict from gen_ai settings that match no target sub-pattern (no overfit)' {
        # The real observed gen_ai wallpaper/image settings must NOT map to any of the
        # four GWS-GEMINI checks — the app-scope broadening stays safe because the
        # per-setting sub-pattern still gates.
        $r = InModuleScope PSGuerrilla {
            $e = @(
                @{ EventName='CHANGE_CHROME_OS_USER_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ SETTING_NAME='gen_ai_wallpaper_settings';    NEW_VALUE='true' } }
                @{ EventName='CHANGE_CHROME_OS_USER_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ SETTING_NAME='gen_ai_inline_image_settings'; NEW_VALUE='true' } }
                @{ EventName='CHANGE_CHROME_OS_USER_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ SETTING_NAME='gen_ai_default_settings';      NEW_VALUE='true' } }
            )
            ConvertTo-GeminiDerivedSettings -Events $e
        }
        $r.Keys.Count | Should -Be 0
    }

    It 'ignores non-Gemini application setting changes' {
        $r = InModuleScope PSGuerrilla {
            $e = @( @{ EventName='CHANGE_APPLICATION_SETTING'; Timestamp='2026-05-01T10:00:00.000Z'; Params=@{ APPLICATION_NAME='Drive and Docs'; SETTING_NAME='Drive sharing'; NEW_VALUE='true' } } )
            ConvertTo-GeminiDerivedSettings -Events $e
        }
        $r.Keys.Count | Should -Be 0
    }

    It 'returns an empty map for no events (never throws, never fabricates)' {
        $r = InModuleScope PSGuerrilla { ConvertTo-GeminiDerivedSettings -Events @() }
        $r.Keys.Count | Should -Be 0
    }
}
