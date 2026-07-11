# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# GUI-driven alert-provider entry (the "Add Provider" modal on the Signals tab).
# Mirrors Show-AddCredentialDialog: a pure builder (New-SignalProviderEntry) that turns
# collected field values into the exact { Type, VaultKey, Secret, SeverityThreshold,
# ProviderConfig } shape the Signals tab stores, plus a modal WPF dialog to collect them.
#
# Storage convention is identical to Set-Safehouse / Invoke-CredentialMigration and is
# read back by Send-Signal's channel resolver:
#   teams/slack/webhook/pagerduty -> vault secret is a single string
#   pushover/sendgrid/mailgun/twilio -> vault secret is a compact JSON blob
#   syslog/eventlog -> no secret (config-only)
# Canonical vault keys match Invoke-CredentialMigration:
#   GUERRILLA_TEAMS_WEBHOOK, GUERRILLA_SLACK_WEBHOOK, GUERRILLA_WEBHOOK_URL,
#   GUERRILLA_PAGERDUTY_KEY, GUERRILLA_PUSHOVER_KEY, GUERRILLA_SENDGRID_KEY,
#   GUERRILLA_MAILGUN_KEY, GUERRILLA_TWILIO_KEY.

function Get-SignalProviderCatalog {
    <#
    .SYNOPSIS
        Returns the static catalog of alert-provider types: canonical vault key, secret
        format (None/String/Json), and the dialog field set. Single source of truth shared
        by the dialog and the Signals tab handlers. Pure — unit-testable.
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{ Type = 'teams';     Display = 'Microsoft Teams (webhook)'; VaultKey = 'GUERRILLA_TEAMS_WEBHOOK'; SecretFormat = 'String'; Fields = @('Url') }
        [PSCustomObject]@{ Type = 'slack';     Display = 'Slack (webhook)';           VaultKey = 'GUERRILLA_SLACK_WEBHOOK'; SecretFormat = 'String'; Fields = @('Url') }
        [PSCustomObject]@{ Type = 'webhook';   Display = 'Generic webhook / SIEM';     VaultKey = 'GUERRILLA_WEBHOOK_URL';   SecretFormat = 'String'; Fields = @('Url') }
        [PSCustomObject]@{ Type = 'pagerduty'; Display = 'PagerDuty (Events v2)';      VaultKey = 'GUERRILLA_PAGERDUTY_KEY'; SecretFormat = 'String'; Fields = @('RoutingKey') }
        [PSCustomObject]@{ Type = 'pushover';  Display = 'Pushover';                   VaultKey = 'GUERRILLA_PUSHOVER_KEY';  SecretFormat = 'Json';   Fields = @('ApiToken', 'UserKey') }
        [PSCustomObject]@{ Type = 'sendgrid';  Display = 'Email — SendGrid';           VaultKey = 'GUERRILLA_SENDGRID_KEY';  SecretFormat = 'Json';   Fields = @('ApiKey', 'FromEmail', 'ToEmails') }
        [PSCustomObject]@{ Type = 'mailgun';   Display = 'Email — Mailgun';            VaultKey = 'GUERRILLA_MAILGUN_KEY';   SecretFormat = 'Json';   Fields = @('ApiKey', 'Domain', 'FromEmail', 'ToEmails') }
        [PSCustomObject]@{ Type = 'twilio';    Display = 'SMS — Twilio';               VaultKey = 'GUERRILLA_TWILIO_KEY';    SecretFormat = 'Json';   Fields = @('AccountSid', 'AuthToken', 'FromNumber', 'ToNumbers') }
        [PSCustomObject]@{ Type = 'syslog';    Display = 'Syslog (CEF/LEEF)';          VaultKey = $null;                     SecretFormat = 'None';   Fields = @('Server', 'Port') }
        [PSCustomObject]@{ Type = 'eventlog';  Display = 'Windows Event Log';          VaultKey = $null;                     SecretFormat = 'None';   Fields = @() }
    )
}

function New-SignalProviderEntry {
    <#
    .SYNOPSIS
        Pure builder: validates collected dialog values and returns the provider entry to
        store, or a list of error strings. No UI, no side effects — unit-testable.
    .DESCRIPTION
        On success returns a PSCustomObject:
          Type              - provider type (teams/slack/.../eventlog)
          VaultKey          - canonical vault key, or $null for config-only providers
          Secret            - the exact value to write to the vault (string, or compact
                              JSON for pushover/sendgrid/mailgun/twilio), or $null
          SeverityThreshold - per-provider minimum threat level (or '' for inherit)
          ProviderConfig    - the config.alerting.providers.<type> block to merge
                              (non-secret settings + vaultKey + enabled=true), matching
                              what Send-Signal reads back.
        On failure returns @{ Errors = @(...) }.
    .PARAMETER Type
        Provider type from Get-SignalProviderCatalog.
    .PARAMETER Fields
        Hashtable of the raw field values from the dialog.
    .PARAMETER SeverityThreshold
        ALL / LOW / MEDIUM / HIGH / CRITICAL. 'ALL' or '' means inherit the global level.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][hashtable]$Fields,
        [string]$SeverityThreshold = 'ALL'
    )

    $catalog = Get-SignalProviderCatalog
    $spec = $catalog | Where-Object Type -eq $Type | Select-Object -First 1
    if (-not $spec) { return @{ Errors = @("Unknown provider type '$Type'.") } }

    $errs = [System.Collections.Generic.List[string]]::new()
    $url = '^https?://'
    $email = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

    # Normalize the per-provider threshold: 'ALL'/'' inherits the global minimum.
    $threshold = if ($SeverityThreshold -and $SeverityThreshold -ne 'ALL') { $SeverityThreshold } else { '' }

    $secret = $null
    $provCfg = @{ enabled = $true }
    if ($spec.VaultKey) { $provCfg.vaultKey = $spec.VaultKey }
    if ($threshold)     { $provCfg.minimumThreatLevel = $threshold }

    switch ($Type) {
        { $_ -in @('teams', 'slack', 'webhook') } {
            $u = "$($Fields.Url)".Trim()
            if ($u -notmatch $url) { $errs.Add('Webhook URL must start with http:// or https://') }
            $secret = $u
            # config carries the same field Send-Signal injects from the vault
            if ($Type -eq 'webhook') { $provCfg.url = $u } else { $provCfg.webhookUrl = $u }
        }
        'pagerduty' {
            $k = "$($Fields.RoutingKey)".Trim()
            if (-not $k) { $errs.Add('PagerDuty routing key is required.') }
            $secret = $k
            $provCfg.routingKey = $k
        }
        'pushover' {
            $token = "$($Fields.ApiToken)".Trim()
            $user = "$($Fields.UserKey)".Trim()
            if (-not $token) { $errs.Add('Pushover application API token is required.') }
            if (-not $user)  { $errs.Add('Pushover user/group key is required.') }
            $secret = (@{ apiToken = $token; userKey = $user } | ConvertTo-Json -Compress)
            $provCfg.apiToken = $token
            $provCfg.userKey = $user
        }
        { $_ -in @('sendgrid', 'mailgun') } {
            $apiKey = "$($Fields.ApiKey)".Trim()
            $from = "$($Fields.FromEmail)".Trim()
            $toRaw = "$($Fields.ToEmails)".Trim()
            $to = @(($toRaw -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (-not $apiKey) { $errs.Add('API key is required.') }
            if ($from -notmatch $email) { $errs.Add('From email must be a valid address.') }
            if ($to.Count -eq 0) { $errs.Add('At least one recipient email is required.') }
            elseif (@($to | Where-Object { $_ -notmatch $email }).Count -gt 0) { $errs.Add('One or more recipient emails are invalid.') }

            $blob = [ordered]@{ provider = $Type; apiKey = $apiKey; fromEmail = $from; toEmails = $to }
            $provCfg.apiKey = $apiKey
            $provCfg.fromEmail = $from
            $provCfg.toEmails = $to
            if ($Type -eq 'mailgun') {
                $domain = "$($Fields.Domain)".Trim()
                if (-not $domain -and $from -match '@(.+)$') { $domain = $Matches[1] }
                if (-not $domain) { $errs.Add('Mailgun sending domain is required.') }
                $blob.domain = $domain
                $provCfg.domain = $domain
            }
            $secret = ($blob | ConvertTo-Json -Compress)
        }
        'twilio' {
            $sid = "$($Fields.AccountSid)".Trim()
            $token = "$($Fields.AuthToken)".Trim()
            $fromNum = "$($Fields.FromNumber)".Trim()
            $toRaw = "$($Fields.ToNumbers)".Trim()
            $toNums = @(($toRaw -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (-not $sid)     { $errs.Add('Twilio Account SID is required.') }
            if (-not $token)   { $errs.Add('Twilio auth token is required.') }
            if (-not $fromNum) { $errs.Add('Twilio from number is required.') }
            if ($toNums.Count -eq 0) { $errs.Add('At least one destination number is required.') }
            $secret = (@{ accountSid = $sid; authToken = $token; fromNumber = $fromNum; toNumbers = $toNums } | ConvertTo-Json -Compress)
            $provCfg.accountSid = $sid
            $provCfg.authToken = $token
            $provCfg.fromNumber = $fromNum
            $provCfg.toNumbers = $toNums
        }
        'syslog' {
            $server = "$($Fields.Server)".Trim()
            if (-not $server) { $errs.Add('Syslog server host is required.') }
            $port = 514
            if ("$($Fields.Port)".Trim()) {
                if (-not [int]::TryParse("$($Fields.Port)".Trim(), [ref]$port)) { $errs.Add('Syslog port must be a number.') }
            }
            $provCfg.server = $server
            $provCfg.port = $port
        }
        'eventlog' {
            # No fields/secret — config-only. Defaults applied by Send-SignalEventLog.
        }
        default { $errs.Add("Unknown provider type '$Type'.") }
    }

    if ($errs.Count -gt 0) { return @{ Errors = @($errs) } }

    return [PSCustomObject]@{
        Type              = $Type
        VaultKey          = $spec.VaultKey
        Secret            = $secret
        SeverityThreshold = $threshold
        ProviderConfig    = $provCfg
    }
}

function Show-AddSignalDialog {
    <#
    .SYNOPSIS
        Modal WPF dialog to add an alert/signal provider. Returns the provider entry from
        New-SignalProviderEntry (Type / VaultKey / Secret / SeverityThreshold /
        ProviderConfig), or $null if cancelled.
    #>
    [CmdletBinding()]
    param(
        $Owner
    )

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Add Signal Provider" Width="540" Height="520" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" Background="#F4F6F8" FontFamily="Segoe UI" Foreground="#1F2933">
  <Window.Resources>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#1F2933"/><Setter Property="Margin" Value="0,8,0,2"/></Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,5"/><Setter Property="CaretBrush" Value="#1F2933"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" SnapsToDevicePixels="True">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,5"/><Setter Property="CaretBrush" Value="#1F2933"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" SnapsToDevicePixels="True">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="#FFFFFF"/><Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/><Setter Property="Padding" Value="8,4"/><Setter Property="Height" Value="28"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#2563EB"/><Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="16,6"/><Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid Margin="20">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Add an alert/signal provider" FontSize="16" FontWeight="Bold"/>

    <Grid Grid.Row="1" Margin="0,12,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <TextBlock Grid.Column="0" Text="Provider type" VerticalAlignment="Center"/>
      <ComboBox Grid.Column="1" x:Name="cb_Type"/>
    </Grid>

    <Grid Grid.Row="2" Margin="0,8,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <TextBlock Grid.Column="0" Text="Severity threshold" VerticalAlignment="Center"/>
      <ComboBox Grid.Column="1" x:Name="cb_Severity">
        <ComboBoxItem Content="ALL" IsSelected="True"/>
        <ComboBoxItem Content="LOW"/>
        <ComboBoxItem Content="MEDIUM"/>
        <ComboBoxItem Content="HIGH"/>
        <ComboBoxItem Content="CRITICAL"/>
      </ComboBox>
    </Grid>

    <!-- Field stack — populated per selected type in code-behind -->
    <ScrollViewer Grid.Row="3" VerticalScrollBarVisibility="Auto" Margin="0,8,0,0">
      <StackPanel x:Name="sp_Fields"/>
    </ScrollViewer>

    <TextBlock x:Name="tb_Error" Grid.Row="4" Foreground="#DC2626" TextWrapping="Wrap" Margin="0,8,0,0"/>

    <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="btn_Cancel" Content="Cancel" Background="#FFFFFF" Foreground="#1F2933" BorderBrush="#E2E8F0" BorderThickness="1" Margin="0,0,8,0"/>
      <Button x:Name="btn_Save" Content="Add provider"/>
    </StackPanel>
  </Grid>
</Window>
'@

    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $win = [System.Windows.Markup.XamlReader]::Load($reader)
    if ($Owner) { $win.Owner = $Owner }

    $ctl = @{}
    foreach ($n in 'cb_Type', 'cb_Severity', 'sp_Fields', 'tb_Error', 'btn_Cancel', 'btn_Save') {
        $ctl[$n] = $win.FindName($n)
    }

    $catalog = Get-SignalProviderCatalog

    # Friendly labels + secret-masking hints for each dialog field.
    $fieldMeta = @{
        Url        = @{ Label = 'Webhook URL';                 Secret = $false }
        RoutingKey = @{ Label = 'Routing / integration key';   Secret = $true  }
        ApiToken   = @{ Label = 'Application API token';        Secret = $true  }
        UserKey    = @{ Label = 'User / group key';            Secret = $false }
        ApiKey     = @{ Label = 'API key';                     Secret = $true  }
        FromEmail  = @{ Label = 'From email address';          Secret = $false }
        ToEmails   = @{ Label = 'To emails (comma-separated)';  Secret = $false }
        Domain     = @{ Label = 'Sending domain';              Secret = $false }
        AccountSid = @{ Label = 'Account SID';                 Secret = $false }
        AuthToken  = @{ Label = 'Auth token';                  Secret = $true  }
        FromNumber = @{ Label = 'From number (e.g. +15551234567)'; Secret = $false }
        ToNumbers  = @{ Label = 'To numbers (comma-separated)'; Secret = $false }
        Server     = @{ Label = 'Syslog server host';          Secret = $false }
        Port       = @{ Label = 'Port (default 514)';          Secret = $false }
    }

    # Populate the type dropdown.
    foreach ($spec in $catalog) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $spec.Display
        $item.Tag     = $spec.Type
        [void]$ctl.cb_Type.Items.Add($item)
    }
    $ctl.cb_Type.SelectedIndex = 0

    # Map of field-name -> input control for the currently-shown type.
    $fieldControls = @{}

    $rebuildFields = {
        $sel = $ctl.cb_Type.SelectedItem
        if (-not $sel) { return }
        $type = [string]$sel.Tag
        $spec = $catalog | Where-Object Type -eq $type | Select-Object -First 1
        $ctl.sp_Fields.Children.Clear()
        $fieldControls.Clear()
        if (-not $spec -or $spec.Fields.Count -eq 0) {
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.Text = 'This provider needs no fields — it is configured by defaults on this host.'
            $tb.Foreground = '#94A3B8'
            $tb.TextWrapping = 'Wrap'
            [void]$ctl.sp_Fields.Children.Add($tb)
            return
        }
        foreach ($f in $spec.Fields) {
            $meta = $fieldMeta[$f]
            $lbl = New-Object System.Windows.Controls.TextBlock
            $lbl.Text = if ($meta) { $meta.Label } else { $f }
            [void]$ctl.sp_Fields.Children.Add($lbl)
            if ($meta -and $meta.Secret) {
                $box = New-Object System.Windows.Controls.PasswordBox
            } else {
                $box = New-Object System.Windows.Controls.TextBox
            }
            [void]$ctl.sp_Fields.Children.Add($box)
            $fieldControls[$f] = $box
        }
    }.GetNewClosure()

    $ctl.cb_Type.Add_SelectionChanged($rebuildFields)
    & $rebuildFields

    $result = @{ Entry = $null }

    $ctl.btn_Cancel.Add_Click({ $win.Close() }.GetNewClosure())

    $ctl.btn_Save.Add_Click({
        $sel = $ctl.cb_Type.SelectedItem
        $type = [string]$sel.Tag
        $fields = @{}
        foreach ($k in $fieldControls.Keys) {
            $box = $fieldControls[$k]
            $fields[$k] = if ($box -is [System.Windows.Controls.PasswordBox]) { $box.Password } else { $box.Text }
        }
        $severity = "$($ctl.cb_Severity.SelectedItem.Content)"

        $built = New-SignalProviderEntry -Type $type -Fields $fields -SeverityThreshold $severity
        if ($built -is [hashtable] -and $built.Errors) {
            $ctl.tb_Error.Text = ($built.Errors -join '  ')
            return
        }
        $result.Entry = $built
        $win.Close()
    }.GetNewClosure())

    [void]$win.ShowDialog()
    return $result.Entry
}
