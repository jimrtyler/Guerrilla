# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# GUI-driven credential entry (the "Add Credential" modal on the Safehouse tab).
# Builds the list of vault entries from collected field values, and a dark WPF dialog
# to collect them. New-AddCredentialEntries is kept pure so it can be unit-tested without
# a UI; Show-AddCredentialDialog drives the actual window.

function New-AddCredentialEntries {
    <#
    .SYNOPSIS
        Pure builder: turns collected dialog field values into the vault entry list that
        Save-SafehouseCredentialSet stores. No UI, no side effects — unit-testable.
    .PARAMETER Environment
        'microsoftGraph' or 'googleWorkspace'.
    .PARAMETER Fields
        Hashtable of the raw field values from the dialog.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][hashtable]$Fields
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    switch ($Environment) {
        'microsoftGraph' {
            $entries.Add(@{ VaultKey = 'GUERRILLA_GRAPH_TENANT'; Value = $Fields.TenantId; Type = 'tenantId'
                Environment = 'microsoftGraph'; Description = 'Entra ID Tenant ID'; Identity = $Fields.TenantId })
            $entries.Add(@{ VaultKey = 'GUERRILLA_GRAPH_CLIENTID'; Value = $Fields.ClientId; Type = 'clientId'
                Environment = 'microsoftGraph'; Description = 'App Registration Client ID'; Identity = $Fields.ClientId })
            $secret = @{ VaultKey = 'GUERRILLA_GRAPH_SECRET'; Value = $Fields.ClientSecret; Type = 'clientSecret'
                Environment = 'microsoftGraph'; Description = 'Microsoft Graph Client Secret' }
            if ($Fields.Expiration) { $secret.ExpirationDate = $Fields.Expiration }
            $entries.Add($secret)
        }
        'googleWorkspace' {
            $entries.Add(@{ VaultKey = 'GUERRILLA_GWS_SA'; Value = $Fields.ServiceAccountJson; Type = 'serviceAccount'
                Environment = 'googleWorkspace'; Description = 'Google Workspace service account'; Identity = $Fields.SaClientEmail })
            $entries.Add(@{ VaultKey = 'GUERRILLA_GWS_SA_ADMIN_EMAIL'; Value = $Fields.AdminEmail; Type = 'adminEmail'
                Environment = 'googleWorkspace'; Description = 'Google Workspace delegated-admin email'; Identity = $Fields.AdminEmail })
        }
    }
    return $entries
}

function Test-AddCredentialFields {
    <#
    .SYNOPSIS
        Validates collected dialog values; returns an array of human-readable error
        strings (empty array = valid). Pure — unit-testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][hashtable]$Fields
    )

    $errs = [System.Collections.Generic.List[string]]::new()
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    switch ($Environment) {
        'microsoftGraph' {
            if ("$($Fields.TenantId)" -notmatch $guid) { $errs.Add('Tenant ID must be a GUID.') }
            if ("$($Fields.ClientId)" -notmatch $guid) { $errs.Add('Client ID must be a GUID.') }
            if (-not "$($Fields.ClientSecret)") { $errs.Add('Client Secret is required.') }
            if ($Fields.Expiration -and "$($Fields.Expiration)" -notmatch '^\d{4}-\d{2}-\d{2}$') {
                $errs.Add('Secret expiry must be YYYY-MM-DD (or left blank).')
            }
        }
        'googleWorkspace' {
            if (-not "$($Fields.ServiceAccountJson)") { $errs.Add('Service account JSON is required.') }
            elseif (-not $Fields.SaClientEmail)       { $errs.Add('Service account JSON is not valid (no client_email).') }
            if ("$($Fields.AdminEmail)" -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $errs.Add('A valid admin email is required.') }
        }
        default { $errs.Add("Unknown environment '$Environment'.") }
    }
    return @($errs)
}

function Show-AddCredentialDialog {
    <#
    .SYNOPSIS
        Modal WPF dialog to add Entra (Graph) or Google Workspace credentials to the vault.
        Returns the entry list to store (for Save-SafehouseCredentialSet), or $null if the
        user cancelled.
    #>
    [CmdletBinding()]
    param(
        $Owner
    )

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Add Credential" Width="520" Height="480" ResizeMode="NoResize"
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
    <Style TargetType="RadioButton"><Setter Property="Foreground" Value="#1F2933"/><Setter Property="Margin" Value="0,0,16,0"/></Style>
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
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Add a credential to the safehouse vault" FontSize="16" FontWeight="Bold"/>

    <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,12,0,8">
      <TextBlock Text="Environment:" VerticalAlignment="Center" Margin="0,0,12,0"/>
      <RadioButton x:Name="rb_Entra" Content="Microsoft Entra / Graph" GroupName="Env" IsChecked="True" VerticalAlignment="Center"/>
      <RadioButton x:Name="rb_Gws" Content="Google Workspace" GroupName="Env" VerticalAlignment="Center"/>
    </StackPanel>

    <Grid Grid.Row="2">
      <!-- Entra panel -->
      <StackPanel x:Name="panel_Entra" Visibility="Visible">
        <TextBlock Text="Tenant ID (GUID)"/>
        <TextBox x:Name="tb_Tenant"/>
        <TextBlock Text="Application (Client) ID (GUID)"/>
        <TextBox x:Name="tb_ClientId"/>
        <TextBlock Text="Client Secret"/>
        <PasswordBox x:Name="pb_Secret"/>
        <TextBlock Text="Secret expiry (YYYY-MM-DD, optional)"/>
        <TextBox x:Name="tb_Expiry"/>
      </StackPanel>
      <!-- Google Workspace panel -->
      <StackPanel x:Name="panel_Gws" Visibility="Collapsed">
        <TextBlock Text="Service account JSON key file"/>
        <Grid>
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <TextBox x:Name="tb_SaPath" Grid.Column="0"/>
          <Button x:Name="btn_Browse" Grid.Column="1" Content="Browse…" Margin="8,0,0,0"/>
        </Grid>
        <TextBlock Text="Delegated-admin email (a Super Admin)"/>
        <TextBox x:Name="tb_AdminEmail"/>
        <TextBlock Text="The service account needs domain-wide delegation configured in the Google Admin Console." Foreground="#94A3B8" TextWrapping="Wrap" Margin="0,8,0,0"/>
      </StackPanel>
    </Grid>

    <TextBlock x:Name="tb_Error" Grid.Row="3" Foreground="#DC2626" TextWrapping="Wrap" Margin="0,8,0,0"/>

    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="btn_Cancel" Content="Cancel" Background="#FFFFFF" Foreground="#1F2933" BorderBrush="#E2E8F0" BorderThickness="1" Margin="0,0,8,0"/>
      <Button x:Name="btn_Save" Content="Save credential"/>
    </StackPanel>
  </Grid>
</Window>
'@

    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $win = [System.Windows.Markup.XamlReader]::Load($reader)
    if ($Owner) { $win.Owner = $Owner }

    $c = {}
    $ctl = @{}
    foreach ($n in 'rb_Entra', 'rb_Gws', 'panel_Entra', 'panel_Gws', 'tb_Tenant', 'tb_ClientId',
        'pb_Secret', 'tb_Expiry', 'tb_SaPath', 'btn_Browse', 'tb_AdminEmail', 'tb_Error', 'btn_Cancel', 'btn_Save') {
        $ctl[$n] = $win.FindName($n)
    }

    $ctl.rb_Entra.Add_Checked({ $ctl.panel_Entra.Visibility = 'Visible'; $ctl.panel_Gws.Visibility = 'Collapsed' }.GetNewClosure())
    $ctl.rb_Gws.Add_Checked({ $ctl.panel_Entra.Visibility = 'Collapsed'; $ctl.panel_Gws.Visibility = 'Visible' }.GetNewClosure())

    $ctl.btn_Browse.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Service account JSON (*.json)|*.json|All files (*.*)|*.*'
        if ($dlg.ShowDialog()) { $ctl.tb_SaPath.Text = $dlg.FileName }
    }.GetNewClosure())

    $result = @{ Entries = $null }

    $ctl.btn_Cancel.Add_Click({ $win.Close() }.GetNewClosure())

    $ctl.btn_Save.Add_Click({
        $env = if ($ctl.rb_Gws.IsChecked) { 'googleWorkspace' } else { 'microsoftGraph' }
        $fields = @{}
        if ($env -eq 'microsoftGraph') {
            $fields.TenantId     = $ctl.tb_Tenant.Text.Trim()
            $fields.ClientId     = $ctl.tb_ClientId.Text.Trim()
            $fields.ClientSecret = $ctl.pb_Secret.Password
            $fields.Expiration   = $ctl.tb_Expiry.Text.Trim()
        } else {
            $saPath = $ctl.tb_SaPath.Text.Trim()
            $fields.ServiceAccountJson = $null; $fields.SaClientEmail = $null
            if ($saPath -and (Test-Path $saPath)) {
                try {
                    $raw = Get-Content -Path $saPath -Raw
                    $sa = $raw | ConvertFrom-Json
                    $fields.ServiceAccountJson = $raw
                    $fields.SaClientEmail = $sa.client_email
                } catch { }
            }
            $fields.AdminEmail = $ctl.tb_AdminEmail.Text.Trim()
        }

        $errs = Test-AddCredentialFields -Environment $env -Fields $fields
        if ($errs.Count -gt 0) {
            $ctl.tb_Error.Text = ($errs -join '  ')
            return
        }
        $result.Entries = New-AddCredentialEntries -Environment $env -Fields $fields
        $win.Close()
    }.GetNewClosure())

    [void]$win.ShowDialog()
    return $result.Entries
}
