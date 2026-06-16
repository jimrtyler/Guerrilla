# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Show-GuerrillaWindow {
    <#
    .SYNOPSIS
        Internal builder for the Show-Guerrilla WPF window.
    .DESCRIPTION
        Defines the window XAML, parses it, wires up event handlers for all five
        tabs, and blocks until the user closes the window. Public entry point is
        Show-Guerrilla in Public\.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName  = 'PSGuerrilla',
        [string]$ConfigPath,
        [ValidateSet('Operations', 'Safehouse', 'Patrol', 'Reports', 'Settings')]
        [string]$StartOn    = 'Operations',
        [Parameter(Mandatory)]
        [string]$ModulePath
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    $theme       = Get-GuerrillaGuiTheme
    $brushes     = $theme.Brushes
    $reportsDir  = Join-Path (Get-PSGuerrillaDataRoot) 'Reports'

    # XAML for the entire window. Bound at parse time — no runtime DataBinding.
    # Naming convention: x:Name="<tab>_<purpose>" so handlers stay greppable.
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PSGuerrilla — Operations Console"
        Height="720" Width="1100"
        MinHeight="560" MinWidth="900"
        Background="#1A1A1A"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="13" Foreground="#F5F0E6">
  <Window.Resources>
    <Style x:Key="NavButton" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="#B8A97E"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="20,12"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#33322C"/>
          <Setter Property="Foreground" Value="#F5F0E6"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="NavButtonActive" TargetType="Button" BasedOn="{StaticResource NavButton}">
      <Setter Property="Background" Value="#33322C"/>
      <Setter Property="Foreground" Value="#C67A1F"/>
      <Setter Property="FontWeight" Value="Bold"/>
    </Style>
    <Style x:Key="PrimaryButton" TargetType="Button">
      <Setter Property="Background" Value="#C67A1F"/>
      <Setter Property="Foreground" Value="#1A1A1A"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="16,8"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#D88E33"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#55524A"/><Setter Property="Foreground" Value="#8B8B7A"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="SecondaryButton" TargetType="Button">
      <Setter Property="Background" Value="#252420"/>
      <Setter Property="Foreground" Value="#F5F0E6"/>
      <Setter Property="BorderBrush" Value="#55524A"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#33322C"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#8B8B7A"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#252420"/>
      <Setter Property="Foreground" Value="#F5F0E6"/>
      <Setter Property="BorderBrush" Value="#55524A"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="CaretBrush" Value="#F5F0E6"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="#252420"/>
      <Setter Property="Foreground" Value="#F5F0E6"/>
      <Setter Property="BorderBrush" Value="#55524A"/>
      <Setter Property="Padding" Value="8,4"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="#1A1A1A"/>
      <Setter Property="Foreground" Value="#F5F0E6"/>
      <Setter Property="BorderBrush" Value="#55524A"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#33322C"/>
      <Setter Property="RowBackground" Value="#1A1A1A"/>
      <Setter Property="AlternatingRowBackground" Value="#1F1E1A"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="SelectionMode" Value="Single"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#252420"/>
      <Setter Property="Foreground" Value="#C67A1F"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="BorderBrush" Value="#55524A"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,6"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#F5F0E6"/>
      <Setter Property="Margin" Value="0,4"/>
    </Style>
    <Style TargetType="RadioButton">
      <Setter Property="Foreground" Value="#F5F0E6"/>
      <Setter Property="Margin" Value="0,4,16,4"/>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="200"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- ═══ LEFT NAV RAIL ════════════════════════════════════════════════ -->
    <Border Grid.Column="0" Background="#252420" BorderBrush="#55524A" BorderThickness="0,0,1,0">
      <DockPanel>
        <StackPanel DockPanel.Dock="Top" Margin="0,20,0,12">
          <TextBlock Text="PSGuerrilla" Foreground="#F5F0E6" FontSize="20" FontWeight="Bold" Margin="20,0,20,4"/>
          <TextBlock Text="Operations Console" Foreground="#8B8B7A" FontSize="11" Margin="20,0,20,16"/>
          <Border Height="1" Background="#55524A" Margin="0,0,0,8"/>
        </StackPanel>
        <StackPanel DockPanel.Dock="Bottom" Margin="20,12,20,16">
          <TextBlock x:Name="nav_VersionText" Text="" Foreground="#55524A" FontSize="10"/>
          <TextBlock x:Name="nav_VaultText"   Text="" Foreground="#55524A" FontSize="10" Margin="0,2,0,0"/>
        </StackPanel>
        <StackPanel x:Name="navPanel">
          <Button x:Name="nav_Operations" Content="Operations"  Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Safehouse"  Content="Safehouse"   Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Patrol"     Content="Patrol"      Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Reports"    Content="Reports"     Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Settings"   Content="Settings"    Style="{StaticResource NavButton}"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- ═══ RIGHT CONTENT AREA ═══════════════════════════════════════════ -->
    <Grid Grid.Column="1" Margin="24,20,24,20">

      <!-- ─── OPERATIONS PANEL ─── -->
      <Grid x:Name="panel_Operations" Visibility="Visible">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Run a scan" FontSize="22" FontWeight="Bold" Foreground="#F5F0E6" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Pick a theater, select categories, click Run. The HTML report opens when the scan completes." Foreground="#8B8B7A" Margin="0,0,0,16"/>

        <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,12">
          <TextBlock Text="Theater:" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <RadioButton x:Name="ops_TheaterAD"        Content="Active Directory" GroupName="Theater" IsChecked="True"/>
          <RadioButton x:Name="ops_TheaterWorkspace" Content="Google Workspace" GroupName="Theater"/>
          <RadioButton x:Name="ops_TheaterCloud"     Content="Entra / Azure / M365" GroupName="Theater"/>
          <RadioButton x:Name="ops_TheaterCampaign"  Content="All theaters (Campaign)" GroupName="Theater"/>
        </StackPanel>

        <Border Grid.Row="3" BorderBrush="#55524A" BorderThickness="1" Padding="12" Margin="0,0,0,12">
          <StackPanel>
            <TextBlock Text="Categories" Foreground="#C67A1F" FontWeight="Bold" Margin="0,0,0,8"/>
            <WrapPanel x:Name="ops_CategoryPanel" Orientation="Horizontal"/>
          </StackPanel>
        </Border>

        <Grid Grid.Row="4" Margin="0,0,0,12">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0" Orientation="Horizontal">
            <TextBlock Text="Scan mode:" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,0,12,0"/>
            <RadioButton x:Name="ops_ModeFast" Content="Fast" GroupName="Mode" IsChecked="True"/>
            <RadioButton x:Name="ops_ModeFull" Content="Full" GroupName="Mode"/>
            <CheckBox x:Name="ops_NoReports" Content="No reports" Margin="24,0,12,0"/>
            <CheckBox x:Name="ops_NoDelta"   Content="No delta"/>
          </StackPanel>
        </Grid>

        <Grid Grid.Row="5" Margin="0,0,0,12">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Output:" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBox   Grid.Column="1" x:Name="ops_OutputDir"/>
          <Button    Grid.Column="2" x:Name="ops_BrowseOutput" Content="Browse..." Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
        </Grid>

        <Grid Grid.Row="6" Margin="0,12,0,0">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <Grid Grid.Row="0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Button Grid.Column="0" x:Name="ops_RunButton" Content="Run Scan" Style="{StaticResource PrimaryButton}"/>
            <Button Grid.Column="2" x:Name="ops_CancelButton" Content="Cancel" Style="{StaticResource SecondaryButton}" Visibility="Collapsed"/>
            <ProgressBar Grid.Column="1" x:Name="ops_Progress" IsIndeterminate="True" Height="6" Margin="16,0,16,0" Visibility="Collapsed" Foreground="#C67A1F" Background="#252420"/>
          </Grid>
          <Border Grid.Row="1" BorderBrush="#55524A" BorderThickness="1" Margin="0,12,0,0">
            <TextBox x:Name="ops_LogPane" IsReadOnly="True" VerticalScrollBarVisibility="Auto"
                     AcceptsReturn="True" TextWrapping="NoWrap" FontFamily="Consolas" FontSize="12"
                     Background="#0F0F0F" Foreground="#B8A97E" BorderThickness="0" Padding="8"/>
          </Border>
        </Grid>

        <Border Grid.Row="7" x:Name="ops_ResultBanner" Background="#1F2F1F" BorderBrush="#6B8E6B" BorderThickness="1"
                Padding="12,8" Margin="0,8,0,0" Visibility="Collapsed">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" x:Name="ops_ResultText" Foreground="#F5F0E6" VerticalAlignment="Center" TextWrapping="Wrap"/>
            <Button    Grid.Column="1" x:Name="ops_OpenReport" Content="Open Report" Style="{StaticResource PrimaryButton}" Margin="12,0,0,0"/>
          </Grid>
        </Border>
      </Grid>

      <!-- ─── SAFEHOUSE PANEL ─── -->
      <Grid x:Name="panel_Safehouse" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Safehouse" FontSize="22" FontWeight="Bold" Foreground="#F5F0E6" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Stored credentials, expiration status, and rotation history." Foreground="#8B8B7A" Margin="0,0,0,16"/>
        <DataGrid x:Name="sh_Grid" Grid.Row="2">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Environment"   Binding="{Binding Environment}"   Width="140"/>
            <DataGridTextColumn Header="Description"   Binding="{Binding Description}"   Width="*"/>
            <DataGridTextColumn Header="Identity"      Binding="{Binding Identity}"      Width="220"/>
            <DataGridTextColumn Header="Stored"        Binding="{Binding StoredDate}"    Width="120"/>
            <DataGridTextColumn Header="Expires"       Binding="{Binding ExpirationDate}" Width="120"/>
            <DataGridTextColumn Header="Status"        Binding="{Binding Status}"        Width="120"/>
          </DataGrid.Columns>
        </DataGrid>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="sh_Add"      Content="Add Credential"  Style="{StaticResource PrimaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="sh_Rotate"   Content="Rotate Selected" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="sh_Remove"   Content="Remove Selected" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="sh_Test"     Content="Test All"        Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="sh_Export"   Content="Export Metadata" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="sh_Refresh"  Content="Refresh"         Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
      </Grid>

      <!-- ─── PATROL PANEL ─── -->
      <Grid x:Name="panel_Patrol" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Patrol" FontSize="22" FontWeight="Bold" Foreground="#F5F0E6" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Scheduled scans that run continuously and dispatch alerts on new findings." Foreground="#8B8B7A" Margin="0,0,0,16"/>
        <DataGrid x:Name="pt_Grid" Grid.Row="2">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Task Name"  Binding="{Binding TaskName}"  Width="*"/>
            <DataGridTextColumn Header="State"      Binding="{Binding State}"     Width="100"/>
            <DataGridTextColumn Header="Last Run"   Binding="{Binding LastRunTime}" Width="160"/>
            <DataGridTextColumn Header="Next Run"   Binding="{Binding NextRunTime}" Width="160"/>
            <DataGridTextColumn Header="Result"     Binding="{Binding LastTaskResult}" Width="90"/>
          </DataGrid.Columns>
        </DataGrid>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="pt_Register"   Content="Register New"   Style="{StaticResource PrimaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="pt_Unregister" Content="Unregister"     Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="pt_Refresh"    Content="Refresh"        Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
      </Grid>

      <!-- ─── REPORTS PANEL ─── -->
      <Grid x:Name="panel_Reports" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Reports" FontSize="22" FontWeight="Bold" Foreground="#F5F0E6" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" x:Name="rp_DirHint" Foreground="#8B8B7A" Margin="0,0,0,16"/>
        <DataGrid x:Name="rp_Grid" Grid.Row="2">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Name"     Binding="{Binding Name}"     Width="*"/>
            <DataGridTextColumn Header="Theater"  Binding="{Binding Theater}"  Width="140"/>
            <DataGridTextColumn Header="Size"     Binding="{Binding SizeKB}"   Width="80"/>
            <DataGridTextColumn Header="Modified" Binding="{Binding Modified}" Width="160"/>
          </DataGrid.Columns>
        </DataGrid>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="rp_Open"    Content="Open in browser" Style="{StaticResource PrimaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="rp_Pdf"     Content="Convert to PDF"  Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="rp_Delete"  Content="Delete"          Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="rp_Refresh" Content="Refresh"         Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
      </Grid>

      <!-- ─── SETTINGS PANEL ─── -->
      <Grid x:Name="panel_Settings" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Settings" FontSize="22" FontWeight="Bold" Foreground="#F5F0E6" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Runtime configuration applied to all subsequent scans." Foreground="#8B8B7A" Margin="0,0,0,16"/>
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
          <Grid Margin="0,0,16,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="200"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" Text="Profile" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,8"/>
            <ComboBox  Grid.Row="0" Grid.Column="1" x:Name="st_Profile" Margin="0,8">
              <ComboBoxItem Content="Default" IsSelected="True"/>
              <ComboBoxItem Content="K12"/>
            </ComboBox>
            <TextBlock Grid.Row="1" Grid.Column="0" Text="Minimum alert level" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,8"/>
            <ComboBox  Grid.Row="1" Grid.Column="1" x:Name="st_AlertLevel" Margin="0,8">
              <ComboBoxItem Content="CRITICAL"/>
              <ComboBoxItem Content="HIGH" IsSelected="True"/>
              <ComboBoxItem Content="MEDIUM"/>
              <ComboBoxItem Content="LOW"/>
            </ComboBox>
            <TextBlock Grid.Row="2" Grid.Column="0" Text="Output directory" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,8"/>
            <Grid Grid.Row="2" Grid.Column="1" Margin="0,8">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <TextBox Grid.Column="0" x:Name="st_OutputDir"/>
              <Button  Grid.Column="1" x:Name="st_BrowseOutput" Content="Browse..." Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
            </Grid>
            <TextBlock Grid.Row="3" Grid.Column="0" Text="Config file path" Foreground="#B8A97E" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="3" Grid.Column="1" x:Name="st_ConfigPath" Margin="0,8" IsReadOnly="True"/>
            <TextBlock Grid.Row="4" Grid.Column="1" x:Name="st_StatusLine" Foreground="#6B8E6B" Margin="0,16,0,0"/>
          </Grid>
        </ScrollViewer>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="st_Apply"  Content="Apply"  Style="{StaticResource PrimaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="st_Revert" Content="Revert" Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
      </Grid>

    </Grid>
  </Grid>
</Window>
'@

    # Parse XAML and find named controls.
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)

    # Bind every x:Name'd control as a script-scoped variable for easy reference.
    $namedControls = @{}
    $xpath = "//*[@x:Name]"
    $nsm = New-Object System.Xml.XmlNamespaceManager(([xml]$xaml).NameTable)
    $nsm.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    foreach ($node in ([xml]$xaml).SelectNodes($xpath, $nsm)) {
        $name = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
        $namedControls[$name] = $window.FindName($name)
    }

    # ── Side-effect-bearing state for the GUI session ─────────────────────
    $session = [PSCustomObject]@{
        Window          = $window
        Controls        = $namedControls
        VaultName       = $VaultName
        ConfigPath      = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
        ModulePath      = $ModulePath
        ReportsDir      = $reportsDir
        CurrentTab      = 'Operations'
        CurrentAsync    = $null
        LastReportPath  = $null
    }

    # ── Helpers ───────────────────────────────────────────────────────────
    $setActiveTab = {
        param([string]$Tab)
        foreach ($t in @('Operations', 'Safehouse', 'Patrol', 'Reports', 'Settings')) {
            $panel = $session.Controls["panel_$t"]
            $navBtn = $session.Controls["nav_$t"]
            if ($t -eq $Tab) {
                $panel.Visibility  = 'Visible'
                $navBtn.Style      = $session.Window.FindResource('NavButtonActive')
            } else {
                $panel.Visibility  = 'Collapsed'
                $navBtn.Style      = $session.Window.FindResource('NavButton')
            }
        }
        $session.CurrentTab = $Tab
        # Lazy-load each tab's data on first visit.
        switch ($Tab) {
            'Safehouse' { & $refreshSafehouseGrid }
            'Patrol'    { & $refreshPatrolGrid }
            'Reports'   { & $refreshReportsGrid }
            'Settings'  { & $loadSettings }
        }
    }

    $appendLog = {
        param([string]$Message)
        $tb = $session.Controls['ops_LogPane']
        $stamp = [datetime]::Now.ToString('HH:mm:ss')
        $tb.AppendText("[$stamp] $Message`r`n")
        $tb.ScrollToEnd()
    }

    $resetOperationsUI = {
        $session.Controls['ops_RunButton'].IsEnabled  = $true
        $session.Controls['ops_RunButton'].Visibility = 'Visible'
        $session.Controls['ops_CancelButton'].Visibility = 'Collapsed'
        $session.Controls['ops_Progress'].Visibility = 'Collapsed'
    }

    $loadCategoriesForTheater = {
        $panel = $session.Controls['ops_CategoryPanel']
        $panel.Children.Clear()
        $categories = if ($session.Controls['ops_TheaterAD'].IsChecked) {
            @('DomainForest','Trusts','PrivilegedAccounts','PasswordPolicy','Kerberos','ACLDelegation',
              'GroupPolicy','LogonScripts','CertificateServices','StaleObjects','Network','TierZero','Logging','Tradecraft')
        } elseif ($session.Controls['ops_TheaterWorkspace'].IsChecked) {
            @('Authentication','EmailSecurity','DriveSecurity','OAuthSecurity','AdminManagement',
              'Collaboration','DeviceManagement','LoggingAlerting')
        } elseif ($session.Controls['ops_TheaterCloud'].IsChecked) {
            @('ConditionalAccess','AuthenticationMethods','PIM','Applications','Federation',
              'TenantConfig','AzureIAM','Intune','M365Services')
        } else {
            @()  # Campaign runs everything by default
        }

        if ($categories.Count -eq 0) {
            $panel.Children.Add([Windows.Controls.TextBlock]@{
                Text       = 'Campaign runs the default set in each enabled theater.'
                Foreground = $brushes.Gray
                Margin     = '0,4'
            })
            return
        }

        # "All" toggle
        $allCb = New-Object System.Windows.Controls.CheckBox
        $allCb.Content     = 'All'
        $allCb.IsChecked   = $true
        $allCb.FontWeight  = 'Bold'
        $allCb.Foreground  = $brushes.Amber
        $allCb.Margin      = '0,4,16,4'
        $panel.Children.Add($allCb) | Out-Null
        $allCb.Add_Checked({
            foreach ($child in $session.Controls['ops_CategoryPanel'].Children) {
                if ($child -is [System.Windows.Controls.CheckBox] -and $child.Content -ne 'All') {
                    $child.IsChecked = $true
                }
            }
        })
        $allCb.Add_Unchecked({
            foreach ($child in $session.Controls['ops_CategoryPanel'].Children) {
                if ($child -is [System.Windows.Controls.CheckBox] -and $child.Content -ne 'All') {
                    $child.IsChecked = $false
                }
            }
        })

        foreach ($cat in $categories) {
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content   = $cat
            $cb.IsChecked = $true
            $cb.Margin    = '0,4,16,4'
            $panel.Children.Add($cb) | Out-Null
        }
    }

    $getSelectedCategories = {
        $cats = @()
        foreach ($child in $session.Controls['ops_CategoryPanel'].Children) {
            if ($child -is [System.Windows.Controls.CheckBox] -and
                $child.Content -ne 'All' -and $child.IsChecked) {
                $cats += [string]$child.Content
            }
        }
        return @($cats)
    }

    # ── Operations tab handlers ───────────────────────────────────────────
    foreach ($r in @('ops_TheaterAD','ops_TheaterWorkspace','ops_TheaterCloud','ops_TheaterCampaign')) {
        $session.Controls[$r].Add_Checked({ & $loadCategoriesForTheater })
    }

    $session.Controls['ops_BrowseOutput'].Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $session.Controls['ops_OutputDir'].Text
        $dlg.Description  = 'Select output directory for the scan report'
        if ($dlg.ShowDialog() -eq 'OK') {
            $session.Controls['ops_OutputDir'].Text = $dlg.SelectedPath
        }
    })

    $session.Controls['ops_RunButton'].Add_Click({
        $session.Controls['ops_RunButton'].IsEnabled  = $false
        $session.Controls['ops_RunButton'].Visibility = 'Collapsed'
        $session.Controls['ops_CancelButton'].Visibility = 'Visible'
        $session.Controls['ops_Progress'].Visibility = 'Visible'
        $session.Controls['ops_ResultBanner'].Visibility = 'Collapsed'
        $session.Controls['ops_LogPane'].Clear()

        $outDir       = $session.Controls['ops_OutputDir'].Text
        $mode         = if ($session.Controls['ops_ModeFull'].IsChecked) { 'Full' } else { 'Fast' }
        $noReports    = $session.Controls['ops_NoReports'].IsChecked
        $noDelta      = $session.Controls['ops_NoDelta'].IsChecked
        $selectedCats = & $getSelectedCategories

        $cmdletName = if ($session.Controls['ops_TheaterAD'].IsChecked)        { 'Invoke-Reconnaissance' }
                      elseif ($session.Controls['ops_TheaterWorkspace'].IsChecked) { 'Invoke-Fortification' }
                      elseif ($session.Controls['ops_TheaterCloud'].IsChecked)     { 'Invoke-Infiltration' }
                      else                                                          { 'Invoke-Campaign' }

        & $appendLog "Starting $cmdletName ($($selectedCats.Count) categories, mode=$mode)..."

        # Pass params explicitly into the scriptblock rather than relying on
        # closure capture — closures don't survive the runspace transfer reliably.
        $action = {
            param([string]$CmdletName, [string]$OutputDir, [string]$Mode,
                  [bool]$NoReports, [bool]$NoDelta, [string[]]$Categories)
            $invokeArgs = @{ Quiet = $false }
            if ($OutputDir)  { $invokeArgs.OutputDirectory = $OutputDir }
            if ($NoReports)  { $invokeArgs.NoReports = $true }
            if ($NoDelta)    { $invokeArgs.NoDelta   = $true }
            if ($Categories.Count -gt 0 -and $CmdletName -ne 'Invoke-Campaign') {
                $invokeArgs.Categories = $Categories
            }
            if ($Mode -and $CmdletName -in @('Invoke-Recon','Invoke-Fortification','Invoke-Infiltration','Invoke-Surveillance','Invoke-Wiretap','Invoke-Watchtower')) {
                $invokeArgs.ScanMode = $Mode
            }
            & $CmdletName @invokeArgs
        }
        $actionArgs = @($cmdletName, $outDir, $mode, [bool]$noReports, [bool]$noDelta, @($selectedCats))

        # Invoke-GuerrillaGuiAsync fires these callbacks from its own DispatcherTimer
        # scope, so they must carry everything they need by closure. GetNewClosure()
        # snapshots only THIS click-handler's locals — NOT the function-scope helpers
        # ($appendLog/$resetOperationsUI/$session/$brushes), which are merely *visible*
        # here through the scope chain. Copy them into handler-locals first so the
        # closures actually capture them (a direct `& $appendLog` works above without
        # this, but a GetNewClosure() snapshot does not).
        $appendLog         = $appendLog
        $resetOperationsUI = $resetOperationsUI
        $session           = $session
        $brushes           = $brushes

        $onLog = { param($msg) & $appendLog $msg }.GetNewClosure()

        $onComplete = {
            param($result)
            $reportPath = $null
            if ($result -and $result.HtmlReportPath) {
                $reportPath = $result.HtmlReportPath
            } else {
                # Best-effort: pick the newest HTML in the reports dir
                $newest = Get-ChildItem (Join-Path (Get-PSGuerrillaDataRoot) 'Reports') -Filter '*.html' -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($newest) { $reportPath = $newest.FullName }
            }
            $session.LastReportPath = $reportPath
            & $appendLog 'Scan complete.'
            if ($reportPath) {
                $session.Controls['ops_ResultText'].Text = "Report ready: $reportPath"
                $session.Controls['ops_ResultBanner'].Visibility = 'Visible'
            } else {
                $session.Controls['ops_ResultText'].Text = 'Scan complete (no report path returned — check the output directory).'
                $session.Controls['ops_ResultBanner'].Visibility = 'Visible'
            }
            & $resetOperationsUI
        }.GetNewClosure()

        $onError = {
            param($err)
            & $appendLog "ERROR: $err"
            $session.Controls['ops_ResultText'].Text = "Scan failed: $err"
            $session.Controls['ops_ResultBanner'].Background = $brushes.Red
            $session.Controls['ops_ResultBanner'].Visibility = 'Visible'
            & $resetOperationsUI
        }.GetNewClosure()

        $session.CurrentAsync = Invoke-GuerrillaGuiAsync `
            -ModulePath  $session.ModulePath `
            -Action      $action `
            -Arguments   $actionArgs `
            -Dispatcher  $session.Window.Dispatcher `
            -OnLog       $onLog `
            -OnComplete  $onComplete `
            -OnError     $onError
    })

    $session.Controls['ops_CancelButton'].Add_Click({
        if ($session.CurrentAsync) {
            Stop-GuerrillaGuiAsync -State $session.CurrentAsync
            & $appendLog 'Cancelled by user.'
            & $resetOperationsUI
        }
    })

    $session.Controls['ops_OpenReport'].Add_Click({
        if ($session.LastReportPath -and (Test-Path $session.LastReportPath)) {
            Invoke-Item $session.LastReportPath
        }
    })

    # ── Safehouse tab handlers ────────────────────────────────────────────
    $refreshSafehouseGrid = {
        try {
            $sh = Get-Safehouse -VaultName $session.VaultName -ErrorAction Stop
            $rows = @()
            if ($sh.credentials) {
                foreach ($key in $sh.credentials.Keys) {
                    $c = $sh.credentials[$key]
                    $rows += [PSCustomObject]@{
                        VaultKey        = $key
                        Environment     = $c.environment
                        Description     = $c.description
                        Identity        = $c.identity
                        StoredDate      = if ($c.storedDate) { ([datetime]$c.storedDate).ToString('yyyy-MM-dd') } else { '' }
                        ExpirationDate  = if ($c.expirationDate) { $c.expirationDate } else { '' }
                        Status          = $c.status
                    }
                }
            }
            $session.Controls['sh_Grid'].ItemsSource = $rows
        } catch {
            [System.Windows.MessageBox]::Show("Could not read vault: $_`r`n`r`nThe vault may not be initialized yet. Click 'Add Credential' to set it up.", 'Vault unavailable', 'OK', 'Information') | Out-Null
        }
    }

    $session.Controls['sh_Refresh'].Add_Click({ & $refreshSafehouseGrid })

    $session.Controls['sh_Add'].Add_Click({
        $msg = "To add credentials, run from a PowerShell prompt:`r`n`r`n    Set-Safehouse`r`n`r`n" +
               "It will ask which environments you want to set up. GUI-driven credential entry is on the roadmap for the next release."
        [System.Windows.MessageBox]::Show($msg, 'Add Credential', 'OK', 'Information') | Out-Null
    })

    $session.Controls['sh_Remove'].Add_Click({
        $row = $session.Controls['sh_Grid'].SelectedItem
        if (-not $row) { return }
        $ans = [System.Windows.MessageBox]::Show("Remove credential '$($row.VaultKey)'?", 'Confirm', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') {
            try {
                Set-Safehouse -Remove $row.Environment -VaultName $session.VaultName -ErrorAction Stop
                & $refreshSafehouseGrid
            } catch {
                [System.Windows.MessageBox]::Show("Remove failed: $_", 'Error', 'OK', 'Error') | Out-Null
            }
        }
    })

    $session.Controls['sh_Rotate'].Add_Click({
        $row = $session.Controls['sh_Grid'].SelectedItem
        if (-not $row) { return }
        [System.Windows.MessageBox]::Show("To rotate, run from a PowerShell prompt:`r`n`r`n    Set-Safehouse -Rotate $($row.Environment)", 'Rotate Credential', 'OK', 'Information') | Out-Null
    })

    $session.Controls['sh_Test'].Add_Click({
        [System.Windows.MessageBox]::Show("To test all connections, run:`r`n`r`n    Set-Safehouse -Test`r`n`r`n(GUI-driven connectivity testing is on the roadmap.)", 'Test All', 'OK', 'Information') | Out-Null
    })

    $session.Controls['sh_Export'].Add_Click({
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter   = 'JSON files (*.json)|*.json'
        $dlg.FileName = 'safehouse-metadata.json'
        if ($dlg.ShowDialog()) {
            try {
                Set-Safehouse -ExportMetadata -Path $dlg.FileName -VaultName $session.VaultName -ErrorAction Stop
                [System.Windows.MessageBox]::Show("Exported to $($dlg.FileName)", 'Done', 'OK', 'Information') | Out-Null
            } catch {
                [System.Windows.MessageBox]::Show("Export failed: $_", 'Error', 'OK', 'Error') | Out-Null
            }
        }
    })

    # ── Patrol tab handlers ───────────────────────────────────────────────
    $refreshPatrolGrid = {
        try {
            $patrols = @(Get-Patrol -ErrorAction SilentlyContinue)
            $rows = foreach ($p in $patrols) {
                [PSCustomObject]@{
                    TaskName       = $p.TaskName
                    State          = "$($p.State)"
                    LastRunTime    = if ($p.LastRunTime) { ([datetime]$p.LastRunTime).ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    NextRunTime    = if ($p.NextRunTime) { ([datetime]$p.NextRunTime).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
                    LastTaskResult = if ($null -ne $p.LastTaskResult) { "$($p.LastTaskResult)" } else { '-' }
                }
            }
            $session.Controls['pt_Grid'].ItemsSource = @($rows)
        } catch {
            $session.Controls['pt_Grid'].ItemsSource = @()
        }
    }

    $session.Controls['pt_Refresh'].Add_Click({ & $refreshPatrolGrid })

    $session.Controls['pt_Register'].Add_Click({
        $msg = "Patrol registration runs a scheduled task that re-scans periodically.`r`n`r`n" +
               "To register from a PowerShell prompt:`r`n`r`n" +
               "    Register-Patrol -ConfigFile .\guerrilla-config.json ``r`n" +
               "        -Theaters AD, Workspace ``r`n" +
               "        -IntervalMinutes 60 -SendAlerts`r`n`r`n" +
               "GUI-driven registration is on the roadmap."
        [System.Windows.MessageBox]::Show($msg, 'Register Patrol', 'OK', 'Information') | Out-Null
    })

    $session.Controls['pt_Unregister'].Add_Click({
        $row = $session.Controls['pt_Grid'].SelectedItem
        if (-not $row) { return }
        $ans = [System.Windows.MessageBox]::Show("Unregister scheduled task '$($row.TaskName)'?", 'Confirm', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') {
            try {
                Unregister-Patrol -TaskName $row.TaskName -Force -ErrorAction Stop
                & $refreshPatrolGrid
            } catch {
                [System.Windows.MessageBox]::Show("Unregister failed: $_", 'Error', 'OK', 'Error') | Out-Null
            }
        }
    })

    # ── Reports tab handlers ──────────────────────────────────────────────
    $session.Controls['rp_DirHint'].Text = "From $($session.ReportsDir). Newest first."

    $refreshReportsGrid = {
        if (-not (Test-Path $session.ReportsDir)) {
            $session.Controls['rp_Grid'].ItemsSource = @()
            return
        }
        $files = Get-ChildItem -Path $session.ReportsDir -Filter '*.html' -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending
        $rows = foreach ($f in $files) {
            $theater = switch -Regex ($f.Name) {
                '^[Rr]econnaissance'  { 'Active Directory' }
                '^[Ff]ortification'   { 'Workspace' }
                '^[Ii]nfiltration'    { 'Cloud' }
                '^[Cc]ampaign'        { 'All Theaters' }
                '^[Ss]urveillance'    { 'Entra monitoring' }
                '^[Ww]atchtower'      { 'AD monitoring' }
                '^[Ww]iretap'         { 'M365 monitoring' }
                '^field_report'       { 'Workspace (Recon)' }
                'Executive'           { 'Summary' }
                'Technical'           { 'Technical' }
                'Playbook|Remediation' { 'Remediation' }
                'Dashboard'           { 'Dashboard' }
                default               { 'Other' }
            }
            [PSCustomObject]@{
                Name     = $f.Name
                Theater  = $theater
                SizeKB   = [Math]::Round($f.Length / 1KB, 1)
                Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                FullPath = $f.FullName
            }
        }
        $session.Controls['rp_Grid'].ItemsSource = @($rows)
    }

    $session.Controls['rp_Refresh'].Add_Click({ & $refreshReportsGrid })

    $session.Controls['rp_Open'].Add_Click({
        $row = $session.Controls['rp_Grid'].SelectedItem
        if ($row -and (Test-Path $row.FullPath)) { Invoke-Item $row.FullPath }
    })

    $session.Controls['rp_Pdf'].Add_Click({
        $row = $session.Controls['rp_Grid'].SelectedItem
        if (-not $row) { return }
        try {
            Export-ReportPdf -InputPath $row.FullPath -ErrorAction Stop
            [System.Windows.MessageBox]::Show('PDF generated next to the HTML report.', 'Done', 'OK', 'Information') | Out-Null
            & $refreshReportsGrid
        } catch {
            [System.Windows.MessageBox]::Show("PDF conversion failed: $_", 'Error', 'OK', 'Error') | Out-Null
        }
    })

    $session.Controls['rp_Delete'].Add_Click({
        $row = $session.Controls['rp_Grid'].SelectedItem
        if (-not $row) { return }
        $ans = [System.Windows.MessageBox]::Show("Delete '$($row.Name)'?", 'Confirm', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') {
            Remove-Item -LiteralPath $row.FullPath -Force -ErrorAction SilentlyContinue
            & $refreshReportsGrid
        }
    })

    # ── Settings tab handlers ─────────────────────────────────────────────
    $loadSettings = {
        $session.Controls['st_ConfigPath'].Text = $session.ConfigPath
        if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
            try {
                $cfg = Get-Content -Path $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
                if ($cfg.profile) {
                    foreach ($item in $session.Controls['st_Profile'].Items) {
                        if ("$($item.Content)" -eq $cfg.profile) { $item.IsSelected = $true; break }
                    }
                }
                if ($cfg.alerting -and $cfg.alerting.minimumThreatLevel) {
                    foreach ($item in $session.Controls['st_AlertLevel'].Items) {
                        if ("$($item.Content)" -eq $cfg.alerting.minimumThreatLevel) { $item.IsSelected = $true; break }
                    }
                }
                if ($cfg.output -and $cfg.output.directory) {
                    $session.Controls['st_OutputDir'].Text = $cfg.output.directory
                }
            } catch { }
        }
        $session.Controls['st_StatusLine'].Text = ''
    }

    $session.Controls['st_BrowseOutput'].Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $session.Controls['st_OutputDir'].Text
        if ($dlg.ShowDialog() -eq 'OK') {
            $session.Controls['st_OutputDir'].Text = $dlg.SelectedPath
        }
    })

    $session.Controls['st_Apply'].Add_Click({
        try {
            $params = @{
                ConfigPath        = $session.ConfigPath
                Profile           = "$($session.Controls['st_Profile'].SelectedItem.Content)"
                MinimumAlertLevel = "$($session.Controls['st_AlertLevel'].SelectedItem.Content)"
            }
            if ($session.Controls['st_OutputDir'].Text) {
                $params.OutputDirectory = $session.Controls['st_OutputDir'].Text
            }
            Set-Safehouse @params -ErrorAction Stop | Out-Null
            $session.Controls['st_StatusLine'].Text = "Saved at $([datetime]::Now.ToString('HH:mm:ss'))."
        } catch {
            $session.Controls['st_StatusLine'].Foreground = $brushes.Red
            $session.Controls['st_StatusLine'].Text = "Save failed: $_"
        }
    })

    $session.Controls['st_Revert'].Add_Click({ & $loadSettings })

    # ── Nav button wiring ─────────────────────────────────────────────────
    foreach ($t in @('Operations','Safehouse','Patrol','Reports','Settings')) {
        $btn = $session.Controls["nav_$t"]
        $tab = $t  # capture
        $btn.Add_Click({ & $setActiveTab $tab }.GetNewClosure())
    }

    # ── Initial state ─────────────────────────────────────────────────────
    $session.Controls['ops_OutputDir'].Text = $session.ReportsDir
    # Read the version from the manifest so the footer can't drift like it did at v2.3.0.
    $guiVersion = try { (Import-PowerShellDataFile $session.ModulePath).ModuleVersion } catch { $null }
    $session.Controls['nav_VersionText'].Text = if ($guiVersion) { "v$guiVersion" } else { '' }
    $session.Controls['nav_VaultText'].Text   = "Vault: $($session.VaultName)"
    & $loadCategoriesForTheater
    & $setActiveTab $StartOn

    # Cleanup on window close
    $window.Add_Closing({
        if ($session.CurrentAsync) {
            Stop-GuerrillaGuiAsync -State $session.CurrentAsync
        }
    })

    # Block until the user closes the window. ShowDialog returns nothing useful.
    [void]$window.ShowDialog()
}
