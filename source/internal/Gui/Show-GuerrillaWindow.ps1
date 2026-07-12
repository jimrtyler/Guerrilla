# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Show-GuerrillaWindow {
    <#
    .SYNOPSIS
        Internal builder for the Show-Guerrilla WPF window.
    .DESCRIPTION
        Defines the window XAML, parses it, wires up event handlers for each
        tab, and blocks until the user closes the window. Public entry point is
        Show-Guerrilla in Public\.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName  = 'Guerrilla',
        [string]$ConfigPath,
        [ValidateSet('Operations', 'Safehouse', 'Reports', 'Settings', 'Source', 'Branding')]
        [string]$StartOn    = 'Operations',
        [Parameter(Mandatory)]
        [string]$ModulePath
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    $theme       = Get-GuerrillaGuiTheme
    $brushes     = $theme.Brushes
    $reportsDir  = Join-Path (Get-GuerrillaDataRoot) 'Reports'

    # XAML for the entire window. Bound at parse time — no runtime DataBinding.
    # Naming convention: x:Name="<tab>_<purpose>" so handlers stay greppable.
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Guerrilla — Operations Console"
        Height="720" Width="1100"
        MinHeight="560" MinWidth="900"
        Background="#F4F6F8"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="13" Foreground="#1F2933">
  <Window.Resources>
    <Style x:Key="NavButton" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="#44515E"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="20,12"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                                VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#EDF1F6"/>
          <Setter Property="Foreground" Value="#1F2933"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="NavButtonActive" TargetType="Button" BasedOn="{StaticResource NavButton}">
      <Setter Property="Background" Value="#EFF4FF"/>
      <Setter Property="Foreground" Value="#2563EB"/>
      <Setter Property="FontWeight" Value="Bold"/>
    </Style>
    <Style x:Key="PrimaryButton" TargetType="Button">
      <Setter Property="Background" Value="#2563EB"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="16,8"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#1D4ED8"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#F1F5F9"/><Setter Property="Foreground" Value="#94A3B8"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="SecondaryButton" TargetType="Button">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#EDF1F6"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#94A3B8"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,5"/>
      <Setter Property="CaretBrush" Value="#1F2933"/>
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
    <!-- Full dark template. The stock ComboBox template renders the closed selection box
         (SelectionBoxItem) via the system theme, ignoring Foreground, so the selected text
         was invisible/blank when collapsed. This template themes the selection box too. -->
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="Height" Value="28"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton x:Name="ToggleButton" Focusable="False" ClickMode="Press"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <!-- Hardcode the box fill so the closed selection box matches the theme
                         instead of inheriting system button chrome. Light surface with dark
                         selection text now; the chevron uses primary text color. -->
                    <Border Background="#FFFFFF" BorderBrush="#E2E8F0" BorderThickness="1" CornerRadius="4" SnapsToDevicePixels="True">
                      <Grid>
                        <Grid.ColumnDefinitions>
                          <ColumnDefinition Width="*"/>
                          <ColumnDefinition Width="20"/>
                        </Grid.ColumnDefinitions>
                        <Path Grid.Column="1" HorizontalAlignment="Center" VerticalAlignment="Center"
                              Data="M 0 0 L 4 4 L 8 0 Z" Fill="#1F2933"/>
                      </Grid>
                    </Border>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter x:Name="ContentSite" IsHitTestVisible="False"
                                Content="{TemplateBinding SelectionBoxItem}"
                                ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                Margin="8,0,28,0" VerticalAlignment="Center" HorizontalAlignment="Left"
                                TextElement.Foreground="#1F2933"/>
              <Popup x:Name="Popup" Placement="Bottom" Focusable="False" AllowsTransparency="True"
                     IsOpen="{TemplateBinding IsDropDownOpen}" PopupAnimation="Slide">
                <Grid MaxHeight="{TemplateBinding MaxDropDownHeight}"
                      MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}">
                  <Border Background="#FFFFFF" BorderBrush="#E2E8F0" BorderThickness="1" CornerRadius="4">
                    <ScrollViewer SnapsToDevicePixels="True">
                      <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                    </ScrollViewer>
                  </Border>
                </Grid>
              </Popup>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <!-- Dropdown items: force a light surface with dark text, and an accent-tint
         highlight so the highlighted item stays readable (dark text on tint). -->
    <Style TargetType="ComboBoxItem">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="Padding" Value="8,5"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="bd" Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="bd" Property="Background" Value="#EFF4FF"/>
                <Setter Property="Foreground" Value="#1F2933"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="#F4F6F8"/>
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#EDF1F6"/>
      <Setter Property="RowBackground" Value="#FFFFFF"/>
      <Setter Property="AlternatingRowBackground" Value="#EDF1F6"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="SelectionMode" Value="Single"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#2563EB"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,6"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="Margin" Value="0,4"/>
    </Style>
    <Style TargetType="RadioButton">
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="Margin" Value="0,4,16,4"/>
    </Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#1F2933"/>
      <Setter Property="BorderBrush" Value="#E2E8F0"/>
      <Setter Property="BorderThickness" Value="1"/>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="200"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- ═══ LEFT NAV RAIL ════════════════════════════════════════════════ -->
    <Border Grid.Column="0" Background="#FFFFFF" BorderBrush="#E2E8F0" BorderThickness="0,0,1,0">
      <DockPanel>
        <StackPanel DockPanel.Dock="Top" Margin="0,20,0,12">
          <TextBlock Text="Guerrilla" Foreground="#1F2933" FontSize="20" FontWeight="Bold" Margin="20,0,20,4"/>
          <TextBlock Text="Operations Console" Foreground="#94A3B8" FontSize="11" Margin="20,0,20,16"/>
          <Border Height="1" Background="#E2E8F0" Margin="0,0,0,8"/>
        </StackPanel>
        <StackPanel DockPanel.Dock="Bottom" Margin="20,12,20,16">
          <TextBlock x:Name="nav_VersionText" Text="" Foreground="#94A3B8" FontSize="10"/>
          <TextBlock x:Name="nav_VaultText"   Text="" Foreground="#94A3B8" FontSize="10" Margin="0,2,0,0"/>
        </StackPanel>
        <StackPanel x:Name="navPanel">
          <Button x:Name="nav_Operations" Content="Operations"  Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Safehouse"  Content="Safehouse"   Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Reports"    Content="Reports"     Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Settings"   Content="Settings"    Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Source"     Content="Inspector"   Style="{StaticResource NavButton}"/>
          <Button x:Name="nav_Branding"   Content="Branding"    Style="{StaticResource NavButton}"/>
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
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Run a scan" FontSize="22" FontWeight="Bold" Foreground="#1F2933" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Pick a platform, select categories, click Run. The HTML report opens when the scan completes." Foreground="#94A3B8" Margin="0,0,0,16"/>

        <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,12">
          <TextBlock Text="Platform:" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <RadioButton x:Name="ops_PlatformAD"        Content="Active Directory" GroupName="Platform" IsChecked="True"/>
          <RadioButton x:Name="ops_PlatformWorkspace" Content="Google Workspace" GroupName="Platform"/>
          <RadioButton x:Name="ops_PlatformCloud"     Content="Entra / Azure / M365" GroupName="Platform"/>
          <RadioButton x:Name="ops_PlatformCampaign"  Content="All platforms (Campaign)" GroupName="Platform"/>
        </StackPanel>

        <Border Grid.Row="3" BorderBrush="#E2E8F0" BorderThickness="1" Padding="12" Margin="0,0,0,12">
          <StackPanel>
            <TextBlock Text="Categories" Foreground="#2563EB" FontWeight="Bold" Margin="0,0,0,8"/>
            <WrapPanel x:Name="ops_CategoryPanel" Orientation="Horizontal"/>
          </StackPanel>
        </Border>

        <Grid Grid.Row="4" Margin="0,0,0,12">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0" Orientation="Horizontal">
            <TextBlock Text="Scan mode:" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,12,0"/>
            <RadioButton x:Name="ops_ModeFast" Content="Fast" GroupName="Mode" IsChecked="True"/>
            <RadioButton x:Name="ops_ModeFull" Content="Full" GroupName="Mode"/>
            <CheckBox x:Name="ops_NoReports" Content="No reports" Margin="24,0,12,0"/>
            <CheckBox x:Name="ops_NoDelta"   Content="No delta"/>
            <CheckBox x:Name="ops_TestMode"  Content="Test mode" Margin="12,0,0,0" ToolTip="Simulate a scan with no live connection — produces an all-fail report so you can preview themes and branding."/>
          </StackPanel>
          <StackPanel Grid.Column="1" Orientation="Horizontal">
            <TextBlock Text="Report style:" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <ComboBox x:Name="ops_ReportStyle" Width="140">
              <ComboBoxItem Content="Guerrilla" IsSelected="True"/>
              <ComboBoxItem Content="Professional"/>
              <ComboBoxItem Content="Slate"/>
            </ComboBox>
          </StackPanel>
        </Grid>

        <Grid Grid.Row="5" x:Name="ops_StudentOuRow" Margin="0,0,0,12">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Student OUs:" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBox   Grid.Column="1" x:Name="ops_StudentOU"
                     AutomationProperties.Name="Student organizational units"
                     AutomationProperties.HelpText="Comma-separated OU paths that contain student accounts, e.g. /Students. K12 checks that assess student posture require this; without it they report Not Assessed."
                     ToolTip="Comma-separated OU path(s) containing student accounts, e.g. /Students or OU=Students,DC=district,DC=org. Required by the OU-scoped K12 checks; leave empty to skip them (they report Not Assessed)."/>
        </Grid>

        <Grid Grid.Row="6" Margin="0,0,0,12">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Output:" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBox   Grid.Column="1" x:Name="ops_OutputDir"/>
          <Button    Grid.Column="2" x:Name="ops_BrowseOutput" Content="Browse..." Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
        </Grid>

        <Grid Grid.Row="7" Margin="0,12,0,0">
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
            <ProgressBar Grid.Column="1" x:Name="ops_Progress" IsIndeterminate="True" Height="6" Margin="16,0,16,0" Visibility="Collapsed" Foreground="#2563EB" Background="#EDF1F6"/>
          </Grid>
          <Border Grid.Row="1" BorderBrush="#E2E8F0" BorderThickness="1" Margin="0,12,0,0">
            <TextBox x:Name="ops_LogPane" IsReadOnly="True" VerticalScrollBarVisibility="Auto"
                     AcceptsReturn="True" TextWrapping="NoWrap" FontFamily="Consolas" FontSize="12"
                     Background="#FFFFFF" Foreground="#1F2933" BorderThickness="0" Padding="8"/>
          </Border>
        </Grid>

        <Border Grid.Row="8" x:Name="ops_ResultBanner" Background="#ECFDF5" BorderBrush="#16A34A" BorderThickness="1"
                Padding="12,8" Margin="0,8,0,0" Visibility="Collapsed">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" x:Name="ops_ResultText" Foreground="#1F2933" VerticalAlignment="Center" TextWrapping="Wrap"/>
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
        <TextBlock Grid.Row="0" Text="Safehouse" FontSize="22" FontWeight="Bold" Foreground="#1F2933" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Stored credentials, expiration status, and rotation history." Foreground="#94A3B8" Margin="0,0,0,16"/>
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

      <!-- ─── REPORTS PANEL ─── -->
      <Grid x:Name="panel_Reports" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Reports" FontSize="22" FontWeight="Bold" Foreground="#1F2933" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" x:Name="rp_DirHint" Foreground="#94A3B8" Margin="0,0,0,16"/>
        <DataGrid x:Name="rp_Grid" Grid.Row="2">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Name"     Binding="{Binding Name}"     Width="*"/>
            <DataGridTextColumn Header="Platform"  Binding="{Binding Platform}"  Width="140"/>
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
        <TextBlock Grid.Row="0" Text="Settings" FontSize="22" FontWeight="Bold" Foreground="#1F2933" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Runtime configuration applied to all subsequent scans." Foreground="#94A3B8" Margin="0,0,0,16"/>
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
            <TextBlock Grid.Row="0" Grid.Column="0" Text="Profile" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <ComboBox  Grid.Row="0" Grid.Column="1" x:Name="st_Profile" Margin="0,8">
              <ComboBoxItem Content="Default" IsSelected="True"/>
              <ComboBoxItem Content="K12"/>
            </ComboBox>
            <TextBlock Grid.Row="2" Grid.Column="0" Text="Output directory" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <Grid Grid.Row="2" Grid.Column="1" Margin="0,8">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <TextBox Grid.Column="0" x:Name="st_OutputDir"/>
              <Button  Grid.Column="1" x:Name="st_BrowseOutput" Content="Browse..." Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
            </Grid>
            <TextBlock Grid.Row="3" Grid.Column="0" Text="Config file path" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="3" Grid.Column="1" x:Name="st_ConfigPath" Margin="0,8" IsReadOnly="True"/>
            <TextBlock Grid.Row="4" Grid.Column="1" x:Name="st_StatusLine" Foreground="#16A34A" Margin="0,16,0,0"/>
          </Grid>
        </ScrollViewer>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="st_Apply"  Content="Apply"  Style="{StaticResource PrimaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="st_Revert" Content="Revert" Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
      </Grid>

      <!-- ─── INSPECTOR PANEL ─── -->
      <Grid x:Name="panel_Source" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Function &amp; Scan Inspector" FontSize="22" FontWeight="Bold" Foreground="#1F2933" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Read the actual source of every scan, check, and helper in this module. Filter by area or search by name, then select a function to view its code." Foreground="#94A3B8" Margin="0,0,0,16" TextWrapping="Wrap"/>
        <Grid Grid.Row="2" Margin="0,0,0,12">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <ComboBox  Grid.Column="0" x:Name="src_AreaFilter" Margin="0,0,8,0"/>
          <TextBox   Grid.Column="1" x:Name="src_Search"/>
          <TextBlock Grid.Column="2" x:Name="src_Count" Foreground="#94A3B8" VerticalAlignment="Center" Margin="12,0,0,0"/>
        </Grid>
        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="320"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <ListBox Grid.Column="0" x:Name="src_List"/>
          <Grid Grid.Column="1" Margin="12,0,0,0">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <Grid Grid.Row="0" Margin="0,0,0,6">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" x:Name="src_Meta" Foreground="#94A3B8" VerticalAlignment="Center" TextWrapping="Wrap" Text="Select a function to view its source."/>
              <Button Grid.Column="1" x:Name="src_Copy" Content="Copy" Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
            </Grid>
            <TextBox Grid.Row="1" x:Name="src_Code" IsReadOnly="True" FontFamily="Consolas, Courier New" FontSize="12"
                     Background="#FFFFFF" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                     TextWrapping="NoWrap" AcceptsReturn="True" AcceptsTab="True"/>
          </Grid>
        </Grid>
      </Grid>

      <!-- ─── BRANDING PANEL ─── -->
      <Grid x:Name="panel_Branding" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Report Branding (White-Label)" FontSize="22" FontWeight="Bold" Foreground="#1F2933" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Add your firm's details to the header of generated reports. The &quot;Generated with Guerrilla by Jim Tyler, Microsoft MVP&quot; attribution always remains in the footer. Saved to your config and applied on the next scan." Foreground="#94A3B8" Margin="0,0,0,16" TextWrapping="Wrap"/>
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
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" Text="Firm / company name" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="br_FirmName" Margin="0,8"/>
            <TextBlock Grid.Row="1" Grid.Column="0" Text="Logo (file path or URL)" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <Grid Grid.Row="1" Grid.Column="1" Margin="0,8">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <TextBox Grid.Column="0" x:Name="br_LogoPath"/>
              <Button  Grid.Column="1" x:Name="br_BrowseLogo" Content="Browse..." Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
            </Grid>
            <TextBlock Grid.Row="2" Grid.Column="0" Text="Consultant name" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="2" Grid.Column="1" x:Name="br_ConsultantName" Margin="0,8"/>
            <TextBlock Grid.Row="3" Grid.Column="0" Text="Consultant email" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="3" Grid.Column="1" x:Name="br_ConsultantEmail" Margin="0,8"/>
            <TextBlock Grid.Row="4" Grid.Column="0" Text="Client / org assessed" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="4" Grid.Column="1" x:Name="br_ClientName" Margin="0,8"/>
            <TextBlock Grid.Row="5" Grid.Column="0" Text="Confidentiality banner" Foreground="#64748B" VerticalAlignment="Center" Margin="0,8"/>
            <TextBox   Grid.Row="5" Grid.Column="1" x:Name="br_Confidentiality" Margin="0,8"/>
            <TextBlock Grid.Row="6" Grid.Column="1" x:Name="br_StatusLine" Foreground="#16A34A" Margin="0,16,0,0"/>
          </Grid>
        </ScrollViewer>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="br_Save"   Content="Save"   Style="{StaticResource PrimaryButton}" Margin="0,0,8,0"/>
          <Button x:Name="br_Revert" Content="Revert" Style="{StaticResource SecondaryButton}"/>
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
        FunctionIndex   = $null
    }

    # ── Helpers ───────────────────────────────────────────────────────────
    $setActiveTab = {
        param([string]$Tab)
        foreach ($t in @('Operations', 'Safehouse', 'Reports', 'Settings', 'Source', 'Branding')) {
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
            'Reports'   { & $refreshReportsGrid }
            'Settings'  { & $loadSettings }
            'Source'    { & $refreshSourceList }
            'Branding'  { & $loadBranding }
        }
    }

    $appendLog = {
        param([string]$Message)
        $tb = $session.Controls['ops_LogPane']
        # In test mode the log timestamps are zeroed so demo/sample output is deterministic
        # (matches the zeroed in-scan [0000 UTC] stamps from the console helpers).
        $tm = $session.Controls['ops_TestMode']
        $stamp = if ($tm -and $tm.IsChecked) { '00:00:00' } else { [datetime]::Now.ToString('HH:mm:ss') }
        $tb.AppendText("[$stamp] $Message`r`n")
        $tb.ScrollToEnd()
    }

    $resetOperationsUI = {
        $session.Controls['ops_RunButton'].IsEnabled  = $true
        $session.Controls['ops_RunButton'].Visibility = 'Visible'
        $session.Controls['ops_CancelButton'].Visibility = 'Collapsed'
        $session.Controls['ops_Progress'].Visibility = 'Collapsed'
    }

    $loadCategoriesForPlatform = {
        $panel = $session.Controls['ops_CategoryPanel']
        $panel.Children.Clear()
        $categories = if ($session.Controls['ops_PlatformAD'].IsChecked) {
            @('DomainForest','Trusts','PrivilegedAccounts','PasswordPolicy','Kerberos','ACLDelegation',
              'GroupPolicy','LogonScripts','CertificateServices','StaleObjects','Network','TierZero','Logging','Tradecraft','AttackPath')
        } elseif ($session.Controls['ops_PlatformWorkspace'].IsChecked) {
            @('Authentication','EmailSecurity','DriveSecurity','OAuthSecurity','AdminManagement',
              'Collaboration','DeviceManagement','LoggingAlerting','K12')
        } elseif ($session.Controls['ops_PlatformCloud'].IsChecked) {
            @('ConditionalAccess','AuthenticationMethods','PIM','Applications','Federation',
              'TenantConfig','AzureIAM','Intune','M365Services')
        } else {
            @()  # Campaign runs everything by default
        }

        # Categories that start unchecked even though they belong to the platform.
        # Email Security is opt-in for Google Workspace scans (noisier, slower set).
        $defaultUnchecked = if ($session.Controls['ops_PlatformWorkspace'].IsChecked) { @('EmailSecurity') } else { @() }

        if ($categories.Count -eq 0) {
            $panel.Children.Add([Windows.Controls.TextBlock]@{
                Text       = 'Campaign runs the default set in each enabled platform.'
                Foreground = $brushes.Gray
                Margin     = '0,4'
            })
            return
        }

        # "All" toggle
        $allCb = New-Object System.Windows.Controls.CheckBox
        $allCb.Content     = 'All'
        $allCb.IsChecked   = ($defaultUnchecked.Count -eq 0)
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
            $cb.IsChecked = ($cat -notin $defaultUnchecked)
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
    foreach ($r in @('ops_PlatformAD','ops_PlatformWorkspace','ops_PlatformCloud','ops_PlatformCampaign')) {
        $session.Controls[$r].Add_Checked({ & $loadCategoriesForPlatform })
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
        $reportStyle  = "$($session.Controls['ops_ReportStyle'].SelectedItem.Content)"
        $testMode     = [bool]$session.Controls['ops_TestMode'].IsChecked
        $selectedCats = & $getSelectedCategories
        $studentOus   = @("$($session.Controls['ops_StudentOU'].Text)" -split '[,;]' |
            ForEach-Object { $_.Trim() } | Where-Object { $_ })

        $cmdletName = if ($session.Controls['ops_PlatformAD'].IsChecked)        { 'Invoke-ADAudit' }
                      elseif ($session.Controls['ops_PlatformWorkspace'].IsChecked) { 'Invoke-GWSAudit' }
                      elseif ($session.Controls['ops_PlatformCloud'].IsChecked)     { 'Invoke-EntraAudit' }
                      else                                                          { 'Invoke-Campaign' }

        & $appendLog "Starting $cmdletName ($($selectedCats.Count) categories, mode=$mode)..."

        # Pass params explicitly into the scriptblock rather than relying on
        # closure capture — closures don't survive the runspace transfer reliably.
        $action = {
            param([string]$CmdletName, [string]$OutputDir, [string]$Mode,
                  [bool]$NoReports, [bool]$NoDelta, [string[]]$Categories, [string]$VaultName,
                  [string]$ReportStyle, [bool]$TestMode, [string[]]$StudentOU)
            # Only pass parameters the target cmdlet actually declares. The four
            # platform cmdlets have different surfaces (e.g. Invoke-Campaign has no
            # -Categories/-NoReports; none take -ScanMode), so gating on the real
            # parameter set avoids "A parameter cannot be found that matches ..."
            # instead of maintaining brittle per-cmdlet name lists. The cmdlets
            # auto-resolve credentials from the safehouse vault, so passing -VaultName
            # is all that's needed for a vault-only setup.
            $params = (Get-Command $CmdletName).Parameters
            $invokeArgs = @{}
            if ($params.ContainsKey('Quiet'))                                    { $invokeArgs.Quiet = $false }
            if ($VaultName          -and $params.ContainsKey('VaultName'))        { $invokeArgs.VaultName = $VaultName }
            if ($OutputDir          -and $params.ContainsKey('OutputDirectory')) { $invokeArgs.OutputDirectory = $OutputDir }
            if ($NoReports          -and $params.ContainsKey('NoReports'))       { $invokeArgs.NoReports = $true }
            if ($NoDelta            -and $params.ContainsKey('NoDelta'))         { $invokeArgs.NoDelta = $true }
            if ($Categories.Count -gt 0 -and $params.ContainsKey('Categories')) { $invokeArgs.Categories = $Categories }
            if ($Mode               -and $params.ContainsKey('ScanMode'))       { $invokeArgs.ScanMode = $Mode }
            if ($ReportStyle        -and $params.ContainsKey('ReportStyle'))    { $invokeArgs.ReportStyle = $ReportStyle }
            if ($TestMode           -and $params.ContainsKey('TestMode'))       { $invokeArgs.TestMode = $true }
            if ($StudentOU.Count -gt 0 -and $params.ContainsKey('StudentOU'))  { $invokeArgs.StudentOU = $StudentOU }
            & $CmdletName @invokeArgs
        }
        $actionArgs = @($cmdletName, $outDir, $mode, [bool]$noReports, [bool]$noDelta, @($selectedCats), $session.VaultName, $reportStyle, $testMode, @($studentOus))

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
                $newest = Get-ChildItem $session.ReportsDir -Filter '*.html' -ErrorAction SilentlyContinue |
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
        try {
            $entries = Show-AddCredentialDialog -Owner $session.Window
            if (-not $entries) { return }   # cancelled
            # Make sure the vault exists before writing.
            if (-not (Get-SecretVault -Name $session.VaultName -ErrorAction SilentlyContinue)) {
                Initialize-GuerrillaVault -VaultName $session.VaultName | Out-Null
            }
            $n = Save-SafehouseCredentialSet -Entries $entries -VaultName $session.VaultName
            & $refreshSafehouseGrid
            [System.Windows.MessageBox]::Show("Stored $n credential value(s). Use 'Test All' to verify connectivity.", 'Credential saved', 'OK', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("Could not save credential: $_", 'Error', 'OK', 'Error') | Out-Null
        }
    })

    $session.Controls['sh_Remove'].Add_Click({
        $row = $session.Controls['sh_Grid'].SelectedItem
        if (-not $row) {
            [System.Windows.MessageBox]::Show('Select a credential row first, then click Remove Selected.', 'No selection', 'OK', 'Information') | Out-Null
            return
        }
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
        if (-not $row) {
            [System.Windows.MessageBox]::Show('Select a credential row first, then click Rotate Selected.', 'No selection', 'OK', 'Information') | Out-Null
            return
        }
        [System.Windows.MessageBox]::Show("To rotate, run from a PowerShell prompt:`r`n`r`n    Set-Safehouse -Rotate $($row.Environment)", 'Rotate Credential', 'OK', 'Information') | Out-Null
    })

    $session.Controls['sh_Test'].Add_Click({
        $btn = $session.Controls['sh_Test']
        $btn.IsEnabled = $false
        $btn.Content = 'Testing…'

        $testComplete = {
            param($result)
            $btn.IsEnabled = $true
            $btn.Content = 'Test All'
            $rows = @($result)
            if ($rows.Count -eq 0) {
                [System.Windows.MessageBox]::Show('No credentials were found to test. Add credentials first.', 'Test All', 'OK', 'Information') | Out-Null
                return
            }
            $passStates = @('CONNECTED', 'VALID', 'STORED', 'KERBEROS')
            $pass = @($rows | Where-Object { $passStates -contains $_.Status }).Count
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("$pass of $($rows.Count) checks passed.")
            $lastEnv = ''
            foreach ($r in $rows) {
                if ($r.Environment -ne $lastEnv) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine($r.Environment)
                    $lastEnv = $r.Environment
                }
                $icon = if ($passStates -contains $r.Status) { '[OK] ' } else { '[X]  ' }
                $detail = if ($r.Detail) { " - $($r.Detail)" } else { '' }
                [void]$sb.AppendLine("  $icon$($r.Name): $($r.Status) ($($r.ElapsedMs)ms)$detail")
            }
            $icon = if ($pass -eq $rows.Count) { 'Information' } else { 'Warning' }
            [System.Windows.MessageBox]::Show($sb.ToString(), 'Safehouse Connectivity Test', 'OK', $icon) | Out-Null
        }.GetNewClosure()

        $testError = {
            param($err)
            $btn.IsEnabled = $true
            $btn.Content = 'Test All'
            [System.Windows.MessageBox]::Show("Connectivity test failed: $err", 'Test All', 'OK', 'Error') | Out-Null
        }.GetNewClosure()

        Invoke-GuerrillaGuiAsync `
            -ModulePath $session.ModulePath `
            -Action     { param($VaultName) Test-Safehouse -VaultName $VaultName } `
            -Arguments  @($session.VaultName) `
            -Dispatcher $session.Window.Dispatcher `
            -OnComplete $testComplete `
            -OnError    $testError
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
            $platform = switch -Regex ($f.Name) {
                '^[Rr]econnaissance'  { 'Active Directory' }
                '^[Ff]ortification'   { 'Workspace' }
                '^[Ii]nfiltration'    { 'Cloud' }
                '^[Cc]ampaign'        { 'All Platforms' }
                'Executive'           { 'Summary' }
                'Technical'           { 'Technical' }
                'Playbook|Remediation' { 'Remediation' }
                'Dashboard'           { 'Dashboard' }
                default               { 'Other' }
            }
            [PSCustomObject]@{
                Name     = $f.Name
                Platform  = $platform
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
                ConfigPath = $session.ConfigPath
                Profile    = "$($session.Controls['st_Profile'].SelectedItem.Content)"
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

    # ── Inspector tab handlers ────────────────────────────────────────────
    # Map a module-relative file path (and function name as a fallback) to a
    # friendly area label used by the Inspector's area filter.
    $classifyFunctionArea = {
        param([string]$Rel, [string]$Name)
        $p = ($Rel -replace '\\', '/')
        if ($p -match '^Private/AD/'     -or $Name -match '^(Test-AD|Test-TIER|Invoke-AD|Invoke-TierZero)') { return 'Active Directory' }
        if ($p -match '^Private/Audit/'  -or $Name -match '^(Test-(EMAIL|DRIVE|ADMIN|AUTH|COLLAB|GROUP|OAUTH|DEVICE|LOG|GTRADE|GWS)|Invoke-Gws|Invoke-Google)') { return 'Google Workspace' }
        if ($p -match '^Private/Entra/'  -or $Name -match '^(Test-(EID|M365|INTUNE|AZIAM|AIAGENT)|Invoke-Entra|Invoke-M365|Invoke-Azure|Invoke-Intune)') { return 'Entra / Azure / M365' }
        if ($p -match '^Private/Export/') { return 'Reporting & Export' }
        if ($p -match '^Private/Gui/')   { return 'GUI' }
        if ($p -match '^Public/')        { return 'Public cmdlets' }
        return 'Core & helpers'
    }

    # Parse every module .ps1 once and index each function's name, area, source
    # location, and full source text. Built lazily on first Inspector visit.
    $ensureFunctionIndex = {
        if ($session.FunctionIndex) { return }
        $root = Split-Path $session.ModulePath -Parent
        $index = [System.Collections.Generic.List[object]]::new()
        foreach ($sub in @('Public', 'Private')) {
            $dir = Join-Path $root $sub
            if (-not (Test-Path $dir)) { continue }
            foreach ($file in (Get-ChildItem -Path $dir -Recurse -Filter *.ps1 -File)) {
                $tokens = $null; $perrors = $null
                try {
                    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$perrors)
                } catch { continue }
                $funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
                foreach ($fn in $funcs) {
                    $rel = $file.FullName.Substring($root.Length).TrimStart('\', '/')
                    $index.Add([PSCustomObject]@{
                        Name      = $fn.Name
                        Area      = (& $classifyFunctionArea $rel $fn.Name)
                        RelFile   = $rel
                        StartLine = $fn.Extent.StartLineNumber
                        Source    = $fn.Extent.Text
                    })
                }
            }
        }
        $session.FunctionIndex = @($index | Sort-Object Area, Name)

        # Populate the area filter dropdown once: "All areas" + each distinct area.
        $combo = $session.Controls['src_AreaFilter']
        if ($combo.Items.Count -eq 0) {
            $allItem = New-Object System.Windows.Controls.ComboBoxItem
            $allItem.Content = 'All areas'
            [void]$combo.Items.Add($allItem)
            foreach ($area in (@($session.FunctionIndex.Area) | Sort-Object -Unique)) {
                $ci = New-Object System.Windows.Controls.ComboBoxItem
                $ci.Content = $area
                [void]$combo.Items.Add($ci)
            }
            $combo.SelectedIndex = 0
        }
    }

    # Filter the index by area + search term and rebuild the function list.
    $refreshSourceList = {
        & $ensureFunctionIndex
        $area = if ($session.Controls['src_AreaFilter'].SelectedItem) {
            [string]$session.Controls['src_AreaFilter'].SelectedItem.Content
        } else { 'All areas' }
        $term = [string]$session.Controls['src_Search'].Text
        $items = @($session.FunctionIndex)
        if ($area -and $area -ne 'All areas') { $items = @($items | Where-Object { $_.Area -eq $area }) }
        if ($term) { $items = @($items | Where-Object { $_.Name -like "*$term*" }) }

        $list = $session.Controls['src_List']
        $list.Items.Clear()
        foreach ($it in $items) {
            $li = New-Object System.Windows.Controls.ListBoxItem
            $li.Content = $it.Name
            $li.Tag     = $it
            [void]$list.Items.Add($li)
        }
        $session.Controls['src_Count'].Text = "$($items.Count) function(s)"
    }

    $session.Controls['src_List'].Add_SelectionChanged({
        $sel = $session.Controls['src_List'].SelectedItem
        if (-not $sel) { return }
        $info = $sel.Tag
        $session.Controls['src_Code'].Text = $info.Source
        $session.Controls['src_Meta'].Text = "$($info.Name)   $([char]0x2014)   $($info.RelFile) : line $($info.StartLine)   $([char]0x00B7)   $($info.Area)"
    })
    $session.Controls['src_Search'].Add_TextChanged({ & $refreshSourceList })
    $session.Controls['src_AreaFilter'].Add_SelectionChanged({ & $refreshSourceList })
    $session.Controls['src_Copy'].Add_Click({
        $code = $session.Controls['src_Code'].Text
        if ($code) { try { [System.Windows.Clipboard]::SetText($code) } catch { } }
    })

    # ── Branding (white-label) tab handlers ───────────────────────────────
    $loadBranding = {
        $b = @{}
        try {
            if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
                $cfg = Get-Content $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
                if ($cfg.branding) { $b = $cfg.branding }
            }
        } catch { }
        $session.Controls['br_FirmName'].Text        = [string]($b.FirmName ?? '')
        $session.Controls['br_LogoPath'].Text        = [string]($b.LogoPath ?? '')
        $session.Controls['br_ConsultantName'].Text  = [string]($b.ConsultantName ?? '')
        $session.Controls['br_ConsultantEmail'].Text = [string]($b.ConsultantEmail ?? '')
        $session.Controls['br_ClientName'].Text      = [string]($b.ClientName ?? '')
        $session.Controls['br_Confidentiality'].Text = [string]($b.Confidentiality ?? '')
        $session.Controls['br_StatusLine'].Foreground = $brushes.Sage
        $session.Controls['br_StatusLine'].Text = ''
    }

    $session.Controls['br_BrowseLogo'].Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Images|*.png;*.jpg;*.jpeg;*.gif;*.svg|All files|*.*'
        if ($dlg.ShowDialog() -eq 'OK') { $session.Controls['br_LogoPath'].Text = $dlg.FileName }
    })

    $session.Controls['br_Save'].Add_Click({
        try {
            $cfg = @{}
            if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
                $cfg = Get-Content $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
            }
            if (-not $cfg) { $cfg = @{} }
            $cfg.branding = @{
                FirmName        = $session.Controls['br_FirmName'].Text
                LogoPath        = $session.Controls['br_LogoPath'].Text
                ConsultantName  = $session.Controls['br_ConsultantName'].Text
                ConsultantEmail = $session.Controls['br_ConsultantEmail'].Text
                ClientName      = $session.Controls['br_ClientName'].Text
                Confidentiality = $session.Controls['br_Confidentiality'].Text
            }
            $dir = Split-Path $session.ConfigPath -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $session.ConfigPath -Encoding UTF8
            $session.Controls['br_StatusLine'].Foreground = $brushes.Sage
            $session.Controls['br_StatusLine'].Text = "Saved at $([datetime]::Now.ToString('HH:mm:ss')). Applied on your next scan."
        } catch {
            $session.Controls['br_StatusLine'].Foreground = $brushes.Red
            $session.Controls['br_StatusLine'].Text = "Save failed: $_"
        }
    })
    $session.Controls['br_Revert'].Add_Click({ & $loadBranding })

    # ── Nav button wiring ─────────────────────────────────────────────────
    foreach ($t in @('Operations','Safehouse','Reports','Settings','Source','Branding')) {
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
    & $loadCategoriesForPlatform
    & $setActiveTab $StartOn

    # Single-instance guard. Two windows share config.json + platform *-state.json files,
    # so a second instance would clobber state (last-writer-wins). Refuse the second window —
    # but self-heal: the old guard used initiallyOwned + createdNew, which reported "already
    # open" whenever the *named* mutex still existed (a launch that threw or was force-killed,
    # or a still-alive prior session, left the handle open and never cleared). Now:
    #   - dispose any stale handle from an earlier launch in THIS session,
    #   - WaitOne(0) to test real ownership, treating an AbandonedMutex (previous owner exited
    #     without releasing) as "we own it now" rather than a permanent block.
    if ($script:GuerrillaGuiMutex) {
        try { $script:GuerrillaGuiMutex.Dispose() } catch {}
        $script:GuerrillaGuiMutex = $null
    }
    $haveLock = $false
    try {
        $m = New-Object System.Threading.Mutex($false, 'Global\Guerrilla.GuiSingleInstance')
        try { $haveLock = $m.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $haveLock = $true }  # prior owner died without releasing
        if ($haveLock) { $script:GuerrillaGuiMutex = $m } else { $m.Dispose() }
    } catch {
        # Mutex unavailable (rare) — fail open rather than block the GUI entirely.
        $haveLock = $true
        $script:GuerrillaGuiMutex = $null
    }
    if (-not $haveLock) {
        # Advisory, not absolute: the "holder" may be a stranded/zombie process (a prior launch
        # whose window got lost behind a hidden console) that still holds the OS mutex. Refusing
        # outright traps the user. Let them open anyway; only the genuine two-live-windows case
        # risks state clobbering, and they're told.
        $resp = [System.Windows.MessageBox]::Show(
            "Guerrilla appears to already be open in another window. Two windows share the same config/state files (last save wins).`n`nOpen a new window anyway?`n  Yes = open it now    No = switch to the existing window (Alt+Tab)",
            'Already running', 'YesNo', 'Warning')
        if ($resp -ne 'Yes') { return }
        # Proceeding without the lock — the other process owns it, so we must not release it on close.
        $script:GuerrillaGuiMutex = $null
    }

    # Cleanup on window close (stop any running scan). The single-instance lock is released in
    # the finally below so it is freed even if Closing never fires (window threw before opening).
    $window.Add_Closing({
        if ($session.CurrentAsync) {
            Stop-GuerrillaGuiAsync -State $session.CurrentAsync
        }
    })

    # Bring the window to the front on first render so it can't open hidden behind other windows
    # (which, with the console hidden, is how a launch gets stranded). A brief Topmost flash +
    # Activate pulls it forward without keeping it always-on-top.
    $window.Add_ContentRendered({
        try { $window.Activate(); $window.Topmost = $true; $window.Topmost = $false } catch {}
    })

    # Block until the user closes the window, then always release the single-instance lock.
    try {
        [void]$window.ShowDialog()
    } finally {
        if ($script:GuerrillaGuiMutex) {
            try { $script:GuerrillaGuiMutex.ReleaseMutex() } catch {}
            try { $script:GuerrillaGuiMutex.Dispose() } catch {}
            $script:GuerrillaGuiMutex = $null
        }
    }
}
