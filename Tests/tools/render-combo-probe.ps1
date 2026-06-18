# Off-screen WPF render probe for the ComboBox selection-box (GUI-2).
# Renders a collapsed ComboBox with the given <Style> to a PNG so we can VERIFY the
# fix by looking at the actual rendered pixels. Run: powershell -STA -NoProfile -File <this>
param(
    [Parameter(Mandatory)][string]$StylePath,           # file with just the <Style TargetType="ComboBox">...</Style>
    [string]$OutPng = (Join-Path $env:TEMP 'combo-probe.png')
)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$style = Get-Content -Raw $StylePath
# Root is a Border (not a Window) so it arranges/renders off-screen without being shown.
$xaml = @"
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="240" Height="60" Background="#1A1A1A">
  <Border.Resources>
    $style
  </Border.Resources>
  <Grid>
    <ComboBox x:Name="cb" Width="160" Height="28" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="14,0,0,0">
      <ComboBoxItem Content="Guerrilla"/>
      <ComboBoxItem Content="Professional"/>
      <ComboBoxItem Content="Slate" IsSelected="True"/>
    </ComboBox>
  </Grid>
</Border>
"@

$root = [Windows.Markup.XamlReader]::Parse($xaml)
$scale = 5
$sz = [Windows.Size]::new(240, 60)
$root.Measure($sz)
$root.Arrange([Windows.Rect]::new([Windows.Point]::new(0,0), $sz))
$root.UpdateLayout()
$root.UpdateLayout()

$rtb = New-Object Windows.Media.Imaging.RenderTargetBitmap ([int](240*$scale)), ([int](60*$scale)), (96.0*$scale), (96.0*$scale), ([Windows.Media.PixelFormats]::Pbgra32)
$rtb.Render($root)

$enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
$enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
$fs = [IO.File]::Create($OutPng)
$enc.Save($fs); $fs.Close()
Write-Host "PNG: $OutPng  ($([int](240*$scale))x$([int](60*$scale)))"
