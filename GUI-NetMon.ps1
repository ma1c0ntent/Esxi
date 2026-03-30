#Requires -Version 5.1
<#
.SYNOPSIS
    WPF GUI wrapper for parallel RDP port monitoring with state-change detection and CSV logging.

.DESCRIPTION
    Loads a CSV of hostnames/IPs, checks TCP 3389 concurrently via a RunspacePool,
    tracks Open/Closed state changes, logs events to CSV, and displays results in a
    modern WPF dark-theme GUI with live updating DataGrid and output log.

.NOTES
    CSV Format:
        Hostname,Label
        server01,DC01
        10.0.1.50,Web Server
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName Microsoft.Win32

#region --- XAML ---
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="RDP Monitor"
    Height="640" Width="960"
    MinHeight="480" MinWidth="700"
    WindowStartupLocation="CenterScreen"
    Background="#1E1E2E">

    <Window.Resources>
        <SolidColorBrush x:Key="BgBase"      Color="#1E1E2E"/>
        <SolidColorBrush x:Key="BgSurface"   Color="#2A2A3E"/>
        <SolidColorBrush x:Key="BgElevated"  Color="#313145"/>
        <SolidColorBrush x:Key="AccentBlue"  Color="#5B9BD5"/>
        <SolidColorBrush x:Key="AccentGreen" Color="#4EC994"/>
        <SolidColorBrush x:Key="AccentRed"   Color="#E06C75"/>
        <SolidColorBrush x:Key="AccentYellow"Color="#E5C07B"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#CDD6F4"/>
        <SolidColorBrush x:Key="TextMuted"   Color="#6C7086"/>
        <SolidColorBrush x:Key="BorderColor" Color="#45475A"/>

        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background"      Value="#5B9BD5"/>
            <Setter Property="Foreground"      Value="#CDD6F4"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding"         Value="16,8"/>
            <Setter Property="FontSize"        Value="12"/>
            <Setter Property="FontFamily"      Value="Segoe UI"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#4A8BC4"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#3A7AB3"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#45475A"/>
                                <Setter Property="Foreground" Value="#6C7086"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="ModernTextBox" TargetType="TextBox">
            <Setter Property="Background"      Value="#2A2A3E"/>
            <Setter Property="Foreground"      Value="#CDD6F4"/>
            <Setter Property="CaretBrush"      Value="#CDD6F4"/>
            <Setter Property="BorderBrush"     Value="#45475A"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding"         Value="10,6"/>
            <Setter Property="FontSize"        Value="12"/>
            <Setter Property="FontFamily"      Value="Segoe UI"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter Property="BorderBrush" Value="#5B9BD5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="ModernDataGrid" TargetType="DataGrid">
            <Setter Property="Background"               Value="#2A2A3E"/>
            <Setter Property="Foreground"               Value="#CDD6F4"/>
            <Setter Property="BorderBrush"              Value="#45475A"/>
            <Setter Property="BorderThickness"          Value="1"/>
            <Setter Property="RowBackground"            Value="#2A2A3E"/>
            <Setter Property="AlternatingRowBackground" Value="#313145"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#45475A"/>
            <Setter Property="VerticalGridLinesBrush"   Value="#45475A"/>
            <Setter Property="FontFamily"               Value="Segoe UI"/>
            <Setter Property="FontSize"                 Value="12"/>
            <Setter Property="ColumnHeaderHeight"       Value="34"/>
        </Style>

        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background"      Value="#313145"/>
            <Setter Property="Foreground"      Value="#5B9BD5"/>
            <Setter Property="FontWeight"      Value="SemiBold"/>
            <Setter Property="Padding"         Value="10,0"/>
            <Setter Property="BorderBrush"     Value="#45475A"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>

        <Style TargetType="DataGridRow">
            <Setter Property="Height" Value="28"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#3D3D5C"/>
                </Trigger>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#35354F"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SectionLabel" TargetType="TextBlock">
            <Setter Property="Foreground"  Value="#6C7086"/>
            <Setter Property="FontSize"    Value="10"/>
            <Setter Property="FontFamily"  Value="Segoe UI"/>
            <Setter Property="FontWeight"  Value="SemiBold"/>
            <Setter Property="Margin"      Value="0,0,0,4"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="50"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="32"/>
        </Grid.RowDefinitions>

        <!-- TITLE BAR -->
        <Border Grid.Row="0" Background="#161625">
            <Grid Margin="16,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Width="28" Height="28" Background="#5B9BD5" CornerRadius="6" Margin="0,0,10,0">
                        <TextBlock Text="⬡" FontSize="15" HorizontalAlignment="Center"
                                   VerticalAlignment="Center" Foreground="White"/>
                    </Border>
                    <TextBlock Text="RDP Monitor" FontSize="15" FontWeight="SemiBold"
                               Foreground="#CDD6F4" FontFamily="Segoe UI" VerticalAlignment="Center"/>
                    <TextBlock Text="v1.0" FontSize="10" Foreground="#6C7086"
                               FontFamily="Segoe UI" VerticalAlignment="Center" Margin="8,2,0,0"/>
                </StackPanel>
                <!-- Cycle counter -->
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="Cycle " Foreground="#6C7086" FontFamily="Segoe UI" FontSize="12"/>
                    <TextBlock x:Name="lblCycle" Text="0" Foreground="#5B9BD5"
                               FontFamily="Segoe UI" FontSize="12" FontWeight="Bold"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- MAIN CONTENT -->
        <Grid Grid.Row="1" Margin="16">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="210"/>
                <ColumnDefinition Width="12"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- LEFT PANEL -->
            <Border Grid.Column="0" Background="#2A2A3E" CornerRadius="8" Padding="14">
                <StackPanel>
                    <TextBlock Text="CONFIGURATION" Style="{StaticResource SectionLabel}" Margin="0,0,0,12"/>

                    <TextBlock Text="CSV Path" Style="{StaticResource SectionLabel}"/>
                    <Grid Margin="0,0,0,12">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="6"/>
                            <ColumnDefinition Width="32"/>
                        </Grid.ColumnDefinitions>
                        <TextBox x:Name="txtCsvPath" Style="{StaticResource ModernTextBox}"
                                 PlaceholderText="hosts.csv..." IsReadOnly="True"/>
                        <Button x:Name="btnBrowse" Grid.Column="2" Content="…"
                                Style="{StaticResource ModernButton}"
                                Padding="0" Height="32" ToolTip="Browse for CSV"/>
                    </Grid>

                    <TextBlock Text="Port" Style="{StaticResource SectionLabel}"/>
                    <TextBox x:Name="txtPort" Style="{StaticResource ModernTextBox}"
                             Text="3389" Margin="0,0,0,12"/>

                    <TextBlock Text="Interval (seconds)" Style="{StaticResource SectionLabel}"/>
                    <TextBox x:Name="txtInterval" Style="{StaticResource ModernTextBox}"
                             Text="30" Margin="0,0,0,12"/>

                    <TextBlock Text="Timeout (ms)" Style="{StaticResource SectionLabel}"/>
                    <TextBox x:Name="txtTimeout" Style="{StaticResource ModernTextBox}"
                             Text="2000" Margin="0,0,0,12"/>

                    <TextBlock Text="Max Runspaces" Style="{StaticResource SectionLabel}"/>
                    <TextBox x:Name="txtRunspaces" Style="{StaticResource ModernTextBox}"
                             Text="50" Margin="0,0,0,20"/>

                    <Button x:Name="btnStart" Content="▶  Start Monitoring"
                            Style="{StaticResource ModernButton}" Height="34" Margin="0,0,0,8"/>
                    <Button x:Name="btnStop" Content="■  Stop"
                            Style="{StaticResource ModernButton}" Height="34"
                            Background="#E06C75" IsEnabled="False" Margin="0,0,0,8"/>
                    <Button x:Name="btnExport" Content="Export CSV"
                            Style="{StaticResource ModernButton}" Height="34"
                            Background="#4EC994" Foreground="#1E1E2E"/>

                    <Separator Background="#45475A" Margin="0,16"/>

                    <TextBlock Text="SUMMARY" Style="{StaticResource SectionLabel}" Margin="0,0,0,10"/>

                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                        <TextBlock Text="Total" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblTotal" Grid.Column="1" Text="0"
                                   Foreground="#5B9BD5" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                        <TextBlock Text="Open" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblOpen" Grid.Column="1" Text="0"
                                   Foreground="#4EC994" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                        <TextBlock Text="Closed" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblClosed" Grid.Column="1" Text="0"
                                   Foreground="#E06C75" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                        <TextBlock Text="State Changes" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblChanges" Grid.Column="1" Text="0"
                                   Foreground="#E5C07B" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                </StackPanel>
            </Border>

            <!-- RIGHT PANEL -->
            <Grid Grid.Column="2">
                <Grid.RowDefinitions>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="12"/>
                    <RowDefinition Height="155"/>
                </Grid.RowDefinitions>

                <!-- DataGrid -->
                <Border Grid.Row="0" Background="#2A2A3E" CornerRadius="8"
                        BorderBrush="#45475A" BorderThickness="1">
                    <DataGrid x:Name="dgResults"
                              Style="{StaticResource ModernDataGrid}"
                              AutoGenerateColumns="False"
                              IsReadOnly="True"
                              SelectionMode="Extended"
                              GridLinesVisibility="Horizontal"
                              HeadersVisibility="Column"
                              CanUserResizeRows="False"
                              Margin="1">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Host"        Binding="{Binding Host}"       Width="180"/>
                            <DataGridTextColumn Header="Label"       Binding="{Binding Label}"      Width="120"/>
                            <DataGridTextColumn Header="Port"        Binding="{Binding Port}"       Width="60"/>
                            <DataGridTextColumn Header="Status"      Binding="{Binding Status}"     Width="80"/>
                            <DataGridTextColumn Header="Latency(ms)" Binding="{Binding Latency}"    Width="90"/>
                            <DataGridTextColumn Header="Last Change" Binding="{Binding LastChange}" Width="130"/>
                            <DataGridTextColumn Header="Last Seen"   Binding="{Binding LastSeen}"   Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Border>

                <!-- Log -->
                <Border Grid.Row="2" Background="#161625" CornerRadius="8"
                        BorderBrush="#45475A" BorderThickness="1" Padding="10,8">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <TextBlock Text="OUTPUT LOG" Style="{StaticResource SectionLabel}" Margin="0,0,0,6"/>
                        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
                            <TextBox x:Name="txtLog"
                                     Background="Transparent"
                                     Foreground="#4EC994"
                                     BorderThickness="0"
                                     FontFamily="Cascadia Code, Consolas, monospace"
                                     FontSize="11"
                                     IsReadOnly="True"
                                     TextWrapping="Wrap"
                                     AcceptsReturn="True"/>
                        </ScrollViewer>
                    </Grid>
                </Border>
            </Grid>
        </Grid>

        <!-- STATUS BAR -->
        <Border Grid.Row="2" Background="#161625" BorderBrush="#45475A" BorderThickness="0,1,0,0">
            <Grid Margin="16,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="lblStatus" Text="Ready — load a CSV to begin"
                           Foreground="#6C7086" FontFamily="Segoe UI" FontSize="11"
                           VerticalAlignment="Center"/>
                <TextBlock x:Name="lblTime" Foreground="#6C7086" FontFamily="Segoe UI"
                           FontSize="11" VerticalAlignment="Center" HorizontalAlignment="Right"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@
#endregion

#region --- Build Window & Wire Controls ---
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$txtCsvPath  = $window.FindName("txtCsvPath")
$txtPort     = $window.FindName("txtPort")
$txtInterval = $window.FindName("txtInterval")
$txtTimeout  = $window.FindName("txtTimeout")
$txtRunspaces= $window.FindName("txtRunspaces")
$txtLog      = $window.FindName("txtLog")
$dgResults   = $window.FindName("dgResults")
$btnBrowse   = $window.FindName("btnBrowse")
$btnStart    = $window.FindName("btnStart")
$btnStop     = $window.FindName("btnStop")
$btnExport   = $window.FindName("btnExport")
$lblStatus   = $window.FindName("lblStatus")
$lblTime     = $window.FindName("lblTime")
$lblTotal    = $window.FindName("lblTotal")
$lblOpen     = $window.FindName("lblOpen")
$lblClosed   = $window.FindName("lblClosed")
$lblChanges  = $window.FindName("lblChanges")
$lblCycle    = $window.FindName("lblCycle")
#endregion

#region --- State ---
$script:hostList    = @()
$script:stateMap    = @{}        # Hostname -> 'Open' | 'Closed' | 'Unknown'
$script:rowMap      = @{}        # Hostname -> PSCustomObject (bound to DataGrid)
$script:logPath     = $null
$script:csvLogPath  = $null
$script:changeCount = 0
$script:cycleCount  = 0
$script:running     = $false
$script:stopFlag    = $false
$script:pool        = $null
#endregion

#region --- TCP Check Scriptblock (runs inside runspace) ---
$tcpCheckScript = {
    param(
        [string]$Hostname,
        [int]$Port,
        [int]$TimeoutMs,
        [System.Collections.Concurrent.ConcurrentDictionary[string,object]]$ResultDict
    )

    $open    = $false
    $latency = $null
    $sw      = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        $sw.Stop()

        if ($ok -and $tcp.Connected) {
            $open    = $true
            $latency = $sw.ElapsedMilliseconds
        }
        $tcp.Close()
    }
    catch { }

    $ResultDict[$Hostname] = [PSCustomObject]@{
        Open    = $open
        Latency = $latency
        Time    = [datetime]::Now
    }
}
#endregion

#region --- Helpers ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts     = Get-Date -Format "HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"     { "[INFO]   " }
        "OPEN"     { "[OPEN]   " }
        "CLOSED"   { "[CLOSED] " }
        "CHANGE"   { "[CHANGE] " }
        "WARN"     { "[WARN]   " }
        "ERROR"    { "[ERROR]  " }
    }
    $line = "$ts $prefix$Message"
    $txtLog.AppendText("$line`n")
    $txtLog.ScrollToEnd()

    if ($script:logPath) {
        Add-Content -Path $script:logPath -Value $line -ErrorAction SilentlyContinue
    }
}

function Update-Summary {
    $lblTotal.Text   = $script:rowMap.Count
    $lblOpen.Text    = ($script:rowMap.Values | Where-Object { $_.Status -eq "Open"   }).Count
    $lblClosed.Text  = ($script:rowMap.Values | Where-Object { $_.Status -eq "Closed" }).Count
    $lblChanges.Text = $script:changeCount
}

function Update-Status { param([string]$Msg); $lblStatus.Text = $Msg }

function Log-CsvEvent {
    param([string]$Hostname, [string]$OldState, [string]$NewState)
    if (-not $script:csvLogPath) { return }
    $row = [PSCustomObject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Hostname  = $Hostname
        OldState  = $OldState
        NewState  = $NewState
        Port      = $txtPort.Text
    }
    $row | Export-Csv -Path $script:csvLogPath -Append -NoTypeInformation -ErrorAction SilentlyContinue
}
#endregion

#region --- Monitor Loop (runs on background thread via DispatcherTimer) ---
function Start-MonitorCycle {
    if ($script:stopFlag -or -not $script:hostList) { return }

    $port       = [int]$txtPort.Text
    $timeoutMs  = [int]$txtTimeout.Text
    $maxRS      = [int]$txtRunspaces.Text

    # Init pool on first cycle
    if (-not $script:pool -or $script:pool.RunspacePoolStateInfo.State -ne 'Opened') {
        $script:pool = [runspacefactory]::CreateRunspacePool(1, $maxRS)
        $script:pool.Open()
    }

    $resultDict = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
    $handles    = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($h in $script:hostList) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $script:pool
        [void]$ps.AddScript($tcpCheckScript)
        [void]$ps.AddArgument($h.Hostname)
        [void]$ps.AddArgument($port)
        [void]$ps.AddArgument($timeoutMs)
        [void]$ps.AddArgument($resultDict)
        $handles.Add(@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }

    foreach ($item in $handles) {
        try   { [void]$item.PS.EndInvoke($item.Handle) }
        catch { Write-Log "Runspace error: $_" "ERROR" }
        finally { $item.PS.Dispose() }
    }

    $script:cycleCount++
    $lblCycle.Text = $script:cycleCount

    # Process results on dispatcher thread (we're already on it via DispatcherTimer)
    foreach ($h in $script:hostList) {
        if (-not $resultDict.ContainsKey($h.Hostname)) { continue }

        $result    = $resultDict[$h.Hostname]
        $newStatus = if ($result.Open) { "Open" } else { "Closed" }
        $prevStatus= $script:stateMap[$h.Hostname]
        $row       = $script:rowMap[$h.Hostname]

        # Update state
        $script:stateMap[$h.Hostname] = $newStatus
        $row.Status  = $newStatus
        $row.Latency = if ($result.Latency) { "$($result.Latency)" } else { "-" }
        $row.LastSeen= $result.Time.ToString("HH:mm:ss")

        # State change detection
        if ($prevStatus -ne "Unknown" -and $prevStatus -ne $newStatus) {
            $script:changeCount++
            $row.LastChange = $result.Time.ToString("HH:mm:ss")
            $level = if ($newStatus -eq "Open") { "OPEN" } else { "CLOSED" }
            Write-Log "$($h.Hostname) — $prevStatus → $newStatus" "CHANGE"
            Log-CsvEvent $h.Hostname $prevStatus $newStatus
        }
    }

    # Force DataGrid refresh
    $dgResults.Items.Refresh()
    Update-Summary
    Update-Status "Last poll: $(Get-Date -Format 'HH:mm:ss')  |  Cycle $($script:cycleCount)"
}
#endregion

#region --- Event Handlers ---

# Clock
$clockTimer          = [System.Windows.Threading.DispatcherTimer]::new()
$clockTimer.Interval = [TimeSpan]::FromSeconds(1)
$clockTimer.Add_Tick({ $lblTime.Text = (Get-Date -Format "yyyy-MM-dd  HH:mm:ss") })
$clockTimer.Start()

# Monitor timer (fires each interval)
$monitorTimer = [System.Windows.Threading.DispatcherTimer]::new()
$monitorTimer.Add_Tick({ Start-MonitorCycle })

# Browse CSV
$btnBrowse.Add_Click({
    $dlg        = [Microsoft.Win32.OpenFileDialog]::new()
    $dlg.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dlg.Title  = "Select host CSV"
    if ($dlg.ShowDialog()) {
        $txtCsvPath.Text = $dlg.FileName
        Write-Log "CSV selected: $($dlg.FileName)" "INFO"
    }
})

# Start monitoring
$btnStart.Add_Click({
    # Validate CSV
    if (-not $txtCsvPath.Text -or -not (Test-Path $txtCsvPath.Text)) {
        Write-Log "No valid CSV path specified." "WARN"
        Update-Status "Select a valid CSV file first."
        return
    }

    try { $script:hostList = Import-Csv -Path $txtCsvPath.Text }
    catch {
        Write-Log "Failed to load CSV: $_" "ERROR"
        return
    }

    if (-not ($script:hostList | Get-Member -Name 'Hostname' -ErrorAction SilentlyContinue)) {
        Write-Log "CSV must contain a 'Hostname' column." "ERROR"
        return
    }

    # Validate numeric fields
    foreach ($field in @($txtPort, $txtInterval, $txtTimeout, $txtRunspaces)) {
        if (-not [int]::TryParse($field.Text, [ref]$null)) {
            Write-Log "Invalid value in configuration fields." "WARN"
            return
        }
    }

    # Init state and DataGrid rows
    $script:stateMap    = @{}
    $script:rowMap      = @{}
    $script:changeCount = 0
    $script:cycleCount  = 0
    $script:stopFlag    = $false

    $rows = [System.Collections.ObjectModel.ObservableCollection[object]]::new()

    foreach ($h in $script:hostList) {
        $label = if ($h.PSObject.Properties['Label'] -and $h.Label) { $h.Label } else { $h.Hostname }
        $row   = [PSCustomObject]@{
            Host       = $h.Hostname
            Label      = $label
            Port       = $txtPort.Text
            Status     = "Unknown"
            Latency    = "-"
            LastChange = "-"
            LastSeen   = "-"
        }
        $script:stateMap[$h.Hostname] = "Unknown"
        $script:rowMap[$h.Hostname]   = $row
        $rows.Add($row)
    }

    $dgResults.ItemsSource = $rows

    # Set up log files next to the CSV
    $csvDir             = Split-Path $txtCsvPath.Text
    $ts                 = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath     = Join-Path $csvDir "RDPMonitor_$ts.log"
    $script:csvLogPath  = Join-Path $csvDir "RDPMonitor_StateChanges_$ts.csv"

    Write-Log "Monitoring $($script:hostList.Count) hosts on port $($txtPort.Text)" "INFO"
    Write-Log "Interval: $($txtInterval.Text)s | Timeout: $($txtTimeout.Text)ms | Runspaces: $($txtRunspaces.Text)" "INFO"
    Write-Log "Log: $($script:logPath)" "INFO"

    # UI state
    $btnStart.IsEnabled   = $false
    $btnStop.IsEnabled    = $true
    $txtPort.IsEnabled    = $false
    $txtInterval.IsEnabled= $false
    $txtTimeout.IsEnabled = $false
    $txtRunspaces.IsEnabled= $false
    $txtCsvPath.IsEnabled = $false
    $btnBrowse.IsEnabled  = $false

    # Kick off immediately then start interval timer
    Start-MonitorCycle
    $monitorTimer.Interval = [TimeSpan]::FromSeconds([int]$txtInterval.Text)
    $monitorTimer.Start()

    Update-Status "Monitoring $($script:hostList.Count) hosts..."
})

# Stop monitoring
$btnStop.Add_Click({
    $script:stopFlag = $true
    $monitorTimer.Stop()

    if ($script:pool) {
        $script:pool.Close()
        $script:pool.Dispose()
        $script:pool = $null
    }

    $btnStart.IsEnabled    = $true
    $btnStop.IsEnabled     = $false
    $txtPort.IsEnabled     = $true
    $txtInterval.IsEnabled = $true
    $txtTimeout.IsEnabled  = $true
    $txtRunspaces.IsEnabled= $true
    $txtCsvPath.IsEnabled  = $true
    $btnBrowse.IsEnabled   = $true

    Write-Log "Monitoring stopped after $($script:cycleCount) cycle(s)." "INFO"
    Update-Status "Stopped. $($script:cycleCount) cycle(s) completed."
})

# Export current DataGrid snapshot
$btnExport.Add_Click({
    if (-not $dgResults.Items.Count) {
        Write-Log "Nothing to export." "WARN"
        return
    }
    $dlg            = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter     = "CSV Files (*.csv)|*.csv"
    $dlg.FileName   = "RDPMonitor_Snapshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog()) {
        $dgResults.Items | Select-Object Host, Label, Port, Status, Latency, LastChange, LastSeen |
            Export-Csv -Path $dlg.FileName -NoTypeInformation
        Write-Log "Snapshot exported: $($dlg.FileName)" "INFO"
        Update-Status "Exported to $($dlg.FileName)"
    }
})

# Clean up on close
$window.Add_Closing({
    $monitorTimer.Stop()
    $clockTimer.Stop()
    if ($script:pool) {
        $script:pool.Close()
        $script:pool.Dispose()
    }
})

#endregion

$window.ShowDialog() | Out-Null
