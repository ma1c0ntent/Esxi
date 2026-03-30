!-- RDPMonitor.xaml -->
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="RDP Monitor"
    Height="640" Width="960"
    MinHeight="480" MinWidth="700"
    WindowStartupLocation="CenterScreen"
    Background="#1E1E2E">

    <Window.Resources>
        <SolidColorBrush x:Key="BgBase"       Color="#1E1E2E"/>
        <SolidColorBrush x:Key="BgSurface"    Color="#2A2A3E"/>
        <SolidColorBrush x:Key="BgElevated"   Color="#313145"/>
        <SolidColorBrush x:Key="AccentBlue"   Color="#5B9BD5"/>
        <SolidColorBrush x:Key="AccentGreen"  Color="#4EC994"/>
        <SolidColorBrush x:Key="AccentRed"    Color="#E06C75"/>
        <SolidColorBrush x:Key="AccentYellow" Color="#E5C07B"/>
        <SolidColorBrush x:Key="TextPrimary"  Color="#CDD6F4"/>
        <SolidColorBrush x:Key="TextMuted"    Color="#6C7086"/>
        <SolidColorBrush x:Key="BorderColor"  Color="#45475A"/>

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
            <Setter Property="Foreground" Value="#6C7086"/>
            <Setter Property="FontSize"   Value="10"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Margin"     Value="0,0,0,4"/>
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
                    <Border Width="28" Height="28" Background="#5B9BD5"
                            CornerRadius="6" Margin="0,0,10,0">
                        <TextBlock Text="⬡" FontSize="15" HorizontalAlignment="Center"
                                   VerticalAlignment="Center" Foreground="White"/>
                    </Border>
                    <TextBlock Text="RDP Monitor" FontSize="15" FontWeight="SemiBold"
                               Foreground="#CDD6F4" FontFamily="Segoe UI" VerticalAlignment="Center"/>
                    <TextBlock Text="v1.0" FontSize="10" Foreground="#6C7086"
                               FontFamily="Segoe UI" VerticalAlignment="Center" Margin="8,2,0,0"/>
                </StackPanel>
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
                                 IsReadOnly="True"/>
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
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Text="Total" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblTotal" Grid.Column="1" Text="0"
                                   Foreground="#5B9BD5" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Text="Open" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblOpen" Grid.Column="1" Text="0"
                                   Foreground="#4EC994" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Text="Closed" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="12"/>
                        <TextBlock x:Name="lblClosed" Grid.Column="1" Text="0"
                                   Foreground="#E06C75" FontWeight="Bold" FontFamily="Segoe UI" FontSize="12"/>
                    </Grid>
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
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
