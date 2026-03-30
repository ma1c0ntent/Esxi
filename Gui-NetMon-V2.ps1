# Invoke-RDPMonitor.ps1

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName Microsoft.Win32

#region --- Load XAML ---
$xamlPath = Join-Path $PSScriptRoot "RDPMonitor.xaml"

if (-not (Test-Path $xamlPath)) {
    throw "UI file not found: $xamlPath"
}

[xml]$xaml = (Get-Content -Path $xamlPath -Raw) -replace 'x:Class="[^"]*"', ''
$reader    = [System.Xml.XmlNodeReader]::new($xaml)
$window    = [System.Windows.Markup.XamlReader]::Load($reader)
#endregion

#region --- Wire Controls ---
$txtCsvPath   = $window.FindName("txtCsvPath")
$txtPort      = $window.FindName("txtPort")
$txtInterval  = $window.FindName("txtInterval")
$txtTimeout   = $window.FindName("txtTimeout")
$txtRunspaces = $window.FindName("txtRunspaces")
$txtLog       = $window.FindName("txtLog")
$dgResults    = $window.FindName("dgResults")
$btnBrowse    = $window.FindName("btnBrowse")
$btnStart     = $window.FindName("btnStart")
$btnStop      = $window.FindName("btnStop")
$btnExport    = $window.FindName("btnExport")
$lblStatus    = $window.FindName("lblStatus")
$lblTime      = $window.FindName("lblTime")
$lblTotal     = $window.FindName("lblTotal")
$lblOpen      = $window.FindName("lblOpen")
$lblClosed    = $window.FindName("lblClosed")
$lblChanges   = $window.FindName("lblChanges")
$lblCycle     = $window.FindName("lblCycle")
#endregion

#region --- State ---
$script:hostList    = @()
$script:stateMap    = @{}
$script:rowMap      = @{}
$script:logPath     = $null
$script:csvLogPath  = $null
$script:changeCount = 0
$script:cycleCount  = 0
$script:stopFlag    = $false
$script:pool        = $null
#endregion

#region --- TCP Check Scriptblock ---
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
        "INFO"   { "[INFO]   " }
        "OPEN"   { "[OPEN]   " }
        "CLOSED" { "[CLOSED] " }
        "CHANGE" { "[CHANGE] " }
        "WARN"   { "[WARN]   " }
        "ERROR"  { "[ERROR]  " }
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
    [PSCustomObject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Hostname  = $Hostname
        OldState  = $OldState
        NewState  = $NewState
        Port      = $txtPort.Text
    } | Export-Csv -Path $script:csvLogPath -Append -NoTypeInformation -ErrorAction SilentlyContinue
}
#endregion

#region --- Monitor Cycle ---
function Start-MonitorCycle {
    if ($script:stopFlag -or -not $script:hostList) { return }

    $port      = [int]$txtPort.Text
    $timeoutMs = [int]$txtTimeout.Text
    $maxRS     = [int]$txtRunspaces.Text

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

    foreach ($h in $script:hostList) {
        if (-not $resultDict.ContainsKey($h.Hostname)) { continue }

        $result     = $resultDict[$h.Hostname]
        $newStatus  = if ($result.Open) { "Open" } else { "Closed" }
        $prevStatus = $script:stateMap[$h.Hostname]
        $row        = $script:rowMap[$h.Hostname]

        $script:stateMap[$h.Hostname] = $newStatus
        $row.Status   = $newStatus
        $row.Latency  = if ($result.Latency) { "$($result.Latency)" } else { "-" }
        $row.LastSeen = $result.Time.ToString("HH:mm:ss")

        if ($prevStatus -ne "Unknown" -and $prevStatus -ne $newStatus) {
            $script:changeCount++
            $row.LastChange = $result.Time.ToString("HH:mm:ss")
            Write-Log "$($h.Hostname) — $prevStatus → $newStatus" "CHANGE"
            Log-CsvEvent $h.Hostname $prevStatus $newStatus
        }
    }

    $dgResults.Items.Refresh()
    Update-Summary
    Update-Status "Last poll: $(Get-Date -Format 'HH:mm:ss')  |  Cycle $($script:cycleCount)"
}
#endregion

#region --- Timers ---
$clockTimer          = [System.Windows.Threading.DispatcherTimer]::new()
$clockTimer.Interval = [TimeSpan]::FromSeconds(1)
$clockTimer.Add_Tick({ $lblTime.Text = (Get-Date -Format "yyyy-MM-dd  HH:mm:ss") })
$clockTimer.Start()

$monitorTimer = [System.Windows.Threading.DispatcherTimer]::new()
$monitorTimer.Add_Tick({ Start-MonitorCycle })
#endregion

#region --- Event Handlers ---
$btnBrowse.Add_Click({
    $dlg        = [Microsoft.Win32.OpenFileDialog]::new()
    $dlg.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dlg.Title  = "Select host CSV"
    if ($dlg.ShowDialog()) {
        $txtCsvPath.Text = $dlg.FileName
        Write-Log "CSV selected: $($dlg.FileName)" "INFO"
    }
})

$btnStart.Add_Click({
    if (-not $txtCsvPath.Text -or -not (Test-Path $txtCsvPath.Text)) {
        Write-Log "No valid CSV path specified." "WARN"
        Update-Status "Select a valid CSV file first."
        return
    }

    try { $script:hostList = Import-Csv -Path $txtCsvPath.Text }
    catch { Write-Log "Failed to load CSV: $_" "ERROR"; return }

    if (-not ($script:hostList | Get-Member -Name 'Hostname' -ErrorAction SilentlyContinue)) {
        Write-Log "CSV must contain a 'Hostname' column." "ERROR"
        return
    }

    foreach ($field in @($txtPort, $txtInterval, $txtTimeout, $txtRunspaces)) {
        if (-not [int]::TryParse($field.Text, [ref]$null)) {
            Write-Log "Invalid value in configuration fields." "WARN"
            return
        }
    }

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

    $csvDir            = Split-Path $txtCsvPath.Text
    $ts                = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath    = Join-Path $csvDir "RDPMonitor_$ts.log"
    $script:csvLogPath = Join-Path $csvDir "RDPMonitor_StateChanges_$ts.csv"

    Write-Log "Monitoring $($script:hostList.Count) host(s) on port $($txtPort.Text)" "INFO"
    Write-Log "Interval: $($txtInterval.Text)s | Timeout: $($txtTimeout.Text)ms | Runspaces: $($txtRunspaces.Text)" "INFO"
    Write-Log "Log: $($script:logPath)" "INFO"

    $btnStart.IsEnabled    = $false
    $btnStop.IsEnabled     = $true
    $txtPort.IsEnabled     = $false
    $txtInterval.IsEnabled = $false
    $txtTimeout.IsEnabled  = $false
    $txtRunspaces.IsEnabled= $false
    $txtCsvPath.IsEnabled  = $false
    $btnBrowse.IsEnabled   = $false

    Start-MonitorCycle
    $monitorTimer.Interval = [TimeSpan]::FromSeconds([int]$txtInterval.Text)
    $monitorTimer.Start()

    Update-Status "Monitoring $($script:hostList.Count) host(s)..."
})

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

$btnExport.Add_Click({
    if (-not $dgResults.Items.Count) { Write-Log "Nothing to export." "WARN"; return }
    $dlg          = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter   = "CSV Files (*.csv)|*.csv"
    $dlg.FileName = "RDPMonitor_Snapshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog()) {
        $dgResults.Items |
            Select-Object Host, Label, Port, Status, Latency, LastChange, LastSeen |
            Export-Csv -Path $dlg.FileName -NoTypeInformation
        Write-Log "Snapshot exported: $($dlg.FileName)" "INFO"
        Update-Status "Exported to $($dlg.FileName)"
    }
})

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
