#Requires -Version 5.1
<#
.SYNOPSIS
    Monitors TCP port 3389 (RDP) across multiple hosts using parallel runspaces.

.DESCRIPTION
    Checks TCP port 3389 on one or more hosts using a runspace pool for parallelism.
    Tracks state changes against a persistent CSV database, exports results to CSV,
    and writes structured logs to both the console and a log file.

.PARAMETER ComputerName
    One or more hostnames or IP addresses to check.

.PARAMETER InputFile
    Path to a TXT file (one host per line) or CSV file (with ComputerName, Hostname,
    IPAddress, or DNSName column). Format is auto-detected by file extension.

.PARAMETER DatabasePath
    Path to the persistent state database CSV. Created on first run.
    Defaults to .\rdp_state_db.csv

.PARAMETER OutputPath
    Path to write the current-run results CSV.
    Defaults to .\rdp_results_<timestamp>.csv

.PARAMETER LogPath
    Path to the log file.
    Defaults to .\rdp_monitor_<timestamp>.log

.PARAMETER Port
    TCP port to test. Defaults to 3389.

.PARAMETER TimeoutMs
    Connection timeout per host in milliseconds. Defaults to 2000.

.PARAMETER MaxThreads
    Maximum concurrent runspace threads. Defaults to 50.

.EXAMPLE
    .\Invoke-RDPMonitor.ps1 -ComputerName 192.168.1.10, 192.168.1.11

.EXAMPLE
    .\Invoke-RDPMonitor.ps1 -InputFile .\hosts.txt -DatabasePath .\state_db.csv

.EXAMPLE
    .\Invoke-RDPMonitor.ps1 -InputFile .\servers.csv -DatabasePath .\state_db.csv

.EXAMPLE
    .\Invoke-RDPMonitor.ps1 -ComputerName dc01.corp.local -InputFile .\servers.csv
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,

    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputFile,

    [string]$DatabasePath = ".\rdp_state_db.csv",
    [string]$OutputPath   = ".\rdp_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$LogPath      = ".\rdp_monitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    [int]$Port      = 3389,
    [int]$TimeoutMs = 2000,

    [ValidateRange(1, 500)]
    [int]$MaxThreads = 50
)

#region ── Logging ──────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','CHANGE')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "[$timestamp] [$Level] $Message"

    $colour = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARN'    { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
        'CHANGE'  { 'Magenta' }
        default   { 'White'   }
    }

    Write-Host $entry -ForegroundColor $colour
    Add-Content -Path $LogPath -Value $entry
}

#endregion

#region ── State DB helpers ─────────────────────────────────────────────────────

function Load-StateDB {
    param([string]$Path)
    if (Test-Path $Path) {
        return Import-Csv $Path | Group-Object Host -AsHashTable -AsString
    }
    return @{}
}

function Save-StateDB {
    param([string]$Path, [object[]]$Results)
    $latest = $Results | Sort-Object Timestamp | Group-Object Host |
              ForEach-Object { $_.Group | Select-Object -Last 1 }
    $latest | Export-Csv -Path $Path -NoTypeInformation -Force
}

function Get-StateChange {
    param($Previous, $Current)
    if (-not $Previous) { return 'NEW' }
    $prevStatus = ($Previous | Select-Object -Last 1).Status
    if ($prevStatus -ne $Current.Status) {
        return "CHANGED ($prevStatus -> $($Current.Status))"
    }
    return $Current.Status
}

#endregion

#region ── Worker script block ──────────────────────────────────────────────────

$workerScript = {
    param($Target, $Port, $TimeoutMs)

    $result = [PSCustomObject]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Host      = $Target
        Port      = $Port
        Status    = 'UNKNOWN'
        LatencyMs = $null
        ErrorMsg  = ''
    }

    try {
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $iar = $tcp.BeginConnect($Target, $Port, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        $sw.Stop()

        if ($ok -and $tcp.Connected) {
            $tcp.EndConnect($iar)
            $result.Status    = 'UP'
            $result.LatencyMs = $sw.ElapsedMilliseconds
        } else {
            $result.Status   = 'DOWN'
            $result.ErrorMsg = 'Connection timed out or refused'
        }
    }
    catch {
        $result.Status   = 'DOWN'
        $result.ErrorMsg = $_.Exception.Message
    }
    finally {
        if ($tcp) { $tcp.Dispose() }
    }

    return $result
}

#endregion

#region ── Collect targets ──────────────────────────────────────────────────────

Write-Log "RDP Monitor starting — Port: $Port | Threads: $MaxThreads | Timeout: ${TimeoutMs}ms"

$targets = [System.Collections.Generic.List[string]]::new()

if ($ComputerName) {
    foreach ($h in $ComputerName) { $targets.Add($h.Trim()) }
}

if ($InputFile) {
    $extension = [System.IO.Path]::GetExtension($InputFile).ToLower()

    if ($extension -eq '.csv') {
        $fileHosts = Import-Csv $InputFile |
                     ForEach-Object {
                         $col = if ($_.ComputerName) { $_.ComputerName }
                                elseif ($_.Hostname)  { $_.Hostname }
                                elseif ($_.IPAddress) { $_.IPAddress }
                                elseif ($_.DNSName)   { $_.DNSName }
                         $col
                     } |
                     Where-Object { $_ -and $_.Trim() -ne '' } |
                     ForEach-Object { $_.Trim() }
    } else {
        # TXT — one host per line, # comments skipped
        $fileHosts = Get-Content $InputFile |
                     Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' } |
                     ForEach-Object { $_.Trim() }
    }

    if (-not $fileHosts) {
        Write-Log "No hosts could be parsed from $InputFile — check column names or file content." -Level WARN
    } else {
        foreach ($h in $fileHosts) { $targets.Add($h) }
        Write-Log "Loaded $($fileHosts.Count) host(s) from $InputFile ($($extension.TrimStart('.').ToUpper()))"
    }
}

$targets = $targets | Select-Object -Unique

if (-not $targets) {
    Write-Log "No targets specified. Use -ComputerName or -InputFile." -Level ERROR
    exit 1
}

Write-Log "Total unique targets: $($targets.Count)"

#endregion

#region ── Load state database ──────────────────────────────────────────────────

$stateDB = Load-StateDB -Path $DatabasePath
Write-Log "State database loaded: $($stateDB.Count) known host(s) from $DatabasePath"

#endregion

#region ── Dispatch runspaces ───────────────────────────────────────────────────

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
$pool.Open()

$jobs = [System.Collections.Generic.List[hashtable]]::new()

Write-Log "Dispatching $($targets.Count) host(s) to runspace pool..."

foreach ($target in $targets) {
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($workerScript)
    [void]$ps.AddArgument($target)
    [void]$ps.AddArgument($Port)
    [void]$ps.AddArgument($TimeoutMs)

    $jobs.Add(@{
        PowerShell = $ps
        Handle     = $ps.BeginInvoke()
        Target     = $target
    })
}

#endregion

#region ── Collect results ──────────────────────────────────────────────────────

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($job in $jobs) {
    try {
        $result = $job.PowerShell.EndInvoke($job.Handle)

        if ($result) {
            $r = $result[0]

            $prevRecords = if ($stateDB.ContainsKey($r.Host)) { $stateDB[$r.Host] } else { $null }
            $stateLabel  = Get-StateChange -Previous $prevRecords -Current $r

            $r | Add-Member -NotePropertyName 'StateChange' -NotePropertyValue $stateLabel -Force

            $results.Add($r)

            if ($stateLabel -like 'CHANGED*') {
                Write-Log "$($r.Host):$Port — $($r.Status) — $stateLabel" -Level CHANGE
            } elseif ($r.Status -eq 'UP') {
                Write-Log "$($r.Host):$Port — UP ($($r.LatencyMs)ms)" -Level SUCCESS
            } else {
                Write-Log "$($r.Host):$Port — DOWN — $($r.ErrorMsg)" -Level WARN
            }
        }
    }
    catch {
        Write-Log "Error collecting result for $($job.Target): $_" -Level ERROR
    }
    finally {
        $job.PowerShell.Dispose()
    }
}

$pool.Close()
$pool.Dispose()

#endregion

#region ── Export & summary ─────────────────────────────────────────────────────

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
Write-Log "Results exported to $OutputPath"

Save-StateDB -Path $DatabasePath -Results $results
Write-Log "State database updated at $DatabasePath"

$up      = ($results | Where-Object Status -eq 'UP').Count
$down    = ($results | Where-Object Status -eq 'DOWN').Count
$changed = ($results | Where-Object { $_.StateChange -like 'CHANGED*' }).Count

Write-Log "─────────────────────────────────────────────"
Write-Log "SUMMARY  Total: $($results.Count) | UP: $up | DOWN: $down | State Changes: $changed"
Write-Log "─────────────────────────────────────────────"
Write-Log "Log file: $LogPath"

return $results

#endregion
