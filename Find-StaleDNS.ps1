#Requires -Modules ActiveDirectory, DnsServer
<#
.SYNOPSIS
    Detects stale DNS records by cross-referencing AD computer objects, DNS records,
    and live ping results across all DNS zones on a target server.

.DESCRIPTION
    Phase 1 - AD Pull:    Gets all computer objects from Active Directory
    Phase 2 - DNS Pull:   Gets all A records from all forward lookup zones
    Phase 3 - Ping:       Tests connectivity in parallel via RunspacePool
    Analysis:             Cross-references all three datasets and flags stale conditions
    Output:               Exports results to CSV

.PARAMETER DnsServer
    FQDN or IP of the DNS server to query. Defaults to $env:LOGONSERVER.

.PARAMETER Domain
    AD domain to query. Defaults to current domain.

.PARAMETER OutputPath
    Path for the CSV export. Defaults to .\StaleDNS_<timestamp>.csv

.PARAMETER MaxThreads
    Max concurrent runspaces for ping phase. Default 50.

.PARAMETER PingTimeoutMs
    Timeout in milliseconds per ping attempt. Default 1000.

.EXAMPLE
    .\Find-StaleDNS.ps1 -DnsServer dc01.corp.local -OutputPath C:\Reports\stale.csv
#>

[CmdletBinding()]
param(
    [string]$DnsServer    = ($env:LOGONSERVER -replace '\\\\', ''),
    [string]$Domain       = $env:USERDNSDOMAIN,
    [string]$OutputPath   = ".\StaleDNS_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]$MaxThreads      = 50,
    [int]$PingTimeoutMs   = 1000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Write-Phase {
    param([int]$Number, [string]$Message)
    Write-Host "`n[Phase $Number] $Message" -ForegroundColor Cyan
}

function Write-Status {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host "  >> $Message" -ForegroundColor $Color
}

#endregion

#region Phase 1 - Active Directory

Write-Phase 1 "Pulling computer objects from Active Directory ($Domain)"

$adComputers = @{}

try {
    Get-ADComputer -Filter * -Server $Domain -Properties LastLogonDate |
        ForEach-Object {
            $adComputers[$_.DNSHostName.ToLower()] = [PSCustomObject]@{
                Hostname      = $_.DNSHostName.ToLower()
                LastLogonDate = $_.LastLogonDate
            }
        }
    Write-Status "$($adComputers.Count) computer objects retrieved" 'Green'
}
catch {
    Write-Error "Failed to query Active Directory: $_"
    exit 1
}

#endregion

#region Phase 2 - DNS Records

Write-Phase 2 "Pulling A records from all forward lookup zones on $DnsServer"

$dnsRecords = @{}

try {
    $zones = Get-DnsServerZone -ComputerName $DnsServer |
        Where-Object { -not $_.IsReverseLookupZone -and $_.ZoneType -ne 'Forwarder' }

    Write-Status "Found $($zones.Count) forward lookup zones"

    foreach ($zone in $zones) {
        try {
            Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone.ZoneName -RRType A |
                ForEach-Object {
                    $fqdn = "$($_.HostName).$($zone.ZoneName)".ToLower().TrimEnd('.')

                    # Only keep the first record if duplicates exist across zones
                    if (-not $dnsRecords.ContainsKey($fqdn)) {
                        $dnsRecords[$fqdn] = [PSCustomObject]@{
                            Hostname        = $fqdn
                            IPAddress       = $_.RecordData.IPv4Address.ToString()
                            RecordTimestamp = $_.TimeStamp   # null if not scavenging-enabled
                            ZoneName        = $zone.ZoneName
                        }
                    }
                }
        }
        catch {
            Write-Status "Skipped zone '$($zone.ZoneName)': $_" 'Yellow'
        }
    }

    Write-Status "$($dnsRecords.Count) A records retrieved" 'Green'
}
catch {
    Write-Error "Failed to query DNS server: $_"
    exit 1
}

#endregion

#region Phase 3 - Parallel Ping via RunspacePool

Write-Phase 3 "Pinging hosts in parallel (MaxThreads=$MaxThreads, Timeout=${PingTimeoutMs}ms)"

# Build a deduplicated list of all unique hostnames across both datasets
$allHostnames = @(
    $adComputers.Keys
    $dnsRecords.Keys
) | Sort-Object -Unique

Write-Status "Testing $($allHostnames.Count) unique hostnames"

# Scriptblock executed in each runspace
$pingScript = {
    param([string]$Hostname, [int]$TimeoutMs)

    $result = [PSCustomObject]@{
        Hostname = $Hostname
        Online   = $false
    }

    try {
        $ping  = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($Hostname, $TimeoutMs)
        $result.Online = ($reply.Status -eq 'Success')
    }
    catch {
        # Unresolvable or unreachable — stays $false
    }
    finally {
        if ($ping) { $ping.Dispose() }
    }

    return $result
}

# Initialize RunspacePool
$pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
$pool.Open()

$jobs = New-Object System.Collections.Generic.List[hashtable]

foreach ($hostname in $allHostnames) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($pingScript).AddArgument($hostname).AddArgument($PingTimeoutMs)

    $jobs.Add(@{
        PowerShell = $ps
        Handle     = $ps.BeginInvoke()
        Hostname   = $hostname
    })
}

# Collect results
$pingResults = @{}
$completed   = 0
$total       = $jobs.Count

foreach ($job in $jobs) {
    try {
        $result = $job.PowerShell.EndInvoke($job.Handle)
        if ($result) {
            $pingResults[$job.Hostname] = $result.Online
        }
    }
    catch {
        $pingResults[$job.Hostname] = $false
    }
    finally {
        $job.PowerShell.Dispose()
    }

    $completed++
    if ($completed % 50 -eq 0 -or $completed -eq $total) {
        Write-Status "Progress: $completed / $total"
    }
}

$pool.Close()
$pool.Dispose()

$onlineCount = ($pingResults.Values | Where-Object { $_ }).Count
Write-Status "$onlineCount / $total hosts responded" 'Green'

#endregion

#region Analysis - Cross-Reference and Flag Stale Conditions

Write-Phase 4 "Cross-referencing datasets and flagging stale records"

$report = New-Object System.Collections.Generic.List[PSCustomObject]

# All unique hostnames across all three datasets
$universe = @(
    $adComputers.Keys
    $dnsRecords.Keys
) | Sort-Object -Unique

foreach ($hostname in $universe) {
    $inAD   = $adComputers.ContainsKey($hostname)
    $inDNS  = $dnsRecords.ContainsKey($hostname)
    $online = $pingResults[$hostname] -eq $true

    $adObj  = if ($inAD)  { $adComputers[$hostname] } else { $null }
    $dnsObj = if ($inDNS) { $dnsRecords[$hostname]  } else { $null }

    $staleFlags = New-Object System.Collections.Generic.List[string]

    # Full truth table across InAD / InDNS / Online (7 stale conditions, 1 healthy)
    #
    #  InAD  InDNS  Online  | Result
    #  ----  -----  ------  | ------
    #   Y     Y      Y      | Healthy - skip
    #   Y     Y      N      | C1 - registered everywhere but not responding
    #   Y     N      Y      | C2 - pinging but missing DNS record (shadow device or reg failure)
    #   Y     N      N      | C3 - AD object only, no DNS, offline (likely stale AD object)
    #   N     Y      Y      | C4 - online and in DNS but no AD object (rogue or decommissioned)
    #   N     Y      N      | C5 - DNS record only, offline (classic stale DNS)
    #   N     N      Y      | C6 - pinging but not in AD or DNS (universe scope guard)
    #   N     N      N      | N/A - won't appear, not in universe

    if ($inAD -and $inDNS -and $online) {
        continue  # Healthy
    }
    elseif ($inAD -and $inDNS -and -not $online) {
        [void]$staleFlags.Add('C1: In AD and DNS but not responding to ping')
    }
    elseif ($inAD -and -not $inDNS -and $online) {
        [void]$staleFlags.Add('C2: In AD and pinging but no DNS record')
    }
    elseif ($inAD -and -not $inDNS -and -not $online) {
        [void]$staleFlags.Add('C3: In AD only - no DNS record and offline')
    }
    elseif (-not $inAD -and $inDNS -and $online) {
        [void]$staleFlags.Add('C4: In DNS and pinging but no AD computer object')
    }
    elseif (-not $inAD -and $inDNS -and -not $online) {
        [void]$staleFlags.Add('C5: DNS record only - no AD object and offline')
    }
    elseif (-not $inAD -and -not $inDNS -and $online) {
        [void]$staleFlags.Add('C6: Responding to ping but not found in AD or DNS')
    }

    $report.Add([PSCustomObject]@{
        Hostname           = $hostname
        IPAddress          = if ($dnsObj) { $dnsObj.IPAddress }       else { 'N/A' }
        Online             = $online
        InAD               = $inAD
        InDNS              = $inDNS
        StaleReasons       = $staleFlags -join ' | '
        ADLastLogonDate    = if ($adObj)  { $adObj.LastLogonDate }    else { 'N/A' }
        DNSRecordTimestamp = if ($dnsObj) { $dnsObj.RecordTimestamp } else { 'N/A' }
        DNSZone            = if ($dnsObj) { $dnsObj.ZoneName }        else { 'N/A' }
    })
}

Write-Status "$($report.Count) stale records identified" $(if ($report.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region Export

Write-Phase 5 "Exporting to $OutputPath"

try {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Status "Export complete: $OutputPath" 'Green'
}
catch {
    Write-Error "Failed to export CSV: $_"
    exit 1
}

Write-Host "`nDone." -ForegroundColor Cyan
