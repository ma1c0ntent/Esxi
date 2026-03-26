#Requires -Modules VCF.PowerCLI
<#
.SYNOPSIS
    Collects VM inventory from one or more ESXi/vCenter servers and validates
    DNS hostname resolution and network reachability.

.DESCRIPTION
    Can be used two ways:
      1. Directly:  .\Get-VMInventory.ps1 -Server vcenter01 -OutputDir C:\Reports
      2. Dot-sourced and called as a function:
            . .\Get-VMInventory.ps1
            Get-VMInventory -Server vcenter01 -OutputDir C:\Reports

.PARAMETER Server
    One or more vCenter / ESXi hostnames or IP addresses to query.

.PARAMETER Credential
    PSCredential used to authenticate to every server in -Server.
    If omitted you will be prompted once and that credential is reused.

.PARAMETER OutputDir
    Directory where the CSV will be written. Defaults to the current directory.

.PARAMETER PingCount
    Number of ICMP echo requests sent per VM. Default: 2.

.PARAMETER PassThru
    If specified, returns the result objects to the pipeline in addition to
    writing the CSV. Useful when calling as a function and piping results onward.

.EXAMPLE
    # Run directly as a script
    .\Get-VMInventory.ps1 -Server vcenter01.corp.local -OutputDir C:\Reports

.EXAMPLE
    # Dot-source and call as a function
    . .\Get-VMInventory.ps1
    Get-VMInventory -Server vcenter01.corp.local, vcenter02.corp.local `
                    -Credential (Get-Credential) -PassThru

.EXAMPLE
    # Pipe results into further filtering
    . .\Get-VMInventory.ps1
    Get-VMInventory -Server vcenter01.corp.local | Where-Object { -not $_.PingReachable }
#>

#region ── Script-level parameters (used when run directly) ──────────────────
param (
    [string[]] $Server,
    [PSCredential] $Credential,
    [string] $OutputDir = (Get-Location).Path,
    [ValidateRange(1,10)]
    [int] $PingCount = 2,
    [switch] $PassThru
)
#endregion

#region ── Helper: normalise GuestId to a friendly OS label ──────────────────
function Get-NormalisedOS {
    param([string]$GuestId)

    switch -Regex ($GuestId) {
        # ── Red Hat Enterprise Linux ──────────────────────────────────────────
        'rhel9'             { return 'RHEL 9' }
        'rhel8'             { return 'RHEL 8' }
        'rhel7'             { return 'RHEL 7' }
        'rhel6'             { return 'RHEL 6' }
        'rhel'              { return 'RHEL (other)' }

        # ── CentOS ────────────────────────────────────────────────────────────
        'centos8'           { return 'CentOS 8' }
        'centos7'           { return 'CentOS 7' }
        'centos'            { return 'CentOS (other)' }

        # ── Rocky / AlmaLinux ─────────────────────────────────────────────────
        'rockylinux'        { return 'Rocky Linux' }
        'almalinux'         { return 'AlmaLinux' }

        # ── Oracle Linux ──────────────────────────────────────────────────────
        'oraclelinux'       { return 'Oracle Linux' }

        # ── Ubuntu ────────────────────────────────────────────────────────────
        'ubuntu64'          { return 'Ubuntu (64-bit)' }
        'ubuntu'            { return 'Ubuntu (32-bit)' }

        # ── Debian ────────────────────────────────────────────────────────────
        'debian'            { return 'Debian' }

        # ── SUSE / SLES ───────────────────────────────────────────────────────
        'sles16'            { return 'SLES 16' }
        'sles15'            { return 'SLES 15' }
        'sles12'            { return 'SLES 12' }
        'sles'              { return 'SLES (other)' }
        'opensuse'          { return 'openSUSE' }

        # ── Windows Server ────────────────────────────────────────────────────
        'windows2025srv'    { return 'Windows Server 2025' }
        'windows2022srv'    { return 'Windows Server 2022' }
        'windows2019srv'    { return 'Windows Server 2019' }
        'windows2016srv'    { return 'Windows Server 2016' }
        'windows2012r2'     { return 'Windows Server 2012 R2' }
        'windows2012'       { return 'Windows Server 2012' }
        'windows2008r2'     { return 'Windows Server 2008 R2' }
        'windows2008'       { return 'Windows Server 2008' }
        'winlonghornguest'  { return 'Windows Server 2008 (Longhorn)' }

        # ── Windows Desktop ───────────────────────────────────────────────────
        'windows11'         { return 'Windows 11' }
        'windows10'         { return 'Windows 10' }
        'windows9'          { return 'Windows 8.1 / 10' }
        'windows8'          { return 'Windows 8' }
        'windows7'          { return 'Windows 7' }

        # ── VMware / Other ────────────────────────────────────────────────────
        'vmkernel'          { return 'VMware ESXi' }
        'freebsd'           { return 'FreeBSD' }
        'solaris'           { return 'Solaris' }
        'darwin'            { return 'macOS' }
        'other24xlinux'     { return 'Linux (other, 2.4.x)' }
        'other26xlinux'     { return 'Linux (other, 2.6.x)' }
        'otherlinux'        { return 'Linux (other)' }
        'other'             { return 'Other / Unknown' }

        default             { return $GuestId }
    }
}
#endregion

#region ── Helper: reverse-DNS lookup ────────────────────────────────────────
function Resolve-IPtoHostname {
    param([string]$IPAddress)

    if ([string]::IsNullOrWhiteSpace($IPAddress)) { return $null }

    try {
        $entry = [System.Net.Dns]::GetHostEntry($IPAddress)
        return $entry.HostName.Split('.')[0]
    }
    catch {
        return $null
    }
}
#endregion

#region ── Main function ─────────────────────────────────────────────────────
function Get-VMInventory {
<#
.SYNOPSIS
    Collects VM inventory from one or more ESXi/vCenter servers.

.PARAMETER Server
    One or more vCenter / ESXi hostnames or IP addresses to query.

.PARAMETER Credential
    PSCredential for vCenter/ESXi authentication. Prompts if omitted.

.PARAMETER OutputDir
    Directory for the output CSV. Defaults to the current directory.

.PARAMETER PingCount
    ICMP echo requests per VM. Default: 2.

.PARAMETER PassThru
    Returns result objects to the pipeline in addition to writing the CSV.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]] $Server,

        [PSCredential] $Credential,

        [string] $OutputDir = (Get-Location).Path,

        [ValidateRange(1,10)]
        [int] $PingCount = 2,

        [switch] $PassThru
    )

    begin {
        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        if (-not $Credential) {
            $Credential = Get-Credential -Message 'Enter credentials for vCenter/ESXi access'
        }
    }

    process {
        foreach ($srv in $Server) {
            Write-Host "`n[+] Connecting to $srv ..." -ForegroundColor Cyan

            try {
                $viConn = Connect-VIServer -Server $srv -Credential $Credential -ErrorAction Stop
                Write-Host "    Connected as $($viConn.User)" -ForegroundColor Green
            }
            catch {
                Write-Warning "    FAILED to connect to $srv : $_"
                continue
            }

            $vms = Get-VM -Server $viConn
            Write-Host "    Found $($vms.Count) VM(s)" -ForegroundColor Green

            foreach ($vm in $vms) {
                Write-Verbose "  Processing VM: $($vm.Name)"

                $primaryIP = $vm.Guest.IPAddress |
                                 Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } |
                                 Select-Object -First 1

                $rawGuestId   = $vm.ExtensionData.Config.GuestId
                $normalisedOS = Get-NormalisedOS -GuestId $rawGuestId

                $resolvedHost     = Resolve-IPtoHostname -IPAddress $primaryIP
                $dnsMatchesVMName = if ($resolvedHost) {
                    $resolvedHost -ieq $vm.Name
                } else {
                    $false
                }

                $pingResult = if ($primaryIP) {
                    Test-Connection -ComputerName $primaryIP -Count $PingCount -Quiet
                } else {
                    $false
                }

                $allResults.Add([PSCustomObject]@{
                    vCenter          = $srv
                    VMName           = $vm.Name
                    PowerState       = $vm.PowerState
                    PrimaryIP        = if ($primaryIP) { $primaryIP } else { 'N/A' }
                    RawGuestId       = $rawGuestId
                    NormalisedOS     = $normalisedOS
                    ResolvedHostname = if ($resolvedHost) { $resolvedHost } else { 'N/A' }
                    DNSMatchesVMName = $dnsMatchesVMName
                    PingReachable    = $pingResult
                })
            }

            Disconnect-VIServer -Server $viConn -Confirm:$false
            Write-Host "    Disconnected from $srv" -ForegroundColor Gray
        }
    }

    end {
        if ($allResults.Count -eq 0) {
            Write-Warning 'No VM data collected — nothing to export.'
            return
        }

        $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $outputPath = Join-Path $OutputDir "VMInventory_$timestamp.csv"

        $allResults | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

        Write-Host "`n[+] Exported $($allResults.Count) records to:" -ForegroundColor Green
        Write-Host "    $outputPath" -ForegroundColor Yellow

        $allResults |
            Group-Object vCenter |
            ForEach-Object {
                $reachable = ($_.Group | Where-Object PingReachable).Count
                $dnsMiss   = ($_.Group | Where-Object { -not $_.DNSMatchesVMName }).Count
                Write-Host "`n    $($_.Name): $($_.Count) VMs | Reachable: $reachable | DNS mismatches: $dnsMiss"
            }

        if ($PassThru) { $allResults }
    }
}
#endregion

#region ── Script entry point (only runs when executed directly, not dot-sourced)
if ($Server) {
    Get-VMInventory -Server $Server -Credential $Credential `
                    -OutputDir $OutputDir -PingCount $PingCount -PassThru:$PassThru
}
#endregion
