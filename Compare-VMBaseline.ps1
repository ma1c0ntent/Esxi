function Compare-VMBaseline {
<#
.SYNOPSIS
    Compares VM inventory results against a hardware baseline CSV and reports
    matches and deviations.

.DESCRIPTION
    Imports the VM inventory CSV (output of Get-VMInventory) and a hardware
    baseline CSV, then attempts to match each VM by VMName or ResolvedHostname
    against the baseline. Produces a report of matched VMs with any field
    deviations, and a list of VMs that have no baseline entry.

    Note: The baseline may contain non-VM machines. Only VMs present in the
    inventory are evaluated — baseline entries with no matching VM are ignored.

.PARAMETER InventoryPath
    Path to the VM inventory CSV produced by Get-VMInventory.

.PARAMETER BaselinePath
    Path to the hardware baseline CSV.

.PARAMETER BaselineNameField
    Column name in the baseline CSV that holds the hostname to match against.
    Default: 'Hostname'

.PARAMETER OutputDir
    Directory for the output report CSV. Defaults to the current directory.

.PARAMETER PassThru
    Returns result objects to the pipeline in addition to writing the CSV.

.EXAMPLE
    Compare-VMBaseline -InventoryPath .\VMInventory_20260325_120000.csv `
                       -BaselinePath .\HardwareBaseline.csv

.EXAMPLE
    Compare-VMBaseline -InventoryPath .\VMInventory_20260325_120000.csv `
                       -BaselinePath .\HardwareBaseline.csv `
                       -BaselineNameField 'ServerName' `
                       -OutputDir C:\Reports -PassThru |
        Where-Object { $_.Status -eq 'Deviated' }
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string] $InventoryPath,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string] $BaselinePath,

        [string] $BaselineNameField = 'Hostname',

        [string] $OutputDir = (Get-Location).Path,

        [switch] $PassThru
    )

    #region ── Import ─────────────────────────────────────────────────────────
    Write-Host "`n[+] Importing inventory: $InventoryPath" -ForegroundColor Cyan
    $inventory = Import-Csv -Path $InventoryPath

    Write-Host "[+] Importing baseline:  $BaselinePath" -ForegroundColor Cyan
    $baseline  = Import-Csv -Path $BaselinePath

    # Validate that the baseline name field actually exists
    $baselineFields = $baseline[0].PSObject.Properties.Name
    if ($BaselineNameField -notin $baselineFields) {
        throw "Baseline CSV does not contain a column named '$BaselineNameField'. " +
              "Available columns: $($baselineFields -join ', ')"
    }

    Write-Host "    Inventory records : $($inventory.Count)"
    Write-Host "    Baseline records  : $($baseline.Count)"
    #endregion

    #region ── Build baseline lookup (name -> row) ────────────────────────────
    $baselineLookup = @{}
    foreach ($row in $baseline) {
        $key = $row.$BaselineNameField.Trim().ToLower()
        if ($key) { $baselineLookup[$key] = $row }
    }
    #endregion

    #region ── Compare ────────────────────────────────────────────────────────
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($vm in $inventory) {

        # Try VMName first, then ResolvedHostname as fallback
        $matchedBy     = $null
        $baselineEntry = $null

        foreach ($candidate in @($vm.VMName, $vm.ResolvedHostname)) {
            if ([string]::IsNullOrWhiteSpace($candidate) -or $candidate -eq 'N/A') { continue }
            $key = $candidate.Trim().ToLower()
            if ($baselineLookup.ContainsKey($key)) {
                $matchedBy     = $candidate
                $baselineEntry = $baselineLookup[$key]
                break
            }
        }

        if (-not $baselineEntry) {
            $results.Add([PSCustomObject]@{
                VMName           = $vm.VMName
                ResolvedHostname = $vm.ResolvedHostname
                MatchedBy        = 'None'
                Status           = 'NoBaseline'
                DeviatedFields   = 'N/A'
                BaselineDetails  = 'N/A'
                InventoryDetails = "OS=$($vm.NormalisedOS); IP=$($vm.PrimaryIP); Power=$($vm.PowerState)"
            })
            continue
        }

        # Compare every baseline field that also exists in the inventory
        $deviations = [System.Collections.Generic.List[string]]::new()

        foreach ($field in $baselineFields) {
            if ($field -eq $BaselineNameField) { continue }

            if ($vm.PSObject.Properties.Name -contains $field) {
                $baselineVal  = $baselineEntry.$field.Trim()
                $inventoryVal = $vm.$field.Trim()

                if ($baselineVal -ne '' -and $inventoryVal -ine $baselineVal) {
                    $deviations.Add("$field [baseline='$baselineVal' | found='$inventoryVal']")
                }
            }
        }

        $results.Add([PSCustomObject]@{
            VMName           = $vm.VMName
            ResolvedHostname = $vm.ResolvedHostname
            MatchedBy        = $matchedBy
            Status           = if ($deviations.Count -eq 0) { 'Matched' } else { 'Deviated' }
            DeviatedFields   = if ($deviations.Count -gt 0) { $deviations -join ' | ' } else { 'None' }
            BaselineDetails  = ($baselineFields | ForEach-Object { "$_=$($baselineEntry.$_)" }) -join '; '
            InventoryDetails = "OS=$($vm.NormalisedOS); IP=$($vm.PrimaryIP); Power=$($vm.PowerState)"
        })
    }
    #endregion

    #region ── Summary ────────────────────────────────────────────────────────
    $matched  = ($results | Where-Object Status -eq 'Matched').Count
    $deviated = ($results | Where-Object Status -eq 'Deviated').Count
    $noBase   = ($results | Where-Object Status -eq 'NoBaseline').Count

    Write-Host "`n── Comparison Summary ───────────────────────────────" -ForegroundColor Cyan
    Write-Host "    Matched           : $matched"  -ForegroundColor Green
    Write-Host "    Deviated          : $deviated" -ForegroundColor Yellow
    Write-Host "    No baseline entry : $noBase"   -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Cyan
    #endregion

    #region ── Export ─────────────────────────────────────────────────────────
    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputPath = Join-Path $OutputDir "VMBaselineReport_$timestamp.csv"

    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n[+] Report written to:" -ForegroundColor Green
    Write-Host "    $outputPath"          -ForegroundColor Yellow
    #endregion

    if ($PassThru) { $results }
}
