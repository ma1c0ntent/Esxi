```powershell
function Compare-CKLBChecklist {
    <#
    .SYNOPSIS
        Compares two CKLB checklists and reports added/removed Vuln_Nums and rule title/description changes.

    .DESCRIPTION
        Loads two CKLB (JSON) files, builds hashtables keyed by Vuln_Num, and produces three
        diff categories:
          - Added    : Vuln_Nums present in NewPath but not OldPath (new rules in V2R3)
          - Removed  : Vuln_Nums present in OldPath but not NewPath (retired rules from V2R2)
          - Changed  : Rule_Title or Vuln_Discuss differ between versions

        Results are printed to console and exported to CSV.

    .PARAMETER OldPath
        Path to the older CKLB file (e.g. V2R2).

    .PARAMETER NewPath
        Path to the newer CKLB file (e.g. V2R3).

    .PARAMETER OutputDir
        Directory to write CSV exports. Defaults to the current directory.

    .EXAMPLE
        Compare-CKLBChecklist -OldPath ".\V2R2.cklb" -NewPath ".\V2R3.cklb" -OutputDir ".\diffs"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$OldPath,
        [Parameter(Mandatory)][string]$NewPath,
        [string]$OutputDir = "."
    )

    #region --- Helpers ---

    # Attributes to extract from stig_data for enriched output
    $enrichAttrs = @(
        'Rule_ID', 'Rule_Ver', 'Rule_Title',
        'Vuln_Discuss', 'Severity', 'IA_Controls',
        'Check_Content', 'Fix_Text', 'CCI_REF'
    )

    function Get-VulnHashtable {
        param([string]$FilePath)

        $label = Split-Path $FilePath -Leaf

        if (-not (Test-Path $FilePath)) {
            throw "CKLB file not found: $FilePath"
        }

        Write-Verbose "Parsing $label..."
        $ckl = Get-Content $FilePath -Raw | ConvertFrom-Json

        $ht = @{}

        foreach ($stig in $ckl.stigs) {
            foreach ($vuln in $stig.vuln_data) {

                # Flatten stig_data array into a simple hashtable
                $attrs = @{}
                foreach ($entry in $vuln.stig_data) {
                    $attrs[$entry.vuln_attribute] = $entry.attribute_data
                }

                $vulnNum = $attrs['Vuln_Num']
                if (-not $vulnNum) {
                    Write-Warning "Skipping entry with no Vuln_Num in $label"
                    continue
                }

                $ht[$vulnNum] = [PSCustomObject]@{
                    Vuln_Num   = $vulnNum
                    Status     = $vuln.status
                    Attrs      = $attrs     # full stig_data map for enrichment
                    Raw        = $vuln      # keep raw object if needed
                }
            }
        }

        Write-Verbose "  -> $($ht.Count) vulnerabilities indexed from $label"
        return $ht
    }

    function Expand-VulnDetail {
        # Builds a flat PSCustomObject from a vuln entry for CSV/console output
        param(
            [PSCustomObject]$VulnEntry,
            [string]$ChangeType,
            [string]$ChangeDetail = ""
        )

        $obj = [ordered]@{
            Change_Type   = $ChangeType
            Change_Detail = $ChangeDetail
            Vuln_Num      = $VulnEntry.Vuln_Num
            Status        = $VulnEntry.Status
        }

        foreach ($attr in $enrichAttrs) {
            $obj[$attr] = $VulnEntry.Attrs[$attr]
        }

        return [PSCustomObject]$obj
    }

    #endregion

    #region --- Load & Index ---

    $oldLabel = Split-Path $OldPath -Leaf
    $newLabel = Split-Path $NewPath -Leaf

    $htOld = Get-VulnHashtable -FilePath $OldPath
    $htNew = Get-VulnHashtable -FilePath $NewPath

    #endregion

    #region --- Diff Logic ---

    $added   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $removed = [System.Collections.Generic.List[PSCustomObject]]::new()
    $changed = [System.Collections.Generic.List[PSCustomObject]]::new()

    $allKeys = ($htOld.Keys + $htNew.Keys) | Sort-Object -Unique

    foreach ($key in $allKeys) {

        $inOld = $htOld.ContainsKey($key)
        $inNew = $htNew.ContainsKey($key)

        if ($inNew -and -not $inOld) {
            # --- ADDED in new version ---
            $added.Add(
                (Expand-VulnDetail -VulnEntry $htNew[$key] -ChangeType 'ADDED' `
                    -ChangeDetail "Present in $newLabel, not in $oldLabel")
            )

        } elseif ($inOld -and -not $inNew) {
            # --- REMOVED from old version ---
            $removed.Add(
                (Expand-VulnDetail -VulnEntry $htOld[$key] -ChangeType 'REMOVED' `
                    -ChangeDetail "Present in $oldLabel, not in $newLabel")
            )

        } else {
            # --- EXISTS IN BOTH: check Rule_Title and Vuln_Discuss ---
            $titleOld   = $htOld[$key].Attrs['Rule_Title']
            $titleNew   = $htNew[$key].Attrs['Rule_Title']
            $discussOld = $htOld[$key].Attrs['Vuln_Discuss']
            $discussNew = $htNew[$key].Attrs['Vuln_Discuss']

            $titleChanged   = $titleOld   -ne $titleNew
            $discussChanged = $discussOld -ne $discussNew

            if ($titleChanged -or $discussChanged) {
                $detail = @()
                if ($titleChanged)   { $detail += 'Rule_Title' }
                if ($discussChanged) { $detail += 'Vuln_Discuss' }

                # Emit one row per version so diffs are side-by-side in the CSV
                $changed.Add(
                    (Expand-VulnDetail -VulnEntry $htOld[$key] `
                        -ChangeType 'CHANGED' `
                        -ChangeDetail "[$($detail -join ', ')] changed | VERSION: $oldLabel")
                )
                $changed.Add(
                    (Expand-VulnDetail -VulnEntry $htNew[$key] `
                        -ChangeType 'CHANGED' `
                        -ChangeDetail "[$($detail -join ', ')] changed | VERSION: $newLabel")
                )
            }
        }
    }

    #endregion

    #region --- Console Output ---

    $consoleProps = @('Change_Type','Vuln_Num','Rule_Ver','Severity','Rule_Title','Change_Detail')

    Write-Host "`n===== ADDED in $newLabel ($($added.Count) rules) =====" -ForegroundColor Green
    if ($added.Count -gt 0) {
        $added | Format-Table $consoleProps -AutoSize -Wrap
    } else {
        Write-Host "  None`n"
    }

    Write-Host "`n===== REMOVED from $oldLabel ($($removed.Count) rules) =====" -ForegroundColor Red
    if ($removed.Count -gt 0) {
        $removed | Format-Table $consoleProps -AutoSize -Wrap
    } else {
        Write-Host "  None`n"
    }

    Write-Host "`n===== CHANGED Rule_Title / Vuln_Discuss ($($changed.Count / 2) rules) =====" -ForegroundColor Yellow
    if ($changed.Count -gt 0) {
        $changed | Format-Table $consoleProps -AutoSize -Wrap
    } else {
        Write-Host "  None`n"
    }

    #endregion

    #region --- CSV Export ---

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $base      = "$OutputDir\CKLB_Diff_${timestamp}"

    $addedCsv   = "${base}_ADDED.csv"
    $removedCsv = "${base}_REMOVED.csv"
    $changedCsv = "${base}_CHANGED.csv"

    $added   | Export-Csv $addedCsv   -NoTypeInformation -Encoding UTF8
    $removed | Export-Csv $removedCsv -NoTypeInformation -Encoding UTF8
    $changed | Export-Csv $changedCsv -NoTypeInformation -Encoding UTF8

    Write-Host "`n===== CSV Exports =====" -ForegroundColor Cyan
    Write-Host "  Added   -> $addedCsv"
    Write-Host "  Removed -> $removedCsv"
    Write-Host "  Changed -> $changedCsv`n"

    #endregion

    #region --- Summary ---

    Write-Host "===== Summary =====" -ForegroundColor Cyan
    Write-Host "  Added   (new in $newLabel)       : $($added.Count)"
    Write-Host "  Removed (retired from $oldLabel) : $($removed.Count)"
    Write-Host "  Changed (title/discuss drift)    : $($changed.Count / 2)"

    #endregion

    # Return all results as a single object for pipeline use
    return [PSCustomObject]@{
        Added   = $added
        Removed = $removed
        Changed = $changed
    }
}
```

---

**Usage:**

```powershell
# Basic
Compare-CKLBChecklist -OldPath ".\ESXi_V2R2.cklb" -NewPath ".\ESXi_V2R3.cklb"

# Custom output dir + verbose parsing info
Compare-CKLBChecklist -OldPath ".\ESXi_V2R2.cklb" -NewPath ".\ESXi_V2R3.cklb" `
    -OutputDir ".\diffs" -Verbose

# Capture for further pipeline work
$diff = Compare-CKLBChecklist -OldPath ".\ESXi_V2R2.cklb" -NewPath ".\ESXi_V2R3.cklb"
$diff.Added | Where-Object { $_.Severity -eq 'high' }
```

---

**Key design decisions worth noting:**

- **CHANGED rows are emitted as pairs** — one row labeled `VERSION: V2R2` and one `VERSION: V2R3` — so you can open the CSV and visually compare the old and new text side-by-side without any pivot gymnastics.
- **`$enrichAttrs`** at the top of the function is easy to extend — if you later want `IA_Controls`, `Fix_Text`, or `CCI_REF` in your output, they're already being pulled, just add them to `$consoleProps` to surface them on screen.
- The function **returns the diff object**, so if you're running this inside a larger pipeline (e.g. feeding results into your ESXiManScan workflow), you can consume `$diff.Added`, `$diff.Removed`, and `$diff.Changed` directly without re-parsing.
