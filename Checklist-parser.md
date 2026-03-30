You just need to pull two more things from the CKLB structure — the asset hostname and the `CCI_REF` attribute from `stig_data`. Here's the updated approach:

## Where the Data Lives in a CKLB

```
ckl
 └── stigs[]
      ├── stig_info        <- STIG metadata
      ├── target_data[]    <- asset info (hostname lives here)
      └── vuln_data[]
           └── stig_data[] <- vuln attributes including CCI_REF
```

The hostname is at the **stig level** (not vuln level), so you grab it once per stig block and carry it into the vuln loop.

---

## Updated Script

```powershell
$cklbFiles = Get-ChildItem -Path ".\checklists" -Filter "*.cklb"

# Key: Vuln_Num
# Value: hashtable with Count, Computers (list), CCIs (list)
$vulnMap = @{}

foreach ($file in $cklbFiles) {
    $ckl = Get-Content $file.FullName -Raw | ConvertFrom-Json

    foreach ($stig in $ckl.stigs) {

        # Pull hostname from target_data for this stig block
        $hostname = $stig.target_data |
            Where-Object { $_.name -eq 'host_name' } |
            Select-Object -ExpandProperty value

        if (-not $hostname) { $hostname = $file.Name }  # fallback to filename

        foreach ($vuln in $stig.vuln_data) {

            # Flatten stig_data into a lookup hashtable
            $attrs = @{}
            foreach ($entry in $vuln.stig_data) {
                $attrs[$entry.vuln_attribute] = $entry.attribute_data
            }

            $vulnNum = $attrs['Vuln_Num']
            if (-not $vulnNum) { continue }

            # CCI_REF can be multi-value (e.g. "CCI-000054 CCI-000381")
            # split so each CCI is a discrete entry
            $ccis = $attrs['CCI_REF'] -split '\s+' |
                Where-Object { $_ -ne '' }

            # Initialize entry if first time seeing this Vuln_Num
            if (-not $vulnMap.ContainsKey($vulnNum)) {
                $vulnMap[$vulnNum] = @{
                    Count     = 0
                    Computers = [System.Collections.Generic.List[string]]::new()
                    CCIs      = [System.Collections.Generic.HashSet[string]]::new()  # deduplicated
                    Rule_Title = $attrs['Rule_Title']
                    Severity   = $attrs['Severity']
                }
            }

            $vulnMap[$vulnNum]['Count']++

            # Only add hostname if not already listed for this vuln
            if (-not $vulnMap[$vulnNum]['Computers'].Contains($hostname)) {
                $vulnMap[$vulnNum]['Computers'].Add($hostname)
            }

            # HashSet handles CCI deduplication automatically
            foreach ($cci in $ccis) {
                $vulnMap[$vulnNum]['CCIs'].Add($cci) | Out-Null
            }
        }
    }
}
```

---

## Output — Console + CSV

```powershell
$results = foreach ($vulnNum in $vulnMap.Keys) {
    $entry = $vulnMap[$vulnNum]

    [PSCustomObject]@{
        Vuln_Num       = $vulnNum
        Severity       = $entry['Severity']
        Rule_Title     = $entry['Rule_Title']
        ChecklistCount = $entry['Count']
        Computers      = $entry['Computers'] -join '; '
        CCIs           = $entry['CCIs'] -join '; '
    }
}

# Console
$results | Sort-Object ChecklistCount -Descending | Format-Table -AutoSize

# CSV
$results | Sort-Object ChecklistCount -Descending |
    Export-Csv ".\VulnID_Summary.csv" -NoTypeInformation -Encoding UTF8
```

---

## Key Design Decisions

**`HashSet` for CCIs instead of a List** — since the same CCI will appear on every checklist that has the vuln, a `HashSet` deduplicates automatically. `CCI-000054` appearing across 20 checklists still only shows up once in the output.

**Computers uses `.Contains()` check** — same reason, you want one entry per unique hostname, not 20 duplicates of the same machine.

**CCI split on whitespace** — some CKLB files store multiple CCIs in a single `CCI_REF` field as a space-separated string (`"CCI-000054 CCI-000381"`), so splitting ensures each one is tracked discretely.

The CSV output will look like:

```
Vuln_Num   | Severity | ChecklistCount | Computers                  | CCIs
V-256385   | high     | 20             | esxi01; esxi02; esxi03; ... | CCI-000054; CCI-000381
V-256386   | medium   | 50             | esxi01; esxi02; ...         | CCI-000213
```
