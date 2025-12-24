param(
    [string]$InputPath = "",
    [string]$OutDir = "",
    [string]$BaselinePath = "",
    [switch]$ParseEvtx,
    [int]$MaxFindingsPerSource = 200,
    [int]$MaxTableRows = 200,
    [switch]$AutoExtractZip = $true,
    [switch]$Interactive = $true
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
try { $OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Meta = $null

function NewDir([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return }
    if (-not (Test-Path -LiteralPath $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
}

function Get-NowIso { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }

function Get-NowStamp { (Get-Date).ToString('yyyyMMdd_HHmmss') }

function Get-DesktopPath {
    return [Environment]::GetFolderPath('Desktop')
}

function Normalize-Whitespace([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    return ($s -replace '\s+', ' ').Trim()
}

function Read-Lines([string]$Path, [int]$MaxLines) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        $lines.Add($line) | Out-Null
        $i++
        if ($MaxLines -gt 0 -and $i -ge $MaxLines) { break }
    }
    return $lines.ToArray()
}

function Get-FileText([string]$Path, [int]$MaxChars) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try {
        $t = [System.IO.File]::ReadAllText($Path)
        if ($MaxChars -gt 0 -and $t.Length -gt $MaxChars) { return $t.Substring(0, $MaxChars) }
        return $t
    } catch {
        return ''
    }
}

function Add-Finding {
    param(
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$EvidencePath,
        [string]$Evidence,
        [string]$Recommendation
    )

    $rank = 0
    switch ($Severity) {
        'Critical' { $rank = 4 }
        'High' { $rank = 3 }
        'Medium' { $rank = 2 }
        'Low' { $rank = 1 }
        default { $rank = 0 }
    }

    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        SeverityRank = $rank
        Category = $Category
        Title = $Title
        EvidencePath = $EvidencePath
        Evidence = $Evidence
        Recommendation = $Recommendation
    }) | Out-Null
}

function Invoke-Safely {
    param([string]$Name, [scriptblock]$Block)
    try {
        & $Block
    } catch {
        Add-Finding -Severity 'Low' -Category 'Analyzer' -Title ("Analyzer error: " + $Name) -EvidencePath '' -Evidence (Normalize-Whitespace $_.Exception.Message) -Recommendation 'Fix input corruption or permissions, then re-run analyzer.'
    }
}

function Get-FindingsSorted {
    return ($script:Findings | Sort-Object -Property @{Expression='SeverityRank';Descending=$true}, @{Expression='Category';Descending=$false}, @{Expression='Title';Descending=$false})
}

function Resolve-CaseRoot {
    param([string]$Path, [switch]$AutoExtract)

    if (Test-Path -LiteralPath $Path -PathType Container) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $ext = ([System.IO.Path]::GetExtension($Path)).ToLowerInvariant()
        if ($ext -eq '.zip' -and $AutoExtract) {
            $base = Join-Path ([System.IO.Path]::GetTempPath()) ('ikarus_case_' + [guid]::NewGuid().ToString())
            NewDir $base
            Expand-Archive -LiteralPath $Path -DestinationPath $base -Force
            $candidates = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue
            if ($candidates -and $candidates.Count -eq 1) { return $candidates[0].FullName }
            return $base
        }
        throw 'InputPath is a file, but not a zip. Provide a folder path or a zip.'
    }

    throw 'InputPath not found. Provide a valid case folder path or zip.'
}

function Get-CaseMeta {
    param([string]$CaseRoot)

    $meta = [ordered]@{
        CaseRoot = $CaseRoot
        RunInfoPath = (Join-Path $CaseRoot 'meta\run_info.txt')
        TranscriptPath = (Join-Path $CaseRoot 'meta\transcript.txt')
        ToolsInventoryPath = (Join-Path $CaseRoot 'meta\tools_inventory.csv')
        ShaManifestPath = (Join-Path $CaseRoot 'meta\sha256_manifest.csv')
        IOCSummaryPath = (Join-Path $CaseRoot 'meta\ioc_summary.txt')
        Hostname = ''
        CollectedAt = ''
        Mode = ''
        TimeframeDays = ''
        ToolsPolicy = ''
        ToolsAvailable = ''
    }

    if (Test-Path -LiteralPath $meta.RunInfoPath -PathType Leaf) {
        foreach ($line in [System.IO.File]::ReadLines($meta.RunInfoPath)) {
            if ($line -match '^\s*Computer:\s*(.+)\s*$') { $meta.Hostname = $Matches[1].Trim(); continue }
            if ($line -match '^\s*Collection Time:\s*(.+)\s*$') { $meta.CollectedAt = $Matches[1].Trim(); continue }
            if ($line -match '^\s*Mode:\s*(.+)\s*$') { $meta.Mode = $Matches[1].Trim(); continue }
            if ($line -match '^\s*Timeframe:\s*(\d+)\s*days\s*$') { $meta.TimeframeDays = $Matches[1].Trim(); continue }
            if ($line -match '^\s*Tools Policy:\s*(.+)\s*$') { $meta.ToolsPolicy = $Matches[1].Trim(); continue }
            if ($line -match '^\s*Tools Available:\s*(.+)\s*$') { $meta.ToolsAvailable = $Matches[1].Trim(); continue }
        }
    }

    return [pscustomobject]$meta
}

function Pick-CaseFromCollections {
    param([string]$CollectionsDir)

    if (-not (Test-Path -LiteralPath $CollectionsDir -PathType Container)) { throw 'Collections directory not found.' }

    $cases = Get-ChildItem -LiteralPath $CollectionsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'windows_Forensic_*' -or $_.Name -like 'windows_Forensic_*_*' } |
        Sort-Object LastWriteTime -Descending

    if (-not $cases -or $cases.Count -eq 0) { throw 'No case folders found under windows_Forensic_Collections.' }

    Write-Host ''
    Write-Host 'Detected case folders:'
    Write-Host '----------------------------------------'
    $i = 0
    foreach ($c in ($cases | Select-Object -First 25)) {
        $i++
        Write-Host ("[{0}] {1}  ({2})" -f $i, $c.FullName, $c.LastWriteTime)
    }
    Write-Host '----------------------------------------'
    $sel = Read-Host 'Select a case number (Enter = 1)'
    if ([string]::IsNullOrWhiteSpace($sel)) { return $cases[0].FullName }
    $n = 0
    if (-not [int]::TryParse($sel, [ref]$n)) { return $cases[0].FullName }
    if ($n -lt 1) { $n = 1 }
    if ($n -gt $cases.Count) { $n = $cases.Count }
    return $cases[$n-1].FullName
}

function Find-RegexHitsInFile {
    param([string]$Path, [string[]]$Regexes, [int]$MaxHits)

    $hits = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $hits }

    $lineNo = 0
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        $lineNo++
        foreach ($rx in $Regexes) {
            if ($line -match $rx) {
                $hits.Add([pscustomobject]@{ LineNo = $lineNo; Line = $line; Pattern = $rx }) | Out-Null
                break
            }
        }
        if ($MaxHits -gt 0 -and $hits.Count -ge $MaxHits) { break }
    }
    return $hits
}

function Get-SuspiciousCommandRegexes {
    return @(
        '(?i)\b(powershell|pwsh)\b.*\s(-enc|-encodedcommand)\b',
        '(?i)\b(powershell|pwsh)\b.*\s(-w\s+hidden|-windowstyle\s+hidden)\b',
        '(?i)\bIEX\b|\bInvoke-Expression\b',
        '(?i)\bDownloadString\b|\bWebClient\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b',
        '(?i)\bbitsadmin\b|\bcertutil\b\s+.*-urlcache\b|\bcurl\b|\bwget\b',
        '(?i)\bmshta\b|\brundll32\b|\bregsvr32\b|\bwscript\b|\bcscript\b',
        '(?i)\bschtasks\b\s+/(create|change|run)\b',
        '(?i)\bwmic\b\s+process\b\s+call\b\s+create\b',
        '(?i)\bnet\b\s+(user|localgroup|use|share)\b',
        '(?i)\b(nltest|dsquery|dsget)\b',
        '(?i)\bprocdump\b|\brubeus\b|\bmimikatz\b|\bsecretsdump\b|\bbloodhound\b|\bimpacket\b|\bcobalt\b|\bsliver\b'
    )
}

function Get-SuspiciousPathRegexes {
    return @(
        '(?i)\\Users\\Public\\',
        '(?i)\\ProgramData\\',
        '(?i)\\Windows\\Temp\\',
        '(?i)\\Temp\\',
        '(?i)\\AppData\\(Roaming|Local)\\',
        '(?i)\\PerfLogs\\'
    )
}

function Get-SuspiciousExtensionsRegex {
    return '(?i)\.(exe|dll|sys|ps1|vbs|bat|cmd|js|jse|hta|lnk|msi|msp|iso|img|vhd|vhdx|zip|7z|rar)\b'
}

function Get-CsvRowsSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    try { return (Import-Csv -LiteralPath $Path) } catch { return @() }
}

function Find-FirstCaseFile {
    param(
        [string]$CaseRoot,
        [string[]]$RelativeCandidates,
        [string[]]$LeafPatterns,
        [int]$MaxSearch = 1
    )

    foreach ($r in $RelativeCandidates) {
        if ([string]::IsNullOrWhiteSpace($r)) { continue }
        $p = Join-Path $CaseRoot $r
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }

    foreach ($pat in $LeafPatterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        $found = Get-ChildItem -LiteralPath $CaseRoot -Recurse -File -Filter $pat -ErrorAction SilentlyContinue | Select-Object -First $MaxSearch
        if ($found) { return $found[0].FullName }
    }

    return $null
}

function Find-CaseFiles {
    param(
        [string]$CaseRoot,
        [string[]]$RelativeCandidates,
        [string[]]$LeafPatterns,
        [int]$MaxSearch = 10
    )

    $list = New-Object System.Collections.Generic.List[string]

    foreach ($r in $RelativeCandidates) {
        if ([string]::IsNullOrWhiteSpace($r)) { continue }
        $p = Join-Path $CaseRoot $r
        if (Test-Path -LiteralPath $p -PathType Leaf) { $list.Add($p) | Out-Null }
    }

    foreach ($pat in $LeafPatterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        $found = Get-ChildItem -LiteralPath $CaseRoot -Recurse -File -Filter $pat -ErrorAction SilentlyContinue | Select-Object -First $MaxSearch
        foreach ($f in $found) { $list.Add($f.FullName) | Out-Null }
    }

    return @($list | Select-Object -Unique)
}

function Analyze-ToolsInventory {
    param([pscustomobject]$Meta)

    if (-not (Test-Path -LiteralPath $Meta.ToolsInventoryPath -PathType Leaf)) { return }
    try {
        $rows = Import-Csv -LiteralPath $Meta.ToolsInventoryPath
        $missing = @($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.ResolvedPath) })
        if ($missing.Count -gt 0) {
            Add-Finding -Severity 'Low' -Category 'Coverage' -Title ('Missing third-party tools: ' + (($missing.Tool | Select-Object -Unique) -join ', ')) -EvidencePath $Meta.ToolsInventoryPath -Evidence ('Missing count: ' + $missing.Count) -Recommendation 'Stage missing tools in ToolsDir or enable AutoDownloadTools for full coverage.'
        }
    } catch { }
}

function Analyze-RunInfoBasics {
    param([pscustomobject]$Meta)

    if (-not (Test-Path -LiteralPath $Meta.RunInfoPath -PathType Leaf)) { return }
    $t = Get-FileText -Path $Meta.RunInfoPath -MaxChars 200000

    if ($t -match '(?i)OfflineOnly:\s*True' -and $t -match '(?i)AutoDownloadTools:\s*True') {
        Add-Finding -Severity 'Info' -Category 'Runtime' -Title 'Both OfflineOnly and AutoDownloadTools appear enabled' -EvidencePath $Meta.RunInfoPath -Evidence 'Check run_info toggle values' -Recommendation 'Confirm intended tools policy selection during execution.'
    }

    if ($t -match '(?i)IncludeMemoryDump:\s*True') {
        Add-Finding -Severity 'Info' -Category 'Runtime' -Title 'Memory acquisition was requested' -EvidencePath $Meta.RunInfoPath -Evidence 'IncludeMemoryDump: True' -Recommendation 'If a memory image exists under memory/, analyze volatile artifacts on a forensic workstation.'
    }
}

function Analyze-DefenderExclusions {
    param([string]$CaseRoot)

    $p1 = Join-Path $CaseRoot 'security\defender_exclusions.txt'
    $p2 = Join-Path $CaseRoot 'siem\DefenderExclusions.csv'
    $values = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $p2 -PathType Leaf) {
        try {
            $rows = Import-Csv -LiteralPath $p2
            foreach ($r in $rows) {
                $v = ''
                try { $v = [string]$r.Value } catch { $v = '' }
                $t = ''
                try { $t = [string]$r.Type } catch { $t = '' }
                if (-not [string]::IsNullOrWhiteSpace($v)) { $values.Add((Normalize-Whitespace ($t + ': ' + $v))) | Out-Null }
            }
        } catch { }
    } elseif (Test-Path -LiteralPath $p1 -PathType Leaf) {
        $text = Get-FileText -Path $p1 -MaxChars 600000
        if ($text -match '(?i)ExclusionPath:\s*[\r\n]+([^\r\n]+)') { $values.Add(('ExclusionPath: ' + $Matches[1].Trim())) | Out-Null }
        if ($text -match '(?i)ExclusionProcess:\s*[\r\n]+([^\r\n]+)') { $values.Add(('ExclusionProcess: ' + $Matches[1].Trim())) | Out-Null }
        if ($text -match '(?i)ExclusionExtension:\s*[\r\n]+([^\r\n]+)') { $values.Add(('ExclusionExtension: ' + $Matches[1].Trim())) | Out-Null }
    }

    $uniq = @($values | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -Unique)
    if ($uniq.Count -gt 0) {
        $joined = $uniq -join ' | '
        $ep = $p1
        if (Test-Path -LiteralPath $p2 -PathType Leaf) { $ep = $p2 }
        Add-Finding -Severity 'High' -Category 'Security Controls' -Title 'Windows Defender exclusions detected' -EvidencePath $ep -Evidence $joined -Recommendation 'Review exclusions for legitimacy. Broad exclusions are commonly abused to evade defenses.'
    }
}

function Analyze-UAC {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'security\uac_settings.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
    $t = Get-FileText -Path $p -MaxChars 200000
    if ($t -match '(?i)EnableLUA\s+REG_DWORD\s+0x0') {
        Add-Finding -Severity 'Medium' -Category 'Security Controls' -Title 'UAC appears disabled (EnableLUA=0)' -EvidencePath $p -Evidence 'EnableLUA=0' -Recommendation 'Confirm if UAC is intentionally disabled. Disabling UAC increases abuse surface for privilege escalation.'
    }
}

function Analyze-Firewall {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'security\firewall_status.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
    $t = Get-FileText -Path $p -MaxChars 600000

    $disabled = New-Object System.Collections.Generic.List[string]
    if ($t -match '(?i)Domain Profile Settings[\s\S]*?State\s+OFF') { $disabled.Add('Domain') | Out-Null }
    if ($t -match '(?i)Private Profile Settings[\s\S]*?State\s+OFF') { $disabled.Add('Private') | Out-Null }
    if ($t -match '(?i)Public Profile Settings[\s\S]*?State\s+OFF') { $disabled.Add('Public') | Out-Null }

    if ($disabled.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Security Controls' -Title ('Windows Firewall disabled: ' + (($disabled | Select-Object -Unique) -join ', ')) -EvidencePath $p -Evidence ('Profiles OFF: ' + (($disabled | Select-Object -Unique) -join ', ')) -Recommendation 'Validate firewall policy compliance and investigate any unauthorized changes.'
    }
}

function Analyze-AuditPolicy {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'security\auditpol.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 12000
    $weak = New-Object System.Collections.Generic.List[string]

    foreach ($l in $lines) {
        if ($l -match '(?i)Logon/Logoff|Account Logon|Account Management|Detailed Tracking') {
            if ($l -match '(?i)\bNo Auditing\b') { $weak.Add((Normalize-Whitespace $l)) | Out-Null }
        }
    }

    if ($weak.Count -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Logging' -Title 'Potentially weak audit policy settings detected' -EvidencePath $p -Evidence (($weak | Select-Object -First 20) -join ' ; ') -Recommendation 'Ensure key audit categories (logon, account management, process creation) are enabled per baseline policy.'
    }
}

function Analyze-WMI-Subscriptions {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'persistence\wmi_subscriptions.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $t = Get-FileText -Path $p -MaxChars 800000
    if ([string]::IsNullOrWhiteSpace($t)) { return }

    $rxCmd = Get-SuspiciousCommandRegexes
    $susp = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rxCmd) {
        if ($t -match $r) {
            $susp.Add($r) | Out-Null
            if ($susp.Count -ge 8) { break }
        }
    }

    if ($t -match '(?i)__EventFilter' -and $t -match '(?i)CommandLineEventConsumer') {
        $sev = 'Medium'
        if ($susp.Count -gt 0) { $sev = 'High' }
        Add-Finding -Severity $sev -Category 'Persistence' -Title 'WMI event subscription artifacts present' -EvidencePath $p -Evidence ('WMI subscription objects present. Indicators: ' + (($susp | Select-Object -Unique) -join ', ')) -Recommendation 'WMI permanent event subscriptions are high-value persistence. Review consumers, filters, and command lines for legitimacy.'
    }
}

function Analyze-RunKeysAndWinlogon {
    param([string]$CaseRoot)

    $p1 = Join-Path $CaseRoot 'persistence\run_hklm.txt'
    $p2 = Join-Path $CaseRoot 'persistence\run_hkcu.txt'
    $p3 = Join-Path $CaseRoot 'persistence\winlogon_keys.txt'

    $rxCmd = Get-SuspiciousCommandRegexes
    $rxExt = Get-SuspiciousExtensionsRegex
    $rxPath = Get-SuspiciousPathRegexes

    foreach ($p in @($p1,$p2,$p3)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }

        $hits = Find-RegexHitsInFile -Path $p -Regexes $rxCmd -MaxHits $MaxFindingsPerSource
        if ($hits.Count -gt 0) {
            $ev = ($hits | Select-Object -First 12 | ForEach-Object { ('L' + $_.LineNo + ':' + (Normalize-Whitespace $_.Line)) }) -join ' | '
            Add-Finding -Severity 'High' -Category 'Persistence' -Title ('Suspicious command patterns in persistence keys (' + (Split-Path -Leaf $p) + ')') -EvidencePath $p -Evidence $ev -Recommendation 'Review referenced binaries/scripts and validate registry autoruns against known-good baselines.'
            continue
        }

        $lines = Read-Lines -Path $p -MaxLines 20000
        $s = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            if ($l -match $rxExt) {
                foreach ($r in $rxPath) {
                    if ($l -match $r) { $s.Add((Normalize-Whitespace $l)) | Out-Null; break }
                }
            }
            if ($s.Count -ge 20) { break }
        }

        if ($s.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Persistence' -Title ('Executable/script references in high-risk locations within ' + (Split-Path -Leaf $p)) -EvidencePath $p -Evidence (($s | Select-Object -First 20) -join ' ; ') -Recommendation 'Validate autorun entries pointing to AppData/Temp/ProgramData/Public. Investigate unknown publishers and recent write times.'
        }
    }
}

function Analyze-ScheduledTasks {
    param([string]$CaseRoot)

    $p1 = Join-Path $CaseRoot 'process\scheduledtasks_list_v.txt'
    $p2 = Join-Path $CaseRoot 'persistence\scheduled_tasks_summary.txt'
    $p = $null

    if (Test-Path -LiteralPath $p1 -PathType Leaf) { $p = $p1 }
    elseif (Test-Path -LiteralPath $p2 -PathType Leaf) { $p = $p2 }
    else { return }

    $rxCmd = Get-SuspiciousCommandRegexes
    $hits = Find-RegexHitsInFile -Path $p -Regexes $rxCmd -MaxHits $MaxFindingsPerSource
    if ($hits.Count -gt 0) {
        $ev = ($hits | Select-Object -First 14 | ForEach-Object { ('L' + $_.LineNo + ':' + (Normalize-Whitespace $_.Line)) }) -join ' | '
        Add-Finding -Severity 'High' -Category 'Persistence' -Title 'Suspicious command patterns inside scheduled tasks output' -EvidencePath $p -Evidence $ev -Recommendation 'Review task actions, triggers, authors, and creation times. Confirm if tasks map to approved software.'
        return
    }

    $lines = Read-Lines -Path $p -MaxLines 40000
    $odd = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match '(?i)\\Users\\Public\\|\\ProgramData\\|\\Windows\\Temp\\|\\AppData\\') {
            $odd.Add((Normalize-Whitespace $l)) | Out-Null
        }
        if ($odd.Count -ge 25) { break }
    }

    if ($odd.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Persistence' -Title 'Scheduled task references to high-risk file system locations' -EvidencePath $p -Evidence (($odd | Select-Object -First 25) -join ' ; ') -Recommendation 'Validate tasks executing from user-writable directories. Correlate with recent file drops and process creation telemetry.'
    }
}

function Analyze-Services {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'process\services_detailed.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 90000
    $rxExt = Get-SuspiciousExtensionsRegex
    $rxPath = Get-SuspiciousPathRegexes

    $sus = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match $rxExt) {
            foreach ($r in $rxPath) {
                if ($l -match $r) { $sus.Add((Normalize-Whitespace $l)) | Out-Null; break }
            }
        }
        if ($sus.Count -ge 35) { break }
    }

    if ($sus.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Persistence' -Title 'Service binary paths point to high-risk locations' -EvidencePath $p -Evidence (($sus | Select-Object -First 30) -join ' ; ') -Recommendation 'Investigate services running binaries from user-writable paths. Validate signer, install time, and service creation telemetry.'
    }
}

function Analyze-AutorunsCsv {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'third_party_analysis\autoruns_output.csv'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $rows = @()
    try { $rows = Import-Csv -LiteralPath $p } catch { $rows = @() }
    if (-not $rows -or $rows.Count -eq 0) { return }

    $rxPath = Get-SuspiciousPathRegexes
    $rxExt = Get-SuspiciousExtensionsRegex
    $rxCmd = Get-SuspiciousCommandRegexes

    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        $img = ''
        $cmd = ''
        $loc = ''
        try { $img = [string]$r.ImagePath } catch { $img = '' }
        try { $cmd = [string]$r.LaunchString } catch { $cmd = '' }
        try { $loc = [string]$r.Location } catch { $loc = '' }

        $s = ($img + ' ' + $cmd + ' ' + $loc)
        if ([string]::IsNullOrWhiteSpace($s)) { continue }

        $flag = $false
        foreach ($x in $rxCmd) { if ($s -match $x) { $flag = $true; break } }

        if (-not $flag -and ($s -match $rxExt)) {
            foreach ($p0 in $rxPath) { if ($s -match $p0) { $flag = $true; break } }
        }

        if ($flag) {
            $line = Normalize-Whitespace ($loc + ' | ' + $img + ' | ' + $cmd)
            if ($line.Length -gt 420) { $line = $line.Substring(0, 420) + '...' }
            $hits.Add($line) | Out-Null
        }

        if ($hits.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($hits.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Persistence' -Title 'Autoruns: suspicious entries (high-risk paths / commands)' -EvidencePath $p -Evidence (($hits | Select-Object -First 20) -join ' ; ') -Recommendation 'Review Autoruns entries for unsigned or recently created binaries. Validate publisher and compare with baseline autoruns.'
    }
}

function Analyze-SigcheckOutput {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'third_party_analysis\sigcheck_output.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 120000
    $sus = New-Object System.Collections.Generic.List[string]

    foreach ($l in $lines) {
        if ($l -match '(?i)\bUnsigned\b|\bNot Verified\b|\bUnknown Publisher\b|\bReputation\b') {
            $sus.Add((Normalize-Whitespace $l)) | Out-Null
        }
        if ($sus.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($sus.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'File Trust' -Title 'Sigcheck: unsigned / unverified files observed' -EvidencePath $p -Evidence (($sus | Select-Object -First 30) -join ' ; ') -Recommendation 'Validate unsigned binaries found in scan scope. Prioritize those in Temp/AppData/ProgramData/Public and with recent timestamps.'
    }
}

function Analyze-NetworkConnections {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'siem\OpenTCPConnections.csv'
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        $rows = Get-CsvRowsSafe -Path $p
        if (-not $rows -or $rows.Count -eq 0) { return }

        $external = New-Object System.Collections.Generic.List[string]
        $procCount = @{}

        foreach ($r in $rows) {
            $state = ''
            try { $state = [string]$r.State } catch { $state = '' }
            if ($state -ne 'Established') { continue }

            $ra = ''
            try { $ra = [string]$r.RemoteAddress } catch { $ra = '' }
            if ([string]::IsNullOrWhiteSpace($ra)) { continue }
            if ($ra -eq '127.0.0.1' -or $ra -eq '::1') { continue }
            if ($ra -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)') { continue }

            $pn = ''
            try { $pn = [string]$r.ProcessName } catch { $pn = '' }
            if ([string]::IsNullOrWhiteSpace($pn)) {
                $pid = ''
                try { $pid = [string]$r.OwningProcess } catch { $pid = '' }
                $pn = 'PID_' + $pid
            }

            if (-not $procCount.ContainsKey($pn)) { $procCount[$pn] = 0 }
            $procCount[$pn] = [int]$procCount[$pn] + 1

            $rp = ''
            try { $rp = [string]$r.RemotePort } catch { $rp = '' }
            $external.Add(($pn + ' -> ' + $ra + ':' + $rp)) | Out-Null
            if ($external.Count -ge $MaxFindingsPerSource) { break }
        }

        if ($external.Count -gt 0) {
            $topProc = $procCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { ($_.Key + '=' + $_.Value) }
            Add-Finding -Severity 'Medium' -Category 'Network' -Title 'External established connections detected' -EvidencePath $p -Evidence (('Top processes: ' + ($topProc -join ', ')) + ' | Samples: ' + (($external | Select-Object -First 20) -join ' ; ')) -Recommendation 'Validate external connections. Confirm process legitimacy and correlate with DNS cache and execution/persistence artifacts.'
        }
        return
    }

    $p2 = Join-Path $CaseRoot 'network\netstat_abno.txt'
    if (-not (Test-Path -LiteralPath $p2 -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p2 -MaxLines 30000
    $sus = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match '(?i)\bESTABLISHED\b' -and $l -match '(?i)\b:3389\b|\b:5985\b|\b:5986\b|\b:445\b|\b:139\b') {
            $sus.Add((Normalize-Whitespace $l)) | Out-Null
        }
        if ($sus.Count -ge 40) { break }
    }
    if ($sus.Count -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Network' -Title 'Netstat indicates established sessions on admin/service ports (sampling)' -EvidencePath $p2 -Evidence (($sus | Select-Object -First 30) -join ' ; ') -Recommendation 'Correlate admin-port sessions with expected remote management activity and authentication artifacts.'
    }
}

function Analyze-DnsCache {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'siem\DNSCache.csv'
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        $rows = Get-CsvRowsSafe -Path $p
        if (-not $rows -or $rows.Count -eq 0) { return }

        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($r in $rows) {
            $name = ''
            $data = ''
            try { $name = [string]$r.Name } catch { $name = '' }
            try { $data = [string]$r.Data } catch { $data = '' }
            $line = ($name + ' -> ' + $data)
            if ($line -match '(?i)\b(ngrok|duckdns|no-ip|dyn|paste|raw\.github|discord|telegram|tunnel)\b') {
                $hits.Add((Normalize-Whitespace $line)) | Out-Null
            }
            if ($hits.Count -ge $MaxFindingsPerSource) { break }
        }

        if ($hits.Count -gt 0) {
            Add-Finding -Severity 'Low' -Category 'Network' -Title 'DNS cache contains domains commonly used in tooling/C2 (keyword match)' -EvidencePath $p -Evidence (($hits | Select-Object -First 30) -join ' ; ') -Recommendation 'Validate domains and correlate with execution artifacts and outbound connections.'
        }
        return
    }

    $p2 = Join-Path $CaseRoot 'network\dns_cache.txt'
    if (-not (Test-Path -LiteralPath $p2 -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p2 -MaxLines 25000
    $susp = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match '(?i)\b(update|paste|cdn|raw|git|discord|telegram|ngrok|tunnel|duckdns|no-ip|dyn)\b') {
            $susp.Add((Normalize-Whitespace $l)) | Out-Null
        }
        if ($susp.Count -ge 40) { break }
    }

    if ($susp.Count -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Network' -Title 'DNS cache includes potentially suspicious domains (keyword match)' -EvidencePath $p2 -Evidence (($susp | Select-Object -First 30) -join ' ; ') -Recommendation 'Review domains for legitimacy and correlate with browser artifacts and process/network telemetry.'
    }
}

function Analyze-SuspiciousFileListings {
    param([string]$CaseRoot)

    $dir = Join-Path $CaseRoot 'file_listings'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return }

    $csvs = Get-ChildItem -LiteralPath $dir -File -Filter '*_recent_suspicious.csv' -ErrorAction SilentlyContinue
    if (-not $csvs -or $csvs.Count -eq 0) { return }

    $finds = New-Object System.Collections.Generic.List[string]
    foreach ($c in $csvs) {
        $rows = Get-CsvRowsSafe -Path $c.FullName
        foreach ($r in $rows) {
            $path = ''
            try { $path = [string]$r.Path } catch { $path = '' }
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            if ($path -match '(?i)\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\') {
                $finds.Add($path) | Out-Null
            }
            if ($finds.Count -ge $MaxFindingsPerSource) { break }
        }
        if ($finds.Count -ge $MaxFindingsPerSource) { break }
    }

    $uniq = @($finds | Where-Object { $_ } | Select-Object -Unique)
    if ($uniq.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'File Drops' -Title 'Recent suspicious file listings in high-risk directories' -EvidencePath $dir -Evidence (($uniq | Select-Object -First $MaxTableRows) -join ' ; ') -Recommendation 'Triage newly written executables/scripts. Validate signature/hash and correlate with autoruns/tasks/services.'
    }
}

function Analyze-PowerShellOperationalText {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'enhanced_artifacts\powershell_op_recent.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $rx = Get-SuspiciousCommandRegexes
    $hits = Find-RegexHitsInFile -Path $p -Regexes $rx -MaxHits $MaxFindingsPerSource
    if ($hits.Count -gt 0) {
        $ev = ($hits | Select-Object -First 14 | ForEach-Object { ('L' + $_.LineNo + ':' + (Normalize-Whitespace $_.Line)) }) -join ' | '
        Add-Finding -Severity 'High' -Category 'Execution' -Title 'Suspicious PowerShell patterns in Operational log text export' -EvidencePath $p -Evidence $ev -Recommendation 'Investigate encoded commands / IEX / download activity. Correlate with process creation, network, and user sessions.'
    }
}

function Analyze-DefenderEventsText {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'enhanced_artifacts\defender_recent_events.txt'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 12000
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match '(?i)\b(Threat|Malware|Detected|Quarantined|Remediation|Blocked)\b') {
            $hits.Add((Normalize-Whitespace $l)) | Out-Null
        }
        if ($hits.Count -ge 30) { break }
    }

    if ($hits.Count -gt 0) {
        Add-Finding -Severity 'Info' -Category 'Security Controls' -Title 'Defender events indicate detections/blocks (keyword match)' -EvidencePath $p -Evidence (($hits | Select-Object -First 25) -join ' ; ') -Recommendation 'If detections occurred, collect full details, affected paths/hashes, and correlate with persistence/execution.'
    }
}

function Analyze-SIEM-SecurityEventsCsv {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot 'siem\SecurityEvents.csv'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $rows = Get-CsvRowsSafe -Path $p
    if (-not $rows -or $rows.Count -eq 0) { return }

    $cnt4625 = 0
    $cnt4672 = 0
    $cnt4688 = 0
    $cnt1102 = 0

    $rx = Get-SuspiciousCommandRegexes
    $cmd = New-Object System.Collections.Generic.List[string]

    foreach ($r in $rows) {
        $id = 0
        try { $id = [int]$r.Id } catch { $id = 0 }

        if ($id -eq 4625) { $cnt4625++ }
        elseif ($id -eq 4672) { $cnt4672++ }
        elseif ($id -eq 4688) { $cnt4688++ }
        elseif ($id -eq 1102) { $cnt1102++ }

        if ($id -eq 4688) {
            $m = ''
            try { $m = [string]$r.Message } catch { $m = '' }
            if (-not [string]::IsNullOrWhiteSpace($m)) {
                $flag = $false
                foreach ($x in $rx) { if ($m -match $x) { $flag = $true; break } }
                if ($flag) {
                    $s = Normalize-Whitespace $m
                    if ($s.Length -gt 260) { $s = $s.Substring(0, 260) + '...' }
                    $cmd.Add($s) | Out-Null
                }
            }
        }

        if ($cmd.Count -ge 40) { break }
    }

    if ($cnt1102 -gt 0) {
        Add-Finding -Severity 'High' -Category 'Anti-Forensics' -Title 'Security log clear events detected (1102)' -EvidencePath $p -Evidence ('1102 count (sample): ' + $cnt1102) -Recommendation 'Treat as suspicious. Determine who cleared logs and correlate with privileged activity.'
    }

    if ($cnt4625 -gt 25) {
        Add-Finding -Severity 'Medium' -Category 'Authentication' -Title 'Multiple failed logons detected (4625)' -EvidencePath $p -Evidence ('4625 count (sample): ' + $cnt4625) -Recommendation 'Investigate brute force/spray. Identify source hosts, targeted accounts, and correlate with successful logons.'
    }

    if ($cnt4672 -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Privilege' -Title 'Special privileges assigned to logon sessions (4672) observed' -EvidencePath $p -Evidence ('4672 count (sample): ' + $cnt4672) -Recommendation 'Correlate privileged logons with approved admin activity and expected endpoints.'
    }

    if ($cmd.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Execution' -Title 'Suspicious process creation command-lines (4688 keyword match)' -EvidencePath $p -Evidence (($cmd | Select-Object -First 18) -join ' ; ') -Recommendation 'Review full command-lines and correlate with parent processes, persistence, and outbound connections.'
    }
}

function Analyze-EVTX {
    param([string]$CaseRoot)

    $securityEvtx = Join-Path $CaseRoot 'eventlogs\Security.evtx'
    if (-not (Test-Path -LiteralPath $securityEvtx -PathType Leaf)) { return }

    try {
        $events = Get-WinEvent -Path $securityEvtx -MaxEvents 5000 -ErrorAction Stop
    } catch {
        Add-Finding -Severity 'Info' -Category 'EVTX' -Title 'EVTX parsing skipped (Get-WinEvent failed)' -EvidencePath $securityEvtx -Evidence (Normalize-Whitespace $_.Exception.Message) -Recommendation 'Move EVTX to a forensic workstation and parse with EVTX tooling or SIEM.'
        return
    }

    $fail = @($events | Where-Object { $_.Id -eq 4625 }).Count
    $priv = @($events | Where-Object { $_.Id -eq 4672 }).Count
    $clear = @($events | Where-Object { $_.Id -eq 1102 }).Count

    if ($clear -gt 0) { Add-Finding -Severity 'High' -Category 'Anti-Forensics' -Title 'EVTX: security log clear events detected (1102)' -EvidencePath $securityEvtx -Evidence ('1102 count (sample): ' + $clear) -Recommendation 'Treat as suspicious. Identify actor and correlate to privileged activity.' }
    if ($fail -gt 50) { Add-Finding -Severity 'Medium' -Category 'Authentication' -Title 'EVTX: high failed logons (4625)' -EvidencePath $securityEvtx -Evidence ('4625 count (sample): ' + $fail) -Recommendation 'Investigate brute force/spray patterns. Correlate accounts, source hosts, and timeline.' }
    if ($priv -gt 0) { Add-Finding -Severity 'Low' -Category 'Privilege' -Title 'EVTX: privileged logons (4672) observed' -EvidencePath $securityEvtx -Evidence ('4672 count (sample): ' + $priv) -Recommendation 'Validate privileged logons against approved admin activity.' }

    $rx = Get-SuspiciousCommandRegexes
    $cmdHits = New-Object System.Collections.Generic.List[string]
    foreach ($e in ($events | Where-Object { $_.Id -eq 4688 })) {
        $m = [string]$e.Message
        if ([string]::IsNullOrWhiteSpace($m)) { continue }
        $flag = $false
        foreach ($x in $rx) { if ($m -match $x) { $flag = $true; break } }
        if ($flag) {
            $short = Normalize-Whitespace $m
            if ($short.Length -gt 260) { $short = $short.Substring(0, 260) + '...' }
            $cmdHits.Add($short) | Out-Null
        }
        if ($cmdHits.Count -ge 40) { break }
    }

    if ($cmdHits.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Execution' -Title 'EVTX: suspicious process creation patterns (4688)' -EvidencePath $securityEvtx -Evidence (($cmdHits | Select-Object -First 18) -join ' ; ') -Recommendation 'Review full 4688 events, correlate parent process and outbound connections.'
    }
}

function Load-ManifestMap {
    param([string]$ManifestCsvPath)

    $map = @{}
    if (-not (Test-Path -LiteralPath $ManifestCsvPath -PathType Leaf)) { return $map }
    $rows = @()
    try { $rows = Import-Csv -LiteralPath $ManifestCsvPath } catch { return $map }
    foreach ($r in $rows) {
        $p = ''
        $h = ''
        try { $p = [string]$r.Path } catch { $p = '' }
        try { $h = [string]$r.SHA256 } catch { $h = '' }
        if ([string]::IsNullOrWhiteSpace($p) -or [string]::IsNullOrWhiteSpace($h)) { continue }
        if (-not $map.ContainsKey($p)) { $map[$p] = $h }
    }
    return $map
}

function Analyze-BaselineDiff {
    param([pscustomobject]$Meta, [string]$BaselineRoot)

    if ([string]::IsNullOrWhiteSpace($BaselineRoot)) { return }
    if (-not (Test-Path -LiteralPath $BaselineRoot -PathType Container)) { return }
    if (-not (Test-Path -LiteralPath $Meta.ShaManifestPath -PathType Leaf)) { return }

    $baselineManifest = Join-Path $BaselineRoot 'meta\sha256_manifest.csv'
    if (-not (Test-Path -LiteralPath $baselineManifest -PathType Leaf)) { return }

    $newMap = Load-ManifestMap -ManifestCsvPath $Meta.ShaManifestPath
    $oldMap = Load-ManifestMap -ManifestCsvPath $baselineManifest

    if ($newMap.Count -eq 0 -or $oldMap.Count -eq 0) { return }

    $added = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]

    foreach ($k in $newMap.Keys) {
        if (-not $oldMap.ContainsKey($k)) { $added.Add($k) | Out-Null; continue }
        if ($oldMap[$k] -ne $newMap[$k]) { $changed.Add($k) | Out-Null }
    }

    $rxRisk = Get-SuspiciousPathRegexes
    $addedRisk = New-Object System.Collections.Generic.List[string]
    foreach ($p in $added) { foreach ($r in $rxRisk) { if ($p -match $r) { $addedRisk.Add($p) | Out-Null; break } } }

    $changedRisk = New-Object System.Collections.Generic.List[string]
    foreach ($p in $changed) { foreach ($r in $rxRisk) { if ($p -match $r) { $changedRisk.Add($p) | Out-Null; break } } }

    if ($changedRisk.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Change Detection' -Title 'Files changed since baseline in high-risk locations (manifest diff)' -EvidencePath $Meta.ShaManifestPath -Evidence (($changedRisk | Select-Object -First $MaxTableRows) -join ' ; ') -Recommendation 'Investigate modified binaries/scripts in high-risk directories. Validate hashes, signatures, and provenance.'
    }

    if ($addedRisk.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Change Detection' -Title 'New files since baseline in high-risk locations (manifest diff)' -EvidencePath $Meta.ShaManifestPath -Evidence (($addedRisk | Select-Object -First $MaxTableRows) -join ' ; ') -Recommendation 'Review newly introduced files in AppData/Temp/ProgramData/Public. Correlate timestamps with execution and persistence.'
    }
}

function Select-FirstColumnValue {
    param([object]$Row, [string[]]$Candidates)

    foreach ($c in $Candidates) {
        try {
            $v = $Row.$c
            if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
        } catch { }
    }
    return ''
}

function Parse-InstalledPrograms {
    param([string]$Path)

    $items = New-Object System.Collections.Generic.List[object]

    if ([string]::IsNullOrWhiteSpace($Path)) { return $items }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $items }

    if ($Path.ToLowerInvariant().EndsWith('.csv')) {
        $rows = @()
        try { $rows = Import-Csv -LiteralPath $Path } catch { $rows = @() }
        foreach ($r in $rows) {
            $name = Select-FirstColumnValue -Row $r -Candidates @('DisplayName','Name','Program','Application','Product','Title')
            $ver  = Select-FirstColumnValue -Row $r -Candidates @('DisplayVersion','Version','ProductVersion')
            $pub  = Select-FirstColumnValue -Row $r -Candidates @('Publisher','Vendor','Company')
            $date = Select-FirstColumnValue -Row $r -Candidates @('InstallDate','InstalledOn','Date')
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $items.Add([pscustomobject]@{ Name=$name; Version=$ver; Publisher=$pub; InstallDate=$date }) | Out-Null
        }
        return $items
    }

    $lines = Read-Lines -Path $Path -MaxLines 30000
    foreach ($l in $lines) {
        $x = Normalize-Whitespace $l
        if ([string]::IsNullOrWhiteSpace($x)) { continue }
        if ($x.Length -lt 3) { continue }
        $items.Add([pscustomobject]@{ Name=$x; Version=''; Publisher=''; InstallDate='' }) | Out-Null
    }
    return $items
}

function Get-ProgramRiskTag {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }

    $n = $Name.ToLowerInvariant()

    $high = @(
        'anydesk','teamviewer','screenconnect','connectwise','logmein','radmin','ammyy','ultravnc','tightvnc','realvnc','rustdesk','splashtop',
        'ngrok','frp','zerotier','tailscale',
        'mimikatz','rubeus','secretsdump','impacket','bloodhound','cobalt','sliver','metasploit','msf','ncat','netcat','psexec'
    )

    $medium = @(
        'wireshark','nmap','burp','postman','fiddler','procdump','sysinternals','advanced ip scanner','masscan','john the ripper','hashcat',
        'python','node.js','nodejs','golang','go language'
    )

    foreach ($k in $high) { if ($n -like "*$k*") { return 'High' } }
    foreach ($k in $medium) { if ($n -like "*$k*") { return 'Medium' } }

    return ''
}

function Analyze-InstalledPrograms {
    param([string]$CaseRoot, [string]$BaselineRoot)

    $p = Find-FirstCaseFile -CaseRoot $CaseRoot -RelativeCandidates @(
        'software\installed_programs.csv',
        'software\installed_programs.txt',
        'software\installed_apps.csv',
        'software\installed_apps.txt',
        'software\programs.csv',
        'software\programs.txt',
        'system\installed_programs.csv',
        'system\installed_programs.txt',
        'registry\uninstall_apps.csv',
        'registry\uninstall_apps.txt'
    ) -LeafPatterns @(
        '*installed*program*.csv',
        '*installed*app*.csv',
        '*uninstall*.csv',
        '*installed*program*.txt',
        '*installed*app*.txt',
        '*uninstall*.txt'
    ) -MaxSearch 1

    if ([string]::IsNullOrWhiteSpace($p)) { return }

    $items = Parse-InstalledPrograms -Path $p
    if (-not $items -or $items.Count -eq 0) { return }

    $susHigh = New-Object System.Collections.Generic.List[string]
    $susMed  = New-Object System.Collections.Generic.List[string]

    foreach ($it in $items) {
        $tag = Get-ProgramRiskTag -Name $it.Name
        if ($tag -eq 'High') { $susHigh.Add($it.Name) | Out-Null; continue }
        if ($tag -eq 'Medium') { $susMed.Add($it.Name) | Out-Null; continue }
    }

    $uniqHigh = @($susHigh | Select-Object -Unique)
    $uniqMed  = @($susMed  | Select-Object -Unique)

    if ($uniqHigh.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Installed Software' -Title 'Potentially high-risk installed software detected (keyword match)' -EvidencePath $p -Evidence (($uniqHigh | Select-Object -First 40) -join ' ; ') -Recommendation 'Validate if remote-access or offensive tooling is expected. If not approved, treat as suspicious and correlate with execution/persistence.'
    }

    if ($uniqMed.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Installed Software' -Title 'Potentially suspicious installed software detected (keyword match)' -EvidencePath $p -Evidence (($uniqMed | Select-Object -First 40) -join ' ; ') -Recommendation 'Review these tools against baseline/asset inventory. Correlate install time and user activity.'
    }

    if (-not [string]::IsNullOrWhiteSpace($BaselineRoot) -and (Test-Path -LiteralPath $BaselineRoot -PathType Container)) {
        $bp = Find-FirstCaseFile -CaseRoot $BaselineRoot -RelativeCandidates @(
            'software\installed_programs.csv',
            'software\installed_programs.txt',
            'software\installed_apps.csv',
            'software\installed_apps.txt',
            'software\programs.csv',
            'software\programs.txt',
            'system\installed_programs.csv',
            'system\installed_programs.txt',
            'registry\uninstall_apps.csv',
            'registry\uninstall_apps.txt'
        ) -LeafPatterns @(
            '*installed*program*.csv',
            '*installed*app*.csv',
            '*uninstall*.csv',
            '*installed*program*.txt',
            '*installed*app*.txt',
            '*uninstall*.txt'
        ) -MaxSearch 1

        if (-not [string]::IsNullOrWhiteSpace($bp) -and (Test-Path -LiteralPath $bp -PathType Leaf)) {
            $baseItems = Parse-InstalledPrograms -Path $bp

            $newSet = @{}
            foreach ($i in $items) {
                $k = ($i.Name + '|' + $i.Version)
                if (-not $newSet.ContainsKey($k)) { $newSet[$k] = $true }
            }

            $oldSet = @{}
            foreach ($i in $baseItems) {
                $k = ($i.Name + '|' + $i.Version)
                if (-not $oldSet.ContainsKey($k)) { $oldSet[$k] = $true }
            }

            $added = New-Object System.Collections.Generic.List[string]
            foreach ($k in $newSet.Keys) {
                if (-not $oldSet.ContainsKey($k)) { $added.Add($k) | Out-Null }
            }

            if ($added.Count -gt 0) {
                $addedHigh = New-Object System.Collections.Generic.List[string]
                $addedMed  = New-Object System.Collections.Generic.List[string]
                foreach ($a in $added) {
                    $n = $a.Split('|')[0]
                    $tag = Get-ProgramRiskTag -Name $n
                    if ($tag -eq 'High') { $addedHigh.Add($a) | Out-Null; continue }
                    if ($tag -eq 'Medium') { $addedMed.Add($a) | Out-Null; continue }
                }

                $uAh = @($addedHigh | Select-Object -Unique)
                $uAm = @($addedMed | Select-Object -Unique)

                if ($uAh.Count -gt 0) {
                    Add-Finding -Severity 'High' -Category 'Change Detection' -Title 'New high-risk software since baseline (programs diff)' -EvidencePath $p -Evidence (($uAh | Select-Object -First 50) -join ' ; ') -Recommendation 'Treat as significant change. Validate source, installer, signer, and correlate with persistence and outbound traffic.'
                } elseif ($uAm.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Category 'Change Detection' -Title 'New potentially suspicious software since baseline (programs diff)' -EvidencePath $p -Evidence (($uAm | Select-Object -First 50) -join ' ; ') -Recommendation 'Confirm these installations are approved and expected for this endpoint.'
                } else {
                    Add-Finding -Severity 'Info' -Category 'Change Detection' -Title 'New software items since baseline detected (programs diff)' -EvidencePath $p -Evidence ((@($added | Select-Object -First 60) -join ' ; ')) -Recommendation 'Review added software list and verify legitimacy.'
                }
            }
        }
    }
}

function Extract-ExtensionLine {
    param([string]$Line)

    $x = Normalize-Whitespace $Line
    if ([string]::IsNullOrWhiteSpace($x)) { return '' }
    if ($x.Length -gt 480) { $x = $x.Substring(0, 480) + '...' }
    return $x
}

function Get-ExtensionRiskTag {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return '' }
    $t = $Line.ToLowerInvariant()

    if ($t -match '(proxy|vpn|cookie|steal|stealer|wallet|inject|tamper|captcha|bypass|adblock|telegram|whatsapp|discord)') {
        if ($t -match '(steal|stealer|wallet|inject|tamper)') { return 'High' }
        return 'Medium'
    }

    if ($t -match '(unpacked|developer mode|load unpacked|local extension)') { return 'Medium' }

    return ''
}

function Parse-ExtensionsFromText {
    param([string]$Path)

    $out = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Path)) { return $out }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $out }

    $lines = Read-Lines -Path $Path -MaxLines 40000
    foreach ($l in $lines) {
        $x = Extract-ExtensionLine -Line $l
        if ([string]::IsNullOrWhiteSpace($x)) { continue }
        if ($x -match '^(Name|ID|Extension|Path|Profile|Installed|Version)\s*[:=]') { $out.Add($x) | Out-Null; continue }
        if ($x -match '(?i)\b(extension|chrome|edge|firefox|addons|add-on)\b') { $out.Add($x) | Out-Null; continue }
    }

    if ($out.Count -eq 0) {
        foreach ($l in ($lines | Select-Object -First 2000)) {
            $x = Extract-ExtensionLine -Line $l
            if ([string]::IsNullOrWhiteSpace($x)) { continue }
            $out.Add($x) | Out-Null
            if ($out.Count -ge 200) { break }
        }
    }

    return $out
}

function Analyze-BrowserExtensions {
    param([string]$CaseRoot, [string]$BaselineRoot)

    $paths = Find-CaseFiles -CaseRoot $CaseRoot -RelativeCandidates @(
        'browser\chrome_extensions.txt',
        'browser\edge_extensions.txt',
        'browser\firefox_extensions.txt',
        'browser\browser_extensions.txt',
        'enhanced_artifacts\browser_extensions.txt'
    ) -LeafPatterns @(
        '*chrome*extension*.txt',
        '*edge*extension*.txt',
        '*firefox*extension*.txt',
        '*browser*extension*.txt',
        '*extensions*.txt'
    ) -MaxSearch 10

    if (-not $paths -or $paths.Count -eq 0) { return }

    $riskHigh = New-Object System.Collections.Generic.List[string]
    $riskMed  = New-Object System.Collections.Generic.List[string]

    foreach ($p in $paths) {
        $lines = Parse-ExtensionsFromText -Path $p
        foreach ($l in $lines) {
            $tag = Get-ExtensionRiskTag -Line $l
            if ($tag -eq 'High') { $riskHigh.Add(($l + ' | File=' + (Split-Path -Leaf $p))) | Out-Null; continue }
            if ($tag -eq 'Medium') { $riskMed.Add(($l + ' | File=' + (Split-Path -Leaf $p))) | Out-Null; continue }
        }
    }

    $uH = @($riskHigh | Select-Object -Unique)
    $uM = @($riskMed  | Select-Object -Unique)

    if ($uH.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Browser Extensions' -Title 'Potentially high-risk browser extensions detected (keyword match)' -EvidencePath ($paths -join ' ; ') -Evidence (($uH | Select-Object -First 60) -join ' ; ') -Recommendation 'Validate extensions against enterprise policy. Investigate unpacked/dev-mode and any extension with credential/cookie access patterns.'
    } elseif ($uM.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Browser Extensions' -Title 'Potentially suspicious browser extensions detected (keyword match)' -EvidencePath ($paths -join ' ; ') -Evidence (($uM | Select-Object -First 60) -join ' ; ') -Recommendation 'Review extension list. Correlate with browser history, proxy settings, and user sessions.'
    } else {
        Add-Finding -Severity 'Info' -Category 'Browser Extensions' -Title 'Browser extension inventory detected' -EvidencePath ($paths -join ' ; ') -Evidence ('Extension files found: ' + ($paths.Count)) -Recommendation 'If incident involves browser abuse, review extensions and profiles in detail.'
    }

    if (-not [string]::IsNullOrWhiteSpace($BaselineRoot) -and (Test-Path -LiteralPath $BaselineRoot -PathType Container)) {
        $basePaths = Find-CaseFiles -CaseRoot $BaselineRoot -RelativeCandidates @(
            'browser\chrome_extensions.txt',
            'browser\edge_extensions.txt',
            'browser\firefox_extensions.txt',
            'browser\browser_extensions.txt',
            'enhanced_artifacts\browser_extensions.txt'
        ) -LeafPatterns @(
            '*chrome*extension*.txt',
            '*edge*extension*.txt',
            '*firefox*extension*.txt',
            '*browser*extension*.txt',
            '*extensions*.txt'
        ) -MaxSearch 10

        if ($basePaths -and $basePaths.Count -gt 0) {
            $newSet = @{}
            foreach ($p in $paths) {
                $lines = Parse-ExtensionsFromText -Path $p
                foreach ($l in $lines) {
                    $k = Normalize-Whitespace $l
                    if ([string]::IsNullOrWhiteSpace($k)) { continue }
                    if (-not $newSet.ContainsKey($k)) { $newSet[$k] = $true }
                }
            }

            $oldSet = @{}
            foreach ($p in $basePaths) {
                $lines = Parse-ExtensionsFromText -Path $p
                foreach ($l in $lines) {
                    $k = Normalize-Whitespace $l
                    if ([string]::IsNullOrWhiteSpace($k)) { continue }
                    if (-not $oldSet.ContainsKey($k)) { $oldSet[$k] = $true }
                }
            }

            $added = New-Object System.Collections.Generic.List[string]
            foreach ($k in $newSet.Keys) {
                if (-not $oldSet.ContainsKey($k)) { $added.Add($k) | Out-Null }
            }

            if ($added.Count -gt 0) {
                $ah = New-Object System.Collections.Generic.List[string]
                $am = New-Object System.Collections.Generic.List[string]
                foreach ($a in $added) {
                    $tag = Get-ExtensionRiskTag -Line $a
                    if ($tag -eq 'High') { $ah.Add($a) | Out-Null; continue }
                    if ($tag -eq 'Medium') { $am.Add($a) | Out-Null; continue }
                }

                $uah = @($ah | Select-Object -Unique)
                $uam = @($am | Select-Object -Unique)

                if ($uah.Count -gt 0) {
                    Add-Finding -Severity 'High' -Category 'Change Detection' -Title 'New high-risk browser extension indicators since baseline (extensions diff)' -EvidencePath ($paths -join ' ; ') -Evidence (($uah | Select-Object -First 60) -join ' ; ') -Recommendation 'Treat as meaningful change. Verify extension origin, permissions, and correlate with browser-based credential theft patterns.'
                } elseif ($uam.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Category 'Change Detection' -Title 'New potentially suspicious browser extension indicators since baseline (extensions diff)' -EvidencePath ($paths -join ' ; ') -Evidence (($uam | Select-Object -First 60) -join ' ; ') -Recommendation 'Review new extension indicators and confirm they are approved for this endpoint.'
                } else {
                    Add-Finding -Severity 'Info' -Category 'Change Detection' -Title 'New browser extension indicators since baseline (extensions diff)' -EvidencePath ($paths -join ' ; ') -Evidence ((@($added | Select-Object -First 80) -join ' ; ')) -Recommendation 'Review new extension indicators and validate legitimacy.'
                }
            }
        }
    }
}

function Analyze-RegistryIndicators {
    param([string]$CaseRoot)

    $regDir = Join-Path $CaseRoot 'registry'
    if (-not (Test-Path -LiteralPath $regDir -PathType Container)) { return }

    $files = Get-ChildItem -LiteralPath $regDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 40
    if (-not $files) { return }

    $patternsHigh = @(
        '(?i)Image File Execution Options',
        '(?i)\bDebugger\b',
        '(?i)SilentProcessExit',
        '(?i)AppInit_DLLs',
        '(?i)WDigest',
        '(?i)UseLogonCredential',
        '(?i)Security Packages',
        '(?i)Notification Packages',
        '(?i)DisableAntiSpyware',
        '(?i)DisableRealtimeMonitoring',
        '(?i)RunOnceEx',
        '(?i)Winlogon\\Shell',
        '(?i)Winlogon\\Userinit'
    )

    $patternsMed = @(
        '(?i)\\Run\\',
        '(?i)\\RunOnce\\',
        '(?i)\\Policies\\Explorer\\Run',
        '(?i)\\Services\\',
        '(?i)\\Tasks\\',
        '(?i)\\Office\\.*\\Addins',
        '(?i)\\CurrentVersion\\Explorer\\Browser Helper Objects',
        '(?i)\\CurrentVersion\\Shell Extensions'
    )

    $hitsHigh = New-Object System.Collections.Generic.List[string]
    $hitsMed  = New-Object System.Collections.Generic.List[string]

    foreach ($f in $files) {
        $t = Get-FileText -Path $f.FullName -MaxChars 300000
        if ([string]::IsNullOrWhiteSpace($t)) { continue }

        foreach ($p in $patternsHigh) {
            if ($t -match $p) {
                $hitsHigh.Add((Split-Path -Leaf $f.FullName) + ':' + $p) | Out-Null
            }
        }

        foreach ($p in $patternsMed) {
            if ($t -match $p) {
                $hitsMed.Add((Split-Path -Leaf $f.FullName) + ':' + $p) | Out-Null
            }
        }

        if ($hitsHigh.Count -ge 30) { break }
    }

    $uH = @($hitsHigh | Select-Object -Unique)
    $uM = @($hitsMed  | Select-Object -Unique)

    if ($uH.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Registry' -Title 'Registry artifacts include high-risk indicator strings (heuristic scan)' -EvidencePath $regDir -Evidence (($uH | Select-Object -First 40) -join ' ; ') -Recommendation 'Investigate registry persistence/defense-evasion keys. Validate values and correlate to autoruns/tasks/services.'
    } elseif ($uM.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Registry' -Title 'Registry artifacts include persistence-related indicator strings (heuristic scan)' -EvidencePath $regDir -Evidence (($uM | Select-Object -First 60) -join ' ; ') -Recommendation 'Review registry export scope. Look for non-baselined autoruns and suspicious shell extensions/addins.'
    }
}

function Analyze-LocalAccounts {
    param([string]$CaseRoot, [string]$BaselineRoot)

    $pUsers = Find-FirstCaseFile -CaseRoot $CaseRoot -RelativeCandidates @(
        'accounts\local_users.txt',
        'security\local_users.txt',
        'system\local_users.txt',
        'enhanced_artifacts\local_users.txt'
    ) -LeafPatterns @(
        '*local*users*.txt',
        '*users_local*.txt'
    ) -MaxSearch 1

    $pAdmins = Find-FirstCaseFile -CaseRoot $CaseRoot -RelativeCandidates @(
        'accounts\local_admins.txt',
        'security\local_admins.txt',
        'system\local_admins.txt',
        'enhanced_artifacts\local_admins.txt'
    ) -LeafPatterns @(
        '*local*admin*.txt',
        '*administrators*.txt'
    ) -MaxSearch 1

    if ($pUsers) {
        $lines = Read-Lines -Path $pUsers -MaxLines 20000
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            $x = Normalize-Whitespace $l
            if ([string]::IsNullOrWhiteSpace($x)) { continue }
            if ($x -match '(?i)^(name|user|account)\b') { continue }
            if ($x.Length -gt 2) { $list.Add($x) | Out-Null }
            if ($list.Count -ge 200) { break }
        }

        $uniq = @($list | Select-Object -Unique)
        if ($uniq.Count -gt 0) {
            Add-Finding -Severity 'Info' -Category 'Accounts' -Title 'Local user inventory detected' -EvidencePath $pUsers -Evidence (($uniq | Select-Object -First 60) -join ' ; ') -Recommendation 'Review local accounts for unknown users. Correlate with logons and privilege events.'
        }
    }

    if ($pAdmins) {
        $lines = Read-Lines -Path $pAdmins -MaxLines 20000
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            $x = Normalize-Whitespace $l
            if ([string]::IsNullOrWhiteSpace($x)) { continue }
            if ($x -match '(?i)^(name|member)\b') { continue }
            if ($x.Length -gt 2) { $list.Add($x) | Out-Null }
            if ($list.Count -ge 200) { break }
        }

        $uniq = @($list | Select-Object -Unique)
        if ($uniq.Count -gt 0) {
            $sus = @($uniq | Where-Object { $_ -match '(?i)admin|support|help|temp|test|svc|service|backup|operator' })
            if ($sus.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Category 'Accounts' -Title 'Local Administrators membership includes potentially suspicious names (heuristic)' -EvidencePath $pAdmins -Evidence (($sus | Select-Object -First 60) -join ' ; ') -Recommendation 'Validate local admin members against approved admin groups. Investigate unknown accounts.'
            } else {
                Add-Finding -Severity 'Info' -Category 'Accounts' -Title 'Local Administrators inventory detected' -EvidencePath $pAdmins -Evidence (($uniq | Select-Object -First 60) -join ' ; ') -Recommendation 'Review local admin membership for policy compliance.'
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($BaselineRoot) -and (Test-Path -LiteralPath $BaselineRoot -PathType Container) -and $pAdmins) {
        $bpAdmins = Find-FirstCaseFile -CaseRoot $BaselineRoot -RelativeCandidates @(
            'accounts\local_admins.txt',
            'security\local_admins.txt',
            'system\local_admins.txt',
            'enhanced_artifacts\local_admins.txt'
        ) -LeafPatterns @(
            '*local*admin*.txt',
            '*administrators*.txt'
        ) -MaxSearch 1

        if ($bpAdmins -and (Test-Path -LiteralPath $bpAdmins -PathType Leaf)) {
            $cur = @((Read-Lines -Path $pAdmins -MaxLines 20000) | ForEach-Object { Normalize-Whitespace $_ } | Where-Object { $_ -and $_.Length -gt 2 } | Select-Object -Unique)
            $old = @((Read-Lines -Path $bpAdmins -MaxLines 20000) | ForEach-Object { Normalize-Whitespace $_ } | Where-Object { $_ -and $_.Length -gt 2 } | Select-Object -Unique)

            $new = New-Object System.Collections.Generic.List[string]
            foreach ($x in $cur) { if (-not ($old -contains $x)) { $new.Add($x) | Out-Null } }

            if ($new.Count -gt 0) {
                Add-Finding -Severity 'High' -Category 'Change Detection' -Title 'New local admin members since baseline (admins diff)' -EvidencePath $pAdmins -Evidence (($new | Select-Object -First 60) -join ' ; ') -Recommendation 'Treat as high-impact change. Confirm who added admin members and correlate to 4672/4728/4732 events if available.'
            }
        }
    }
}

function Analyze-UnsignedDrivers {
    param([string]$CaseRoot)

    $p = Find-FirstCaseFile -CaseRoot $CaseRoot -RelativeCandidates @(
        'drivers\drivers.txt',
        'system\drivers.txt',
        'system\driver_inventory.txt',
        'security\drivers.txt',
        'third_party_analysis\driverquery.txt'
    ) -LeafPatterns @(
        '*driver*inventory*.txt',
        '*drivers*.txt',
        '*driverquery*.txt'
    ) -MaxSearch 1

    if ([string]::IsNullOrWhiteSpace($p)) { return }

    $lines = Read-Lines -Path $p -MaxLines 60000
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        $x = Normalize-Whitespace $l
        if ([string]::IsNullOrWhiteSpace($x)) { continue }
        if ($x -match '(?i)\bunsigned\b|\bnot signed\b|\bunknown publisher\b|\bnot verified\b') {
            $hits.Add($x) | Out-Null
        }
        if ($hits.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($hits.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Drivers' -Title 'Unsigned/unverified driver indicators detected (keyword match)' -EvidencePath $p -Evidence (($hits | Select-Object -First 40) -join ' ; ') -Recommendation 'Unsigned drivers can indicate rootkit/EDR bypass. Validate driver origin, hash, signer, and load events.'
    }
}

function Build-ReportMarkdown {
    param([pscustomobject]$Meta, [string]$ReportPath)

    $counts = $script:Findings | Group-Object Severity | ForEach-Object { [pscustomobject]@{ Severity = $_.Name; Count = $_.Count } }
    $byCat = $script:Findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Category = $_.Name; Count = $_.Count } }
    $top = Get-FindingsSorted | Select-Object -First 140

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add('# iKarus Collection Output Analysis') | Out-Null
    $md.Add('') | Out-Null
    $md.Add('Generated: ' + (Get-NowIso)) | Out-Null
    $md.Add('Case Root: ' + $Meta.CaseRoot) | Out-Null
    if ($Meta.Hostname) { $md.Add('Host: ' + $Meta.Hostname) | Out-Null }
    if ($Meta.CollectedAt) { $md.Add('Collected At: ' + $Meta.CollectedAt) | Out-Null }
    if ($Meta.Mode) { $md.Add('Mode: ' + $Meta.Mode) | Out-Null }
    if ($Meta.TimeframeDays) { $md.Add('Timeframe (days): ' + $Meta.TimeframeDays) | Out-Null }
    if ($Meta.ToolsPolicy) { $md.Add('Tools Policy: ' + $Meta.ToolsPolicy) | Out-Null }
    $md.Add('') | Out-Null

    $md.Add('## Summary') | Out-Null
    $md.Add('') | Out-Null

    $md.Add('### Findings by Severity') | Out-Null
    $md.Add('') | Out-Null
    $md.Add('| Severity | Count |') | Out-Null
    $md.Add('|---|---:|') | Out-Null
    foreach ($c in @('Critical','High','Medium','Low','Info')) {
        $n = 0
        $hit = $counts | Where-Object { $_.Severity -eq $c } | Select-Object -First 1
        if ($hit) { $n = $hit.Count }
        $md.Add('| ' + $c + ' | ' + $n + ' |') | Out-Null
    }
    $md.Add('') | Out-Null

    $md.Add('### Findings by Category') | Out-Null
    $md.Add('') | Out-Null
    $md.Add('| Category | Count |') | Out-Null
    $md.Add('|---|---:|') | Out-Null
    foreach ($c in ($byCat | Select-Object -First 25)) {
        $md.Add('| ' + $c.Category + ' | ' + $c.Count + ' |') | Out-Null
    }
    $md.Add('') | Out-Null

    $md.Add('## Top Findings') | Out-Null
    $md.Add('') | Out-Null

    foreach ($f in $top) {
        $md.Add('### ' + $f.Severity + ' - ' + $f.Title) | Out-Null
        $md.Add('') | Out-Null
        if ($f.Category) { $md.Add('*Category:* ' + $f.Category) | Out-Null }
        if ($f.EvidencePath) { $md.Add('*Evidence Path:* ' + $f.EvidencePath) | Out-Null }
        if ($f.Evidence) { $md.Add('*Evidence:* ' + $f.Evidence) | Out-Null }
        if ($f.Recommendation) { $md.Add('*Recommendation:* ' + $f.Recommendation) | Out-Null }
        $md.Add('') | Out-Null
    }

    [System.IO.File]::WriteAllLines($ReportPath, $md.ToArray(), [System.Text.Encoding]::UTF8)
}

function Export-Findings {
    param([string]$OutDir)

    NewDir $OutDir
    $csv = Join-Path $OutDir 'findings.csv'
    $json = Join-Path $OutDir 'findings.json'
    $md = Join-Path $OutDir 'analysis_report.md'

    $sorted = Get-FindingsSorted
    $sorted | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8 -Force
    $sorted | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $json -Encoding UTF8 -Force
    Build-ReportMarkdown -Meta $script:Meta -ReportPath $md

    return [pscustomobject]@{
        FindingsCsv = $csv
        FindingsJson = $json
        ReportMarkdown = $md
    }
}

function Get-DefaultOutDir {
    param([string]$CaseRoot, [pscustomobject]$Meta)

    $desk = Get-DesktopPath
    $name = ''
    if ($Meta -and $Meta.Hostname) { $name = $Meta.Hostname } else { $name = (Split-Path -Leaf $CaseRoot) }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'CASE' }
    $dirName = ('iKarus_Analysis_' + $name + '_' + (Get-NowStamp))
    return (Join-Path $desk $dirName)
}

function Read-InteractiveInputPath {
    Write-Host ''
    Write-Host 'Select input type:'
    Write-Host '[1] Case folder (already extracted)'
    Write-Host '[2] Case zip file'
    Write-Host '[3] windows_Forensic_Collections folder (pick a case)'
    $sel = Read-Host 'Choice (Enter = 2)'
    if ([string]::IsNullOrWhiteSpace($sel)) { $sel = '2' }

    switch ($sel) {
        '1' {
            $p = Read-Host 'Enter case folder path'
            return $p
        }
        '2' {
            $p = Read-Host 'Enter case zip path'
            return $p
        }
        '3' {
            $p = Read-Host 'Enter windows_Forensic_Collections folder path'
            if ([string]::IsNullOrWhiteSpace($p)) { return '' }
            return $p
        }
        default {
            $p = Read-Host 'Enter case zip path'
            return $p
        }
    }
}

function Ask-YesNo {
    param([string]$Prompt, [string]$Default = 'Y')

    $d = $Default.ToUpperInvariant()
    $suffix = '(Y/N)'
    if ($d -eq 'Y') { $suffix = '(Y/N, Enter=Y)' }
    elseif ($d -eq 'N') { $suffix = '(Y/N, Enter=N)' }

    $ans = Read-Host ($Prompt + ' ' + $suffix)
    if ([string]::IsNullOrWhiteSpace($ans)) { $ans = $d }
    $a = $ans.Trim().ToUpperInvariant()
    return ($a -eq 'Y' -or $a -eq 'YES')
}

function Run-Analyzer {
    if ([string]::IsNullOrWhiteSpace($InputPath) -and $Interactive) {
        Write-Host ''
        Write-Host '============================================================'
        Write-Host '                 iKARUS OUTPUT ANALYZER'
        Write-Host '============================================================'
        Write-Host ''
        $InputPath = Read-InteractiveInputPath
    }

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        throw 'InputPath is required. Provide -InputPath or run with -Interactive.'
    }

    if (Test-Path -LiteralPath $InputPath -PathType Container) {
        $leaf = Split-Path -Leaf $InputPath
        if ($leaf -ieq 'windows_Forensic_Collections') {
            $InputPath = Pick-CaseFromCollections -CollectionsDir $InputPath
        }
    }

    if ($Interactive -and (Test-Path -LiteralPath $InputPath -PathType Container)) {
        $leaf = Split-Path -Leaf $InputPath
        if ($leaf -ieq 'windows_Forensic_Collections') {
            $InputPath = Pick-CaseFromCollections -CollectionsDir $InputPath
        }
    }

    $caseRoot = Resolve-CaseRoot -Path $InputPath -AutoExtract:$AutoExtractZip
    $script:Meta = Get-CaseMeta -CaseRoot $caseRoot

    if ([string]::IsNullOrWhiteSpace($OutDir)) {
        $OutDir = Get-DefaultOutDir -CaseRoot $caseRoot -Meta $script:Meta
        if ($Interactive) {
            $custom = Read-Host ('Output folder (Enter = Desktop default): ' + $OutDir)
            if (-not [string]::IsNullOrWhiteSpace($custom)) { $OutDir = $custom.Trim() }
        }
    }

    NewDir $OutDir

    Add-Finding -Severity 'Info' -Category 'Runtime' -Title 'Analysis started' -EvidencePath $caseRoot -Evidence ('InputPath=' + $InputPath) -Recommendation 'Review findings, validate against baselines, and correlate across categories.'

    Invoke-Safely -Name 'RunInfoBasics' -Block { Analyze-RunInfoBasics -Meta $script:Meta }
    Invoke-Safely -Name 'ToolsInventory' -Block { Analyze-ToolsInventory -Meta $script:Meta }

    Invoke-Safely -Name 'DefenderExclusions' -Block { Analyze-DefenderExclusions -CaseRoot $caseRoot }
    Invoke-Safely -Name 'UAC' -Block { Analyze-UAC -CaseRoot $caseRoot }
    Invoke-Safely -Name 'Firewall' -Block { Analyze-Firewall -CaseRoot $caseRoot }
    Invoke-Safely -Name 'AuditPolicy' -Block { Analyze-AuditPolicy -CaseRoot $caseRoot }

    Invoke-Safely -Name 'WMI_Subscriptions' -Block { Analyze-WMI-Subscriptions -CaseRoot $caseRoot }
    Invoke-Safely -Name 'RunKeys_Winlogon' -Block { Analyze-RunKeysAndWinlogon -CaseRoot $caseRoot }
    Invoke-Safely -Name 'ScheduledTasks' -Block { Analyze-ScheduledTasks -CaseRoot $caseRoot }
    Invoke-Safely -Name 'Services' -Block { Analyze-Services -CaseRoot $caseRoot }

    Invoke-Safely -Name 'AutorunsCSV' -Block { Analyze-AutorunsCsv -CaseRoot $caseRoot }
    Invoke-Safely -Name 'SigcheckOutput' -Block { Analyze-SigcheckOutput -CaseRoot $caseRoot }

    Invoke-Safely -Name 'NetworkConnections' -Block { Analyze-NetworkConnections -CaseRoot $caseRoot }
    Invoke-Safely -Name 'DNSCache' -Block { Analyze-DnsCache -CaseRoot $caseRoot }
    Invoke-Safely -Name 'SuspiciousFileListings' -Block { Analyze-SuspiciousFileListings -CaseRoot $caseRoot }

    Invoke-Safely -Name 'PowerShellOperationalText' -Block { Analyze-PowerShellOperationalText -CaseRoot $caseRoot }
    Invoke-Safely -Name 'DefenderEventsText' -Block { Analyze-DefenderEventsText -CaseRoot $caseRoot }

    Invoke-Safely -Name 'SIEM_SecurityEvents' -Block { Analyze-SIEM-SecurityEventsCsv -CaseRoot $caseRoot }

    $baselineRoot = ''
    if (-not [string]::IsNullOrWhiteSpace($BaselinePath)) {
        $baselineRoot = Resolve-CaseRoot -Path $BaselinePath -AutoExtract:$AutoExtractZip
    }

    Invoke-Safely -Name 'InstalledPrograms' -Block { Analyze-InstalledPrograms -CaseRoot $caseRoot -BaselineRoot $baselineRoot }
    Invoke-Safely -Name 'BrowserExtensions' -Block { Analyze-BrowserExtensions -CaseRoot $caseRoot -BaselineRoot $baselineRoot }
    Invoke-Safely -Name 'RegistryIndicators' -Block { Analyze-RegistryIndicators -CaseRoot $caseRoot }
    Invoke-Safely -Name 'LocalAccounts' -Block { Analyze-LocalAccounts -CaseRoot $caseRoot -BaselineRoot $baselineRoot }
    Invoke-Safely -Name 'UnsignedDrivers' -Block { Analyze-UnsignedDrivers -CaseRoot $caseRoot }

    if ($ParseEvtx) {
        Invoke-Safely -Name 'EVTX' -Block { Analyze-EVTX -CaseRoot $caseRoot }
    }

    if (-not [string]::IsNullOrWhiteSpace($baselineRoot)) {
        Invoke-Safely -Name 'BaselineDiff' -Block { Analyze-BaselineDiff -Meta $script:Meta -BaselineRoot $baselineRoot }
    }

    $exported = Export-Findings -OutDir $OutDir

    Write-Host ''
    Write-Host '================================================================================' -ForegroundColor Green
    Write-Host '                 iKARUS OUTPUT ANALYSIS COMPLETE' -ForegroundColor Green
    Write-Host '================================================================================' -ForegroundColor Green
    Write-Host ('Case Root: {0}' -f $caseRoot) -ForegroundColor White
    Write-Host ('Output:    {0}' -f $OutDir) -ForegroundColor White
    Write-Host ('Report:    {0}' -f $exported.ReportMarkdown) -ForegroundColor White
    Write-Host ('CSV:       {0}' -f $exported.FindingsCsv) -ForegroundColor White
    Write-Host ('JSON:      {0}' -f $exported.FindingsJson) -ForegroundColor White
    Write-Host '================================================================================' -ForegroundColor Green

    if ($Interactive) {
        $open = Ask-YesNo -Prompt 'Open output folder now?' -Default 'Y'
        if ($open) {
            try { Start-Process -FilePath 'explorer.exe' -ArgumentList @("$OutDir") | Out-Null } catch { }
            $openReport = Ask-YesNo -Prompt 'Open report file now?' -Default 'Y'
            if ($openReport) {
                try { Start-Process -FilePath "$($exported.ReportMarkdown)" | Out-Null } catch { }
            }
        }
    }
}

Run-Analyzer
