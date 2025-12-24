param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [string]$OutDir = "",
    [string]$BaselinePath = "",
    [switch]$ParseEvtx,
    [int]$MaxFindingsPerSource = 200,
    [int]$MaxTableRows = 200,
    [switch]$AutoExtractZip = $true
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function NewDir([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return }
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Get-NowIso() { (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }

function Read-Lines([string]$Path, [int]$MaxLines) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        $lines.Add($line)
        $i++
        if ($MaxLines -gt 0 -and $i -ge $MaxLines) { break }
    }
    return $lines.ToArray()
}

function Get-FileText([string]$Path, [int]$MaxChars) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    try {
        $t = [System.IO.File]::ReadAllText($Path)
        if ($MaxChars -gt 0 -and $t.Length -gt $MaxChars) { return $t.Substring(0, $MaxChars) }
        return $t
    } catch { return "" }
}

$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [ValidateSet("Critical","High","Medium","Low","Info")][string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$EvidencePath,
        [string]$Evidence,
        [string]$Recommendation
    )

    $rank = 0
    switch ($Severity) {
        "Critical" { $rank = 4 }
        "High" { $rank = 3 }
        "Medium" { $rank = 2 }
        "Low" { $rank = 1 }
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

function Resolve-CaseRoot {
    param([string]$Path, [switch]$AutoExtract)

    if (Test-Path -LiteralPath $Path -PathType Container) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $ext = ([System.IO.Path]::GetExtension($Path)).ToLowerInvariant()
        if ($ext -eq ".zip" -and $AutoExtract) {
            $base = Join-Path ([System.IO.Path]::GetTempPath()) ("ikarus_case_" + [guid]::NewGuid().ToString())
            NewDir $base
            try {
                Expand-Archive -LiteralPath $Path -DestinationPath $base -Force
            } catch {
                throw "Failed to extract zip: $Path"
            }

            $candidates = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue
            if ($candidates.Count -eq 1) { return $candidates[0].FullName }
            return $base
        }
        throw "InputPath is a file, but not a zip. Provide a folder path or a zip."
    }

    throw "InputPath not found: $Path"
}

function Get-CaseMeta {
    param([string]$CaseRoot)

    $meta = [ordered]@{
        CaseRoot = $CaseRoot
        RunInfoPath = (Join-Path $CaseRoot "meta\run_info.txt")
        TranscriptPath = (Join-Path $CaseRoot "meta\transcript.txt")
        ToolsInventoryPath = (Join-Path $CaseRoot "meta\tools_inventory.csv")
        ShaManifestPath = (Join-Path $CaseRoot "meta\sha256_manifest.csv")
        IOCSummaryPath = (Join-Path $CaseRoot "meta\ioc_summary.txt")
        Hostname = ""
        CollectedAt = ""
        Mode = ""
        TimeframeDays = ""
        ToolsPolicy = ""
        ToolsAvailable = ""
    }

    if (Test-Path -LiteralPath $meta.RunInfoPath) {
        foreach ($line in [System.IO.File]::ReadLines($meta.RunInfoPath)) {
            if ($line -match "^\s*Computer:\s*(.+)\s*$") { $meta.Hostname = $Matches[1].Trim(); continue }
            if ($line -match "^\s*Collection Time:\s*(.+)\s*$") { $meta.CollectedAt = $Matches[1].Trim(); continue }
            if ($line -match "^\s*Mode:\s*(.+)\s*$") { $meta.Mode = $Matches[1].Trim(); continue }
            if ($line -match "^\s*Timeframe:\s*(\d+)\s*days\s*$") { $meta.TimeframeDays = $Matches[1].Trim(); continue }
            if ($line -match "^\s*Tools Policy:\s*(.+)\s*$") { $meta.ToolsPolicy = $Matches[1].Trim(); continue }
            if ($line -match "^\s*Tools Available:\s*(.+)\s*$") { $meta.ToolsAvailable = $Matches[1].Trim(); continue }
        }
    }

    return [pscustomobject]$meta
}

function Find-RegexHitsInFile {
    param(
        [string]$Path,
        [string[]]$Regexes,
        [int]$MaxHits
    )

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
        "(?i)\b(powershell|pwsh)\b.*\s(-enc|-encodedcommand)\b",
        "(?i)\b(powershell|pwsh)\b.*\s(-w\s+hidden|-windowstyle\s+hidden)\b",
        "(?i)\bIEX\b|\bInvoke-Expression\b",
        "(?i)\bDownloadString\b|\bWebClient\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b",
        "(?i)\bbitsadmin\b|\bcertutil\b\s+.*-urlcache\b|\bcurl\b|\bwget\b",
        "(?i)\bmshta\b|\brundll32\b|\bregsvr32\b|\bwscript\b|\bcscript\b",
        "(?i)\bschtasks\b\s+/(create|change|run)\b",
        "(?i)\bwmic\b\s+process\b\s+call\b\s+create\b",
        "(?i)\bnet\b\s+(user|localgroup|use|share)\b",
        "(?i)\b(nltest|dsquery|dsget)\b",
        "(?i)\bprocdump\b|\brubeus\b|\bmimikatz\b|\bsecretsdump\b"
    )
}

function Get-SuspiciousPathRegexes {
    return @(
        "(?i)\\Users\\Public\\",
        "(?i)\\ProgramData\\",
        "(?i)\\Windows\\Temp\\",
        "(?i)\\Temp\\",
        "(?i)\\AppData\\(Roaming|Local)\\",
        "(?i)\\PerfLogs\\"
    )
}

function Get-SuspiciousExtensionsRegex {
    return "(?i)\.(exe|dll|sys|ps1|vbs|bat|cmd|js|jse|hta|lnk|msi|msp|iso|img|vhd|vhdx|zip|7z|rar)\b"
}

function Analyze-ToolsInventory {
    param([pscustomobject]$Meta)

    if (-not (Test-Path -LiteralPath $Meta.ToolsInventoryPath -PathType Leaf)) { return }

    try {
        $rows = Import-Csv -LiteralPath $Meta.ToolsInventoryPath
        $missing = @($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.ResolvedPath) })
        if ($missing.Count -gt 0) {
            Add-Finding -Severity "Low" -Category "Coverage" -Title ("Missing third-party tools: " + (($missing.Tool | Select-Object -Unique) -join ", ")) -EvidencePath $Meta.ToolsInventoryPath -Evidence ("Missing count: " + $missing.Count) -Recommendation "If policy allows, stage missing tools in ToolsDir or enable AutoDownloadTools for full coverage."
        }
    } catch {}
}

function Analyze-RunInfoBasics {
    param([pscustomobject]$Meta)

    if (-not (Test-Path -LiteralPath $Meta.RunInfoPath -PathType Leaf)) { return }

    $t = Get-FileText -Path $Meta.RunInfoPath -MaxChars 4000
    if ($t -match "(?i)OfflineOnly:\s*True" -and $t -match "(?i)AutoDownloadTools:\s*True") {
        Add-Finding -Severity "Info" -Category "Runtime" -Title "Both OfflineOnly and AutoDownloadTools appear enabled" -EvidencePath $Meta.RunInfoPath -Evidence "Check run_info toggle values" -Recommendation "Confirm intended tools policy selection during execution."
    }

    if ($t -match "(?i)IncludeMemoryDump:\s*True") {
        Add-Finding -Severity "Info" -Category "Runtime" -Title "Memory acquisition was requested" -EvidencePath $Meta.RunInfoPath -Evidence "IncludeMemoryDump: True" -Recommendation "If memory image exists under memory/, consider volatile artifact analysis with appropriate tooling."
    }
}

function Analyze-DefenderExclusions {
    param([string]$CaseRoot)

    $p1 = Join-Path $CaseRoot "security\defender_exclusions.txt"
    $p2 = Join-Path $CaseRoot "siem\DefenderExclusions.csv"
    $values = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $p2 -PathType Leaf) {
        try {
            $rows = Import-Csv -LiteralPath $p2
            foreach ($r in $rows) {
                if ($r.Value -and $r.Value.Trim().Length -gt 0) { $values.Add(($r.Type + ": " + $r.Value)) | Out-Null }
            }
        } catch {}
    } elseif (Test-Path -LiteralPath $p1 -PathType Leaf) {
        $text = Get-FileText -Path $p1 -MaxChars 200000
        if ($text -match "(?i)ExclusionPath:\s*[\r\n]+([^\r\n]+)") { $values.Add(("ExclusionPath: " + $Matches[1].Trim())) | Out-Null }
        if ($text -match "(?i)ExclusionProcess:\s*[\r\n]+([^\r\n]+)") { $values.Add(("ExclusionProcess: " + $Matches[1].Trim())) | Out-Null }
        if ($text -match "(?i)ExclusionExtension:\s*[\r\n]+([^\r\n]+)") { $values.Add(("ExclusionExtension: " + $Matches[1].Trim())) | Out-Null }
    }

    $joined = ($values | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -Unique) -join " | "
    if (-not [string]::IsNullOrWhiteSpace($joined)) {
        Add-Finding -Severity "High" -Category "Security Controls" -Title "Windows Defender exclusions detected" -EvidencePath ($(if (Test-Path $p2) { $p2 } else { $p1 })) -Evidence $joined -Recommendation "Review exclusions for legitimacy. Excessive or broad exclusions are commonly abused by malware."
    }
}

function Analyze-UAC {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "security\uac_settings.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
    $t = Get-FileText -Path $p -MaxChars 50000

    if ($t -match "(?i)EnableLUA\s+REG_DWORD\s+0x0") {
        Add-Finding -Severity "Medium" -Category "Security Controls" -Title "UAC appears disabled (EnableLUA=0)" -EvidencePath $p -Evidence "EnableLUA=0" -Recommendation "Confirm if UAC is intentionally disabled. Disabling UAC increases abuse surface for local privilege escalation and lateral movement."
    }
}

function Analyze-Firewall {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "security\firewall_status.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
    $t = Get-FileText -Path $p -MaxChars 120000

    $disabled = @()
    if ($t -match "(?i)Domain Profile Settings[\s\S]*?State\s+OFF") { $disabled += "Domain" }
    if ($t -match "(?i)Private Profile Settings[\s\S]*?State\s+OFF") { $disabled += "Private" }
    if ($t -match "(?i)Public Profile Settings[\s\S]*?State\s+OFF") { $disabled += "Public" }

    if ($disabled.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "Security Controls" -Title ("Windows Firewall disabled: " + ($disabled -join ", ")) -EvidencePath $p -Evidence ("Profiles OFF: " + ($disabled -join ", ")) -Recommendation "Validate firewall policy compliance and investigate any unauthorized changes."
    }
}

function Analyze-AuditPolicy {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "security\auditpol.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 5000
    $weak = New-Object System.Collections.Generic.List[string]

    foreach ($l in $lines) {
        if ($l -match "(?i)Logon/Logoff" -or $l -match "(?i)Account Logon" -or $l -match "(?i)Account Management") {
            if ($l -match "(?i)\bNo Auditing\b") { $weak.Add($l.Trim()) | Out-Null }
        }
    }

    if ($weak.Count -gt 0) {
        Add-Finding -Severity "Low" -Category "Logging" -Title "Potentially weak audit policy settings detected" -EvidencePath $p -Evidence (($weak | Select-Object -First 12) -join " ; ") -Recommendation "Ensure key audit categories (logon, account management, process creation) are enabled per baseline policy."
    }
}

function Get-CsvRowsSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    try { return (Import-Csv -LiteralPath $Path) } catch { return @() }
}

function Normalize-Whitespace([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    return ($s -replace "\s+", " ").Trim()
}

function Analyze-WMI-Subscriptions {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "persistence\wmi_subscriptions.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $t = Get-FileText -Path $p -MaxChars 500000
    if ([string]::IsNullOrWhiteSpace($t)) { return }

    $susp = @()
    $rxCmd = Get-SuspiciousCommandRegexes
    foreach ($r in $rxCmd) {
        if ($t -match $r) {
            $susp += $r
            if ($susp.Count -ge 8) { break }
        }
    }

    if ($t -match "(?i)__EventFilter" -and $t -match "(?i)CommandLineEventConsumer") {
        $sev = "Medium"
        if ($susp.Count -gt 0) { $sev = "High" }
        Add-Finding -Severity $sev -Category "Persistence" -Title "WMI event subscription artifacts present" -EvidencePath $p -Evidence ("WMI subscription objects present. Indicators: " + (($susp | Select-Object -Unique) -join ", ")) -Recommendation "WMI permanent event subscriptions are high-value persistence. Review consumers, filters, and command lines for legitimacy."
    }
}

function Analyze-RunKeysAndWinlogon {
    param([string]$CaseRoot)

    $p1 = Join-Path $CaseRoot "persistence\run_hklm.txt"
    $p2 = Join-Path $CaseRoot "persistence\run_hkcu.txt"
    $p3 = Join-Path $CaseRoot "persistence\winlogon_keys.txt"

    $rxCmd = Get-SuspiciousCommandRegexes
    $rxExt = Get-SuspiciousExtensionsRegex
    $rxPath = Get-SuspiciousPathRegexes

    foreach ($p in @($p1,$p2,$p3)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $hits = Find-RegexHitsInFile -Path $p -Regexes $rxCmd -MaxHits $MaxFindingsPerSource
        if ($hits.Count -gt 0) {
            $ev = ($hits | Select-Object -First 10 | ForEach-Object { ("L" + $_.LineNo + ":" + (Normalize-Whitespace $_.Line)) }) -join " | "
            Add-Finding -Severity "High" -Category "Persistence" -Title ("Suspicious command patterns in persistence keys (" + (Split-Path -Leaf $p) + ")") -EvidencePath $p -Evidence $ev -Recommendation "Review referenced binaries/scripts and validate registry autoruns against known-good baseline."
            continue
        }

        $lines = Read-Lines -Path $p -MaxLines 8000
        $s = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            if ($l -match $rxExt) {
                foreach ($r in $rxPath) {
                    if ($l -match $r) { $s.Add(Normalize-Whitespace $l) | Out-Null; break }
                }
            }
            if ($s.Count -ge 12) { break }
        }

        if ($s.Count -gt 0) {
            Add-Finding -Severity "Medium" -Category "Persistence" -Title ("Executable/script references in high-risk locations within " + (Split-Path -Leaf $p)) -EvidencePath $p -Evidence (($s | Select-Object -First 12) -join " ; ") -Recommendation "Validate autorun entries pointing to AppData/Temp/ProgramData/Public. Investigate unknown publishers and recent write times."
        }
    }
}

function Analyze-ScheduledTasks {
    param([string]$CaseRoot)

    $p1 = Join-Path $CaseRoot "process\scheduledtasks_list_v.txt"
    $p2 = Join-Path $CaseRoot "persistence\scheduled_tasks_summary.txt"
    $p = $null
    if (Test-Path -LiteralPath $p1 -PathType Leaf) { $p = $p1 }
    elseif (Test-Path -LiteralPath $p2 -PathType Leaf) { $p = $p2 }
    else { return }

    $rxCmd = Get-SuspiciousCommandRegexes
    $hits = Find-RegexHitsInFile -Path $p -Regexes $rxCmd -MaxHits $MaxFindingsPerSource
    if ($hits.Count -gt 0) {
        $ev = ($hits | Select-Object -First 12 | ForEach-Object { ("L" + $_.LineNo + ":" + (Normalize-Whitespace $_.Line)) }) -join " | "
        Add-Finding -Severity "High" -Category "Persistence" -Title "Suspicious command patterns inside scheduled tasks output" -EvidencePath $p -Evidence $ev -Recommendation "Review task actions, triggers, authors, and creation times. Confirm if tasks map to approved software."
        return
    }

    $lines = Read-Lines -Path $p -MaxLines 15000
    $odd = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match "(?i)\\Users\\Public\\|\\ProgramData\\|\\Windows\\Temp\\|\\AppData\\") {
            $odd.Add(Normalize-Whitespace $l) | Out-Null
        }
        if ($odd.Count -ge 18) { break }
    }

    if ($odd.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "Persistence" -Title "Scheduled task references to high-risk file system locations" -EvidencePath $p -Evidence (($odd | Select-Object -First 16) -join " ; ") -Recommendation "Validate tasks that execute from user-writable directories. Correlate with recent file drops and process creation telemetry."
    }
}

function Analyze-Services {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "process\services_detailed.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 40000
    $rxExt = Get-SuspiciousExtensionsRegex
    $rxPath = Get-SuspiciousPathRegexes

    $sus = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match "(?i)PathName" -or $l -match "(?i)StartName" -or $l -match "(?i)Name") { continue }
        if ($l -match $rxExt) {
            foreach ($r in $rxPath) {
                if ($l -match $r) {
                    $sus.Add(Normalize-Whitespace $l) | Out-Null
                    break
                }
            }
        }
        if ($sus.Count -ge 20) { break }
    }

    if ($sus.Count -gt 0) {
        Add-Finding -Severity "High" -Category "Persistence" -Title "Service binary paths point to high-risk locations" -EvidencePath $p -Evidence (($sus | Select-Object -First 18) -join " ; ") -Recommendation "Investigate services running binaries from user-writable paths (AppData/Temp/ProgramData/Public). Validate signer, install time, and service creation events."
    }
}

function Analyze-AutorunsCsv {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "third_party_analysis\autoruns_output.csv"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $rows = @()
    try { $rows = Import-Csv -LiteralPath $p } catch { $rows = @() }
    if (-not $rows -or $rows.Count -eq 0) { return }

    $rxPath = Get-SuspiciousPathRegexes
    $rxExt = Get-SuspiciousExtensionsRegex
    $rxCmd = Get-SuspiciousCommandRegexes

    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        $img = ""
        $cmd = ""
        $loc = ""
        try { $img = [string]$r.ImagePath } catch { $img = "" }
        try { $cmd = [string]$r.LaunchString } catch { $cmd = "" }
        try { $loc = [string]$r.Location } catch { $loc = "" }

        $s = ($img + " " + $cmd + " " + $loc)
        if ([string]::IsNullOrWhiteSpace($s)) { continue }

        $flag = $false
        foreach ($x in $rxCmd) { if ($s -match $x) { $flag = $true; break } }
        if (-not $flag -and ($s -match $rxExt)) {
            foreach ($p0 in $rxPath) { if ($s -match $p0) { $flag = $true; break } }
        }

        if ($flag) {
            $line = Normalize-Whitespace ($loc + " | " + $img + " | " + $cmd)
            if ($line.Length -gt 360) { $line = $line.Substring(0, 360) + "..." }
            $hits.Add($line) | Out-Null
        }

        if ($hits.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($hits.Count -gt 0) {
        Add-Finding -Severity "High" -Category "Persistence" -Title "Autoruns: suspicious entries (high-risk paths / commands)" -EvidencePath $p -Evidence (($hits | Select-Object -First 15) -join " ; ") -Recommendation "Review Autoruns entries for unsigned or recently created binaries in user-writable paths. Validate publisher and compare with baseline autoruns."
    }
}

function Analyze-SigcheckOutput {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "third_party_analysis\sigcheck_output.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $lines = Read-Lines -Path $p -MaxLines 50000
    $sus = New-Object System.Collections.Generic.List[string]

    foreach ($l in $lines) {
        if ($l -match "(?i)\bUnsigned\b") { $sus.Add(Normalize-Whitespace $l) | Out-Null; continue }
        if ($l -match "(?i)\bNot Verified\b") { $sus.Add(Normalize-Whitespace $l) | Out-Null; continue }
        if ($l -match "(?i)\bUnknown Publisher\b") { $sus.Add(Normalize-Whitespace $l) | Out-Null; continue }
        if ($l -match "(?i)\bReputation\b") { $sus.Add(Normalize-Whitespace $l) | Out-Null; continue }
        if ($sus.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($sus.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "File Trust" -Title "Sigcheck: unsigned / unverified files observed" -EvidencePath $p -Evidence (($sus | Select-Object -First 20) -join " ; ") -Recommendation "Validate unsigned binaries found in scan scope. Prioritize those in Temp/AppData/ProgramData/Public and those with recent write times."
    }
}

function Analyze-NetworkConnections {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "siem\OpenTCPConnections.csv"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        $p2 = Join-Path $CaseRoot "network\netstat_abno.txt"
        if (-not (Test-Path -LiteralPath $p2 -PathType Leaf)) { return }

        $lines = Read-Lines -Path $p2 -MaxLines 20000
        $sus = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            if ($l -match "(?i)\bESTABLISHED\b" -and $l -match "(?i)\b:3389\b|\b:5985\b|\b:5986\b|\b:445\b|\b:139\b") {
                $sus.Add(Normalize-Whitespace $l) | Out-Null
            }
            if ($sus.Count -ge 30) { break }
        }
        if ($sus.Count -gt 0) {
            Add-Finding -Severity "Low" -Category "Network" -Title "Netstat indicates established sessions on admin/service ports (sampling)" -EvidencePath $p2 -Evidence (($sus | Select-Object -First 20) -join " ; ") -Recommendation "Correlate established admin-port sessions with expected remote management activity and user logons."
        }
        return
    }

    $rows = Get-CsvRowsSafe -Path $p
    if (-not $rows -or $rows.Count -eq 0) { return }

    $external = New-Object System.Collections.Generic.List[string]
    $procCount = @{}

    foreach ($r in $rows) {
        $state = [string]$r.State
        if ($state -ne "Established") { continue }
        $ra = [string]$r.RemoteAddress
        if ([string]::IsNullOrWhiteSpace($ra)) { continue }
        if ($ra -eq "127.0.0.1" -or $ra -eq "::1") { continue }
        if ($ra -match "^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)") { continue }

        $pn = [string]$r.ProcessName
        if ([string]::IsNullOrWhiteSpace($pn)) { $pn = ("PID_" + [string]$r.OwningProcess) }
        if (-not $procCount.ContainsKey($pn)) { $procCount[$pn] = 0 }
        $procCount[$pn] = [int]$procCount[$pn] + 1

        $line = ($pn + " -> " + $ra + ":" + [string]$r.RemotePort)
        $external.Add($line) | Out-Null
        if ($external.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($external.Count -gt 0) {
        $topProc = $procCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { ($_.Key + "=" + $_.Value) }
        Add-Finding -Severity "Medium" -Category "Network" -Title "External established connections detected" -EvidencePath $p -Evidence (("Top processes: " + (($topProc -join ", "))) + " | Samples: " + (($external | Select-Object -First 15) -join " ; ")) -Recommendation "Validate external connections. Confirm process legitimacy and cross-check with DNS cache and execution/persistence artifacts."
    }
}

function Analyze-DnsCache {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "siem\DNSCache.csv"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        $p2 = Join-Path $CaseRoot "network\dns_cache.txt"
        if (-not (Test-Path -LiteralPath $p2 -PathType Leaf)) { return }

        $lines = Read-Lines -Path $p2 -MaxLines 15000
        $susp = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            if ($l -match "(?i)\b(update|paste|cdn|raw|git|discord|telegram|ngrok|tunnel|duckdns|no-ip|dyn)\b") {
                $susp.Add(Normalize-Whitespace $l) | Out-Null
            }
            if ($susp.Count -ge 30) { break }
        }
        if ($susp.Count -gt 0) {
            Add-Finding -Severity "Low" -Category "Network" -Title "DNS cache includes potentially suspicious domains (keyword match)" -EvidencePath $p2 -Evidence (($susp | Select-Object -First 18) -join " ; ") -Recommendation "Review resolved domains for legitimacy. Correlate with browser artifacts and process/network telemetry."
        }
        return
    }

    $rows = Get-CsvRowsSafe -Path $p
    if (-not $rows -or $rows.Count -eq 0) { return }

    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        $name = [string]$r.Name
        $data = [string]$r.Data
        $line = ($name + " -> " + $data)
        if ($line -match "(?i)\b(ngrok|duckdns|no-ip|dyn|paste|raw\.github|discord|telegram|tunnel)\b") {
            $hits.Add($line) | Out-Null
        }
        if ($hits.Count -ge $MaxFindingsPerSource) { break }
    }

    if ($hits.Count -gt 0) {
        Add-Finding -Severity "Low" -Category "Network" -Title "DNS cache contains domains commonly used in tooling/C2 (keyword match)" -EvidencePath $p -Evidence (($hits | Select-Object -First 20) -join " ; ") -Recommendation "Validate suspicious domains and consider blocking/containment if unauthorized. Correlate with connection logs and suspicious executions."
    }
}

function Analyze-SuspiciousFileListings {
    param([string]$CaseRoot)

    $dir = Join-Path $CaseRoot "file_listings"
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return }

    $csvs = Get-ChildItem -LiteralPath $dir -File -Filter "*_recent_suspicious.csv" -ErrorAction SilentlyContinue
    if (-not $csvs -or $csvs.Count -eq 0) { return }

    $rxCmd = Get-SuspiciousCommandRegexes
    $finds = New-Object System.Collections.Generic.List[string]

    foreach ($c in $csvs) {
        $rows = Get-CsvRowsSafe -Path $c.FullName
        foreach ($r in $rows) {
            $path = [string]$r.Path
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $line = $path
            $flag = $false
            foreach ($x in $rxCmd) { if ($line -match $x) { $flag = $true; break } }
            if ($path -match "(?i)\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\") { $flag = $true }
            if ($flag) { $finds.Add($path) | Out-Null }
            if ($finds.Count -ge $MaxFindingsPerSource) { break }
        }
        if ($finds.Count -ge $MaxFindingsPerSource) { break }
    }

    $uniq = $finds | Where-Object { $_ } | Select-Object -Unique
    if ($uniq.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "File Drops" -Title "Recent suspicious file extensions observed in high-risk directories (listings)" -EvidencePath $dir -Evidence (($uniq | Select-Object -First $MaxTableRows) -join " ; ") -Recommendation "Triage newly written executables/scripts. Validate signer, hash, and correlate with autoruns/tasks/services and process creation events."
    }
}

function Analyze-PowerShellOperationalText {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "enhanced_artifacts\powershell_op_recent.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $rx = Get-SuspiciousCommandRegexes
    $hits = Find-RegexHitsInFile -Path $p -Regexes $rx -MaxHits $MaxFindingsPerSource
    if ($hits.Count -gt 0) {
        $ev = ($hits | Select-Object -First 12 | ForEach-Object { ("L" + $_.LineNo + ":" + (Normalize-Whitespace $_.Line)) }) -join " | "
        Add-Finding -Severity "High" -Category "Execution" -Title "Suspicious PowerShell patterns in Operational log text export" -EvidencePath $p -Evidence $ev -Recommendation "Investigate suspicious PowerShell usage (encoded commands, IEX, web download). Correlate with 4688, network connections, and user sessions."
    }
}

function Analyze-DefenderEventsText {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "enhanced_artifacts\defender_recent_events.txt"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $t = Get-FileText -Path $p -MaxChars 600000
    if ([string]::IsNullOrWhiteSpace($t)) { return }

    if ($t -match "(?i)\b(Threat|Malware|Detected|Quarantined|Remediation|Blocked)\b") {
        $sample = ""
        $lines = Read-Lines -Path $p -MaxLines 6000
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($l in $lines) {
            if ($l -match "(?i)\b(Threat|Malware|Detected|Quarantined|Remediation|Blocked)\b") {
                $hits.Add(Normalize-Whitespace $l) | Out-Null
            }
            if ($hits.Count -ge 18) { break }
        }
        if ($hits.Count -gt 0) { $sample = ($hits | Select-Object -First 12) -join " ; " }
        Add-Finding -Severity "Info" -Category "Security Controls" -Title "Windows Defender operational events indicate detections/blocks (keyword match)" -EvidencePath $p -Evidence $sample -Recommendation "If detections occurred, extract full details, affected paths/hashes, and correlate with persistence and execution artifacts."
    }
}

function Analyze-SIEM-SecurityEventsCsv {
    param([string]$CaseRoot)

    $p = Join-Path $CaseRoot "siem\SecurityEvents.csv"
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
            $m = [string]$r.Message
            if (-not [string]::IsNullOrWhiteSpace($m)) {
                $flag = $false
                foreach ($x in $rx) { if ($m -match $x) { $flag = $true; break } }
                if ($flag) {
                    $s = Normalize-Whitespace $m
                    if ($s.Length -gt 220) { $s = $s.Substring(0, 220) + "..." }
                    $cmd.Add($s) | Out-Null
                }
            }
        }

        if ($cmd.Count -ge 30) { break }
    }

    if ($cnt4625 -gt 25) {
        Add-Finding -Severity "Medium" -Category "Authentication" -Title "Multiple failed logons detected (4625)" -EvidencePath $p -Evidence ("4625 count (sample): " + $cnt4625) -Recommendation "Investigate brute force or password spraying. Identify source IPs, targeted accounts, and correlate with successful logons."
    }

    if ($cnt4672 -gt 0) {
        Add-Finding -Severity "Low" -Category "Privilege" -Title "Special privileges assigned to new logon sessions (4672) observed" -EvidencePath $p -Evidence ("4672 count (sample): " + $cnt4672) -Recommendation "Correlate privileged logons with admins and expected maintenance windows. Validate accounts and source hosts."
    }

    if ($cnt1102 -gt 0) {
        Add-Finding -Severity "High" -Category "Anti-Forensics" -Title "Security log clear events detected (1102)" -EvidencePath $p -Evidence ("1102 count (sample): " + $cnt1102) -Recommendation "Treat as suspicious. Determine who cleared logs and correlate with other privileged activity."
    }

    if ($cmd.Count -gt 0) {
        Add-Finding -Severity "High" -Category "Execution" -Title "SIEM SecurityEvents: suspicious process creation command-lines (4688 keyword match)" -EvidencePath $p -Evidence (($cmd | Select-Object -First 12) -join " ; ") -Recommendation "Review full command-lines and parent/child relationships. Correlate with persistence artifacts and outbound connections."
    }
}

function Analyze-EVTX {
    param([string]$CaseRoot)

    $securityEvtx = Join-Path $CaseRoot "eventlogs\Security.evtx"
    if (-not (Test-Path -LiteralPath $securityEvtx -PathType Leaf)) { return }

    try {
        $hasWevtutil = $true
        try { wevtutil el | Out-Null } catch { $hasWevtutil = $false }

        if (-not $hasWevtutil) {
            Add-Finding -Severity "Info" -Category "EVTX" -Title "EVTX parsing skipped (wevtutil unavailable)" -EvidencePath $securityEvtx -Evidence "wevtutil not available" -Recommendation "Use a system with wevtutil to parse EVTX or import into a forensic workstation/SIEM."
            return
        }

        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ikarus_evtx_" + [guid]::NewGuid().ToString() + ".txt")
        try {
            wevtutil qe $securityEvtx /f:text /c:2000 > $tmp
        } catch {}

        if (Test-Path -LiteralPath $tmp -PathType Leaf) {
            $text = Get-FileText -Path $tmp -MaxChars 800000
            try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}

            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $fail = ([regex]::Matches($text, "(?i)\bEvent ID:\s*4625\b")).Count
                $priv = ([regex]::Matches($text, "(?i)\bEvent ID:\s*4672\b")).Count
                $clear = ([regex]::Matches($text, "(?i)\bEvent ID:\s*1102\b")).Count

                if ($fail -gt 50) { Add-Finding -Severity "Medium" -Category "Authentication" -Title "EVTX parse: high failed logons (4625)" -EvidencePath $securityEvtx -Evidence ("4625 count (sample): " + $fail) -Recommendation "Investigate brute force/spray patterns. Correlate account names, source hosts, and time ranges." }
                if ($priv -gt 0) { Add-Finding -Severity "Low" -Category "Privilege" -Title "EVTX parse: privileged logons (4672) observed" -EvidencePath $securityEvtx -Evidence ("4672 count (sample): " + $priv) -Recommendation "Validate privileged logons against approved admin activity and expected endpoints." }
                if ($clear -gt 0) { Add-Finding -Severity "High" -Category "Anti-Forensics" -Title "EVTX parse: security log clear events detected (1102)" -EvidencePath $securityEvtx -Evidence ("1102 count (sample): " + $clear) -Recommendation "Treat as suspicious. Identify actor and correlate to privileged activity." }

                $rx = Get-SuspiciousCommandRegexes
                $cmdHits = New-Object System.Collections.Generic.List[string]
                try {
                    $events = Get-WinEvent -Path $securityEvtx -ErrorAction SilentlyContinue | Select-Object -First 2000
                    foreach ($e in ($events | Where-Object { $_.Id -eq 4688 })) {
                        $m = [string]$e.Message
                        if ([string]::IsNullOrWhiteSpace($m)) { continue }
                        $flag = $false
                        foreach ($x in $rx) { if ($m -match $x) { $flag = $true; break } }
                        if ($flag) {
                            $short = $m -replace "\s+", " "
                            if ($short.Length -gt 220) { $short = $short.Substring(0, 220) + "..." }
                            $cmdHits.Add($short) | Out-Null
                        }
                        if ($cmdHits.Count -ge 30) { break }
                    }
                } catch {}

                if ($cmdHits.Count -gt 0) {
                    Add-Finding -Severity "High" -Category "Execution" -Title "EVTX parse: suspicious process creation patterns (4688)" -EvidencePath $securityEvtx -Evidence (($cmdHits | Select-Object -First 12) -join " ; ") -Recommendation "Review full 4688 command lines and correlate with parent processes and network activity."
                }
            }
        }
    } catch {}
}

function Load-ManifestMap {
    param([string]$ManifestCsvPath)

    $map = @{}
    if (-not (Test-Path -LiteralPath $ManifestCsvPath -PathType Leaf)) { return $map }
    try { $rows = Import-Csv -LiteralPath $ManifestCsvPath } catch { return $map }
    foreach ($r in $rows) {
        $p = [string]$r.Path
        $h = [string]$r.SHA256
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

    $baselineManifest = Join-Path $BaselineRoot "meta\sha256_manifest.csv"
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
        Add-Finding -Severity "High" -Category "Change Detection" -Title "Files changed since baseline in high-risk locations (manifest diff)" -EvidencePath $Meta.ShaManifestPath -Evidence (($changedRisk | Select-Object -First $MaxTableRows) -join " ; ") -Recommendation "Investigate modified binaries/scripts in high-risk directories. Validate hashes, signatures, and provenance."
    }

    if ($addedRisk.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "Change Detection" -Title "New files since baseline in high-risk locations (manifest diff)" -EvidencePath $Meta.ShaManifestPath -Evidence (($addedRisk | Select-Object -First $MaxTableRows) -join " ; ") -Recommendation "Review newly introduced files in AppData/Temp/ProgramData/Public. Correlate timestamps with user activity and execution logs."
    }
}

function Build-ReportMarkdown {
    param([pscustomobject]$Meta, [string]$ReportPath)

    $counts = $script:Findings | Group-Object Severity | ForEach-Object { [pscustomobject]@{ Severity = $_.Name; Count = $_.Count } }
    $byCat = $script:Findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Category = $_.Name; Count = $_.Count } }

    $top = $script:Findings | Sort-Object SeverityRank -Descending | Select-Object -First 80

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add("# iKarus Collection Output Analysis 🧠🔎") | Out-Null
    $md.Add("") | Out-Null
    $md.Add(("Generated: " + (Get-NowIso()))) | Out-Null
    $md.Add(("Case Root: " + $Meta.CaseRoot)) | Out-Null
    if ($Meta.Hostname) { $md.Add(("Host: " + $Meta.Hostname)) | Out-Null }
    if ($Meta.CollectedAt) { $md.Add(("Collected At: " + $Meta.CollectedAt)) | Out-Null }
    if ($Meta.Mode) { $md.Add(("Mode: " + $Meta.Mode)) | Out-Null }
    if ($Meta.TimeframeDays) { $md.Add(("Timeframe (days): " + $Meta.TimeframeDays)) | Out-Null }
    if ($Meta.ToolsPolicy) { $md.Add(("Tools Policy: " + $Meta.ToolsPolicy)) | Out-Null }
    $md.Add("") | Out-Null

    $md.Add("## Summary 📌") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("### Findings by Severity") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("| Severity | Count |") | Out-Null
    $md.Add("|---|---:|") | Out-Null
    foreach ($c in @("Critical","High","Medium","Low","Info")) {
        $n = 0
        $hit = $counts | Where-Object { $_.Severity -eq $c } | Select-Object -First 1
        if ($hit) { $n = $hit.Count }
        $md.Add(("| " + $c + " | " + $n + " |")) | Out-Null
    }
    $md.Add("") | Out-Null

    $md.Add("### Findings by Category") | Out-Null
    $md.Add("") | Out-Null
    $md.Add("| Category | Count |") | Out-Null
    $md.Add("|---|---:|") | Out-Null
    foreach ($c in ($byCat | Select-Object -First 15)) {
        $md.Add(("| " + $c.Category + " | " + $c.Count + " |")) | Out-Null
    }
    $md.Add("") | Out-Null

    $md.Add("## Top Findings 🚩") | Out-Null
    $md.Add("") | Out-Null
    foreach ($f in $top) {
        $md.Add(("### " + $f.Severity + " — " + $f.Title)) | Out-Null
        $md.Add("") | Out-Null
        if ($f.Category) { $md.Add(("*Category:* " + $f.Category)) | Out-Null }
        if ($f.EvidencePath) { $md.Add(("*Evidence Path:* " + $f.EvidencePath)) | Out-Null }
        if ($f.Evidence) { $md.Add(("*Evidence:* " + $f.Evidence)) | Out-Null }
        if ($f.Recommendation) { $md.Add(("*Recommendation:* " + $f.Recommendation)) | Out-Null }
        $md.Add("") | Out-Null
    }

    [System.IO.File]::WriteAllLines($ReportPath, $md.ToArray(), [System.Text.Encoding]::UTF8)
}

function Export-Findings {
    param([string]$OutDir)

    NewDir $OutDir
    $csv = Join-Path $OutDir "findings.csv"
    $json = Join-Path $OutDir "findings.json"
    $md = Join-Path $OutDir "analysis_report.md"

    $script:Findings | Sort-Object SeverityRank -Descending, Category, Title | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8 -Force
    $script:Findings | Sort-Object SeverityRank -Descending, Category, Title | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $json -Encoding UTF8 -Force
    Build-ReportMarkdown -Meta $script:Meta -ReportPath $md

    return [pscustomobject]@{
        FindingsCsv = $csv
        FindingsJson = $json
        ReportMarkdown = $md
    }
}

$caseRoot = Resolve-CaseRoot -Path $InputPath -AutoExtract:$AutoExtractZip
$script:Meta = Get-CaseMeta -CaseRoot $caseRoot

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $caseRoot "analysis"
}

Add-Finding -Severity "Info" -Category "Runtime" -Title "Analysis started" -EvidencePath $caseRoot -Evidence ("InputPath=" + $InputPath) -Recommendation "Review findings, validate against environment baselines, and correlate across categories."

Analyze-RunInfoBasics -Meta $script:Meta
Analyze-ToolsInventory -Meta $script:Meta

Analyze-DefenderExclusions -CaseRoot $caseRoot
Analyze-UAC -CaseRoot $caseRoot
Analyze-Firewall -CaseRoot $caseRoot
Analyze-AuditPolicy -CaseRoot $caseRoot

Analyze-WMI-Subscriptions -CaseRoot $caseRoot
Analyze-RunKeysAndWinlogon -CaseRoot $caseRoot
Analyze-ScheduledTasks -CaseRoot $caseRoot
Analyze-Services -CaseRoot $caseRoot

Analyze-AutorunsCsv -CaseRoot $caseRoot
Analyze-SigcheckOutput -CaseRoot $caseRoot

Analyze-NetworkConnections -CaseRoot $caseRoot
Analyze-DnsCache -CaseRoot $caseRoot

Analyze-SuspiciousFileListings -CaseRoot $caseRoot

Analyze-PowerShellOperationalText -CaseRoot $caseRoot
Analyze-DefenderEventsText -CaseRoot $caseRoot

Analyze-SIEM-SecurityEventsCsv -CaseRoot $caseRoot

if ($ParseEvtx) { Analyze-EVTX -CaseRoot $caseRoot }

if (-not [string]::IsNullOrWhiteSpace($BaselinePath)) {
    $baselineRoot = Resolve-CaseRoot -Path $BaselinePath -AutoExtract:$AutoExtractZip
    Analyze-BaselineDiff -Meta $script:Meta -BaselineRoot $baselineRoot
}

$exported = Export-Findings -OutDir $OutDir

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "                 iKARUS OUTPUT ANALYSIS COMPLETE ✅" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ("Case Root: {0}" -f $caseRoot) -ForegroundColor White
Write-Host ("Output:    {0}" -f $OutDir) -ForegroundColor White
Write-Host ("Report:    {0}" -f $exported.ReportMarkdown) -ForegroundColor White
Write-Host ("CSV:       {0}" -f $exported.FindingsCsv) -ForegroundColor White
Write-Host ("JSON:      {0}" -f $exported.FindingsJson) -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Green
