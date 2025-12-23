param(
    [string]$OutRoot = "",
    [ValidateSet("Triage","Deep")][string]$Mode = "Triage",
    [switch]$IncludeAD,
    [string]$ToolsDir = "",
    [switch]$RunTools,
    [switch]$HashEvidence,
    [switch]$ExportSIEM,
    [switch]$ZipOutput,
    [ValidateSet("Workstation","Server","DomainController")][string]$Profile = "Workstation",
    [switch]$IncludeUserArtifacts,
    [switch]$IncludeBrowserArtifacts,
    [switch]$IncludeMemoryDump,
    [ValidateSet(7,30,60,90,180,365)][int]$Timeframe = 60,
    [switch]$OfflineOnly,
    [switch]$AutoDownloadTools,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:ScriptBoundParameters = $PSBoundParameters

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$global:TranscriptPath = $null
$script:MemoryDumpCreated = $false
$script:StopRequested = $false
$script:StopReason = ""
$script:ResolvedToolPaths = @{}
$script:ToolsPolicy = "Offline"
$script:EffectiveMode = $Mode

$script:IncludeMemoryDumpRuntime = $false
$script:HashEvidenceRuntime = $false
$script:RunToolsRuntime = $false
$script:IncludeUserArtifactsRuntime = $false
$script:IncludeBrowserArtifactsRuntime = $false
$script:ExportSIEMRuntime = $false
$script:ZipOutputRuntime = $false

$script:Defaults = @{
    MaxTotalCopyMB_Triage = 250
    MaxTotalCopyMB_Deep   = 2048
    MaxFileMB_Triage      = 50
    MaxFileMB_Deep        = 250
    MaxFilesPerCollector_Triage = 3000
    MaxFilesPerCollector_Deep   = 15000
    MaxListings_Triage    = 15000
    MaxListings_Deep      = 75000
}

$global:RequiredTools = @{
    "WinPMEM" = @{
        "Download" = @(
            @{ "Url" = "https://github.com/Velocidex/WinPmem/releases/download/v4.1.dev1/go-winpmem_amd64_1.0-rc2_signed.exe"; "Path" = "Memory\go-winpmem.exe" },
            @{ "Url" = "https://github.com/Velocidex/WinPmem/releases/download/v4.1.dev1/winpmem_mini_x64_rc2.exe"; "Path" = "Memory\winpmem_mini_x64.exe" },
            @{ "Url" = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/go-winpmem_amd64_1.0-rc2_signed.exe"; "Path" = "Memory\go-winpmem.exe" },
            @{ "Url" = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe"; "Path" = "Memory\winpmem_mini_x64.exe" }
        )
        "AcceptPaths" = @("Memory\go-winpmem.exe", "Memory\winpmem_mini_x64.exe")
        "OfflineCandidates" = @(
            "go-winpmem_amd64_1.0-rc2_signed.exe",
            "go-winpmem.exe",
            "winpmem_mini_x64_rc2.exe",
            "winpmem_mini_x64.exe"
        )
        "Description" = "Physical memory acquisition tool"
        "IsExecutable" = $true
    }

    "Autoruns" = @{
        "Download" = @(
            @{ "Url" = "https://download.sysinternals.com/files/Autoruns.zip"; "Path" = "Sysinternals\autorunsc.exe" },
            @{ "Url" = "https://live.sysinternals.com/Autoruns.zip"; "Path" = "Sysinternals\autorunsc.exe" }
        )
        "AcceptPaths" = @("Sysinternals\autorunsc.exe")
        "OfflineCandidates" = @("Autoruns.zip", "autoruns.zip", "autorunsc.exe", "autorunsc64.exe")
        "Description" = "Startup program detection"
        "IsExecutable" = $true
    }

    "TCPView" = @{
        "Download" = @(
            @{ "Url" = "https://download.sysinternals.com/files/TCPView.zip"; "Path" = "Sysinternals\tcpvcon.exe" },
            @{ "Url" = "https://live.sysinternals.com/TCPView.zip"; "Path" = "Sysinternals\tcpvcon.exe" }
        )
        "AcceptPaths" = @("Sysinternals\tcpvcon.exe")
        "OfflineCandidates" = @("TCPView.zip", "tcpview.zip", "tcpvcon.exe")
        "Description" = "Network connection viewer"
        "IsExecutable" = $true
    }

    "Sigcheck" = @{
        "Download" = @(
            @{ "Url" = "https://download.sysinternals.com/files/Sigcheck.zip"; "Path" = "Sysinternals\sigcheck.exe" },
            @{ "Url" = "https://live.sysinternals.com/Sigcheck.zip"; "Path" = "Sysinternals\sigcheck.exe" }
        )
        "AcceptPaths" = @("Sysinternals\sigcheck.exe")
        "OfflineCandidates" = @("Sigcheck.zip", "sigcheck.zip", "sigcheck.exe", "sigcheck64.exe")
        "Description" = "File signature verification"
        "IsExecutable" = $true
    }
}

function Request-Stop {
    param([string]$Reason)
    $script:StopRequested = $true
    $script:StopReason = $Reason
}

function Show-Banner {
    param([int]$SelectedTimeframe)

    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                  windows Forensic Toolkit v3.6" -ForegroundColor Cyan
    Write-Host "                  Developer: ikarus" -ForegroundColor Cyan
    Write-Host "                  DFIR Evidence Collection (Artifact-first)" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "System Information:" -ForegroundColor Yellow
    Write-Host ("  Computer: {0}" -f $env:COMPUTERNAME) -ForegroundColor White
    Write-Host ("  User: {0}" -f $env:USERNAME) -ForegroundColor White
    Write-Host ("  Domain: {0}" -f $env:USERDOMAIN) -ForegroundColor White
    Write-Host ("  Mode: {0}" -f $script:EffectiveMode) -ForegroundColor White
    Write-Host ("  Timeframe: {0} days" -f $SelectedTimeframe) -ForegroundColor White
    Write-Host ("  Profile: {0}" -f $Profile) -ForegroundColor White
    Write-Host ("  Tools Policy: {0}" -f $script:ToolsPolicy) -ForegroundColor White
    Write-Host ("  SIEM CSV Export: {0}" -f ($(if ($script:ExportSIEMRuntime) { "Enabled" } else { "Disabled" }))) -ForegroundColor White
    Write-Host ("  Zip Output: {0}" -f ($(if ($script:ZipOutputRuntime) { "Enabled" } else { "Disabled" }))) -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Progress($Activity, $Status, $PercentComplete) {
    if (-not $NonInteractive) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}

function Show-Menu {
    param([string]$Title, [array]$Options)

    Write-Host ("`n{0}" -f $Title) -ForegroundColor Yellow
    Write-Host ("{0}" -f ("-" * $Title.Length)) -ForegroundColor Yellow

    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host ("  {0}. {1}" -f ($i + 1), $Options[$i]) -ForegroundColor White
    }

    while ($true) {
        $choice = Read-Host ("`nSelect option (1-{0})" -f $Options.Count)
        if ($choice -match "^\d+$" -and [int]$choice -ge 1 -and [int]$choice -le $Options.Count) {
            return [int]$choice
        }
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
    }
}

function Get-YesNo {
    param([string]$Prompt, [string]$Default)

    if ($NonInteractive) {
        return ($Default -eq "Y")
    }

    $d = "Y"
    if ($Default -eq "N") { $d = "N" }

    while ($true) {
        $r = Read-Host ("{0} (Y/N) [{1}]" -f $Prompt, $d)
        if ([string]::IsNullOrWhiteSpace($r)) { $r = $d }
        if ($r -match "^[Yy]$") { return $true }
        if ($r -match "^[Nn]$") { return $false }
        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
    }
}

function Get-ModeSelection {
    $modeProvided = $false
    try { $modeProvided = $script:ScriptBoundParameters.ContainsKey("Mode") } catch { $modeProvided = $false }

    if ($modeProvided) { return $Mode }
    if ($NonInteractive) { return "Triage" }

    $opts = @("Triage (Fast, minimal copy)", "Deep (Artifact-rich, still bounded)")
    $sel = Show-Menu -Title "Select Collection Mode" -Options $opts
    if ($sel -eq 2) { return "Deep" }
    return "Triage"
}

function Get-ToolsPolicySelection {
    if ($OfflineOnly) { return "Offline" }
    if ($AutoDownloadTools) { return "Download" }
    if ($NonInteractive) { return "Offline" }

    $opts = @("Offline only (no internet)", "Auto-download missing tools (internet)")
    $sel = Show-Menu -Title "Select Tools Acquisition Policy" -Options $opts
    if ($sel -eq 2) { return "Download" }
    return "Offline"
}

function Get-TimeframeSelection {
    $timeframeWasProvided = $false
    try { $timeframeWasProvided = $script:ScriptBoundParameters.ContainsKey("Timeframe") } catch { $timeframeWasProvided = $false }

    if ($timeframeWasProvided) { return [int]$Timeframe }
    if ($NonInteractive) { return 60 }

    $menuOptions = @(
        "Last 7 days",
        "Last 30 days",
        "Last 60 days",
        "Last 90 days",
        "Last 180 days",
        "Last 365 days"
    )

    $selection = Show-Menu -Title "Select Timeframe for Analysis" -Options $menuOptions

    switch ($selection) {
        1 { return 7 }
        2 { return 30 }
        3 { return 60 }
        4 { return 90 }
        5 { return 180 }
        6 { return 365 }
        default { return 60 }
    }
}

function Resolve-DefaultTogglesForDeep {
    $includeMemoryProvided = $false
    $hashProvided = $false
    $runToolsProvided = $false
    $userArtifactsProvided = $false
    $browserProvided = $false
    $siemProvided = $false
    $zipProvided = $false

    try { $includeMemoryProvided = $script:ScriptBoundParameters.ContainsKey("IncludeMemoryDump") } catch { $includeMemoryProvided = $false }
    try { $hashProvided = $script:ScriptBoundParameters.ContainsKey("HashEvidence") } catch { $hashProvided = $false }
    try { $runToolsProvided = $script:ScriptBoundParameters.ContainsKey("RunTools") } catch { $runToolsProvided = $false }
    try { $userArtifactsProvided = $script:ScriptBoundParameters.ContainsKey("IncludeUserArtifacts") } catch { $userArtifactsProvided = $false }
    try { $browserProvided = $script:ScriptBoundParameters.ContainsKey("IncludeBrowserArtifacts") } catch { $browserProvided = $false }
    try { $siemProvided = $script:ScriptBoundParameters.ContainsKey("ExportSIEM") } catch { $siemProvided = $false }
    try { $zipProvided = $script:ScriptBoundParameters.ContainsKey("ZipOutput") } catch { $zipProvided = $false }

    if ($script:EffectiveMode -eq "Deep") {
        if (-not $includeMemoryProvided) { $script:IncludeMemoryDumpRuntime = $true } else { $script:IncludeMemoryDumpRuntime = [bool]$IncludeMemoryDump }
        if (-not $hashProvided) { $script:HashEvidenceRuntime = $true } else { $script:HashEvidenceRuntime = [bool]$HashEvidence }
        if (-not $runToolsProvided) { $script:RunToolsRuntime = $true } else { $script:RunToolsRuntime = [bool]$RunTools }
        if (-not $userArtifactsProvided) { $script:IncludeUserArtifactsRuntime = $true } else { $script:IncludeUserArtifactsRuntime = [bool]$IncludeUserArtifacts }
        if (-not $browserProvided) { $script:IncludeBrowserArtifactsRuntime = $true } else { $script:IncludeBrowserArtifactsRuntime = [bool]$IncludeBrowserArtifacts }
        if (-not $siemProvided) { $script:ExportSIEMRuntime = $true } else { $script:ExportSIEMRuntime = [bool]$ExportSIEM }
        if (-not $zipProvided) { $script:ZipOutputRuntime = $true } else { $script:ZipOutputRuntime = [bool]$ZipOutput }
        return
    }

    $script:IncludeMemoryDumpRuntime = [bool]$IncludeMemoryDump
    $script:HashEvidenceRuntime = [bool]$HashEvidence
    $script:RunToolsRuntime = [bool]$RunTools
    $script:IncludeUserArtifactsRuntime = [bool]$IncludeUserArtifacts
    $script:IncludeBrowserArtifactsRuntime = [bool]$IncludeBrowserArtifacts
    $script:ExportSIEMRuntime = [bool]$ExportSIEM
    $script:ZipOutputRuntime = [bool]$ZipOutput

    $anyProvided = $false
    try {
        $anyProvided = $script:ScriptBoundParameters.ContainsKey("IncludeMemoryDump") -or
                       $script:ScriptBoundParameters.ContainsKey("HashEvidence") -or
                       $script:ScriptBoundParameters.ContainsKey("RunTools") -or
                       $script:ScriptBoundParameters.ContainsKey("IncludeUserArtifacts") -or
                       $script:ScriptBoundParameters.ContainsKey("IncludeBrowserArtifacts") -or
                       $script:ScriptBoundParameters.ContainsKey("ExportSIEM") -or
                       $script:ScriptBoundParameters.ContainsKey("ZipOutput")
    } catch { $anyProvided = $false }

    if (-not $anyProvided -and (-not $NonInteractive)) {
        $script:IncludeMemoryDumpRuntime = Get-YesNo -Prompt "Enable Memory Acquisition" -Default "Y"
        $script:HashEvidenceRuntime = Get-YesNo -Prompt "Enable Evidence Hashing (SHA256)" -Default "Y"
        $script:RunToolsRuntime = Get-YesNo -Prompt "Run Third-Party Tools (Sysinternals/WinPMEM)" -Default "Y"
        $script:IncludeUserArtifactsRuntime = Get-YesNo -Prompt "Collect User Artifacts (MRU/JumpLists/LNK/Histories)" -Default "Y"
        $script:IncludeBrowserArtifactsRuntime = Get-YesNo -Prompt "Collect Browser Artifacts (History/Cookies/Login Data)" -Default "Y"
        $script:ExportSIEMRuntime = Get-YesNo -Prompt "Export SIEM CSV files" -Default "Y"
        $script:ZipOutputRuntime = Get-YesNo -Prompt "Zip output folder at the end" -Default "Y"
    }
}

function NewDir([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

function SaveText([string]$path, $value) {
    $dir = Split-Path -Parent $path
    NewDir $dir
    $value | Out-File -LiteralPath $path -Encoding UTF8 -Force
}

function RunSave([string]$path, [scriptblock]$scriptBlock) {
    try {
        $dir = Split-Path -Parent $path
        NewDir $dir
        & $scriptBlock 2>&1 | Out-File -LiteralPath $path -Encoding UTF8 -Force
    } catch {
        SaveText $path ("ERROR: {0}" -f $_.Exception.Message)
    }
}

function CopyFile([string]$source, [string]$destination) {
    try {
        if (Test-Path -LiteralPath $source) {
            $dir = Split-Path -Parent $destination
            NewDir $dir
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
    } catch {}
}

function ExportReg([string]$key, [string]$dstFile) {
    try {
        $dir = Split-Path -Parent $dstFile
        NewDir $dir
        reg export $key $dstFile /y | Out-Null
    } catch {}
}

function ExportEvtx([string]$logName, [string]$dstFile) {
    try {
        $dir = Split-Path -Parent $dstFile
        NewDir $dir
        $out = & wevtutil epl $logName $dstFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            $errFile = $dstFile + ".error.txt"
            $msg = @()
            $msg += ("Log: {0}" -f $logName)
            $msg += ("Destination: {0}" -f $dstFile)
            $msg += ("ExitCode: {0}" -f $LASTEXITCODE)
            if ($out) { $msg += ($out | Out-String) }
            SaveText $errFile ($msg -join "`r`n")
        }
    } catch {
        $errFile = $dstFile + ".error.txt"
        SaveText $errFile ("ERROR exporting {0}: {1}" -f $logName, $_.Exception.Message)
    }
}

function IsAdmin() {
    try {
        $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Initialize-ToolsDirectory {
    param([string]$toolsPath)

    if ([string]::IsNullOrEmpty($toolsPath)) {
        $base = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($base)) { $base = $PWD.Path }
        if ($base -like "$env:WINDIR*") { $base = [Environment]::GetFolderPath("Desktop") }
        $toolsPath = Join-Path $base "windows_Forensic_Tools"
    }

    NewDir $toolsPath

    $requiredDirs = @("Memory", "Sysinternals", "Temporary", "OfflinePackages", "OfflinePackages\_expanded")
    foreach ($dir in $requiredDirs) { NewDir (Join-Path $toolsPath $dir) }

    return $toolsPath
}

function Test-FileHeaderSignature {
    param([string]$FilePath)

    try {
        if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $false }
        $ext = ([System.IO.Path]::GetExtension($FilePath)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($ext)) { return $true }

        $fs = $null
        try {
            $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $b = New-Object byte[] 2
            $read = $fs.Read($b, 0, 2)
            if ($read -lt 2) { return $false }

            if ($ext -eq ".zip") { return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B) }

            if ($ext -eq ".exe" -or $ext -eq ".dll" -or $ext -eq ".sys") {
                return ($b[0] -eq 0x4D -and $b[1] -eq 0x5A)
            }

            return $true
        } finally {
            if ($fs) { try { $fs.Close() } catch {} }
        }
    } catch {
        return $false
    }
}

function Test-FileValid {
    param([string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $false }

    try {
        $fileInfo = Get-Item -LiteralPath $FilePath
        if ($fileInfo.Length -lt 1024) { return $false }
        if (-not (Test-FileHeaderSignature -FilePath $FilePath)) { return $false }
        return $true
    } catch {
        return $false
    }
}

function Resolve-ToolPath {
    param([string]$baseDir, [string]$toolRelOrAbs)

    if ([string]::IsNullOrWhiteSpace($toolRelOrAbs)) { return $null }
    if ([System.IO.Path]::IsPathRooted($toolRelOrAbs)) { return $toolRelOrAbs }
    return (Join-Path $baseDir $toolRelOrAbs)
}

function Invoke-WebRequestCompat {
    param([string]$Uri, [string]$OutFile, [hashtable]$Headers)

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $Headers -UseBasicParsing -ErrorAction Stop | Out-Null
    } else {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $Headers -ErrorAction Stop | Out-Null
    }
}

function Get-ToolAcceptRelPaths {
    param([hashtable]$ToolInfo)

    if ($ToolInfo.ContainsKey("AcceptPaths") -and $ToolInfo.AcceptPaths) {
        if ($ToolInfo.AcceptPaths -is [System.Array]) { return $ToolInfo.AcceptPaths }
        return @([string]$ToolInfo.AcceptPaths)
    }
    return @()
}

function Get-ToolDownloadEntries {
    param([hashtable]$ToolInfo)

    if ($ToolInfo.ContainsKey("Download") -and $ToolInfo.Download) { return $ToolInfo.Download }
    return @()
}

function Get-OfflineSearchDirs {
    param([string]$ToolsRoot)

    $dirs = @()
    try { $dirs += (Join-Path $ToolsRoot "OfflinePackages") } catch {}
    try { $dirs += $ToolsRoot } catch {}
    try { if ($PSScriptRoot) { $dirs += $PSScriptRoot } } catch {}
    try { if ($PWD -and $PWD.Path) { $dirs += $PWD.Path } } catch {}
    try { if ($env:USERPROFILE) { $dirs += (Join-Path $env:USERPROFILE "Downloads") } } catch {}
    try { $d = [Environment]::GetFolderPath("Desktop"); if ($d) { $dirs += $d } } catch {}
    try { $d = [Environment]::GetFolderPath("MyDocuments"); if ($d) { $dirs += $d } } catch {}
    return $dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
}

function Select-WinPmemDestRel {
    param([hashtable]$ToolInfo, [string]$CandidateName)

    $accept = Get-ToolAcceptRelPaths $ToolInfo
    if ($accept.Count -eq 1) { return $accept[0] }

    $n = $CandidateName.ToLowerInvariant()
    foreach ($p in $accept) {
        $pl = $p.ToLowerInvariant()
        if ($n -match "go-winpmem" -and $pl -match "go-winpmem") { return $p }
        if ($n -match "mini" -and $pl -match "mini") { return $p }
    }
    return $accept[0]
}

function Get-ToolCandidateExeNames {
    param([string]$ToolName, [hashtable]$ToolInfo)

    $names = @()
    $accept = Get-ToolAcceptRelPaths $ToolInfo
    foreach ($rp in $accept) {
        try {
            $leaf = Split-Path -Leaf $rp
            if ($leaf) { $names += $leaf }
        } catch {}
    }

    if ($ToolInfo.ContainsKey("OfflineCandidates") -and $ToolInfo.OfflineCandidates) {
        foreach ($c in $ToolInfo.OfflineCandidates) {
            try {
                $cn = [string]$c
                if ($cn -and $cn.ToLowerInvariant().EndsWith(".exe")) { $names += $cn }
            } catch {}
        }
    }

    if ($ToolName -eq "Autoruns") { $names += "autorunsc64.exe"; $names += "autorunsc.exe" }
    elseif ($ToolName -eq "TCPView") { $names += "tcpvcon.exe" }
    elseif ($ToolName -eq "Sigcheck") { $names += "sigcheck64.exe"; $names += "sigcheck.exe" }
    elseif ($ToolName -eq "WinPMEM") { $names += "go-winpmem.exe"; $names += "winpmem_mini_x64.exe"; $names += "winpmem.exe" }

    return ($names | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -Unique)
}

function Find-ExistingToolBinary {
    param([string]$ToolsRoot, [string]$ToolName, [hashtable]$ToolInfo)

    $accept = Get-ToolAcceptRelPaths $ToolInfo
    foreach ($rp in $accept) {
        $fp = Resolve-ToolPath -baseDir $ToolsRoot -toolRelOrAbs $rp
        if ($fp -and (Test-FileValid -FilePath $fp)) { return $fp }
    }

    $cand = Get-ToolCandidateExeNames -ToolName $ToolName -ToolInfo $ToolInfo
    if (-not $cand -or $cand.Count -eq 0) { return $null }

    try {
        $all = Get-ChildItem -LiteralPath $ToolsRoot -Recurse -File -Force -ErrorAction SilentlyContinue
        foreach ($n in $cand) {
            $hit = $all | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
            if ($hit -and (Test-FileValid -FilePath $hit.FullName)) { return $hit.FullName }
        }
    } catch {}

    return $null
}

function Get-OfflinePackageFile {
    param([string]$ToolsRoot, [string]$ToolName, [hashtable]$ToolInfo)

    $offlineDirs = Get-OfflineSearchDirs $ToolsRoot
    $candidates = @()

    if ($ToolInfo.ContainsKey("OfflineCandidates") -and $ToolInfo.OfflineCandidates) { $candidates += $ToolInfo.OfflineCandidates }

    $downloadEntries = Get-ToolDownloadEntries $ToolInfo
    foreach ($e in $downloadEntries) {
        try {
            $u = [string]$e.Url
            if ($u) {
                $leaf = Split-Path -Leaf ([uri]$u).AbsolutePath
                if ($leaf) { $candidates += $leaf }
            }
        } catch {}
    }

    $candidates = $candidates | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -Unique
    if ($candidates.Count -eq 0) { return $null }

    foreach ($dir in $offlineDirs) {
        foreach ($c in $candidates) {
            try {
                $p = Join-Path $dir $c
                if (Test-Path -LiteralPath $p -PathType Leaf) {
                    if (Test-FileValid -FilePath $p) { return $p }
                }
            } catch {}
        }
    }

    return $null
}

function Extract-OfflineZipAndPickExe {
    param([string]$ToolsRoot, [string]$ToolName, [hashtable]$ToolInfo, [string]$ZipPath)

    $expandBase = Join-Path (Join-Path $ToolsRoot "OfflinePackages\_expanded") $ToolName
    NewDir $expandBase
    $jobDir = Join-Path $expandBase ([guid]::NewGuid().ToString())
    NewDir $jobDir

    try {
        try { Expand-Archive -Path $ZipPath -DestinationPath $jobDir -Force } catch { return $null }

        $candNames = Get-ToolCandidateExeNames -ToolName $ToolName -ToolInfo $ToolInfo
        $files = @()
        try { $files = Get-ChildItem -LiteralPath $jobDir -Recurse -File -ErrorAction SilentlyContinue } catch { $files = @() }

        foreach ($n in $candNames) {
            $hit = $files | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
            if ($hit -and (Test-FileValid -FilePath $hit.FullName)) { return $hit.FullName }
        }

        if ($ToolName -eq "Autoruns") {
            $hit2 = $files | Where-Object { $_.Name -imatch "^autorunsc(64)?\.exe$" } | Select-Object -First 1
            if ($hit2 -and (Test-FileValid -FilePath $hit2.FullName)) { return $hit2.FullName }
        } elseif ($ToolName -eq "Sigcheck") {
            $hit2 = $files | Where-Object { $_.Name -imatch "^sigcheck(64)?\.exe$" } | Select-Object -First 1
            if ($hit2 -and (Test-FileValid -FilePath $hit2.FullName)) { return $hit2.FullName }
        } elseif ($ToolName -eq "TCPView") {
            $hit2 = $files | Where-Object { $_.Name -ieq "tcpvcon.exe" } | Select-Object -First 1
            if ($hit2 -and (Test-FileValid -FilePath $hit2.FullName)) { return $hit2.FullName }
        }

        $fallback = $files | Where-Object { $_.Extension -ieq ".exe" } | Select-Object -First 1
        if ($fallback -and (Test-FileValid -FilePath $fallback.FullName)) { return $fallback.FullName }

        return $null
    } catch {
        return $null
    }
}

function Stage-ToolFromOffline {
    param([string]$ToolsRoot, [string]$ToolName, [hashtable]$ToolInfo)

    $pkg = Get-OfflinePackageFile -ToolsRoot $ToolsRoot -ToolName $ToolName -ToolInfo $ToolInfo
    if (-not $pkg) { return $null }

    $ext = ""
    try { $ext = ([System.IO.Path]::GetExtension($pkg)).ToLowerInvariant() } catch { $ext = "" }

    if ($ext -eq ".zip") {
        $picked = Extract-OfflineZipAndPickExe -ToolsRoot $ToolsRoot -ToolName $ToolName -ToolInfo $ToolInfo -ZipPath $pkg
        if (-not $picked) { return $null }

        $destRel = (Get-ToolAcceptRelPaths $ToolInfo)[0]
        if ($ToolName -eq "WinPMEM") { $destRel = Select-WinPmemDestRel -ToolInfo $ToolInfo -CandidateName (Split-Path -Leaf $picked) }

        $destFull = Resolve-ToolPath -baseDir $ToolsRoot -toolRelOrAbs $destRel
        try {
            $destDir = Split-Path -Parent $destFull
            NewDir $destDir
            Copy-Item -LiteralPath $picked -Destination $destFull -Force
            try { Unblock-File -LiteralPath $destFull -ErrorAction SilentlyContinue } catch {}
            if (Test-FileValid -FilePath $destFull) {
                Write-Host ("  [+] {0} staged from offline zip: {1}" -f $ToolName, $pkg) -ForegroundColor Green
                return $destFull
            }
        } catch {}
        return $null
    }

    if ($ext -eq ".exe") {
        $destRel = (Get-ToolAcceptRelPaths $ToolInfo)[0]
        if ($ToolName -eq "WinPMEM") { $destRel = Select-WinPmemDestRel -ToolInfo $ToolInfo -CandidateName (Split-Path -Leaf $pkg) }
        $destFull = Resolve-ToolPath -baseDir $ToolsRoot -toolRelOrAbs $destRel
        try {
            $destDir = Split-Path -Parent $destFull
            NewDir $destDir
            Copy-Item -LiteralPath $pkg -Destination $destFull -Force
            try { Unblock-File -LiteralPath $destFull -ErrorAction SilentlyContinue } catch {}
            if (Test-FileValid -FilePath $destFull) {
                Write-Host ("  [+] {0} staged from offline exe: {1}" -f $ToolName, $pkg) -ForegroundColor Green
                return $destFull
            }
        } catch {}
        return $null
    }

    return $null
}

function Download-ToolSingle {
    param(
        [string]$ToolsRoot,
        [string]$Url,
        [string]$DestinationFullPath,
        [string]$ToolName
    )

    $downloadRoot = Join-Path $ToolsRoot "Temporary"
    $jobDir = Join-Path $downloadRoot ([guid]::NewGuid().ToString())
    $tempFile = $null

    try {
        NewDir $downloadRoot
        NewDir $jobDir

        $urlExt = $null
        try { $urlExt = [System.IO.Path]::GetExtension(([uri]$Url).AbsolutePath) } catch { $urlExt = $null }
        if ([string]::IsNullOrWhiteSpace($urlExt)) { $urlExt = ".bin" }

        $tempFile = Join-Path $jobDir ("{0}{1}" -f $ToolName, $urlExt)

        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            "Accept" = "*/*"
        }

        Write-Host ("  [*] Downloading {0}..." -f $ToolName) -ForegroundColor Yellow
        Invoke-WebRequestCompat -Uri $Url -OutFile $tempFile -Headers $headers

        if (-not (Test-Path -LiteralPath $tempFile -PathType Leaf)) {
            Write-Host ("  [-] Download failed for {0}" -f $ToolName) -ForegroundColor Yellow
            return $false
        }

        if (-not (Test-FileValid -FilePath $tempFile)) {
            Write-Host ("  [-] Downloaded file invalid for {0}. Url: {1}" -f $ToolName, $Url) -ForegroundColor Yellow
            return $false
        }

        $destDir = Split-Path -Parent $DestinationFullPath
        NewDir $destDir

        if ($urlExt.ToLowerInvariant() -eq ".zip") {
            try { Expand-Archive -Path $tempFile -DestinationPath $jobDir -Force } catch { return $false }

            $targetName = Split-Path -Leaf $DestinationFullPath
            $found = Get-ChildItem -Path $jobDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq $targetName } | Select-Object -First 1

            if (-not $found) {
                if ($ToolName -eq "Autoruns") {
                    $found = Get-ChildItem -Path $jobDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -imatch "^autorunsc(64)?\.exe$" } | Select-Object -First 1
                } elseif ($ToolName -eq "TCPView") {
                    $found = Get-ChildItem -Path $jobDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq "tcpvcon.exe" } | Select-Object -First 1
                } elseif ($ToolName -eq "Sigcheck") {
                    $found = Get-ChildItem -Path $jobDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -imatch "^sigcheck(64)?\.exe$" } | Select-Object -First 1
                } elseif ($ToolName -eq "WinPMEM") {
                    $found = Get-ChildItem -Path $jobDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -imatch "winpmem|go-winpmem" } | Select-Object -First 1
                }
            }

            if (-not $found) { $found = Get-ChildItem -Path $jobDir -Recurse -Filter "*.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }

            if ($found) {
                Copy-Item -LiteralPath $found.FullName -Destination $DestinationFullPath -Force
                try { Unblock-File -LiteralPath $DestinationFullPath -ErrorAction SilentlyContinue } catch {}
                if (Test-FileValid -FilePath $DestinationFullPath) {
                    Write-Host ("  [+] {0} downloaded successfully" -f $ToolName) -ForegroundColor Green
                    return $true
                }
            }

            return $false
        } else {
            Move-Item -LiteralPath $tempFile -Destination $DestinationFullPath -Force
            try { Unblock-File -LiteralPath $DestinationFullPath -ErrorAction SilentlyContinue } catch {}
            if (Test-FileValid -FilePath $DestinationFullPath) {
                Write-Host ("  [+] {0} downloaded successfully" -f $ToolName) -ForegroundColor Green
                return $true
            }
            return $false
        }
    } catch {
        Write-Host ("  [-] Download error for {0}: {1}" -f $ToolName, $_.Exception.Message) -ForegroundColor Yellow
        return $false
    } finally {
        try {
            if ($jobDir -and (Test-Path -LiteralPath $jobDir)) {
                Remove-Item -LiteralPath $jobDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

function Download-ToolWithAlternatives {
    param([string]$ToolsRoot, [string]$ToolName, [hashtable]$ToolInfo)

    $entries = Get-ToolDownloadEntries $ToolInfo
    if (-not $entries -or $entries.Count -eq 0) { return $false }

    foreach ($e in $entries) {
        $u = $null
        $rp = $null
        try { $u = [string]$e.Url } catch { $u = $null }
        try { $rp = [string]$e.Path } catch { $rp = $null }
        if ([string]::IsNullOrWhiteSpace($u) -or [string]::IsNullOrWhiteSpace($rp)) { continue }

        $dest = Resolve-ToolPath -baseDir $ToolsRoot -toolRelOrAbs $rp
        if ($dest -and (Test-FileValid -FilePath $dest)) { return $true }

        $ok = Download-ToolSingle -ToolsRoot $ToolsRoot -Url $u -DestinationFullPath $dest -ToolName $ToolName
        if ($ok) { return $true }
    }

    return $false
}

function Ensure-ToolReady {
    param([string]$ToolsRoot, [string]$ToolName, [hashtable]$ToolInfo)

    $existing = Find-ExistingToolBinary -ToolsRoot $ToolsRoot -ToolName $ToolName -ToolInfo $toolInfo
    if ($existing) { return $existing }

    $staged = Stage-ToolFromOffline -ToolsRoot $ToolsRoot -ToolName $ToolName -ToolInfo $ToolInfo
    if ($staged) { return $staged }

    if ($script:ToolsPolicy -eq "Download") {
        $ok = Download-ToolWithAlternatives -ToolsRoot $ToolsRoot -ToolName $ToolName -ToolInfo $ToolInfo
        if ($ok) {
            $existing2 = Find-ExistingToolBinary -ToolsRoot $ToolsRoot -ToolName $ToolName -ToolInfo $ToolInfo
            if ($existing2) { return $existing2 }
        }
    }

    return $null
}

function Write-ToolsInventory {
    param([string]$OutDir, [string]$ToolsRoot)

    try {
        $metaDir = Join-Path $OutDir "meta"
        NewDir $metaDir
        $csv = Join-Path $metaDir "tools_inventory.csv"
        "Tool,ResolvedPath,SHA256,Length" | Out-File -LiteralPath $csv -Encoding UTF8 -Force

        foreach ($toolName in $global:RequiredTools.Keys) {
            $resolved = $null
            try { $resolved = $script:ResolvedToolPaths[$toolName] } catch { $resolved = $null }

            if ($resolved -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                $h = ""
                try { $h = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch { $h = "" }
                $len = ""
                try { $len = (Get-Item -LiteralPath $resolved -ErrorAction SilentlyContinue).Length } catch { $len = "" }
                $line = '"' + ($toolName.Replace('"','""')) + '","' + ($resolved.Replace('"','""')) + '",' + $h + "," + $len
                Add-Content -LiteralPath $csv -Value $line -Encoding UTF8
            } else {
                $line = '"' + ($toolName.Replace('"','""')) + '",,,'
                Add-Content -LiteralPath $csv -Value $line -Encoding UTF8
            }
        }
    } catch {}
}

function Check-RequiredTools {
    param([string]$toolsPath)

    Write-Host "`n[+] Checking required tools..." -ForegroundColor Green

    $script:ResolvedToolPaths = @{}
    $availableTools = @()
    $missingTools = @()

    foreach ($toolName in $global:RequiredTools.Keys) {
        $toolInfo = $global:RequiredTools[$toolName]
        $resolved = Ensure-ToolReady -ToolsRoot $toolsPath -ToolName $toolName -ToolInfo $toolInfo
        if ($resolved) {
            $script:ResolvedToolPaths[$toolName] = $resolved
            Write-Host ("  [+] {0} ready: {1}" -f $toolName, $resolved) -ForegroundColor Green
            $availableTools += $toolName
        } else {
            Write-Host ("  [-] {0} missing" -f $toolName) -ForegroundColor Yellow
            $missingTools += ,@{ Name = $toolName; Info = $toolInfo }
        }
    }

    if ($missingTools.Count -gt 0) {
        Write-Host ("`n[!] Missing {0} tool(s)" -f $missingTools.Count) -ForegroundColor Yellow
        Write-Host ("[*] OfflinePackages folder: {0}" -f (Join-Path $toolsPath "OfflinePackages")) -ForegroundColor Cyan
        Write-Host ("[*] Tools Policy: {0}" -f $script:ToolsPolicy) -ForegroundColor Cyan
        if ($script:ToolsPolicy -eq "Offline") {
            Write-Host "[!] Offline policy selected. Missing tools will remain missing." -ForegroundColor Yellow
            Write-Host ("[!] Missing: {0}" -f ($missingTools.Name -join ", ")) -ForegroundColor Yellow
        } else {
            Write-Host "[!] Download policy selected but some tools still missing after attempts." -ForegroundColor Yellow
            Write-Host ("[!] Missing: {0}" -f ($missingTools.Name -join ", ")) -ForegroundColor Yellow
        }
    }

    Write-Host ("`n[*] Tool Status: {0}/{1} available" -f $availableTools.Count, $global:RequiredTools.Count) -ForegroundColor Cyan
    return $availableTools
}

function New-CopyBudget {
    param([string]$ModeValue)

    $budget = [pscustomobject]@{
        Mode = $ModeValue
        BytesBudget = 0L
        BytesUsed = 0L
        FilesBudget = 0
        FilesCopied = 0
        FileMaxBytes = 0L
    }

    if ($ModeValue -eq "Deep") {
        $budget.BytesBudget = [int64]($script:Defaults.MaxTotalCopyMB_Deep * 1MB)
        $budget.FilesBudget = [int]$script:Defaults.MaxFilesPerCollector_Deep
        $budget.FileMaxBytes = [int64]($script:Defaults.MaxFileMB_Deep * 1MB)
    } else {
        $budget.BytesBudget = [int64]($script:Defaults.MaxTotalCopyMB_Triage * 1MB)
        $budget.FilesBudget = [int]$script:Defaults.MaxFilesPerCollector_Triage
        $budget.FileMaxBytes = [int64]($script:Defaults.MaxFileMB_Triage * 1MB)
    }

    return $budget
}

function Copy-Selective {
    param(
        [string]$SourceRoot,
        [string]$DestinationRoot,
        [datetime]$Since,
        [string[]]$Extensions,
        [int]$MaxFiles,
        [pscustomobject]$Budget
    )

    try {
        if (-not (Test-Path -LiteralPath $SourceRoot)) { return }

        NewDir $DestinationRoot

        $files = @()
        try {
            $files = Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
                $_.LastWriteTime -ge $Since
            } | Sort-Object LastWriteTime -Descending
        } catch {
            $files = @()
        }

        $count = 0
        foreach ($f in $files) {
            if ($script:StopRequested) { return }
            if ($MaxFiles -gt 0 -and $count -ge $MaxFiles) { break }
            if ($Budget -and $Budget.FilesCopied -ge $Budget.FilesBudget) { break }
            if ($Budget -and $Budget.BytesUsed -ge $Budget.BytesBudget) { break }

            $okExt = $true
            if ($Extensions -and $Extensions.Count -gt 0) {
                $okExt = $false
                $ext = $f.Extension.ToLowerInvariant()
                foreach ($e in $Extensions) {
                    if ($ext -eq $e.ToLowerInvariant()) { $okExt = $true; break }
                }
            }
            if (-not $okExt) { continue }

            if ($Budget -and $f.Length -gt $Budget.FileMaxBytes) { continue }

            $rel = $null
            try { $rel = $f.FullName.Substring($SourceRoot.Length).TrimStart('\') } catch { $rel = $f.Name }
            $dest = Join-Path $DestinationRoot $rel
            $destDir = Split-Path -Parent $dest
            NewDir $destDir

            try {
                Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $dest) {
                    $count++
                    if ($Budget) {
                        $Budget.FilesCopied++
                        $Budget.BytesUsed += [int64]$f.Length
                    }
                }
            } catch {}
        }
    } catch {}
}

function List-RecentFiles {
    param(
        [string]$SourceRoot,
        [string]$OutCsv,
        [datetime]$Since,
        [string[]]$Extensions,
        [int]$MaxRows
    )

    try {
        if (-not (Test-Path -LiteralPath $SourceRoot)) { return }

        $dir = Split-Path -Parent $OutCsv
        NewDir $dir
        "Path,Length,CreationTimeUtc,LastWriteTimeUtc,LastAccessTimeUtc" | Out-File -LiteralPath $OutCsv -Encoding UTF8 -Force

        $files = @()
        try {
            $files = Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
                $_.LastWriteTime -ge $Since
            } | Sort-Object LastWriteTime -Descending
        } catch { $files = @() }

        $n = 0
        foreach ($f in $files) {
            if ($MaxRows -gt 0 -and $n -ge $MaxRows) { break }

            $okExt = $true
            if ($Extensions -and $Extensions.Count -gt 0) {
                $okExt = $false
                $ext = $f.Extension.ToLowerInvariant()
                foreach ($e in $Extensions) {
                    if ($ext -eq $e.ToLowerInvariant()) { $okExt = $true; break }
                }
            }
            if (-not $okExt) { continue }

            $p = $f.FullName.Replace('"', '""')
            $line = '"' + $p + '",' + $f.Length + ',"' + $f.CreationTimeUtc.ToString("o") + '","' + $f.LastWriteTimeUtc.ToString("o") + '","' + $f.LastAccessTimeUtc.ToString("o") + '"'
            Add-Content -LiteralPath $OutCsv -Value $line -Encoding UTF8
            $n++
        }
    } catch {}
}

function Export-CsvUtf8 {
    param(
        [string]$Path,
        [object]$Data
    )

    try {
        $dir = Split-Path -Parent $Path
        NewDir $dir
        if ($null -eq $Data) {
            "" | Out-File -LiteralPath $Path -Encoding UTF8 -Force
            return
        }

        if ($Data -is [string]) {
            $Data | Out-File -LiteralPath $Path -Encoding UTF8 -Force
            return
        }

        $Data | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        try { SaveText $Path ("ERROR exporting CSV: {0}" -f $_.Exception.Message) } catch {}
    }
}

function HashManifest([string]$root,[string]$outCsv) {
    try {
        if ($global:TranscriptPath -and (Test-Path -LiteralPath $global:TranscriptPath)) {
            try { Stop-Transcript | Out-Null } catch {}
            Start-Sleep -Milliseconds 300
        }

        $dir = Split-Path -Parent $outCsv
        NewDir $dir
        "Path,SHA256,Length,LastWriteTimeUtc" | Out-File -LiteralPath $outCsv -Encoding UTF8 -Force

        $files = @()
        try { $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue } catch { $files = @() }

        $totalFiles = 0
        try { $totalFiles = $files.Count } catch { $totalFiles = 0 }
        $processed = 0

        foreach ($file in $files) {
            $processed++
            if ($totalFiles -gt 0) {
                Show-Progress -Activity "Hashing Evidence Files" -Status ("Processing {0}" -f $file.Name) -PercentComplete (($processed / $totalFiles) * 100)
            }

            try {
                $h = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h) {
                    $p = $file.FullName.Replace('"', '""')
                    $line = '"' + $p + '",' + $h.Hash + "," + $file.Length + ',"' + $file.LastWriteTimeUtc.ToString("o") + '"'
                    Add-Content -LiteralPath $outCsv -Value $line -Encoding UTF8
                }
            } catch {}
        }

        Show-Progress -Activity "Hashing Evidence Files" -Status "Completed" -PercentComplete 100
        Start-Sleep -Milliseconds 300
        Show-Progress -Activity "Hashing Evidence Files" -Status "Completed" -Completed

        if ($global:TranscriptPath) {
            try { Start-Transcript -Path $global:TranscriptPath -Append -Force | Out-Null } catch {}
        }
    } catch {
        SaveText $outCsv ("ERROR Hashing: {0}" -f $_.Exception.Message)
    }
}

function Acquire-Memory([string]$outputDir, [string]$toolsPath) {
    Write-Host "`n[+] Starting Memory Acquisition..." -ForegroundColor Green

    $memoryDir = Join-Path $outputDir "memory"
    NewDir $memoryDir

    if (-not (IsAdmin)) {
        Write-Host "  [!] Memory dump requires Administrator PowerShell." -ForegroundColor Yellow
        $script:MemoryDumpCreated = $false
        return $false
    }

    $winpmemResolved = $null
    try { $winpmemResolved = $script:ResolvedToolPaths["WinPMEM"] } catch { $winpmemResolved = $null }

    $memFile = Join-Path $memoryDir ("{0}_memory_{1}.raw" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))

    $goPath = Resolve-ToolPath -baseDir $toolsPath -toolRelOrAbs "Memory\go-winpmem.exe"
    $miniPath = Resolve-ToolPath -baseDir $toolsPath -toolRelOrAbs "Memory\winpmem_mini_x64.exe"

    $candidates = @()
    if ($winpmemResolved) { $candidates += $winpmemResolved }
    if ($goPath) { $candidates += $goPath }
    if ($miniPath) { $candidates += $miniPath }

    $picked = $null
    foreach ($c in ($candidates | Select-Object -Unique)) {
        if ($c -and (Test-FileValid -FilePath $c)) { $picked = $c; break }
    }

    if ($picked) {
        Write-Host ("  [*] Using WinPMEM: {0}" -f $picked) -ForegroundColor Yellow

        $log1 = Join-Path $memoryDir "winpmem_info.txt"
        $log2 = Join-Path $memoryDir "winpmem_acquire.txt"

        RunSave $log1 {
            & $picked --help 2>&1
            ""
            & $picked -h 2>&1
            ""
            & $picked --version 2>&1
            ""
        }

        RunSave $log2 {
            $attempts = @(
                { & $picked acquire --progress $memFile 2>&1 },
                { & $picked acquire $memFile 2>&1 },
                { & $picked -o $memFile 2>&1 },
                { & $picked $memFile 2>&1 }
            )

            foreach ($a in $attempts) {
                try { & $a | Out-String } catch {}
                Start-Sleep -Seconds 1
                if (Test-Path -LiteralPath $memFile) { break }
            }

            ("ExitCode: {0}" -f $LASTEXITCODE)
        }

        if (Test-Path -LiteralPath $memFile) {
            $sizeMB = [math]::Round((Get-Item -LiteralPath $memFile).Length / 1MB, 2)
            Write-Host ("  [+] Memory dump created: {0} MB" -f $sizeMB) -ForegroundColor Green
            $script:MemoryDumpCreated = $true
            return $true
        }

        Write-Host "  [!] WinPMEM executed but no dump file created." -ForegroundColor Yellow
    } else {
        Write-Host "  [!] WinPMEM not available." -ForegroundColor Yellow
    }

    Write-Host "  [!] Falling back to memory context collection." -ForegroundColor Yellow

    RunSave (Join-Path $memoryDir "process_info.txt") {
        Get-Process | Select-Object Name, Id, Path,
            @{Name = "WorkingSet(MB)"; Expression = { [math]::Round($_.WorkingSet64 / 1MB, 2) } },
            @{Name = "PrivateMemory(MB)"; Expression = { [math]::Round($_.PrivateMemorySize64 / 1MB, 2) } },
            @{Name = "StartTime"; Expression = { $_.StartTime } } |
        Sort-Object "WorkingSet(MB)" -Descending | Format-Table -AutoSize
    }

    RunSave (Join-Path $memoryDir "net_tcp_connections.txt") {
        try {
            Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
            Sort-Object State, LocalPort | Format-Table -AutoSize
        } catch {
            netstat -anob
        }
    }

    RunSave (Join-Path $memoryDir "loaded_modules_top.txt") {
        try {
            $procs = Get-Process -ErrorAction SilentlyContinue
            foreach ($p in ($procs | Sort-Object WorkingSet64 -Descending | Select-Object -First 25)) {
                ("=== {0} ({1}) ===" -f $p.Name, $p.Id)
                try {
                    $mods = $p.Modules | Select-Object ModuleName, FileName | Sort-Object ModuleName
                    $mods | Format-Table -AutoSize
                } catch {
                    "Access denied or module enumeration failed."
                }
                ""
            }
        } catch {
            "Failed."
        }
    }

    $script:MemoryDumpCreated = $false
    return $false
}

function Collect-SystemInfo([string]$outputDir) {
    Write-Host "[*] Collecting system information..." -ForegroundColor Green
    $systemDir = Join-Path $outputDir "system"
    NewDir $systemDir

    RunSave (Join-Path $systemDir "computerinfo.txt") { Get-ComputerInfo }
    RunSave (Join-Path $systemDir "systeminfo.txt") { systeminfo }
    RunSave (Join-Path $systemDir "whoami_all.txt") { whoami /all }
    RunSave (Join-Path $systemDir "hotfixes.txt") { Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize }
    RunSave (Join-Path $systemDir "drivers_pnputil.txt") { pnputil /enum-drivers }
    RunSave (Join-Path $systemDir "environment_variables.txt") { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize }
    RunSave (Join-Path $systemDir "timezone.txt") { tzutil /g }
    RunSave (Join-Path $systemDir "startup_commands_wmic.txt") { wmic startup get Caption, Command, Location, User }
    RunSave (Join-Path $systemDir "tasklist_v.txt") { tasklist /v }
    RunSave (Join-Path $systemDir "gpresult_r.txt") { gpresult /r 2>$null | Out-String }
}

function Collect-UserInfo([string]$outputDir, [int]$daysBack) {
    Write-Host "[*] Collecting user information..." -ForegroundColor Green
    $usersDir = Join-Path $outputDir "users"
    NewDir $usersDir

    $dateThreshold = (Get-Date).AddDays(-$daysBack)

    RunSave (Join-Path $usersDir "local_users.txt") { Get-LocalUser | Format-Table -AutoSize }
    RunSave (Join-Path $usersDir "local_groups.txt") { Get-LocalGroup | Format-Table -AutoSize }
    RunSave (Join-Path $usersDir "local_admins.txt") { Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize }
    RunSave (Join-Path $usersDir "loggedon_quser.txt") { quser }
    RunSave (Join-Path $usersDir "user_sessions.txt") { query session }

    RunSave (Join-Path $usersDir ("recent_logons_{0}days.txt" -f $daysBack)) {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 800 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $dateThreshold } |
        Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="LogonType";Expression={$_.Properties[8].Value}} |
        Sort-Object TimeCreated -Descending | Format-Table -AutoSize
    }
}

function Collect-ProcessInfo([string]$outputDir) {
    Write-Host "[*] Collecting process and service information..." -ForegroundColor Green
    $processDir = Join-Path $outputDir "process"
    NewDir $processDir

    RunSave (Join-Path $processDir "processes.txt") {
        Get-Process | Select-Object Name, Id, Path,
            @{Name="WorkingSet(MB)";Expression={[math]::Round($_.WorkingSet64/1MB,2)}},
            @{Name="CPU";Expression={$_.CPU}},
            @{Name="StartTime";Expression={$_.StartTime}} |
        Sort-Object "WorkingSet(MB)" -Descending | Format-Table -AutoSize
    }

    RunSave (Join-Path $processDir "tasklist_svc.txt") { tasklist /svc }
    RunSave (Join-Path $processDir "services.txt") { Get-Service | Sort-Object Status,Name | Format-Table -AutoSize }
    RunSave (Join-Path $processDir "drivers_driverquery.txt") { driverquery /V }
    RunSave (Join-Path $processDir "scheduledtasks_list_v.txt") { schtasks /query /fo LIST /v }

    RunSave (Join-Path $processDir "services_detailed.txt") {
        Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
        Sort-Object Name | Format-Table -AutoSize
    }
}

function Collect-NetworkInfo([string]$outputDir) {
    Write-Host "[*] Collecting network information..." -ForegroundColor Green
    $networkDir = Join-Path $outputDir "network"
    NewDir $networkDir

    RunSave (Join-Path $networkDir "ipconfig_all.txt") { ipconfig /all }
    RunSave (Join-Path $networkDir "routes.txt") { route print }
    RunSave (Join-Path $networkDir "arp.txt") { arp -a }
    RunSave (Join-Path $networkDir "netstat_abno.txt") { netstat -abno }
    RunSave (Join-Path $networkDir "dns_cache.txt") { ipconfig /displaydns }
    RunSave (Join-Path $networkDir "firewall_rules.txt") { netsh advfirewall firewall show rule name=all }
    RunSave (Join-Path $networkDir "network_shares.txt") { net share }
    RunSave (Join-Path $networkDir "wifi_profiles.txt") { netsh wlan show profiles }
}

function Collect-Persistence([string]$outputDir) {
    Write-Host "[*] Collecting persistence artifacts..." -ForegroundColor Green
    $persistenceDir = Join-Path $outputDir "persistence"
    NewDir $persistenceDir

    RunSave (Join-Path $persistenceDir "run_hklm.txt") { reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s }
    RunSave (Join-Path $persistenceDir "run_hkcu.txt") { reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s }
    RunSave (Join-Path $persistenceDir "run_once.txt") {
        reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s
        reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s
    }

    RunSave (Join-Path $persistenceDir "winlogon_keys.txt") {
        reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s
        reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s
    }

    RunSave (Join-Path $persistenceDir "wmi_subscriptions.txt") {
        Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Format-List *
        Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Format-List *
        Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Format-List *
    }

    RunSave (Join-Path $persistenceDir "scheduled_tasks_summary.txt") {
        Get-ScheduledTask | Select-Object TaskName, State, Author, Date, TaskPath | Sort-Object TaskPath, TaskName | Format-Table -AutoSize
    }

    RunSave (Join-Path $persistenceDir "services_autostart.txt") {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Where-Object { $_.StartMode -match "Auto" } |
        Sort-Object Name | Format-Table -AutoSize
    }

    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path -LiteralPath $path) {
            $safePath = $path -replace '[:\\]', '_'
            RunSave (Join-Path $persistenceDir ("startup_{0}.txt" -f $safePath)) {
                Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
                Select-Object FullName, CreationTime, LastWriteTime, Length | Format-Table -AutoSize
            }
        }
    }
}

function Collect-SoftwareInfo([string]$outputDir) {
    Write-Host "[*] Collecting software information..." -ForegroundColor Green
    $softwareDir = Join-Path $outputDir "software"
    NewDir $softwareDir

    RunSave (Join-Path $softwareDir "installed_64.txt") {
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object DisplayName | Format-Table -AutoSize
    }

    RunSave (Join-Path $softwareDir "installed_32.txt") {
        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object DisplayName | Format-Table -AutoSize
    }

    RunSave (Join-Path $softwareDir "windows_features.txt") {
        try {
            Get-WindowsOptionalFeature -Online | Where-Object { $_.State -ne "Disabled" } |
            Select-Object FeatureName, State | Format-Table -AutoSize
        } catch {
            "Get-WindowsOptionalFeature not available."
        }
    }
}

function Collect-SecurityInfo([string]$outputDir) {
    Write-Host "[*] Collecting security information..." -ForegroundColor Green
    $securityDir = Join-Path $outputDir "security"
    NewDir $securityDir

    RunSave (Join-Path $securityDir "defender_status.txt") { Get-MpComputerStatus | Format-List * }
    RunSave (Join-Path $securityDir "defender_preferences.txt") { Get-MpPreference | Format-List * }
    RunSave (Join-Path $securityDir "defender_exclusions.txt") {
        try {
            $p = Get-MpPreference
            "ExclusionPath:"
            $p.ExclusionPath
            ""
            "ExclusionProcess:"
            $p.ExclusionProcess
            ""
            "ExclusionExtension:"
            $p.ExclusionExtension
        } catch {
            "Not available."
        }
    }

    RunSave (Join-Path $securityDir "auditpol.txt") { auditpol /get /category:* }
    RunSave (Join-Path $securityDir "firewall_status.txt") {
        netsh advfirewall show allprofiles
        netsh advfirewall show currentprofile
    }

    RunSave (Join-Path $securityDir "uac_settings.txt") {
        reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>$null
        reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2>$null
    }

    RunSave (Join-Path $securityDir "security_products_wmi.txt") {
        try {
            Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Format-List *
        } catch {
            "SecurityCenter2 not available."
        }
    }

    if (IsAdmin) {
        $mpLogSrc = Join-Path $env:ProgramData "Microsoft\Windows Defender\Support"
        if (Test-Path -LiteralPath $mpLogSrc) {
            $dst = Join-Path $securityDir "mp_logs"
            NewDir $dst
            $since = (Get-Date).AddDays(-14)
            $budget = New-CopyBudget -ModeValue $script:EffectiveMode
            Copy-Selective -SourceRoot $mpLogSrc -DestinationRoot $dst -Since $since -Extensions @(".log",".txt") -MaxFiles 2000 -Budget $budget
        }
    }
}

function Collect-EventLogs([string]$outputDir) {
    Write-Host "[*] Collecting event logs..." -ForegroundColor Green
    $evDir = Join-Path $outputDir "eventlogs"
    NewDir $evDir

    $baseLogs = @(
        "System",
        "Application",
        "Security",
        "Setup",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    )

    foreach($l in $baseLogs){
        $safe = $l.Replace("/","_").Replace(" ","_")
        ExportEvtx $l (Join-Path $evDir ($safe + ".evtx"))
    }

    if ($script:EffectiveMode -eq "Deep") {
        RunSave (Join-Path $evDir "all_logs_list.txt") { wevtutil el }
    }
}

function Collect-RegistryHives([string]$outputDir) {
    Write-Host "[*] Collecting registry hives..." -ForegroundColor Green
    $regDir = Join-Path $outputDir "registry"
    NewDir $regDir

    ExportReg "HKCU" (Join-Path $regDir "HKCU.reg")
    ExportReg "HKLM" (Join-Path $regDir "HKLM.reg")

    try {
        CopyFile "C:\Windows\System32\config\SYSTEM" (Join-Path $regDir "SYSTEM")
        CopyFile "C:\Windows\System32\config\SOFTWARE" (Join-Path $regDir "SOFTWARE")
        CopyFile "C:\Windows\System32\config\SECURITY" (Join-Path $regDir "SECURITY")
        CopyFile "C:\Windows\System32\config\SAM" (Join-Path $regDir "SAM")
    } catch {
        Write-Host "  [!] Could not copy registry hives (requires administrative privileges)" -ForegroundColor Red
    }

    $regKeys = @(
        "HKLM\SYSTEM\CurrentControlSet\Services",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        "HKCU\Software\Microsoft\Terminal Server Client\Servers",
        "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    )

    foreach ($key in $regKeys) {
        $safeKey = ($key -replace '\\', '_' -replace ':', '')
        ExportReg $key (Join-Path $regDir ("{0}.reg" -f $safeKey))
    }

    if ($script:EffectiveMode -eq "Deep") {
        $userRoot = "C:\Users"
        $dstUsersReg = Join-Path $regDir "per_user"
        NewDir $dstUsersReg

        if (Test-Path -LiteralPath $userRoot) {
            Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $u = $_.FullName
                $n = $_.Name
                $nt = Join-Path $u "NTUSER.DAT"
                $uc = Join-Path $u "AppData\Local\Microsoft\Windows\UsrClass.dat"
                if (Test-Path -LiteralPath $nt) { CopyFile $nt (Join-Path $dstUsersReg ("{0}_NTUSER.DAT" -f $n)) }
                if (Test-Path -LiteralPath $uc) { CopyFile $uc (Join-Path $dstUsersReg ("{0}_UsrClass.dat" -f $n)) }
            }
        }
    }
}

function Collect-OSArtifacts([string]$outputDir, [int]$daysBack) {
    Write-Host "[*] Collecting OS execution artifacts..." -ForegroundColor Green
    $artDir = Join-Path $outputDir "os_artifacts"
    NewDir $artDir

    $since = (Get-Date).AddDays(-$daysBack)
    $budget = New-CopyBudget -ModeValue $script:EffectiveMode

    $prefetchDst = Join-Path $artDir "prefetch"
    if (Test-Path -LiteralPath "C:\Windows\Prefetch") {
        Copy-Selective -SourceRoot "C:\Windows\Prefetch" -DestinationRoot $prefetchDst -Since $since -Extensions @(".pf") -MaxFiles 5000 -Budget $budget
        List-RecentFiles -SourceRoot "C:\Windows\Prefetch" -OutCsv (Join-Path $artDir "prefetch_recent.csv") -Since $since -Extensions @(".pf") -MaxRows ($(if ($script:EffectiveMode -eq "Deep") { 20000 } else { 8000 }))
    }

    CopyFile "C:\Windows\AppCompat\Programs\Amcache.hve" (Join-Path $artDir "Amcache.hve")

    if (Test-Path -LiteralPath "C:\Windows\System32\sru") {
        if ($script:EffectiveMode -eq "Deep") {
            Copy-Selective -SourceRoot "C:\Windows\System32\sru" -DestinationRoot (Join-Path $artDir "sru") -Since $since.AddDays(-3650) -Extensions @(".dat") -MaxFiles 200 -Budget $budget
        } else {
            List-RecentFiles -SourceRoot "C:\Windows\System32\sru" -OutCsv (Join-Path $artDir "sru_listing.csv") -Since $since.AddDays(-3650) -Extensions @() -MaxRows 3000
        }
    }

    RunSave (Join-Path $artDir "shimcache_hint.txt") {
        reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache 2>$null
        reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /s 2>$null
    }

    RunSave (Join-Path $artDir "recycle_bin_listing.txt") {
        try {
            Get-ChildItem -LiteralPath "C:\`$Recycle.Bin" -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, CreationTime, LastWriteTime, Length | Format-Table -AutoSize
        } catch {
            "Not accessible."
        }
    }
}

function Collect-BrowserArtifacts([string]$userPath, [string]$userName, [string]$outputBase) {
    $browserTargets = @()

    $chromeBase = Join-Path $userPath "AppData\Local\Google\Chrome\User Data"
    if (Test-Path -LiteralPath $chromeBase) {
        $profiles = Get-ChildItem -LiteralPath $chromeBase -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^(Default|Profile \d+)$" }
        foreach ($p in $profiles) {
            $browserTargets += @{Name=("Chrome_{0}" -f $p.Name); Path=$p.FullName}
        }
    }

    $edgeBase = Join-Path $userPath "AppData\Local\Microsoft\Edge\User Data"
    if (Test-Path -LiteralPath $edgeBase) {
        $profiles = Get-ChildItem -LiteralPath $edgeBase -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^(Default|Profile \d+)$" }
        foreach ($p in $profiles) {
            $browserTargets += @{Name=("Edge_{0}" -f $p.Name); Path=$p.FullName}
        }
    }

    $braveBase = Join-Path $userPath "AppData\Local\BraveSoftware\Brave-Browser\User Data"
    if (Test-Path -LiteralPath $braveBase) {
        $profiles = Get-ChildItem -LiteralPath $braveBase -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^(Default|Profile \d+)$" }
        foreach ($p in $profiles) {
            $browserTargets += @{Name=("Brave_{0}" -f $p.Name); Path=$p.FullName}
        }
    }

    $firefoxBase = Join-Path $userPath "AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $firefoxBase) {
        $browserTargets += @{Name="Firefox_Profiles"; Path=$firefoxBase}
    }

    foreach($browser in $browserTargets) {
        $browserName = $browser.Name
        $browserDir = $browser.Path

        if(Test-Path -LiteralPath $browserDir) {
            $browserOutput = Join-Path $outputBase ("{0}\Browser_{1}" -f $userName, $browserName)
            NewDir $browserOutput

            if ($browserName -like "Firefox_*") {
                try {
                    $profiles = Get-ChildItem -LiteralPath $browserDir -Directory -ErrorAction SilentlyContinue
                    foreach ($p in $profiles) {
                        $po = Join-Path $browserOutput ("Profile_{0}" -f $p.Name)
                        NewDir $po
                        $ffFiles = @("places.sqlite","cookies.sqlite","logins.json","key4.db","formhistory.sqlite","prefs.js","addons.json")
                        foreach ($ff in $ffFiles) {
                            $sf = Join-Path $p.FullName $ff
                            if (Test-Path -LiteralPath $sf) { CopyFile $sf (Join-Path $po $ff) }
                        }
                    }
                } catch {}
                Write-Host ("    [+] Collected {0} artifacts for {1}" -f "Firefox", $userName) -ForegroundColor Green
                continue
            }

            $artifactFiles = @(
                "History",
                "Cookies",
                "Login Data",
                "Web Data",
                "Preferences",
                "Bookmarks",
                "Last Session",
                "Current Session",
                "Visited Links",
                "Shortcuts",
                "Top Sites",
                "Favicons",
                "Network\Cookies"
            )

            foreach($file in $artifactFiles) {
                $srcFile = Join-Path $browserDir $file
                if(Test-Path -LiteralPath $srcFile) {
                    $safeName = $file -replace '[\\/:*?"<>|]', '_'
                    CopyFile $srcFile (Join-Path $browserOutput $safeName)
                }
            }

            $extDir = Join-Path $browserDir "Extensions"
            if (Test-Path -LiteralPath $extDir) {
                RunSave (Join-Path $browserOutput "extensions_listing.txt") {
                    Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue |
                    Select-Object FullName, CreationTime, LastWriteTime | Sort-Object LastWriteTime -Descending | Format-Table -AutoSize
                }
            }

            Write-Host ("    [+] Collected {0} artifacts for {1}" -f $browserName, $userName) -ForegroundColor Green
        }
    }
}

function Collect-UserArtifacts([string]$outputDir, [int]$daysBack) {
    Write-Host "[*] Collecting user artifacts (MRU/JumpLists/LNK/Histories)..." -ForegroundColor Green
    $usersArtifactsDir = Join-Path $outputDir "users_artifacts"
    NewDir $usersArtifactsDir

    $since = (Get-Date).AddDays(-$daysBack)
    $budget = New-CopyBudget -ModeValue $script:EffectiveMode

    $userRoot = "C:\Users"
    if (Test-Path -LiteralPath $userRoot) {
        Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $u = $_.FullName
            $name = $_.Name

            $userDir = Join-Path $usersArtifactsDir $name
            NewDir $userDir

            $mruDir = Join-Path $userDir "mru"
            NewDir $mruDir

            $recent = Join-Path $u "AppData\Roaming\Microsoft\Windows\Recent"
            $autoJL = Join-Path $u "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
            $custJL = Join-Path $u "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"

            if (Test-Path -LiteralPath $recent) {
                Copy-Selective -SourceRoot $recent -DestinationRoot (Join-Path $mruDir "Recent") -Since $since -Extensions @(".lnk") -MaxFiles 5000 -Budget $budget
                List-RecentFiles -SourceRoot $recent -OutCsv (Join-Path $mruDir "recent_lnk.csv") -Since $since.AddDays(-3650) -Extensions @(".lnk") -MaxRows 20000
            }

            if (Test-Path -LiteralPath $autoJL) {
                Copy-Selective -SourceRoot $autoJL -DestinationRoot (Join-Path $mruDir "AutomaticDestinations") -Since $since.AddDays(-3650) -Extensions @(".automaticDestinations-ms") -MaxFiles 5000 -Budget $budget
            }

            if (Test-Path -LiteralPath $custJL) {
                Copy-Selective -SourceRoot $custJL -DestinationRoot (Join-Path $mruDir "CustomDestinations") -Since $since.AddDays(-3650) -Extensions @(".customDestinations-ms") -MaxFiles 5000 -Budget $budget
            }

            $psHist = Join-Path $u "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if (Test-Path -LiteralPath $psHist) {
                CopyFile $psHist (Join-Path $userDir "powershell_history.txt")
            }

            $rdp = Join-Path $u "Documents\Default.rdp"
            if (Test-Path -LiteralPath $rdp) { CopyFile $rdp (Join-Path $userDir "default_rdp.rdp") }

            RunSave (Join-Path $userDir "rdp_registry.txt") {
                reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>$null
                reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /s 2>$null
            }

            RunSave (Join-Path $userDir "office_mru_registry.txt") {
                $officeApps = @("Word", "Excel", "PowerPoint", "Access", "Publisher", "Visio", "Project", "OneNote")
                foreach ($app in $officeApps) {
                    ("=== Microsoft {0} ===" -f $app)
                    reg query ("HKCU\Software\Microsoft\Office\16.0\{0}\File MRU" -f $app) /s 2>$null
                    reg query ("HKCU\Software\Microsoft\Office\15.0\{0}\File MRU" -f $app) /s 2>$null
                    reg query ("HKCU\Software\Microsoft\Office\14.0\{0}\File MRU" -f $app) /s 2>$null
                    ""
                }
            }

            if ($script:IncludeBrowserArtifactsRuntime) {
                Write-Host ("  [*] Browser artifacts for user: {0}" -f $name) -ForegroundColor Yellow
                Collect-BrowserArtifacts $u $name $userDir
            }

            if ($script:EffectiveMode -eq "Deep") {
                $ntuserPath = Join-Path $u "NTUSER.DAT"
                if (Test-Path -LiteralPath $ntuserPath) { CopyFile $ntuserPath (Join-Path $userDir "NTUSER.DAT") }
                $usrClassPath = Join-Path $u "AppData\Local\Microsoft\Windows\UsrClass.dat"
                if (Test-Path -LiteralPath $usrClassPath) { CopyFile $usrClassPath (Join-Path $userDir "UsrClass.dat") }
            }

            $suspDir = Join-Path $userDir "suspicious_recent_files"
            NewDir $suspDir

            $susExt = @(".exe",".dll",".sys",".ps1",".vbs",".bat",".cmd",".js",".jse",".hta",".lnk",".iso",".img",".vhd",".vhdx",".zip",".7z",".rar",".msi",".msp")
            $appdataLocal = Join-Path $u "AppData\Local"
            $appdataRoam  = Join-Path $u "AppData\Roaming"
            $downloads = Join-Path $u "Downloads"

            List-RecentFiles -SourceRoot $downloads -OutCsv (Join-Path $suspDir "downloads_recent_suspicious.csv") -Since $since -Extensions $susExt -MaxRows 5000

            if ($script:EffectiveMode -eq "Deep") {
                Copy-Selective -SourceRoot $downloads -DestinationRoot (Join-Path $suspDir "downloads_samples") -Since $since -Extensions $susExt -MaxFiles 200 -Budget $budget
            }

            List-RecentFiles -SourceRoot $appdataLocal -OutCsv (Join-Path $suspDir "appdata_local_recent_suspicious.csv") -Since $since -Extensions $susExt -MaxRows 8000
            List-RecentFiles -SourceRoot $appdataRoam -OutCsv (Join-Path $suspDir "appdata_roaming_recent_suspicious.csv") -Since $since -Extensions $susExt -MaxRows 8000
        }
    }
}

function Collect-FileListings([string]$outputDir, [int]$daysBack) {
    Write-Host "[*] Creating targeted file listings..." -ForegroundColor Green
    $listingsDir = Join-Path $outputDir "file_listings"
    NewDir $listingsDir

    $since = (Get-Date).AddDays(-$daysBack)
    $maxRows = $(if ($script:EffectiveMode -eq "Deep") { $script:Defaults.MaxListings_Deep } else { $script:Defaults.MaxListings_Triage })

    $targets = @(
        @{Name="Windows_Temp"; Path="C:\Windows\Temp"},
        @{Name="ProgramData"; Path="C:\ProgramData"},
        @{Name="Users_Public"; Path="C:\Users\Public"},
        @{Name="Tasks"; Path="C:\Windows\System32\Tasks"},
        @{Name="Drivers"; Path="C:\Windows\System32\drivers"},
        @{Name="Startup_Common"; Path="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"}
    )

    $susExt = @(".exe",".dll",".sys",".ps1",".vbs",".bat",".cmd",".js",".jse",".hta",".lnk",".msi",".msp")

    foreach ($t in $targets) {
        if (Test-Path -LiteralPath $t.Path) {
            List-RecentFiles -SourceRoot $t.Path -OutCsv (Join-Path $listingsDir ("{0}_recent_suspicious.csv" -f $t.Name)) -Since $since -Extensions $susExt -MaxRows $maxRows
        }
    }
}

function Collect-EnhancedArtifacts([string]$outputDir, [int]$daysBack) {
    Write-Host ("`n[+] Collecting Enhanced Artifacts (last {0} days)..." -f $daysBack) -ForegroundColor Green

    $enhancedDir = Join-Path $outputDir "enhanced_artifacts"
    NewDir $enhancedDir

    $dateThreshold = (Get-Date).AddDays(-$daysBack)

    RunSave (Join-Path $enhancedDir ("windows_timeline_{0}days.txt" -f $daysBack)) {
        try {
            $timelinePath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform\*"
            if (Test-Path $timelinePath) {
                Get-ChildItem -Path $timelinePath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $dateThreshold } |
                Select-Object Name, FullName, LastWriteTime, Length |
                Sort-Object LastWriteTime -Descending |
                Format-Table -AutoSize
            } else {
                "Windows Timeline database not found."
            }
        } catch {
            ("Error accessing Windows Timeline: {0}" -f $_.Exception.Message)
        }
    }

    RunSave (Join-Path $enhancedDir ("notifications_{0}days.txt" -f $daysBack)) {
        try {
            $notificationPath = "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\*"
            if (Test-Path $notificationPath) {
                Get-ChildItem -Path $notificationPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $dateThreshold } |
                Select-Object Name, LastWriteTime, Length |
                Sort-Object LastWriteTime -Descending |
                Format-Table -AutoSize
            } else {
                "Notification database not found."
            }
        } catch {
            ("Error accessing notification database: {0}" -f $_.Exception.Message)
        }
    }

    RunSave (Join-Path $enhancedDir "defender_recent_events.txt") {
        try {
            Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 800 -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $dateThreshold } |
            Select-Object TimeCreated, Id, ProviderName, Message |
            Sort-Object TimeCreated -Descending |
            Format-Table -AutoSize
        } catch {
            ("Error accessing Windows Defender logs: {0}" -f $_.Exception.Message)
        }
    }

    RunSave (Join-Path $enhancedDir "powershell_op_recent.txt") {
        try {
            Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1200 -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $dateThreshold } |
            Select-Object TimeCreated, Id, ProviderName, Message |
            Sort-Object TimeCreated -Descending |
            Format-Table -AutoSize
        } catch {
            "Not available."
        }
    }

    RunSave (Join-Path $enhancedDir "shadow_copies.txt") {
        try { vssadmin list shadows } catch { "Not available." }
    }

    RunSave (Join-Path $enhancedDir "remotely_opened_files.txt") {
        try { openfiles /query /fo table /v 2>&1 | Out-String } catch { "Not available." }
    }
}

function Collect-NetworkForensics([string]$outputDir, [int]$daysBack) {
    Write-Host "`n[+] Collecting Network Forensic Artifacts..." -ForegroundColor Green

    $networkDir = Join-Path $outputDir "network_forensics"
    NewDir $networkDir

    RunSave (Join-Path $networkDir "detailed_network_connections.txt") {
        "Active Network Connections:"
        "==========================="
        netstat -anob
    }

    RunSave (Join-Path $networkDir "dns_cache_analysis.txt") {
        "DNS Cache Entries:"
        "=================="
        ipconfig /displaydns | Out-String
        ""
        try {
            Get-DnsClientCache | Select-Object Entry, Name, Data, DataLength, TTL | Sort-Object Name | Format-Table -AutoSize
        } catch {
            "Get-DnsClientCache not available."
        }
    }

    RunSave (Join-Path $networkDir "firewall_detailed.txt") {
        netsh advfirewall show currentprofile
        ""
        netsh advfirewall show allprofiles
    }

    RunSave (Join-Path $networkDir "rdp_sessions.txt") {
        try { qwinsta } catch { "Not available." }
        ""
        try { quser } catch { "Not available." }
    }

    RunSave (Join-Path $networkDir "usb_connected_devices.txt") {
        try {
            Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Class -match "USB" } |
            Select-Object FriendlyName, Class, InstanceId, Status, Manufacturer | Format-Table -AutoSize
        } catch {
            "Get-PnpDevice not available."
        }
    }
}

function Run-ThirdPartyTools([string]$outputDir, [string]$toolsPath, [array]$availableTools) {
    Write-Host "`n[+] Running Third-Party Analysis Tools..." -ForegroundColor Green

    $thirdPartyDir = Join-Path $outputDir "third_party_analysis"
    NewDir $thirdPartyDir

    $summary = @()
    $summary += ("RunTime: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    $summary += ("ToolsDir: {0}" -f $toolsPath)
    $summary += ("AvailableTools: {0}" -f ($availableTools -join ", "))
    $summary += ""

    $autorunsPath = $null
    $tcpviewPath = $null
    $sigcheckPath = $null

    try { $autorunsPath = $script:ResolvedToolPaths["Autoruns"] } catch { $autorunsPath = $null }
    try { $tcpviewPath = $script:ResolvedToolPaths["TCPView"] } catch { $tcpviewPath = $null }
    try { $sigcheckPath = $script:ResolvedToolPaths["Sigcheck"] } catch { $sigcheckPath = $null }

    if ($autorunsPath -and (Test-FileValid -FilePath $autorunsPath)) {
        Write-Host "  [*] Running Autoruns" -ForegroundColor Yellow
        RunSave (Join-Path $thirdPartyDir "autoruns_output.csv") { & $autorunsPath -accepteula -a * -c -h -s -m -vt 2>&1 }
        $summary += ("Autoruns: executed ({0})" -f $autorunsPath)
    } else {
        $summary += "Autoruns: not available"
    }

    if ($tcpviewPath -and (Test-FileValid -FilePath $tcpviewPath)) {
        Write-Host "  [*] Running TCPView" -ForegroundColor Yellow
        RunSave (Join-Path $thirdPartyDir "tcpview_output.txt") { & $tcpviewPath -accepteula -c 2>&1 }
        $summary += ("TCPView: executed ({0})" -f $tcpviewPath)
    } else {
        $summary += "TCPView: not available"
    }

    if ($sigcheckPath -and (Test-FileValid -FilePath $sigcheckPath)) {
        Write-Host "  [*] Running Sigcheck on high-risk locations..." -ForegroundColor Yellow
        RunSave (Join-Path $thirdPartyDir "sigcheck_output.txt") {
            $targets = @(
                "C:\Windows\Temp",
                "$env:TEMP",
                "C:\Users\Public",
                "C:\ProgramData",
                "C:\Windows\System32",
                "C:\Windows\SysWOW64"
            )

            foreach ($t in $targets) {
                if (Test-Path -LiteralPath $t) {
                    ("=== {0} ===" -f $t)
                    & $sigcheckPath -accepteula -u -e -h -s $t 2>&1
                    ""
                }
            }
        }
        $summary += ("Sigcheck: executed ({0})" -f $sigcheckPath)
    } else {
        $summary += "Sigcheck: not available"
    }

    $summaryFile = Join-Path $thirdPartyDir "third_party_summary.txt"
    SaveText $summaryFile ($summary -join "`r`n")
}

function CollectAD([string]$outputDir) {
    Write-Host "[*] Collecting Active Directory information..." -ForegroundColor Green
    $adDir = Join-Path $outputDir "active_directory"
    NewDir $adDir

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.PartOfDomain) {
        Write-Host ("  [+] Computer is domain joined to: {0}" -f $cs.Domain) -ForegroundColor Green

        RunSave (Join-Path $adDir "domain_info.txt") {
            ("Domain Name: {0}" -f $cs.Domain)
            ("Domain Role: {0}" -f $cs.DomainRole)
            ("Workgroup: {0}" -f $cs.Workgroup)
            ""
        }

        RunSave (Join-Path $adDir "domain_policies.txt") { gpresult /z 2>$null | Out-String }
        RunSave (Join-Path $adDir "domain_trusts.txt") { nltest /domain_trusts 2>$null }
        RunSave (Join-Path $adDir "domain_users.txt") { query user /server:$($cs.Domain) 2>$null }
    } else {
        Write-Host "  [!] Computer is not domain joined" -ForegroundColor Yellow
        SaveText (Join-Path $adDir "not_domain_joined.txt") "Computer is not part of a domain"
    }
}

function Collect-SIEMExports([string]$outputDir, [int]$daysBack) {
    if (-not $script:ExportSIEMRuntime) { return }

    Write-Host "`n[+] Exporting SIEM CSV files..." -ForegroundColor Green
    $siemDir = Join-Path $outputDir "siem"
    NewDir $siemDir

    $threshold = (Get-Date).AddDays(-$daysBack)

    try {
        $ip = @()
        try {
            $adapters = Get-NetIPConfiguration -ErrorAction SilentlyContinue
            foreach ($a in $adapters) {
                $ip += [pscustomobject]@{
                    InterfaceAlias = $a.InterfaceAlias
                    IPv4Address = ($a.IPv4Address | ForEach-Object { $_.IPv4Address }) -join ";"
                    IPv6Address = ($a.IPv6Address | ForEach-Object { $_.IPv6Address }) -join ";"
                    DNSServer = ($a.DnsServer.ServerAddresses) -join ";"
                    IPv4DefaultGateway = ($a.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ";"
                    IPv6DefaultGateway = ($a.IPv6DefaultGateway | ForEach-Object { $_.NextHop }) -join ";"
                    DHCP = $a.Dhcp
                }
            }
        } catch {
            $ip += [pscustomobject]@{ InterfaceAlias=""; IPv4Address=""; IPv6Address=""; DNSServer=""; IPv4DefaultGateway=""; IPv6DefaultGateway=""; DHCP="" }
        }
        Export-CsvUtf8 -Path (Join-Path $siemDir "IPConfiguration.csv") -Data $ip
    } catch {}

    try {
        $tcp = @()
        try {
            $c = Get-NetTCPConnection -ErrorAction SilentlyContinue
            foreach ($x in $c) {
                $pname = ""
                try { $pname = (Get-Process -Id $x.OwningProcess -ErrorAction SilentlyContinue).Name } catch { $pname = "" }
                $tcp += [pscustomobject]@{
                    State = $x.State
                    LocalAddress = $x.LocalAddress
                    LocalPort = $x.LocalPort
                    RemoteAddress = $x.RemoteAddress
                    RemotePort = $x.RemotePort
                    OwningProcess = $x.OwningProcess
                    ProcessName = $pname
                }
            }
        } catch {
            $tcp = @()
        }
        Export-CsvUtf8 -Path (Join-Path $siemDir "OpenTCPConnections.csv") -Data $tcp
    } catch {}

    try {
        $procs = @()
        try {
            $p = Get-Process -ErrorAction SilentlyContinue
            foreach ($x in $p) {
                $procs += [pscustomobject]@{
                    Name = $x.Name
                    Id = $x.Id
                    Path = $x.Path
                    StartTime = $x.StartTime
                    WorkingSetMB = [math]::Round(($x.WorkingSet64/1MB),2)
                    CPU = $x.CPU
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "Processes.csv") -Data $procs
    } catch {}

    try {
        $svc = @()
        try {
            $s = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
            foreach ($x in $s) {
                $svc += [pscustomobject]@{
                    Name = $x.Name
                    DisplayName = $x.DisplayName
                    State = $x.State
                    StartMode = $x.StartMode
                    StartName = $x.StartName
                    PathName = $x.PathName
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "RunningServices.csv") -Data $svc
    } catch {}

    try {
        $tasks = @()
        try {
            $t = Get-ScheduledTask -ErrorAction SilentlyContinue
            foreach ($x in $t) {
                $tasks += [pscustomobject]@{
                    TaskName = $x.TaskName
                    TaskPath = $x.TaskPath
                    State = $x.State
                    Author = $x.Author
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "ScheduledTasks.csv") -Data $tasks
    } catch {}

    try {
        $users = @()
        try {
            $u = Get-LocalUser -ErrorAction SilentlyContinue
            foreach ($x in $u) {
                $users += [pscustomobject]@{
                    Name = $x.Name
                    Enabled = $x.Enabled
                    LastLogon = $x.LastLogon
                    PasswordLastSet = $x.PasswordLastSet
                    SID = $x.SID.Value
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "LocalUsers.csv") -Data $users
    } catch {}

    try {
        $activeUsers = @()
        try {
            $raw = quser 2>$null
            foreach ($line in $raw) {
                $activeUsers += [pscustomobject]@{ Line = $line }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "ActiveUsers.csv") -Data $activeUsers
    } catch {}

    try {
        $dns = @()
        try {
            $d = Get-DnsClientCache -ErrorAction SilentlyContinue
            foreach ($x in $d) {
                $dns += [pscustomobject]@{
                    Entry = $x.Entry
                    Name = $x.Name
                    Data = $x.Data
                    TTL = $x.TTL
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "DNSCache.csv") -Data $dns
    } catch {}

    try {
        $shares = @()
        try {
            $s = Get-SmbShare -ErrorAction SilentlyContinue
            foreach ($x in $s) {
                $shares += [pscustomobject]@{
                    Name = $x.Name
                    Path = $x.Path
                    Description = $x.Description
                    ShareState = $x.ShareState
                }
            }
        } catch {
            try {
                $raw = net share
                foreach ($line in $raw) { $shares += [pscustomobject]@{ Line = $line } }
            } catch {}
        }
        Export-CsvUtf8 -Path (Join-Path $siemDir "NetworkShares.csv") -Data $shares
    } catch {}

    try {
        $usb = @()
        try {
            $d = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Class -match "USB" }
            foreach ($x in $d) {
                $usb += [pscustomobject]@{
                    FriendlyName = $x.FriendlyName
                    InstanceId = $x.InstanceId
                    Status = $x.Status
                    Manufacturer = $x.Manufacturer
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "ConnectedDevices.csv") -Data $usb
    } catch {}

    try {
        $soft = @()
        try {
            $a = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                 Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
            foreach ($x in $a) {
                if ([string]::IsNullOrWhiteSpace($x.DisplayName)) { continue }
                $soft += [pscustomobject]@{
                    DisplayName = $x.DisplayName
                    DisplayVersion = $x.DisplayVersion
                    Publisher = $x.Publisher
                    InstallDate = $x.InstallDate
                    InstallLocation = $x.InstallLocation
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "InstalledSoftware.csv") -Data $soft
    } catch {}

    try {
        $drivers = @()
        try {
            $raw = pnputil /enum-drivers 2>&1
            foreach ($line in $raw) { $drivers += [pscustomobject]@{ Line = $line } }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "Drivers.csv") -Data $drivers
    } catch {}

    try {
        $defEx = @()
        try {
            $p = Get-MpPreference -ErrorAction SilentlyContinue
            $defEx += [pscustomobject]@{ Type="ExclusionPath"; Value=(($p.ExclusionPath) -join ";") }
            $defEx += [pscustomobject]@{ Type="ExclusionProcess"; Value=(($p.ExclusionProcess) -join ";") }
            $defEx += [pscustomobject]@{ Type="ExclusionExtension"; Value=(($p.ExclusionExtension) -join ";") }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "DefenderExclusions.csv") -Data $defEx
    } catch {}

    try {
        $shadow = @()
        try {
            $raw = vssadmin list shadows 2>&1
            foreach ($line in $raw) { $shadow += [pscustomobject]@{ Line = $line } }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "ShadowCopy.csv") -Data $shadow
    } catch {}

    try {
        $rdp = @()
        try {
            $raw = qwinsta 2>$null
            foreach ($line in $raw) { $rdp += [pscustomobject]@{ Line = $line } }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "RDPSessions.csv") -Data $rdp
    } catch {}

    try {
        $officeProcs = @("WINWORD","EXCEL","POWERPNT","OUTLOOK","ONENOTE","MSACCESS","VISIO","WINPROJ")
        $office = @()
        try {
            $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
            foreach ($x in $conns) {
                $pname = ""
                try { $pname = (Get-Process -Id $x.OwningProcess -ErrorAction SilentlyContinue).Name } catch { $pname = "" }
                if ([string]::IsNullOrWhiteSpace($pname)) { continue }
                if ($officeProcs -contains $pname.ToUpperInvariant()) {
                    $office += [pscustomobject]@{
                        ProcessName = $pname
                        OwningProcess = $x.OwningProcess
                        State = $x.State
                        LocalAddress = $x.LocalAddress
                        LocalPort = $x.LocalPort
                        RemoteAddress = $x.RemoteAddress
                        RemotePort = $x.RemotePort
                    }
                }
            }
        } catch {}
        Export-CsvUtf8 -Path (Join-Path $siemDir "OfficeConnections.csv") -Data $office
    } catch {}

    if (IsAdmin) {
        try {
            $sec = @()
            $ids = @(4624,4625,4672,4688,4697,4698,4702,4720,4722,4723,4724,4725,4726,4732,4733,4738,4740,4768,4769,4776,1102)
            try {
                $events = Get-WinEvent -FilterHashtable @{ LogName="Security"; StartTime=$threshold } -ErrorAction SilentlyContinue |
                          Where-Object { $ids -contains $_.Id } | Select-Object TimeCreated, Id, ProviderName, Message
                foreach ($e in $events) {
                    $sec += [pscustomobject]@{
                        TimeCreated = $e.TimeCreated
                        Id = $e.Id
                        ProviderName = $e.ProviderName
                        Message = $e.Message
                    }
                }
            } catch {}
            Export-CsvUtf8 -Path (Join-Path $siemDir "SecurityEvents.csv") -Data $sec
        } catch {}
    } else {
        Export-CsvUtf8 -Path (Join-Path $siemDir "SecurityEvents.csv") -Data @()
    }
}

function Write-IOCQuickSummary([string]$outputDir, [int]$daysBack) {
    Write-Host "[*] Building quick IOC summary..." -ForegroundColor Green
    $metaDir = Join-Path $outputDir "meta"
    NewDir $metaDir
    $p = Join-Path $metaDir "ioc_summary.txt"

    $threshold = (Get-Date).AddDays(-$daysBack)

    $lines = @()
    $lines += ("Time: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    $lines += ("Host: {0}" -f $env:COMPUTERNAME)
    $lines += ("DaysBack: {0}" -f $daysBack)
    $lines += ("IsAdmin: {0}" -f ($(if (IsAdmin) { "True" } else { "False" })))
    $lines += ""

    try {
        $susExt = @(".exe",".dll",".sys",".ps1",".vbs",".bat",".cmd",".js",".jse",".hta",".lnk",".msi",".msp",".iso",".img",".vhd",".vhdx",".zip",".7z",".rar")
        $countSus = 0
        $roots = @("C:\Users","C:\ProgramData","C:\Windows\Temp")
        foreach ($r in $roots) {
            if (-not (Test-Path -LiteralPath $r)) { continue }
            try {
                $files = Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $threshold }
                foreach ($f in $files) {
                    if ($susExt -contains $f.Extension.ToLowerInvariant()) { $countSus++ }
                }
            } catch {}
        }
        $lines += ("Recent suspicious extensions (rough count): {0}" -f $countSus)
    } catch {}

    try {
        $ex = ""
        try { $p = Get-MpPreference -ErrorAction SilentlyContinue; $ex = (($p.ExclusionPath) -join ";") } catch { $ex = "" }
        if ([string]::IsNullOrWhiteSpace($ex)) { $lines += "Defender exclusions path: None/Unavailable" } else { $lines += ("Defender exclusions path: {0}" -f $ex) }
    } catch {}

    try {
        $lines += ""
        $lines += "Top outbound connections (by process):"
        $counts = @{}
        try {
            $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" }
            foreach ($c in $conns) {
                $pn = ""
                try { $pn = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } catch { $pn = "" }
                if ([string]::IsNullOrWhiteSpace($pn)) { $pn = ("PID_{0}" -f $c.OwningProcess) }
                if (-not $counts.ContainsKey($pn)) { $counts[$pn] = 0 }
                $counts[$pn] = [int]$counts[$pn] + 1
            }
        } catch {}

        $top = $counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15
        foreach ($t in $top) { $lines += ("  {0}: {1}" -f $t.Key, $t.Value) }
    } catch {}

    SaveText $p ($lines -join "`r`n")
}

function Compress-OutputFolder([string]$OutDir) {
    if (-not $script:ZipOutputRuntime) { return $null }
    try {
        $zipPath = $OutDir.TrimEnd('\') + ".zip"
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path $OutDir -DestinationPath $zipPath -Force
        if (Test-Path -LiteralPath $zipPath) { return $zipPath }
        return $null
    } catch {
        return $null
    }
}

try {
    $script:EffectiveMode = Get-ModeSelection
    $daysBack = Get-TimeframeSelection

    $script:ToolsPolicy = Get-ToolsPolicySelection
    if ($script:ToolsPolicy -eq "Offline") {
        $OfflineOnly = $true
        $AutoDownloadTools = $false
    } else {
        $OfflineOnly = $false
        $AutoDownloadTools = $true
    }

    Resolve-DefaultTogglesForDeep

    Show-Banner -SelectedTimeframe $daysBack

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    if ([string]::IsNullOrWhiteSpace($OutRoot)) {
        $base = $PSScriptRoot
        if ([string]::IsNullOrWhiteSpace($base)) { $base = $PWD.Path }
        if ($base -like "$env:WINDIR*") { $base = [Environment]::GetFolderPath("Desktop") }
        $OutRoot = Join-Path $base "windows_Forensic_Collections"
    }

    $OutDir = Join-Path $OutRoot ("windows_Forensic_{0}_{1}" -f $env:COMPUTERNAME, $timestamp)
    NewDir $OutDir

    $ToolsDir = Initialize-ToolsDirectory -toolsPath $ToolsDir
    $availableTools = Check-RequiredTools -toolsPath $ToolsDir

    if ($script:StopRequested) {
        Write-Host ("`n[!] {0}" -f $script:StopReason) -ForegroundColor Red
        Write-Host "[!] Script stopped without closing PowerShell." -ForegroundColor Yellow
        return
    }

    Write-ToolsInventory -OutDir $OutDir -ToolsRoot $ToolsDir

    $runInfoContent = "iKarus Forensic Toolkit v3.6`r`n"
    $runInfoContent += ("Collection Time: {0}`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $runInfoContent += ("Computer: {0}`r`n" -f $env:COMPUTERNAME)
    $runInfoContent += ("User: {0}`r`n" -f $env:USERNAME)
    $runInfoContent += ("Domain: {0}`r`n" -f $env:USERDOMAIN)
    $runInfoContent += ("Mode: {0}`r`n" -f $script:EffectiveMode)
    $runInfoContent += ("Timeframe: {0} days`r`n" -f $daysBack)
    $runInfoContent += ("Tools Policy: {0}`r`n" -f $script:ToolsPolicy)
    $runInfoContent += ("Tools Available: {0}`r`n" -f ($availableTools -join ', '))
    $runInfoContent += ("Offline Packages Dir: {0}`r`n" -f (Join-Path $ToolsDir "OfflinePackages"))
    $runInfoContent += ("OfflineOnly: {0}`r`n" -f ($(if ($OfflineOnly) { "True" } else { "False" })))
    $runInfoContent += ("AutoDownloadTools: {0}`r`n" -f ($(if ($AutoDownloadTools) { "True" } else { "False" })))
    $runInfoContent += ("IncludeMemoryDump: {0}`r`n" -f ($(if ($script:IncludeMemoryDumpRuntime) { "True" } else { "False" })))
    $runInfoContent += ("HashEvidence: {0}`r`n" -f ($(if ($script:HashEvidenceRuntime) { "True" } else { "False" })))
    $runInfoContent += ("RunTools: {0}`r`n" -f ($(if ($script:RunToolsRuntime) { "True" } else { "False" })))
    $runInfoContent += ("IncludeUserArtifacts: {0}`r`n" -f ($(if ($script:IncludeUserArtifactsRuntime) { "True" } else { "False" })))
    $runInfoContent += ("IncludeBrowserArtifacts: {0}`r`n" -f ($(if ($script:IncludeBrowserArtifactsRuntime) { "True" } else { "False" })))
    $runInfoContent += ("ExportSIEM: {0}`r`n" -f ($(if ($script:ExportSIEMRuntime) { "True" } else { "False" })))
    $runInfoContent += ("ZipOutput: {0}`r`n" -f ($(if ($script:ZipOutputRuntime) { "True" } else { "False" })))

    SaveText (Join-Path $OutDir "meta\run_info.txt") $runInfoContent

    $global:TranscriptPath = Join-Path $OutDir "meta\transcript.txt"
    Start-Transcript -Path $global:TranscriptPath -Force -Append | Out-Null

    $collectionPhases = @()

    if ($script:IncludeMemoryDumpRuntime) {
        $collectionPhases += @{Name = "Memory Acquisition"; ScriptBlock = { Acquire-Memory $OutDir $ToolsDir } }
    }

    $collectionPhases += @{Name = "System Information"; ScriptBlock = { Collect-SystemInfo $OutDir } }
    $collectionPhases += @{Name = "User Information"; ScriptBlock = { Collect-UserInfo $OutDir $daysBack } }
    $collectionPhases += @{Name = "Process and Services"; ScriptBlock = { Collect-ProcessInfo $OutDir } }
    $collectionPhases += @{Name = "Network Information"; ScriptBlock = { Collect-NetworkInfo $OutDir } }
    $collectionPhases += @{Name = "Persistence Mechanisms"; ScriptBlock = { Collect-Persistence $OutDir } }
    $collectionPhases += @{Name = "Software Inventory"; ScriptBlock = { Collect-SoftwareInfo $OutDir } }
    $collectionPhases += @{Name = "Security Information"; ScriptBlock = { Collect-SecurityInfo $OutDir } }
    $collectionPhases += @{Name = "Event Logs"; ScriptBlock = { Collect-EventLogs $OutDir } }
    $collectionPhases += @{Name = "Registry Hives"; ScriptBlock = { Collect-RegistryHives $OutDir } }
    $collectionPhases += @{Name = "OS Execution Artifacts"; ScriptBlock = { Collect-OSArtifacts $OutDir $daysBack } }

    if ($script:IncludeUserArtifactsRuntime -or $script:IncludeBrowserArtifactsRuntime) {
        $collectionPhases += @{Name = "User Artifacts"; ScriptBlock = { Collect-UserArtifacts $OutDir $daysBack } }
    }

    $collectionPhases += @{Name = "File Listings"; ScriptBlock = { Collect-FileListings $OutDir $daysBack } }
    $collectionPhases += @{Name = "Enhanced Artifacts"; ScriptBlock = { Collect-EnhancedArtifacts $OutDir $daysBack } }
    $collectionPhases += @{Name = "Network Forensics"; ScriptBlock = { Collect-NetworkForensics $OutDir $daysBack } }

    if ($IncludeAD) {
        $collectionPhases += @{Name = "Active Directory"; ScriptBlock = { CollectAD $OutDir } }
    }

    if ($script:RunToolsRuntime) {
        $collectionPhases += @{Name = "Third-Party Tools"; ScriptBlock = { Run-ThirdPartyTools $OutDir $ToolsDir $availableTools } }
    }

    $collectionPhases += @{Name = "SIEM CSV Export"; ScriptBlock = { Collect-SIEMExports $OutDir $daysBack } }
    $collectionPhases += @{Name = "IOC Quick Summary"; ScriptBlock = { Write-IOCQuickSummary $OutDir $daysBack } }

    if ($script:HashEvidenceRuntime) {
        $collectionPhases += @{Name = "Evidence Hashing"; ScriptBlock = { HashManifest $OutDir (Join-Path $OutDir "meta\sha256_manifest.csv") } }
    }

    $totalPhases = $collectionPhases.Count
    $currentPhase = 1

    foreach ($phase in $collectionPhases) {
        Write-Host ""
        Write-Host ("[{0}/{1}] {2}..." -f $currentPhase, $totalPhases, $phase.Name) -ForegroundColor Cyan

        try {
            & $phase.ScriptBlock
            Write-Host "  [+] Completed" -ForegroundColor Green
        } catch {
            Write-Host ("  [-] Error: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }

        $currentPhase++
    }

    try { Stop-Transcript | Out-Null } catch {}

    $zipPath = $null
    if ($script:ZipOutputRuntime) {
        Write-Host "`n[+] Creating zip package..." -ForegroundColor Green
        $zipPath = Compress-OutputFolder -OutDir $OutDir
        if ($zipPath) { Write-Host ("  [+] Zip created: {0}" -f $zipPath) -ForegroundColor Green } else { Write-Host "  [!] Zip creation failed." -ForegroundColor Yellow }
    }

    $totalSize = 0
    $items = Get-ChildItem -Path $OutDir -Recurse -ErrorAction SilentlyContinue
    if ($items) { $totalSize = ($items | Measure-Object -Property Length -Sum).Sum }
    $totalSizeMB = [math]::Round(($totalSize / 1MB), 2)
    $totalSizeGB = [math]::Round(($totalSize / 1GB), 2)

    $memoryStatus = "Skipped"
    if ($script:IncludeMemoryDumpRuntime) {
        if ($script:MemoryDumpCreated) { $memoryStatus = "Performed" } else { $memoryStatus = "Attempted/NoDump" }
    }

    $hashStatus = "Skipped"
    if ($script:HashEvidenceRuntime) { $hashStatus = "Completed" }

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "                    iKARUS FORENSIC COLLECTION COMPLETE" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "Summary Information:" -ForegroundColor Yellow
    Write-Host ("  Output Directory: {0}" -f $OutDir) -ForegroundColor White
    if ($zipPath) { Write-Host ("  Zip Package: {0}" -f $zipPath) -ForegroundColor White }
    Write-Host ("  Total Collection Size: {0} MB ({1} GB)" -f $totalSizeMB, $totalSizeGB) -ForegroundColor White
    Write-Host ("  Timeframe Analyzed: Last {0} days" -f $daysBack) -ForegroundColor White
    Write-Host ("  Collection Mode: {0}" -f $script:EffectiveMode) -ForegroundColor White
    Write-Host ("  Tools Policy: {0}" -f $script:ToolsPolicy) -ForegroundColor White
    Write-Host ("  Memory Acquisition: {0}" -f $memoryStatus) -ForegroundColor White
    Write-Host ("  Evidence Hashing: {0}" -f $hashStatus) -ForegroundColor White
    Write-Host ("  Third-Party Tools: {0}" -f ($(if ($script:RunToolsRuntime) { "Enabled" } else { "Disabled" }))) -ForegroundColor White
    Write-Host ("  SIEM CSV Export: {0}" -f ($(if ($script:ExportSIEMRuntime) { "Enabled" } else { "Disabled" }))) -ForegroundColor White
    Write-Host ("  Zip Output: {0}" -f ($(if ($script:ZipOutputRuntime) { "Enabled" } else { "Disabled" }))) -ForegroundColor White
    Write-Host ("  Tools Available: {0}" -f ($availableTools -join ", ")) -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green

    if (-not $NonInteractive) {
        $response = Read-Host "`nOpen output directory? (Y/N)"
        if ($response -eq "Y" -or $response -eq "y") { explorer $OutDir }
    }

} catch {
    Write-Host ("Fatal Error: {0}" -f $_.Exception.Message) -ForegroundColor Red
    try { Write-Host ("Stack Trace: {0}" -f $_.ScriptStackTrace) -ForegroundColor Red } catch {}
    if ($global:TranscriptPath) { try { Stop-Transcript | Out-Null } catch {} }
    if ($NonInteractive) { exit 1 } else { return }
}
