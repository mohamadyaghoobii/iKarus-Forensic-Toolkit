# iKarus Forensic Toolkit (Windows) 🕵️‍♂️🧰
**Author:** Mohamad Yaghoobi 👤  
**Repository:** https://github.com/mohamadyaghoobii/iKarus-Forensic-Toolkit 🔗  
**Current Version:** 3.6 🧾  
**Last Updated (this README):** 2025-12-24 📅  

A professional **artifact-first, offline-capable Windows DFIR evidence collection toolkit** built for **Incident Response (IR)**, **SOC operations**, and **forensic investigations** across workstations, servers, and domain-joined systems. 🛡️🧠

> Designed for real-world enterprise environments where **repeatability**, **restricted connectivity**, and **defensible evidence handling** matter.

---

## 📚 What “Forensics” Means in IR (Quick Primer)

Digital forensics in incident response is the practice of **collecting**, **preserving**, and **analyzing** digital evidence to answer questions like:

- **What happened?** (intrusion vector, timeline, attacker goals) 🧩  
- **Where did the attacker go?** (hosts, users, lateral movement) 🧭  
- **What changed?** (persistence, new services/tasks, registry changes, new software) 🔁  
- **What data was accessed/exfiltrated?** (where possible) 📤  
- **How do we contain and recover safely?** (with evidence intact) 🧯  

Key principles:
- **Integrity:** evidence should remain unchanged (hashes, chain of custody) 🔐  
- **Repeatability:** collection should be consistent and auditable 🧾  
- **Minimized impact:** collect what’s needed without destabilizing systems ⚖️  
- **Context matters:** artifacts are most valuable when correlated (process + network + persistence + timeline) 🧠  

iKarus follows these principles by prioritizing **high-value artifacts** first, with bounded, controlled acquisition.

---

## 🎯 Purpose & Design Philosophy

During an incident, responders need **fast, consistent, and defensible evidence collection** without blindly copying entire disks or relying on internet access. ⏱️📦

iKarus was designed to:

- Standardize Windows evidence collection across teams 🧩  
- Operate in **offline / air-gapped environments** 📴  
- Optionally support **controlled online auto-download** when permitted 🌐  
- Produce **case-ready, structured output** 🗂️  
- Support **chain-of-custody** via cryptographic hashing 🔐  
- Integrate smoothly with **SIEM and SOC workflows** 📊  
- Keep execution **auditable** (transcripts, logs, explicit run metadata) 📝  

The toolkit follows an **artifact-first philosophy**: prioritize the artifacts that most reliably answer “what’s going on?” early in an investigation—while keeping acquisition bounded and operationally safe.

---

## ✨ Core Capabilities

- Two collection modes: **Triage** ⚡ and **Deep** 🔎  
- Offline-first handling for third-party tools 📴  
- Optional execution of trusted forensic utilities 🧪  
- Evidence integrity via SHA256 hashing 🧾  
- SIEM-ready CSV exports 📈  
- Optional ZIP packaging for transfer 🗜️  
- Fully scripted, repeatable, and auditable execution 📝  
- Clear output layout mapped to forensic domains 🗂️  

---

## 🧠 Collection Modes

### ⚡ Triage Mode (Fast, Low Impact)
Optimized for speed and minimal system impact:

- Smaller copy budgets and file size limits 🚧  
- Emphasis on metadata and listings over bulk copying 📋  
- Ideal for first response, remote IR, or high-load systems  
- Quickly answers: *What’s running? What changed recently? Where should we look next?* 🧭  

### 🔎 Deep Mode (Richer Visibility, Still Controlled)
Designed for deeper forensic visibility while remaining bounded:

- Expanded artifact collection with controlled limits  
- Commonly enables:
  - Physical memory acquisition 🧠  
  - Evidence hashing 🔐  
  - Third-party tool execution 🧪  
  - User + browser artifacts 👤🌐  
  - SIEM exports 📊  
  - ZIP output 🗜️  

All features remain manually overridable to fit operational constraints.

---

## 📴🌐 Offline & Online Operation Model

### 📴 Offline-First (Air-Gapped Friendly)
The toolkit is fully functional **without internet access**.

To operate offline:
- Place required tools in the expected directories (default: `windows_Forensic_Tools`) 🗂️  
- Optionally stage ZIP/EXE packages under `OfflinePackages` 📦  
- The script automatically searches:
  - Tools directory  
  - OfflinePackages  
  - Script directory  
  - Current working directory  
  - Downloads / Desktop / Documents  

Ideal for:
- Government and financial institutions 🏛️🏦  
- Critical infrastructure environments ⚡  
- Military, OT, and restricted enterprise networks 🚫🌐  

### 🌐 Controlled Auto-Download (Optional)
When permitted, missing tools can be downloaded from **official vendor sources only** (per toolkit policy):

- Microsoft Sysinternals (ZIP releases)  
- Velocidex WinPMEM (official GitHub releases)  

Downloads are validated with checks such as:
- Minimum size checks  
- File header validation (ZIP / PE `MZ`) 🧾  

---

## 🧰 Supported Third-Party Tools

- **WinPMEM** 🧠 – Physical memory acquisition  
- **Autoruns (Sysinternals)** 🚦 – Persistence and startup analysis  
- **TCPView (Sysinternals)** 🌐 – Network connection snapshot  
- **Sigcheck (Sysinternals)** 🧾 – Signature and hash validation  

---

## 🪟 Supported Platforms & Requirements

- Windows 10 / 11  
- Windows Server 2016+  
- PowerShell 5.1 (native) or PowerShell 7+  

Recommended:
- Run as **Administrator** for full coverage (Security logs, protected registry areas, memory, etc.) 🧑‍💻  
- Use an approved response account and follow internal IR procedure 📋  

---

## 🚀 Quick Start

### Interactive Execution
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_forensic_toolkit.ps1
```

### Non-Interactive (Automation / IR Playbooks)
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_forensic_toolkit.ps1 -NonInteractive
```

---

## ⚙️ Key Parameters (Collector)

| Parameter | Description |
|---|---|
| `Mode` | `Triage` or `Deep` collection profile |
| `Timeframe` | Time window (days) for scoped collection |
| `OfflineOnly` | Disable all downloads |
| `AutoDownloadTools` | Allow controlled tool downloads |
| `IncludeMemoryDump` | Physical memory acquisition |
| `RunTools` | Execute third-party tools |
| `HashEvidence` | Generate SHA256 manifest |
| `ExportSIEM` | Export SIEM-friendly CSVs |
| `ZipOutput` | Compress final output |
| `IncludeUserArtifacts` | MRU, JumpLists, user activity artifacts |
| `IncludeBrowserArtifacts` | Browser artifacts collection |
| `IncludeAD` | Active Directory data (domain-joined) |
| `NonInteractive` | Suppress prompts |

---

## 🗂️ Output Structure

Each run produces a timestamped, case-ready directory:

```text
windows_Forensic_<HOSTNAME>_<TIMESTAMP>/
├── meta/
├── memory/
├── system/
├── users/
├── process/
├── network/
├── persistence/
├── software/
├── security/
├── eventlogs/
├── registry/
├── os_artifacts/
├── users_artifacts/
├── file_listings/
├── enhanced_artifacts/
├── network_forensics/
├── active_directory/
├── third_party_analysis/
└── siem/
```

### 📁 Folder Intent (What each area is for)

- `meta/` 🧾: run info, transcripts, tool inventory, hashes (chain of custody)  
- `memory/` 🧠: physical memory image (if enabled)  
- `system/` 🪟: OS and host configuration snapshots (version, patches, services baseline info)  
- `users/` 👤: user-level enumeration (profiles, groups, local admins, etc.)  
- `process/` ⚙️: running processes, services, scheduled tasks, drivers  
- `network/` 🌐: interfaces, routes, ARP, netstat snapshots, DNS info  
- `persistence/` 🚦: autoruns, run keys, WMI persistence indicators, startup folders  
- `software/` 📦: installed software inventory, potentially unwanted apps, updates  
- `security/` 🛡️: Defender config, firewall, audit policy, security posture snapshots  
- `eventlogs/` 🧾: EVTX and/or exported log snippets as collected  
- `registry/` 🧩: key registry hives and exports (bounded)  
- `os_artifacts/` 🗃️: OS-level artifacts such as prefetch, amcache, shimcache (as available)  
- `users_artifacts/` 🧷: MRU, JumpLists, recent files, RDP artifacts, etc.  
- `file_listings/` 📋: targeted directory listings and “recent/suspicious” enumerations  
- `enhanced_artifacts/` 🔎: enriched exports (e.g., PowerShell operational text, Defender events text)  
- `network_forensics/` 🛰️: extended network artifacts (as collected)  
- `active_directory/` 🏢: domain artifacts (if enabled)  
- `third_party_analysis/` 🧪: Sysinternals outputs (Autoruns, Sigcheck, TCPView)  
- `siem/` 📊: CSV exports intended for SIEM ingestion  

---

# 🔎 iKarus Output Analyzer (Post-Collection Analysis)

The **iKarus Output Analyzer** (`ikarus_analyzer.ps1`) is a post-collection analysis engine designed to systematically review iKarus outputs and highlight attacker-relevant activity. 🧠🔎

## 🎯 Analyzer Objectives

- Identify persistence mechanisms 🧷  
- Detect suspicious execution patterns ⚙️  
- Highlight security control tampering 🛡️  
- Analyze network and DNS artifacts 🌐  
- Detect suspicious changes compared to a baseline 🔁  
- Produce analyst-ready reports 📄  

## 🧠 Analyzer Coverage (High Level)

### Persistence 🚦
- Services (unusual paths, user-writable directories)  
- Scheduled tasks (odd paths and suspicious commands)  
- WMI event subscription artifacts  
- Run keys + Winlogon key outputs  
- Autoruns CSV (high-signal triage view)  

### Execution ⚙️
- PowerShell abuse patterns (encoded commands, hidden window, IEX, download cradles)  
- LOLBins and suspicious command-line indicators (mshta, rundll32, regsvr32, wscript/cscript, etc.)  

### Network 🌐
- Established external connections (process ↔ remote IP)  
- Suspicious domain keywords in DNS cache and exports  

### Security Controls 🛡️
- Windows Defender exclusions  
- UAC disabled  
- Firewall profile disabled  
- Weak audit policy (sampling)  

### Anti-Forensics 🧨
- Security log clear events (1102) from SIEM exports and/or EVTX parsing  

### Change Detection 🔁
- Hash-based diff against a baseline case (`meta/sha256_manifest.csv`)  
- Focus on **high-risk directories** (AppData, Temp, ProgramData, Public)  

---

## 🧪 Analyzer Usage

### Analyze a case folder
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_analyzer.ps1 `
  -InputPath "D:\IR\windows_Forensic_HOST_20250101_120000"
```

### Analyze a ZIP (auto-extract)
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_analyzer.ps1 `
  -InputPath "C:\IR\case.zip"
```

### Baseline comparison
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_analyzer.ps1 `
  -InputPath "D:\IR\case_suspect" `
  -BaselinePath "D:\IR\case_baseline"
```

### Analyzer outputs 📦
- `analysis_report.md`  
- `findings.csv`  
- `findings.json`  

---

## 🧭 How to Interpret Findings (Practical Guidance)

Think of findings as **leads**, not verdicts. 🧠

A good triage loop:
1. Start with **High/Critical** items (persistence + execution + log clears) 🚨  
2. Pivot from a finding to:
   - file path ➜ hash/signature ➜ creation time  
   - process name ➜ parent/child chain (if available)  
   - external IP ➜ reputation ➜ related DNS queries  
3. Confirm legitimacy using environment baselines (golden images, known tools) ✅  
4. If suspicious: contain host, collect memory/disk image where needed 🧯  

---

## 🧩 Extensibility (Add Your Org’s Detections)

Typical additions organizations make:
- Detect newly installed remote access tools (RMM, VPN, tunneling) 🛰️  
- Flag risky scheduled task patterns (encoded PowerShell, downloads) ⚙️  
- Check “program installed” lists against allowlists/denylists 📦  
- Add artifact parsers (Prefetch summary, Amcache parsing, Shimcache parsing) 🧠  
- Add per-org suspicious domain and IP lists 🧾  

---

## 🧯 Operational Considerations

- Live response data collection can trigger EDR alerts 🚨  
- Memory acquisition and Security log access may be monitored by endpoint controls 🛡️  
- Always operate within approved IR playbooks, change control, and legal policy 📋  
- Keep collected data secured: treat it as sensitive evidence 🔐  

---

## 🧰 Troubleshooting (Common Issues)

- **Access denied**: run PowerShell as Administrator 🧑‍💻  
- **Missing tools**: stage tools in `windows_Forensic_Tools` or enable controlled downloads 🧰  
- **SIEM CSV warnings**: some CSV exports may contain inconsistent headers across Windows versions; normalize in SIEM pipeline 🧹  
- **ZIP extraction path**: analyzer extracts ZIPs to a temporary directory by design; move output if needed 📦  

---

## ❓ FAQ

**Q: Is this a full disk forensic imager?**  
A: No. It’s artifact-first DFIR collection (fast, bounded, operationally safer). For full imaging, use dedicated imaging workflows. 🧱

**Q: Can I run it on servers?**  
A: Yes (Server 2016+), but tune parameters and follow change control. 🖥️

**Q: Is internet required?**  
A: No. Offline-first. Online auto-download is optional and policy-driven. 📴🌐

---

## 🤝 Contributing

PRs, issues, and improvements are welcome:
- Add new collectors  
- Improve parsers and detections  
- Add organization-friendly exports  

When reporting issues, attach:
- `meta/transcript.txt`  
- `meta/run_info.txt`  
- Windows version + PowerShell version  

---

## 📜 License

Recommended options:
- MIT ✅  
- Apache-2.0 ✅  

Choose the license that matches your distribution and policy.

---

## 🙌 Credits

- Microsoft Sysinternals Suite  
- Velocidex WinPMEM  

---

## 🔗 Links

- Repository: https://github.com/mohamadyaghoobii/iKarus-Forensic-Toolkit  
