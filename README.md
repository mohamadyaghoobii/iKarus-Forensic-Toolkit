# iKarus Forensic Toolkit (Windows) 🕵️‍♂️🧰
**Author:** Mohamad Yaghoobi 👤  
**GitHub Repository:** https://github.com/mohamadyaghoobii/iKarus-Forensic-Toolkit 🔗  
**Version:** 3.6 🧾  

A professional, **artifact‑first and offline‑capable Windows DFIR evidence collection toolkit** designed for Incident Response (IR), SOC operations, and forensic investigations across workstations, servers, and domain‑joined systems. 🛡️🧠

> Built for real-world enterprise environments where reliability, repeatability, and restricted connectivity matter.

---

## 🎯 Purpose & Design Philosophy

During an incident, responders need **fast, consistent, and defensible evidence collection** without blindly copying entire disks or relying on internet access. ⏱️📦

iKarus Forensic Toolkit was designed to:

- Standardize Windows evidence collection across teams 🧩  
- Operate in **offline / air‑gapped environments** 📴  
- Optionally support **online auto‑download** when permitted 🌐  
- Produce **case‑ready, structured output** 🗂️  
- Support **chain‑of‑custody** via cryptographic hashing 🔐  
- Integrate smoothly with **SIEM and SOC workflows** 📊  

---

## ✨ Core Capabilities

- Two collection modes: **Triage** ⚡ and **Deep** 🔎  
- Offline‑first third‑party tool handling 📴  
- Optional execution of trusted forensic utilities 🧪  
- Evidence integrity via SHA256 hashing 🧾  
- SIEM‑ready CSV exports 📈  
- Optional ZIP packaging for transfer 🗜️  

---

## 🧠 Collection Modes

### ⚡ Triage Mode
Optimized for speed and minimal system impact:

- Smaller copy budgets and file size limits 🚧  
- Emphasis on metadata and listings over bulk copying 📋  
- Ideal for first response, remote IR, or high‑load systems  

---

### 🔎 Deep Mode
Designed for richer forensic visibility while remaining controlled:

- Expanded artifact collection with bounded limits  
- Enables by default:
  - Physical memory acquisition 🧠  
  - Evidence hashing 🔐  
  - Third‑party tool execution 🧪  
  - User and browser artifacts 👤🌐  
  - SIEM exports 📊  
  - ZIP output 🗜️  

All features remain manually overridable.

---

## 📴🌐 Offline & Online Operation Model

### 📴 Offline‑First (Air‑Gapped Friendly)

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

This model is ideal for:
- Government and financial institutions 🏛️🏦  
- Critical infrastructure environments ⚡  
- Networks with strict egress restrictions 🚫🌐  

---

### 🌐 Online / Auto‑Download (Optional)

When allowed, missing tools can be downloaded from **official vendor sources only**:

- Microsoft Sysinternals (ZIP releases)  
- Velocidex WinPMEM (official GitHub releases)  

Downloaded tools are validated using:
- Minimum size checks  
- File header validation (ZIP / PE `MZ`) 🧾  

---

## 🧰 Supported Third‑Party Tools

- **WinPMEM** 🧠 – Physical memory acquisition  
- **Autoruns (Sysinternals)** 🚦 – Persistence and startup analysis  
- **TCPView (Sysinternals)** 🌐 – Network connection snapshot  
- **Sigcheck (Sysinternals)** 🧾 – Signature and hash validation  

---

## 🪟 Supported Platforms

- Windows 10 / 11  
- Windows Server 2016 and later  
- PowerShell 5.1 (native) or PowerShell 7+  

Administrator privileges are required for memory acquisition, protected registry hives, and Security event logs.

---

## 🚀 Quick Start

### Interactive Execution
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_forensic_toolkit.ps1
```

### Non‑Interactive (Automation / IR Playbooks)
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ikarus_forensic_toolkit.ps1 -NonInteractive
```

---

## ⚙️ Key Parameters

| Parameter | Description |
|---------|-------------|
| `Mode` | Triage or Deep collection profile |
| `Timeframe` | Time window (days) for scoped collection |
| `OfflineOnly` | Disable all downloads |
| `AutoDownloadTools` | Allow controlled tool downloads |
| `IncludeMemoryDump` | Physical memory acquisition |
| `RunTools` | Execute third‑party tools |
| `HashEvidence` | Generate SHA256 manifest |
| `ExportSIEM` | Export SIEM‑friendly CSVs |
| `ZipOutput` | Compress final output |
| `IncludeUserArtifacts` | MRU, JumpLists, histories |
| `IncludeBrowserArtifacts` | Browser data collection |
| `IncludeAD` | Active Directory data |
| `NonInteractive` | Suppress prompts |

---

## 🗂️ Output Structure

Each execution produces a timestamped, case‑ready directory:

```
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

Each directory maps to a specific forensic domain, enabling fast triage, parallel analysis, and clean evidence transfer.

---

## 🧾 Evidence Integrity (SHA256)

When enabled, the toolkit generates `meta/sha256_manifest.csv` containing:

- File path  
- SHA256 hash  
- File size  
- Last write timestamp (UTC)  

Use cases:
- Chain‑of‑custody documentation 🧾  
- Post‑transfer integrity verification 📦  
- Repeatable forensic validation 🔬  

---

## 🧯 Operational Considerations

- Designed for **live response scenarios**  
- Memory acquisition and Security logs may trigger EDR alerts 🚨  
- All actions are logged via PowerShell transcript for auditability 📝  
- Use within approved IR and change‑management procedures  

---

## 🧩 Extensibility

- Easily add tools via the `RequiredTools` definition  
- Implement new collectors following the existing `Collect-*` pattern  
- Centralized configuration for copy budgets and limits  

---

## 📜 License

Recommended: **MIT** or **Apache‑2.0**

---

## 🙌 Credits

- Microsoft Sysinternals Suite  
- Velocidex WinPMEM  

---

## 📬 Support & Contributions

For issues or contributions, visit the project repository:

https://github.com/mohamadyaghoobii/iKarus-Forensic-Toolkit 🔗

Attach the following when reporting issues:
- `meta/transcript.txt`
- `meta/run_info.txt`
- Windows version and PowerShell version
