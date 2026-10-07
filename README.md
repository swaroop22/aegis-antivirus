# 🛡️ Aegis Defender Pro — Next-Gen Cross-Platform Antivirus Suite

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows-blue.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.7+-green.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)
[![Architecture](https://img.shields.io/badge/Engine-Multi--Layer%20Heuristic%20%2B%20Entropy-cyan.svg)](#)

**Aegis Defender Pro** is a high-performance, cross-platform antivirus engine and cybersecurity command center inspired by commercial suites like **Norton 360** and **McAfee**. It delivers real-time filesystem protection, multi-layer heuristic threat detection, Shannon entropy crypter analysis, zero-execute quarantine isolation, process behavioral auditing, and an interactive Cyber Command Dashboard.

---

## ⚡ Quick Start

### 🍏 On macOS (MacBook Pro / Air / Mac Studio)
Open Terminal and run:
```bash
cd /Users/krishnajyothiswarooppothamsetti/Desktop/Gemini Projects/aegis-antivirus
./run.sh
```
*Or directly with Python:*
```bash
python3 server.py 8787
```
Then navigate to **`http://localhost:8787`** in your browser.

---

### 🪟 On Windows (Windows 10 / 11 / Server)
Double-click `run.bat` or run in Command Prompt / PowerShell:
```cmd
cd aegis-antivirus
run.bat
```
*Or directly with Python:*
```cmd
python server.py 8787
```
Then navigate to **`http://localhost:8787`** in your browser.

---

## 🚀 Key Features

### 1. 🛡️ Real-Time Filesystem Shield
- Continuously monitors high-risk entry points (e.g. `Downloads`, `Desktop`, and custom directories).
- Instantly intercepts new or modified files.
- Automatically isolates and neutralizes detected malware into the encrypted **Quarantine Vault** before the user can open it.

### 2. 🔍 Multi-Layer Detection Engine
- **Hash Signature Matching**: Fast $O(1)$ SHA-256 and MD5 lookups for prominent ransomware (WannaCry, Ryuk, Locky, DarkSide), trojans (Emotet, TrickBot), credential stealers (Mimikatz), and spyware (Pegasus).
- **YARA-Style Heuristics**: Identifies obfuscated PowerShell download cradles, interactive Unix/Windows reverse shells, AppleScript password spoofers, and web shells.
- **Shannon Entropy Analysis**: Detects packed or encrypted executables ($H > 7.5$) characteristic of ransomware and polymorphic droppers.
- **Binary Header & Packer Inspection**: Inspects Mach-O (macOS) and PE (Windows) headers for abnormal sections (`UPX`, `.themida`, `.vmp0`).
- **Masquerading Detection**: Flags deceptive double-extensions (`.pdf.exe`, `.docx.app`, `.xlsx.vbs`).

### 3. ☣️ Zero-Execute Quarantine Vault
- Applies **bitwise XOR byte-scrambling** (`byte ^ 0x5A`) to neutralize malicious payloads on disk.
- Strips executable permissions (`chmod 000` / restricted access).
- Stores threat metadata (SHA-256, origin path, detection timestamp).
- Supports **1-Click Safe Restoration** or **Zero-Overwriting Permanent Shred**.

### 4. ⚙️ Process & Memory Behavior Guard
- Real-time audit of running OS processes, CPU, memory, and command-line arguments.
- Flags suspicious reverse shells, cryptominers (`xmrig`), unauthorized admin prompt requests, or encoded payloads.
- Includes a 1-click **Terminate Process** defense action.

### 5. 🧪 EICAR Verification Test Lab
- Built-in safe verification testing:
  - **Test 1**: Drops the standard 68-byte harmless EICAR test file to verify real-time shield interception and auto-quarantine.
  - **Test 2**: Drops a mock reverse-shell dropper script to verify YARA heuristic regex matching.

### 6. 🌐 Modern Cyber Command Center
- **Obsidian Dark Mode** with electric cyan & emerald green glowing aesthetics.
- **Pulsing Radar Shield** with live system protection status.
- **Drag-and-Drop Sandbox Zone**: Drop any local file for instantaneous hashing, entropy analysis, and heuristic verdict.
- **Custom Signatures Manager**: Add your own custom SHA-256 hashes or regex pattern rules on the fly.

---

## 🧪 Automated Engine Testing

To run the automated 5-step self-test suite:
```bash
python3 test_detection.py
```

Expected output:
```
==================================================
  AEGIS DEFENDER PRO - SELF-TEST SUITE
==================================================
[1/5] Initializing Database & Scanner...
      Loaded 12 hashes and 10 heuristic rules.

[2/5] Testing EICAR Standard Signature Detection...
      Scan Result: is_threat=True, threat_name=EICAR-Test-Signature.Standard
      -> PASSED: EICAR Signature accurately detected.

[3/5] Testing Quarantine Vault Isolation & Neutralization...
      Quarantined ID: 99e5cc22, Scrambled File: .../quarantine_vault/...
      Restored original file successfully.
      -> PASSED: Quarantine isolation and recovery verified.

[4/5] Testing Heuristic Reverse Shell Detection...
      Scan Result: is_threat=True, threat_name=Heuristic.Unix.BashReverseShell
      -> PASSED: Heuristic pattern intercepted.

[5/5] Testing Process Monitor...
      Audited 585 running processes.
      -> PASSED: Process inspector functioning.

==================================================
  ALL 5 SECURITY CHECKS PASSED SUCCESSFULLY!
==================================================
```

---

## 📁 Project Structure

```
aegis-antivirus/
├── engine/
│   ├── database.py         # Signature database, EICAR string, and YARA heuristic rules
│   ├── scanner.py          # Core multi-layer file scanner (Hashes, Entropy, Headers)
│   ├── quarantine.py       # Quarantine vault with XOR byte-scrambling & safe restore
│   ├── realtime_shield.py  # Continuous filesystem watcher and instant interceptor
│   ├── process_monitor.py  # Live process auditor and threat termination
│   └── scan_manager.py     # Quick, Deep, and Custom scan coordinator
├── static/
│   ├── index.html          # Cyber Command Dashboard UI
│   ├── styles.css          # Glassmorphism cyber dark stylesheet
│   └── app.js              # Real-time telemetry, scans, audio synthesizer, and drag-and-drop
├── server.py               # Self-contained multi-threaded HTTP REST API & static server
├── test_detection.py       # Automated end-to-end self-test verification
├── run.sh                  # One-click launcher for macOS and Linux
├── run.bat                 # One-click launcher for Windows
├── ARCHITECTURE.md         # Deep-dive on internal engine & macOS/Windows kernel extensions
└── README.md               # User manual & quickstart guide
```

---

## 📖 Deep Architectural Comparison
For a detailed guide on how commercial products like **Norton**, **McAfee**, and **Microsoft Defender** operate at the operating system kernel level (Apple **`EndpointSecurity.framework`** and Windows **Minifilter Drivers / AMSI**), please read [ARCHITECTURE.md](ARCHITECTURE.md).
