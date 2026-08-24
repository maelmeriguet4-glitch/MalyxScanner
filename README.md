<p align="center">
  <img src="assets/logo.png" width="160" alt="MalyxScanner Logo">
</p>

<h1 align="center">MalyxScanner</h1>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://microsoft.com"><img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6.svg?logo=windows" alt="Platform: Windows"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11+-3776AB.svg?logo=python" alt="Python: 3.11+"></a>
  <a href="https://github.com/maelmeriguet4-glitch/MalyxScanner/releases/tag/v2.1.3"><img src="https://img.shields.io/badge/release-v2.1.3-blueviolet.svg" alt="Release: v2.1.3"></a>
  <a href="#privacy--offline-first-architecture"><img src="https://img.shields.io/badge/privacy-100%25%20Local-success.svg" alt="Privacy: 100% Local"></a>
</p>

<p align="center">
  <b>High-performance offline static malware analysis engine and incident response triage desktop utility.</b>
</p>

---

## Overview

**MalyxScanner** is an open-source static malware analysis and file triage utility for Windows. It evaluates binary structure, cryptographic signatures, chunked Shannon entropy, Indicators of Compromise (IOCs), and YARA rule matches to classify potential threats without executing the target payload.

Traditional signature-based antivirus solutions often miss newly packed droppers and custom stealth payloads. MalyxScanner inspects structural indicators in depth to detect packers, anomalous write+execute memory sections, unverified binaries, and evasive behaviors.

---

## Technical Capabilities

### 1. Static PE & Binary Inspection
* **Authenticode Verification**: Validates WinTrust digital certificates and flags unsigned or self-signed executables.
* **Section Analysis & Anomaly Detection**: Highlights dangerous memory section permission combinations (such as `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`).
* **MITRE ATT&CK API Mapping**: Maps imported Windows system APIs against known malicious techniques (Process Injection, Persistence, Evasion, Token Manipulation, C2 Communications).
* **Forensic Metadata**: Extracts PDB debug paths, timestamp anomalies, compilation metadata, Subsystem, and `StringFileInfo`.

### 2. Shannon Entropy & Packer Detection
* **Global & Block-Level Entropy**: Calculates byte randomness across 16 KB chunks to pinpoint hidden, encrypted, or packed payloads within resource sections or overlay data.
* **Packing Signatures**: Recognizes UPX, VMProtect, Themida, and custom packer compression structures.

### 3. Forensic IOC & Pattern Extraction
* **Network Indicators**: Extracts public IPv4 addresses, hostnames, and suspicious protocol URLs (`http://`, `https://`, `ftp://`).
* **System Footprints**: Detects persistence registry keys (`CurrentVersion\Run`, services) and administrative commands (`powershell -enc`, `vssadmin delete shadows`, `certutil -urlcache`).
* **Universal File Support**: Analyzes 12 distinct file families (Executables, Office documents, Archives, Scripts, PDF, System binaries, Source code, Game assets, Media).

### 4. YARA Signature Matching
* Embedded standard rules for high-profile malware families, ransomware notes, and common offensive tooling.
* Extensible rule repository via custom `.yar` definitions in the `rules/` directory.

### 5. Automated Triage & Incident Remediation
* **Composite Risk Scoring (0–100)**: Evaluates structural anomalies, entropy distribution, and heuristics to assign clear verdicts (*Clean*, *Suspicious*, *Malicious*).
* **Safe Quarantine**: Atomically isolates suspicious files into an access-restricted directory (`%APPDATA%\MalyxScanner\quarantine`) with neutralized permissions and `.malyx_quarantine` metadata preservation.
* **Secure Deletion**: Offers irreversible disk shredding for confirmed threats.
* **Optional SOC AI Analyst**: Integrates with OpenRouter, Gemini, OpenAI, or Claude to generate concise, human-readable executive incident briefings.
* **Optional VirusTotal Verification**: Queries 70+ AV engines using only the file's SHA-256 hash (the file payload itself is never transmitted).

---

## Privacy & Offline-First Architecture

| Asset | Processing Model | Network Destination |
| :--- | :--- | :--- |
| **File Contents & Data** | 100% Local (in-memory streaming) | **None (Never uploaded)** |
| **SHA-256 Hash** | Optional (only when VirusTotal is explicitly queried) | VirusTotal API |
| **AI Analyst Payload** | Optional (only when AI generation is triggered) | Configured LLM Endpoint |
| **Telemetry & Tracking** | None | **Zero tracking / 100% Private** |

---

## Installation & Usage

### Prerequisites
* Windows 10 / 11 (64-bit)
* Python 3.11+

### Quick Start
```powershell
# Clone the repository
git clone https://github.com/maelmeriguet4-glitch/MalyxScanner.git
cd MalyxScanner

# Set up virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run MalyxScanner
python src/main.py
```

### Running Test Suite
The automated test suite verifies static parsing, entropy math, threat classification, and quarantine mechanics:
```powershell
python tests/test_analyzer.py
```

### Building Standalone Windows Executable
To compile an isolated standalone `.exe` using PyInstaller:
```powershell
pyinstaller --noconfirm MalyxScanner.spec
```
The compiled output is located in `dist/MalyxScanner/MalyxScanner.exe`.

---

## Project Structure

```
MalyxScanner/
├── assets/                  # Application icons and branding assets
├── rules/                   # Embedded YARA detection rules
├── src/
│   ├── core/
│   │   ├── ai_analyst.py         # AI SOC brief generator
│   │   ├── analyzer.py           # Core static analysis orchestrator
│   │   ├── entropy.py            # Shannon entropy calculation engine
│   │   ├── filetype.py           # Magic bytes and MIME detection
│   │   ├── hashes.py             # MD5, SHA-1, SHA-256, SHA-512, Imphash
│   │   ├── pe_analysis.py        # Windows PE header & MITRE parser
│   │   ├── remediation.py        # Safe quarantine and secure deletion
│   │   ├── risk_score.py         # Heuristic composite risk scoring
│   │   ├── strings_extractor.py  # IOC and string extraction
│   │   ├── threat_classifier.py  # Threat family taxonomy
│   │   ├── virustotal.py         # Cloud hash reputation client
│   │   └── yara_scanner.py       # YARA rule scanning engine
│   ├── gui/
│   │   ├── app.py                # Main application window & top toolbar
│   │   ├── result_view.py        # Multi-tab analysis dashboard
│   │   ├── settings_dialog.py    # Configuration and profile settings
│   │   └── theme_manager.py      # Cyber dark / High contrast themes
│   ├── i18n/                     # Bilingual support (FR / EN)
│   └── main.py                   # Application entry point
├── tests/
│   └── test_analyzer.py          # Unit & regression test suite (27 tests)
└── README.md
```

---

## Contact & Feedback

* **Maintainer**: Mael Meriguet
* **Email**: [maelmeriguet4@proton.me](mailto:maelmeriguet4@proton.me?subject=[MalyxScanner]%20Inquiry%20/%20Feedback)
* **Issues**: [GitHub Issues](https://github.com/maelmeriguet4-glitch/MalyxScanner/issues)

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
