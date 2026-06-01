# 🔍 PackDetect

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![PE Analysis](https://img.shields.io/badge/PE-Analysis-red)
![Malware Analysis](https://img.shields.io/badge/Malware-Research-orange)
![Static Analysis](https://img.shields.io/badge/Static-Analysis-green)
![Status](https://img.shields.io/badge/Status-Educational-success)

## PE Packer & Unpacker Detection Platform

PackDetect is an educational cybersecurity and malware analysis project developed by **Karanam Shrivasta**.

The project provides PE file analysis, packer detection, entropy analysis, section inspection, import analysis, string extraction, binary fingerprinting, static malware triage, and security reporting through both a modern web dashboard and command-line interface. :contentReference[oaicite:0]{index=0}

---

# 🚀 Features

## Packer Detection

- UPX Detection
- ASPack Detection
- MPRESS Detection
- Themida Detection
- VMProtect Detection
- Generic Packed Binary Detection
- Suspicious Section Detection

## PE Analysis

- DOS Header Analysis
- PE Header Analysis
- Optional Header Analysis
- Architecture Detection
- Entry Point Analysis
- Image Base Analysis
- Security Flag Inspection

## Section Analysis

- Section Entropy Analysis
- Hidden Data Detection
- RWX Section Detection
- Executable Section Detection
- Writable Section Detection
- Alignment Validation
- Empty Section Detection

## Import Analysis

- DLL Analysis
- API Analysis
- Delayed Import Detection
- Import Tree Visualization

## Security Analysis

- Anti-Debug API Detection
- Process Injection API Detection
- Network API Detection
- Registry API Detection
- Cryptographic API Detection
- Suspicious Behavior Indicators

## Resource Analysis

- Resource Enumeration
- Manifest Detection
- Icon Detection
- Resource Metadata Inspection

## Binary Intelligence

- MD5 Hash
- SHA1 Hash
- SHA256 Hash
- SHA512 Hash
- SSDEEP Support
- TLSH Support

## String Extraction

- ASCII Strings
- Unicode Strings
- URLs
- Domains
- IP Addresses
- Email Addresses
- Registry Paths
- PowerShell Commands
- CMD Commands
- File Paths

## Advanced Analysis

- Rich Header Detection
- Overlay Detection
- Debug Information Analysis
- PDB Path Extraction
- TLS Callback Detection
- Code Signing Detection
- .NET Detection

## Reporting

- JSON Export
- CSV Export
- HTML Export
- PDF Export

## Dashboard Features

- Dark Theme
- Light Theme
- Responsive Design
- Interactive Tables
- Entropy Graphs
- PE Tree Visualization
- Hash Export
- Report Downloads

---

# ⚙️ How It Works

PackDetect performs static analysis of Portable Executable (PE) files.

Workflow:

1. User uploads a PE file.
2. File hashes are calculated.
3. PE headers are parsed.
4. Sections are analyzed.
5. Entropy calculations are performed.
6. Imports and APIs are inspected.
7. Strings are extracted.
8. Security indicators are identified.
9. Risk score is generated.
10. Findings are reported.

No code execution is performed.

No malware execution is performed.

Analysis is performed statically. :contentReference[oaicite:1]{index=1}

---

# 🏗️ Architecture

```text
User
 │
 ▼
PE File Upload
 │
 ▼
PE Parser
 │
 ├── Header Analysis
 ├── Section Analysis
 ├── Import Analysis
 ├── Resource Analysis
 ├── String Extraction
 ├── Entropy Analysis
 └── Security Analysis
 │
 ▼
Risk Scoring Engine
 │
 ▼
Reporting Engine
 │
 ▼
Dashboard & Exports
```

---

# 📦 Installation

## Clone Repository

```bash
git clone https://github.com/mrshrivasta/PackDetect.git

cd PackDetect
```

## Install Dependencies

```bash
pip install flask pefile
```

Optional:

```bash
pip install ssdeep
pip install py-tlsh
```

---

# 🚀 Run Web Dashboard

```bash
python packdetect.py web
```

Open:

```text
http://127.0.0.1:5000
```

---

# 💻 CLI Usage

## Analyze File

```bash
python packdetect.py scan sample.exe
```

## JSON Output

```bash
python packdetect.py scan sample.exe --json
```

## HTML Report

```bash
python packdetect.py scan sample.exe --html report.html
```

## CSV Report

```bash
python packdetect.py scan sample.exe --csv report.csv
```

## PDF Report

```bash
python packdetect.py scan sample.exe --pdf report.pdf
```

---

# 🔐 Security Features

- Entropy-Based Detection
- Suspicious API Detection
- Packed Binary Detection
- Overlay Detection
- Anti-Debug Detection
- Process Injection Indicators
- Registry Activity Indicators
- Network Activity Indicators
- RWX Memory Indicators
- Hidden Data Detection

---

# 🎯 Use Cases

- Malware Analysis
- Reverse Engineering
- Digital Forensics
- Security Research
- Cybersecurity Education
- PE File Inspection
- Threat Hunting
- Binary Analysis
- Home Lab Research
- Portfolio Demonstrations

---

# 📊 Risk Scoring

The scanner generates a risk score based on:

- Suspicious Sections
- High Entropy Sections
- RWX Sections
- Hidden Data Indicators
- Process Injection APIs
- Anti-Debug APIs
- Overlay Data
- Packer Signatures

Higher scores indicate more suspicious characteristics.

---

# ❓ FAQ

### Does this prove malware?

No.

The presence of suspicious indicators does not prove that a file is malicious.

### Does this execute malware?

No.

PackDetect performs static analysis only.

### Is this a replacement for antivirus software?

No.

### Can it detect every packer?

No.

### Are findings guaranteed to be accurate?

No.

Users must independently verify all findings.

---

# 🛣️ Roadmap

- [ ] YARA Integration
- [ ] VirusTotal Integration
- [ ] CAPA Integration
- [ ] Signature Database
- [ ] Multi-File Scanning
- [ ] IOC Correlation
- [ ] Threat Intelligence Feeds
- [ ] Rule Engine
- [ ] Docker Support
- [ ] Offline Signature Packs

---

# 🔍 SEO Keywords

```text
PackDetect
Karanam Shrivasta
PE Analysis
Packer Detection
Unpacker Detection
Malware Analysis
Static Analysis
Binary Analysis
Reverse Engineering
Digital Forensics
PE File Scanner
Executable Analysis
Entropy Analysis
Threat Research
Cybersecurity Project
Portable Executable
PE Security Tool
Windows Malware Analysis
Malware Research
Threat Hunting
```

---

# ⚠️ EXTREME DISCLAIMER

## READ THIS ENTIRE SECTION CAREFULLY

PackDetect is an educational, experimental, research, demonstration, and portfolio project created by **Karanam Shrivasta**.

This software is NOT:

- An Antivirus Product
- An EDR Platform
- An XDR Platform
- A Malware Sandbox
- A Managed Security Service
- A Commercial Security Product
- A Threat Intelligence Platform
- A Forensic Certification Tool

---

# ⚠️ STATIC ANALYSIS LIMITATIONS

This project performs static analysis only.

The software:

- Does NOT execute files.
- Does NOT emulate files.
- Does NOT guarantee malware detection.
- Does NOT guarantee packer identification.
- Does NOT guarantee attribution.
- Does NOT determine author intent.

A clean result does NOT mean a file is safe.

A suspicious result does NOT mean a file is malicious.

---

# ⚠️ NO WARRANTY

THIS SOFTWARE IS PROVIDED "AS IS".

NO WARRANTIES OF ANY KIND ARE PROVIDED.

The author makes NO guarantee regarding:

- Accuracy
- Reliability
- Availability
- Detection Rates
- Security Findings
- Risk Scores
- Classification Results
- Report Contents

---

# ⚠️ USER RESPONSIBILITY

By downloading, installing, modifying, distributing, or using this software, you acknowledge and agree that:

- You are solely responsible for your use of this software.
- You are solely responsible for validating findings.
- You are solely responsible for legal compliance.
- You are solely responsible for handling analyzed files.
- You are solely responsible for any actions performed using this software.

Use this software entirely at your own risk.

---

# ⚠️ LIABILITY DISCLAIMER

To the maximum extent permitted by law:

**Karanam Shrivasta shall not be responsible or liable for:**

- Data Loss
- Security Incidents
- Malware Infections
- Incorrect Findings
- False Positives
- False Negatives
- Business Losses
- Financial Losses
- Legal Consequences
- Direct Damages
- Indirect Damages
- Consequential Damages
- Special Damages

Once this software has been downloaded, installed, modified, distributed, or used, all responsibility remains solely with the user.

---

# 👨‍💻 Author

## Karanam Shrivasta

Cybersecurity Enthusiast • Malware Analysis Learner • Developer

GitHub:
https://github.com/mrshrivasta

---

# 📜 License

Educational and Research Use Only.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

USE AT YOUR OWN RISK.

© Karanam Shrivasta. All Rights Reserved.
