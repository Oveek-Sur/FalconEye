# 🦅 FalconEye — Oveek Sur

## ⭐ Overview

FalconEye is a unified, CLI-driven intelligence and vulnerability platform built to streamline reconnaissance, network discovery, and initial vulnerability validation. By aggregating outputs from multiple industry-standard tools into a single, actionable report, FalconEye reduces the need to memorize many individual commands and significantly accelerates the reconnaissance-to-exploitation workflow for security researchers, penetration testers, and bug bounty hunters.


---

## 📜 The FalconEye Development Story: Human-Augmented AI Testing
This project is a testament to the power of human oversight in complex AI-driven development. While the initial code base utilized the speed of multiple AI models (Gemini, ChatGPT, and Penetration Test GPT), the path to a stable, usable tool was defined entirely by rigorous human testing and engineering oversight.

## 🕵️‍♂️ Purpose

FalconEye’s primary goals are:

* **Consolidate:** Bring powerful reconnaissance and scanning utilities into a single, consistent command-line interface.
* **Actionable Intelligence:** Produce clear, prioritized, and actionable intelligence that accelerates triage and remediation.
* **Reduce Friction:** Minimize the operational overhead of switching between disparate tools and output formats.
*  **Verified Stability:** FalconEye is proven stable even against challenging targets.
*   **Custom Control:** The user retains full control over speed and timeout profiles.
*  **Zero Command Fatigue:** Achieve full-cycle reconnaissance without memorizing complex command-line syntax.

---

## ⚙️ Professional Description

FalconEye is an orchestration framework for reconnaissance and early-stage vulnerability assessment. It automates the collection, normalization, and enrichment of target data — transforming raw tool outputs into structured, high-value reports. The platform emphasizes repeatability, clarity, and prioritization: discovered assets and findings are grouped, annotated with contextual metadata (e.g., CVSS scores), and linked to relevant exploit references when available.

**Key professional benefits:**

* **Efficiency:** Run multi-tool pipelines from one interface to save time and reduce cognitive load.
* **Actionability:** Reports are structured to be immediately useful for follow-up testing or remediation.
* **Traceability:** Tool outputs are preserved and organized for reproducibility and auditing.

---

## 🛠️ Major Modules & Features

### 1. 🌐 Deep Reconnaissance (CLI Report)

* Full attack-surface mapping for domains or IPs.
* Integrates: `amass`, `subfinder`, `sublist3r` (subdomains), `gau` (historical URLs), `subjs` (JS assets), `httpx`/`wappalyzer` (tech fingerprinting), DNS & WHOIS collection, and fast port discovery (`naabu`).
* Outputs consolidated, human-readable CLI reports suitable for triage and export.

### 2. 📡 Professional Nmap Scanning

* Curated Nmap interface with selectable scan profiles: Quick, Full (0–65535), Stealth (SYN), UDP, and Custom.
* Timing control (T0–T5) and preset profiles for safer or aggressive scanning.
* Parsed and normalized output for downstream vulnerability checks.

### 3. 🚨 Vulnerability Scanning & Prioritization

* Uses Nmap Scripting Engine (vuln category) to identify common service-level vulnerabilities and misconfigurations.
* Integrates with SearchSploit/ExploitDB to map services to potential public exploits.
* Presents findings in a CVSS-prioritized table to focus remediation on highest-risk items.

---

## 🚀 Setup & Installation Guide

**Target platform:** Debian/Ubuntu-based systems (adjust for other distros).

### 1) System update

```bash
sudo apt update && sudo apt upgrade -y
```

### 2) Install core dependencies

```bash
sudo apt install -y python3 python3-pip python3-venv git curl wget tar
```

### 3) Clone repo & create virtual environment (recommended)

```bash
# Clone repository
git clone https://github.com/Oveek-Sur/FalconEye.git


# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
cd FalconEye
```

> When active, your shell prompt shows `(venv)`.

### 4) Install or place external reconnaissance binaries on `PATH`

FalconEye relies on several external tools. Install those you need and ensure they are accessible via `PATH` (e.g., `/usr/local/bin`). Example installations:

**Subjs**

```bash
wget https://github.com/lc/subjs/releases/latest/download/subjs_$(curl -s https://api.github.com/repos/lc/subjs/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')_linux_amd64.tar.gz
tar xzf subjs_*_linux_amd64.tar.gz
chmod +x subjs
sudo mv subjs /usr/local/bin/
subjs -h
```

**Gau (GetAllUrls)**

```bash
wget https://github.com/lc/gau/releases/latest/download/gau_$(curl -s https://api.github.com/repos/lc/gau/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')_linux_amd64.tar.gz
tar xzf gau_*_linux_amd64.tar.gz
chmod +x gau
sudo mv gau /usr/local/bin/
gau --version
```

**Naabu**

```bash
sudo apt update
sudo apt install -y naabu
# or follow ProjectDiscovery installation instructions
```

**Nmap & SearchSploit/ExploitDB**

```bash
sudo apt install -y nmap exploitdb
```

> Tip: You may keep binaries inside the project and update `PATH` locally if you prefer not to install system-wide.

### 5) Run FalconEye

```bash
sudo python3 falconEye.py
```

The launcher will verify presence of required tools and notify if anything is missing.

---

## 📝 Notes & Troubleshooting

* **Permissions:** Certain scans require elevated privileges. Use `sudo` only when necessary and avoid running untrusted scripts as root.
* **Missing tools:** If a module fails because a binary is missing, install that tool and retry.
* **Performance:** On low-resource systems, use conservative Nmap timings (T0–T2) and reduce scan ranges.
* **Legal:** Always have explicit authorization before scanning or testing targets; unauthorized scanning may be illegal.

---

## 📦 Dependencies (summary)

* Python 3
* Git
* Recon tools: `amass`, `subfinder`, `sublist3r`, `theharvester` (optional)
* Web analysis: `httpx`, `wappalyzer`
* Scanning & vuln: `naabu`, `subjs`, `gau`, `nmap`, `searchsploit`/`exploitdb`
## The tool will automatically tell you if something or any tool is misssing then please manually install them.
---

## 📜 License & Contact

* **License:** GNU General Public License v3.0 (GPL-3.0)
* **Project:** FalconEye
* **Author:** Oveek Sur
* **Repository:** [https://github.com/Oveek-Sur/FalconEye](https://github.com/Oveek-Sur/FalconEye)





