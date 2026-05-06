# ⬡ SudoSu
### *Security Unified Defense & Offensive Scanning Utility*

> **A modular Linux security scanner written in pure Python.**  
> Forensic · Threat Detection · Firewall Advisory · Report Generation

```
  _____ _   _______ _____ _____ _   _
 /  ___| | | |  _  \  _  /  ___| | | |
 \ `--.| | | | | | | | | \ `--.| | | |
  `--. \ | | | | | | | | |`--. \ | | |
 /\__/ / |_| | |/ /\ \_/ /\__/ / |_| |
 \____/ \___/|___/  \___/\____/ \___/

 Security Unified Defense & Offensive Scanning Utility
 by SudoSu Labs  ·  v0.1.0
```

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Sample Output](#sample-output)
- [Cyber Concepts Covered](#cyber-concepts-covered)
- [Roadmap](#roadmap)

---

## Overview

SudoSu is a post-incident forensic and threat detection tool for Linux systems. It replicates what a SOC analyst does manually over several hours — scanning suspicious files, verifying hashes against VirusTotal, monitoring live processes through `/proc`, detecting C2 connections in `/proc/net/tcp`, auditing `auth.log` for brute force patterns, and generating contextual firewall rules from everything it finds.

**What SudoSu does:**

- Scans files for IOCs: dangerous extensions, SUID bits, YARA-like content patterns, fileless malware indicators
- Verifies SHA256 hashes against VirusTotal (70+ antivirus engines)
- Monitors processes via `/proc` to detect privilege escalations, active webshells, and reverse shells
- Reads `/proc/net/tcp` directly — no `netstat`, no external dependencies
- Parses `auth.log` for SSH brute force, root logins, sudo abuse, and LKM rootkit loading
- Generates contextual `iptables`/`ipset` rules based on what other modules found
- Produces a SHA256-signed `report_<timestamp>.json` + a self-contained HTML report

**What SudoSu does NOT do:**

- Never modifies the system (read-only, except writing reports)
- Never deletes any file
- Never applies firewall rules without explicit human confirmation

---

## Architecture

```
sudosu/
├── main.py                   # CLI entry point (argparse)
├── requirements.txt
│
├── config/
│   └── patterns.py           # IOC signature base (YARA-like rules)
│
├── core/
│   ├── file_analyzer.py      # Static file analysis + permission checks
│   ├── hash_checker.py       # SHA256 + VirusTotal API + FIM baseline
│   ├── process_watcher.py    # /proc monitoring — PIDs, UIDs, fileless
│   ├── network_monitor.py    # /proc/net/tcp — ports, C2, reverse shells
│   ├── log_auditor.py        # auth.log, syslog, kern.log, cron.log
│   └── firewall_advisor.py   # iptables analysis + recommended rules
│
├── utils/
│   ├── printer.py            # Rich display (colors, tables, progress bars)
│   ├── logger.py             # Structured UTC logging per module
│   └── reporter.py           # JSON (SHA256-signed) + standalone HTML export
│
├── reports/                  # Generated reports  →  report_<timestamp>.json / .html
└── logs/                     # Session logs       →  securescope_<timestamp>.log
```

### Execution Pipeline

```
main.py
  │
  ├─► file_analyzer   →  findings[]  ──────────────────────────┐
  │                                                             │
  ├─► hash_checker    →  enriches findings[] with SHA256 / VT  │
  │                                                             │
  ├─► process_watcher →  findings[]  ──────────────────────────┤
  │                                                             │
  ├─► network_monitor →  findings[]  ──────────────────────────┤
  │                                                             │
  ├─► log_auditor     →  findings[]  ──────────────────────────┤
  │                                                             ▼
  ├─► firewall_advisor ◄── correlates ALL findings  →  rules + recommendations
  │
  └─► reporter  →  report_<timestamp>.json + .html
      logger    →  logs/securescope_<timestamp>.log
```

Each module feeds the next. The `firewall_advisor` is the only module that receives findings from **all** previous modules, enabling cross-source correlation — the same principle used by SOAR platforms.

---

## Installation

```bash
# Clone
git clone https://github.com/yourhandle/sudosu.git
cd sudosu

# Install the single dependency
pip install -r requirements.txt

# Optional: VirusTotal API key (free at virustotal.com)
export VT_API_KEY="your_key_here"
```

**Requirements:**
- Python 3.10+
- `rich` >= 13.7.0 — the only external dependency
- Root access recommended to read `/proc/<PID>/exe` and `/var/log/auth.log`

---

## Usage

```bash
# Quick scan — file analysis only, fast
python main.py --target /home --mode quick

# Full scan with HTML report
python main.py --target / --mode full --output html

# Files + VirusTotal hash lookup
python main.py --target /tmp --mode files --verbose

# Network surveillance + firewall advisory
python main.py --target / --mode network --output json

# System log audit (auth.log, syslog, kern.log, cron)
python main.py --target / --mode logs --verbose

# Dry run — scan without writing anything to disk
python main.py --target /var/www --mode full --dry-run

# Cross-platform: force Windows mode
python main.py --target "C:\Users" --mode files --os windows
```

### Arguments

| Argument | Values | Description |
|----------|--------|-------------|
| `--target` / `-t` | path | Root directory to scan (default: `/`) |
| `--mode` / `-m` | `quick` `files` `network` `processes` `logs` `full` | Scan scope |
| `--output` / `-o` | `json` `html` `txt` | Report format |
| `--depth` / `-d` | integer | Max recursion depth (default: 5) |
| `--verbose` / `-v` | flag | Detailed output per file/process |
| `--dry-run` | flag | Analyze without writing reports or logs |
| `--os` | `linux` `windows` | Override OS detection |

### Scan Modes

| Mode | Active Modules | Estimated Duration |
|------|---------------|--------------------|
| `quick` | file_analyzer only | ~5–30s |
| `files` | file_analyzer + hash_checker | ~1–5min |
| `processes` | process_watcher | ~5s |
| `network` | network_monitor + firewall_advisor | ~10s |
| `logs` | log_auditor | ~15s |
| `full` | all modules in sequence | ~5–15min |

---

## Modules

### 🔍 file_analyzer — Static File Analysis

Walks the target directory recursively and applies **7 heuristics in cascade**, ordered from cheapest to most expensive — a key performance principle when analyzing thousands of files.

| # | Heuristic | Example |
|---|-----------|---------|
| 1 | Suspicious filename | `mimikatz`, `c99.php`, `beacon`, `meterpreter` |
| 2 | Double extension | `report.pdf.sh` displays as PDF, runs as shell |
| 3 | Dangerous extension in risky dir | `.sh` in `/tmp`, `.php` in `/dev/shm` |
| 4 | High-risk directory | `/tmp`, `/dev/shm`, `/var/tmp` (world-writable) |
| 5 | SUID bit or world-writable | Privilege escalation / RCE vector |
| 6 | Critical system file recently modified | `/etc/passwd` touched at 3am |
| 7 | YARA-like content pattern | `eval(base64_decode`, `bash -i >& /dev/tcp/`, AWS keys |

Content scanning reads only the **first 8 KB** of each file in raw bytes. Malware typically places its payload header at the start — scanning 8 KB instead of entire files gives a ~1000x performance gain across large directories.

Parallelized with `ThreadPoolExecutor` (8 workers, I/O-bound tasks).  
Anti-noise filter: at least 2 convergent IOCs required for a MEDIUM severity finding.

---

### #️⃣ hash_checker — Cryptographic Fingerprinting + Threat Intel

Two distinct uses of cryptographic hashing:

**Identification** — SHA256 of a suspicious file is sent to VirusTotal. If 70+ AV engines recognize it → confirmed malware, regardless of filename or location.

**File Integrity Monitoring (FIM)** — SHA256 system binaries at T0 (clean state). At T1, rehash and compare. A different hash on `/bin/ls` means a trojan binary replaced the real one — the classic rootkit technique.

- Streamed in 4 MB chunks — handles large files without memory pressure
- Hash deduplication: same malware dropped in multiple locations → one VT request
- Rate limiting: respects VirusTotal's 4 req/min free tier
- Only the hash is sent — the file content stays on the machine (privacy)

---

### 👁 process_watcher — Live Process Surveillance via /proc

Reads `/proc/<PID>/status`, `/proc/<PID>/cmdline`, and `/proc/<PID>/exe` for every active PID — no `ps`, no `psutil`.

| Detection | Technique | Severity |
|-----------|-----------|----------|
| Privilege escalation | `UID > 0` but `EUID = 0`, process not in whitelist | CRITICAL |
| Fileless malware | `/proc/<PID>/exe` ends with `(deleted)` | CRITICAL |
| Active webshell | Shell process spawned by `apache`/`nginx`/`php` | CRITICAL |
| Known offensive tool | `meterpreter`, `sliver`, `chisel`, `mimikatz` in name/cmdline | CRITICAL |
| Obfuscated cmdline | `base64 -d`, `/dev/tcp/`, `bash -i >&`, `eval(__import__` | HIGH |
| Orphan shell | `PPID=1` + interactive shell → detached reverse shell | HIGH |

Why read `/proc` directly instead of using `ps`? A rootkit can hook the syscalls `ps` depends on to hide processes. `/proc` is significantly harder to falsify without patching the kernel itself.

---

### 🌐 network_monitor — Network Surveillance Without External Tools

Parses `/proc/net/tcp` and `/proc/net/tcp6` directly. Decodes IP addresses from x86 little-endian hex format — the same way `ss` and `netstat` work internally.

```
0100007F:0035  →  hex decode + byte-swap  →  127.0.0.1:53
```

| Detection | Indicator | Severity |
|-----------|-----------|----------|
| Known C2 port | 4444 (Meterpreter), 9001 (Cobalt Strike), 1337, 31337 | CRITICAL |
| Bind shell | Unusual port in LISTEN state | HIGH |
| Reverse shell | ESTABLISHED to public IP on non-standard port | HIGH |
| Raw socket anomaly | Local port = 0 on ESTABLISHED connection | MEDIUM |

Performs reverse DNS on remote IPs to detect DGA domains (Domain Generation Algorithm) — random-looking hostnames used by malware to rotate C2 infrastructure.

---

### 📋 log_auditor — Log Forensics with Temporal Correlation

Reads `auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron.log`. Handles `.gz` rotated files. Falls back to `journalctl` on systemd-only systems.

Key principle: **individual log lines are meaningless in isolation**. A single failed SSH login is normal. 150 failures from the same IP, followed by a successful login, is a confirmed brute force attack. SudoSu aggregates with `defaultdict` counters across all lines before making decisions — the same logic as a SIEM correlation rule.

| Detection | Source | Severity |
|-----------|--------|----------|
| SSH brute force (>10 failures / IP) | auth.log | HIGH → CRITICAL if login succeeds |
| User enumeration (>5 invalid usernames / IP) | auth.log | MEDIUM |
| Direct root SSH login | auth.log | HIGH |
| Sudo to root shell (`COMMAND=/bin/bash`) | auth.log | HIGH |
| LKM rootkit loaded | kern.log | HIGH |
| Cron persistence (`curl\|sh`, `/tmp/`, `base64 -d`) | cron.log | HIGH–CRITICAL |
| Anti-forensic: empty auth.log | filesystem | HIGH |

---

### 🛡 firewall_advisor — Firewall Analysis + Contextual Rules

Detects the active firewall stack (nftables → iptables → ufw → firewalld) and audits its configuration.

**Static analysis:**

| Issue | Severity |
|-------|----------|
| No firewall detected | CRITICAL |
| `INPUT ACCEPT` policy (default-allow) | HIGH |
| `OUTPUT ACCEPT` (no egress filtering) | MEDIUM |
| Missing `ESTABLISHED,RELATED` rule | HIGH |

**Cross-module correlation** — the only module that reads findings from all previous modules:

- Attacking IPs from `log_auditor` → `ipset` block rules (O(1) lookup)
- C2 ports from `network_monitor` → `fuser -k <port>/tcp` + DROP rules
- Reverse shell detected → full egress filtering ruleset
- SSH brute force → `--recent` rate limiting + `fail2ban` recommendation

All output is a **copy-paste ready bash script** with inline comments. SudoSu suggests — the admin decides.

---

### 📊 reporter — Forensic-Grade Report Generation

**JSON** — structured report with metadata, per-severity summary, and full finding details.  
`meta.report_hash` contains the SHA256 of the report itself → *chain of custody*: proves the report was not altered after generation.

**HTML** — self-contained dark-themed report with inline CSS. No external dependencies, no CDN calls. Viewable offline, archivable for years — the same approach used by Nessus and Burp Suite.

---

## Sample Output

### JSON Finding (excerpt)

```json
{
  "severity": "CRITICAL",
  "target": "/tmp/update.sh",
  "reason": "Dangerous extension: .sh | High-risk dir /tmp | Pattern: reverse_shell_bash | SHA256: 24d004a1... [no VT key]",
  "module": "file_analyzer",
  "timestamp": "2026-05-04T09:54:45Z",
  "details": {
    "sha256": "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    "permissions": "-rwxr-xr-x",
    "owner": "root",
    "modified_ago_hours": 1.3,
    "matched_patterns": ["reverse_shell_bash"],
    "virustotal": {
      "malicious": 58,
      "total": 72,
      "name": "linux.backdoor.bashdoor",
      "vt_permalink": "https://www.virustotal.com/gui/file/24d004a1..."
    }
  }
}
```

### Terminal Output (summary table)

```
╔══════════╦══════════════════════════════════╦═════════════════════════════════════╗
║ Severity ║ Path / Target                    ║ Reason                              ║
╠══════════╬══════════════════════════════════╬═════════════════════════════════════╣
║ CRITICAL ║ /tmp/update.sh                   ║ reverse_shell_bash + high-risk dir  ║
║ CRITICAL ║ Brute force from 185.220.101.47  ║ 150 fails → SUCCESSFUL LOGIN        ║
║ HIGH     ║ /tmp/report.pdf.sh               ║ Double extension detected: .pdf.sh  ║
║ HIGH     ║ PID 1337 (bash)                  ║ Shell spawned by nginx (webshell)   ║
║ HIGH     ║ 0.0.0.0:4444 [LISTEN]            ║ Known C2 port: Meterpreter default  ║
║ HIGH     ║ /etc/passwd                      ║ Critical system file modified 2.1h  ║
╚══════════╩══════════════════════════════════╩═════════════════════════════════════╝
```

---

## Cyber Concepts Covered

| Concept | Module | What it means |
|---------|--------|----------------|
| IOC (Indicator of Compromise) | file_analyzer | Observable artifact indicating a breach |
| YARA-like rules | file_analyzer | Regex-based content signatures on raw bytes |
| SUID / Privilege Escalation | file_analyzer, process_watcher | Real UID ≠ Effective UID |
| Fileless malware | process_watcher | Executable deleted from disk, still in RAM |
| Webshell detection | process_watcher | Shell spawned by a web server process |
| SHA256 / Chain of custody | hash_checker | Cryptographic integrity proof |
| File Integrity Monitoring (FIM) | hash_checker | Baseline T0 vs current state comparison |
| VirusTotal Threat Intel | hash_checker | 70+ AV engines, hash-only query |
| /proc filesystem | process_watcher, network_monitor | Direct kernel interface, no tool abstraction |
| Little-endian IP decoding | network_monitor | Raw /proc/net/tcp format parsing |
| C2 (Command & Control) | network_monitor | Attacker-controlled beacon infrastructure |
| Bind shell vs Reverse shell | network_monitor | Two sides of remote access |
| DGA (Domain Generation Algorithm) | network_monitor | Rotating C2 domains via algorithm |
| Temporal correlation | log_auditor | Aggregating events to detect patterns |
| PAM (Pluggable Auth Modules) | log_auditor | Linux authentication abstraction |
| LKM Rootkit | log_auditor | Kernel-level malicious modules |
| Anti-forensic detection | log_auditor | Empty/truncated log files as IOC |
| Default Deny policy | firewall_advisor | Allowlist vs blocklist approach |
| Stateful inspection | firewall_advisor | ESTABLISHED,RELATED connection tracking |
| Egress filtering | firewall_advisor | Blocking outbound reverse shells |
| ipset O(1) vs iptables O(N) | firewall_advisor | Hash-based vs linear IP matching |
| SOAR correlation | firewall_advisor | Multi-source findings → automated response |
| UTC logging | logger | Timezone-agnostic forensic traceability |
| Report integrity hash | reporter | SHA256 of the report itself |

---

## Roadmap

- [ ] `--baseline` — generate and save a FIM baseline of system binaries
- [ ] `--compare` — diff two reports (before / after an incident)
- [ ] `vuln_scanner` — check installed packages against NIST NVD CVEs
- [ ] `ssh_auditor` — audit `/etc/ssh/sshd_config` for weak settings
- [ ] STIX 2.1 export — share discovered IOCs in a standard format
- [ ] Slack / Discord webhook — real-time alert integration
- [ ] Daemon mode — continuous monitoring with configurable intervals
- [ ] Docker packaging — isolated execution environment

---

## Legal Disclaimer

SudoSu is designed for auditing **your own systems** or within an explicitly authorized scope (defined pentest engagement, bug bounty program).  
Using it against systems without written authorization is illegal in most jurisdictions.  
The author assumes no liability for any misuse.

---

*SudoSu Labs — Built for defenders, inspired by attackers.*