# WinDefend Toolkit — Windows Security Monitor

> Lightweight, zero-dependency Windows security monitoring toolkit. No cloud. No API key. Just PowerShell and bash.

---

## What it does

| Script | What it monitors |
|--------|-----------------|
| `install_tracker.ps1` | New software installs, known malicious processes, new unknown processes |
| `watchdog_pc.ps1` | New processes vs baseline, new startup entries, new Run registry keys |
| `check_threats.ps1` | Full audit: processes, scheduled tasks, startup, temp scripts, network connections |
| `scan-pc.sh` | Open ports, listening services, npm vulnerabilities (Docker) |
| `scan-obelisk.sh` | Web app scan: Nuclei + Semgrep + OWASP ZAP (adapt to your app) |

---

## Quick Start

### 1. Clone
```bash
git clone https://github.com/YOUR_USERNAME/windows-security-monitor
cd windows-security-monitor
```

### 2. Initialize baselines (run once)
```powershell
# Software baseline
powershell -ExecutionPolicy Bypass -File install_tracker.ps1 -Init

# Process baseline
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Init
```

### 3. Run a check
```powershell
# Check for new installs + suspicious processes
powershell -ExecutionPolicy Bypass -File install_tracker.ps1 -Check

# Full threat audit
powershell -ExecutionPolicy Bypass -File check_threats.ps1

# Monitor new processes vs baseline
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Check
```

### 4. Automate (Task Scheduler)
```powershell
# Every 6 hours — install tracker
schtasks /Create /TN "WinDefend\InstallTracker" /TR "powershell -File C:\path\to\install_tracker.ps1 -Check" /SC HOURLY /MO 6 /F

# At login — watchdog
schtasks /Create /TN "WinDefend\Watchdog" /TR "powershell -File C:\path\to\watchdog_pc.ps1 -Check" /SC ONLOGON /F
```

---

## install_tracker.ps1

Detects:
- **New software** installed since baseline (checks HKLM + HKCU registry)
- **Removed software**
- **Known malicious processes**: `wscript`, `mshta`, `xmrig`, `cryptominer`, etc.
- **New unknown processes** not in baseline or whitelist

```
=== RAPPORT 2026-03-14 04:09 ===
[INSTALLS]
  [OK] Aucune nouvelle installation
[PROCESSUS SUSPECTS]
  [OK] Aucun processus suspect
[NOUVEAUX PROCESSUS]
  [NEW] LockApp path=C:\Windows\SystemApps\LockApp_...
=== FIN ===
```

Reports saved to `reports/alerts-YYYYMMDD.txt`.

---

## check_threats.ps1

Full security audit covering:
1. Suspicious processes (wscript, mshta, xmrig...)
2. Scheduled tasks (non-Microsoft, active)
3. HKCU Run registry entries
4. HKLM Run registry entries
5. User Startup folder contents
6. Scripts (vbs/bat/js/hta/ps1) modified in the last 7 days in Temp
7. Active network connections (external IPs)

```powershell
powershell -ExecutionPolicy Bypass -File check_threats.ps1
```

---

## watchdog_pc.ps1

Monitors changes vs a saved baseline:
- New processes appearing
- New items in the Startup folder
- New entries in `HKCU\Software\...\Run`

```powershell
# First run — save baseline
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Init

# Subsequent runs — alert on changes
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Check
```

---

## Web App Scanning (Linux/WSL — requires Docker)

```bash
# Port scan + npm audit
bash scan-pc.sh

# Full web scan: Nuclei + Semgrep + OWASP ZAP
bash scan-obelisk.sh   # adapt TARGET and paths for your own app
```

Tools used (all free, via Docker):

| Tool | Role |
|------|------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Web vulnerability scan (8000+ CVE templates) |
| [OWASP ZAP](https://www.zaproxy.org/) | Active pentest — auth bypass, injection |
| [Semgrep](https://semgrep.dev/) | Static code analysis (JS/Python) |
| Nmap | Open ports + exposed services |
| npm audit | Vulnerable JS dependencies |

---

## Reports

All reports are saved locally in `reports/`:
```
reports/
├── alerts-20260314.txt     ← Daily alert log
├── installs.log            ← All installs detected over time
└── threats-20260314-0900.txt  ← Full audit output
```

> `reports/` and `*.json` baseline files are in `.gitignore` — they are never committed.

---

## Files

```
windows-security-monitor/
├── install_tracker.ps1     # Software + process monitor
├── watchdog_pc.ps1         # Process + startup baseline watcher
├── check_threats.ps1       # Full security audit
├── scan-pc.sh              # Port scan + npm audit (Docker)
├── scan-obelisk.sh         # Web app deep scan (adapt for your app)
├── scan-supa.sh            # Example: scan another local service
├── scan-supachess.sh       # Example: scan a production web app
├── scan-all.sh             # Run all scans in sequence
├── setup.sh                # One-time setup
└── reports/                # (gitignored) local reports
```

---

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Docker Desktop (for web scanning scripts)
- WSL or Git Bash (for `.sh` scripts)

---

## License

MIT
