# WinDefend Toolkit — Windows Security Monitor

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?logo=windows)
![License](https://img.shields.io/badge/license-MIT-green)

> Lightweight, zero-dependency Windows security monitoring toolkit.
> No cloud. No API key. Runs locally in minutes.

## Français — présentation

WinDefend Toolkit est un ensemble d’outils locaux de surveillance et de vérification pour Windows. Le README décrit le suivi des installations, des processus, des éléments de démarrage et des connexions réseau, ainsi que des scripts d’analyse pour certaines applications.

### À quoi ça sert, et pourquoi ?

Il aide à repérer des changements inhabituels par rapport à un état de référence et à lancer des vérifications ponctuelles. Les alertes sont des éléments à examiner, pas une preuve automatique d’infection.

### Exemples

- Comparer les logiciels installés et les processus courants à l’état de référence.
- Examiner une nouvelle entrée de démarrage ou une connexion réseau inattendue.
- Utiliser les scripts d’analyse API/web après avoir vérifié leurs dépendances.

L’installation indiquée crée des baselines et des tâches planifiées. Lire et vérifier les scripts avant de les exécuter, puis examiner toute alerte manuellement.

### Campagne quotidienne dans cette branche

L’installateur proposé lance d’abord les tests de la politique, puis une campagne quotidienne réelle mais contenue :

- **Vérifications d’intégration bornées** (`local_integration_checks.ps1`) : dépôt git courant (diff + statut, job limité à 30 s), services pm2 interrogés via node, points de terminaison HTTP locaux, présence des journaux, tâches planifiées attendues. Aucune action modifiante, lecture seule.
- **Réponse graduée réelle, uniquement en bac à sable** (`adaptive_response.ps1` + `sandbox/sandbox_service.js`, ports locaux 18250/18251) : surveillance → limitation → pause/restauration, exécutées contre un service sandbox local. Garde-fous : jamais d’arrêt par nom de processus (PID + identité ligne de commande uniquement), aucune suppression, journal d’abord, aucune action sur un hôte hors sandbox.
- **Rapport schema 3** (`daily_security_campaign.ps1`) : environnement, commit, graine quotidienne unique et rejouable, durée, limites, état de restauration, verdict global PASS / FAIL / INCOMPLETE. Inclut 9 cas fixes de décision, 5 contrôles de reprise, 5 000 séquences synthétiques (~52 s), charge HTTP 160 requêtes / 4 connexions et fuzz HTTP seedé (100 itérations) contre le service sandbox.
- **Tests** (`tests/adaptive_response.tests.ps1`, Pester, 8/8) : faux positifs sans action, doublons idempotents, perte de journal bloquant l’action avec verdict INCOMPLETE, gates après redémarrage, restauration propre, zéro processus orphelin.
- **Installateur vérifié** (`install.ps1`) : télécharge les nouveaux composants, programme la campagne à 03:17 (limite 15 min) et refuse de déclarer l’installation active si les trois tâches planifiées (`InstallTracker`, `Watchdog`, `DailySecurityCampaign`) n’existent pas réellement.

La campagne enregistre un rapport JSON dans `reports/` et programme une tâche quotidienne à 03:17, relancée au prochain démarrage si l’ordinateur était éteint. Les actions de réponse réelles ne s’exécutent que contre le service sandbox local ; la réponse graduée sur un vrai poste reste à activer après validation des détecteurs et de la restauration sur l’environnement cible.

## Install (one line)

```powershell
irm https://raw.githubusercontent.com/JirA44/windows-security-monitor/main/install.ps1 | iex
```

> Installs to `~\WinDefend\`, initializes baselines, creates scheduled tasks automatically.

---

## Preview

```
  WinDefend Toolkit — Installer
  ================================

[1/4] Install directory: C:\Users\you\WinDefend
      Downloaded: install_tracker.ps1
      Downloaded: watchdog_pc.ps1
      Downloaded: check_threats.ps1
[2/4] Scripts downloaded
[3/4] Baselines initialized
      [OK] Baseline: 312 software entries recorded
      [OK] Baseline saved: 183 processes, 3 startup entries
[4/4] Scheduled tasks created (every 6h + at login)

  Done! WinDefend is active.
```

```
=== SECURITY CHECK 2026-03-14 08:00 ===
[INSTALLS]
  [NEW] SuspiciousApp v1.0 (Unknown Publisher)        ← alert!
  [OK] No removals detected
[SUSPICIOUS PROCESSES]
  [ALERT] PID=4821 xmrig.exe                          ← cryptominer detected!
[NEW PROCESSES]
  [OK] No new unknown processes
=== END ===
```

---

## What it does

| Script | What it monitors |
|--------|-----------------|
| `install_tracker.ps1` | New software installs, known malicious processes, new unknown processes |
| `watchdog_pc.ps1` | New processes vs baseline, new startup entries, new Run registry keys |
| `check_threats.ps1` | Full audit: processes, scheduled tasks, startup folder, temp scripts, network connections |
| `response_policy.ps1` / `daily_security_campaign.ps1` | Severity policy and daily campaign: integration checks, seeded synthetic decisions (5,000), sandboxed HTTP load/fuzz, schema 3 report (PASS/FAIL/INCOMPLETE) |
| `local_integration_checks.ps1` | Read-only bounded checks: git repo, pm2 services, local HTTP endpoints, logs, scheduled tasks |
| `adaptive_response.ps1` + `sandbox/sandbox_service.js` | Graduated real response (monitor → limit → pause → restore) executed only against the local sandbox service; PID+cmdline identity, journal-first, no deletion |
| `scan-pc.sh` | Open ports, listening services, npm vulnerabilities |
| `scan-api.sh` | Deep scan of a local REST API: Nuclei + Semgrep + OWASP ZAP |
| `scan-webapp.sh` | Deep scan of a production web app: Nuclei + Semgrep |

---

## Requirements

**PowerShell scripts** (Windows only):
- Windows 10/11
- PowerShell 5.1+ (built-in)

**Shell scripts** (`.sh`):
- [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) or [Git Bash](https://gitforwindows.org/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) *(or see [Without Docker](#without-docker) below)*

---

## Quick Start

### 1. Clone
```bash
git clone https://github.com/YOUR_USERNAME/windows-security-monitor
cd windows-security-monitor
```

### 2. Initialize baselines (run once)
```powershell
# Software baseline (tracks installed programs)
powershell -ExecutionPolicy Bypass -File install_tracker.ps1 -Init

# Process baseline (tracks running processes)
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Init
```

### 3. Run checks
```powershell
# New installs + suspicious processes
powershell -ExecutionPolicy Bypass -File install_tracker.ps1 -Check

# Full threat audit
powershell -ExecutionPolicy Bypass -File check_threats.ps1

# New processes vs baseline
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Check
```

### 4. Automate (Windows Task Scheduler)
```powershell
# Every 6 hours — install tracker
schtasks /Create /TN "WinDefend\InstallTracker" /TR "powershell -ExecutionPolicy Bypass -File C:\path\to\install_tracker.ps1 -Check" /SC HOURLY /MO 6 /F

# At login — watchdog
schtasks /Create /TN "WinDefend\Watchdog" /TR "powershell -ExecutionPolicy Bypass -File C:\path\to\watchdog_pc.ps1 -Check" /SC ONLOGON /F
```

---

## PowerShell Scripts

### install_tracker.ps1

Detects:
- **New software** installed since baseline (checks HKLM + HKCU registry)
- **Removed software**
- **Known malicious processes**: `wscript`, `mshta`, `xmrig`, `cryptominer`, etc.
- **New unknown processes** not in baseline or whitelist

```
=== RAPPORT 2026-03-14 04:09 ===
[INSTALLS]
  [OK] No new installs
[SUSPICIOUS PROCESSES]
  [OK] No suspicious processes found
[NEW PROCESSES]
  [NEW] LockApp path=C:\Windows\SystemApps\LockApp_...
=== END ===
```

Reports saved to `reports/alerts-YYYYMMDD.txt`.

---

### check_threats.ps1

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

### watchdog_pc.ps1

Monitors changes vs a saved baseline:
- New processes appearing
- New items in the Startup folder
- New entries in `HKCU\Software\...\Run`

```powershell
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Init   # first run
powershell -ExecutionPolicy Bypass -File watchdog_pc.ps1 -Check  # subsequent runs
```

---

## Web App Scanning (WSL / Git Bash)

### scan-pc.sh — Port + npm audit
```bash
bash scan-pc.sh
```
Checks open ports, listening services, and npm dependency vulnerabilities across your Node.js projects.

### scan-api.sh — Local REST API deep scan

Edit the variables at the top of the file:
```bash
TARGET="http://localhost:3001"    # your API
SOURCE_DIR="$HOME/my-app"        # your source code
LANG="nodejs"                     # nodejs | python | javascript | go
```
Then:
```bash
bash scan-api.sh
```
Runs: **Nuclei** (8000+ CVE templates) + **Semgrep** (static analysis) + **OWASP ZAP** (active pentest).

### scan-webapp.sh — Production web app scan

Edit the variables at the top:
```bash
TARGET="https://your-app.example.com"
SOURCE_DIR="$HOME/my-app"
LANG="javascript"
```
Then:
```bash
bash scan-webapp.sh
```

---

## Without Docker

You can run each tool natively (no Docker required):

### Nuclei (binary — Windows/Linux/Mac)
```bash
# Download binary from GitHub releases:
# https://github.com/projectdiscovery/nuclei/releases
nuclei -u http://localhost:3001 -tags auth,injection,ssrf -severity medium,high,critical
```

### Semgrep (Python)
```bash
pip install semgrep
semgrep --config p/nodejs-security-audit --config p/secrets ./my-app
```

### OWASP ZAP (Desktop app)
Download the GUI from [zaproxy.org](https://www.zaproxy.org/download/) — no Docker needed.
Use the built-in active scanner against your target URL.

### Nmap
```bash
# Windows (via winget)
winget install -e --id Insecure.Nmap

# WSL / Linux
sudo apt install nmap
nmap -sV --open -p 1-9999 localhost
```

---

## Reports

All reports are saved locally in `reports/` (never committed):
```
reports/
├── alerts-20260314.txt          ← Daily alert log
├── installs.log                 ← Install history over time
├── threats-20260314-0900.txt    ← Full audit output
└── api-2026-03-14_09-00/
    ├── nuclei.txt               ← Vulnerability findings
    ├── semgrep.json             ← Static analysis results
    └── zap-report.html          ← ZAP report (open in browser)
```

---

## Files

```
windows-security-monitor/
├── install_tracker.ps1           # Software + process monitor
├── watchdog_pc.ps1               # Process + startup baseline watcher
├── check_threats.ps1             # Full security audit
├── daily_security_campaign.ps1   # Daily campaign + schema 3 JSON report
├── response_policy.ps1           # Severity policy
├── local_integration_checks.ps1  # Bounded read-only integration checks
├── adaptive_response.ps1         # Graduated sandboxed response
├── sandbox/sandbox_service.js    # Local sandbox service (18250/18251)
├── tests/adaptive_response.tests.ps1  # Pester tests (8)
├── scan-pc.sh                    # Port scan + npm audit
├── scan-api.sh                   # Local API deep scan (Nuclei + Semgrep + ZAP)
├── scan-webapp.sh                # Production web app scan (Nuclei + Semgrep)
├── scan-all.sh                   # Run all scans in sequence
└── setup.sh                      # One-time setup
```

---

## License

MIT
