#!/usr/bin/env bash
# ============================================================
# Security Stack Setup — No API key required
# Run once: bash ~/security/setup.sh
# ============================================================
set -e

echo "=== Security Stack Setup ($(date)) ==="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
  echo "[!] Docker not found. Lance Docker Desktop d'abord."
  exit 1
fi
echo "[OK] Docker: $(docker --version | head -1)"

# Pull images
echo ""
echo "[+] Pulling security tools..."

docker pull projectdiscovery/nuclei:latest
echo "[OK] Nuclei — Web vulnerability scanner"

docker pull owasp/zap2docker-stable:latest
echo "[OK] OWASP ZAP — Web app pentester"

docker pull returntocorp/semgrep:latest
echo "[OK] Semgrep — Static code analysis"

# Nmap via WSL
if ! command -v nmap &> /dev/null; then
  echo ""
  echo "[+] Installing nmap..."
  sudo apt-get install -y nmap 2>/dev/null || echo "[!] Install manually: sudo apt install nmap"
else
  echo "[OK] Nmap: $(nmap --version | head -1)"
fi

# Create dirs
mkdir -p "$HOME/security/reports"/{nuclei,zap,semgrep,nmap}

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Commandes:"
echo "  bash ~/security/scan-obelisk.sh       # Scan Obelisk API"
echo "  bash ~/security/scan-supachess.sh      # Scan SupaChess"
echo "  bash ~/security/scan-pc.sh             # Audit PC"
echo "  bash ~/security/scan-all.sh            # Tout scanner"
