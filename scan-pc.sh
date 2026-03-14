#!/usr/bin/env bash
# ============================================================
# PC Security Audit — Ports + Services + Firewall
# ============================================================
set -e

REPORT_DIR="$HOME/security/reports/pc"
TIMESTAMP=$(date +%Y-%m-%d_%H-%M)
REPORT="$REPORT_DIR/audit-$TIMESTAMP.txt"
mkdir -p "$REPORT_DIR"

echo "=== PC Security Audit ($(date)) ===" | tee "$REPORT"
echo "" | tee -a "$REPORT"

# 1. PM2 services actifs
echo "--- PM2 Services ---" | tee -a "$REPORT"
pm2 list 2>/dev/null | tee -a "$REPORT" || echo "PM2 not available" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 2. Ports en écoute
echo "--- Ports en écoute ---" | tee -a "$REPORT"
if command -v netstat.exe &> /dev/null; then
  netstat.exe -an | grep -E "LISTENING" | sort | tee -a "$REPORT"
else
  ss -tlnp | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# 3. Nmap localhost
echo "--- Nmap localhost ---" | tee -a "$REPORT"
if command -v nmap &> /dev/null; then
  nmap -sV --open -p 1-9999 localhost 2>/dev/null | tee -a "$REPORT"
else
  # Via Docker si nmap pas installé
  docker run --rm --network host instrumentisto/nmap \
    -sV --open -p 1-9999 localhost 2>/dev/null | tee -a "$REPORT" || \
  echo "  nmap non disponible — install: sudo apt install nmap" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# 4. Ports critiques
echo "--- Vérification ports critiques ---" | tee -a "$REPORT"
OPEN_PORTS=""
for port in 3001 8200 8201 3000 4000 5000 8080 8888 9229; do
  if nc -z localhost $port 2>/dev/null; then
    echo "  [OPEN] :$port" | tee -a "$REPORT"
    OPEN_PORTS="$OPEN_PORTS $port"
  fi
done
[ -z "$OPEN_PORTS" ] && echo "  (aucun port critique ouvert)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 5. npm audit sur les projets
echo "--- npm audit ---" | tee -a "$REPORT"
# Add your Node.js project directories below
for dir in ~/my-app ~/another-app; do
  if [ -f "$dir/package.json" ]; then
    echo "  → $dir:" | tee -a "$REPORT"
    cd "$dir" && npm audit --audit-level=high 2>/dev/null | tail -5 | tee -a "$REPORT" || true
    cd ~
  fi
done
echo "" | tee -a "$REPORT"

# 6. Recommandations
cat << 'EOF' | tee -a "$REPORT"
--- Recommandations ---
1. API ports (3001, 8200...) → Auth required on ALL sensitive routes
2. Rate limiting             → Add on sensitive endpoints
3. Windows Firewall          → These ports must NOT be exposed to the Internet
4. npm audit                 → Update dependencies with HIGH/CRITICAL vulnerabilities

Bloquer un port depuis Internet (PowerShell admin):
  netsh advfirewall firewall add rule name="Block 3001" dir=in action=block protocol=TCP localport=3001
EOF

echo "" | tee -a "$REPORT"
echo "Rapport: $REPORT"
