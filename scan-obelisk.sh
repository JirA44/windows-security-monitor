#!/usr/bin/env bash
# ============================================================
# Scan — Obelisk API (localhost:3001)
# Obelisk doit tourner: pm2 start obelisk
# ============================================================
set -e

TARGET_LOCAL="http://host.docker.internal:3001"
OBELISK_DIR="$HOME/obelisk"
REPORT="$HOME/security/reports/obelisk-$(date +%Y-%m-%d_%H-%M)"
mkdir -p "$REPORT"

# Vérifier Obelisk running
if ! curl -s http://localhost:3001/api/health > /dev/null 2>&1; then
  echo "[!] Obelisk not running — pm2 start obelisk"
  exit 1
fi

echo "=== Obelisk Security Scan ($(date)) ==="
echo "Target: $TARGET_LOCAL"
echo "Report: $REPORT/"
echo ""

# ── 1. NUCLEI — Scan vulnérabilités web ──────────────────────
echo "[1/3] Nuclei — Web vulnerability scan..."
docker run --rm \
  --network host \
  -v "$REPORT:/output" \
  projectdiscovery/nuclei:latest \
  -u "http://localhost:3001" \
  -tags "auth,injection,ssrf,idor,cors,misconfig,exposure" \
  -severity "medium,high,critical" \
  -o "/output/nuclei.txt" \
  -json-export "/output/nuclei.json" \
  2>&1 | tee "$REPORT/nuclei-log.txt"

echo "[OK] Nuclei done → $REPORT/nuclei.txt"
echo ""

# ── 2. SEMGREP — Analyse statique du code ────────────────────
echo "[2/3] Semgrep — Static code analysis..."
docker run --rm \
  -v "$OBELISK_DIR:/src" \
  -v "$REPORT:/output" \
  returntocorp/semgrep:latest \
  semgrep \
  --config "p/nodejs-security-audit" \
  --config "p/javascript" \
  --config "p/secrets" \
  --output "/output/semgrep.json" \
  --json \
  /src \
  2>&1 | tee "$REPORT/semgrep-log.txt"

echo "[OK] Semgrep done → $REPORT/semgrep.json"
echo ""

# ── 3. ZAP — Pentest actif API ───────────────────────────────
echo "[3/3] OWASP ZAP — Active scan..."
docker run --rm \
  --network host \
  -v "$REPORT:/zap/wrk" \
  owasp/zap2docker-stable:latest \
  zap-api-scan.py \
  -t "http://host.docker.internal:3001" \
  -f openapi \
  -r "zap-report.html" \
  -J "zap-report.json" \
  2>&1 | tee "$REPORT/zap-log.txt" || true

echo "[OK] ZAP done → $REPORT/zap-report.html"
echo ""

# ── Résumé ───────────────────────────────────────────────────
echo "=== Scan terminé ==="
echo ""
echo "Rapports:"
ls -lh "$REPORT/"
echo ""
echo "Vulnérabilités critiques trouvées:"
grep -i '"severity":"critical"\|CRITICAL\|HIGH' "$REPORT/nuclei.txt" 2>/dev/null | head -20 || echo "  (aucune critique)"
