#!/usr/bin/env bash
# ============================================================
# scan-api.sh — Local REST API security scan
# Tools: Nuclei + Semgrep + OWASP ZAP (via Docker)
#
# USAGE: bash scan-api.sh
# CUSTOMIZE: edit the 3 variables below
# ============================================================
set -e

# ── CONFIGURE THESE ──────────────────────────────────────────
TARGET="http://localhost:3001"          # Your API URL
SOURCE_DIR="$HOME/my-app"              # Your source code directory (for Semgrep)
LANG="nodejs"                          # nodejs | python | javascript | go
# ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT="$SCRIPT_DIR/reports/api-$(date +%Y-%m-%d_%H-%M)"
mkdir -p "$REPORT"

# Check target is reachable
if ! curl -s "$TARGET" > /dev/null 2>&1; then
  echo "[!] Target not reachable: $TARGET"
  echo "    Make sure your API is running."
  exit 1
fi

echo "=== API Security Scan ($(date)) ==="
echo "Target:  $TARGET"
echo "Source:  $SOURCE_DIR"
echo "Report:  $REPORT/"
echo ""

# ── 1. NUCLEI — Web vulnerability scan ───────────────────────
echo "[1/3] Nuclei — scanning $TARGET ..."
docker run --rm \
  --network host \
  -v "$REPORT:/output" \
  projectdiscovery/nuclei:latest \
  -u "$TARGET" \
  -tags "auth,injection,ssrf,idor,cors,misconfig,exposure" \
  -severity "medium,high,critical" \
  -o "/output/nuclei.txt" \
  -json-export "/output/nuclei.json" \
  2>&1 | tee "$REPORT/nuclei-log.txt"
echo "[OK] Nuclei → $REPORT/nuclei.txt"
echo ""

# ── 2. SEMGREP — Static code analysis ────────────────────────
echo "[2/3] Semgrep — analyzing $SOURCE_DIR ($LANG) ..."
case $LANG in
  python)  SEMGREP_CONFIGS="--config p/python --config p/flask --config p/secrets" ;;
  nodejs)  SEMGREP_CONFIGS="--config p/nodejs-security-audit --config p/javascript --config p/secrets" ;;
  *)       SEMGREP_CONFIGS="--config p/javascript --config p/secrets" ;;
esac
docker run --rm \
  -v "$SOURCE_DIR:/src" \
  -v "$REPORT:/output" \
  returntocorp/semgrep:latest \
  semgrep $SEMGREP_CONFIGS \
  --output "/output/semgrep.json" \
  --json /src \
  2>&1 | tee "$REPORT/semgrep-log.txt"
echo "[OK] Semgrep → $REPORT/semgrep.json"
echo ""

# ── 3. OWASP ZAP — Active API pentest ────────────────────────
echo "[3/3] OWASP ZAP — active scan ..."
docker run --rm \
  --network host \
  -v "$REPORT:/zap/wrk" \
  owasp/zap2docker-stable:latest \
  zap-api-scan.py \
  -t "$TARGET" \
  -f openapi \
  -r "zap-report.html" \
  -J "zap-report.json" \
  2>&1 | tee "$REPORT/zap-log.txt" || true
echo "[OK] ZAP → $REPORT/zap-report.html"
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "=== Scan complete ==="
echo ""
echo "Reports:"
ls -lh "$REPORT/"
echo ""
echo "Critical / High findings:"
grep -i 'CRITICAL\|HIGH\|"severity":"critical"\|"severity":"high"' "$REPORT/nuclei.txt" 2>/dev/null | head -20 || echo "  (none found)"
