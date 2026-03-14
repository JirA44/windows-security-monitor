#!/usr/bin/env bash
# ============================================================
# scan-webapp.sh — Production web app security scan
# Tools: Nuclei + Semgrep (via Docker)
#
# USAGE: bash scan-webapp.sh
# CUSTOMIZE: edit the 3 variables below
# ============================================================
set -e

# ── CONFIGURE THESE ──────────────────────────────────────────
TARGET="https://your-app.example.com"   # Your production URL
SOURCE_DIR="$HOME/my-app"               # Your source code directory (for Semgrep)
LANG="javascript"                        # nodejs | python | javascript | go
# ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT="$SCRIPT_DIR/reports/webapp-$(date +%Y-%m-%d_%H-%M)"
mkdir -p "$REPORT"

echo "=== Web App Security Scan ($(date)) ==="
echo "Target:  $TARGET"
echo "Source:  $SOURCE_DIR"
echo "Report:  $REPORT/"
echo ""

# ── 1. NUCLEI — Web vulnerability scan ───────────────────────
echo "[1/2] Nuclei — scanning $TARGET ..."
docker run --rm \
  -v "$REPORT:/output" \
  projectdiscovery/nuclei:latest \
  -u "$TARGET" \
  -tags "auth,injection,xss,ssrf,cors,misconfig,exposure,token" \
  -severity "medium,high,critical" \
  -o "/output/nuclei.txt" \
  -json-export "/output/nuclei.json" \
  2>&1 | tee "$REPORT/nuclei-log.txt"
echo "[OK] Nuclei → $REPORT/nuclei.txt"
echo ""

# ── 2. SEMGREP — Static code analysis ────────────────────────
echo "[2/2] Semgrep — analyzing $SOURCE_DIR ($LANG) ..."
case $LANG in
  python)      SEMGREP_CONFIGS="--config p/python --config p/secrets" ;;
  javascript)  SEMGREP_CONFIGS="--config p/javascript --config p/secrets --config p/xss" ;;
  nodejs)      SEMGREP_CONFIGS="--config p/nodejs-security-audit --config p/javascript --config p/secrets" ;;
  *)           SEMGREP_CONFIGS="--config p/javascript --config p/secrets" ;;
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

# ── Summary ───────────────────────────────────────────────────
echo "=== Scan complete ==="
ls -lh "$REPORT/"
echo ""
echo "Critical / High findings:"
grep -i 'CRITICAL\|HIGH\|"severity":"critical"\|"severity":"high"' "$REPORT/nuclei.txt" 2>/dev/null | head -20 || echo "  (none found)"
