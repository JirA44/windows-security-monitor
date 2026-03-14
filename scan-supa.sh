#!/usr/bin/env bash
# ============================================================
# Scan — SUPA API (localhost:8200)
# ============================================================
set -e

SUPA_DIR="$HOME/supa"
REPORT="$HOME/security/reports/supa-$(date +%Y-%m-%d_%H-%M)"
mkdir -p "$REPORT"

if ! curl -s http://localhost:8200/health > /dev/null 2>&1; then
  echo "[!] SUPA not running — pm2 start supa-api"
  exit 1
fi

echo "=== SUPA Security Scan ($(date)) ==="

# 1. Nuclei
echo "[1/2] Nuclei scan..."
docker run --rm \
  --network host \
  -v "$REPORT:/output" \
  projectdiscovery/nuclei:latest \
  -u "http://localhost:8200" \
  -tags "auth,injection,ssrf,exposure,misconfig" \
  -severity "medium,high,critical" \
  -o "/output/nuclei.txt" \
  -json-export "/output/nuclei.json"

# 2. Semgrep Python (SUPA est Python)
echo "[2/2] Semgrep — Python security analysis..."
docker run --rm \
  -v "$SUPA_DIR:/src" \
  -v "$REPORT:/output" \
  returntocorp/semgrep:latest \
  semgrep \
  --config "p/python" \
  --config "p/secrets" \
  --config "p/flask" \
  --output "/output/semgrep.json" \
  --json \
  /src 2>/dev/null || true

echo ""
echo "=== SUPA Scan terminé — $REPORT/ ==="
