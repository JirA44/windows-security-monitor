#!/usr/bin/env bash
# ============================================================
# Scan — SupaChess (supachess.pages.dev)
# ============================================================
set -e

TARGET="https://supachess.pages.dev"
CHESS_DIR="$HOME/chessnova"
REPORT="$HOME/security/reports/supachess-$(date +%Y-%m-%d_%H-%M)"
mkdir -p "$REPORT"

echo "=== SupaChess Security Scan ($(date)) ==="
echo "Target: $TARGET"
echo ""

# 1. Nuclei
echo "[1/2] Nuclei scan..."
docker run --rm \
  -v "$REPORT:/output" \
  projectdiscovery/nuclei:latest \
  -u "$TARGET" \
  -tags "auth,injection,xss,ssrf,cors,misconfig,exposure,token" \
  -severity "medium,high,critical" \
  -o "/output/nuclei.txt" \
  -json-export "/output/nuclei.json"

echo ""

# 2. Semgrep (JS frontend)
echo "[2/2] Semgrep — Frontend JS analysis..."
docker run --rm \
  -v "$CHESS_DIR:/src" \
  -v "$REPORT:/output" \
  returntocorp/semgrep:latest \
  semgrep \
  --config "p/javascript" \
  --config "p/secrets" \
  --config "p/xss" \
  --output "/output/semgrep.json" \
  --json \
  /src 2>/dev/null || true

echo ""
echo "=== SupaChess Scan terminé ==="
echo "Rapports: $REPORT/"
