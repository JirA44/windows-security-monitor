#!/usr/bin/env bash
# ============================================================
# Scan ALL — Lance tous les scans séquentiellement
# Usage: bash ~/security/scan-all.sh
# ============================================================
set -e

LOG="$HOME/security/reports/scan-all-$(date +%Y-%m-%d_%H-%M).log"
mkdir -p "$HOME/security/reports"
ERRORS=0

echo "=== Full Security Scan ($(date)) ===" | tee "$LOG"
echo "" | tee -a "$LOG"

run() {
  local name="$1" script="$2"
  echo "▶ $name..." | tee -a "$LOG"
  if bash "$script" >> "$LOG" 2>&1; then
    echo "  [✓] $name OK" | tee -a "$LOG"
  else
    echo "  [✗] $name FAILED" | tee -a "$LOG"
    ERRORS=$((ERRORS+1))
  fi
  echo "" | tee -a "$LOG"
}

# PC toujours
run "PC Audit" ~/security/scan-pc.sh

# Obelisk si running
curl -s http://localhost:3001/api/health > /dev/null 2>&1 \
  && run "Obelisk" ~/security/scan-obelisk.sh \
  || echo "[SKIP] Obelisk not running" | tee -a "$LOG"

# SUPA si running
curl -s http://localhost:8200/health > /dev/null 2>&1 \
  && run "SUPA" ~/security/scan-supa.sh \
  || echo "[SKIP] SUPA not running" | tee -a "$LOG"

# SupaChess (toujours dispo en prod)
run "SupaChess" ~/security/scan-supachess.sh

echo "" | tee -a "$LOG"
echo "=== Terminé — Erreurs: $ERRORS ===" | tee -a "$LOG"
echo "Log: $LOG"
echo "Rapports: ~/security/reports/"
