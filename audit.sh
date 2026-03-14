#!/usr/bin/env bash
# ============================================================
# Audit sécurité — Simple, rapide, sans Docker
# Usage: bash ~/security/audit.sh
# ============================================================

REPORT="$HOME/security/reports/audit-$(date +%Y-%m-%d).txt"
mkdir -p "$HOME/security/reports"
ISSUES=0

log() { echo "$1" | tee -a "$REPORT"; }

log "=== Audit Sécurité ($(date)) ==="
log ""

# ── 1. Secrets hardcodés ─────────────────────────────────────
log "--- Secrets dans le code ---"
PATTERNS='(PRIVATE_KEY|sk-ant-|sk-|SECRET|PASSWORD|mnemonic|seed_phrase|0x[0-9a-fA-F]{64})'
for dir in ~/obelisk ~/mixbot ~/supa ~/chessnova; do
  [ -d "$dir" ] || continue
  FOUND=$(grep -rE "$PATTERNS" "$dir" \
    --include="*.js" --include="*.py" --include="*.ts" \
    --exclude-dir=node_modules --exclude-dir=.git \
    -l 2>/dev/null)
  if [ -n "$FOUND" ]; then
    log "  [!] Secrets potentiels dans: $dir"
    echo "$FOUND" | while read f; do log "      $f"; done
    ISSUES=$((ISSUES+1))
  fi
done
[ $ISSUES -eq 0 ] && log "  [OK] Aucun secret détecté"
log ""

# ── 2. npm audit ─────────────────────────────────────────────
log "--- npm audit (HIGH + CRITICAL) ---"
for dir in ~/obelisk ~/mixbot ~/chessnova; do
  [ -f "$dir/package.json" ] || continue
  PROJECT=$(basename "$dir")
  AUDIT=$(cd "$dir" && npm audit --audit-level=high 2>/dev/null | grep -E "high|critical" | head -3)
  if [ -n "$AUDIT" ]; then
    log "  [!] $PROJECT:"
    echo "$AUDIT" | while read l; do log "      $l"; done
    ISSUES=$((ISSUES+1))
  else
    log "  [OK] $PROJECT — aucune vuln HIGH/CRITICAL"
  fi
done
log ""

# ── 3. Ports exposés ─────────────────────────────────────────
log "--- Ports ouverts ---"
for port in 3001 8200 8201 3000 5000 8080; do
  if nc -z localhost $port 2>/dev/null; then
    log "  [:$port] ouvert — vérifier auth si exposé en prod"
  fi
done
log ""

# ── Résumé ───────────────────────────────────────────────────
log "=== Résultat: $ISSUES problème(s) trouvé(s) ==="
log "Rapport: $REPORT"
