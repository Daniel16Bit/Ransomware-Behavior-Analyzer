#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         RANSOMWARE ANALYZER - Build & Run Script            ║
# ╚══════════════════════════════════════════════════════════════╝

set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
CYN='\033[0;36m'
RST='\033[0m'

banner() {
    echo -e "${GRN}"
    echo "  ██████╗  █████╗ ███╗  ██╗███████╗ ██████╗ ███╗  ███╗"
    echo "  ██╔══██╗██╔══██╗████╗ ██║██╔════╝██╔═══██╗████╗████║"
    echo "  ██████╔╝███████║██╔██╗██║███████╗██║   ██║██╔████╔██║"
    echo "  ██╔══██╗██╔══██║██║╚████║╚════██║██║   ██║██║╚██╔╝██║"
    echo "  ██║  ██║██║  ██║██║ ╚███║███████║╚██████╔╝██║ ╚═╝ ██║"
    echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝"
    echo -e "${CYN}       [ BEHAVIORAL RANSOMWARE ANALYZER v2.0 ]${RST}"
    echo ""
}

step() { echo -e "${CYN}[*]${RST} $1"; }
ok()   { echo -e "${GRN}[✓]${RST} $1"; }
warn() { echo -e "${YLW}[!]${RST} $1"; }
fail() { echo -e "${RED}[✗]${RST} $1"; exit 1; }

# ── Check OS ──────────────────────────────────────────────────────
if [[ "$(uname)" != "Linux" ]]; then
    fail "This tool requires Linux (inotify, /proc filesystem)"
fi

banner

# ── Mode selection ────────────────────────────────────────────────
MODE="${1:-run}"

case "$MODE" in
    build)
        step "Compiling C module (entropy_calc.so)..."
        gcc -O2 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm \
            && ok "entropy_calc.so compiled" \
            || fail "GCC compilation failed"

        step "Checking Python dependencies..."
        python3 -c "import watchdog" 2>/dev/null \
            || fail "watchdog not found. Run: pip install watchdog"
        python3 -c "import psutil"   2>/dev/null \
            || warn "psutil not found (proc panel may be limited)"

        ok "Build complete!"
        ;;

    run)
        # Build first if .so missing
        if [[ ! -f "entropy_calc.so" ]]; then
            step "Building C module first..."
            gcc -O2 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm \
                && ok "Built entropy_calc.so" \
                || fail "Build failed"
        fi

        step "Starting analyzer..."
        mkdir -p /tmp/test_watch logs hashes
        python3 main.py
        ;;

    test)
        # ── Ransomware simulation (run in separate terminal) ───────
        WATCH="/tmp/test_watch"
        mkdir -p "$WATCH"

        echo -e "${YLW}╔══════════════════════════════════════════╗"
        echo       "║   RANSOMWARE BEHAVIOR SIMULATOR          ║"
        echo -e    "╚══════════════════════════════════════════╝${RST}"
        echo ""
        warn "This simulates ransomware behavior for TESTING ONLY"
        warn "Watch the analyzer UI while this runs"
        echo ""

        step "Phase 1: Write burst (${YLW}WRITE_BURST${RST})"
        for i in $(seq 1 25); do
            echo "plaintext data iteration $i" > "$WATCH/document_${i}.txt"
            sleep 0.05
        done
        ok "Write burst done"
        sleep 1

        step "Phase 2: High entropy files (${RED}HIGH_ENTROPY${RST})"
        for i in 1 2 3; do
            dd if=/dev/urandom bs=1K count=64 of="$WATCH/encrypted_${i}.dat" 2>/dev/null
            sleep 0.3
        done
        ok "High entropy files created"
        sleep 1

        step "Phase 3: Rename to ransomware extensions (${RED}CRITICAL${RST})"
        for i in $(seq 1 6); do
            src="$WATCH/document_${i}.txt"
            dst="$WATCH/document_${i}.locked"
            [[ -f "$src" ]] && mv "$src" "$dst"
            sleep 0.2
        done
        ok "Renames done"
        sleep 1

        step "Phase 4: Ransom note (${RED}RANSOM_NOTE${RST})"
        cat > "$WATCH/READ_ME_DECRYPT.txt" << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED
Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
EOF
        ok "Ransom note created"
        sleep 1

        step "Phase 5: Delete burst (${YLW}DELETE_BURST${RST})"
        for i in $(seq 10 25); do
            rm -f "$WATCH/document_${i}.txt"
            sleep 0.05
        done
        ok "Delete burst done"

        echo ""
        ok "Simulation complete! Check analyzer UI for alerts."
        echo -e "${GRN}Logs: $DIR/logs/events.jsonl${RST}"
        ;;

    clean)
        step "Cleaning build artifacts..."
        rm -f entropy_calc.so
        rm -f logs/*.jsonl
        rm -f hashes/*.sha256
        ok "Cleaned"
        ;;

    logs)
        step "Showing structured logs..."
        if [[ -f "logs/events.jsonl" ]]; then
            python3 -c "
import json, sys
with open('logs/events.jsonl') as f:
    lines = f.readlines()
print(f'Total events: {len(lines)}')
print()
for line in lines[-30:]:
    e = json.loads(line)
    sev_color = {
        'INFO':     '\033[36m',
        'WARN':     '\033[33m',
        'ALERT':    '\033[31m',
        'CRITICAL': '\033[35m',
    }.get(e['severity'], '')
    rst = '\033[0m'
    ts  = e['ts'][11:19]
    print(f\"{sev_color}[{e['severity']:8s}]{rst} [{ts}] {e['event']:<25s} {e['file']}\")
"
        else
            warn "No log file found. Run the analyzer first."
        fi
        ;;

    help|*)
        echo "Usage: $0 [command]"
        echo ""
        echo "  build   Compile C module + check Python deps"
        echo "  run     Build (if needed) and launch analyzer UI"
        echo "  test    Simulate ransomware behavior for testing"
        echo "  logs    Pretty-print recent events from log file"
        echo "  clean   Remove build artifacts and logs"
        echo ""
        echo "Quick start:"
        echo "  Terminal 1:  $0 run"
        echo "  Terminal 2:  $0 test"
        ;;
esac
