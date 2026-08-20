#!/usr/bin/env bash
# Build + flash s32k_demo App + s32k_easy_boot, then capture UART via Tera Term.
#
# Flash order that works on this PEMicro/S32K312 setup (confirmed 2026-08-20):
#   1) App with -programmingtype=3 (erase sectors of App ELF) — also blanks
#      easy_boot (same mass-erase quirk as type=0 on App).
#   2) App with -programmingtype=1 (program/verify, no erase).
#   3) Bootloader with -programmingtype=1 (program onto blank 0x00400000).
# Trying "bootloader type=0 then app type=1" fails when App flash is not blank
# (type=1 cannot overwrite). See AGENTS.md flash-wipe notes.
#
# Usage:
#   bash tools/flash_and_log.sh
#   bash tools/flash_and_log.sh --skip-build
#   bash tools/flash_and_log.sh --capture-only
#   bash tools/flash_and_log.sh --capture-ms 45000

set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$DEMO_ROOT/.." && pwd)"
EASYBOOT_ROOT="$WORKSPACE_ROOT/s32k_easy_boot"
PROVISION_TOOLS="$WORKSPACE_ROOT/s32k312_provision/tools"
PEG_SERVER="C:\\NXP\\S32DS.3.5\\eclipse\\plugins\\com.pemicro.debug.gdbjtag.pne_6.2.1.202606301718\\win32\\pegdbserver_console.exe"
GDB="C:\\NXP\\S32DS.3.5\\eclipse\\plugins\\com.pemicro.debug.gdbjtag.pne_6.2.1.202606301718\\win32\\gdb\\arm-none-eabi-gdb.exe"
APP_ELF="$DEMO_ROOT/Debug_FLASH/Hello_World.elf"
BOOT_ELF="$EASYBOOT_ROOT/build/Easy_Boot.elf"
LOG_PATH="$WORKSPACE_ROOT/logs/uart_latest.log"
PORT="${UART_PORT:-COM3}"
CAPTURE_MS=45000
SKIP_BUILD=0
CAPTURE_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --capture-only) CAPTURE_ONLY=1; SKIP_BUILD=1; shift ;;
        --capture-ms) CAPTURE_MS="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

win_path() { echo "$1" | sed -E 's#^/([a-zA-Z])/#\1:/#'; }

start_peg() {
    local ptype="$1"
    powershell -NoProfile -Command "
Get-Process pegdbserver_console -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 1000
Start-Process '$PEG_SERVER' -ArgumentList '-startserver','-device=NXP_S32K3xx_S32K312','-serverport=7224','-programmingtype=$ptype' -WindowStyle Hidden
Start-Sleep -Seconds 3
"
}

gdb_load() {
    local elf_win="$1"
    local extra="${2:-}"
    local script
    script="$(mktemp -t flashXXXX.gdb)"
    cat > "$script" <<EOF
set pagination off
set confirm off
target remote localhost:7224
file ${elf_win}
load
${extra}
detach
quit
EOF
    "$GDB" -batch -x "$script" 2>&1 || true
    rm -f "$script"
}

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "[build] s32k_demo"
    ( cd "$DEMO_ROOT" && /c/opt/Mingw/bin/mingw32-make -j4 ) || ( cd "$DEMO_ROOT" && /c/opt/Mingw/bin/mingw32-make -j4 )
    echo "[build] s32k_easy_boot"
    ( cd "$EASYBOOT_ROOT" && /c/opt/Mingw/bin/mingw32-make -j4 ) || ( cd "$EASYBOOT_ROOT" && /c/opt/Mingw/bin/mingw32-make -j4 )
fi

mkdir -p "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"

APP_WIN="$(win_path "$APP_ELF")"
BOOT_WIN="$(win_path "$BOOT_ELF")"
MAGIC_HDR="$(grep 'APP_BUILD_MAGIC_STR' "$DEMO_ROOT/include/build_magic.h" | sed -n 's/.*"\(0x[0-9A-Fa-f]*\)".*/\1/p')"

if [ "$CAPTURE_ONLY" -eq 0 ]; then
    echo "[flash] (1/3) app erase-only type=3 (also blanks easy_boot)"
    start_peg 3
    gdb_load "$APP_WIN"

    echo "[flash] (2/3) app program type=1"
    start_peg 1
    gdb_load "$APP_WIN" "x/4xw 0x00440000"

    echo "[flash] (3/3) bootloader program type=1 (onto blank 0x00400000)"
    start_peg 1
    OUT="$(gdb_load "$BOOT_WIN" "x/4xw 0x00400000
x/4xw 0x00440000")"
    echo "$OUT"
    if echo "$OUT" | grep -q "0x400000:.*0xffffffff.*0xffffffff"; then
        echo "!!! bootloader still blank after type=1 — probe may be wedged !!!"
    else
        echo "[verify] bootloader + app headers look programmed."
    fi
    echo "[flash] build magic: $MAGIC_HDR — expect UART [build-magic] $MAGIC_HDR"
fi

echo "[check] expect UART: [build-magic] $MAGIC_HDR"
UART_SCRIPT_WIN="$(win_path "$PROVISION_TOOLS/uart_capture_teraterm.ps1")"
LOG_PATH_WIN="$(win_path "$LOG_PATH")"

echo "[uart] Tera Term capture on $PORT for ${CAPTURE_MS}ms -> $LOG_PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File "$UART_SCRIPT_WIN" \
    -Port "$PORT" -Baud 115200 -DurationMs "$CAPTURE_MS" -LogFile "$LOG_PATH_WIN" &
CAPTURE_PID=$!
sleep 2

echo "[reset] debugger core reset (prefer physical power-cycle if log is empty)"
start_peg 0
"$GDB" -batch -ex "target remote localhost:7224" -ex "monitor reset" -ex "detach" -ex "quit" || true

echo "[uart] waiting for capture (${CAPTURE_MS}ms)..."
wait "$CAPTURE_PID" || true

echo ""
echo "===== UART capture ($LOG_PATH) ====="
cat "$LOG_PATH" || true
echo "===== end capture ====="

if grep -q '\[build-magic\]' "$LOG_PATH" 2>/dev/null; then
    MAGIC_LOG="$(grep '\[build-magic\]' "$LOG_PATH" | head -1)"
    echo "[check] uart line: $MAGIC_LOG"
    if echo "$MAGIC_LOG" | grep -q "$MAGIC_HDR"; then
        echo "[check] MAGIC MATCH"
    else
        echo "[check] MAGIC MISMATCH"
    fi
else
    echo "[check] no [build-magic] — power-cycle and: bash tools/flash_and_log.sh --capture-only"
fi

if grep -q 'CMAC test passed via mbedTLS' "$LOG_PATH" 2>/dev/null; then
    echo "[check] mbedTLS CMAC PASSED"
fi
