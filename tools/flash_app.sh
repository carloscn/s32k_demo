#!/usr/bin/env bash
# Build + flash ONLY s32k_demo (App), completely independent of
# s32k_easy_boot. Flashes to 0x00440000+ only (s32k_demo's own linker
# script region), and does NOT rebuild or touch easy_boot.
#
# Uses pegdbserver -programmingtype=1 (program/verify, no erase) so
# easy_boot at 0x00400000 is not wiped. Type=0 erase/program/verify
# reproducibly erases 0x00400000 even though the App ELF only loads
# 0x00440000+ (confirmed on hardware 2026-08-20). After flashing, the
# same GDB session readbacks both regions — no second connection (unreliable).
#
# Usage:
#   bash tools/flash_app.sh                 # build + flash + verify
#   bash tools/flash_app.sh --skip-build     # flash + verify only

set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"
PEG_SERVER="C:\\NXP\\S32DS.3.5\\eclipse\\plugins\\com.pemicro.debug.gdbjtag.pne_6.2.1.202606301718\\win32\\pegdbserver_console.exe"
# program/verify only — do NOT erase. Default erase/program/verify (type=0)
# reproducibly wipes easy_boot's 0x00400000 region even though the App ELF
# only has LOAD segments at 0x00440000+ (confirmed on hardware 2026-08-20).
PEG_PROGRAMMING_TYPE=1
GDB="C:\\NXP\\S32DS.3.5\\eclipse\\plugins\\com.pemicro.debug.gdbjtag.pne_6.2.1.202606301718\\win32\\gdb\\arm-none-eabi-gdb.exe"
ELF_PATH="$DEMO_ROOT/Debug_FLASH/Hello_World.elf"
GDB_SCRIPT="$DEMO_ROOT/Debug_FLASH/flash_app.gdb"
SKIP_BUILD=0

read_build_magic() {
    local hdr="$DEMO_ROOT/include/build_magic.h"
    BUILD_MAGIC_STR="$(grep 'APP_BUILD_MAGIC_STR' "$hdr" | sed -n 's/.*"\(0x[0-9A-Fa-f]*\)".*/\1/p')"
    BUILD_MAGIC_TIME="$(grep 'APP_BUILD_MAGIC_TIME' "$hdr" | sed -n 's/.*"\([^"]*\)".*/\1/p')"
}

[ "${1:-}" = "--skip-build" ] && SKIP_BUILD=1

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "[build] mingw32-make -j4 in $DEMO_ROOT"
    ( cd "$DEMO_ROOT" && mingw32-make -j4 ) || ( cd "$DEMO_ROOT" && mingw32-make -j4 )
fi

if [ ! -f "$ELF_PATH" ]; then
    echo "Not found: $ELF_PATH" >&2
    exit 1
fi
echo "[flash] target: $ELF_PATH ($(date -r "$ELF_PATH"))"
read_build_magic
echo "[flash] build magic: $BUILD_MAGIC_STR ($BUILD_MAGIC_TIME)"
echo "[flash] expect UART line: [build-magic] $BUILD_MAGIC_STR (...)"

ELF_PATH_WIN="$(echo "$ELF_PATH" | sed -E 's#^/([a-zA-Z])/#\1:/#')"

powershell -NoProfile -Command "
Get-Process pegdbserver_console -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 800
Start-Process '$PEG_SERVER' -ArgumentList '-startserver','-device=NXP_S32K3xx_S32K312','-serverport=7224','-programmingtype=$PEG_PROGRAMMING_TYPE' -WindowStyle Hidden
Start-Sleep -Seconds 2
"

cat > "$GDB_SCRIPT" <<EOF
set pagination off
set confirm off
target remote localhost:7224
file ${ELF_PATH_WIN}
load
x/4xw 0x00400000
x/4xw 0x00440000
monitor reset
detach
quit
EOF

FLASH_OUT="$("$GDB" -batch -x "$GDB_SCRIPT" 2>&1)" || true
echo "$FLASH_OUT"
echo "[flash] app flash done."

if echo "$FLASH_OUT" | grep -A1 "0x400000:" | grep -q "0xffffffff.*0xffffffff.*0xffffffff.*0xffffffff"; then
    echo ""
    echo "!!! WARNING: 0x00400000 (easy_boot) looks erased after app flash !!!"
    echo "!!! Reflash bootloader, then reflash app with --skip-build:           !!!"
    echo "!!!   bash ../s32k_easy_boot/tools/flash_bootloader.sh --skip-build     !!!"
    echo "!!!   bash tools/flash_app.sh --skip-build                            !!!"
elif echo "$FLASH_OUT" | grep -q "0x400000:"; then
    echo "[verify] easy_boot region (0x00400000) intact after app flash."
else
    echo "[verify] could not parse 0x00400000 readback — check FLASH_OUT above."
fi
echo "[flash] build magic flashed: $BUILD_MAGIC_STR — confirm in UART [build-magic] line"
