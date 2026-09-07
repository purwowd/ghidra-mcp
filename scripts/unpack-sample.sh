#!/usr/bin/env bash
# Lab helper: unpack known packers when tools exist; refuse blind unpack otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <binary> [output]"
  echo "  UPX: requires upx + UPX! marker"
  echo "  Other: use ./scripts/custom-unpack-lab.sh scaffold <binary>"
  exit 1
fi

SRC="$1"
OUT="${2:-}"
if [[ ! -f "$SRC" ]]; then
  echo "Not found: $SRC" >&2
  exit 1
fi

detect() {
  local s
  s="$(strings "$SRC" 2>/dev/null || true)"
  if echo "$s" | grep -q 'UPX!'; then echo UPX; return; fi
  if echo "$s" | grep -qi 'VMProtect'; then echo VMProtect; return; fi
  if echo "$s" | grep -qi 'Themida'; then echo Themida; return; fi
  if echo "$s" | grep -qi 'aPack\|ASPack'; then echo ASPack; return; fi
  echo UNKNOWN
}

KIND="$(detect)"
echo "[*] Detected: $KIND"

case "$KIND" in
  UPX)
    if ! command -v upx >/dev/null 2>&1; then
      echo "upx not installed. On macOS: brew install upx" >&2
      exit 1
    fi
    BACKUP="${SRC}.packed"
    cp -n "$SRC" "$BACKUP" || cp "$SRC" "$BACKUP"
    TARGET="$SRC"
    if [[ -n "$OUT" ]]; then
      cp "$SRC" "$OUT"
      TARGET="$OUT"
    fi
    upx -d "$TARGET"
    echo "[+] Unpacked: $TARGET"
    echo "[+] Packed backup: $BACKUP"
    echo "[+] Next: import into Ghidra and Analyze; optional compare_programs_by_hash vs packed"
    ;;
  VMProtect|Themida|ASPack|UNKNOWN)
    echo "[!] No safe host-side unpacker for $KIND — scaffolding custom lab workspace"
    exec "$ROOT/scripts/custom-unpack-lab.sh" scaffold "$SRC"
    ;;
esac
