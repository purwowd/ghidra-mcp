#!/usr/bin/env bash
# Custom / commercial packer unpack lab helper (host-side automation only).
# Does NOT run packers or malware on the macOS host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-help}"
SAMPLE="${2:-}"
OUT_ROOT="${UNPACK_LAB_DIR:-$ROOT/pocs/POC-DETONATION-LAB/evidence/unpack}"

usage() {
  cat <<EOF
Usage: $0 <command> [args]

  scaffold <sample-path>   Create unpack workspace + OEP checklist
  upx <sample-path>        Delegate to unpack-sample.sh (UPX only)
  status                   Show latest workspace
  help

After OEP dump in Windows VM (x64dbg+Scylla) or Ghidra Debugger:
  - Place dump as <workspace>/dump/unpacked.bin (or .exe)
  - Import into Ghidra; MCP: compare_programs_by_hash / malware_triage

MCP helpers:
  detect_packer / unpack_workflow
  export_memory_block (static)
  debugger/dump_memory_to_file (live OEP)
EOF
}

die() { echo "[-] $*" >&2; exit 1; }
ok() { echo "[+] $*"; }

cmd_scaffold() {
  [[ -n "$SAMPLE" && -f "$SAMPLE" ]] || die "scaffold needs existing sample path"
  local base hash label ws
  base="$(basename "$SAMPLE")"
  hash="$(shasum -a 256 "$SAMPLE" | awk '{print $1}')"
  label="${base%.*}-${hash:0:12}"
  ws="$OUT_ROOT/$label"
  mkdir -p "$ws"/{dump,notes,packed}
  cp "$SAMPLE" "$ws/packed/"
  cat > "$ws/notes/OEP_CHECKLIST.md" <<EOF
# Custom unpack — $base

SHA256: $hash

## Windows lab VM (preferred for PE protectors)

1. Snapshot VM
2. Open sample in x64dbg
3. Break on VirtualAlloc / VirtualProtect / packer stub EOF
4. Reach OEP (look for typical prologue / jump to clear code)
5. Scylla: IAT Autosearch → Get Imports → Dump → Fix Dump
6. Copy fixed dump to:
   $ws/dump/unpacked.exe
7. Revert snapshot

## Ghidra Debugger path

1. Window → Debugger; launch/attach in lab target
2. Break near OEP; when stopped:
   debugger/dump_memory_to_file output_path=$ws/dump/raw_oep.bin address=<module_base> size=<image_size>
3. Rebuild PE offline (Scylla) if raw dump is not a valid PE
4. Import into Ghidra → Analyze

## After import

\`\`\`text
detect_packer
malware_triage
compare_programs_by_hash
\`\`\`
EOF
  printf '%s\n' "$ws" > "$OUT_ROOT/.last_workspace"
  ok "Workspace: $ws"
  ok "Checklist: $ws/notes/OEP_CHECKLIST.md"
}

cmd_upx() {
  [[ -n "$SAMPLE" && -f "$SAMPLE" ]] || die "upx needs sample path"
  exec "$ROOT/scripts/unpack-sample.sh" "$SAMPLE"
}

cmd_status() {
  if [[ -f "$OUT_ROOT/.last_workspace" ]]; then
    ok "Last: $(cat "$OUT_ROOT/.last_workspace")"
  else
    echo "[*] No workspace yet"
  fi
}

case "$MODE" in
  scaffold) cmd_scaffold ;;
  upx) cmd_upx ;;
  status) cmd_status ;;
  help|-h|--help) usage ;;
  *) usage; die "unknown: $MODE" ;;
esac
