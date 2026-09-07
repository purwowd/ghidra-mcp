#!/usr/bin/env bash
# Build + deploy GhidraMCP into the user Ghidra 12.1.3 Extensions folder.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIP="$ROOT/mcp-server/target/GhidraMCP-7.0.0.zip"
EXT="${GHIDRA_USER_EXTENSIONS:-$HOME/Library/ghidra/ghidra_12.1.3_PUBLIC/Extensions}"
SKIP_BUILD="${SKIP_BUILD:-0}"

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "[*] Building GhidraMCP (mvn package)…"
  (cd "$ROOT/mcp-server" && mvn -q -DskipTests clean package assembly:single)
fi

if [[ ! -f "$ZIP" ]]; then
  echo "Missing $ZIP — build failed or SKIP_BUILD=1 without prior package" >&2
  exit 1
fi

mkdir -p "$EXT"
rm -rf "$EXT/GhidraMCP"
unzip -qo "$ZIP" -d "$EXT/"
echo "[+] Installed to $EXT/GhidraMCP ($(date -r "$ZIP" '+%Y-%m-%d %H:%M:%S') zip)"
ls "$EXT/GhidraMCP/lib" 2>/dev/null || ls "$EXT" | head
# Sanity: new lab tools must be in the jar
if ! jar tf "$EXT/GhidraMCP/lib/GhidraMCP-7.0.0.jar" | grep -q 'ProgramFlowService'; then
  echo "[!] WARNING: ProgramFlowService missing from installed jar" >&2
fi
echo "Restart Ghidra, then check: curl -s http://127.0.0.1:8089/mcp/schema | grep program_flow"
