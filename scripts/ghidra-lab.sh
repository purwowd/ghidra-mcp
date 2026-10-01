#!/usr/bin/env bash
# Launch Ghidra lab project + print MCP / Agent next steps (Mac Mini M4 16GB).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA_RUN="${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}/ghidraRun"
if [[ ! -x "$GHIDRA_RUN" ]]; then
  GHIDRA_RUN="$(command -v ghidraRun || true)"
fi
PROJECT="${GHIDRA_LAB_PROJECT:-$HOME/Ghidra/mcp-lab}"
MCP_URL="${GHIDRA_MCP_URL:-http://127.0.0.1:8089}"
JAVA_HOME_DEFAULT="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"

export JAVA_HOME="${JAVA_HOME:-$JAVA_HOME_DEFAULT}"
export PATH="$JAVA_HOME/bin:/opt/homebrew/bin:$PATH"
export GHIDRA_MAXMEM="${GHIDRA_MAXMEM:-4G}"
export GHIDRA_JAVA_OPTIONS="${GHIDRA_JAVA_OPTIONS:--XX:+UseG1GC -XX:MaxGCPauseMillis=200}"
export GHIDRA_MCP_URL="$MCP_URL"

START_AGENT=0
NO_LAUNCH=0
WAIT_SECS=90

usage() {
  cat <<EOF
Usage: $(basename "$0") [--agent] [--no-launch] [--wait SECONDS]

  --agent       After health OK, start: agent --trust --approve-mcps
  --no-launch   Do not start Ghidra; only check MCP + print tips
  --wait N      Seconds to wait for MCP health (default: $WAIT_SECS)

Project: $PROJECT
MCP:     $MCP_URL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) START_AGENT=1; shift ;;
    --no-launch) NO_LAUNCH=1; shift ;;
    --wait) WAIT_SECS="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

mcp_health() {
  curl -sf --connect-timeout 1 "$MCP_URL/mcp/health" >/dev/null 2>&1
}

echo "[*] JAVA_HOME=$JAVA_HOME"
echo "[*] GHIDRA_MAXMEM=$GHIDRA_MAXMEM"
echo "[*] project=$PROJECT"

if [[ "$NO_LAUNCH" -eq 0 ]]; then
  if [[ ! -x "$GHIDRA_RUN" ]]; then
    echo "[!] ghidraRun not found. brew install ghidra / set GHIDRA_INSTALL_DIR" >&2
    exit 1
  fi
  if mcp_health; then
    echo "[+] MCP already up at $MCP_URL"
  else
    echo "[*] Starting Ghidra…"
    if [[ -e "${PROJECT}.gpr" || -d "$PROJECT" || -e "$PROJECT" ]]; then
      # ghidraRun accepts a project path when present
      nohup "$GHIDRA_RUN" "$PROJECT" >/tmp/ghidra-lab.log 2>&1 &
    else
      nohup "$GHIDRA_RUN" >/tmp/ghidra-lab.log 2>&1 &
      echo "[!] Project not found at $PROJECT — open/create mcp-lab manually."
    fi
    echo "[*] log: /tmp/ghidra-lab.log"
  fi
fi

echo "[*] Waiting up to ${WAIT_SECS}s for MCP health (open a binary in CodeBrowser if needed)…"
deadline=$((SECONDS + WAIT_SECS))
while (( SECONDS < deadline )); do
  if mcp_health; then
    echo "[+] MCP healthy:"
    curl -s "$MCP_URL/mcp/health" || true
    echo
    curl -s "$MCP_URL/list_open_programs" 2>/dev/null | head -c 500 || true
    echo
    break
  fi
  sleep 2
done

if ! mcp_health; then
  cat <<EOF
[!] MCP not up yet.

In Ghidra:
  1) Open project mcp-lab
  2) Double-click chal_symbols or chal_stripped
  3) Analyze → Yes
  4) Re-run: $0 --no-launch

Binaries: $ROOT/samples/ctf-rev-mcp/bin/
Prompts:  $ROOT/prompts/rev-mcp.md
EOF
  exit 2
fi

echo
echo "[*] Approve / check MCP (Cursor backend):"
echo "    agent mcp enable ghidra && agent mcp list"
echo "[*] Chat:"
echo "    cd $ROOT && agent --trust --approve-mcps"
echo "[*] Prompt pack: $ROOT/prompts/rev-mcp.md"

if [[ "$START_AGENT" -eq 1 ]]; then
  cd "$ROOT"
  agent mcp enable ghidra >/dev/null 2>&1 || true
  exec agent --trust --approve-mcps
fi
