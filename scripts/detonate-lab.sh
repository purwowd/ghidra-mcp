#!/usr/bin/env bash
# Lab detonation loop helper — NEVER executes samples on the macOS host.
# Modes: check | scaffold | status | full (orchestrates checklist; guest run is manual/VM).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="${DETONATION_LAB_DIR:-$ROOT/pocs/POC-DETONATION-LAB}"
REPORTS_DIR="${LAB_DIR}/reports"
EVIDENCE_DIR="${LAB_DIR}/evidence"
MODE="${1:-check}"
SAMPLE_HASH="${2:-}"

usage() {
  cat <<EOF
Usage: $0 [--mode] check|scaffold|status|full [sha256-or-label]

  check     Verify lab layout + safety gates (default)
  scaffold  Create reports/<label>/ tree for a new sample (hashes only in-repo)
  status    Show last scaffold + docker sinkhole status
  full      check → print guest detonation checklist (no host execute)

Env:
  DETONATION_LAB_DIR  override lab root (default: pocs/POC-DETONATION-LAB)
  DETONATION_VM_HINT  e.g. utm://Windows-Lab or qemu:///system

Safety: unknown malware must run only inside an isolated guest with snapshot + sinkhole.
EOF
}

die() { echo "[-] $*" >&2; exit 1; }
ok() { echo "[+] $*"; }
info() { echo "[*] $*"; }

require_layout() {
  mkdir -p "$LAB_DIR"/{scripts,sinkhole,evidence,.snapshots-meta}
  mkdir -p "$REPORTS_DIR"
}

mode_check() {
  require_layout
  local fail=0
  [[ -f "$LAB_DIR/README.md" ]] || { info "README missing (will exist after scaffold package)"; }
  [[ -f "$LAB_DIR/docker-compose.yml" ]] && ok "sinkhole compose present" || { info "no compose yet"; fail=0; }
  if [[ "$(uname -s)" == "Darwin" ]]; then
    ok "Host is macOS — refusing any auto-exec of samples (by design)"
  fi
  # Never allow DETONATE_ON_HOST
  if [[ "${DETONATE_ON_HOST:-}" == "1" ]]; then
    die "DETONATE_ON_HOST=1 is forbidden in this lab harness"
  fi
  command -v docker >/dev/null 2>&1 && ok "docker available for sinkhole" || info "docker optional (sinkhole)"
  command -v utmctl >/dev/null 2>&1 && ok "utmctl found" || info "utmctl optional (UTM VMs)"
  command -v virsh >/dev/null 2>&1 && ok "virsh found" || info "virsh optional"
  ok "check complete (exit gates OK)"
  return 0
}

mode_scaffold() {
  require_layout
  local label="${SAMPLE_HASH:-sample-$(date +%Y%m%d-%H%M%S)}"
  label="$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-80)"
  label="${label%%_}"
  local dest="$REPORTS_DIR/RE-$label"
  mkdir -p "$dest"/{static,dynamic/evidence,detection}
  cat > "$dest/README.md" <<EOF
# RE-$label

Lab detonation report scaffold. Store **hashes only** in-repo; keep samples outside git.

## Sample

- SHA256: (fill)
- Path (VM only): (fill)
- Snapshot name: (fill)

## Phases

1. Snapshot VM
2. Start sinkhole: \`cd $LAB_DIR && docker compose up -d\`
3. Copy sample into guest (shared folder / scp to lab VLAN)
4. Detonate under Procmon/Sysmon; capture PCAP on sinkhole
5. Collect drops → \`dynamic/evidence/\`
6. Revert snapshot
7. Static follow-up in Ghidra + MCP \`malware_triage\`

## ATT&CK

(fill after run)
EOF
  cat > "$dest/hashes.txt" <<EOF
# sha256  filename_note
# (paste after hashing inside the VM or on an isolated volume)
EOF
  cat > "$dest/dynamic/reproduce.md" <<EOF
# Detonation reproduce

1. Restore clean snapshot
2. Ensure guest NIC points at sinkhole / host-only
3. Run sample once; note PID / drops
4. Export Procmon CSV + PCAP to evidence/
5. Revert snapshot immediately
EOF
  printf '%s\n' "$dest" > "$LAB_DIR/.snapshots-meta/last_scaffold"
  ok "Scaffold: $dest"
  info "Next: fill hashes.txt; use MCP detonation_playbook from Assist"
}

mode_status() {
  require_layout
  if [[ -f "$LAB_DIR/.snapshots-meta/last_scaffold" ]]; then
    ok "Last scaffold: $(cat "$LAB_DIR/.snapshots-meta/last_scaffold")"
  else
    info "No scaffold yet"
  fi
  if [[ -f "$LAB_DIR/docker-compose.yml" ]] && command -v docker >/dev/null 2>&1; then
    (cd "$LAB_DIR" && docker compose ps) || true
  fi
  info "VM hint: ${DETONATION_VM_HINT:-unset}"
}

mode_full() {
  mode_check
  mode_scaffold
  cat <<EOF

========== GUEST DETONATION CHECKLIST (manual) ==========
[ ] Clean snapshot restored
[ ] Sinkhole up:  cd $LAB_DIR && docker compose up -d
[ ] Guest DNS/gateway → sinkhole
[ ] Sample copied into guest (not executed on host)
[ ] Procmon/Sysmon + PCAP rolling
[ ] Run sample → collect evidence into report dynamic/evidence/
[ ] Revert snapshot
[ ] Ghidra: malware_triage / c_binary_triage on drops
=========================================================

Host will NOT execute the sample. That is intentional.
EOF
}

case "$MODE" in
  -h|--help|help) usage; exit 0 ;;
  check) mode_check ;;
  scaffold) mode_scaffold ;;
  status) mode_status ;;
  full) mode_full ;;
  *) usage; die "unknown mode: $MODE" ;;
esac
