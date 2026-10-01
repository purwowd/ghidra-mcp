# POC-DETONATION-LAB

Isolated **Windows/Linux guest detonation loop** for malware RE. Lab-only.

Default CLI: `--mode check` (via `../../scripts/detonate-lab.sh check`).  
Primary path: `../../scripts/detonate-lab.sh full <label>`.

## Safety

- **Never** run unknown samples on the macOS analysis host.
- Guest must use snapshot + host-only / sinkhole NIC (no open egress).
- Git tracks **hashes + notes**; store binaries outside the repo.

## Quick start

```bash
# 1) Verify gates
./scripts/detonate-lab.sh check

# 2) Scaffold report + print guest checklist
./scripts/detonate-lab.sh full lab-sample-001

# 3) Optional HTTP/DNS sinkhole (host side of the lab bridge)
cd pocs/POC-DETONATION-LAB && docker compose up -d
```

Point the guest DNS/gateway at the sinkhole container IP (or host IP on the host-only network).

## Loop

```text
snapshot → copy sample (guest) → detonate → collect → revert → Ghidra static
```

MCP: `detonation_playbook`  
Ghidra Assist: **Tools ▾ → Detonation playbook**

## Layout

```
pocs/POC-DETONATION-LAB/
├── README.md
├── docker-compose.yml      # sinkhole (HTTP + DNS stub)
├── sinkhole/               # nginx static + named stubs
├── reports/RE-<label>/     # per-sample (scaffolded)
└── evidence/               # optional host-side captures (gitignored pattern)
```

See `ai_agent_instructions/16_RE_MALWARE_ANALYSIS.md` and `prompts/windows-malware-lab.md`.
