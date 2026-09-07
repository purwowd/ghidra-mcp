# 17 - C2 & Post-Exploitation Lab Standard

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `14_RED_TEAM_KILLCHAIN.md`, `13_LAB_POC_STANDARD.md`, `08_SAFETY_OVERRIDES.md`

---

## Purpose

Define how to build **lab-contained C2 and post-exploitation** components that are
reproducible, observable, and cleanable — suitable for red↔blue exercises.

This is **not** a guide for uncontrolled real-world malware campaigns.

---

## Non-Negotiables

| Rule | Detail |
|------|--------|
| Lab-only callbacks | Listener binds to lab IP/VPN; document allowlist |
| Explicit enable | Implant features behind flags; no silent persistence |
| Kill switch | `--die` / magic callback / max lifetime (default short TTL) |
| Evidence | Beacon logs + optional pcap; marker tasks (`whoami`, hostname) |
| Cleanup | Remove services, tasks, files, firewall rules, registry keys |
| No worming | No autonomous lateral spread loops |
| Synthetic data | Exfil only `LAB_*` markers |

---

## Minimal Lab C2 Architecture

```
[Operator CLI] ←→ [Teamserver / listener] ←→ [Agent on lab host]
                         │
                         └─ logs/evidence/beacons.jsonl
```

Prefer simple protocols for teaching/detection:
- HTTP(S) with clear URI/header markers (`X-Lab-C2: 1`)
- TCP length-prefixed JSON
- Optional DNS lab zone (easy to detect with Zeek)

Default interval: high (e.g. 5–10s) for lab demos; document jitter.

---

## Package Layout

```
pocs/C2-<name>/  or  tools/c2_<name>/
├── README.md
├── listener.py          # teamserver
├── agent.py             # lab agent (or agent/ with Go build notes)
├── operator.py          # optional CLI
├── tasks/               # example task payloads (markers only)
├── docker-compose.yml   # listener (+ optional victim container)
├── detection/           # Suricata/Sigma for beacon pattern
├── evidence/
└── cleanup.sh
```

CLI contract (align with `13` where applicable):

```
listener.py --bind 0.0.0.0 --port 8443 --token LABTOKEN
agent.py --url http://listener:8443 --token LABTOKEN --ttl 600
operator.py --task whoami
```

Modes:
- `--mode check` — listener health + agent check-in without tasking
- `--mode full` — check-in → task `whoami`/`id` → verify output → agent exit/cleanup

---

## Agent Capability Tiers

### Tier C1 — Teaching Beacon (Default)

- Check-in + sleep
- Run allowlisted commands: `id`, `whoami`, `hostname`, `pwd`
- No file steal, no inject, no priv-esc

### Tier C2 — Post-Ex Lab Kit (Explicit Request)

- File read of allowlisted paths only
- Process list
- Optional SOCKS/pivot **inside docker network**
- Still no credential dump unless AD lab doc + explicit flag

### Tier C3 — Evasion Lab (Blue Pair Required)

- Simple obfuscation / sleep masking for **detection engineering**
- Must ship detection pack validating the technique
- Document “detectability goals” in README

---

## Post-Exploitation Modules (Lab)

Ship as separate scripts invoked by operator, each with cleanup:

| Module | Evidence | Cleanup |
|--------|----------|---------|
| Priv-esc check | `whoami` before/after | N/A |
| Persistence (opt-in) | path/key created | delete path/key |
| Cred access (AD lab) | ticket/hash marker | purge ticket cache |
| Lateral (PSRemoting/SSH) | remote `hostname` | close sessions |
| Exfil | `LAB_SECRET` over C2 | wipe temp files |

---

## Detection Expectations

For any C2 package, prefer:

- Suricata rule on URI/User-Agent/header marker
- Sigma on agent process ancestry (if host telemetry)
- Zeek notice on periodic beacons to lab IP

Validate with positive (beacon on) and negative (normal browse) runs (`10`).

---

## Prompt Shape

```
Context: lab C2 (doc 17). Tier: C1|C2|C3.
Topology: listener container + victim container/VM.
Tasks allowlist: [id, whoami, hostname]
Deliverable: listener+agent+operator + docker-compose + detection + cleanup
--mode full reproduces check-in → task → verify → die
Save under: pocs/C2-<name>/
```

---

**End of C2 series doc. Related: `14` kill chain · `18` SE · `19` containers. Index: `INDEX.md`.**
