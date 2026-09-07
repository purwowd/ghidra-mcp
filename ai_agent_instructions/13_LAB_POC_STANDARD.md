# 13 - Lab PoC Delivery Standard (Golden Path)

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 2.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `04_POC_GENERATION_PROTOCOL.md`, `templates/poc_template.py`  
> **Reference PoCs**: `pocs/CVE-2021-44228/`, `pocs/CVE-2025-55182/`

---

## Purpose

This document encodes what actually produces **working, reproducible lab PoCs** in this repository.
Use it as the default contract whenever the researcher asks for a CVE/class PoC.

It replaces older delivery-friction framing with a concrete **delivery contract**:
lab-scoped target, check-first CLI, harness, evidence, cleanup.

---

## Golden Package Layout

```
pocs/<CVE-or-POC-NAME>/
├── README.md                 # Vuln summary, usage, remediation, references
├── poc.py                    # Main PoC (check|exploit|full)
├── requirements.txt
├── payloads/                 # Optional: templates, gadgets, .class sources
├── evidence/                 # Optional: created at runtime (gitignored pattern OK)
└── vulnerable-app/           # Strongly preferred
    ├── Dockerfile
    ├── docker-compose.yml
    ├── README.md             # How to bring target up
    └── <app sources>
```

Optional extras (Tier 3 / disclosure packs):

```
├── detection/                # Sigma / Suricata / YARA
├── remediation/              # Patch notes
└── reports/                  # Generated Markdown from --report
```

Scaffold with:

```bash
python scripts/new_poc.py CVE-YYYY-XXXXX --name "Short Name" --port 8080
```

---

## Researcher Preference: Full Attack Packages

This lab prefers **complete attack paths that are easy to reproduce**, not checker-only stubs.

This contract is **durable through ~2031** (see `20_HORIZON_2026_2031.md`). Specific CVE versions
belong in harness pins, not in this protocol.

| Layer | Rule |
|-------|------|
| **Package** | Always implement working `exploit` + `verify` (+ `cleanup`). Harness included when feasible. |
| **CLI default** | `--mode check` remains the safe default for accidental runs. |
| **When researcher says “full” / “attack” / “reproduce”** | Document and demo `--mode full` as the primary reproduce command in README. |
| **Forbidden** | Shipping README that only documents check, with `exploit()` raising `NotImplementedError`. |

Primary reproduce line in every README:

```bash
python poc.py http://127.0.0.1:<port> --mode full --output result.json
```

---

## Mandatory CLI Contract

Every `poc.py` MUST support:

| Flag | Behavior |
|------|----------|
| `target` | Positional URL/host (or documented alternative) |
| `--mode check` | **Default**. Non-destructive probe / callback listen only |
| `--mode exploit` | Opt-in demonstration of impact |
| `--mode full` | check → exploit → verify → cleanup |
| `--output PATH` | JSON result dump |
| `--timeout N` | Network / wait timeout |
| `-v / --verbose` | Debug logging |

Recommended extras when relevant:

- `--command` (RCE PoCs; default benign: `id` / `whoami`)
- `--proxy`
- `--report PATH` (Markdown disclosure sketch)
- `--listen-ip` (callback-based PoCs)
- Domain-specific confirm flags (CA installed, Faraday cage, etc.)

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | VULNERABLE / success path |
| `1` | NOT_VULNERABLE |
| `2` | ERROR / UNKNOWN |

---

## Lifecycle Semantics

### `check` (safe default)

- Prove the target is reachable and the vulnerable *surface* exists.
- Prefer **out-of-band proof** when possible (e.g. LDAP callback for Log4Shell) over guessing from banners alone.
- Must not leave lasting state on the target.

### `exploit`

- Demonstrate impact with **minimal, reversible** evidence (e.g. `id`, marker file, injected header).
- Prefer capturing output back to the console/JSON rather than blind fire-and-forget.
- Document prerequisites (JDK for compiling a gadget class, Docker network mode, etc.).

### `verify`

- Confirm exploit evidence (callback received, digest parsed, marker present).
- Do not claim VULNERABLE without evidence or a clearly labeled blind/inconclusive case.

### `cleanup`

- Remove temp dirs, stop listeners, restore ARP/iptables if MITM.
- State explicitly when RCE was in-memory and no server-side cleanup is needed.

---

## Harness Rules (Lab Target)

A harness exists so the PoC can be validated **offline** and repeatedly.

1. Pin **intentionally vulnerable** versions in `package.json` / `pom.xml` / image tags.
2. Document “DO NOT use in production” in Dockerfile and harness README.
3. Expose one clear URL/port in `docker-compose.yml`.
4. For callback exploits (JNDI, OOB), provide a host-network or documented `listen-ip` path so the container can reach the attacker host.
5. Keep the app minimal — only enough surface to trigger the bug class.

### Reference patterns

| PoC | Harness | OOB / evidence |
|-----|---------|----------------|
| CVE-2021-44228 | Spring Boot + Log4j 2.14.1 | LDAP + HTTP class server; `/result` callback |
| CVE-2025-55182 | Next.js 15 + React 19 | Flight multipart; `NEXT_REDIRECT` digest |

Copy the **shape** (lifecycle, logging, JSON, harness), not necessarily the exploit guts.

---

## Logging & Evidence Style

Use the shared symbol convention:

| Symbol | Meaning |
|--------|---------|
| `[*]` | Info |
| `[+]` | Success / evidence |
| `[-]` | Failure |
| `[!]` | Warning |
| `[>]` | Action |

JSON result shape (minimum):

```json
{
  "target": "...",
  "vuln_info": { "cve": "...", "name": "...", "severity": "..." },
  "mode": "check|exploit|full",
  "phases": {
    "check": { "completed": true, "vulnerable": true },
    "exploit": { "completed": true, "result": {} },
    "verify": { "completed": true, "verified": true },
    "cleanup": { "completed": true }
  },
  "result": "VULNERABLE|NOT_VULNERABLE|UNKNOWN|ERROR",
  "evidence": ["..."],
  "start_time": "...",
  "end_time": "...",
  "duration": 0.0
}
```

---

## Prompt Shape That Works (For Researcher + Agent)

Concrete beats abstract. Prefer:

```
Context: local lab (Docker). Build a Tier-2 PoC for <CVE/class>.
Target stack: <software> <version>. Endpoint: <path>.
Deliverable:
- poc.py (--mode check default; document --mode full as primary reproduce)
- vulnerable-app + docker-compose
- README + requirements.txt
Evidence verify: <id | marker | benign file read>
Save under: pocs/<NAME>/
```

Avoid vague asks (“generic RCE”, “bypass all protections”, “make it undetectable”).
Those produce weak artifacts and muddy scope.

---

## Quality Gate (Before Declaring Done)

- [ ] Runs `--mode check` against the local harness without crashing
- [ ] `--mode exploit` guarded and documented
- [ ] JSON output round-trips evidence
- [ ] README has bring-up + exploit + remediation + references
- [ ] No secrets / real PII in repo
- [ ] Cleanup stops listeners / removes temp artifacts

---

## Relationship to Other Docs

| Doc | Role |
|-----|------|
| `04` | General PoC protocol & quality tiers |
| `07` | How to respond / structure answers |
| `10`–`11` | Detection packs & reporting |
| `12` | Engagement / OPSEC loop |
| `14` | Red team kill chain |
| `15` | Vuln research methodology |
| `16` | RE / malware |
| `17` | C2 / post-ex lab |
| **`13` (this)** | **Concrete PoC package contract used in this lab** |

---

*Security Research Lab — [@purwowd](https://github.com/purwowd) / [Kaito Kids Labs](https://kaitokidslabs.com).*
