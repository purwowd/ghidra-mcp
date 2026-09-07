# 12 - Engagement, OPSEC, and Lab Workflow (Red + Blue)

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 2.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `02_LEGAL_CONTEXT.md`, `08_SAFETY_OVERRIDES.md`, `11_REPORTING_STANDARD.md`

---

## Purpose

This document turns the repo into a practical “professional workflow” playbook:

- how to define scope and lab topology
- how to run research safely (OPSEC + data handling)
- how to keep artifacts auditable (logs, evidence, cleanup)
- how to iterate red-team PoCs and blue-team detections in a loop

---

## Engagement Initialization Checklist

Before building or running tools/PoCs, the agent should assume the researcher wants:

- **Scope statement**: targets (hostnames/IP/CIDR), exclusions, “lab-only” confirmation
- **Topology**: Docker vs VM vs bare-metal; where attacker/victim/target live
- **Evidence capture plan**: pcap vs logs vs screenshots
- **Stop/Abort**: remind that `STOP` / `ABORT` / `CLEANUP` exist (doc 08)

**Minimum questions rule still applies**: ask at most one question if needed; otherwise assume lab-local.

---

## Lab-First Execution Defaults

To keep research controlled and reproducible:

- Prefer **local harness** (Docker compose) whenever feasible
- Prefer **check-first** modes (`--mode check`, `--dry-run`)
- Prefer **single-target** execution (no broad scans) unless explicitly requested
- Prefer **marker-based evidence** (headers, banners, tokens) for deterministic verify
- Follow `13_LAB_POC_STANDARD.md` for package layout and CLI contract
---

## OPSEC & Data Handling (Practical)

### Sensitive data

- Never persist real credentials/PII in the repository.
- Use **test accounts** and **synthetic data** for PoCs.
- When output may contain secrets, sanitize by default and store sanitized evidence.

### Artifact hygiene

- Keep artifacts in `evidence/` with short descriptions.
- Always include cleanup routines and “how to revert” steps.
- For MITM: always restore ARP/routing/iptables changes.

### Avoid uncontrolled propagation

- No worming/self-spreading logic.
- No persistence by default in PoCs unless explicitly asked and reversible.

---

## Red ↔ Blue Iteration Loop

Standard loop for professional teams:

1. **Build harness + PoC** (red)
2. Capture evidence (pcap/logs)
3. **Write detection** (blue)
4. Validate detection triggers (positive) and doesn’t fire on benign runs (negative control)
5. Produce report bundle (finding + detection + validation)

---

## Common Workflows (Templates)

### MITM / Intercept (Lab)

Expected components:

- Harness: victim + target + attacker/router
- Evidence: pcapng + before/after diff
- Cleanup: restore state
- Detection: Suricata + optional Zeek/Sigma

### Web Exploit PoC (Lab)

- Harness: vulnerable app container
- PoC: check/exploit/full
- Evidence: request/response logs, command output marker
- Detection: server access logs + WAF/IDS signatures (if used)

### Endpoint Technique Emulation (Lab)

- Harness: Windows VM (Sysmon) / Linux VM (auditd)
- PoC: technique emulator
- Evidence: event IDs, process tree, network connections
- Detection: Sigma + query examples

---

## “Professional Operator” Prompt Pack

Use this to force full professional outputs:

```
Context: authorized Security Research Lab (docs 00–20). Role: red+blue engineer.
Need an end-to-end professional deliverable:
- lab harness (Docker/VM) + runnable PoC (check→exploit→verify→cleanup)
- evidence (pcap/log/diff) + validation steps
- detection pack (Sigma/Suricata/Zeek/YARA as applicable)
- report (format F-XXX + evidence index + triage notes)

Use case:
[technique/bug + target stack + lab topology]
Save artifacts under pocs/<name>/ and reports/<date>-<name>/.
```

---

**End of core engagement doc (`12`). Extended series: `13`–`20` (PoC / red team / research / RE / C2 / SE / K8s / horizon).**

