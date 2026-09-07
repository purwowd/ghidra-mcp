# 15 - Vulnerability Research Methodology (Expert Path)

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `04_POC_GENERATION_PROTOCOL.md`, `05_EXPLOIT_DEVELOPMENT_GUIDE.md`, `13_LAB_POC_STANDARD.md`  
> **Companion**: `16_RE_MALWARE_ANALYSIS.md`

---

## Purpose

Define how the agent supports **expert vulnerability research** — not only “write a PoC for known CVE”,
but **root-cause analysis, patch diffing, variant hunting, and disclosure-grade packaging**.

---

## Research Modes

| Mode | Goal | Primary outputs |
|------|------|-----------------|
| **A. Known CVE reproduce** | Validate vendor advisory in lab | Harness + full PoC (`13`) |
| **B. Patch analysis** | Understand fix; find incomplete fixes | Diff notes + variant PoC |
| **C. Target audit** | Find new bugs in chosen software | Findings list + minimal PoCs |
| **D. Crash triage** | Turn crash into security bug | Root cause + exploitability call |
| **E. Variant / sibling hunt** | Same pattern elsewhere | Matrix of affected products/paths |

Ask at most one question to select mode if unclear; default to **A** when a CVE is named,
**C** when a codebase/path is named.

---

## Standard Research Workflow

```
1. SCOPE      → software, version, trust boundary, threat model
2. BUILD      → reproducible lab build (container/VM/commit pin)
3. SURFACE    → entry points, parsers, authz, IPC, deserialization
4. HYPOTHESIS → bug class + why reachable
5. PROBE      → minimal inputs / harness tests (asan/ubsan when C/C++)
6. ROOT CAUSE → exact code path + missing check
7. EXPLOIT    → reliable PoC with evidence (full path)
8. VARIANT    → same sink / same pattern elsewhere
9. FIX REVIEW → patch completeness; bypass ideas (lab only)
10. PACKAGE   → pocs/<ID>/ + report (`11`) + optional detection (`10`)
```

---

## Root Cause Writeup (Required for Research-Grade Work)

Every serious finding package should include `reports/` or README section:

```markdown
## Root Cause
- **Sink**: [function/file:line]
- **Missing check**: [bounds / authz / allowlist / type confusion / ...]
- **Attacker control**: [which input reaches sink]
- **Trust boundary crossed**: [network → process / user → kernel / ...]
- **Why previous defenses failed**: [WAF, parser, sandbox]
```

Avoid “it’s vulnerable because CVE says so” without local confirmation.

---

## Patch Diff Protocol

When a fixed version / commit is available:

1. Pin vulnerable and fixed revisions.
2. Diff security-relevant paths (authz, parsers, memcpy, deserialization, URL allowlists).
3. Classify change: complete fix / incomplete / behavior break / unrelated refactor.
4. Attempt **incomplete-fix bypass** in lab only (document as variant).
5. Record: commit hash, files, before/after snippet references (no huge vendor code dumps).

Output artifact: `analysis/PATCH_DIFF.md` inside the PoC package.

---

## Exploitability Rubric

| Rating | Meaning |
|--------|---------|
| **E0** | Crash / DoS only (no clear control) |
| **E1** | Info leak / limited primitive |
| **E2** | Strong primitive (RIP control, arbitrary read, auth bypass) |
| **E3** | Reliable RCE / domain impact in lab conditions |

State assumptions (ASLR, auth, race window). Prefer honest E-ratings over hype.

---

## Tooling Defaults by Target Class

| Class | Prefer |
|-------|--------|
| Web / API | harness + httpx/requests, proxy (`--proxy`), jwt tools |
| Memory (C/C++) | asan/ubsan builds, gdb/lldb, pwntools |
| Java / .NET | gadget analysis, ysoserial-style labs, deserialization hooks |
| Node / Python | prototype pollution / pickle / yaml labs with pinned deps |
| Binary closed-source | see `16` (RE first, then PoC) |

---

## Variant Hunting Checklist

- [ ] Same function copied in other endpoints/modules?
- [ ] Other URL parsers / allowlists with same `startswith`/`contains` mistake?
- [ ] Related products sharing library version?
- [ ] Incomplete patch still trusting client-side fields?
- [ ] Dangerous defaults in sibling config flags?

Deliver a **variant matrix** (product × version × reachable × notes).

---

## Disclosure Package (When Requested)

Follow `11_REPORTING_STANDARD.md` plus:

- Clear CVE/CWE (or “pending”)
- Affected / fixed versions with evidence
- Full reproduce against harness
- Remediation that matches root cause (not generic “sanitize input”)
- Optional detection rules

Responsible disclosure timelines live in `02_LEGAL_CONTEXT.md`.

---

## Anti-Patterns (Research)

- Shipping check-only stubs when researcher asked for full attack reproduce
- Claiming RCE without captured evidence
- Mixing production cloud metadata with lab demos
- Pasting huge proprietary sources into the repo
- Skipping cleanup after invasive tests

---

## Prompt Shape (Research)

```
Mode: [A CVE reproduce | B patch diff | C audit | D triage | E variant]
Target: [software@version / git commit]
Trust boundary: [e.g. unauth HTTP → deserialize]
Deliverable: harness + full PoC + root-cause notes + patch-diff (if any) + report
Save under: pocs/<CVE-or-FINDING>/
```

---

**Next:** `16_RE_MALWARE_ANALYSIS.md`
