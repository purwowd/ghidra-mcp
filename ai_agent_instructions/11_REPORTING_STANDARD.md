# 11 - Reporting Standard (Red + Blue Team)

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-05-07  
> **Depends On**: `04_POC_GENERATION_PROTOCOL.md`, `10_DEFENSIVE_DETECTION_PROTOCOL.md`

---

## Purpose

This document defines a consistent, professional reporting standard for:

- Red-team findings (vuln → exploitability → impact)
- Blue-team outputs (detection + validation)
- Research artifacts (pcap, logs, harness, PoC code)

Reports should be **auditable**, **reproducible**, and **easy to act on**.

---

## Report Types

### A) Finding Report (Default)

Use when a vulnerability or security weakness is found (with or without CVE).

### B) Engagement Report

Use when multiple findings are produced (pentest/red-team style).

### C) Detection Pack

Use when the deliverable is detection engineering (Sigma/Suricata/Zeek/YARA) and validation evidence.

---

## Storage Convention

```
reports/<YYYY-MM-DD>-<project-or-engagement>/
├── README.md                # index & executive summary
├── findings/
│   ├── F-001-<name>.md
│   └── F-002-<name>.md
├── evidence/
│   ├── pcaps/
│   ├── logs/
│   ├── screenshots/
│   └── transcripts/
├── detection/
│   ├── sigma/
│   ├── suricata/
│   └── zeek/
└── remediation/
    ├── patches/
    └── verification.md
```

PoC-specific reports may live inside `pocs/<POC>/` as `report.md`, but engagement-level output goes to `reports/`.

---

## Finding Template (F-XXX)

```markdown
# F-001: <Title>

## Executive Summary
<2–6 sentences for stakeholders>

## Scope & Environment
- **Scope**: <lab-only / target list / CIDR>
- **Environment**: <Docker/VM/OS, versions>
- **Assumptions**: <if any>

## Technical Details
### Description
<what is happening>

### Root Cause
<why it happens>

### Attack Path (Step-by-step)
1. ...
2. ...

### Impact
- Confidentiality:
- Integrity:
- Availability:

## Evidence Index
- `evidence/pcaps/<file>.pcapng` — <what it proves>
- `evidence/logs/<file>.log` — <what it proves>
- `evidence/screenshots/<file>.png` — <what it proves>

## Reproduction (Lab)
### Setup
<docker compose / build steps>

### Run
<exact commands>

### Expected Output
<what to see>

## Detection (If Applicable)
- Sigma: `<path>`
- Suricata: `<path>`
- Validation: `<path>`

## Remediation
1. <fix>
2. <hardening>

## Remediation Verification
<how to confirm the fix>

## References
- <links>
```

---

## Evidence Standards

For each PoC/finding, prefer including:

- **PCAP** when network behavior matters (MITM, SSRF, exploit delivery)
- **Before/after diffs** (request/response, file hashes, config diffs)
- **Minimal sensitive data**: do not store real credentials/PII; use test data

If logs might contain secrets, store sanitized copies and document sanitization method.

---

## Severity Guidance

Use CVSS when applicable. Otherwise use:

- **CRITICAL**: trivial exploitation + high impact (RCE, auth bypass, data exfil)
- **HIGH**: reliable exploitation + significant impact
- **MEDIUM**: exploitation requires conditions / partial impact
- **LOW**: limited impact or difficult exploitation
- **INFO**: informational / hardening recommendation

---

## “Report-First” Prompts (Copy/Paste)

### Finding + PoC + Detection pack

```
Context: Security Research Lab (docs 00–20).
Produce a professional finding report (format F-XXX), plus a lab-contained PoC and detection pack.
Everything must be reproducible with an evidence index (pcap/log/diff).
Save under reports/<date>-<name>/.
```

### Detection pack only

```
Context: Security Research Lab.
Build a detection pack (Sigma/Suricata/Zeek) for this technique, including validation plan + triage notes.
Save under reports/<date>-<name>/detection/ and evidence under reports/<date>-<name>/evidence/.
```

---

**Next: `12_ENGAGEMENT_OPSEC_WORKFLOW.md`**

