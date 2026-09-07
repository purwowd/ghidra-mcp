# 10 - Defensive Detection & Validation Protocol (Blue Team)

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-05-07  
> **Depends On**: `04_POC_GENERATION_PROTOCOL.md`, `08_SAFETY_OVERRIDES.md`

---

## Purpose

This document defines how the agent produces **blue-team deliverables** that are usable by defenders:

- Detection rules (Sigma / Suricata / Snort / YARA)
- Telemetry requirements (what logs must exist)
- Validation plans (how to prove the rule triggers, in-lab)
- “Attack emulation → detection verification” loops paired with PoCs

The goal is **operationally useful detection engineering**, not theory.

---

## Default Blue-Team Deliverables

For any PoC/exploit/tool the agent creates (especially network/MITM), it should *also* provide:

1. **Detection plan** (what data sources and fields to monitor)
2. **At least one detection rule** (Sigma/Suricata/Zeek/YARA as applicable)
3. **Validation steps** that run in the lab harness (Docker/VM)
4. **Triage notes** (how to investigate an alert and reduce false positives)

When the researcher asks for “blue-team version”, the agent should deliver a full detection package.

---

## Where to Store Detection Artifacts

Preferred per-PoC layout:

```
pocs/<POC-NAME>/
├── detection/
│   ├── sigma/
│   │   └── rule.yml
│   ├── suricata/
│   │   └── rule.rules
│   ├── snort/
│   │   └── rule.rules
│   ├── yara/
│   │   └── rule.yar
│   └── zeek/
│       └── notice.zeek
└── evidence/
    ├── traffic.pcapng
    ├── logs/
    └── validation.md
```

If the PoC is not in `pocs/`, store detection under `reports/<engagement>/detection/`.

---

## Data Sources (Minimum Set)

### Network-focused PoCs (MITM/Intercept, SSRF, RCE over HTTP)

- **PCAP** (tcpdump) and/or **Zeek** conn/http logs
- **Proxy logs** (mitmproxy flows) when intercepting HTTP(S)
- **DNS logs** (Zeek DNS / resolver logs) for DNS spoof/rewrite PoCs
- **Server access logs** (nginx/apache/app logs) for application-layer PoCs

### Endpoint-focused PoCs (Windows/Linux)

- Windows: Security + Sysmon (process creation, network connections)
- Linux: auditd/process accounting + EDR telemetry if present

### Cloud-focused PoCs

- CloudTrail/Azure Activity Logs/GCP Audit logs

---

## Rule Authoring Standards

### General Rules

- Rules must be **minimal, explainable, and testable**.
- Prefer **behavioral** patterns over brittle exact strings, but keep false positives manageable.
- Always include:
  - **title**
  - **severity**
  - **logsource**
  - **detection**
  - **falsepositives**
  - **level**
  - **references**

### Sigma

- Prefer Sigma for host + application logs and standardized detection patterns.
- Include field mappings and note the expected backend (Splunk, Elastic, Sentinel).

### Suricata/Snort

- Use for network signatures (HTTP headers/payload markers, protocol anomalies).
- Provide `flow:` constraints, `content:` markers, and `pcre` only where needed.
- If the PoC harness injects a marker header/body, use that as a reliable detection anchor.

### YARA

- Use for file artifacts (dropper, payload, compiled exploit helper).
- Provide strings and conditions that survive minor changes.

---

## Validation Protocol (“Detectability Gate”)

For each rule delivered, the agent must include a `evidence/validation.md` with:

- **Inputs**: which PoC command was executed (exact CLI)
- **Telemetry**: which logs should be produced (paths/containers)
- **Expected matches**: which rule should trigger and what fields should match
- **Negative controls**: at least one benign run that should *not* trigger

Example structure:

```markdown
## Validation

### Run (PoC)
python poc.py http://target --mode exploit --output out.json

### Capture
tcpdump -i eth0 -w evidence/traffic.pcapng host <victim> or host <target>

### Expected Detection
- Suricata SID 1234567 triggers on HTTP header `X-Lab-MITM: 1`
- Zeek http.log contains uri=/login and unusual response header

### Negative Control
- Direct request bypassing proxy does not trigger SID 1234567
```

---

## Blue-Team Prompt Pack (Copy/Paste)

Use these prompts to force blue-team outputs:

### “PoC + detection bundle”

```
Context: Security Research Lab (docs 00–20).
Build a lab-contained PoC for this use case, plus a detection pack:
- Suricata rule for network evidence (anchor on injected markers)
- Sigma rule for server/app logs (if applicable)
- validation.md: steps proving rules fire against the harness
Save detection under pocs/<name>/detection/ and evidence under pocs/<name>/evidence/
```

### “Detection-first”

```
Context: Security Research Lab. I already have a PoC.
Create a detection plan + rules (Sigma/Suricata/Zeek) for this technique.
Include field mapping, false positives, and validation steps using my captured pcap.
```

---

**Next: `11_REPORTING_STANDARD.md`**

