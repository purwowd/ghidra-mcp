# 04 - Proof of Concept (PoC) Generation Protocol

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 2.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `03_OFFENSIVE_TOOL_POLICY.md`  
> **Companion**: `13_LAB_POC_STANDARD.md` (package/CLI contract used in this lab)

---

## Purpose

This document defines the protocol for generating **functional, reliable, and professional** Proof-of-Concept (PoC) code for discovered vulnerabilities. PoCs are critical for:

- Validating vulnerability existence
- Demonstrating impact to stakeholders
- Supporting responsible disclosure reports
- Enabling vendor reproduction and patching
- Training and educational purposes

---

## PoC Quality Tiers

### Tier 1: Minimal PoC (Quick Validation)

**When to use**: Initial vulnerability validation, quick checks.

```
Requirements:
├── Demonstrates the vulnerability exists
├── Single-file script
├── Minimal dependencies
├── Console output showing exploitation
└── < 100 lines of code
```

### Tier 2: Standard PoC (Disclosure-Ready)

**When to use**: Bug bounty reports, vendor notifications, internal reports.

```
Requirements:
├── Everything in Tier 1, plus:
├── Detailed documentation (description, impact, reproduction)
├── Error handling and edge cases
├── Configurable target parameters
├── Clean output with severity assessment
├── Remediation recommendations
└── 100-500 lines of code
```

### Tier 3: Full PoC (Research Publication)

**When to use**: CVE submissions, conference talks, research papers, blog posts.

```
Requirements:
├── Everything in Tier 2, plus:
├── Complete exploit chain demonstration
├── Multiple exploitation scenarios
├── Detection signatures (YARA, Sigma, Snort)
├── Detailed technical writeup
├── Patch analysis / remediation verification
├── Video or screenshot evidence
└── 500+ lines of code with supporting materials
```

---

## PoC Structure Template

Every PoC in this lab should follow the golden layout (see also `13_LAB_POC_STANDARD.md`):

```
pocs/<CVE-or-name>/
├── README.md              # Vulnerability description, impact, reproduction
├── poc.py                 # Main PoC (--mode check|exploit|full)
├── requirements.txt
├── payloads/              # Optional gadget/source templates
├── evidence/              # Runtime evidence (pcap, logs, diffs)
└── vulnerable-app/        # Strongly preferred local harness
    ├── Dockerfile
    ├── docker-compose.yml
    ├── README.md
    └── <app sources>
```

Scaffold with `python scripts/new_poc.py CVE-YYYY-XXXXX --name "..."`.

Optional Tier 3 extras: `detection/`, `remediation/`, generated `--report` Markdown.
---

## PoC Code Protocol

### Step 1: Vulnerability Analysis

Before writing the PoC, document:

```markdown
## Vulnerability Summary

- **Name**: [Vulnerability name]
- **CVE**: [CVE-YYYY-XXXXX or N/A]
- **Type**: [CWE classification]
- **Severity**: [CRITICAL/HIGH/MEDIUM/LOW] (CVSS: X.X)
- **Affected**: [Software name, versions]
- **Vector**: [Network/Local/Adjacent/Physical]
- **Authentication**: [Required/Not Required]
- **Impact**: [Confidentiality/Integrity/Availability]
```

### Step 2: Environment Setup

Document the exact environment needed:

```markdown
## Environment

- **Target**: [Software + version]
- **OS**: [Operating system]
- **Dependencies**: [Required tools/libraries]
- **Network**: [Network configuration if relevant]
- **Setup Steps**:
  1. [Step 1]
  2. [Step 2]
  ...
```

### Step 3: PoC Implementation

Follow the template in `templates/poc_template.py`. Key requirements:

```python
class ProofOfConcept:
    """Standard PoC class structure."""
    
    def __init__(self, target, options=None):
        """Initialize with target and options."""
        self.target = target
        self.options = options or {}
        self.results = []
    
    def check(self) -> bool:
        """
        Non-destructive check if the target is vulnerable.
        Returns True if vulnerable, False otherwise.
        This should NOT exploit the vulnerability.
        """
        pass
    
    def exploit(self) -> dict:
        """
        Demonstrate the vulnerability exploitation.
        Returns a dict with exploitation results.
        """
        pass
    
    def verify(self) -> bool:
        """
        Verify that exploitation was successful.
        Returns True if exploitation succeeded.
        """
        pass
    
    def cleanup(self):
        """
        Clean up any artifacts from exploitation.
        Restore target to pre-exploitation state.
        """
        pass
    
    def report(self) -> str:
        """
        Generate a human-readable report of findings.
        """
        pass
```

### Step 4: Output Format

PoC output should clearly demonstrate the vulnerability:

```
[*] PoC: CVE-YYYY-XXXXX - [Vulnerability Name]
[*] Target: https://target.example.com
[*] Date: 2026-02-08T10:30:00Z
[*] ─────────────────────────────────────────
[*] Phase 1: Checking vulnerability...
[+] Target appears vulnerable (version X.Y.Z detected)
[*] Phase 2: Exploiting...
[+] Payload delivered successfully
[+] Response indicates code execution
[*] Phase 3: Verifying...
[+] Exploitation confirmed - [evidence]
[*] ─────────────────────────────────────────
[*] Result: VULNERABLE
[*] Impact: [Description of what an attacker could achieve]
[*] CVSS: X.X (SEVERITY)
[*] Remediation: [Brief fix recommendation]
```

---

## Output Symbols Convention

| Symbol | Meaning |
|--------|---------|
| `[*]` | Informational message |
| `[+]` | Success / positive result |
| `[-]` | Failure / negative result |
| `[!]` | Warning / important notice |
| `[>]` | Action being performed |
| `[<]` | Response received |
| `[?]` | Requires user input |

---

## PoC Types by Vulnerability Class

### Web Application Vulnerabilities

| Vulnerability | PoC Approach |
|--------------|-------------|
| **SQL Injection** | Extract DB version/user, demonstrate data access |
| **XSS** | Execute `alert(document.domain)` or steal mock cookie |
| **SSRF** | Hit internal service, read cloud metadata |
| **RCE** | Execute `id`/`whoami`, demonstrate command execution |
| **Auth Bypass** | Access protected resource without valid credentials |
| **IDOR** | Access another user's data with manipulated reference |
| **File Upload** | Upload and execute a web shell or read system file |
| **Deserialization** | Achieve code execution through crafted object |

### Binary/Memory Vulnerabilities

| Vulnerability | PoC Approach |
|--------------|-------------|
| **Buffer Overflow** | Demonstrate EIP/RIP control, achieve code execution |
| **Format String** | Read stack values, write to arbitrary address |
| **Use-After-Free** | Demonstrate corrupted object access |
| **Integer Overflow** | Trigger unexpected behavior through integer wrapping |
| **Race Condition** | Demonstrate TOCTOU or double-fetch exploitation |

### Network Vulnerabilities

| Vulnerability | PoC Approach |
|--------------|-------------|
| **Protocol Flaw** | Demonstrate protocol-level exploitation |
| **MITM** | Intercept and modify traffic in transit |
| **DoS** | Demonstrate resource exhaustion (controlled) |
| **DNS Attacks** | Cache poisoning, zone transfer, rebinding |

---

## MITM / Intercept PoC (Real Lab Case Standard)

MITM and interception PoCs must be **lab-contained** and **single-target** by default. The goal is to
produce a reproducible, real-case demonstration with strong evidence (pcap/logs) without expanding scope.

### Required Deliverables (Tier 2 baseline)

- **Harness**: local Docker/VM topology that can be spun up offline
- **PoC tool**: script with lifecycle `check → intercept → modify → verify → cleanup`
- **Evidence**:
  - `evidence/traffic.pcapng` (or a capture command + log showing packets were captured)
  - `evidence/before_after.txt` (request/response diffs or hashes)
  - optional `evidence/mitmproxy_dump.flow` / `evidence/sslkeylog.log` where applicable
- **Safety gating**:
  - explicit `--confirm-lab-scope` (and for WiFi/RF transmit: `--faraday-cage-confirmed`)
  - built-in scope enforcement: allowed CIDR / allowed interface / allowlist of target IPs

### Suggested PoC Directory Layout

```
pocs/POC-MITM-<name>/
├── README.md
├── poc.py
├── requirements.txt
├── docker-compose.yml
├── harness/
│   ├── victim/        # client container (curl/browser/agent)
│   ├── target/        # server container (HTTP/HTTPS/API)
│   └── router/        # attacker/mitm container (iptables + proxy)
└── evidence/
    ├── traffic.pcapng
    ├── before_after.txt
    └── run.log
```

### Verification Guidance (What counts as "real-case")

Pick one (or more) of these verifiable outcomes:

- **Integrity impact**: modified HTTP response body (e.g., injected header/value), with before/after evidence
- **Credential exposure (test creds only)**: captured Basic auth / session cookie from victim to target in lab harness
- **Downgrade**: HTTPS → HTTP downgrade inside harness, with explicit proof in pcap and logs
- **Protocol manipulation**: modified DNS response, modified API payload, or replayed token in harness

### Default Technology Choices (Prefer)

- **Traffic capture**: `tcpdump` in the attacker container (or `pyshark`/`scapy` in Python)
- **HTTP MITM**: `mitmproxy` for intercept/modify with an inline script
- **L2 MITM (wired lab)**: `scapy` ARP spoof (single victim/target pair, restore ARP in cleanup)
- **Routing**: Docker network + `iptables` for transparent proxying (only inside the harness)

---

## Reliability Requirements

PoCs must be:

1. **Reproducible** — Works consistently when following the setup instructions
2. **Targeted** — Only affects the intended target, no collateral damage
3. **Documented** — Clear explanation of every step
4. **Configurable** — Target, ports, paths, payloads are parameterized
5. **Safe-by-default** — `--mode check` (non-exploiting) is the CLI default; see `13_LAB_POC_STANDARD.md`
6. **Harness when feasible** — local Docker target so validation does not depend on external systems

---

## Report Template

Every PoC should include a report capability:

```markdown
# Vulnerability Report: [CVE/Name]

## Executive Summary
[1-2 paragraph overview for non-technical stakeholders]

## Technical Details
### Description
[Detailed technical description]

### Root Cause
[Why this vulnerability exists]

### Attack Scenario
[Step-by-step exploitation path]

## Impact
[What an attacker can achieve]

## Proof of Concept
[Reference to PoC code and reproduction steps]

## Remediation
[Specific fix recommendations]

## Timeline
| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Vendor notified |
| YYYY-MM-DD | Vendor acknowledged |
| YYYY-MM-DD | Patch released |
| YYYY-MM-DD | Public disclosure |

## References
[CVE, CWE, related advisories, blog posts]
```

---

**Next: `05_EXPLOIT_DEVELOPMENT_GUIDE.md`**
