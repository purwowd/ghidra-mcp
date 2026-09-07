# 14 - Red Team Kill Chain & Lab Engagement Playbook

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `03_OFFENSIVE_TOOL_POLICY.md`, `12_ENGAGEMENT_OPSEC_WORKFLOW.md`, `13_LAB_POC_STANDARD.md`  
> **Companions**: `templates/ad_windows_lab_template.py`, `17_C2_POSTEX_LAB_STANDARD.md`

---

## Purpose

Give the agent a **complete red-team operator mental model** for lab engagements:
phase objectives, ATT&CK-aligned technique classes, required lab topology, evidence, and
deliverable shape — without relying on vague “build me red team stuff” prompts.

Default engagement style in this lab: **full attack path is packaged and reproducible**;
CLI may still default to `--mode check`, but every package must implement a working
`--mode exploit|full` path (see `13`).

---

## Kill Chain (Lab Mapping)

Align loosely to Lockheed + MITRE ATT&CK. Prefer ATT&CK technique IDs in reports.

```
RECON → WEAPONIZE/PREP → DELIVER → EXPLOIT → INSTALL → C2 → ACTIONS ON OBJECTIVES
   │         │              │         │         │       │            │
   └─ OSINT  └─ payload     └─ phish  └─ RCE    └─ drop └─ beacon    └─ lateral /
        /scan     /harness      /link     /auth      /persist           dump / exfil
```

| Phase | Lab objective | Typical evidence | Prefer package under |
|-------|---------------|------------------|----------------------|
| **Recon** | Map attack surface in-scope | JSON inventory, screenshots | `recon/`, `tools/` |
| **Weaponize** | Build payload/PoC + harness | build logs, hash of artifact | `payloads/`, `pocs/` |
| **Deliver** | Get payload to target (lab) | email lab log, USB mount log, HTTP access | `pocs/`, `exploits/` |
| **Exploit** | Gain code exec / auth bypass | command output, session cookie, token | `pocs/`, `exploits/` |
| **Install** | Optional persistence (opt-in) | autorun path, service name, cleanup script | `payloads/`, `scripts/` |
| **C2** | Lab callback channel | beacon log, JA3/pcap | see doc `17` |
| **Objectives** | Priv-esc, lateral, dump, exfil (lab data) | tickets, secrets markers, AD objects | AD/cloud templates |

---

## Phase Playbooks (What To Deliver)

### 1) Reconnaissance

**Must deliver when asked for recon tooling:**
- Scope gate (CIDR / domain allowlist)
- Rate limit + timeout
- Structured output (JSON)
- No destructive probes by default

**Technique classes:** port/service enum, web crawl/dirbrute, DNS/OSINT, cloud bucket enum (lab accounts only).

### 2) Initial Access / Delivery

Lab-safe delivery channels only:
- Local file / shared folder
- Lab phishing page + mailcatcher / MailHog
- Exploit against vulnerable harness (preferred for research)
- USB / ISO only in isolated VM topology

Never target real third-party users or production mail.

### 3) Execution / Exploitation

Follow `13_LAB_POC_STANDARD.md`:
- Harness when feasible
- `--mode full` implements complete attack
- Marker-based verify (`id`, token, injected header)

### 4) Persistence (Opt-In)

Only when researcher asks. Requirements:
- Explicit `--enable-persistence` (or equivalent)
- Document every artifact path
- `cleanup()` removes all artifacts
- Prefer user-land / lab-only mechanisms over firmware/bootkits

### 5) Privilege Escalation

Linux: SUID, sudo misconfig, kernel (lab kernel only), container escape (Docker socket lab).  
Windows: service abuse, token, UAC lab paths, misconfig (always lab VM).  
Always capture **before/after** privilege evidence (`whoami` / `id` / `whoami /priv`).

### 6) Credential Access & Lateral Movement

Prefer **lab AD / lab IdP**:
- AS-REP / Kerberoasting / NTLM relay (isolated VLAN)
- Pass-the-hash / ticket (lab hashes only)
- SSH key / cloud key abuse (synthetic keys)

Package with: domain FQDN, DC IP, test users, cleanup (purge tickets/sessions).

### 7) Collection / Exfiltration

Exfil **synthetic markers only** (e.g. `LAB_SECRET=...`).  
Channels: HTTP POST to lab listener, DNS label (lab DNS), SMB to lab share.  
Include size limits and no recursive home-dir theft by default.

---

## ATT&CK Coverage Expectations (Minimum Breadth)

When building a “full red team lab kit”, cover at least one technique per tactic below
(or explicitly mark N/A for engagement type):

| Tactic | Example lab techniques |
|--------|------------------------|
| Reconnaissance | T1595 Active Scanning |
| Resource Development | T1587 Develop Capabilities |
| Initial Access | T1190 Exploit Public-Facing; T1566 Phishing (lab) |
| Execution | T1059 Command/Scripting |
| Persistence | T1547 Boot/Logon (opt-in) |
| Privilege Escalation | T1068 Exploitation for PrivEsc |
| Defense Evasion | T1027 Obfuscated Files (lab AV) |
| Credential Access | T1558 Kerberos; T1003 OS Credential Dumping (lab) |
| Discovery | T1082 System Info |
| Lateral Movement | T1021 Remote Services |
| Collection | T1005 Data from Local System (markers) |
| C2 | T1071 Application Layer Protocol |
| Exfiltration | T1041 Exfil Over C2 |

Map techniques in `README.md` and optional detection pack (`10`).

---

## Recommended Lab Topologies

### A) Web / App Research
`attacker laptop` → `docker vulnerable-app` (+ optional `metadata` sidecar)

### B) Windows / AD
```
[Attacker Linux/Win]
      │
[Lab LAN]
      ├── DC01 (AD DS)
      ├── WS01 (domain workstation + Sysmon)
      └── optional: CA / File share
```
Use snapshot revert. Document domain: `lab.local`, users `attacker` / `victim` / `admin`.

### C) Cloud
LocalStack / Minikube / Terraform lab account with **non-prod billing alerts**.  
Never use personal cloud with real customer data.

### D) RF / Cellular
Faraday cage; `--faraday-cage-confirmed` for TX (`08`, RF template).

---

## Engagement Package Layout

```
pocs/RT-<ENGAGEMENT-or-TECH>/
├── README.md                 # objectives, ATT&CK map, topology, reproduce steps
├── scope.yml                 # allowlist CIDR/hosts/users
├── attack/
│   ├── 01_recon.py
│   ├── 02_initial_access.py  # or poc.py single-entry with --phase
│   ├── 03_privesc.py
│   └── 04_lateral.py
├── c2/                       # optional — see doc 17
├── vulnerable-app/ or vagrant/ or terraform/
├── detection/
├── evidence/
└── reports/
```

Single-technique engagements may stay as one `poc.py` (prefer for CVE research).
Multi-phase red team ops should use the layout above.

---

## Operator Defaults (This Lab)

1. **Reproduce-first**: Docker/Vagrant/Terraform bring-up in README ≤ 10 commands.
2. **Full path in package**: exploit/objectives implemented, not “check-only stubs”.
3. **Evidence or it didn’t happen**: JSON + marker strings.
4. **Cleanup is mandatory** for persistence, relay, firewall, ARP, scheduled tasks.
5. **Detection optional but preferred** for professional packs (`10` + template).
6. **One clarifying question max** if topology missing — then assume lab defaults above.

---

## Prompt Shape (Red Team)

```
Context: lab red team (docs 00–20). Topology: [AD / web / cloud].
Objective: [e.g. user → Domain Admin via Kerberoast + PSRemoting].
Deliverable: full attack package + harness/VM notes + evidence markers + cleanup.
ATT&CK map in README. Detection pack if host telemetry is available.
Save under: pocs/RT-<name>/
```

---

**Next:** `15_VULN_RESEARCH_METHODOLOGY.md`
