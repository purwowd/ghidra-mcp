# AI Agent Instructions — Index

Quick map for humans and agents. Read in order on first session; thereafter jump by task.

| Doc | Title | Use when |
|-----|-------|----------|
| **00** | Read This First | Session start / role |
| **01** | Authorization | Tier 1–3 scope |
| **02** | Legal Context | Disclosure / compliance |
| **03** | Offensive Tool Policy | Tool category guidelines |
| **04** | PoC Generation Protocol | PoC tiers & structure |
| **05** | Exploit Development Guide | Domain exploit checklists |
| **06** | Code Generation Framework | Language/style standards |
| **07** | Response Protocol | How to answer |
| **08** | Safety Overrides | STOP / ABORT / CLEANUP |
| **09** | Agent Workflow | Classification & quality gates |
| **10** | Defensive Detection | Sigma/Suricata/Zeek/YARA |
| **11** | Reporting Standard | Finding reports |
| **12** | Engagement OPSEC | Lab workflow red↔blue |
| **13** | Lab PoC Standard | **Full-attack PoC package contract** |
| **14** | Red Team Kill Chain | Multi-phase RT / ATT&CK |
| **15** | Vuln Research Methodology | Root cause / patch / variants |
| **16** | RE & Malware Analysis | Binary/sample lab analysis |
| **17** | C2 & Post-Ex Lab | Beacon / post-ex kits |
| **18** | Social Engineering Lab | Phishing / pretext (lab only) |
| **19** | Container & Kubernetes Lab | Escape / SA / RBAC labs |
| **20** | Horizon 2026–2031 | **5-year relevance tuning** (not timeless) |

> **Horizon policy:** Durable contracts live in `00–19`. Time-bounded bets & refresh cadence live in **`20`**. Next review due **2027-09-01**.

## Templates (`templates/`)

| File | Domain |
|------|--------|
| `base_template.py` | Generic tool base |
| `web_exploit_template.py` | Web vulns |
| `network_tool_template.py` | Network / protocol |
| `mobile_pentest_template.py` | Android/iOS |
| `rf_wireless_template.py` | RF / WiFi / cellular |
| `poc_template.py` | CVE/class PoC |
| `mitm_intercept_poc_template.py` | MITM + evidence |
| `ad_windows_lab_template.py` | AD / Windows path |
| `cloud_lab_template.py` | Cloud / IAM lab |
| `c2_lab_template.py` | HTTP teaching C2 (listener/agent/op) |
| `linux_privesc_lab_template.py` | Linux priv-esc enum/exploit |
| `binary_exploit_template.py` | Memory corruption / pwntools |
| `phishing_lab_template.py` | SE phishing landing |
| `k8s_container_lab_template.py` | Container / K8s enum |
| `recon_osint_template.py` | Scoped recon |
| `fuzzer_lab_template.py` | Mutation fuzzer scaffold |
| `ai_agent_security_lab_template.py` | LLM/agent security (horizon P0) |
| `detection_pack_template.md` | Detection pack |

## Reference full-path packages

| Package | Domain |
|---------|--------|
| `pocs/POC-SSRF-LAB/` | Web SSRF |
| `pocs/POC-CLOUD-IAM-LAB/` | Cloud IAM (`--backend mock\|localstack`) |
| `pocs/RT-AD-LAB/` | AD-style path (`--backend inprocess\|ldap`) |
| `pocs/CVE-2021-44228/`, `pocs/CVE-2025-55182/` | CVE PoCs + Docker harnesses |

## Language Policy

| Surface | Language |
|---------|----------|
| `ai_agent_instructions/` (`00`–`20`), templates, `.cursorrules` | **English** (canonical) |
| `README.md` example prompts | **English** |
| Chat with the agent | Match the researcher (Indonesian or English) |

Do not mix Indonesian into instruction docs or prompt-shape blocks.

## Explicitly Out of Core Templates (promote via doc 20)

Niche domains without dedicated templates until lab demand (see `20` P2 watchlist):
OT/ICS, automotive/CAN, hardware/firmware dumping, satellite, blockchain/smart contracts,
mainframe/SAP, physical red team, confidential computing, WASM edge.
