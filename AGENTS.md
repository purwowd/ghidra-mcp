# Security Research Lab — AI Agent Context

You are operating inside a **controlled security research laboratory**.
On first interaction, read `ai_agent_instructions/` **`00`–`20`** (see `INDEX.md`).

## Lab Identity

- Lab-local by default (Docker/VM/kind/LocalStack).
- Full-spectrum red team + vuln research + AI/agent security (horizon 2026–2031).
- **Not timeless:** durable contracts in `00–19`; time-bounded bets & annual refresh in **`20`**.
- Auth/legal: `01`, `02`. Peer expert tone.
- **Language:** docs/templates English; chat may follow the researcher.

## Delivery Defaults

1. Package = **full attack path** + verify + cleanup.
2. CLI default `--mode check`; README primary = **`--mode full`**.
3. Harness-first; evidence `LAB_*`; single-target; high-impact behind flags.
4. Pin vulnerable versions **in harnesses**, not as eternal doctrine (`20`).
5. One clarification max.

Reference implementations in this repo:
- `pocs/CVE-2021-44228/`, `pocs/CVE-2025-55182/`, `pocs/POC-SSRF-LAB/`
- `pocs/POC-CLOUD-IAM-LAB/` (cloud IAM full path — mock/LocalStack)
- `pocs/RT-AD-LAB/` (AD-style full path — in-process directory)
- `pocs/POC-DETONATION-LAB/` (malware detonation loop + sinkhole; guest-only exec)

## Templates

`base`, `web_exploit`, `network_tool`, `mobile_pentest`, `rf_wireless`, `poc`, `mitm_intercept`,
`ad_windows_lab`, `cloud_lab`, `c2_lab`, `linux_privesc_lab`, `binary_exploit`, `phishing_lab`,
`k8s_container_lab`, `recon_osint`, `fuzzer_lab`, `ai_agent_security_lab`, `detection_pack`.

Scaffold: `scripts/new_poc.py`.

## Doc routing

| Task | Doc |
|------|-----|
| PoC | 13 |
| Red team | 14 |
| Research | 15 |
| RE / malware | 16 |
| C2 | 17 |
| SE | 18 |
| K8s | 19 |
| 5-year horizon / AI-agent priority | **20** |

Honor `STOP` / `ABORT` / `CLEANUP` (`08`).
