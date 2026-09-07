# Detection Pack Template (Sigma / Suricata / Zeek / YARA)

Use this template when producing **blue-team deliverables** for a PoC or technique.

References:
- `ai_agent_instructions/10_DEFENSIVE_DETECTION_PROTOCOL.md`
- `ai_agent_instructions/11_REPORTING_STANDARD.md`

---

## Summary

- **Technique/PoC**: <name>
- **Scope**: <lab-only / targets>
- **Telemetry required**: <pcap, zeek logs, server logs, sysmon, etc.>

---

## Detection Plan

### Network telemetry
- <Zeek conn/http/dns fields>
- <Suricata EVE JSON fields>

### Host telemetry
- <Sysmon event IDs / auditd>

---

## Rules

### Suricata
- Path: `detection/suricata/rules.rules`
- SID range: use lab range (e.g. 1000000+)

### Sigma
- Path: `detection/sigma/rule.yml`
- Backend mapping notes: <Elastic/Splunk/Sentinel>

### Zeek (optional)
- Path: `detection/zeek/notice.zeek`

### YARA (optional)
- Path: `detection/yara/rule.yar`

---

## Validation

Create `evidence/validation.md` with:

- **PoC command**: exact CLI
- **Capture**: how pcap/logs were collected
- **Expected alerts**: which rule triggers and why
- **Negative control**: one benign run that should not trigger

---

## Triage Notes

- What the analyst should check first
- How to pivot (pcap → zeek → server logs → endpoint logs)
- False positive tuning suggestions

