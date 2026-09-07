# RE-smoke-test_

Lab detonation report scaffold. Store **hashes only** in-repo; keep samples outside git.

## Sample

- SHA256: (fill)
- Path (VM only): (fill)
- Snapshot name: (fill)

## Phases

1. Snapshot VM
2. Start sinkhole: `cd /Users/topiputih/Developments/personal/ghidra-mcp/pocs/POC-DETONATION-LAB && docker compose up -d`
3. Copy sample into guest (shared folder / scp to lab VLAN)
4. Detonate under Procmon/Sysmon; capture PCAP on sinkhole
5. Collect drops → `dynamic/evidence/`
6. Revert snapshot
7. Static follow-up in Ghidra + MCP `malware_triage`

## ATT&CK

(fill after run)
