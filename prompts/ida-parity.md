# IDA-parity cookbook (lab)

Agent-facing recipes for the tools added toward IDA Pro outcome parity.
Do **not** invent endpoints — call MCP tools by these names.

## Patching (IDA Edit → Patch program)

1. `read_memory` at target
2. `patch_bytes` with `hex` (e.g. `9090`) or `patch_assemble` (`NOP`, `JMP …`)
3. `list_patches` / `revert_patch`
4. `export_patched_file` with absolute `output_path`
5. Optional: `patch_file_offset` for offline notes

## Debugger

Requires CodeBrowser Debugger view active.

1. `debugger/launch_offers` → `debugger/launch`
2. `debugger/break_at_symbol` (`strcmp`, `main`, …) or `debugger/set_breakpoint`
3. `debugger/resume` → on break: `debugger/registers`, `debugger/read_memory`, `debugger/stack_trace`
4. Map: `debugger/static_to_dynamic` / `debugger/dynamic_to_static`

## Packer

1. `detect_packer`
2. Host: `./scripts/unpack-sample.sh path/to/binary` (UPX) or `./scripts/custom-unpack-lab.sh scaffold …`
3. OEP dump: `debugger/dump_memory_to_file` or Scylla in Windows lab
4. Optional static: `export_memory_block`
5. Re-import unpacked → Analyze → `compare_programs_by_hash`

## Detonation

- `detonation_playbook` + `./scripts/detonate-lab.sh full <label>`
- Sinkhole: `pocs/POC-DETONATION-LAB/docker-compose.yml`

## Kernel / driver

- `kernel_driver_triage` / `kernel_debug_playbook`
- Cookbook: `prompts/kernel-debug-lab.md`

## Signatures (local FLIRT/Lumina-like)

- DB: `~/.ghidra-mcp/function_sigs.json`
- `sig_db_add` on a named function
- `sig_db_match` (`apply=true` to rename auto `FUN_*`)

## Diff / CFG

- `compare_programs_by_hash` — program-level hash match
- `diff_functions` / `find_similar_functions_fuzzy` — deeper
- `get_cfg_slice` — blocks + edges for agent navigation

## Ghidra Assist

- Click `0x…` / `FUN_…` links in transcript → GoTo
- **Save findings** or auto-append on turn complete → `findings/<program>/findings.md`
- Prior findings injected when **Inject context** is on

## Compiled C/C++ triage

- `c_binary_triage` — format, stripped?, main/entry, libc imports, `decompile_first`
- Cookbook: `prompts/compiled-c-re.md`
- Ghidra Assist: **Tools ▾ → C binary triage**

## Linux / macOS flow (unpack + how it works)

- `program_flow_report` — packer/unpack + call graph + CFG summary + deliverable outline
- Cookbook: `prompts/unix-elf-macho-re.md`
- Ghidra Assist: **Tools ▾ → App flow**

## Emulation (already present)

- `emulate_function` for local path exploration without full debugger

## Seed signature DB

With `chal_symbols` (or any named binary) open and analyzed:

```bash
./scripts/seed-sig-db.py --program chal_symbols
# later, on a stripped twin:
./scripts/seed-sig-db.py --program chal_stripped --apply-match
```

## Windows malware

See `prompts/windows-malware-lab.md`.

