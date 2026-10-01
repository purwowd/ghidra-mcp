# Linux / macOS binary RE — unpack + application flow

Lab cookbook for **ELF** (Linux) and **Mach-O** (macOS). Goal: deliverable = **unpacked (or confirmed not packed)** + **how the program works** (flow).

## Pipeline

```text
sample (ELF/Mach-O)
    │
    ├─ detect_packer / unpack-sample.sh
    │     UPX → unpacked file
    │     custom → lldb/gdb OEP dump (lab VM/container)
    │
    └─ Ghidra Analyze
          │
          ├─ program_flow_report   ← unpack status + call graph + CFG summary
          ├─ decompile_function   ← C-like logic of main + callees
          └─ Save findings        ← narrative "how it works"
```

## Expected output (what you hand back)

| Artifact | Source |
|----------|--------|
| Unpacked binary (or note “not packed”) | `./scripts/unpack-sample.sh` / custom dump |
| Identity | format, arch, stripped?, packer evidence |
| Flow | `program_flow_report` → root (`main`/`_start`) + callees |
| Logic | decompiler on root + key callees |
| Writeup | `findings/<program>/findings.md` phases of execution |

You recover **behavior**, not the original `.c` tree.

## Host commands

```bash
# 1) Unpack if UPX (ELF usually fine; Mach-O UPX flaky)
./scripts/unpack-sample.sh path/to/binary

# 2) Import unpacked into Ghidra → Analyze

# 3) Ghidra Assist → Tools ▾ → App flow
#    or agent: program_flow_report
```

## Agent / Assist recipe

```text
Pakai MCP ghidra pada program is_current.
1) program_flow_report
2) jika packed: unpack dulu, re-import, ulangi
3) decompile flow_root + callees penting
4) jelaskan alur aplikasi per fase (init → input → core → output/exit)
5) Save findings. Teknis saja.
```

## Linux-specific notes

- Entry often `_start` → `__libc_start_main` → `main` — flow root usually **`main`**
- Strip: mostly `FUN_*`; use strings + libc imports (`strcmp`, `read`, …)
- Custom packers: container/VM + `gdb`/`lldb` to OEP → dump → re-import

## macOS-specific notes

- Mach-O / dyld; entry may be `_main` or framework `*Main`
- UPX less reliable — prefer `custom-unpack-lab.sh` + lab debug if packed
- Don’t detonate unknown malware on the primary Mac — use VM/container

## Related

- `prompts/compiled-c-re.md` — C compile → decompile mechanism
- `prompts/windows-malware-lab.md` — PE / WinAPI path
- MCP: `c_binary_triage`, `get_cfg_slice`, `get_function_call_graph`
