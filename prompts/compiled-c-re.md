# Compiled C/C++ RE — mechanism + Cursor Assist

Lab cookbook. Goal: analyze **binaries built from C/C++**, not recover the original `.c` tree.

## Mechanism (what actually happens)

```text
.c / .cpp  ──gcc/clang/MSVC──►  machine code (+ optional symbols / DWARF / PDB)
                                         │
                              Import into Ghidra + Auto Analysis
                                         │
                    disasm · functions · xrefs · decompiler (C-like)
                                         │
                         GhidraMCP (:8089)  ←── Cursor Agent / Assist
```

| Layer | Role |
|-------|------|
| Compiler | Turns source into ELF/PE/Mach-O; may strip names |
| Ghidra | Lifts bytes → assembly + **approximate C** via decompiler |
| MCP `c_binary_triage` | One-shot: format, stripped?, main, libc imports, decompile targets |
| Cursor Assist | Injects program/cursor context; agent calls MCP; you chat in CodeBrowser |

**You get:** recoverable logic, types you apply, renamed `FUN_*`, passwords/flags/IOCs.  
**You do not get:** original comments, macros, or exact variable names if the binary was stripped.

## Workflow (any of your own C builds)

1. Build as usual (`gcc -O0 -g` for easier RE; `-s` / strip for harder).
2. Import the binary into the lab Ghidra project → **Analyze**.
3. Window → **Cursor Assist**.
4. **Tools ▾ → C binary triage** (fills recipe + prints `c_binary_triage` JSON).
5. **Send** — agent should `decompile_function` on `decompile_first`.
6. Optional: **Save findings** / sync bookmarks.

With **Context** checked, Assist already sends `language`, `compiler`, `likely_stripped`, cursor function.

## Agent recipe (same as Assist **C RE** preset)

```text
Pakai MCP ghidra pada program yang sedang is_current.
Jangan baca source .c/.cpp dari disk / writeup online.

1) c_binary_triage
2) decompile_function on decompile_first
3) strings + xrefs to strcmp/printf when relevant
4) rename_function for understood FUN_*
5) sig_db_match apply=true if a symbolized sibling was seeded
6) technical summary only
```

## Symbols vs stripped

| Build | Expect |
|-------|--------|
| `-g`, not stripped | Named `main`, helpers; DWARF may enrich types |
| stripped (`-s`) | Mostly `FUN_*`; use libc imports + strings + size heuristics |
| Sibling pair | Seed `sig_db_add` on named binary → `sig_db_match` on stripped twin |

## Cursor Assist buttons

| Action | Use when |
|--------|----------|
| **C binary triage** | Default for any compiled C/C++ / unknown userland |
| **Malware triage** | PE/ELF with suspicious WinAPI / packer focus |
| **Prompt** (C RE) | Load the full agent recipe into the composer |

## Limits

- Heavy C++ (templates, RTTI-stripped) is harder than C — still use the same pipeline.
- Optimized (`-O2`) / LTO / obfuscation merge or destroy structure — expect more manual work.
- Kernel / firmware / custom ISA: Ghidra language support required first; MCP follows.

See also: `prompts/rev-mcp.md`, `prompts/ida-parity.md`, `prompts/windows-malware-lab.md`.
