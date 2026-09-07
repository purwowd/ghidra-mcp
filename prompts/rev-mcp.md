# Ghidra MCP — copy-paste prompts

Prereq: CodeBrowser open on the target binary, `agent mcp list` → `ghidra: ready`.

---

## A. Symbols smoke test (`chal_symbols`)

```text
Pakai MCP ghidra pada program chal_symbols (yang terbuka / is_current).
Jangan baca file source di workspace.

1) list functions
2) decompile check_password dan win
3) ambil password dan flag
4) jawab singkat: password + flag saja di akhir
```

Expect: `hunter2` / `LAB{mcp_symbols_ok_arm64}`

---

## B. Stripped smoke test (`chal_stripped`)

```text
Pakai MCP ghidra pada program chal_stripped (yang terbuka / is_current).
Jangan baca file source di workspace.

1) list functions (harapkan FUN_*)
2) decompile main dan helper XOR/decode
3) cari key obfuscation, decode password + flag
4) jawab singkat: password + flag saja di akhir
```

Expect: `ghidra` / `LAB{mcp_stripped_ok_arm64}`

---

## C. Compiled C/C++ / generic binary (any program in Ghidra)

Preferred: see `prompts/compiled-c-re.md`. Assist: **Tools ▾ → C binary triage**.

For **Linux ELF / macOS Mach-O** “unpack + how it works”: `prompts/unix-elf-macho-re.md` · Assist **App flow**.

```text
Pakai MCP ghidra pada program yang sedang is_current.
Jangan baca source .c/.cpp dari disk.

1) program_flow_report   # unpack status + call/CFG flow
2) jika packed: unpack lalu re-import
3) decompile_function on flow_root + callees
4) jelaskan alur aplikasi per fase; Save findings
```

---

## D. Switch program reminder

Kalau MCP masih menganalisa binary lama:

```text
Panggil list_open_programs. Pakai program yang is_current=true
(atau yang saya sebut eksplisit). Jangan campur hasil antar program.
```

---

## E. Public picoCTF — Classic Crackme 0x100

Binary: `samples/ctf-rev-public/bin/crackme100` (ELF x86-64, not stripped).

```text
Pakai MCP ghidra pada program crackme100.
Jangan baca writeup online.

1) list functions, fokus main / check password
2) decompile logic perbandingan
3) recover password yang mengarah ke SUCCESS
4) jelaskan singkat algoritmanya + password hasil recover
```

Import notes: `samples/ctf-rev-public/README.md`

---

## F. Public picoCTF — Packer

Binary: `samples/ctf-rev-public/bin/packer.out` (ELF x86-64, UPX-packed).

```text
Pakai MCP ghidra pada program packer.out (yang is_current).
Jangan baca writeup online.

1) triage: packed? strings / segments
2) jika UPX: catat bukti; analisis setelah unpack (atau minta user unpack dulu)
3) decompile entry/main
4) recover flag (sering hex-encoded)
5) jawaban teknis singkat: flag + langkah
```

Import notes: `samples/ctf-rev-public/README.md`


```bash
# start lab + wait MCP
./scripts/ghidra-lab.sh

# start lab lalu langsung chat Agent (terminal)
./scripts/ghidra-lab.sh --agent

# cek saja (Ghidra sudah jalan)
./scripts/ghidra-lab.sh --no-launch

# in-Ghidra chat panel (Cursor Assist)
./scripts/build-cursor-assist.sh
# lalu Window → Cursor Assist di CodeBrowser
```

---

## IDA-parity tools

See `prompts/ida-parity.md` for patching, debugger, packer, sig DB, CFG/diff recipes.
