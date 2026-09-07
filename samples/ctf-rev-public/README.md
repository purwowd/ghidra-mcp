# Public reverse samples (picoCTF)

Downloaded from the official picoCTF artifact host for lab practice / Ghidra MCP.

## Inventory

| File | Challenge | Format | Notes |
|------|-----------|--------|-------|
| `bin/crackme100` | Classic Crackme 0x100 (2024) | ELF x86-64, not stripped | password mangler → recover input |
| `bin/packer.out` | Packer (2024) | ELF x86-64, **UPX-packed**, static | unpack then recover hex flag |

Both are **x86-64 Linux**. On Mac Mini (arm64): static RE in Ghidra is enough; to run use Linux VM / Docker `amd64` / `qemu-x86_64`.

---

## A) Classic Crackme 0x100 — `crackme100`

| Field | Value |
|-------|--------|
| Source | https://artifacts.picoctf.net/c_titan/83/crackme100 |
| SHA-256 | `bd1033793580012f9526e07f9be0c698df7e679a5c4268029b1d222abf9991f3` |

Local SUCCESS prints sample flag `picoCTF{sample_flag}`; password must be recovered from binary logic.

### Prompt

```text
Pakai MCP ghidra pada program crackme100.
Jangan cari writeup di internet dan jangan tebak dari sample flag saja.

1) list functions / cari main
2) decompile jalur cek password
3) jelaskan algoritma check-nya
4) recover password yang membuat jalur SUCCESS
5) laporkan password + ringkas cara recover
```

---

## B) Packer — `packer.out` (new)

| Field | Value |
|-------|--------|
| Source | https://artifacts.picoctf.net/c_titan/22/out |
| SHA-256 | `1a32bbc8bf32b7ae23259b705328b500b81a7637a7ef1b85f25420572fd4e831` |
| Packer | UPX 3.95 (`strings` shows `UPX!`) |

### Workflow hint

1. Confirm UPX (`strings packer.out | grep UPX`).
2. Unpack: copy first, then `upx -d packer.out` (or unpack to a new name).
3. In Ghidra: find main/entry, look for hex-encoded flag-like data, decode hex → ASCII.

### Prompt

```text
Pakai MCP ghidra pada program packer.out (yang is_current).
Jangan baca writeup online.

1) triage: packed? strings / segments
2) jika UPX: catat bukti, lalu analisis setelah unpack (atau minta user unpack dulu)
3) decompile entry/main
4) recover flag (sering hex-encoded di printf/string)
5) jawaban teknis singkat: flag + langkah
```

---

## Import ke Ghidra

1. Project `mcp-lab` → **File → Import File…**
2. Pilih `samples/ctf-rev-public/bin/packer.out` (atau `crackme100`)
3. Language **x86:LE:64:default** → OK → **Analyze**
4. Pastikan program itu = current di CodeBrowser

## Re-download

```bash
curl -fsSL -o samples/ctf-rev-public/bin/crackme100 \
  https://artifacts.picoctf.net/c_titan/83/crackme100
chmod +x samples/ctf-rev-public/bin/crackme100

curl -fsSL -o samples/ctf-rev-public/bin/packer.out \
  https://artifacts.picoctf.net/c_titan/22/out
chmod +x samples/ctf-rev-public/bin/packer.out

shasum -a 256 samples/ctf-rev-public/bin/*
```
