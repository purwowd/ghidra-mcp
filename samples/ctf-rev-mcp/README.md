# CTF reverse samples — Ghidra MCP smoke test

Two tiny arm64 macOS crackmes for verifying Ghidra MCP.

| Binary | Symbols | Password | Flag |
|--------|---------|----------|------|
| `bin/chal_symbols` | kept (`-g`, not stripped) | `hunter2` | `LAB{mcp_symbols_ok_arm64}` |
| `bin/chal_stripped` | stripped (`strip -x`) | `ghidra` | `LAB{mcp_stripped_ok_arm64}` |

## Build / verify locally

```bash
cd samples/ctf-rev-mcp
make
make check
```

## Import into Ghidra

1. `ghidraRun` → open/create a project.
2. Import `bin/chal_symbols` and `bin/chal_stripped`.
3. Open each in CodeBrowser (auto-analyze).
4. Confirm MCP listens on `http://127.0.0.1:8089`.

## MCP test prompts (AI backends)

Use the shared pack (preferred): [`../../prompts/rev-mcp.md`](../../prompts/rev-mcp.md)

Or launch:

```bash
../../scripts/ghidra-lab.sh --agent
```

**Symbols binary** — names like `check_password` / `win`; plaintext strings exist.

**Stripped binary** — `FUN_*` names; XOR key `0x37`; no plaintext flag in `strings`.

## CLI sanity (without MCP)

```bash
./bin/chal_symbols hunter2
./bin/chal_stripped ghidra
```

Lab-only samples. Flags are intentionally in this README so you can score MCP answers.
