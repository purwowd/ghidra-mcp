# Ghidra + Cursor MCP — Mac Mini M4 (16 GB)

## Status

Installed and wired. MCP only answers while Ghidra GUI is running with CodeBrowser open.

| Component | Location / version |
|-----------|-------------------|
| OpenJDK 21 | `/opt/homebrew/opt/openjdk@21` |
| Ghidra | 12.1.3 (`brew install ghidra`) → `ghidraRun` |
| Heap | `GHIDRA_MAXMEM=4G` (safe default for 16 GB) |
| MCP plugin | GhidraMCP **7.0.0** in `mcp-server/` (bethington fork, Ghidra 12.x) |
| Cursor MCP | `~/.cursor/mcp.json` + `.cursor/mcp.json` |
| Bridge | `.venv/bin/bridge-mcp-ghidra` + `GHIDRA_MCP_URL=http://127.0.0.1:8089` |

## Start (recommended)

### macOS app (no terminal)

```bash
./scripts/install-ghidra-app.sh   # once → /Applications/Ghidra.app
```

Lalu buka **Ghidra** dari Applications / Spotlight / Dock.  
Icon: official Ghidra dragon (NSA repo). Auto-open `~/Ghidra/mcp-lab` bila ada.

Helper script (opens `~/Ghidra/mcp-lab`, waits for MCP, prints next steps):

```bash
cd ~/Developments/personal/ghidra-mcp
./scripts/ghidra-lab.sh          # start Ghidra + wait for :8089
./scripts/ghidra-lab.sh --agent  # same, then enter Cursor Agent chat
```

In Ghidra: double-click the target binary → Analyze if prompted.

Copy-paste prompts: [`prompts/rev-mcp.md`](prompts/rev-mcp.md)

Agent rules (no reading challenge `.c`): `.cursor/rules/ghidra-mcp-rev.mdc`  
Source/answer ignore: `.cursorignore`

### In-Ghidra chat (Cursor Assist)

Panel chat di CodeBrowser → Cursor Agent CLI + GhidraMCP:

```bash
./scripts/build-cursor-assist.sh   # build + install extension
```

Restart Ghidra → enable **GhidraCursorAssistPlugin** → **Window → Cursor Assist**.

Fitur panel: **Ping MCP**, preset prompts (Symbols/Stripped/Generic/Crackme100), markdown transcript, status tool MCP, filter noise stream-json, `--force` auto-approve tools.

Detail: [`ghidra-cursor-assist/README.md`](ghidra-cursor-assist/README.md)

Manual fallback:

```bash
source ~/.zshrc
ghidraRun ~/Ghidra/mcp-lab
agent mcp enable ghidra && agent mcp list
```

## 16 GB guidance

- Keep heap at **4G**. Use `6G` only for large binaries with little else open.
- One CodeBrowser + one program at a time is the sweet spot on this machine.
- After `brew upgrade ghidra`, re-check `JAVA_HOME` / `GHIDRA_MAXMEM` in `~/.zshrc`.

## Rebuild plugin

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
cd ~/Developments/personal/ghidra-mcp/mcp-server
python3 -m tools.setup build
python3 -m tools.setup deploy --ghidra-path /opt/homebrew/opt/ghidra/libexec
```
