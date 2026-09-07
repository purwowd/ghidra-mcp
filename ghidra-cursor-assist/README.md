# Ghidra Cursor Assist

In-Ghidra chat panel that runs **Cursor Agent CLI** (`agent -p --force`) so you can talk without leaving CodeBrowser. Tools come from **GhidraMCP** on `:8089`.

## Requirements

- Ghidra 12.1.x + OpenJDK 21
- Cursor Agent CLI logged in (`~/.local/bin/agent`)
- GhidraMCP running (CodeBrowser open)
- Workspace with `.cursor/mcp.json` (this repo)

## Build / install

```bash
./scripts/build-cursor-assist.sh
```

Restart Ghidra → CodeBrowser → **File → Configure** → enable **GhidraCursorAssistPlugin** → **Window → Cursor Assist**.

## Panel features

- Compact header: MCP status **dot** + program name + **Context** / preset **Prompt** / **Tools ▾** / **New**
- **Tools** menu: Ping MCP, C binary triage, Malware triage, **Unpack / Detonation / Kernel**, Break WinAPI, Debug strcmp, Patch, Sync bookmarks, Save findings
- Presets: Symbols / Stripped / **C RE** (default for any other program)
- Composer (Send / Stop); thinking indicator while agent runs; status line truncates long text
- Clickable addresses in transcript → GoTo; dark transcript follows Ghidra theme
- Inject context (format, stripped?, cursor fn) + prior findings; markdown transcript; `--force`

## Settings

**Edit → Tool Options → Cursor Assist**

| Option | Default |
|--------|---------|
| Agent binary path | auto `~/.local/bin/agent` |
| Workspace directory | `~/Developments/personal/ghidra-mcp` |
| Model | (agent default) |
| Extra agent args | (optional) |
| GhidraMCP base URL | `http://127.0.0.1:8089` |
| Inject Ghidra context by default | true |

## Architecture

```
Cursor Assist panel
  → agent -p --approve-mcps --force --workspace …
  → GhidraMCP bridge → http://127.0.0.1:8089
```
