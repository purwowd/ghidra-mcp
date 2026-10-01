# Ghidra Assist

In-Ghidra chat panel that runs **Cursor Agent CLI** (`agent -p --force`) or **DeepSeek**
(OpenAI-compatible function calling) so you can talk without leaving CodeBrowser. Tools come
from **GhidraMCP** on `:8089`.

## Requirements

- Ghidra 12.1.x + OpenJDK 21
- Cursor Agent CLI logged in (`~/.local/bin/agent`) — for the Cursor backend
- `DEEPSEEK_API_KEY` env var — for the DeepSeek backend (or set it in Tool Options)
- GhidraMCP running (CodeBrowser open)
- Workspace with `.cursor/mcp.json` (this repo)

## Build / install

```bash
./scripts/build-ghidra-assist.sh
```

Restart Ghidra → CodeBrowser → **File → Configure** → enable **GhidraAssistPlugin** → **Window → Ghidra Assist**.

## Panel features

- Compact header: MCP status **dot** + program name + **backend/model ▾** + **Context** / preset **Prompt** / **Tools ▾** / **New**
- **Backend ▾**: `Cursor` (default), `DeepSeek V4 Pro`, `DeepSeek Flash`
- **Tools** menu: Ping MCP, C binary triage, Malware triage, **Unpack / Detonation / Kernel**, Break WinAPI, Debug strcmp, Patch, Sync bookmarks, Save findings
- Presets: Symbols / Stripped / **C RE** (default for any other program)
- Composer (Send / Stop); thinking indicator while agent runs; status line truncates long text
- Clickable addresses in transcript → GoTo; dark transcript follows Ghidra theme
- Inject context (format, stripped?, cursor fn) + prior findings; markdown transcript; `--force`

## Settings

**Edit → Tool Options → Ghidra Assist**

| Option | Default |
|--------|---------|
| Agent binary path | auto `~/.local/bin/agent` |
| Workspace directory | `~/Developments/personal/ghidra-mcp` |
| Model | (agent default) |
| Extra agent args | (optional) |
| GhidraMCP base URL | `http://127.0.0.1:80
| DeepSeek API key | (empty → `DEEPSEEK_API_KEY` env) |
| DeepSeek base URL | `https://api.deepseek.com` |
| DeepSeek V4 Pro model id | `deepseek-v4-pro` |
| DeepSeek Flash model id | `deepseek-flash` |

## Backends

- **Cursor** — launches `agent -p --approve-mcps --force` and streams its JSON output.
- **DeepSeek** — calls DeepSeek's OpenAI-compatible `/chat/completions` with function calling.
  Each function maps to a GhidraMCP HTTP endpoint discovered live from `/mcp/schema`, so the
  model drives the same tool surface as the Python bridge — no Cursor account required.
  Requires `DEEPSEEK_API_KEY` (or the Tool Options field).89` |
| Inject Ghidra context by default | true |

## Architecture

```
Ghidra Assist panel
  ├─ Cursor backend  → agent -p --approve-mcps --force --workspace … → GhidraMCP bridge (:8089)
  └─ DeepSeek backend → api.deepseek.com chat/completions (function calling)
                        → tool calls hit GhidraMCP HTTP endpoints (:8089, via /mcp/schema)
```
