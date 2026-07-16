# CodeInspectus agent rules

Drop-in rules that make your AI coding agent run CodeInspectus's **scan → surface →
consent → fix → rescan** loop (PRD §12): the tool reports the findings, your agent
**surfaces them to you and asks before changing code**, and fixes only what you approve.
CodeInspectus never edits or deletes your source code or repository — the only file it writes is an optional SBOM (to a managed directory by default, or a path you choose), and engine data + scan history stay under `~/.codeinspectus`; your agent applies any
fix, with your consent. Each scan also returns a read-only **git-safety advisory**: if you have
uncommitted work — or no git repo — your agent will offer, with your approval, to checkpoint first
so any fix can be rolled back cleanly (CodeInspectus itself never runs git). All clients use the
**same MCP server**; only the rule file location differs.

## 1. Register the MCP server (once per machine)

The server command is shared across clients, but the configuration format is
client-specific. JSON-based MCP clients use:

```jsonc
{
  "mcpServers": {
    "codeinspectus": { "command": "npx", "args": ["-y", "codeinspectus"] }
  }
}
```

| Client | Where |
|--------|-------|
| Claude Code | `claude mcp add-json codeinspectus '{"command":"npx","args":["-y","codeinspectus"]}'` |
| Cursor | `~/.cursor/mcp.json` (or project `.cursor/mcp.json`) |
| VS Code | `code --add-mcp '{"name":"codeinspectus","command":"npx","args":["-y","codeinspectus"]}'` |
| Codex | `codex mcp add codeinspectus -- npx -y codeinspectus`, or use Codex settings / TOML below |
| Windsurf / Cline / Aider | that client's JSON MCP configuration |

Codex can also be configured through **Settings → MCP servers → Add server**
(STDIO; command `npx`; arguments `-y`, `codeinspectus`) or with:

```toml
[mcp_servers.codeinspectus]
command = "npx"
args = ["-y", "codeinspectus"]
tool_timeout_sec = 600
```

Codex defaults MCP tool calls to 60 seconds. CodeInspectus allows each security
engine up to five minutes, so 600 seconds prevents premature client timeouts on
larger repositories. This Codex-only setting does not alter other clients.

First run: `npx codeinspectus install-engines` once to fetch + SHA-pin the engine
binaries and the offline Trivy DB (the only network step; install-time only).

## 2. Install the rule

| Client | File |
|--------|------|
| Claude Code | append `claude-code.md` to your project `CLAUDE.md` |
| Cursor | copy `cursor.mdc` to `.cursor/rules/codeinspectus.mdc` |
| Windsurf | append `windsurf.md` to `.windsurfrules` |
| Codex | append `codex-AGENTS.md` to your `AGENTS.md` |
| Cline | add `cline.md` to your Cline custom instructions |

You can also just say "use codeinspectus to check my code" — it resolves to the
same `codeinspectus_scan` tool.
