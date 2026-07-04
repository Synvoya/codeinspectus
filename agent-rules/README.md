# CodeInspectus agent rules

Drop-in rules that make your AI coding agent run CodeInspectus's **scan → surface →
consent → fix → rescan** loop (PRD §12): the tool reports the findings, your agent
**surfaces them to you and asks before changing code**, and fixes only what you approve.
CodeInspectus never writes to your code or repo — it never edits or deletes your files; your agent applies any
fix, with your consent. Each scan also returns a read-only **git-safety advisory**: if you have
uncommitted work — or no git repo — your agent will offer, with your approval, to checkpoint first
so any fix can be rolled back cleanly (CodeInspectus itself never runs git). All clients use the
**same MCP server**; only the rule file location differs.

## 1. Register the MCP server (once per machine)

Identical JSON shape everywhere:

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
| Codex / Windsurf / Cline / Aider | that client's MCP config — same shape |

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
