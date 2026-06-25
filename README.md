# CodeInspectus, by Synvoya

**A local-first, privacy-preserving security MCP server.** Any AI coding agent
(Claude Code, Cursor, Codex, Windsurf, Cline, Aider) can invoke CodeInspectus to
scan AI-generated / "vibe-coded" code for real vulnerabilities, map findings to
compliance frameworks as honest code-level coverage, and drive a **scan → fix →
rescan** loop — fully on your machine, with **no account** and **zero network
egress at scan time**.

CodeInspectus orchestrates three best-in-class OSS engines behind one normalized,
CWE-keyed schema, and adds its own **AI-code-specific checks** that generic
scanners miss:

- **Opengrep** — SAST / OWASP Top 10 (SARIF)
- **Gitleaks** — secrets
- **Trivy** — dependency CVEs (SCA), IaC misconfig, secrets, license, SBOM
- **CodeInspectus AI checks** — client-side secret/bundle exposure, Supabase
  RLS / inverted-auth (the CVE-2025-48757 class), and prompt-injection sinks

> CodeInspectus bundles the official, **SHA-pinned** engine binaries and calls
> them as local subprocesses. It does **not** fork them.

## Install

```bash
# Register once per machine with your agent (see "Client registration"), then:
npx codeinspectus install-engines
```

`install-engines` is the **only** step that touches the network. It downloads the
engine binaries from their verified GitHub release URLs, checks the publisher
signature/checksum, computes each binary's SHA256, and records it in
`engines.lock.json`. It also fetches the offline Trivy vulnerability-DB snapshot
into `~/.codeinspectus/`. After this, **scans perform zero network I/O.**

Re-verify your pinned binaries any time:

```bash
npx codeinspectus verify-engines
```

An MCP server is installed **once per machine** and shared across all your
projects — it is **not** a per-repo `npm install` dependency.

## Client registration

Same JSON shape everywhere; only the location differs.

```jsonc
{
  "mcpServers": {
    "codeinspectus": { "command": "npx", "args": ["-y", "codeinspectus"] }
  }
}
```

| Client | How |
|--------|-----|
| **Claude Code** | `claude mcp add-json codeinspectus '{"command":"npx","args":["-y","codeinspectus"]}'` |
| **Cursor** | add to `~/.cursor/mcp.json` (or project `.cursor/mcp.json`) |
| **VS Code** | `code --add-mcp '{"name":"codeinspectus","command":"npx","args":["-y","codeinspectus"]}'` |
| **Codex / Windsurf / Cline / Aider** | add the same block to that client's MCP config |

Optional: drop in the ready-made [`agent-rules/`](agent-rules/) so your agent
auto-runs the scan → fix → rescan loop.

## Tools

| Tool | Purpose |
|------|---------|
| `codeinspectus_scan` | Full local scan of a path (engines + AI checks). Returns CWE-keyed findings, remediations, framework tags. |
| `codeinspectus_rescan` | Re-scan after fixes; diffs vs a prior scan → resolved / remaining / introduced. |
| `codeinspectus_compliance_report` | Per-framework **code-level control coverage** (not certification). |
| `codeinspectus_explain_finding` | Deep explanation + full remediation for one finding. |
| `codeinspectus_generate_sbom` | CycloneDX/SPDX SBOM (written to the managed dir by default). |
| `codeinspectus_list_rules` | Active detectors, engine versions, detection-DB + Trivy-DB freshness. |

All tools are **read-only** — CodeInspectus reads and reports; it never writes to
or deletes your files. Your agent applies the fixes.

## Honest claims (please read)

- **"No egress" is precise: zero egress _at scan time_.** Engine binaries and the
  initial Trivy DB are fetched _at install time_ from verified sources, with
  SHA256 verification. The scanner functions with the network unplugged. There is
  **no telemetry, ever.**
- **Supply-chain pinning is mandatory.** Trivy was supply-chain-compromised twice
  in early 2026; every engine binary is SHA-pinned in `engines.lock.json` and its
  hash is verified before execution. CodeInspectus refuses to run an unpinned or
  mismatched binary.
- **Secret values are redacted** in all output — type + location + a redacted
  preview only.
- **Compliance = code-level control coverage, never certification.** CodeInspectus
  reports "X of N **code-visible** controls have findings", with the code-visible
  subset as the explicit denominator, plus a standing disclaimer. It never emits
  "you are X% compliant" or "you pass [framework]". The severity-weighted posture
  score is a separate view and is not a percent-compliant figure. **Essential
  Eight** especially: only ~1 of 8 mitigations (Patch Applications) is
  code-evidenced — this is **not** an Essential Eight assessment.
- **Prompt-injection detection is heuristic and immature** — those findings are
  worded "potential …" and marked medium confidence.

## Compliance frameworks (code-visible subset)

NIST CSF 2.0 · ISO/IEC 27001:2022 · SOC 2 · CIS Controls v8.1 · Essential Eight
(Patch Applications only) · OWASP Top 10 (2021) · OWASP LLM Top 10 (2025).
MITRE ATT&CK techniques are shown as related-adversary context only, never as a
coverage score.

> **Compliance mappings are AI-drafted, reviewed by a cybersecurity practitioner
> (Synvoya) — code-level coverage only, not an audit or certification. Community review
> welcome.** The CWE→control mappings are self-audited with per-mapping confidence and an
> open community-verification process — see
> [`docs/COMPLIANCE-RATIONALE.md`](docs/COMPLIANCE-RATIONALE.md) and
> [`CONTRIBUTING.md`](CONTRIBUTING.md). Essential Eight is **not** a coverage view: only
> Patch Applications is code-evidenced (~1 of 8) — this is not an Essential Eight assessment.

## How it works

```
agent → codeinspectus_scan → [Opengrep | Gitleaks | Trivy] + AI checks
      → SARIF normalize → dedup (incl. Trivy⨯Gitleaks secret overlap)
      → CWE-keyed findings → compliance map → compact JSON + summary
ALL LOCAL. NO NETWORK EGRESS AT SCAN TIME.
```

## Trademark

"CodeInspectus" is the name of this free, open-source project (npm `codeinspectus`,
`codeinspectus.com`). "Code Inspect" is a descriptive phrase in a crowded namespace;
registry availability is not trademark clearance, and the name is **not claimed as a
trademark**.

## Development

```bash
npm install
npm run build      # tsc --noEmit && tsup  (must compile clean)
npm run eval       # ≥10 evals against fixtures/vulnerable-app
npm run inspector  # npx @modelcontextprotocol/inspector node dist/index.js
```

## Contributing

CodeInspectus is a **solo, free, open-source** project, built and maintained by
one cybersecurity practitioner under the **Synvoya** name. There is no company
behind it and nothing to sell — which is exactly why outside eyes matter.
**Independent review is genuinely wanted**, not a courtesy line. If you work in
security, your scrutiny is the contribution.

Two areas where review helps most:

- **Compliance CWE→control mappings.** These are **AI-drafted, then policy-reviewed
  by the maintainer** — they are **NOT independently verified.** Every mapping is
  tracked through three explicit states: **AI-drafted → maintainer-policy-reviewed →
  community-verified.** Today almost everything sits in the first two; the
  community-verified count is ~0, and that is reported honestly rather than hidden.
  Moving a mapping to *community-verified* takes evidence (a quote from the control's
  primary source + your basis) — the bar and process are in
  [`CONTRIBUTING.md`](CONTRIBUTING.md); the per-mapping rationale and confidence live
  in [`docs/COMPLIANCE-RATIONALE.md`](docs/COMPLIANCE-RATIONALE.md).
- **Detection rules** (`detection-db/**`, `src/ai-checks/**`). New rules, precision
  fixes, and false-positive reports are all welcome. The merge bar is **precision**:
  a fixture proving the true positive, and a near-miss fixture proving the rule does
  **not** over-fire. Details in [`CONTRIBUTING.md`](CONTRIBUTING.md).

What CodeInspectus claims — and what it deliberately does **not** — is written down so
you can check it before trusting a number: the standing compliance disclaimer (in the
[Compliance frameworks](#compliance-frameworks-code-visible-subset) section above and in
[`docs/COMPLIANCE-RATIONALE.md`](docs/COMPLIANCE-RATIONALE.md)) and the three-state
honesty metric. If something reads as over-claiming, that is a bug — please open an issue.

Workflow: **fork → branch → PR**; the maintainer reviews and merges (external
contributors don't push directly). — *Synvoya (the maintainer, a cybersecurity
practitioner)*

## Licenses

CodeInspectus: MIT. Bundled engines: Opengrep (LGPL-2.1), Gitleaks (MIT, CLI
only), Trivy (Apache-2.0) — all permissive for bundling the compiled binaries.
