# Changelog

All notable changes to CodeInspectus are documented here. Versioning follows
[Semantic Versioning](https://semver.org). AI-code detections and compliance mappings are
AI-drafted and practitioner-reviewed — see the honesty notes in the [README](README.md).

## [0.2.1] — 2026-07-06

### Fixed
- Release provenance: 0.2.1 is published from the public repository, so the npm package's gitHead and the v0.2.1 git tag both resolve to a public commit. (0.1.0 and 0.2.0 were published from a private build repo; their gitHead values point at commits not reachable from this repository and cannot be retroactively corrected.)

### Added
- MCP Registry metadata: `mcpName` in package.json and a root `server.json`, making CodeInspectus installable/listable via the official Model Context Protocol registry.

No detection or scanner behavior changes in this release.

## [0.2.0] — 2026-07-04

### Added
- **New AI-code detection — client-writable `user_metadata` authorization** (`ci-ai-client-metadata-authz`;
  CWE-639; OWASP A01). Flags an authorization decision that trusts Supabase `user_metadata` — e.g.
  `if (user.user_metadata.role === 'admin')`, which any signed-in user can self-assign via `/auth/v1/user`.
  High severity, medium confidence; detects the inline form plus intrafile split-variable / destructured
  forms. Gate privileged logic on the server-only `app_metadata` instead.
- **New AI-code detection — unsanitized model/user output rendered as raw HTML** (`ci-ai-llm-output-dangerous-html`;
  CWE-79/CWE-116; OWASP A03 + LLM05). Flags untrusted request input **or LLM/model output** flowing into
  `dangerouslySetInnerHTML` without sanitization; a `DOMPurify.sanitize(...)` wrap silences it. Fills a React
  raw-HTML-sink gap the bundled Opengrep ruleset defers.
- Detection database now ships **35 rules** (was 33).

### Changed
- User-facing "read-only" claims reworded to the precise **"never writes to your code or repo."** The tool only
  ever writes to a managed dir outside your project (e.g. the optional SBOM), never to your repo.
- Detection-database version → `0.2.0` (2026-07-04).

### Fixed
- `codeinspectus_generate_sbom` now correctly advertises the MCP annotation **`readOnlyHint: false`** — it
  writes an SBOM file (to the managed dir by default). The other five tools remain read-only. Honesty-metadata
  correctness.
- README coverage notes corrected: client-writable `user_metadata` authorization is now **detected**
  (previously documented as "not yet detected").

### Known limitations (stated plainly)
- Both new AI-code rules are precision-gated against frozen fixture corpora (true-positive + false-positive
  cases) and are **validated synthetically** — real-world recall is not yet measured.
- `ci-ai-llm-output-dangerous-html` does **not** yet trace untrusted values arriving via component props,
  database rows, or template data (planned).

## [0.1.0] — 2026-06-21

### Added
- Initial release. Local-first, zero-egress security MCP server orchestrating **Opengrep** (SAST),
  **Gitleaks** (secrets), and **Trivy** (SCA / IaC / license / SBOM) behind one CWE-keyed schema, plus
  CodeInspectus **AI-code checks** (client-side secret/bundle exposure, Supabase RLS / inverted-auth,
  prompt-injection sinks). Compliance mapping as honest code-level control coverage. 33 detection rules.
