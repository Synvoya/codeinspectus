# Changelog

All notable changes to CodeInspectus are documented here. Versioning follows
[Semantic Versioning](https://semver.org). AI-code detections and compliance mappings are
AI-drafted and practitioner-reviewed — see the honesty notes in the [README](README.md).

## [0.3.2] — 2026-07-18

Correctness release for effective Supabase RLS state, secret-scan coverage honesty,
and cross-version rescan proof.

### Fixed
- **Superseded RLS policies are no longer reported as active.** Ordered migration
  sequences now reduce CREATE, ALTER, DROP, enable, and disable operations to final
  effective state. Earlier releases could report a policy that a later migration had
  dropped or safely replaced, and could miss some later final-state changes.
- **Rescan no longer treats detector changes as user fixes.** Every finding now records
  its producing detector components. A vanished finding is `resolved` only when those
  components are present with identical signatures; otherwise it is `not_rechecked`.
  The first rescan of a pre-0.3.2 scan is therefore conservative: present findings stay
  `remaining`, while vanished findings report that CodeInspectus cannot tell whether the
  user fixed them because the checks changed.
- **Target Gitleaks config can no longer silently replace bundled checks.** CodeInspectus
  always uses its bundled config and ignores target `.gitleaks.toml` files and inline
  `gitleaks:allow` comments, disclosing both behaviors in scan output.
- Machines whose Trivy DB predates 0.3.2 report vanished CVEs as `not_rechecked` until
  `install-engines` is run once to record DB provenance; scan output now surfaces this
  expected state and the next `install-engines` run self-heals it.

### Added
- **Component-scoped provenance.** Signatures cover the shared RLS reducer, independent
  AI analyzers, normalization pipeline, engine binaries, invocation flags, the Opengrep
  ruleset, bundled Gitleaks config, Trivy checks, and the Trivy vulnerability DB. Trivy
  DB content is hashed once at install time, never during an offline scan.
- **Secret-coverage status.** A target `.gitleaksignore` remains effective in Gitleaks
  8.30.1 and cannot be neutralized. CodeInspectus continues the useful portion of the
  secret scan but marks `secret_coverage: "unverified"` and warns that coverage is partial.

### Known limitations
- Both paths where final RLS state is off report `high`; sensitivity tiering is pending
  independent validation (CG-83).
- RLS reduction does not compose separate migration directories or standalone SQL
  snapshots, and does not model SQL larger than 2 MiB, dynamic SQL, or dashboard-only
  database changes.
- `.gitleaksignore` can still suppress individual Gitleaks findings. CodeInspectus detects
  and discloses the file but does not claim an unremovable secret-detection floor.

## [0.3.1] — 2026-07-16

Codex integration and cross-platform release hardening. No detection-rule
changes; the 35-rule detection set is unchanged.

### Added
- **MCP-level agent workflow instructions.** Clients now receive the recommended
  scan → explain → consent → fix → rescan workflow during initialization, including
  granular fix consent, git-safety guidance, secret-rotation reminders, and the rule
  that a finding is never called fixed until a rescan confirms it.
- **Native portability CI.** Windows x64, macOS Intel, and Linux ARM64 now build,
  run unit tests and the MCP transport smoke, install and verify the pinned engines,
  require all 17 evals to execute, run the redaction e2e, and scan the fixture app.

### Fixed
- **Windows SARIF paths.** Absolute paths emitted by Opengrep are now normalized
  against Windows backslash targets, so findings retain repository-relative file
  locations across every supported runtime.
- **Accurate Codex setup documentation.** Codex now uses its CLI command, settings
  UI, or `config.toml` instead of the Claude JSON example. The documented
  `tool_timeout_sec = 600` prevents Codex's 60-second default from ending legitimate
  large-repository scans early. Existing Claude setup remains unchanged.
- **GitHub Actions Node.js deprecation warnings.** Checkout, Node setup, and artifact
  actions now use immutable Node 24-based release SHAs. The retired `macos-13`
  Intel runner label is replaced with `macos-15-intel`.

### Internal
- The MCP stdio smoke now requires non-empty server instructions and checks that the
  critical consent/rescan guidance is present in the initialization handshake.

## [0.3.0] — 2026-07-12

Rescan now reports "resolved" only when it can prove it, plus honesty fixes to install docs and stored-scan handling.

### Changed
- **Rescan no longer over-claims "resolved."** A prior finding is reported resolved only when CodeInspectus can prove it was re-checked and is gone — the producing engine actually ran, results weren't truncated, and the original scan's scope was reproduced. When it can't confirm (an engine didn't run, results hit a limit, or the prior scan predates captured scope), the finding is reported as **`not_rechecked`** — an honest "couldn't confirm," never a false all-clear. A genuine fix still shows as resolved.
- **Severity threshold on rescan is now display-only.** It affects what's shown, not what's compared — so filtering to "medium and up" can no longer make a still-present lower-severity finding look resolved.

### Fixed
- Rescans could report a still-present finding as "resolved" when the re-scan used a narrower filter, an engine quietly didn't run, or a co-located secret's identity shifted between runs. All three paths are closed; rescan now matches findings on stable identity, not just a run-specific fingerprint.

### Docs
- Install prerequisites now stated up front: **Node.js 18+** and **cosign** on your PATH (cosign verifies the Opengrep and Trivy downloads; the install fails closed without it — Gitleaks needs none).
- Refined the write-scope wording from 0.2.0: CodeInspectus never edits or deletes your source code or repository; scan history and engines live under `~/.codeinspectus`, and an SBOM is written to a managed directory by default, or a path you choose.

### Internal
- Hardened stored-scan handling against path traversal and added validation of loaded scan files. Added continuous integration (build, tests, engine-verified evals) with dependency-pinned workflows. No change to what gets detected — the 35-rule detection set is unchanged.

### Known limitations (stated plainly)
- A rescan run with a smaller `max_findings` than the original may report some findings as `not_rechecked` rather than resolved — by design, so a truncated re-scan never produces a false all-clear.

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
