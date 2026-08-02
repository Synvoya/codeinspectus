# Changelog

All notable changes to CodeInspectus are documented here. Versioning follows
[Semantic Versioning](https://semver.org). AI-code detections and compliance mappings are
AI-drafted and practitioner-reviewed — see the honesty notes in the [README](README.md).

## [2.1.0] — 2026-08-02

### Added
- `ci-ai-llm-output-dynamic-execution` follows recognized model output into JavaScript
  `eval`/`Function`, import-proven Node shell-string APIs, and import-proven Execa command-string
  APIs. The bounded intrafile rule includes a frozen 5-TP/7-safe corpus and explicit false-negative
  boundaries.
- `ci-ai-nextjs-admin-route-no-authz` checks conventional Pages Router and App Router admin API
  handlers for visible authentication plus a server-controlled role/permission decision. Supabase
  client-writable `user_metadata` is deliberately rejected as authorization evidence; the frozen
  corpus covers both router styles and safe/public near misses.
- The dangerous-HTML rule now follows one local destructured function-component prop hop into
  `dangerouslySetInnerHTML`, with sanitized/trusted/text-rendering precision cases.
- A release-on-published-GitHub-release workflow validates a GitHub-verified signed tag, runs the
  complete release gate, publishes with npm trusted publishing and provenance, and verifies the
  registry version plus SLSA attestation. Provider-side trusted-publisher/environment setup remains
  a prerequisite documented in `docs/RELEASE.md`.
- A V2.1 reproducible public-repository scan/fix/rescan script verifies two sealed evidence bundles.
  It defaults to `codeinspectus@2.1.0` and accepts an exact local tarball through
  `CODEINSPECTUS_CASE_PACKAGE` for pre-publication verification.

### Fixed
- The bounded JavaScript lexer now accepts valid regular-expression literals that begin with `=`,
  including `/=.*/s`, instead of misclassifying them as division assignment and making the full
  scan partial.
- CI now exercises the independent packed TypeScript SDK consumer and the macOS ARM64 platform
  row in addition to the existing platforms.

### Changed
- Package, MCP server, CLI, SDK API, MCP Registry manifest, and reference CI install versions are
  synchronized at `2.1.0`; existing V2 export/storage schema versions remain `2.0.0`.
- Detection database `1.15.0` contains 88 curated detections: 67 first-party native rules across
  16 packs, 18 Opengrep-owned SAST rules, and 3 Gitleaks rules. The JavaScript/TypeScript pack is
  `1.5.0` with 10 analyzers/24 rules; the aggregate native engine is `5.15.0`.

## [2.0.0] — 2026-07-30

### Added
- A first-class local CLI with offline `preflight`, current scans, JSON/SARIF/CSV export, explicit
  CI severity policy, stable exit statuses, and unchanged no-argument MCP stdio startup.
- Versioned aggregate coverage that fails closed for partial, unknown, excluded, unavailable,
  truncated, or not-rechecked work.
- Bounded scan history, arbitrary compatible comparison, append-only local triage, baselines, and
  new-finding enforcement without suppressing raw findings.
- Exact Git diff and working-tree scans with isolated snapshots, supporting repository context, and
  explicit changed/supporting/deleted/renamed/untracked coverage.
- Sealed local evidence bundles with versioned manifests and hash verification before export or
  comparison.
- A spreadsheet-safe CSV projection and the public `codeinspectus/sdk` ESM/type subpath, implemented
  as a bounded shell-free wrapper around the exact installed CLI.
- Resumable bounded scanning of existing local child repositories and explicit bounded immutable
  repository-history scanning. Neither workflow clones repositories or discovers remote accounts.
- Redacted review-only GitHub, Jira, and Linear issue payload adapters. No submission, authentication,
  destination lookup, or network client is included.
- Three shipped agent skills: approval-gated one-finding remediation, untrusted-document
  threat-model interpretation, and evidence-separated bounded multi-agent review.
- A SHA-pinned reference GitHub Actions policy workflow and a complete V2 CLI command reference.

### Changed
- Package, MCP server, CLI, SDK API, and MCP Registry manifest versions are synchronized at `2.0.0`.
- Agent-rule files are included in the npm artifact as well as the fail-closed public repository
  projection.
- The detection database remains `1.13.0`: 86 curated detections, including 65 first-party native
  rules across 16 packs. V2 expands workflow surfaces, not detection breadth.
- Node 22 remains the minimum supported runtime; Node 24 is the primary CI runtime.

### Security and compatibility
- Scans remain zero-egress and repository-read-only. Network access remains limited to explicit
  engine installation/repair and user-run external integrations outside the scanner.
- Existing six MCP tools and stored v1.x scan loading remain backward compatible.
- Output schemas are versioned independently from the npm package. V2 JSON export/storage use
  `2.0.0`; SARIF remains `2.1.0`; bounded workflow manifests use their documented `1.0.0` contracts.
- Optional agent interpretations never suppress, downgrade, override, or enter deterministic
  findings. Exact-prior deterministic rescan evidence remains required for scanner-resolution claims.
- The V2 workflow layer was independently implemented from public product concepts; see
  [workflow design provenance](docs/V2-WORKFLOW-PROVENANCE.md).

## [1.5.0] — 2026-07-29

### Added
- The Python AI/API pack now detects a proven LangChain `FAISS.load_local(...)` call with literal
  `allow_dangerous_deserialization=True` as `ci-python-faiss-dangerous-deserialization` (CWE-502).
  The rule resolves supported current and legacy LangChain imports without executing target code,
  fails closed on unresolved/dynamic/spread calls, and states that exploitability depends on the
  loaded artifact's origin and integrity.
- The Python AI/API pack now detects a complete URL derived from web request input and actually
  fetched by a proven LangChain `WebBaseLoader`. The rule requires exact current/legacy loader
  provenance plus a supported load method, and stays silent for fixed destinations, fixed-origin
  path composition, unused loaders, unresolved helpers, spreads, shadowed classes, and overwritten
  receivers.
- The Python AI/API pack now reports `ci-python-prompt-injection-sink` when framework-proven
  request input reaches OpenAI Responses `instructions` or Anthropic Messages `system`, or when
  request-controlled model input shares the same proven SDK call with configured tool access.
  Ordinary user/input content without tools stays silent; findings are explicitly heuristic at
  medium confidence, with tool-enabled calls raised to high severity.
- The frozen Python TP/FP/fixed corpus, direct analyzer tests, pack inventory, provenance,
  redaction, technology applicability, built-MCP eval, and same-path rescan contracts now cover
  all ten Python AI/API rules.
- The bounded Python lexer now uses Lezer's exact `FormatString` ranges to retain validated
  f-strings as opaque dynamic tokens. Calls inside replacement fields remain deliberately
  uninspected, while unrelated executable code in the same file is no longer discarded.
- Prompt-injection findings now use `CWE-1427` (improper neutralization of input used for LLM
  prompting) instead of the output-validation weakness `CWE-1426`, preventing compliance
  enrichment from incorrectly adding OWASP LLM05 to LLM01 prompt-injection findings.
- The JavaScript/TypeScript pack now reports `ci-ai-llm-tool-argument-command-execution` when
  model-produced tool/function arguments reach import-proven Node `child_process.exec` or
  `execSync` directly or through one local wrapper without a visible checked approval,
  allowlist, or validated replacement value. The bounded rule maps to CWE-78/CWE-1426 and
  OWASP LLM05/LLM06, with medium-confidence wording and explicit cross-module/runtime limits.
- A dedicated TP/FP/fixed corpus, public regression test, vulnerable-app MCP eval, provenance
  component, manifest ownership, explanation/remediation metadata, and pinned public positive
  and negative scans lock the unsafe tool-execution contract.
- The Python AI/API pack now reports `ci-python-llm-tool-argument-command-execution` for proven
  OpenAI/Anthropic tool arguments reaching `os.system`, other inherent shell APIs, or supported
  `subprocess` calls with literal `shell=True`, directly or through one named local wrapper.
  Checked approval/allowlist gates, schema-validated replacement values, `shell=False`, static
  commands, lookalikes, spreads, generic dispatch, and unsupported deeper/cross-module flows stay silent.
- A first-party Go AI pack adds `ci-go-llm-tool-argument-command-execution` for exact official
  OpenAI Go Chat Completions tool arguments reaching import-proven `os/exec` shell interpreters.
  The medium-confidence rule supports bounded direct aliases, JSON unmarshal, one local parser, and
  one local command wrapper; checked rejection/approval or allowlist guards and validated replacement
  values stay silent. TP/FP/fixed fixtures, direct-file parity, bounded loader tests, provenance,
  technology-gated dispatch, built-MCP E37/E38, and pinned public positive/negative scans lock the contract.
- A first-party Java AI pack adds `ci-java-llm-tool-argument-command-execution` for exact official
  OpenAI Java tool-call arguments reaching an actually-started recognized `ProcessBuilder` or
  `Runtime.getRuntime().exec` shell. The medium-confidence rule supports bounded direct aliases,
  one local parser, and one local command wrapper; checked rejection/approval or allowlist guards,
  validated replacements, non-started builders, and fixed executables stay silent. TP/FP/fixed
  fixtures, direct-file parity, bounded loader tests, provenance, technology-gated dispatch,
  built-MCP E39/E40, and pinned public positive/negative scans lock the contract.
- A first-party C# AI pack adds `ci-csharp-llm-tool-argument-command-execution` for exact official
  OpenAI .NET `ChatToolCall.FunctionArguments` reaching an actually-started recognized
  `System.Diagnostics.Process` shell. The medium-confidence rule supports bounded direct aliases,
  `System.Text.Json` dictionary/property extraction, one local parser, and one local command
  wrapper; checked rejection/approval or allowlist guards, validated replacements, non-started
  process configuration, and fixed executables stay silent. TP/FP/fixed fixtures, typed method-
  parameter flow, direct-file parity, bounded loader tests, provenance, language-gated dispatch,
  built-MCP E41/E42, and pinned public positive/negative scans lock the contract.
- A first-party PHP AI pack adds `ci-php-llm-tool-argument-command-execution` for exact
  community-maintained `openai-php/client` or `openai-php/laravel` Composer evidence and tool-call
  `function->arguments` reaching `exec`, `system`, `shell_exec`, or `passthru`. The
  medium-confidence rule supports direct aliases, associative `json_decode`, one local parser, one
  local command wrapper, and one exact mapped variadic method dispatch. Checked approval or
  full-command allowlists and validated replacements stay silent; first-token executable checks do
  not suppress shell-metacharacter risk. TP/FP/fixed fixtures, direct-file parity, bounded loader
  tests, provenance, language-gated dispatch, built-MCP E43/E44, and pinned public positive/negative
  scans lock the contract. The supported PHP clients are community maintained, not official OpenAI SDKs.
- A first-party Rust AI pack adds `ci-rust-llm-tool-argument-command-execution` for exact
  community-maintained `async-openai` Cargo evidence and model tool arguments reaching an
  import-proven standard/Tokio process shell or literal Bollard Docker exec shell vector. The
  medium-confidence rule supports direct aliases, `serde_json` extraction, one recognized
  `generate_function_call` result, and one local command wrapper; checked approval/allowlist
  rejection and validated replacements stay silent. TP/FP/fixed fixtures, multiline-string
  regression coverage, direct-file parity, bounded loader tests, provenance, language-gated
  dispatch, built-MCP E45/E46, and pinned public positive/negative scans lock the contract.
  `async-openai` is community maintained and is not represented as an official OpenAI SDK.
- A first-party Ruby AI pack adds `ci-ruby-llm-tool-argument-command-execution` for exact official
  production `openai` Gemfile or runtime gemspec evidence and Chat tool-call or explicitly typed Responses function-tool arguments
  reaching `system`, `exec`, `IO.popen`, or import-proven Open3 shell execution. The
  medium-confidence rule supports direct aliases, `JSON.parse` command extraction, one local
  parser, and one local command wrapper; checked approval/full-command allowlists and validated
  replacements stay silent. TP/FP/fixed fixtures, string-decoy and heredoc fail-closed coverage,
  direct-file parity, bounded loader tests, provenance, language-gated dispatch, built-MCP E47/E48,
  lockfile-only/development-only exclusions, and a pinned public official-SDK safe-tool scan lock
  the contract.
- A first-party Firebase configuration pack adds `ci-firebase-firestore-public-write`,
  `ci-firebase-storage-public-write`, and `ci-firebase-realtime-database-public-write` for literal
  unconditional public writes in checked-in Security Rules. Public reads and non-literal
  conditions stay silent. The bounded no-follow parser masks Rules comments/strings, requires
  exact Firestore/Storage service declarations, parses Realtime Database rules as strict JSON, and
  never runs Firebase tooling or target code. TP/FP/fixed fixtures, technology gating, provenance,
  built-MCP E49/E50, and pinned public positive/precision scans lock the contract.
- A first-party GitHub Actions workflow pack adds
  `ci-github-actions-untrusted-expression-command` for direct documented attacker-controlled
  `github` context interpolation in `run`, and `ci-github-actions-pwn-request` for the exact
  `pull_request_target` plus untrusted checkout plus checked-out-code execution chain. The bounded
  no-follow YAML 1.2 parser reads only direct workflow files and never executes target code.
  Safe `env`/`with` indirection, normal `pull_request`, checkout without execution, and protected
  checkout v7 stay silent. TP/FP/fixed fixtures, technology gating, provenance, built-MCP E51/E52,
  and pinned public positive/precision scans lock the contract.

### Changed
- Detection database `1.13.0` contains **86 curated detections**: 65 first-party native rules,
  18 Opengrep-owned SAST rules, and 3 custom Gitleaks rules. The JavaScript/TypeScript pack is
  `1.3.0`, the Python AI/API pack is `1.4.0`, the Go AI pack is
  `1.0.0`, the Java AI pack is `1.0.0`, the C# AI pack is `1.0.0`, the PHP AI pack is `1.0.0`,
  the Rust AI pack is `1.0.0`, the Ruby AI pack is `1.0.0`, the Firebase pack is `1.0.0`, the
  GitHub Actions pack is `1.0.0`, and the aggregate native engine signature is `5.13.0`.
- Updated `@modelcontextprotocol/sdk` to `1.30.0` and its Hono adapter to `2.0.12`, removing the
  prior moderate audit findings. One low, development-server-only esbuild advisory remains; the
  affected development server is not used or shipped by CodeInspectus.

## [1.0.0] — 2026-07-27

### Added
- A static native detector-pack registry now owns **49 first-party rule IDs** across eight packs and
  29 independently failing analyzers. Existing AI/framework packs retain their scanner behavior.
- A fail-closed Opengrep reconciliation layer promotes the parity-proven JavaScript/TypeScript
  weak-hash and weak-cipher rules into a native SAST pack before routing and deduplication. Exact
  matches surface native-only provenance; Opengrep remains physically active and wins on reference-
  only or metadata-mismatch cases, while native-only candidates are suppressed. If Opengrep cannot
  run, the native implementation is the explicit fallback. Shadow parity remains a release gate.
- An additive Flutter/Dart pack contributes `ci-flutter-tls-verification-disabled`,
  `ci-flutter-sensitive-shared-preferences`, `ci-flutter-webview-untrusted-content`,
  `ci-flutter-sensitive-log`, `ci-flutter-supabase-privileged-key-client`, and
  `ci-flutter-cleartext-network`. These first-party structural checks run only when Flutter is
  detected and do not replace runtime mobile testing, the separate native platform configuration
  packs, or Pub vulnerability/SBOM analysis.
- Android and iOS configuration packs add eight first-party rules for explicit production
  debuggability, cleartext/user-CA policy, exported AndroidX FileProvider, ATS exceptions/TLS policy,
  and disabled iOS data protection. They use bounded structured repository parsing, never execute
  Gradle, Xcode, or target content, and report unsupported/dynamic inputs as coverage limitations.
- Separate React Native and Expo packs add six first-party structural rules for sensitive
  AsyncStorage writes, unsafe WebView content/origin settings, public Expo configuration secrets,
  and unsigned cleartext updates. They require explicit framework evidence, never execute target
  modules/configuration, and keep bare React Native coverage distinct from Expo coverage.
- A Python AI/API pack adds six high-confidence first-party rules for hardcoded framework signing secrets,
  credentialed all-origin CORS, request-controlled file responses, redirects, and template source,
  plus unsanitized OpenAI/Anthropic output returned as HTML. Bounded Lezer-gated, source-ordered
  intrafile analysis never imports or executes target code; unsupported syntax and project bounds
  fail closed with explicit pack-coverage notes.
- A separate first-party `codeinspectus-pub` engine now analyzes bounded `pubspec.lock` files under
  the `vuln` scanner class, independently of Trivy. It matches only exact affected versions from a
  bundled, provenance-recorded OSV Pub snapshot (11 active reviewed advisories across 10 packages
  at this release), rejects ambiguous lockfiles, excludes custom registries/Git/path/SDK packages,
  and reports explicit dependency coverage instead of treating skipped input as clean.
- Native Pub SBOM support generates CycloneDX 1.6 or SPDX 2.3 inventories, merges official Pub
  components additively into Trivy output, and falls back to a Pub-only document when Trivy is
  unavailable. It preserves lockfile hashes/directness/origin without inventing licenses,
  suppliers, or a dependency graph that `pubspec.lock` does not contain.
- Scan and rescan output now includes deterministic repository technology detection and explicit
  per-pack analyzer/rule execution coverage, including `not_applicable` for an installed pack that
  does not match detected technology. Stored scans from older versions remain loadable.
- `codeinspectus_list_rules` now exposes native-pack inventory and exact manifest-to-pack ownership,
  including user-visible scope limitations that prevent a `ran` state being read as full language
  coverage.
- Detection database `1.0.0` contains **70 curated detections**: 49 first-party native rules,
  18 Opengrep-owned SAST rules, and 3 custom Gitleaks rules. The two promoted native rules retain
  active Opengrep YAML fallbacks, so 20 YAML rules still execute. The aggregate native engine
  signature is `5.0.0`; the separate Pub engine is `1.0.0`, and the built MCP stdio eval suite
  contains 36 cases. Opengrep, Gitleaks, and Trivy remain installed.

### Fixed
- Authored Opengrep confidence metadata now takes precedence over the producer's generic SARIF
  precision, preventing medium-confidence rules from being silently upgraded to high. The weak-
  cipher wording now covers deprecated password-based `createCipher` as well as DES/3DES/RC4.
- Supabase Edge Function authentication analysis now runs for projects that commit Edge Function
  source without also committing Supabase SQL migrations. The SQL project gate remains scoped to
  RLS analysis, and dedicated true-positive/false-positive fixtures lock the behavior.
- Replaced a pathological API-boundary string-masking regular expression with a bounded linear
  scanner. On the pinned Mattermost Mobile checkout, the complete native scan fell from about 69
  seconds to 7-8 seconds without changing finding identities or native-pack coverage.

### Changed
- The supported runtime floor is Node.js 22, with Node 24 LTS as the primary CI/runtime target.
  Node 22 and 24 are tested separately; the production bundle now targets Node 22 instead of the
  end-of-life Node 18 line.

## [0.4.1] — 2026-07-26

### Added
- Offline `engine_setup` health in scan and list-rules output, with stable `ready`,
  `repair_required`, `db_refresh_recommended`, and `unsupported_platform` states.
- Incremental `repair-engines` command. It downloads only unhealthy engine artifacts, verifies
  them against immutable shipped pins, installs binaries atomically, refreshes stale/missing
  Trivy DB state, and serializes concurrent repairs with a per-machine lock.

### Changed
- End-user setup no longer rewrites the npm package's `engines.lock.json`; lockfile mutation is
  restricted to the maintainer-only `pin-engines` command. `install-engines` remains as a
  backward-compatible alias.
- MCP instructions require agents to explain partial coverage and obtain approval before launching
  a networked engine repair. No npm postinstall or scan-time download was added.
- CI now exercises offline health reporting, incremental repair, a real Trivy DB refresh, and
  immutable-lockfile enforcement. The manual maintainer workflow uses `pin-engines` explicitly.

### Fixed
- Long-running MCP processes invalidate cached engine verification when a repaired binary's file
  identity changes, so a successful repair is recognized without restarting the client.
- Binary and Trivy DB updates are staged and replaced atomically; interrupted repairs leave the
  last verified installation usable and clean stale repair locks safely.

## [0.4.0] — 2026-07-26

### Added
- **Project CI Enhancement 1:** four conservative JavaScript/TypeScript API-boundary
  detections for client-visible internal error details, explicit sensitive API-response
  fields, whole unvalidated request objects passed to Prisma/Supabase/Mongoose writes, and
  sensitive request data passed to logs. Each ships with dedicated component provenance,
  CWE plus OWASP Web/API mappings, remediation, redacted snippets, rescan continuity, and
  dual-direction precision fixtures.
- **Credentialed arbitrary-origin CORS detection** for `cors` middleware approval/reflection
  and direct allow-origin header reflection, with safe allowlist/pinned-origin fixtures.
- **Project CI Enhancement 2:** four evidence-gated configuration detections for security
  response headers explicitly disabled/neutralized, production CSP with bare wildcard or
  `'unsafe-eval'` script sources, auth/session cookies with explicitly insecure attributes,
  and Supabase CAPTCHA-enabled auth calls that omit `captchaToken`.
- **Three-state runtime-control evidence** on scan results:
  `verified_in_repository`, `insecure_configuration_found`, or
  `not_verifiable_from_repository`. Only explicit insecure repository configuration enters
  findings; missing/hosted/ambiguous controls remain metadata with no posture penalty.
- Literal configuration fixtures for Next.js last-match header ordering, Vercel, Helmet,
  nginx, Cloudflare Pages `_headers`, cross-layer conflicts,
  development/report-only CSP, cookie near misses, and Supabase hosted/disabled CAPTCHA.

### Changed
- Corrected the existing wildcard-plus-credentials CORS explanation: browsers reject
  credentialed response sharing for that invalid combination; it does not itself expose an
  authenticated response. Its severity is now medium, below the high-severity arbitrary-origin
  credential exposure rule.
- Extended credentialed-CORS precision to separately declared `cors` options while keeping
  realistic `indexOf`/allow-list callbacks silent.
- Hardened API-boundary source analysis against commented examples and minified vendor code;
  added Fastify response/request-log forms, Prisma transaction clients, and lowercase Mongoose
  `*Model` variables while keeping boolean-only sensitive-data presence logging silent.
- Corrected `ci-baseline-insecure-cookie` wording to its actual narrow behavior (explicit
  `httpOnly: false`); the new AI cookie rule covers `secure: false` and
  `SameSite=None` without `Secure`.
- Detection database `0.4.0` now contains **44 curated detections**: 21 AI analyzers,
  20 Opengrep SAST rules, and 3 custom Gitleaks rules. The CodeInspectus AI engine signature
  is `1.2.0`, and the eval suite now contains 21 cases.
- Refreshed permitted transitive patch versions for `fast-uri` and Hono before publication,
  clearing all high/critical advisories from the production dependency tree.

### Known limitations
- New API-boundary analysis is JavaScript/TypeScript source-only and intrafile; build output and
  minified vendor files are excluded. It intentionally prefers silence for ambiguous validation,
  business authorization, runtime middleware, and cross-file dataflow.
- Missing security headers, hosted CAPTCHA state, gateway rate limits, runtime overrides,
  and behavioral auth remain unverified. CodeInspectus reports these as
  `not_verifiable_from_repository`, never as vulnerabilities or proof of protection.

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
