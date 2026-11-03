# Verify — what "done" means for CodeInspectus

Run these before claiming work complete.

## Supported Node runtimes

- Minimum supported runtime: Node 22.
- Primary development and CI runtime: Node 24 LTS (`.nvmrc`).
- Run the build, unit tests, stdio smoke, and native/no-engine eval on both Node 22 and Node 24.
- Do not treat Node 18 or 20 as supported; both release lines are end-of-life.

## Build (must pass clean)
```bash
npm run build        # tsc --noEmit && tsup — zero type errors
```

## Evals (regression suite, PRD §13)
```bash
npm run eval         # drives the built server over MCP stdio
```
Expected: all non-skipped evals PASS. Engine-dependent evals (E16 Opengrep SQLi,
E17 Trivy SCA, E18 Opengrep CORS precision, and E34-E36 Opengrep/native parity)
auto-SKIP when the binary/DB cannot run — that is acceptable, a FAIL is not. The
suite currently has 87 evals. Measured on 2026-11-03: with all four engines and
their databases installed, 87 passed, 0 failed, 0 skipped; with no engine installed (a `HOME` without
`~/.codeinspectus`), 63 passed, 0 failed, 24 skipped (every skip is engine-dependent; E82, E83, E85
and E86 need no engine and E84 skips). Partial installs fall between the two: E59/E60 skip without the
PyPI OSV database, and E61 skips without osv-scanner or when the OSV crates.io database is installed. E17 and E64 skip only without the Trivy DB; E64 requires
every Trivy dependency finding to name its package and, when Trivy reports a fixed version, to
name the upgrade in its remediation (a Trivy finding merged into an osv-scanner one is checked in
osv-scanner's wording: package in the title, `Upgrade <name> ` remediation). E62 scans with
no host locale and must run Opengrep on a UTF-8 `.semgrepignore`; E63 requires a repository
`.semgrepignore` to leave Opengrep's file selection unchanged. Both skip only without Opengrep.
E65 requires valid JSX text with an apostrophe or a bare slash to keep both JavaScript packs `ran`;
it must not skip.
E66 runs Gitleaks on a relative `.gitleaksignore` entry (finding kept, secret coverage `verified`)
and on an absolute one, plain and NEL-prefixed (finding hidden, coverage `unverified`); it skips only
without Gitleaks.
E67 adds a 2.8 MB `.yarn/releases/*.cjs` at runtime and requires both JavaScript packs to read `ran`
with no oversized-source note; it must not skip.
E68 writes `trivy.yaml`, `.trivyignore` and `trivy-secret.yaml` into a scanned copy of vulnerable-app
and requires Trivy's vulnerability, misconfiguration and secret findings anyway; it skips only
without the Trivy DB. E69 scans a single file whose directory holds a `.gitleaksignore` naming it
and requires the Gitleaks finding; it skips only without Gitleaks. E70 adds a file over Opengrep's
1,000,000-byte limit and a syntax error and requires the "Opengrep SAST coverage partial" warning to
count and name the first and the `sast-parse-errors` gap to name the second; it skips only without
Opengrep. E71 scans copies of `opengrep-ignore-suppress`
under `build/`, `tests/` and `node_modules/` folders and requires the planted `eval()` (and the
default `*.min.js` exclusion) in each; it guards the internal
`SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE` variable and skips only without Opengrep. E72 builds a
git repository whose `.gitignore` matches a committed (force-added) and an untracked file and
requires Opengrep findings in both; it skips only without Opengrep. E73 scans
`coverage-honesty-corpus/coverage-gaps` and requires the four declared gap ids with counts and
examples, `accepted_gaps` listing only what `accept_gaps` named, and an unknown id rejected; it must
not skip. E74 starts the server with `SEMGREP_BASELINE_REF=HEAD`, `TRIVY_SEVERITY=CRITICAL`,
`TRIVY_CONFIG` and `GITLEAKS_CONFIG` set and requires the Opengrep, non-critical Trivy and Gitleaks
findings of a committed vulnerable-app copy; it skips only without the Trivy DB. E75 scans
`coverage-honesty-corpus/opengrep-rules`, which holds one folder per bundled Opengrep rule id, and
requires each rule to fire on its `tp/` files only, no Opengrep skip or error warning (an
"Internal matching error" counts), and the folders to match the bundled rule ids; add a folder with
`tp/` cases when you add a rule. It skips only without Opengrep. E76 scans a secret file under
`node_modules/`, `bower_components/`, `vendor/bundle/` and `lib/python3.12/site-packages/` folders and
requires the Gitleaks finding with `verified` coverage, and a single file under `node_modules/` to read
`unverified`; it skips only without Gitleaks. E77 commits planted code under `.vercel/output/` and
`.next/` and requires the Opengrep finding in the first (only BUILD_DIRS are skipped) and none in the
second; it skips only without Opengrep. E78 scans `coverage-honesty-corpus/dev-deps` (npm
devDependency handlebars, Composer `packages-dev` phpunit, production lodash and guzzle) and requires
the development packages' findings, titled `, dev dependency)` (also when osv-scanner's finding survives
the merge), and the production ones unmarked; it
skips only without the Trivy DB. E79 builds a temporary repository with an unparsable `src/broken.ts`, a
directory symlink, a `wpackagist-plugin/*` composer.lock entry and a workflow `uses:` reference, and
requires the gaps `native-parse-errors`, `symlinked-paths`, `wordpress-plugins` and `actions-unchecked`
with exact examples, `accepted_gaps` listing all four, and both JavaScript packs reading `ran`; it must
not skip. E82-E86 cover the Synvoya gap layer (`docs/SYNVOYA.md`). E82 scans `fixtures/synvoya/evals/gap-declarations`
(`node:22.1.0-alpine`, `.nvmrc 20`, `"php": "8.1.*"`, Magento EE 2.4.7-p2) and requires the Node, PHP and
Adobe verify-hotfix findings with their fixes; E83 starts the server from a COPY of the built package
whose `advisories.json` was edited and requires the engine `unavailable`, the warning, and a rescan that
reports the prior Synvoya findings `not_rechecked`; E85 requires `node:22-alpine` to give an info
coverage note and no finding. E86 starts a second server with
`CODEINSPECTUS_INTERNAL_SYNVOYA_DEADLINE_MS=0` over a temporary `HOME` and requires the rescan to report
the prior findings `not_rechecked`, never `resolved`. All four must not skip. E84 scans
`fixtures/synvoya/evals/trivy-covered` and requires one upstream `node-forge` finding with the
Synvoya fix added and its id, fingerprint and producers equal to a scan with Synvoya unavailable; it
skips only without the Trivy DB (or when the installed DB does not list the covered CVE yet).
E22,
E53, and E54 cover Supabase Edge, Next.js admin, and Express admin auth/authz. E55/E56
cover exact source-integrity evidence, vendor-neutral classification, read-only behavior,
and bidirectional same-path trust-artifact rescans; both must not skip.
E57 covers explicit source attribution, real parsed media metadata, protected-record and
approval-gated remediation semantics, human capability summaries, and same-path trust-artifact
rescans; it must not skip. E58 drives the built MCP through fresh cleanup planning, exact approval,
managed checkpointing, atomic source cleanup, same-validator verification and rollback; it must not
skip. The official C2PA adapter must additionally be tested against known-good and known-bad
upstream fixtures before release because the repository does not redistribute that external corpus.
E20/E21 include the Referrer-Policy and Permissions-Policy checks. E23/E24 are
engine-independent MCP stdio checks over the
Flutter TP/FP/fixed corpus, and E25/E26 cover the Android/iOS TP/FP/fixed corpus;
all four must not skip. E27-E29 cover native Pub SCA, same-path rescan, bundled-database
provenance, and CycloneDX/SPDX generation; they also must not skip.
E30/E31 cover the React Native/Expo TP/FP/fixed corpus and bidirectional same-path
rescan; both must not skip.
E32/E33 cover the Python AI/API TP/FP/fixed corpus, exact provenance/coverage/redaction,
and bidirectional same-path rescan; both must not skip.
E37/E38 cover the Go AI TP/FP/fixed corpus, exact language-gated pack dispatch,
provenance, and bidirectional same-path rescan; both must not skip.
E39/E40 cover the Java AI TP/FP/fixed corpus, exact language-gated pack dispatch,
provenance, actually-started process semantics, and bidirectional same-path rescan; both must not skip.
E41/E42 cover the C# AI TP/FP/fixed corpus, exact language-gated pack dispatch,
provenance, actually-started process semantics, and bidirectional same-path rescan; both must not skip.
E43/E44 cover the PHP AI TP/FP/fixed corpus, exact language-gated pack dispatch,
provenance, mapped variadic method dispatch, and bidirectional same-path rescan; both must not skip.
E45/E46 cover the Rust AI TP/FP/fixed corpus, exact language-gated pack dispatch,
provenance, process/Bollard shell semantics, and bidirectional same-path rescan; both must not skip.
E47/E48 cover the Ruby AI TP/FP/fixed corpus, exact official-gem and language-gated pack dispatch,
provenance, Ruby shell semantics, and bidirectional same-path rescan; both must not skip.
E49/E50 cover the Firebase TP/FP/fixed corpus, exact technology-gated pack dispatch, provenance,
literal public-write semantics, and bidirectional same-path rescan; both must not skip.
E51/E52 cover the GitHub Actions TP/FP/fixed corpus, exact workflow-gated pack dispatch,
provenance, attacker-controlled expression and pwn-request semantics, and bidirectional same-path
rescan; both must not skip.

## MCP transport
```bash
node scripts/smoke-stdio.mjs                      # asserts stdout is pure JSON-RPC
npx @modelcontextprotocol/inspector --cli node dist/index.js --method tools/list
```

## Engine integrity (supply-chain guardrail)
```bash
node dist/index.js verify-engines    # every binary's SHA256 must match engines.lock.json
node dist/index.js repair-engines opengrep  # healthy selected engine is an offline no-op
```

## Dependency advisories (release gate)
```bash
npm audit --omit=dev                 # runtime dependencies shipped in the npm package
npx codeinspectus setup              # refresh the Trivy DB when engine_setup reports db_refresh_recommended
```
Before every release, fix each high or critical runtime advisory, or record it under "Known issue" in
the CHANGELOG with its reachability and the release that will fix it. Re-run the audit on the
intended release commit; advisories published after the previous release are the usual gap.

## Fixture scan (manual)
```bash
npx tsx scripts/dev-scan.ts "$(pwd)/fixtures/vulnerable-app"
```
Must detect: client hardcoded secret (CWE-798), USING(true) RLS (CWE-863),
missing RLS (CWE-862), public-env secret, prompt-injection sink (CWE-1427),
SQLi via Opengrep (CWE-89), and — with the Trivy DB present — the lodash/minimist
vulnerable dependency. Safe equivalents (accounts table, parameterized query,
publishable key) must NOT be flagged.

Also run the Enhancement 1 precision corpora:
```bash
npx tsx scripts/dev-scan.ts "$(pwd)/fixtures/api-boundary-corpus" ai
npx tsx scripts/dev-scan.ts "$(pwd)/fixtures/cors-corpus" sast
npx tsx scripts/dev-scan.ts "$(pwd)/fixtures/security-controls-corpus/tp/captcha" ai
```
Expected: 18 API-boundary findings, all under `tp/`; 9 CORS findings (3 invalid
wildcard configurations + 6 arbitrary-origin exposures), with every `fp/` file silent;
and 3 evidence-gated Supabase CAPTCHA integration findings with no raw token/secret values.

For native-pack ownership, applicability, and Flutter/Dart plus Android/iOS precision:
```bash
npx vitest run \
  src/packs/flutter/*.test.ts \
  src/packs/android/android-config.test.ts \
  src/packs/ios/ios-config.test.ts \
  src/packs/react-native/*.test.ts \
  src/packs/expo/*.test.ts \
  src/packs/react-native-expo-corpus.test.ts \
  src/packs/python/*.test.ts \
  src/packs/python-ai-api/*.test.ts \
  src/packs/go/*.test.ts \
  src/packs/java/*.test.ts \
  src/packs/csharp/*.test.ts \
  src/packs/php/*.test.ts \
  src/packs/rust/*.test.ts \
  src/packs/ruby/*.test.ts \
  src/packs/firebase/*.test.ts \
  src/packs/github-actions/*.test.ts \
  src/packs/registry.test.ts \
  src/pub/*.test.ts \
  src/technology-detection.test.ts \
  src/provenance.test.ts \
  src/repository-trust/*.test.ts
```
Expected: all focused tests pass; manifest `1.19.1` owns exactly 72 native rule IDs (29
JavaScript/TypeScript, 6 Flutter/Dart, 4 Android, 4 iOS, 4 React Native, 2 Expo, 10 Python AI/API,
1 Go AI, 1 Java AI, 1 C# AI, 1 PHP AI, 1 Rust AI, 1 Ruby AI, 3 Firebase configuration,
2 GitHub Actions workflow, and 2 JavaScript baseline SAST) across sixteen packs and 45 analyzers;
the aggregate native engine is `5.20.0`. The JavaScript/TypeScript pack is `1.9.0`; the Flutter
pack is `1.1.0`. A detected Flutter project runs the six Flutter analyzers,
a plain Dart package reports that pack as `not_applicable`, Android/iOS project evidence activates
only its matching platform pack, and scanner-filter exclusion reports installed packs as `not_run`
rather than implying execution. The frozen
`fixtures/flutter-corpus/{tp,fp,fixed}` projects must produce exactly six TP findings (one per
Flutter rule), zero FP/fixed findings, exclude generated/test/example files at project-root scope,
and redact `CI_FLUTTER_REDACTION_SENTINEL`. E23/E24 repeat the corpus contract through the built
MCP server, including 6/6 analyzer/rule execution accounting and scan → fixed rescan behavior.
The frozen `fixtures/mobile-config-corpus/{android,ios}/{tp,fp,fixed}` projects must produce exactly
four TP findings per platform and zero FP/fixed findings while retaining 1/1 analyzer and 4/4 rule
execution. E25 validates exact findings, coverage, provenance, and redaction through MCP; E26 proves
all eight findings resolve and can be reintroduced on the same combined-project paths without
`not_rechecked` entries.
The frozen `fixtures/pub-sca-corpus/{tp,fp,fixed,malformed}` inputs must produce six native TP
advisory identities, zero native FP/fixed findings, explicit partial coverage for excluded
custom/Git/path/SDK inputs, and fail-closed malformed coverage. Native CycloneDX and SPDX must
generate even when Trivy is unavailable, while Trivy-present output must merge rather than
duplicate equivalent Pub purls. E27-E29 repeat scan, rescan, database inventory, and both SBOM
formats through the built MCP server.
The frozen `fixtures/react-native-expo-corpus/{tp,fp,fixed}` projects must produce exactly six TP
findings (four React Native and two Expo) and zero FP/fixed findings, with both packs independently
accounted. E30 repeats exact findings, technology evidence, provenance, limitations, and redaction
through MCP; E31 proves all six findings resolve and can be reintroduced on the same paths without
`not_rechecked` entries.
The frozen `fixtures/python-ai-api-corpus/{tp,fp,fixed}` projects must produce exactly ten TP
findings (one per Python AI/API rule) and zero FP/fixed findings while retaining 10/10 analyzer/rule
execution. Unsupported syntax, source bounds, excluded corpora, dependency metadata, and symlink
ancestors must fail closed with explicit coverage notes. E32 repeats exact findings, technology
evidence, provenance, limitations, and redaction through MCP; E33 proves all ten findings resolve
and can be reintroduced on the same paths without `not_rechecked` entries.
The frozen `fixtures/go-ai-corpus/{tp,fp,fixed}` projects must produce exactly three TP findings
for the one Go AI rule and zero FP/fixed findings while retaining 1/1 analyzer/rule execution.
Official OpenAI Go evidence must activate only the Go pack, not the Python pack. E37 repeats exact
findings, technology evidence, provenance, limitations, and redaction through MCP; E38 proves all
three findings resolve and can be reintroduced on the same paths without `not_rechecked` entries.
The frozen `fixtures/java-ai-corpus/{tp,fp,fixed}` projects must produce exactly three TP findings
for the one Java AI rule and zero FP/fixed findings while retaining 1/1 analyzer/rule execution.
Exact official OpenAI Java dependency evidence must activate only the Java pack; a `ProcessBuilder`
constructor without `start()` must stay silent. E39 repeats exact findings, technology evidence,
provenance, limitations, and redaction through MCP; E40 proves all three findings resolve and can be
reintroduced on the same paths without `not_rechecked` entries.
The frozen `fixtures/csharp-ai-corpus/{tp,fp,fixed}` projects must produce exactly three TP findings
for the one C# AI rule and zero FP/fixed findings while retaining 1/1 analyzer/rule execution.
Exact official `OpenAI` NuGet dependency evidence must activate only the C# pack; constructing a
`ProcessStartInfo` without `Process.Start` must stay silent. E41 repeats exact findings, technology
evidence, provenance, limitations, and redaction through MCP; E42 proves all three findings resolve
and can be reintroduced on the same paths without `not_rechecked` entries.
The frozen `fixtures/php-ai-corpus/{tp,fp,fixed}` projects must produce exactly three TP findings
for the one PHP AI rule and zero FP/fixed findings while retaining 1/1 analyzer/rule execution.
Exact community-maintained `openai-php/client` or `openai-php/laravel` Composer evidence must
activate only the PHP pack; checked approval/full-command allowlists and validated replacement
values must stay silent, while first-token executable checks do not suppress shell-metacharacter
risk. E43 repeats exact findings, technology evidence, provenance, limitations, and redaction
through MCP; E44 proves all three findings resolve and can be reintroduced on the same paths without
`not_rechecked` entries.
The frozen `fixtures/rust-ai-corpus/{tp,fp,fixed}` projects must produce exactly three TP findings
for the one Rust AI rule and zero FP/fixed findings while retaining 1/1 analyzer/rule execution.
Exact community-maintained `async-openai` Cargo evidence must activate only the Rust pack;
checked approval/allowlists and validated replacement values must stay silent, while recognized
standard/Tokio process and literal Bollard Docker exec shell vectors remain covered. E45 repeats
exact findings, technology evidence, provenance, limitations, and redaction through MCP; E46 proves
all three findings resolve and can be reintroduced on the same paths without `not_rechecked`
entries. `async-openai` is not represented as an official OpenAI SDK.
The frozen `fixtures/ruby-ai-corpus/{tp,fp,fixed}` projects must produce exactly three TP findings
for the one Ruby AI rule and zero FP/fixed findings while retaining 1/1 analyzer/rule execution.
Exact official `openai` production Gemfile or runtime gemspec evidence must activate only the Ruby
pack; checked approval/full-command allowlists, validated replacements, generic `.arguments`
objects, string/comment decoys, lockfile-only evidence, and development-only dependencies must stay
silent. E47 repeats exact findings, technology
evidence, provenance, limitations, and redaction through MCP; E48 proves all three findings resolve
and can be reintroduced on the same paths without `not_rechecked` entries.
The frozen `fixtures/firebase-config-corpus/{tp,fp,fixed}` projects must produce exactly three TP
findings (one each for Firestore, Cloud Storage, and Realtime Database public writes) and zero
FP/fixed findings while retaining 1/1 analyzer and 3/3 rule execution. Public reads, authenticated
or non-literal conditions, comments/strings, and JSON string-value decoys must stay silent;
malformed input and loader bounds fail closed with coverage notes. E49 repeats exact findings,
technology evidence, provenance, limitations, and metadata through MCP; E50 proves all three
findings resolve and can be reintroduced on the same paths without `not_rechecked` entries.
The frozen `fixtures/github-actions-corpus/{tp,fp,fixed}` projects must produce exactly two TP
findings (one direct untrusted-context expression in `run` and one complete
`pull_request_target` checkout-and-execute chain) and zero FP/fixed findings while retaining 1/1
analyzer and 2/2 rule execution. Safe `env`/`with` indirection, normal `pull_request`, checkout
without execution, protected checkout v7, comments, and malformed or bounded-out inputs must stay
silent or fail closed with coverage notes. E51 repeats exact findings, technology evidence,
provenance, limitations, and metadata through MCP; E52 proves both findings resolve and can be
reintroduced on the same paths without `not_rechecked` entries.

Run the fail-closed Opengrep shadow gate separately:

```bash
npm run shadow:opengrep -- --require-hit \
  fixtures/opengrep-shadow-corpus/tp \
  fixtures/opengrep-shadow-corpus/fp \
  fixtures/opengrep-shadow-corpus/fixed
```

Expected: Opengrep `1.33.1` is available; TP is exact 6/6, FP/fixed are 0/0, direct-file and
project-root identities agree, metadata mismatches are empty, and no candidate loader limitation is
present. E34 repeats the engine-backed parity contract. E35/E36 prove native-only surfaced
provenance, SAST/AI scanner filtering, and same-path fixed/reintroduced rescan behavior while the
Opengrep YAML fallback remains active.

## Guardrail spot-checks
- Run `npx vitest run src/agent-rule-contract.test.ts src/agent-extension-contract.test.ts` and
  require every mutation gate, malicious-document case, orchestration bound, and scanner/agent
  evidence-separation assertion to pass.
- Run the skill-creator `quick_validate.py` validator against `agent-rules/codeinspectus-fix-one/`,
  `agent-rules/codeinspectus-threat-model/`, and `agent-rules/codeinspectus-multi-review/`.
- Inspect `npm pack --dry-run --json` and require all three skill directories to be present while
  workflow fixtures and internal context remain excluded from the npm artifact.
- No `console.log` anywhere in `src/` (stdout must be pure JSON-RPC).
- No raw secret value in any tool output (redaction).
- Compliance output never says "% compliant" / "you pass"; always shows the
  code-visible denominator + disclaimer.
