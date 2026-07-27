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
E17 Trivy SCA, E18 Opengrep CORS precision) auto-SKIP when the binary/DB is
unavailable — that is acceptable, a FAIL is not. E23/E24 are engine-independent MCP stdio checks over the
Flutter TP/FP/fixed corpus, and E25/E26 cover the Android/iOS TP/FP/fixed corpus;
all four must not skip. E27-E29 cover native Pub SCA, same-path rescan, bundled-database
provenance, and CycloneDX/SPDX generation; they also must not skip.
E30/E31 cover the React Native/Expo TP/FP/fixed corpus and bidirectional same-path
rescan; both must not skip.
E32/E33 cover the Python AI/API TP/FP/fixed corpus, exact provenance/coverage/redaction,
and bidirectional same-path rescan; both must not skip.

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

## Fixture scan (manual)
```bash
npx tsx scripts/dev-scan.ts "$(pwd)/fixtures/vulnerable-app"
```
Must detect: client hardcoded secret (CWE-798), USING(true) RLS (CWE-863),
missing RLS (CWE-862), public-env secret, prompt-injection sink (CWE-1426),
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
  src/packs/registry.test.ts \
  src/pub/*.test.ts \
  src/technology-detection.test.ts \
  src/provenance.test.ts
```
Expected: all focused tests pass; manifest `1.0.0` owns exactly 49 native rule IDs (21
JavaScript/TypeScript, 6 Flutter/Dart, 4 Android, 4 iOS, 4 React Native, 2 Expo, and 6 Python AI/API)
plus 2 JavaScript baseline SAST IDs across eight packs and 29 analyzers; the aggregate native engine
is `5.0.0`. A detected Flutter project runs the six Flutter analyzers,
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
The frozen `fixtures/python-ai-api-corpus/{tp,fp,fixed}` projects must produce exactly six TP
findings (one per Python AI/API rule) and zero FP/fixed findings while retaining 6/6 analyzer/rule
execution. Unsupported syntax, source bounds, excluded corpora, dependency metadata, and symlink
ancestors must fail closed with explicit coverage notes. E32 repeats exact findings, technology
evidence, provenance, limitations, and redaction through MCP; E33 proves all six findings resolve
and can be reintroduced on the same paths without `not_rechecked` entries.

Run the fail-closed Opengrep shadow gate separately:

```bash
npm run shadow:opengrep -- --require-hit \
  fixtures/opengrep-shadow-corpus/tp \
  fixtures/opengrep-shadow-corpus/fp \
  fixtures/opengrep-shadow-corpus/fixed
```

Expected: Opengrep `1.23.0` is available; TP is exact 6/6, FP/fixed are 0/0, direct-file and
project-root identities agree, metadata mismatches are empty, and no candidate loader limitation is
present. E34 repeats the engine-backed parity contract. E35/E36 prove native-only surfaced
provenance, SAST/AI scanner filtering, and same-path fixed/reintroduced rescan behavior while the
Opengrep YAML fallback remains active.

## Guardrail spot-checks
- No `console.log` anywhere in `src/` (stdout must be pure JSON-RPC).
- No raw secret value in any tool output (redaction).
- Compliance output never says "% compliant" / "you pass"; always shows the
  code-visible denominator + disclaimer.
