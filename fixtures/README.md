# CodeInspectus fixtures

Test corpus of planted vulnerabilities (true positives) plus safe equivalents
(false-positive guards). This is the regression suite for the weekly intake
(PRD §9, §13): every detection is gated on precision against these fixtures.

## `vulnerable-app/` — planted true positives

| # | Issue | File | Detector | CWE |
|---|-------|------|----------|-----|
| 1 | Hard-coded Stripe **live** secret in client-reachable source | `src/config.ts` | `ci-ai-client-hardcoded-secret` + Gitleaks | CWE-798 / CWE-312 |
| 2a | RLS policy `USING (true)` (CVE-2025-48757 class) | `supabase/migrations/0001_init.sql` | `ci-ai-rls-using-true` | CWE-863 |
| 2b | Public table created without RLS | same | `ci-ai-rls-missing` | CWE-862 |
| 3 | SQL injection via string-built query | `src/db.ts` | Opengrep `ci-baseline-sql-injection-string-build` | CWE-89 |
| 4 | Outdated vulnerable dependency (lodash 4.17.4, minimist 1.2.0) | `package-lock.json` | Trivy (SCA) | CWE-1321/CWE-400 etc. |
| 5 | Prompt-injection sink + tool access | `src/llm.ts` | `ci-ai-prompt-injection-sink` | CWE-1427 |
| 6 | Model-produced tool argument reaches Node shell execution | `src/agent.ts` | `ci-ai-llm-tool-argument-command-execution` | CWE-78 / CWE-1426 |
| + | Secret behind client-exposed env prefix | `src/components/PaymentForm.tsx` | `ci-ai-public-env-secret` | CWE-798 |

## Safe equivalents — must NOT be flagged (precision)

- `src/db.ts` `safeGetUserById` — parameterized query.
- `0001_init.sql` `public.accounts` — RLS enabled with `auth.uid()` policies for all operations.
- `PaymentForm.tsx` `publishable()` — a publishable (non-secret) key behind a public prefix.

Engines 3 and 4 require the managed binaries + Trivy DB (`codeinspectus repair-engines`).
Detectors 1, 2, 5, 6, + are pure-TypeScript and run with no external binary.

## Precision corpora — dual-direction (true positives + false-positive guards)

Contract-driven regression corpora, each with a shipped vitest lock. The per-fixture verdicts live
in each corpus's `CONTRACT.md` (maintainer-guarded; excluded from the public seed — the inline
expectations in the test file are the public spec).

- `metadata-authz-corpus/` — `ci-ai-client-metadata-authz` (client-writable `user_metadata` used
  for authorization; CWE-639). 7 TP (inline / split-variable / destructured / role-ish flag /
  `permissions.includes` / `raw_user_meta_data` / privileged-literal) + 5 FP (feature gate, display
  read, benign read, correct `app_metadata`, non-authz). Locked by `src/ai-checks/metadata-authz.test.ts`.
- `llm-dangerous-html-corpus/` — `ci-ai-llm-output-dangerous-html` (untrusted input OR LLM/model
  output rendered via `dangerouslySetInnerHTML` without sanitization; CWE-79/116, OWASP LLM05). 5 TP
  (arm A untrusted inline/split, arm B model output inline/split/other-SDK) + 4 FP (DOMPurify-sanitized,
  constant/trusted, plain-text render, non-`__html` noise). Locked by `src/ai-checks/llm-dangerous-html.test.ts`.
- `api-boundary-corpus/` — four server/API checks: client-visible internal errors, explicit
  sensitive response fields, unvalidated whole-request database writes, and sensitive logging.
  18 TP + 12 safe near misses covering public-error mapping, Zod/Joi validation, explicit field
  projection, redacted/ordinary logging, comments, and minified vendor code. Locked by
  `src/ai-checks/api-boundary.test.ts`.
- `cors-corpus/` — corrected wildcard-plus-credentials behavior and credentialed arbitrary-origin
  reflection. 3 invalid wildcard configurations + 6 true exposure patterns + 7 safe near misses.
  Locked by eval E18 against the real Opengrep binary.
- `security-controls-corpus/` — explicit insecure header/CSP/session-cookie configuration and
  evidence-gated Supabase CAPTCHA integration. Includes safe configurations, development/report-only
  near misses, hosted unknowns, nginx/Next.js effective-order cases, and unresolved cross-layer
  conflicts. Locked by `src/ai-checks/security-controls.test.ts` plus evals E20/E21.
- `supabase-edge-auth-corpus/` — an Edge Function request handler without caller authentication,
  paired with an authenticated equivalent and non-Edge near miss. It deliberately contains no SQL
  so the Edge Function detector cannot accidentally depend on the separate RLS project gate. Locked
  by `src/ai-checks/supabase-rls.test.ts`.
- `flutter-corpus/` — three complete synthetic Flutter projects: six one-to-one true positives,
  safe near misses plus generated/test/example exclusion guards, and matching remediated files for
  rescan proof. Covers all six first-party Flutter/Dart rules, technology applicability, pack
  execution accounting, detector provenance, and redaction. Locked by
  `src/packs/flutter/corpus.test.ts` and MCP evals E23/E24. The private `CONTRACT.md` expectation
  ledger is excluded from the public seed; this index and the shipped tests are the public spec.
- `mobile-config-corpus/` — Android and iOS TP/FP/fixed repository-configuration projects for the
  eight first-party mobile platform rules. Locks effective release selection, platform/config
  precedence, ignored development corpora, parser bounds, exact provenance, and zero-finding
  remediated states. Covered by `src/packs/android/android-config.test.ts`,
  `src/packs/ios/ios-config.test.ts`, and MCP evals E25/E26. The private `CONTRACT.md` expectation
  ledger is excluded from the public seed; this index and the shipped tests are the public spec.
- `pub-sca-corpus/` — frozen Pub TP/FP/fixed/malformed lockfiles for the first-party offline
  dependency matcher and native SBOM fallback. It locks Pub build-suffix/prerelease boundaries,
  two distinct advisories for one `archive` version, custom-registry/Git/path/SDK exclusions,
  fail-closed malformed input, provenance, and fixed-version rescan behavior. Covered by
  `src/pub/*.test.ts` and MCP evals E27-E29. The private `CONTRACT.md` expectation ledger is
  excluded from the public seed; shipped tests are the public spec.
- `react-native-expo-corpus/` — three complete Expo/React Native projects with exactly one TP for
  each of the four React Native and two Expo rules, safe near misses and excluded test/example/
  generated source, plus path-identical remediated files. It locks framework applicability,
  bounded non-executing parsing, pack coverage, provenance, redaction, and same-path rescan via
  shipped pack tests and MCP evals E30/E31. The private `CONTRACT.md` expectation ledger is excluded
  from the public seed; shipped tests are the public spec.
- `python-ai-api-corpus/` — three Python projects with exactly one TP for each of the ten Python
  AI/API rules, safe near misses plus excluded test/example/generated source, and path-identical
  remediated files. It locks bounded syntax/project loading, framework applicability, source/sink
  provenance, exact LangChain FAISS origin/keyword resolution, dangerous-deserialization opt-in,
  request-controlled LangChain web-loader fetch execution, and role/tool-aware OpenAI/Anthropic
  prompt-injection boundaries, and model tool arguments reaching proven Python shell execution,
  pack coverage, redaction, and same-path rescan through shipped tests and MCP evals
  E32/E33. The private `CONTRACT.md` expectation ledger is excluded from the public seed; shipped
  tests are the public spec.
- `unsafe-tool-execution-corpus/` — JavaScript/TypeScript TP/FP/fixed files for model-produced
  tool arguments reaching import-proven Node shell execution. It locks direct and one-wrapper
  flows, promisified aliases, checked approval and allowlist gates, fixed-executable remediation,
  import/lookalike precision, exact CWE/OWASP metadata, and honest medium confidence. Covered by
  `src/ai-checks/unsafe-tool-execution.test.ts`; the private `CONTRACT.md` is excluded from the
  public seed.
- `go-ai-corpus/` — three Go projects for the exact official OpenAI Go tool-argument-to-shell rule:
  three TP flows, zero safe near-miss findings, and zero remediated findings. It locks direct flow,
  JSON unmarshal, one parsing helper, one command wrapper, approval/allowlist and validated-value
  suppression, import provenance, direct-file parity, bounded loading, exact producer components,
  and same-path rescan through shipped Go pack tests and MCP evals E37/E38. The private
  `CONTRACT.md` expectation ledger is excluded from the public seed; shipped tests are the public spec.
- `java-ai-corpus/` — three Java projects for the exact official OpenAI Java
  tool-argument-to-shell rule: three TP flows, zero safe near-miss findings, and zero remediated
  findings. It locks actually-started `ProcessBuilder`/`Runtime` sinks, direct flow, one parsing
  helper, one command wrapper, approval/allowlist and validated-value suppression, dependency/import
  provenance, direct-file parity, bounded no-follow loading, exact producer components, and same-path
  rescan through shipped Java pack tests and MCP evals E39/E40. The private `CONTRACT.md`
  expectation ledger is excluded from the public seed; shipped tests are the public spec.
- `csharp-ai-corpus/` — three C# projects for the exact official OpenAI .NET
  tool-argument-to-shell rule: three TP flows, zero safe near-miss findings, and zero remediated
  findings. It locks actually-started `System.Diagnostics.Process` shell sinks, direct flow,
  typed `ChatToolCall` method parameters, `System.Text.Json` extraction, one parsing helper, one
  command wrapper, approval/allowlist and validated-value suppression, exact NuGet provenance,
  direct-file parity, bounded no-follow loading, exact producer components, and same-path rescan
  through shipped C# pack tests and MCP evals E41/E42. The private `CONTRACT.md` expectation ledger
  is excluded from the public seed; shipped tests are the public spec.
- `php-ai-corpus/` — three PHP projects for the community-maintained OpenAI PHP ecosystem
  tool-argument-to-command rule: three TP flows, zero safe near-miss findings, and zero remediated
  findings. It locks exact `openai-php/client` Composer provenance, direct aliases, associative
  `json_decode`, one parsing helper, one command wrapper, one exact mapped variadic method dispatch,
  approval/full-command-allowlist and validated-value suppression, first-token-check handling,
  direct-file parity, bounded no-follow loading, exact producer components, and same-path rescan
  through shipped PHP pack tests and MCP evals E43/E44. The PHP client is community maintained,
  not an official OpenAI SDK. The private `CONTRACT.md` expectation ledger is excluded from the
  public seed; shipped tests are the public spec.
- `rust-ai-corpus/` — three Rust projects for the community-maintained `async-openai`
  tool-argument-to-shell rule: three TP flows, zero safe near-miss findings, and zero remediated
  findings. It locks exact Cargo dependency provenance, direct aliases, `serde_json` extraction,
  one recognized `generate_function_call` result, one command wrapper, standard-process and
  literal Bollard Docker exec shell sinks, approval/allowlist and validated-value suppression,
  multiline Rust string handling, direct-file parity, bounded no-follow loading, exact producer
  components, and same-path rescan through shipped Rust pack tests and MCP evals E45/E46.
  `async-openai` is community maintained, not an official OpenAI SDK. The private `CONTRACT.md`
  expectation ledger is excluded from the public seed; shipped tests are the public spec.
- `ruby-ai-corpus/` — three Ruby projects for the exact official production `openai` Gemfile
  or runtime gemspec
  tool-argument-to-command rule: three TP flows, zero safe near-miss findings, and zero remediated
  findings. It locks Chat tool-call arguments, explicitly typed Responses function-tool arguments,
  `JSON.parse` extraction, one parsing helper, one command wrapper, `system`/Open3 shell shapes,
  approval/full-command-allowlist and validated-value suppression, string/comment decoys, heredoc
  fail-closed behavior, direct-file parity, bounded no-follow loading, exact producer components,
  and same-path rescan through shipped Ruby pack tests and MCP evals E47/E48. The private
  `CONTRACT.md` expectation ledger is excluded from the public seed; shipped tests are the public spec.
- `firebase-config-corpus/` — three Firebase projects for literal unconditional public writes:
  exactly one Firestore, one Cloud Storage, and one Realtime Database TP finding, with zero safe
  near-miss or remediated findings. It locks public-read silence, exact-`true` semantics,
  authentication/authorization conditions, comment/string decoys, strict Realtime Database JSON,
  bounded no-follow loading, exact producer components, and same-path rescan through shipped
  Firebase pack tests and MCP evals E49/E50. The private `CONTRACT.md` expectation ledger is
  excluded from the public seed; shipped tests are the public spec.
- `github-actions-corpus/` — TP/FP/fixed GitHub Actions workflows for two bounded workflow rules:
  one direct attacker-controlled `github` expression in `run` and one exact
  `pull_request_target` untrusted-checkout-and-execute chain. It locks safe `env`/`with`
  indirection, normal `pull_request`, checkout without execution, protected checkout v7,
  scalar/block scripts, malformed YAML, loader bounds, exact producer components, and same-path
  rescan through shipped GitHub Actions pack tests and MCP evals E51/E52. The private
  `CONTRACT.md` expectation ledger is excluded from the public seed; shipped tests are the public spec.
- `opengrep-shadow-corpus/` — TP/FP/fixed JavaScript/TypeScript projects for exact raw parity between
  the still-active Opengrep weak-hash/cipher rules and the first native SAST candidates. It covers
  named imports, JS/TS/JSX/TSX, multiline and same-line multiplicity, modern/dynamic algorithms,
  and literal/comment/lookalike exclusions. The candidates remain shadow-only until promotion.
