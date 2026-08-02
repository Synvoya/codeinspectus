# RULE-PROVENANCE.md — bundled detection provenance (for legal review)

> **Purpose:** let a lawyer review the provenance of every active detection and every
> bundled engine against the codebase quickly. **This is review material, not a legal
> clearance.** CodeInspectus asserts the items below are original work (or permissively
> licensed upstream); a human must confirm before the legal-provenance gate is closed.
>
> **Single source of truth:** `detection-db/manifest.json` (`custom_rules` +
> `opengrep_rulesets`) for the custom detections, and `engines.lock.json` for engine
> versions. Where this document and any other doc disagree on a count or a version, the
> two files above win and this document is the one to correct.

_Last refreshed: JavaScript/TypeScript Next.js admin-route and model-output execution, GitHub Actions, Firebase, Ruby, Rust, PHP, C#, Java, Go, JavaScript/TypeScript unsafe tool execution, and Python AI/API native packs
(2026-07-28) — recorded the original bounded GitHub Actions workflow rules, Firebase configuration rules, Ruby, Rust, PHP, C#, Java, Go, JavaScript, and Python model-tool-argument-to-shell rules and ten original Python structural rules
and their first-party pack ownership, including the exact LangChain FAISS dangerous-deserialization
opt-in, request-controlled WebBaseLoader fetch, and bounded OpenAI/Anthropic prompt-injection sink.
The React Native/Expo refresh recorded six original
framework-specific structural rules. The Android/iOS refresh
recorded eight original repository-configuration rules. The Flutter/Dart refresh
recorded six original token-aware structural rules. Project CI Enhancement 2
recorded four original repository-evidence AI analyzers for explicit header/CSP/cookie/CAPTCHA
configuration. Enhancement 1 recorded four original API-boundary AI analyzers and one original
CORS rule, and compared the CORS rule with the closest current Semgrep registry analog. **No
re-audit of the existing rules was performed this session**. Prior
full provenance pass: CG-08 (2026-06-23) audit + the CG-39 sweep, against
`detection-db/manifest.json`, `engines.lock.json`, `detection-db/**`, `src/ai-checks/**`,
and `src/packs/{flutter,android,ios,react-native,expo,python-ai-api,go,java,csharp,php,rust,ruby,firebase,github-actions}/**`._

---

## Reconciled detection count — **88 active CodeInspectus detections**

`detection-db/manifest.json` `custom_rules` has **88** entries:

| Group | Count | Engine | Kind | Where |
|---|---:|---|---|---|
| JavaScript/TypeScript native rules | **24** | `codeinspectus-ai` | `ai` | `src/ai-checks/*.ts` |
| Flutter/Dart native rules | **6** | `codeinspectus-ai` | `ai` | `src/packs/flutter/*.ts` |
| Android configuration native rules | **4** | `codeinspectus-ai` | `ai` | `src/packs/android/*.ts` |
| iOS configuration native rules | **4** | `codeinspectus-ai` | `ai` | `src/packs/ios/*.ts` |
| React Native native rules | **4** | `codeinspectus-ai` | `ai` | `src/packs/react-native/*.ts` |
| Expo native rules | **2** | `codeinspectus-ai` | `ai` | `src/packs/expo/*.ts` |
| Python AI/API native rules | **10** | `codeinspectus-ai` | `ai` | `src/packs/python-ai-api/*.ts` |
| Go AI native rules | **1** | `codeinspectus-ai` | `ai` | `src/packs/go/*.ts` |
| Java AI native rules | **1** | `codeinspectus-ai` | `ai` | `src/packs/java/*.ts` |
| C# AI native rules | **1** | `codeinspectus-ai` | `ai` | `src/packs/csharp/*.ts` |
| PHP AI native rules | **1** | `codeinspectus-ai` | `ai` | `src/packs/php/*.ts` |
| Rust AI native rules | **1** | `codeinspectus-ai` | `ai` | `src/packs/rust/*.ts` |
| Ruby AI native rules | **1** | `codeinspectus-ai` | `ai` | `src/packs/ruby/*.ts` |
| Firebase configuration native rules | **3** | `codeinspectus-ai` | `ai` | `src/packs/firebase/*.ts` |
| GitHub Actions workflow native rules | **2** | `codeinspectus-ai` | `ai` | `src/packs/github-actions/*.ts` |
| JavaScript baseline native rules | **2** | `codeinspectus-ai` | `sast` | `src/packs/javascript-baseline/*.ts` |
| Opengrep-owned SAST rules | **18** | `opengrep` | `sast` | `detection-db/opengrep-rules/security-baseline/` |
| Gitleaks secret rules | **3** | `gitleaks` | `secret` | `detection-db/gitleaks/codeinspectus.toml` |
| **Total** | **88** | — | — | — |

Verified physical counts: 20 Opengrep YAML rule ids and 3 Gitleaks rule ids are greppable on disk.
The catalog assigns 67 rule IDs to sixteen native packs and 18 to Opengrep; the two promoted native
SAST IDs retain physically active Opengrep fallbacks and are not double-counted.

The authoritative current figure is **88**, decomposing as **67 first-party native rules +
18 Opengrep-owned SAST + 3 Gitleaks** (single source of truth: `detection-db/manifest.json`).
CG-25b added two original
CodeInspectus detections: `ci-ai-llm-key-browser-exposed` (B-11; `dangerouslyAllowBrowser: true`) and
`ci-ai-storage-rls-public` (B-12; permissive `USING (true)` on `storage.objects`). CG-50/51 then added
two more original **`ci-ai-*`** moat analyzers — `ci-ai-client-metadata-authz` (CWE-639; an
authorization decision that trusts client-writable Supabase `user_metadata`) and
`ci-ai-llm-output-dangerous-html` (CWE-79/116; untrusted or model output rendered into a React
raw-HTML `__html` sink) — authored contract-first from the maintainer's spec, original TypeScript with
**no registry equivalent to derive from**. All four are framework-specific AI-code failure modes (no
third-party rule content referenced), carried under the **same documented self-diligence** as the rest
of the ci-ai-* moat (the CG-09 / CG-39 framing below, extended to these two by category — original
authorship, nothing derived to audit — **not** a fresh independent review). Project CI Enhancement 1
adds four independently authored TypeScript analyzers (`ci-ai-client-error-leak`,
`ci-ai-sensitive-api-response`, `ci-ai-unvalidated-request-write`, `ci-ai-sensitive-log`) from the
maintainer's detector contract, plus `ci-baseline-cors-arbitrary-origin-credentials`. The new CORS
rule is a paired configuration check: it requires both arbitrary-origin approval/reflection and
credentialed sharing. A post-authoring comparison with the closest current Semgrep analog found a
different taint-mode rule that tracks request input to an allow-origin header (CWE-346) without
requiring credentialed CORS; shared header/API tokens are canonical functional idioms. No message or
subpattern expression was copied. Project CI Enhancement 2 adds four independently authored
TypeScript evidence analyzers (`ci-ai-security-header-disabled`,
`ci-ai-unsafe-production-csp`, `ci-ai-insecure-session-cookie`, and
`ci-ai-supabase-captcha-token-missing`). They were authored from the maintainer's
three-state evidence contract and current primary framework documentation, not from a
third-party detection corpus. No registry rule expression was referenced or copied. The
unsafe tool-execution rule was independently authored from the local precision contract and
public API idioms, then validated against pinned public repositories; no third-party rule
expression or source implementation was copied. The
Flutter/Dart pack adds six independently authored TypeScript analyzers for Dart source:
`ci-flutter-tls-verification-disabled`, `ci-flutter-sensitive-shared-preferences`,
`ci-flutter-webview-untrusted-content`, `ci-flutter-sensitive-log`,
`ci-flutter-supabase-privileged-key-client`, and `ci-flutter-cleartext-network`.
They were written for CodeInspectus from the maintainer's six detector contracts and primary
Dart/Flutter security/API documentation. They are not ports, translations, or derived expressions
from Opengrep, Semgrep, Trivy, or another rule corpus. This records original first-party authorship
under the existing self-diligence frame; it is **not** an independent legal review. The human legal
gate stays **de-risked, not closed**. The Android/iOS packs add eight independently authored
TypeScript repository-configuration rule implementations:
`ci-android-debuggable-release`, `ci-android-cleartext-traffic`, `ci-android-user-ca-trust`,
`ci-android-exported-file-provider`, `ci-ios-ats-global-arbitrary-loads`,
`ci-ios-ats-insecure-domain-exception`, `ci-ios-ats-weak-tls`, and
`ci-ios-data-protection-disabled`. They were written for CodeInspectus from the maintainer's
detector contracts and platform configuration semantics, not ported or translated from a
third-party detection corpus. This is the same first-party authorship record, not an independent
legal review. No new CWE-to-compliance-control mapping claim is made for these rules.
The React Native and Expo packs add six independently authored TypeScript structural rules:
`ci-react-native-sensitive-async-storage`, `ci-react-native-webview-untrusted-content`,
`ci-react-native-webview-mixed-content`, `ci-react-native-webview-universal-file-access`,
`ci-expo-secret-in-public-config`, and `ci-expo-unsigned-cleartext-updates`. They were written for
CodeInspectus from the maintainer's detector contracts and primary React Native, React Native
WebView, and Expo configuration/update documentation. They were not ported, translated, or derived
from Opengrep, Semgrep, Trivy, or another detection corpus. This is an original first-party
authorship record under the existing self-diligence frame, not an independent legal clearance.
The Python AI/API pack adds ten independently authored TypeScript structural rules:
`ci-python-hardcoded-signing-secret`, `ci-python-credentialed-cors-all-origins`,
`ci-python-untrusted-file-response`, `ci-python-untrusted-redirect`,
`ci-python-untrusted-template-source`, `ci-python-llm-output-dangerous-html`,
`ci-python-faiss-dangerous-deserialization`, `ci-python-langchain-web-loader-ssrf`, and
`ci-python-prompt-injection-sink`, and `ci-python-llm-tool-argument-command-execution`. They were written
for CodeInspectus from the maintainer's detector contracts and primary Python framework/API
documentation, including LangChain's documented FAISS and WebBaseLoader contracts, Python's pickle
warning, and OWASP's SSRF and GenAI prompt-injection/excessive-agency guidance.
They were not ported, translated, or derived from Opengrep, Semgrep, Trivy, or
another detection corpus. The Lezer Python parser and smol-toml dependency licenses are reproduced
in `THIRD-PARTY-NOTICES.md`; those parsing libraries do not supply detection rules. This is an
original first-party authorship record under the existing self-diligence frame, not an independent
legal clearance.
The Go AI pack adds one independently authored TypeScript structural rule,
`ci-go-llm-tool-argument-command-execution`. It was written for CodeInspectus from the maintainer's
detector contract, the official OpenAI Go SDK data shape, Go `os/exec` semantics, and OWASP
improper-output-handling/excessive-agency guidance. It was not ported, translated, or derived from
Opengrep, Semgrep, Trivy, or another detection corpus. This is an original first-party authorship
record under the existing self-diligence frame, not an independent legal clearance.
The Java AI pack adds one independently authored TypeScript structural rule,
`ci-java-llm-tool-argument-command-execution`. It was written for CodeInspectus from the
maintainer's detector contract, the official OpenAI Java SDK data shape, Java process semantics,
and OWASP improper-output-handling/excessive-agency guidance. It was not ported, translated, or
derived from Opengrep, Semgrep, Trivy, or another detection corpus. This is an original
first-party authorship record under the existing self-diligence frame, not an independent legal
clearance.
The C# AI pack adds one independently authored TypeScript structural rule,
`ci-csharp-llm-tool-argument-command-execution`. It was written for CodeInspectus from the
maintainer's detector contract, the official OpenAI .NET SDK data shape, .NET process semantics,
and OWASP improper-output-handling/excessive-agency guidance. It was not ported, translated, or
derived from Opengrep, Semgrep, Trivy, or another detection corpus. This is an original
first-party authorship record under the existing self-diligence frame, not an independent legal
clearance.
The PHP AI pack adds one independently authored TypeScript structural rule,
`ci-php-llm-tool-argument-command-execution`. It was written for CodeInspectus from the maintainer's
detector contract, the community-maintained `openai-php/client` tool-call data shape, PHP command
execution semantics, and OWASP improper-output-handling/excessive-agency guidance. It was not
ported, translated, or derived from Opengrep, Semgrep, Trivy, or another detection corpus. The PHP
client is not represented as an official OpenAI SDK. This is an original first-party authorship
record under the existing self-diligence frame, not an independent legal clearance.
The Rust AI pack adds one independently authored TypeScript structural rule,
`ci-rust-llm-tool-argument-command-execution`. It was written for CodeInspectus from the
maintainer's detector contract, the community-maintained `async-openai` tool-call data shape,
standard/Tokio process and Bollard Docker exec semantics, and OWASP improper-output-handling/
excessive-agency guidance. It was not ported, translated, or derived from Opengrep, Semgrep,
Trivy, or another detection corpus. `async-openai` is not represented as an official OpenAI SDK.
This is an original first-party authorship record under the existing self-diligence frame, not an
independent legal clearance.
The Ruby AI pack adds one independently authored TypeScript structural rule,
`ci-ruby-llm-tool-argument-command-execution`. It was written for CodeInspectus from the
maintainer's detector contract, the official OpenAI Ruby SDK Chat/Responses tool-call data shapes,
Ruby process/Open3 semantics, and OWASP improper-output-handling/excessive-agency guidance. It was
not ported, translated, or derived from Opengrep, Semgrep, Trivy, or another detection corpus. This
is an original first-party authorship record under the existing self-diligence frame, not an
independent legal clearance.
The Firebase configuration pack adds three independently authored TypeScript structural rules for
literal unconditional public writes in Firestore, Cloud Storage, and Realtime Database Security
Rules. They were written for CodeInspectus from the maintainer's precision contract and Firebase's
documented rule semantics, not ported, translated, or derived from Opengrep, Semgrep, Trivy, or
another detection corpus. This is an original first-party authorship record under the existing
self-diligence frame, not an independent legal clearance.
The GitHub Actions workflow pack adds two independently authored TypeScript structural rules for
direct attacker-controlled GitHub context interpolation in shell steps and exact privileged
pull-request checkout-and-execute chains. They were written for CodeInspectus from the maintainer's
precision contract and GitHub's documented Actions security model, not ported, translated, or
derived from Opengrep, Semgrep, Trivy, or another detection corpus. The `yaml` parser supplies
syntax parsing only. This is an original first-party authorship record under the existing
self-diligence frame, not an independent legal clearance.
The JavaScript baseline implementation is independently authored TypeScript. After exact shadow
parity, `ci-baseline-weak-hash` and `ci-baseline-weak-cipher` moved to the native SAST pack. Both
original YAML rules remain active as reconciliation references and fallbacks. Exact pairs surface
native-only provenance before global dedup; Opengrep-only or metadata-mismatched pairs remain
Opengrep findings, native-only pairs are suppressed while Opengrep ran, and native results surface
when Opengrep is unavailable. This changes catalog ownership without claiming the contextual rules
are confirmed exploitable vulnerabilities.

---

## Provenance summary (the headline for counsel)

- **All 88 custom detections are CodeInspectus-original work, licensed MIT.** In
  `manifest.json` every `custom_rules` entry carries `"source": "codeinspectus-custom"`,
  and the Opengrep ruleset carries `"source": "codeinspectus-mit"` / `"license": "MIT"`.
- **No detection copies copyrightable expression from a third-party corpus.** For the Opengrep
  SAST rules the public Semgrep/Opengrep registry **was referenced during authoring** (the rules
  were brainstormed by the maintainer with an AI assistant, registry open as a reference) -- but
  **no copyrightable expression was copied**: messages and subpattern structure are independently
  authored, and the residual resemblance is the **forced functional form** of each check (e.g.
  `algorithms: ["none"]`, the `$EL.innerHTML = $X` sink shape) -- an unprotectable **convergent
  idiom** (merger / scenes a faire) that predates the registries. Concordant with the CG-09
  structural audit (`docs/RULE-ORIGINALITY-AUDIT.md`: 0 of the historical 19 show copied expression,
  with the twentieth rule covered by its 2026-07-26 addendum). The two
  highest-overlap rules (`ci-baseline-jwt-alg-none`, `ci-baseline-dom-xss-innerhtml`) were classed
  **CONVERGENT-IDIOM by three concordant reviews** (CG-09 audit + GPT-5.5 + Gemini Pro; see
  `docs/legal/RULE-DERIVATION-REVIEWS.md`) and were reworded + completeness-fixed in CG-13. The
  rules are also deliberately **simpler than the registry equivalents (syntactic, not
  taint-mode)** -- affirmative evidence against copying. No inbound license to reconcile; human
  legal gate **de-risked, not closed**.
- The Opengrep rules use **Semgrep/Opengrep YAML *syntax*** (a pattern language, not a
  copyrightable corpus); the *content* (patterns + metadata) is asserted original and is
  **not** lifted from `opengrep/opengrep-rules` (LGPL-2.1 **+ Commons Clause**) or
  `semgrep/semgrep-rules` (Semgrep Rules License v1.0). This is the legally-sensitive group
  because it *resembles the registry in form*; see
  `detection-db/opengrep-rules/security-baseline/LICENSE-PROVENANCE.md`.
- The Gitleaks rules are original regexes; the AI-code and native mobile-configuration analyzers
  are original TypeScript. Neither has a registry equivalent.

**Method for the reviewer:** every rule id below is greppable in the cited file. Diff the
Opengrep YAML against the upstream registries in a scratch dir if desired — but do **not**
bundle them.

---

## Bundled engines + the engine-authored rulesets in use

The three scan engines are **external SHA-pinned binaries**, **not** npm dependencies. They
are downloaded and verified by `codeinspectus repair-engines` into a per-machine managed
dir (`~/.codeinspectus/`); they are **not** redistributed inside the npm tarball. `npm pack`
ships runtime assets only (`dist/`, `data/`, `detection-db/`, `engines.lock.json`,
`README.md`). So CodeInspectus distributes **pins + download/verify code**, not the engine
binaries or their data.

Versions are cited from **`engines.lock.json` (ground truth)** — *not* the PRD, whose
§0.2/§5 numbers (Opengrep 1.21.0, Trivy 0.71.1) have since drifted.

| Engine | Version (`engines.lock.json`) | Engine license | Engine-authored ruleset in use | Ruleset license | In npm tarball? |
|---|---|---|---|---|---|
| Opengrep | **1.23.0** | LGPL-2.1 (PRD §4.1 / §11) | **None.** Runs only CI's `security-baseline`; explicitly **not** `--config auto` (`src/engines/opengrep.ts`) | — | Binary: **No**. CI rules: yes (`detection-db/`) |
| Gitleaks | **8.30.1** | MIT (CLI; PRD §4.2) | Gitleaks' **built-in default** secret rules (`[extend] useDefault = true` in `codeinspectus.toml`) | MIT (gitleaks-authored) | Binary: **No**. CI `.toml`: yes |
| Trivy | **0.71.2** | Apache-2.0 (PRD §4.3) | Trivy built-in **vuln / misconfig / secret / license** scanners + the Trivy **vuln DB** | Apache-2.0 (engine); **DB = aggregated third-party advisory data, heterogeneous licenses** | Binary + DB: **No** (downloaded) |

Engine-license confirmation: PRD §11 line 400 — *"Gitleaks MIT, Trivy Apache-2.0, Opengrep
LGPL-2.1 — all permissive for bundling."* The human reviewer should re-confirm each
against the `LICENSE` file of the exact pinned release.

**What this means at scan time:** findings can carry engine-authored rule ids that are *not*
`codeinspectus-*` (e.g. Gitleaks default ids like `generic-api-key`, Trivy CVE ids). Those
come from the MIT/Apache-2.0 engines, not from CodeInspectus's corpus, and are clean to use.

---

## Inventory — Opengrep SAST rules (20)

Path: `detection-db/opengrep-rules/security-baseline/`. **Origin: independently authored,
MIT.** Convergent functional idioms; the public registry was referenced during authoring,
**no expression copied** (merger / scenes a faire). See LICENSE-PROVENANCE.md +
`docs/legal/RULE-DERIVATION-REVIEWS.md`.

| Rule id | File | Langs | CWE | What it flags |
|---|---|---|---|---|
| `ci-baseline-weak-hash` | `crypto.yaml` | js,ts | CWE-327 | Weak hashing algorithm (MD5/SHA1) |
| `ci-baseline-weak-cipher` | `crypto.yaml` | js,ts | CWE-327 | Weak/broken cipher (DES/RC4/3DES) |
| `ci-baseline-insecure-random-security` | `crypto.yaml` | js,ts | CWE-338 | `Math.random()` for a security-sensitive value |
| `ci-baseline-weak-hash-python` | `crypto.yaml` | python | CWE-327 | Weak hashing algorithm (MD5/SHA1) |
| `ci-baseline-insecure-deserialization-node` | `deserialization.yaml` | js,ts | CWE-502 | node-serialize `unserialize()` on untrusted data |
| `ci-baseline-insecure-deserialization-python` | `deserialization.yaml` | python | CWE-502 | Insecure deserialization via an untrusted loader |
| `ci-baseline-sql-injection-string-build` | `injection.yaml` | js,ts | CWE-89 | SQL built by string concat/template |
| `ci-baseline-sql-injection-python` | `injection.yaml` | python | CWE-89 | SQL built by string formatting |
| `ci-baseline-command-injection` | `injection.yaml` | js,ts | CWE-77 | Untrusted data to a shell-exec sink |
| `ci-baseline-command-injection-python` | `injection.yaml` | python | CWE-77 | Shell command from non-literal data |
| `ci-baseline-dangerous-eval` | `injection.yaml` | js,ts | CWE-94 | Dynamic eval of a non-literal |
| `ci-baseline-eval-python` | `injection.yaml` | python | CWE-94 | Dynamic eval/exec of non-literal input |
| `ci-baseline-nosql-injection` | `injection.yaml` | js,ts | CWE-943 | NoSQL query operator from request data |
| `ci-baseline-path-traversal` | `injection.yaml` | js,ts | CWE-22 | Filesystem path from request input |
| `ci-baseline-ssrf-request-from-input` | `ssrf.yaml` | js,ts | CWE-918 | Outbound request URL from request input |
| `ci-baseline-cors-wildcard-credentials` | `web-misconfig.yaml` | js,ts | CWE-942 | CORS wildcard origin with credentials |
| `ci-baseline-cors-arbitrary-origin-credentials` | `web-misconfig.yaml` | js,ts | CWE-942 | Credentialed CORS unconditionally accepts or reflects arbitrary origins |
| `ci-baseline-insecure-cookie` | `web-misconfig.yaml` | js,ts | CWE-1004 | Session cookie without httpOnly/secure |
| `ci-baseline-jwt-alg-none` | `web-misconfig.yaml` | js,ts | CWE-347 | JWT verification accepts alg `none` |
| `ci-baseline-dom-xss-innerhtml` | `xss.yaml` | js,ts | CWE-79 | DOM XSS via innerHTML/outerHTML sink |

## Inventory — Gitleaks custom secret rules (3)

Path: `detection-db/gitleaks/codeinspectus.toml`. **Origin: CodeInspectus-original ·
License: MIT · Derived-from: none.** (The file also sets `[extend] useDefault = true`, so
Gitleaks' own MIT default rules run alongside these three.)

| Rule id | CWE | What it flags |
|---|---|---|
| `codeinspectus-stripe-live-secret` | CWE-798 | Stripe live-mode secret key |
| `codeinspectus-supabase-service-role` | CWE-798 | Supabase service_role JWT (bypasses RLS) |
| `codeinspectus-anthropic-key` | CWE-798 | Anthropic API key |

## Inventory — first-party native rules (67) — the moat

Paths: `src/ai-checks/*.ts` and `src/packs/{flutter,android,ios,react-native,expo,python-ai-api,go,java,csharp,php,rust,ruby,firebase,github-actions,javascript-baseline}/*.ts`
(TypeScript implementations).
**Origin: CodeInspectus-original · License: MIT · Derived-from: none.**

### JavaScript/TypeScript pack (24)

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-ai-client-hardcoded-secret` | `client-secrets.ts` | CWE-798 / 312 | Hard-coded secret in client-reachable code |
| `ci-ai-secret-in-bundle` | `client-secrets.ts` | CWE-798 / 312 | Secret compiled into shipped bundle |
| `ci-ai-public-env-secret` | `client-secrets.ts` | CWE-798 / 312 | Secret exposed via client-visible env prefix |
| `ci-ai-supabase-service-role-client` | `client-secrets.ts` | CWE-798 / 285 | Supabase service_role key in client-reachable code |
| `ci-ai-llm-key-browser-exposed` | `client-secrets.ts` | CWE-798 / 312 | LLM SDK client allows browser use (`dangerouslyAllowBrowser: true`) |
| `ci-ai-rls-using-true` | `supabase-rls.ts` | CWE-863 / 285 | Final effective RLS policy state is fully open with `USING (true)` — predicate matches every row |
| `ci-ai-rls-missing` | `supabase-rls.ts` | CWE-862 / 285 | Public table created without Row Level Security |
| `ci-ai-rls-inverted-auth` | `supabase-rls.ts` | CWE-863 | RLS policy tests aud/role instead of user identity |
| `ci-ai-edge-fn-no-auth` | `supabase-rls.ts` | CWE-862 | Supabase Edge Function with no auth verification |
| `ci-ai-storage-rls-public` | `supabase-rls.ts` | CWE-863 / 285 | Permissive `USING (true)` policy on `storage.objects` (public bucket files) |
| `ci-ai-prompt-injection-sink` | `prompt-injection.ts` | CWE-1427 | Potential prompt-injection sink |
| `ci-ai-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Model-produced tool argument reaches import-proven Node shell execution without a visible checked guard |
| `ci-ai-llm-output-dynamic-execution` | `llm-dynamic-execution.ts` | CWE-94 / 78 / 1426 | Recognized model output reaches global dynamic-code or import-proven shell-string execution without a validated replacement |
| `ci-ai-nextjs-admin-route-no-authz` | `nextjs-admin-route.ts` | CWE-862 / 863 / 306 | Conventional Next.js admin API handler lacks visible authentication or server-controlled role/permission authorization |
| `ci-ai-client-metadata-authz` | `metadata-authz.ts` | CWE-639 / 284 | Authorization decision trusts client-writable Supabase `user_metadata` |
| `ci-ai-llm-output-dangerous-html` | `llm-dangerous-html.ts` | CWE-79 / 116 | Untrusted or model output rendered into a React raw-HTML `__html` sink |
| `ci-ai-client-error-leak` | `api-boundary.ts` | CWE-209 | Raw/internal error detail returned to an API client |
| `ci-ai-sensitive-api-response` | `api-boundary.ts` | CWE-201 | Explicit credential or password field returned in an API response |
| `ci-ai-unvalidated-request-write` | `api-boundary.ts` | CWE-915 | Whole request object reaches a common database write without visible validation/allow-listing |
| `ci-ai-sensitive-log` | `api-boundary.ts` | CWE-532 | Explicit credential/header/cookie or auth/payment request body reaches a log sink |
| `ci-ai-security-header-disabled` | `security-controls.ts` | CWE-693 | A recognized response layer explicitly disables, removes, or neutralizes a security header |
| `ci-ai-unsafe-production-csp` | `security-controls.ts` | CWE-693 | Enforced production script policy includes bare wildcard or `'unsafe-eval'` |
| `ci-ai-insecure-session-cookie` | `security-controls.ts` | CWE-1004 / 614 | Auth/session cookie explicitly uses insecure attributes |
| `ci-ai-supabase-captcha-token-missing` | `security-controls.ts` | CWE-693 | Checked-in CAPTCHA enablement paired with a recognized Supabase auth call missing `captchaToken` |

### Flutter/Dart pack (6)

Applicability is intentionally narrow: this pack runs only when bounded repository evidence identifies
a Flutter project. It uses a first-party token-aware Dart lexical/structural layer, without type
resolution or whole-program dataflow. Generated files and test/example corpora are excluded from
project-root scans unless scanned directly. Unreadable Dart files, files over 2 MiB, and source
beyond 10,000 files/64 MiB are skipped and surfaced in pack coverage. These are repository-source
checks, not runtime mobile testing, native Pub vulnerability/SBOM analysis, or a claim of complete
Flutter security coverage. Android/iOS repository configuration is owned by the separate packs
below.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-flutter-tls-verification-disabled` | `tls.ts` | CWE-295 | `badCertificateCallback` unconditionally accepts invalid certificates |
| `ci-flutter-sensitive-shared-preferences` | `preferences.ts` | CWE-312 | A proven SharedPreferences receiver stores explicit credential material |
| `ci-flutter-webview-untrusted-content` | `webview.ts` | CWE-20 / 346 | Route/deep-link input reaches an unrestricted JavaScript WebView without a visible exact HTTPS host allowlist |
| `ci-flutter-sensitive-log` | `logs.ts` | CWE-532 | A recognized Dart/Flutter log sink receives explicit credential data outside a visible `kDebugMode` guard |
| `ci-flutter-supabase-privileged-key-client` | `supabase.ts` | CWE-798 / 312 / 285 | A Supabase service-role or secret key reaches Flutter client initialization |
| `ci-flutter-cleartext-network` | `cleartext.ts` | CWE-319 | A literal cleartext production URL reaches a recognized network or WebView sink |

### Android configuration pack (4)

Applicability requires bounded Android project evidence. The pack uses a structured XML parser and
supports explicit root/main/release manifests, literal Network Security Config references, and the
documented release overlay/resource precedence. It does not run Gradle, expand arbitrary
product-flavor/build-type DSL or placeholders, model the full manifest merger, or claim runtime or
complete Android security coverage. Symlinks and external/DTD entities are never followed or
resolved; malformed, dynamic, unreadable, oversized, or bounded-out evidence is reported as a
coverage limitation.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-android-debuggable-release` | `android-config.ts` | CWE-489 | A release manifest explicitly enables application debugging |
| `ci-android-cleartext-traffic` | `android-config.ts` | CWE-319 | Effective production manifest/network-security configuration explicitly permits cleartext traffic |
| `ci-android-user-ca-trust` | `android-config.ts` | CWE-295 | Effective production network-security configuration trusts user-added certificate authorities |
| `ci-android-exported-file-provider` | `android-config.ts` | CWE-926 | An AndroidX FileProvider is exported to other applications |

### iOS configuration pack (4)

Applicability requires bounded iOS project evidence. The pack parses XML plists/entitlements and
resolves only literal Release/AppStore `INFOPLIST_FILE` and `CODE_SIGN_ENTITLEMENTS` settings with
iPhone platform evidence. It does not run Xcode, expand xcconfig/preprocessing/dynamic variables,
inspect provisioning profiles, or claim runtime or complete iOS security coverage. Symlinks and
external/DTD entities are never followed or resolved; binary, malformed, dynamic, unreadable,
oversized, or bounded-out evidence is reported as a coverage limitation.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-ios-ats-global-arbitrary-loads` | `config.ts` | CWE-319 | App Transport Security globally permits arbitrary network loads |
| `ci-ios-ats-insecure-domain-exception` | `config.ts` | CWE-319 | ATS permits insecure HTTP for a non-local production domain |
| `ci-ios-ats-weak-tls` | `config.ts` | CWE-327 | ATS weakens TLS requirements for a non-local production domain |
| `ci-ios-data-protection-disabled` | `config.ts` | CWE-311 | Default iOS data protection is explicitly disabled |

### React Native pack (4)

Applicability requires an exact `react-native` package dependency or statically proven Expo project
evidence. Proven Expo evidence activates both packs because Expo uses React Native; bare React
Native evidence does not activate Expo configuration rules. The pack uses bounded,
non-executing JavaScript/TypeScript/JSX structure analysis with explicit import and receiver
provenance. It does not resolve types or modules, evaluate dynamic props, perform whole-program or
path-sensitive dataflow, or claim runtime or complete React Native security coverage. Generated,
dependency, test, example, and similar non-production trees are excluded from project-root scans;
symlinked, unreadable, malformed, over-2 MiB, over-200,000-token, or over-64-level files are skipped.
Project discovery is capped at 50,000 entries, 10,000 files, 64 MiB, 1,000,000 tokens, and 32
directory levels; every omission is reported as a coverage limitation.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-react-native-sensitive-async-storage` | `async-storage.ts` | CWE-312 | A proven AsyncStorage receiver stores explicit credential or session material |
| `ci-react-native-webview-untrusted-content` | `webview-untrusted.ts` | CWE-20 / 346 | Route, deep-link, or search-parameter content reaches an imported JavaScript-enabled WebView without a visible safety boundary |
| `ci-react-native-webview-mixed-content` | `webview-mixed-content.ts` | CWE-319 | An imported WebView explicitly permits mixed content for a production HTTPS source |
| `ci-react-native-webview-universal-file-access` | `webview-universal-file-access.ts` | CWE-200 / 942 | A file-backed imported WebView explicitly permits universal origin access while JavaScript remains enabled |

### Expo pack (2)

Applicability requires exact Expo package evidence or an explicit top-level `expo` object in static
application config; generic root `name` + `slug` fields alone do not activate the pack. The pack
parses bounded JSON/JSONC and direct-object JavaScript/TypeScript configuration at
the scan root and eligible nested package roots without importing, evaluating, or executing target
modules. Discovery is capped at 20,000 entries, 500 package roots, and 24 levels; individual configs
at 1 MiB/100,000 tokens; aggregate reads at 4,096 files/4 MiB; and aggregate static parsing at
250,000 tokens/25,000 properties. Dynamic
configuration, spreads, unresolved values, symlinks, malformed input, and bounded-out evidence are
omitted and reported; the pack does not prove deployed update settings or claim complete Expo
security coverage.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-expo-secret-in-public-config` | `config.ts` | CWE-798 / 312 | A non-public server secret environment value is exposed through public Expo application config |
| `ci-expo-unsigned-cleartext-updates` | `config.ts` | CWE-494 / 319 | Enabled Expo updates use a cleartext production URL without a literal code-signing certificate |

### Python AI/API pack (10)

Applicability requires bounded Python/package/framework evidence. Eight rules emit only the
documented exact high-confidence source/sink or literal-configuration shapes; the prompt-injection
and model-tool shell-execution rules emit medium-confidence potential-risk findings. The pack uses a Lezer syntax gate
and source-ordered intrafile analysis without importing or executing target code. It does not
provide type resolution, a module graph, interprocedural flow, or path-sensitive branch merging.
Lezer-validated format strings are opaque dynamic values whose replacement expressions are not
inspected; leading-tab indentation fails closed. Generated, migration,
dependency, build, test, fixture, demo, sample, and example trees are excluded from project-root
scans; unsupported, malformed, symlinked, unreadable, oversized, and bounded-out input is reported
as a coverage limitation rather than inferred safe.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-python-hardcoded-signing-secret` | `hardcoded-signing-secret.ts` | CWE-798 / 321 | A non-empty literal is assigned to a proven Django, Flask, or Starlette signing-secret setting |
| `ci-python-credentialed-cors-all-origins` | `credentialed-cors.ts` | CWE-942 / 346 | A proven framework CORS configuration combines every origin with credentials |
| `ci-python-untrusted-file-response` | `file-response.ts` | CWE-22 / 73 | Proven request input reaches a framework file-response sink without a supported path boundary |
| `ci-python-untrusted-redirect` | `redirect.ts` | CWE-601 | Proven request input reaches a framework redirect sink without a supported destination boundary |
| `ci-python-untrusted-template-source` | `template-source.ts` | CWE-1336 / 94 | Proven request input becomes dynamic Jinja template source and is rendered |
| `ci-python-llm-output-dangerous-html` | `llm-html.ts` | CWE-79 / 116 | Proven OpenAI/Anthropic output reaches an HTML response without supported sanitization |
| `ci-python-faiss-dangerous-deserialization` | `faiss-deserialization.ts` | CWE-502 | A proven LangChain FAISS load explicitly enables pickle deserialization; exploitability depends on artifact origin and integrity |
| `ci-python-langchain-web-loader-ssrf` | `langchain-web-loader-ssrf.ts` | CWE-918 | A proven LangChain WebBaseLoader fetches a complete URL derived from web request input; network and runtime boundaries remain unverified |
| `ci-python-prompt-injection-sink` | `prompt-injection.ts` | CWE-1427 | Framework-proven request input reaches privileged OpenAI/Anthropic instructions, or tool-enabled prompt input; caller authorization and runtime tool controls remain unverified |
| `ci-python-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Model-produced OpenAI/Anthropic tool arguments reach a proven Python shell API directly or through one named wrapper without a visible checked guard |

### Go AI pack (1)

Applicability requires both Go source/module evidence and the exact official
`github.com/openai/openai-go` module. The pack performs bounded, source-ordered intrafile analysis
without building or executing target code. It recognizes direct aliases, `encoding/json.Unmarshal`,
one local parsing helper, and one local command wrapper; checked rejection/approval or allowlist
guards and validated replacement values suppress findings. It does not provide general Go SAST,
type or module resolution, cross-module flow, support for other model SDKs, runtime sandbox proof, or
complete agent/tool security coverage. Symlinked, malformed, unreadable, oversized, generated,
test/example, and bounded-out source is skipped or reported according to the pack limitations.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-go-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Official OpenAI Go tool-call arguments reach an import-proven recognized `os/exec` shell invocation without a visible checked guard |

### Java AI pack (1)

Applicability requires Java source/build evidence and an exact official `com.openai:openai-java`
or `com.openai:openai-java-core` dependency. The pack performs bounded, source-ordered intrafile
analysis without building or executing target code. It recognizes official imported tool-call
argument types, direct aliases, one local parsing helper, and one local command wrapper. A
`ProcessBuilder` must actually be started; checked rejection/approval or allowlist guards and
validated replacement values suppress findings. It does not provide general Java SAST, type/module
resolution, support Spring AI/LangChain4j/Azure OpenAI, or prove runtime authorization/sandboxing.
Java text blocks and malformed, symlinked, unreadable, oversized, generated, test/example, or
bounded-out source fail closed or are reported according to the pack limitations.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-java-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Official OpenAI Java tool-call arguments reach an actually-started recognized Java shell invocation without a visible checked guard |

### C# AI pack (1)

Applicability requires C# source/project evidence and an exact official `OpenAI` NuGet package
reference. The pack performs bounded, intrafile analysis without compiling or executing target
code. It recognizes official `ChatToolCall.FunctionArguments`, direct aliases, supported
`System.Text.Json` dictionary/property extraction, one local parsing helper, and one local command
wrapper. `System.Diagnostics.Process` must actually be started with a recognized shell and command
flag; checked rejection/approval or allowlist guards and validated replacement values suppress
findings. It does not provide general C# SAST, resolve types or project references, support Semantic
Kernel/Azure OpenAI, trace cross-file flow, inspect raw-string contents, or prove runtime
authorization/sandboxing. Malformed raw strings and symlinked, unreadable, oversized, generated,
test/example, build, or bounded-out source fail closed or are reported according to pack limits.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-csharp-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Official OpenAI .NET tool-call arguments reach an actually-started recognized `System.Diagnostics.Process` shell invocation without a visible checked guard |

### PHP AI pack (1)

Applicability requires PHP source/Composer evidence and exact `openai-php/client` or
`openai-php/laravel` package evidence. These packages are community maintained, not official
OpenAI SDKs. The pack performs bounded, intrafile analysis without installing dependencies or
executing target code. It recognizes tool-call `function->arguments`, direct aliases, associative
`json_decode` extraction, one local parsing helper, one local command wrapper, and one exact mapped
variadic method dispatch reaching `exec`, `system`, `shell_exec`, or `passthru`. Checked approval
or full-command allowlists and validated replacement values suppress findings; a first-token
executable check does not neutralize metacharacters in the rest of a command. It does not provide
general PHP SAST, resolve types or the Composer graph, trace cross-file flow, support generic
callable dispatch, or prove runtime authorization/sandboxing. Heredoc/nowdoc, malformed, symlinked,
unreadable, oversized, generated, test/example, build, or bounded-out source fails closed or is
reported according to pack limits.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-php-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Community OpenAI PHP ecosystem tool-call arguments reach a PHP command-execution sink without a visible checked guard |

### Rust AI pack (1)

Applicability requires Rust source/Cargo evidence and exact `async-openai` dependency evidence.
The crate is community maintained, not an official OpenAI SDK. The pack performs bounded,
source-ordered intrafile analysis without fetching crates, invoking rustc, building, or executing
target code. It recognizes imported async-openai tool-call arguments, direct aliases,
`serde_json` extraction, one recognized `generate_function_call` result, one local command
wrapper, import-proven standard/Tokio process shells, and literal Bollard Docker exec shell
vectors paired with `create_exec` and `start_exec`. Checked approval/allowlist rejection and
validated replacement values suppress findings. It does not provide general Rust SAST, resolve
types or the Cargo graph, trace cross-crate flow, support generic dispatch, or prove runtime
container isolation, authorization, or sandboxing. Malformed, symlinked, unreadable, oversized,
generated, test/example, build, or bounded-out source fails closed or is reported according to
pack limits.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-rust-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Community async-openai tool-call arguments reach a recognized Rust process or Bollard Docker exec shell invocation without a visible checked guard |

### Ruby AI pack (1)

Applicability requires Ruby source/Bundler evidence and the exact official `openai` gem in a
production Gemfile or runtime gemspec dependency. Gemfile.lock alone does not activate the pack
because Bundler lockfiles do not preserve dependency groups. The pack performs bounded, source-ordered
intrafile analysis without installing gems or executing target code. It recognizes Chat tool-call
`function.arguments`, explicitly typed Responses function-tool `.arguments`, direct aliases,
`JSON.parse` command extraction, one local parsing helper, and one local command wrapper reaching
`system`, `exec`, `IO.popen`, or import-proven Open3 single-string or explicit shell-vector calls.
Checked approval/full-command allowlists and validated replacement values suppress findings. It
does not provide general Ruby SAST, resolve types or the Bundler graph, trace cross-file flow,
support backticks/percent-x/spawn APIs, or prove runtime authorization/sandboxing. Heredocs,
malformed, symlinked, unreadable, oversized, generated, spec/test/example, build, or bounded-out
source fails closed or is reported according to pack limits.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-ruby-llm-tool-argument-command-execution` | `unsafe-tool-execution.ts` | CWE-78 / 1426 | Official OpenAI Ruby tool-call arguments reach a recognized Ruby command-execution sink without a visible checked guard |

### Firebase configuration pack (3)

Applicability requires Firebase project, package, or recognized rule-file evidence. The pack
performs bounded, read-only parsing without invoking Firebase tooling or executing target code.
Firestore and Cloud Storage findings require exact service declarations plus a literal
write/create/update/delete grant with no condition or a condition exactly equal to `true`;
Realtime Database findings require strict JSON and a `.write` value of boolean or exact string
`true`. Public reads and non-literal conditions stay silent. The pack does not evaluate helper
functions, deployed policy, IAM, App Check, or runtime access.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-firebase-firestore-public-write` | `firebase-config.ts` | CWE-862 / 285 | A literal unconditional public write grant in Cloud Firestore Security Rules |
| `ci-firebase-storage-public-write` | `firebase-config.ts` | CWE-862 / 285 | A literal unconditional public write grant in Cloud Storage Security Rules |
| `ci-firebase-realtime-database-public-write` | `firebase-config.ts` | CWE-862 / 285 | A Realtime Database `.write` rule set to boolean or exact string `true` |

### GitHub Actions workflow pack (2)

Applicability requires direct root `.github/workflows/*.yml` or `.yaml` evidence. The pack uses
strict YAML 1.2 parsing and bounded, no-follow loading without executing workflows or target code.
The expression rule requires a documented attacker-controlled `github` context directly in `run`;
safe intermediate `env` and action `with` values stay silent. The pwn-request rule requires exact
`pull_request_target`, untrusted pull-request checkout into the default workspace, and subsequent
execution of checked-out code or a local action. Protected checkout v7 stays silent unless its
unsafe opt-in is explicit. General expression aliases, custom actions, inter-step/artifact flows,
non-checkout fetches, alternate checkout paths, runner state, deployed policy, and complete workflow
review are outside the contract.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-github-actions-untrusted-expression-command` | `workflow-security.ts` | CWE-78 / 94 | Direct attacker-controlled GitHub event context interpolated into a shell `run` step |
| `ci-github-actions-pwn-request` | `workflow-security.ts` | CWE-94 / 829 | Privileged `pull_request_target` workflow checks out an untrusted PR ref and then executes checked-out code |

### JavaScript baseline SAST pack (2)

Applicability requires detected JavaScript or TypeScript. The pack uses bounded structural parsing
and reconciles raw results against the still-active Opengrep rules before routing or global dedup.
Exact pairs surface only native producer components. Opengrep-only and metadata-mismatched results
remain Opengrep-owned; native-only candidates are suppressed while Opengrep ran; native results are
the explicit fallback if Opengrep is unavailable. These contextual rules are medium-confidence
signals, not proof that every MD5/SHA-1 or deprecated cipher call is security-sensitive.

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-baseline-weak-hash` | `rules.ts` | CWE-327 | JavaScript/TypeScript `createHash` with MD5 or SHA-1 |
| `ci-baseline-weak-cipher` | `rules.ts` | CWE-327 | DES/3DES/RC4 `createCipheriv` or deprecated password-based `createCipher` |

---

## Provenance / license flags (for the human gate)

The legal-provenance gate is a **human sign-off**; CG-08 does not grant it. Outstanding
items for the reviewer, ranked by where attention is best spent:

1. **Opengrep SAST originality (primary risk -- now de-risked).** These 20 rules resemble the
   upstream registry *in form*. The CG-09 structural audit + two independent model reviews
   (GPT-5.5, Gemini Pro) all found **convergent idiom, no copied expression** (the registry was
   referenced, not copied); see `docs/legal/RULE-DERIVATION-REVIEWS.md`. **Remaining action:** a
   qualified lawyer confirms the convergence / merger reasoning before a paid/hosted tier. If any
   single rule's originality is ever in doubt, remove it pending review rather than ship it.
2. **Trivy vuln-DB data licensing (low risk, worth a note).** Trivy's engine is Apache-2.0,
   but its vulnerability DB **aggregates third-party advisory data under mixed licenses**
   (NVD, GitHub Security Advisories, vendor feeds). CodeInspectus **does not redistribute**
   the DB (downloaded by the user at install), so this is the user's local use, not CI's
   distribution — but confirm no DB content is ever copied into the repo or tarball.
3. **Gitleaks default ruleset (low risk).** `useDefault = true` means Gitleaks' own MIT
   rules run. MIT is permissive; no action beyond noting the dependency.
4. **Engine-license re-confirmation (mechanical).** Re-confirm Opengrep LGPL-2.1 / Gitleaks
   MIT / Trivy Apache-2.0 against each pinned release's `LICENSE`; watch for any AGPL
   transitive pull-in if a hosted version is built (PRD §11).
5. **No rule is currently flagged as unclear or risky on provenance** beyond item 1's
   standing originality review. If any single rule's originality is ever in doubt, **remove
   it pending review** rather than ship it (the engine still runs; coverage just narrows).

---

## Removed rules (do not re-add)

- **`ci-ai-rls-write-open` — REMOVED (CG-03).** Flagged a table with a SELECT policy but no
  INSERT/UPDATE/DELETE policy as CWE-862. That logic is **inverted**: with RLS enabled and
  no write policy, Postgres **denies** all writes (secure-by-default), so the rule produced
  only false positives on real read-mostly tables. PRD §6.2 bullet deleted in CG-04. This is
  the rule whose removal takes the AI analyzers from 10 → 9 (and the total from 32 → 31).
- **`ci-ai-rls-using-true` — severity now tiered (CG-04).** Still detects every permissive
  `USING/WITH CHECK (true)` policy, but tiers severity by the protected table's sensitivity
  (per-user/PII or write = critical; public catalog = low) and ignores `service_role`-only
  policies and `(true)` outside a real `CREATE POLICY`.

_Generated from the source files + `detection-db/manifest.json` + `engines.lock.json`;
regenerate if the ruleset or engine pins change._
