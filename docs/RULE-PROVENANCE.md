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

_Last refreshed: CG-08 (2026-06-23). Audited against `detection-db/manifest.json`,
`engines.lock.json`, `detection-db/**`, and `src/ai-checks/**`._

---

## Reconciled detection count — **33 active CodeInspectus detections**

`detection-db/manifest.json` `custom_rules` has **33** entries:

| Group | Count | Engine | Kind | Where |
|---|---:|---|---|---|
| AI-code analyzers | **11** | `codeinspectus-ai` | `ai` | `src/ai-checks/*.ts` |
| Opengrep SAST rules | **19** | `opengrep` | `sast` | `detection-db/opengrep-rules/security-baseline/` |
| Gitleaks secret rules | **3** | `gitleaks` | `secret` | `detection-db/gitleaks/codeinspectus.toml` |
| **Total** | **33** | — | — | — |

Verified counts: 19 Opengrep rule ids and 3 Gitleaks rule ids are greppable on disk;
11 `kind: "ai"` entries in the manifest.

The authoritative current figure is **33**, decomposing as **11 AI analyzers + 19 Opengrep SAST +
3 Gitleaks** (single source of truth: `detection-db/manifest.json`). CG-25b added two original
CodeInspectus detections: `ci-ai-llm-key-browser-exposed` (B-11; `dangerouslyAllowBrowser: true`) and
`ci-ai-storage-rls-public` (B-12; permissive `USING (true)` on `storage.objects`). Both are
framework-specific AI-code failure modes (no third-party rule content referenced), consistent with the
convergent-idiom / original-work framing below.

---

## Provenance summary (the headline for counsel)

- **All 33 custom detections are CodeInspectus-original work, licensed MIT.** In
  `manifest.json` every `custom_rules` entry carries `"source": "codeinspectus-custom"`,
  and the Opengrep ruleset carries `"source": "codeinspectus-mit"` / `"license": "MIT"`.
- **No detection copies copyrightable expression from a third-party corpus.** For the Opengrep
  SAST rules the public Semgrep/Opengrep registry **was referenced during authoring** (the rules
  were brainstormed by the maintainer with an AI assistant, registry open as a reference) -- but
  **no copyrightable expression was copied**: messages and subpattern structure are independently
  authored, and the residual resemblance is the **forced functional form** of each check (e.g.
  `algorithms: ["none"]`, the `$EL.innerHTML = $X` sink shape) -- an unprotectable **convergent
  idiom** (merger / scenes a faire) that predates the registries. Concordant with the CG-09
  structural audit (`docs/RULE-ORIGINALITY-AUDIT.md`: 0 of 19 show copied expression). The two
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
- The Gitleaks rules are original regexes; the AI-code analyzers are original TypeScript.
  Neither has a registry equivalent.

**Method for the reviewer:** every rule id below is greppable in the cited file. Diff the
Opengrep YAML against the upstream registries in a scratch dir if desired — but do **not**
bundle them.

---

## Bundled engines + the engine-authored rulesets in use

The three scan engines are **external SHA-pinned binaries**, **not** npm dependencies. They
are downloaded and verified by `codeinspectus install-engines` into a per-machine managed
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

## Inventory — Opengrep SAST rules (19)

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

## Inventory — AI-code analyzers (11) — the moat

Path: `src/ai-checks/*.ts` (TypeScript). **Origin: CodeInspectus-original · License: MIT ·
Derived-from: none.**

| Rule id | File | CWE | What it flags |
|---|---|---|---|
| `ci-ai-client-hardcoded-secret` | `client-secrets.ts` | CWE-798 / 312 | Hard-coded secret in client-reachable code |
| `ci-ai-secret-in-bundle` | `client-secrets.ts` | CWE-798 / 312 | Secret compiled into shipped bundle |
| `ci-ai-public-env-secret` | `client-secrets.ts` | CWE-798 / 312 | Secret exposed via client-visible env prefix |
| `ci-ai-supabase-service-role-client` | `client-secrets.ts` | CWE-798 / 285 | Supabase service_role key in client-reachable code |
| `ci-ai-llm-key-browser-exposed` | `client-secrets.ts` | CWE-798 / 312 | LLM SDK client allows browser use (`dangerouslyAllowBrowser: true`) |
| `ci-ai-rls-using-true` | `supabase-rls.ts` | CWE-863 / 285 | RLS policy uses `USING (true)` — table fully open |
| `ci-ai-rls-missing` | `supabase-rls.ts` | CWE-862 / 285 | Public table created without Row Level Security |
| `ci-ai-rls-inverted-auth` | `supabase-rls.ts` | CWE-863 | RLS policy tests aud/role instead of user identity |
| `ci-ai-edge-fn-no-auth` | `supabase-rls.ts` | CWE-862 | Supabase Edge Function with no auth verification |
| `ci-ai-storage-rls-public` | `supabase-rls.ts` | CWE-863 / 285 | Permissive `USING (true)` policy on `storage.objects` (public bucket files) |
| `ci-ai-prompt-injection-sink` | `prompt-injection.ts` | CWE-1426 | Potential prompt-injection sink |

---

## Provenance / license flags (for the human gate)

The legal-provenance gate is a **human sign-off**; CG-08 does not grant it. Outstanding
items for the reviewer, ranked by where attention is best spent:

1. **Opengrep SAST originality (primary risk -- now de-risked).** These 19 rules resemble the
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
