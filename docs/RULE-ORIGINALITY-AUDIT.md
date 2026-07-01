# RULE-ORIGINALITY-AUDIT.md — structural originality audit of the Opengrep SAST rules

> **What this is:** an independent structural comparison of all 19 CodeInspectus Opengrep SAST
> rules against the closest same-CWE rules in the public Semgrep/Opengrep registry, to confirm
> no copyrightable expression was copied. The public registry was **referenced during
> authoring**; the finding is that any resemblance is the forced functional form of each check
> (merger / scenes a faire), **not copied expression**. The conclusion is corroborated and
> summarized in [`legal/RULE-DERIVATION-REVIEWS.md`](legal/RULE-DERIVATION-REVIEWS.md); see also
> [`RULE-PROVENANCE.md`](RULE-PROVENANCE.md).

_Structural comparison performed 2026-06-23. Investigation-only — no rule files or shipping
artifacts were changed by this audit._

## What the claim is, and what "derived" means

- **The claim under test:** all 19 `detection-db/opengrep-rules/security-baseline/*` rules are
  CodeInspectus-original, MIT, and **not copied or derived from** `opengrep/opengrep-rules`
  (LGPL-2.1 + Commons Clause) or `semgrep/semgrep-rules` (Semgrep Rules License v1.0).
- **Why it matters:** bundling either restricted corpus's *expression* would block a
  paid/hosted tier. The legally-load-bearing question is **copyright** (did CI copy
  protectable expression?), which is distinct from "did the author ever look at another rule."

## Method (and its limits — under-claimed)

- **Egress worked** from this environment (`raw.githubusercontent.com` -> 200), so this is a
  **real comparison**, not a methodology-only fallback.
- `opengrep/opengrep-rules` was confirmed to **mirror `semgrep/semgrep-rules` file paths
  exactly** (it is a relicensed fork). Comparing against semgrep-rules therefore covers both
  restricted corpora; a few opengrep paths were spot-checked and matched.
- For each of the 19 rules I located the **closest same-CWE analog(s)** in the registry and
  compared: pattern/AST shape, metavariable names, guard idioms (pattern-not), message text,
  metadata fields, and detection **mode** (syntactic vs taint).
- **Limit (stated plainly):** this is a **targeted same-class comparison** against ~20 closest
  analogs, **not** a line-by-line diff against all ~2,150 semgrep-rules / ~2,001 opengrep-rules
  files. An exhaustive diff is the deeper, separate version. No registry rule bodies are
  reproduced here (copyright); similarity is described, with at most de-minimis fragments.

## Registry files compared against (for manual re-check)

All on `semgrep/semgrep-rules@develop` (paths identical on `opengrep/opengrep-rules@main`):

`javascript/lang/security/audit/md5-used-as-password.yaml` ·
`python/lang/security/insecure-hash-algorithms-md5.yaml` ·
`python/cryptography/security/insecure-cipher-algorithms-arc4.yaml` ·
`python/lang/security/audit/eval-detected.yaml` ·
`javascript/lang/security/detect-eval-with-expression.yaml` ·
`python/lang/security/audit/dangerous-system-call-audit.yaml` ·
`python/lang/security/audit/dangerous-subprocess-use-audit.yaml` ·
`javascript/lang/security/audit/spawn-shell-true.yaml` ·
`javascript/lang/security/audit/detect-non-literal-fs-filename.yaml` ·
`javascript/lang/security/audit/sqli/node-mysql-sqli.yaml` ·
`python/django/security/injection/sql/sql-injection-using-db-cursor-execute.yaml` ·
`javascript/express/security/cors-misconfiguration.yaml` ·
`javascript/express/security/audit/express-cookie-settings.yaml` ·
`javascript/jsonwebtoken/security/jwt-none-alg.yaml` ·
`javascript/browser/security/insecure-document-method.yaml` ·
`javascript/browser/security/insecure-innerhtml.yaml` ·
`javascript/express/security/audit/express-ssrf.yaml` ·
`python/lang/security/deserialization/pickle.yaml` ·
`python/lang/security/deserialization/avoid-pyyaml-load.yaml` ·
`javascript/express/security/audit/express-third-party-object-deserialization.yaml`

## Classification key

- **likely-original** — no meaningful structural resemblance to any same-class registry rule.
- **generic-convergence** — resemblance is only the canonical shape of that CWE check (same
  canonical API token / same standard FP guard); independent authoring would converge here.
- **possible-derivation** — resemblance beyond canonical convergence; needs scrutiny.
- **HIGH-SIMILARITY-INVESTIGATE** — strong structural match; treat as likely-referenced.

## Per-rule findings (19)

| CI rule | Closest registry analog | Classification | Reasoning (own words) |
|---|---|---|---|
| `ci-baseline-weak-hash` (js) | `md5-used-as-password.yaml` | generic-convergence | Registry rule is **taint-mode**, password-specific; CI is a plain `createHash` md5/sha1 flag. Shared token is the standard Node crypto API. Different design. |
| `ci-baseline-weak-cipher` (js) | (none — registry JS cipher rule is no-IV) | likely-original | No registry rule flags `createCipheriv` des/rc4 / `createCipher`. CI's set is its own. |
| `ci-baseline-insecure-random-security` | (none for JS `Math.random`) | likely-original | Registry has no JS `Math.random`-for-secret rule. CI's distinctive metavariable-regex gate on the *variable name* (`token|secret|key|...`) is its own design. |
| `ci-baseline-weak-hash-python` | `insecure-hash-algorithms-md5.yaml` | generic-convergence | `hashlib.md5` is the only way to express it (canonical). CI even lacks the registry's `usedforsecurity=False` refinement — convergence, not copy. |
| `ci-baseline-sql-injection-string-build` (js) | `sqli/node-mysql-sqli.yaml` | generic-convergence | Registry is taint-mode, library-specific (mysql/mysql2). CI is syntactic string-concat/template on `$DB.query`. String-built-query shape is standard. |
| `ci-baseline-sql-injection-python` | `sql-injection-using-db-cursor-execute.yaml` | generic-convergence | `cursor.execute` with `%`/`+`/f-string is the canonical Python SQLi shape. CI's is simpler than the registry's. |
| `ci-baseline-command-injection` (js) | `spawn-shell-true.yaml` | likely-original | Registry JS command rules target `spawn(...,{shell:true})`; CI targets `exec`/`execSync` string-concat. Different API, no direct analog. |
| `ci-baseline-command-injection-python` | `dangerous-system-call-audit.yaml` / `dangerous-subprocess-use-audit.yaml` | generic-convergence | Shared canonical tokens (`os.system`, `subprocess`, `shell=True`). Registry rules are far more elaborate (getattr/`__import__` obfuscation, shell-array regex) and use CWE-78; CI is narrow + CWE-77. Convergence on the obvious targets. |
| `ci-baseline-dangerous-eval` (js) | `detect-eval-with-expression.yaml` | generic-convergence | Registry is taint-mode (location.* to the eval sink). CI matches the `eval` and `Function`-constructor sinks plus a not-literal guard. The eval + not-literal idiom is universal. |
| `ci-baseline-eval-python` | `eval-detected.yaml` / `exec-detected.yaml` | generic-convergence | Same eval + not-literal idiom. CI combines eval+exec, uses `$X` (narrower) vs registry ellipsis, and CWE-94 vs registry CWE-95. Convergent idiom, different specifics. |
| `ci-baseline-nosql-injection` (js) | (none — registry NoSQL is Python pymongo / Java) | likely-original | No JS NoSQL-injection rule in the registry. CI's `$COL.find` from `req` shape is its own. |
| `ci-baseline-path-traversal` (js) | `detect-non-literal-fs-filename.yaml` | generic-convergence | Registry rule is large/taint (eslint-derived). CI is syntactic `$FS.readFile($P+...)` with a metavariable-pattern gating `$P` to `req.*`. readFile(user input) is the standard shape. |
| `ci-baseline-cors-wildcard-credentials` (js) | `express/security/cors-misconfiguration.yaml` | likely-original | Registry is taint-mode header injection, **CWE-346**. CI is a one-line `cors({origin:"*",credentials:true})` middleware flag, **CWE-942**. Different rule entirely. |
| `ci-baseline-insecure-cookie` (js) | `express-cookie-settings.yaml` | likely-original | Registry rule is large/complex (missing-flag logic). CI is a single pattern flagging an explicit `httpOnly:false`. Distinct, simpler approach. |
| `ci-baseline-jwt-alg-none` (js) | `jsonwebtoken/security/jwt-none-alg.yaml` | **generic-convergence (HIGH overlap — FLAG)** | Core pattern is near-identical: both match `$JWT.verify(..., {algorithms:[...'none'...]})` with metavariable `$JWT`. **But:** CI uses **CWE-347** (registry CWE-327), adds the singular `algorithm:"none"` variant, has **no** require-jsonwebtoken guard, and its own message. The `{algorithms:['none']}` check has essentially one idiomatic form -> convergence is plausible, but this is one of two I cannot certify zero-reference from structure alone. |
| `ci-baseline-dom-xss-innerhtml` (js) | `browser/security/insecure-document-method.yaml` (+ `insecure-innerhtml.yaml`) | **generic-convergence (HIGH overlap — FLAG)** | Highest-overlap rule. Both flag `innerHTML`/`outerHTML`/`document.write` assignments with not-literal guards, same CWE-79. **But:** CI adds `insertAdjacentHTML` and the `writeln` sink (a CG-13 completeness fix — see `docs/legal/RULE-DERIVATION-REVIEWS.md`), uses metavariable `$X` (registry uses `$HTML`), and its own message. These *are* the canonical DOM-XSS sinks and the not-literal guard is the universal FP reducer, so convergence is defensible — yet this is the rule most likely to have been influenced; warrants a human eyeball + author recollection. |
| `ci-baseline-ssrf-request-from-input` (js) | `express/security/audit/express-ssrf.yaml` | likely-original | Registry is taint-mode. CI is syntactic `fetch($U+...)` / `axios.get` with a metavariable-pattern gating `$U` to `req.*`. No simple syntactic SSRF analog in the registry. |
| `ci-baseline-insecure-deserialization-node` (js) | `express-third-party-object-deserialization.yaml` | generic-convergence | Registry is taint-mode + import-gated to `node-serialize`/`serialize-to-js`. CI is a plain `$S.unserialize($X)` + not-literal. `unserialize` is the node-serialize API token; different structure. |
| `ci-baseline-insecure-deserialization-python` | `deserialization/pickle.yaml` + `avoid-pyyaml-load.yaml` | generic-convergence | `pickle.loads` is canonical. CI's YAML logic **differs**: it flags bare `yaml.load($X)` excluding `SafeLoader`, whereas the registry flags `yaml.unsafe_load` / explicit `Loader=UnsafeLoader`. Convergence on pickle, divergence on yaml. |

### Tally
- **likely-original: 7** — weak-cipher, insecure-random, command-injection (js), nosql,
  cors-wildcard-credentials, insecure-cookie, ssrf.
- **generic-convergence: 10** — weak-hash (js), weak-hash-python, sql-injection-string-build,
  sql-injection-python, command-injection-python, dangerous-eval, eval-python, path-traversal,
  insecure-deserialization-node, insecure-deserialization-python.
- **generic-convergence (HIGH overlap — FLAG): 2** — jwt-alg-none, dom-xss-innerhtml.
- **possible-derivation: 0.**
- **HIGH-SIMILARITY-INVESTIGATE: 0.**

## Cross-cutting observations

1. **Style is distinctively different from the registry.** CI's rules are **simple syntactic
   patterns**; the registry's same-class rules are **overwhelmingly taint-mode** (sources ->
   sinks -> sanitizers) and far more elaborate. A copier would inherit that machinery; CI did
   not. This is the strongest single signal *against* derivation.
2. **Matching CWE-title strings are not evidence of copying.** Both CI and the registry quote
   the **official MITRE CWE titles** verbatim (e.g. the full "CWE-89: ...('SQL Injection')").
   That is two parties citing MITRE, not one copying the other.
3. **Convergence traces to bandit / eslint-plugin-security, not to semgrep specifically.** The
   registry's Python rules cite **bandit** (B303/B304/B307) and its JS eval rule cites
   **eslint-plugin-security**. Those tools defined these canonical checks years before
   semgrep-rules; everyone converges on the same canonical API tokens (`hashlib.md5`, eval,
   `os.system`, `pickle.loads`).
4. **CI is sometimes *less* refined than the registry** (no `usedforsecurity=False` guard, no
   require guard on jwt). A copy would more likely inherit refinements, not drop them.

## Headline verdict

**The copyright-relevant claim holds: I found NO evidence of copied protectable expression
from `semgrep/semgrep-rules` or `opengrep/opengrep-rules`.** Every resemblance is explained by
canonical-idiom convergence, and CI's syntactic style is materially different from the
registry's taint-mode rules. On the evidence, the 19 rules are clean to bundle and sell under
MIT.

**Two caveats, stated honestly:**
1. **Two rules (`dom-xss-innerhtml`, `jwt-alg-none`) have high enough structural overlap** with
   specific registry rules (`insecure-document-method`, `jwt-none-alg`) that I **cannot certify
   zero-reference from structure alone.** Both remain explainable as convergence (CWE/metavar/
   guard differences exist), but they deserve a human eyeball and the author's own recollection
   of whether those two were written with a registry rule open.
2. **This audit was targeted, not exhaustive** (~20 closest analogs, not a full ~4,000-file
   diff). A line-by-line sweep is the deeper version if certainty must be maximal.

## Provenance docs alignment

The provenance docs were aligned to this audit's finding: the absolute "authored from scratch /
zero derived-from" phrasing was replaced with the defensible claim — *independently authored; the
public registry was referenced during authoring; no copyrightable expression copied; resemblance
is convergent functional idiom (merger / scenes a faire)*. The two highest-overlap rules
(`dom-xss-innerhtml`, `jwt-alg-none`) are recorded as convergent, not derived. See
`RULE-PROVENANCE.md`, the rules' `LICENSE-PROVENANCE.md`, and `legal/RULE-DERIVATION-REVIEWS.md`.

_Evidence base: the 19 rule bodies in `detection-db/opengrep-rules/security-baseline/` vs the
registry files listed above, fetched 2026-06-23. No registry content copied into the repo._
