# RULE-DERIVATION-REVIEWS.md — concordant reviews of the two highest-overlap rules

> **Purpose:** the evidence base for the legal-provenance gate on the Opengrep SAST
> ruleset, focused on the two rules with the highest structural overlap to the public
> registry. Three independent reviews concur: **CONVERGENT-IDIOM (merger / scenes a
> faire), low derivation risk.**
>
> **Gate status: DE-RISKED, NOT CLOSED.** This is review material, not a legal opinion.
> The legal-provenance gate remains a qualified human lawyer's sign-off; the reviews
> below lower the risk and document the reasoning, they do not grant the gate.
>
> **No registry rule bodies are reproduced in this repo** (copyright). Similarity is
> described in words, never copied.

_Created CG-13 (2026-06-25). Scope: the two HIGH-overlap rules of the 19 —
`ci-baseline-jwt-alg-none` and `ci-baseline-dom-xss-innerhtml`. The other 17 rules are
lower-overlap and covered by the CG-09 audit (7 likely-original, 10 generic-convergence)._

---

## The question under review

The legally load-bearing question is **copyright**: did CodeInspectus copy *protectable
expression* from `semgrep/semgrep-rules` (Semgrep Rules License v1.0) or
`opengrep/opengrep-rules` (LGPL-2.1 + Commons Clause)? This is distinct from "did the
author ever look at a registry rule." **Referencing a public rule while authoring is not
copying;** copying protectable expression is. The maintainer's recollection is that these
rules were brainstormed by the maintainer with an AI assistant, **with the public registry
referenced during authoring** — not transcribed from a registry file.

---

## Review 1 — CG-09 structural audit (in-repo, first-hand)

Source: `docs/RULE-ORIGINALITY-AUDIT.md` (2026-06-23). Method: real fetch of the closest
same-CWE registry analogs, structural comparison of pattern/AST shape, metavariable names,
guard idioms, message text, metadata, and detection mode (syntactic vs taint).

- **`ci-baseline-jwt-alg-none`** vs registry `jsonwebtoken/security/jwt-none-alg.yaml`:
  classed **generic-convergence (HIGH overlap)**. The core "accepts algorithm none" check
  has essentially one idiomatic form. Differences: CI uses **CWE-347** (registry CWE-327),
  adds the singular `algorithm: "none"` variant, has **no** require-jsonwebtoken guard, and
  carries its own message.
- **`ci-baseline-dom-xss-innerhtml`** vs registry `browser/security/insecure-document-method.yaml`
  (+ `insecure-innerhtml.yaml`): classed **generic-convergence (HIGH overlap)** — the
  highest-overlap rule of the 19. Both flag the canonical DOM-HTML sinks with a not-literal
  guard under the same CWE-79. Differences: CI adds `insertAdjacentHTML`, uses metavariable
  `$X` (registry uses `$HTML`), and carries its own message.
- **Headline:** 0 of 19 rules classed `possible-derivation` or worse; **no copied
  protectable expression found.** Stated caveat (under-claimed): the audit was targeted, not
  exhaustive, and could not certify *zero-reference* from structure alone — which is why
  author recollection and the two further reviews below matter.

## Review 2 — GPT-5.5 (independent model review, maintainer-supplied)

An independent review run by the maintainer outside this repo. **Verdict for both rules:
CONVERGENT-IDIOM (merger / scenes a faire), low derivation risk — not derived.**

> Recorded at verdict level. The underlying transcript is held by the maintainer and is
> not reproduced here; this file attests the verdict and its concordance, not a verbatim
> record I generated.

## Review 3 — Gemini Pro (independent model review, maintainer-supplied)

A second independent review run by the maintainer. **Verdict for both rules:
CONVERGENT-IDIOM (merger / scenes a faire), low derivation risk — not derived.** Recorded
at verdict level, same caveat as Review 2.

---

## Concordance

Three independent reviews — one first-hand structural audit in the repo, two external model
reviews — **reach the same verdict: convergent idiom, not derived.** Combined with the
maintainer's recollection (referenced, not copied), the copyright-relevant claim is well
supported.

## Why convergence holds — merger / scenes a faire

- **Merger.** When a function has only one (or very few) practical expressions, the
  expression *merges* with the idea and is unprotectable. The "reject the `none` algorithm"
  check and the "non-literal value into an HTML sink" check each have essentially one
  idiomatic form (e.g. `algorithms: ["none"]`; an `innerHTML`-family assignment of a
  non-literal). There is no expressive room to diverge while still matching the bug.
- **Scenes a faire.** The standard, expected elements of the domain — the canonical sink
  list (innerHTML / outerHTML / insertAdjacentHTML / document.write / writeln) and the
  not-literal false-positive guard — are stock elements, not protectable authorship.
- **Independently authored surfaces.** Where expressive choice *does* exist — the rule
  message text, the metavariable names, the CWE selection, the set of variants — CI differs
  from the registry. Those are the only weakly-expressive surfaces, and they are CI's own.

## Affirmative evidence against copying (the "cruder than the registry" point)

- **CI rules are plain syntactic patterns; the registry's same-class rules are
  overwhelmingly taint-mode** (source -> sink -> sanitizer) and far more elaborate. A copier
  inherits that machinery; CI does not have it. This is the single strongest signal against
  derivation.
- **CI is sometimes *less* refined than the registry** (no require-guard on the JWT rule; no
  `usedforsecurity=False` refinement on weak-hash). A copy would more likely inherit
  refinements than drop them.
- **Matching MITRE CWE-title strings are not evidence of copying** — both CI and the registry
  quote the official MITRE titles verbatim; that is two parties citing MITRE.

## What CG-13 did to these two rules

- **Both messages reworded** in the maintainer's own independent prose (same technical
  meaning, distinct phrasing) — closing the one expressive surface that overlapped.
- **`ci-baseline-dom-xss-innerhtml` completeness fix** (on the merits, not cosmetic): added
  the `document.writeln` sink (a genuine coverage gap) and made the literal-string exclusions
  consistent across all sinks. Rule id unchanged (fingerprint invariant).

## Gate status (explicit)

**DE-RISKED, NOT CLOSED.** Three concordant CONVERGENT-IDIOM reviews + affirmative structural
evidence lower the risk substantially and document the merger/scenes-a-faire reasoning. The
legal-provenance gate still requires a **qualified human lawyer** to confirm that reasoning
before any paid/hosted tier or trademark/registration step. Standing policy unchanged: if any
single rule's originality is ever in doubt, **remove it pending review** rather than ship it.
