# CodeInspectus security ruleset — license & provenance

**License:** MIT (same as CodeInspectus). © Synvoya.

These Opengrep/Semgrep-syntax rules are **convergent functional idioms** (merger /
scenes a faire). The public Semgrep/Opengrep registry **was referenced during
authoring** (the rules were brainstormed by the maintainer with an AI assistant, with
the registry open as a reference); **no copyrightable expression was copied** from it.
The rule *messages* and *subpattern structure* are independently authored. The
resemblance that remains is the **forced functional form** of each check -- e.g.
`algorithms: ["none"]` for a JWT alg-none test, or the `$EL.innerHTML = $X` sink
shape for DOM-XSS -- which is the only practical way to express the check and is
therefore **unprotectable**. These are the canonical API tokens + standard
false-positive guards that predate the Semgrep/Opengrep registries. Concordant with the
CG-09 structural audit (`docs/RULE-ORIGINALITY-AUDIT.md`): 0 of 19 rules show copied
protectable expression.

**Not copied or derived from** the restricted corpora a paid/hosted tier must avoid:
- `opengrep/opengrep-rules` (LGPL-2.1 **+ Commons Clause** — "no Sell" condition), or
- `semgrep/semgrep-rules` (Semgrep Rules License v1.0).

**Two highest-overlap rules** -- `ci-baseline-jwt-alg-none` and
`ci-baseline-dom-xss-innerhtml` -- were independently reviewed by **three concordant
sources** (the CG-09 structural audit, GPT-5.5, and Gemini Pro), each classing them
**CONVERGENT-IDIOM (merger / scenes a faire), low derivation risk** -- not derived. Each
differs from the closest registry rule in CWE / metavariable / guard; in CG-13 both had
their messages reworded in independent prose, and `dom-xss-innerhtml` received a genuine
completeness fix. See `docs/legal/RULE-DERIVATION-REVIEWS.md`. The human
legal-provenance gate (lawyer sign-off) is **de-risked, not yet closed**.

Bundling either of those upstream corpora would conflict with offering CodeInspectus
as a paid/hosted product. This MIT set is deliberately **simpler than the registry
equivalents -- plain syntactic patterns, not the registry's taint-mode (source -> sink
-> sanitizer) machinery** -- itself affirmative evidence against copying (a copier would
inherit that machinery, not strip it). It is also narrower in coverage; coverage grows
via the human-reviewed weekly intake (PRD §9).

**Pre-launch gate:** a legal review of every bundled rule's provenance. If any
rule's originality is ever in doubt, remove it pending review rather than ship it.

Every rule carries `metadata.cwe` so CodeInspectus's normalizer and compliance
mapper work unchanged. Files are plain local YAML — fully offline, no scan-time
fetch. Keep all files ASCII-only (Opengrep reads rule files as ASCII).
