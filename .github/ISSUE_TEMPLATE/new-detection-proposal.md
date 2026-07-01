---
name: New detection proposal
about: Propose a new vulnerability / footgun for CodeInspectus to detect — with the precision discipline up front
title: "[detection] "
labels: detection-proposal
---

<!-- The merge bar is PRECISION, not coverage. This template asks for the true-positive AND the
     false-positive up front, because a rule without a near-miss fixture cannot be merged.
     See CONTRIBUTING.md → "Detection rules". -->

## The footgun
What insecure pattern should be detected, and why it is dangerous (impact; CWE if known).

## Concrete example (true positive)
The smallest realistic code (synthetic, no real secrets) that **should** fire:

```
// vulnerable example
```

## What must NOT fire (false positive / near-miss)
The realistic **safe** code that looks similar but is correct — the rule must stay silent here:

```
// safe look-alike the rule must NOT flag
```

## Proposed discriminators
How can the rule tell the dangerous case from the safe one? (field/identifier names, call
shapes, surrounding context, file location, …) Be specific — this is the heart of precision.

## Detectability (be honest)
- [ ] Single-line / inline (regex-detectable)
- [ ] Needs intrafile cross-function taint (in scope)
- [ ] Needs cross-file taint (**out of scope for v1** — say so)
- Languages / frameworks it applies to:

## Fixture sketch (TP + FP corpus)
List the fixtures you would add — **at least one true-positive and one false-positive /
near-miss**. A proposal without both will be asked to add them before any code is written.
