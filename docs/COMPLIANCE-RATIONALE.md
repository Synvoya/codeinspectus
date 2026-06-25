# COMPLIANCE-RATIONALE.md — CWE→control mapping rationale (DRAFT, self-audited)

> **AI-drafted, reviewed by a cybersecurity practitioner (Synvoya) — code-level coverage
> only, not an audit or certification. Community review welcome.**
>
> This is a **draft mapping rationale**, not a verified one. Every row carries a
> self-assigned **confidence** and a **reviewer** field; the default reviewer is
> **"AI-drafted, unverified"** and stays that way until a human confirms the row against the
> cited control text. Nothing here is "expert verified" or "independently verified" — the
> maintainer is author *and* reviewer, so the honest verb is **reviewed**, never *verified*.

_Source of truth: `data/cwe_to_controls.json` (`cwe_map` + `buckets`), which carries the
reconciled per-mapping schema (`confidence`, `rationale`, `source_citation`, `reviewer`) applied
under a conservative maintainer policy (**96 mappings retained**). The per-CWE tables below are
the earlier self-audit (pre-reconciliation) and are **superseded by the data file where they
differ** — kept for the reasoning trail; the authoritative confidence values live in the data file._

---

## The two judgments — kept separate on purpose

Every mapping below makes (or leans on) two different claims. They are **not** equally
defensible and CG-08 does not pretend they are:

- **(a) The technical link** — does this weakness class genuinely relate to the control's
  subject? (e.g. broken-crypto-algorithm ↔ a "use of cryptography" control). *This can be
  reasoned about from the control's text, and is what most "high" rows rest on.*
- **(b) The audit-interpretation link** — would an ISO 27001 / SOC 2 / CIS auditor accept
  that a **code finding constitutes coverage** of this control? *This cannot be settled
  here.* Where a mapping leans on (b), confidence is **capped at medium** and the row is
  tagged **"wants a GRC/audit eye."**

## Confidence rubric

| Confidence | Meaning |
|---|---|
| **high** | Direct technical link **and** the control is itself a code/vulnerability control, so a code finding stands as evidence with minimal audit interpretation (mostly judgment (a)). |
| **medium** | Reasonable technical link, but whether a finding *constitutes* coverage is an auditor's call (judgment (b)). Tagged "wants a GRC/audit eye." |
| **low** | Tenuous technical link, **or** the citation/View-ID is itself unverified. Treated as **unverified** — say so loudly; do not ship as coverage without a human. |

## The six-field schema (every mapping carries these)

`cwe` · `control_id` · `confidence` · `rationale` · `source_citation` · `reviewer`.

- In the tables, **`cwe`** is the section heading, **`control_id`** is the *Control* column,
  and **`reviewer` defaults to "AI-drafted, unverified"** for every row (shown once here,
  not repeated per row; it changes only when a community contributor's attribution is merged
  — see CONTRIBUTING.md).
- `source_citation` is the official control's own title/text that the mapping points at.
- **CG-08 keeps this schema in the doc, not in `data/cwe_to_controls.json`.** That data file
  is read by the scanner; adding sibling keys risks the exact bucket-iteration crash fixed in
  the follow-up, and CG-08 is docs-only. Wiring `confidence`/`reviewer` into the data file +
  output is flagged for **CG-09** (a code change).

---

## Citation-verification status (read before trusting any "high")

- **NIST CSF 2.0** subcategory IDs+wording (PR.DS-01/02, PR.AA-05, PR.PS-06, ID.RA-01):
  confirmed **verbatim** against the official CSF 2.0 Core, 2026-06-21 (data-file `_verify`).
- **SOC 2** points (CC6.1/6.6/6.7, CC7.1, CC8.1): IDs/meanings confirmed against the 2017
  TSC; exact punctuation cross-checked via audit-firm references (AICPA PDF paywalled).
- **CIS v8.1** IDs corrected 2026-06-21 (16.6→16.10, 16.11→16.12, 2.1 relabeled).
- **ISO 27001:2022** Annex A titles: treated as grounded (public Annex A list).
- **OWASP-Web View IDs — partial.** PRD §11/§13 confirms only **1345 (A01), 1348 (A04),
  1349 (A05), 1354 (A08)** and explicitly leaves **A02→1346** and **A03→1347** as
  *"follow the sequential pattern — verify."* The data file's `owasp_web_all_views._note`
  claims the **whole** table was verified at cwe.mitre.org on 2026-06-21 — **this contradicts
  the PRD.** CG-08 cannot reach cwe.mitre.org (offline, docs-only), so it **cannot resolve
  the conflict** and follows the PRD's stricter line: **A02→1346 and A03→1347 are treated as
  UNVERIFIED (low)**, and the other non-PRD-confirmed IDs (1352/1353/1355/1356) are
  **medium-unverified** pending one human cwe.mitre.org check. See the dedicated flag below.

---

## Per-CWE explicit mappings (`cwe_map`)

Reviewer for every row below: **AI-drafted, unverified.**

### CWE-798 — Hard-coded credentials

| Control | Conf. | Source citation (official title) | Rationale |
|---|---|---|---|
| ISO A.8.28 | high | "Secure coding" | (a) Hard-coded credentials is a textbook secure-coding defect. |
| ISO A.8.24 | medium | "Use of cryptography" | (a/b) Key/secret management sits under crypto control, but a plaintext cred isn't strictly a cryptography failing — wants a GRC/audit eye. |
| ISO A.8.12 | medium | "Data leakage prevention" | (b) A leaked secret is data leakage, but DLP usually means egress controls — wants a GRC/audit eye. |
| NIST PR.AA-05 | medium | "Access permissions, entitlements, and authorizations are defined…managed, enforced, and reviewed…least privilege" | (b) A hard-coded cred undermines access control; coverage claim is interpretive. |
| NIST PR.DS-01 | **low** | "…data-at-rest are protected" | (a) **Weak link** — a secret in source is not "data at rest" in the storage sense. Unverified. |
| SOC2 CC6.1 | medium | "Implements logical access security…over protected information assets" | (b) Wants a GRC/audit eye. |
| CIS 16.12 | high | "Implement Code-Level Security Checks" | (a) This is literally a code-level security check — the cleanest mapping. |
| CIS 3.11 | **low** | "Encrypt Sensitive Data at Rest" | (a) **Loose** — same issue as PR.DS-01; a source secret isn't "data at rest." Consider dropping in favour of 16.12 alone. Unverified. |
| OWASP A07:2021 | medium | "Identification and Authentication Failures" (CWE View **1353** — *not PRD-confirmed*) | (a) CWE-798 sits in A07 per MITRE view; View ID needs a human check. |
| OWASP LLM02:2025 | high | "Sensitive Information Disclosure" | (a) Exposed secret = sensitive-info disclosure; canonical for AI apps. |

### CWE-312 — Cleartext storage of sensitive data

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.24 | high | "Use of cryptography" | (a) Cleartext storage ↔ failure to apply cryptography. |
| ISO A.8.12 | medium | "Data leakage prevention" | (b) Reasonable; wants a GRC/audit eye. |
| NIST PR.DS-01 | high | "…data-at-rest are protected" | (a) Direct — cleartext storage is exactly an at-rest protection failure. |
| SOC2 CC6.1 | medium | "Logical access security over protected information assets" | (b) Wants a GRC/audit eye. |
| CIS 3.11 | high | "Encrypt Sensitive Data at Rest" | (a) Direct — this is the at-rest encryption control. |
| OWASP A02:2021 | **low** | "Cryptographic Failures" (CWE View **1346** — *PRD says VERIFY; UNVERIFIED*) | (a) Category link is firm; **View ID 1346 is unverified** per PRD. |
| OWASP LLM02:2025 | high | "Sensitive Information Disclosure" | (a) Canonical. |

### CWE-285 / CWE-862 / CWE-863 — Improper / Missing / Incorrect authorization

Same control set for all three (authorization family). Rows identical; listed once.

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.28 | high | "Secure coding" | (a) Authorization defects are secure-coding defects. |
| ISO A.8.26 | medium | "Application security requirements" | (b) A code bug is weak evidence of a *requirements* control — wants a GRC/audit eye. |
| NIST PR.AA-05 | medium | "Access permissions…managed, enforced, and reviewed…least privilege" | (a/b) Strong subject match; coverage claim still interpretive. |
| SOC2 CC6.1 | medium | "Logical access security" | (b) Wants a GRC/audit eye. |
| CIS 16.10 | medium | "Apply Secure Design Principles in Application Architectures" | (b) Design-principle control; a code authz bug is partial evidence. |
| OWASP A01:2021 | high | "Broken Access Control" (CWE View **1345** — PRD-confirmed) | (a) Canonical; View ID confirmed. |

### CWE-89 / CWE-79 — SQL injection / Cross-site scripting

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.28 | high | "Secure coding" | (a) Injection/XSS are the canonical secure-coding defects. |
| NIST PR.PS-06 | medium | "Secure software development practices…throughout the SDLC" | (b) Program/SDLC control; one finding is partial evidence — wants a GRC/audit eye. |
| SOC2 CC8.1 | medium | "Change management — authorizes, designs, develops…tests, approves…changes" | (b) **Proxy mapping** — SOC 2 has no clean secure-coding control; CC8.1 is the closest (SAST as a change gate). Wants a GRC/audit eye. |
| CIS 16.1 | medium | "Establish and Maintain a Secure Application Development Process" | (b) Process-level; an SME may prefer **16.12** (code-level checks). Defensibility call. |
| OWASP A03:2021 | **low** | "Injection" (CWE View **1347** — *PRD says VERIFY; UNVERIFIED*) | (a) Category link is firm (A03↔injection); **View ID 1347 is unverified** per PRD. |

### CWE-77 / CWE-94 — Command injection / Code injection

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.28 | high | "Secure coding" | (a) Canonical secure-coding defect. |
| NIST PR.PS-06 | medium | "Secure software development practices" | (b) Wants a GRC/audit eye. |
| CIS 16.1 | medium | "Secure Application Development Process" | (b) Process-level; 16.12 may fit better. |
| OWASP A03:2021 | **low** | "Injection" (CWE View **1347** — UNVERIFIED) | (a) Category firm; View ID unverified. |

### CWE-1426 — Improper handling of untrusted input to an LLM

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.28 | medium | "Secure coding" | (a/b) Generic secure-coding fit for a novel weakness class; loose. |
| ISO A.8.26 | medium | "Application security requirements" | (b) Wants a GRC/audit eye. |
| NIST PR.PS-06 | medium | "Secure software development practices" | (b) Wants a GRC/audit eye. |
| OWASP LLM01:2025 | high | "Prompt Injection" | (a) Canonical — this is *the* prompt-injection category. |

### CWE-327 — Broken / risky crypto algorithm

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.24 | high | "Use of cryptography" | (a) Direct — broken algorithm ↔ cryptography control. |
| NIST PR.DS-01 | medium | "…data-at-rest are protected" | (a) Weak crypto can affect at-rest data; interpretive. |
| NIST PR.DS-02 | medium | "…data-in-transit are protected" | (a) Weak crypto can affect in-transit data; interpretive. |
| CIS 3.10 | medium | "Encrypt Sensitive Data in Transit" | (a) Applies only when the algorithm guards transit. |
| CIS 3.11 | medium | "Encrypt Sensitive Data at Rest" | (a) Applies only when the algorithm guards at-rest data. |
| OWASP A02:2021 | **low** | "Cryptographic Failures" (CWE View **1346** — UNVERIFIED) | (a) Category firm; View ID 1346 unverified per PRD. |

### CWE-502 — Insecure deserialization

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.28 | high | "Secure coding" | (a) Canonical secure-coding defect. |
| NIST PR.PS-06 | medium | "Secure software development practices" | (b) Wants a GRC/audit eye. |
| OWASP A08:2021 | high | "Software and Data Integrity Failures" (CWE View **1354** — PRD-confirmed) | (a) Canonical; View ID confirmed. |

### CWE-918 — Server-side request forgery

| Control | Conf. | Source citation | Rationale |
|---|---|---|---|
| ISO A.8.28 | high | "Secure coding" | (a) Canonical secure-coding defect. |
| OWASP A10:2021 | medium | "Server-Side Request Forgery (SSRF)" (CWE View **1356** — data-file-corrected, *not PRD-confirmed*) | (a) Category is definitional; View ID 1356 is the data file's correction of the PRD's wrong 1354 — needs the human cwe.mitre.org check. |

> **Note — CWE-918 is under-mapped** (only ISO + OWASP; no NIST/SOC2/CIS row). That is an
> honest sparse mapping, not an error — left thin rather than padded.

---

## Fallback buckets (used when a CWE has no explicit `cwe_map` entry)

Reviewer for every row: **AI-drafted, unverified.** Buckets are coarser than per-CWE rows,
so confidence is generally one notch lower for the same control.

| Bucket (applies to) | Control | Conf. | Source citation | Rationale |
|---|---|---|---|---|
| **credentials** (259/321/322/540/256) | ISO A.8.24 | medium | "Use of cryptography" | (a/b) Class-level; wants a GRC/audit eye. |
| | ISO A.8.12 | medium | "Data leakage prevention" | (b) Wants a GRC/audit eye. |
| | NIST PR.DS-01 | **low** | "…data-at-rest…" | (a) Same at-rest looseness as CWE-798. Unverified. |
| | SOC2 CC6.1 | medium | "Logical access security" | (b) Wants a GRC/audit eye. |
| | CIS 16.12 | high | "Implement Code-Level Security Checks" | (a) Cleanest credentials mapping. |
| | OWASP A07:2021 | medium | "Identification and Authentication Failures" (View 1353 — not PRD-confirmed) | (a) Category fit; View ID unchecked. |
| **crypto** (326/328/916/330/295) | ISO A.8.24 | high | "Use of cryptography" | (a) Direct. |
| | NIST PR.DS-01 / PR.DS-02 | medium | at-rest / in-transit protection | (a) Interpretive per data state. |
| | SOC2 CC6.7 | medium | "Transmission of sensitive data…protected during transmission" | (a/b) Fits transit crypto; wants a GRC/audit eye. |
| | CIS 3.10 / 3.11 | medium | encrypt in transit / at rest | (a) Per data state. |
| | OWASP A02:2021 | **low** | "Cryptographic Failures" (View 1346 — UNVERIFIED) | (a) Category firm; View ID unverified. |
| **access** (284/639/732/269/306) | ISO A.8.28 | high | "Secure coding" | (a) Access defects are secure-coding defects. |
| | ISO A.8.26 | medium | "Application security requirements" | (b) Wants a GRC/audit eye. |
| | NIST PR.AA-05 | medium | access-permissions control | (a/b) Strong subject match; interpretive. |
| | SOC2 CC6.1 | medium | "Logical access security" | (b) Wants a GRC/audit eye. |
| | CIS 16.10 | medium | "Apply Secure Design Principles" | (b) Wants a GRC/audit eye. |
| | OWASP A01:2021 | high | "Broken Access Control" (View 1345 — confirmed) | (a) Canonical. |
| **injection** (78/90/917/643/611/1336) | ISO A.8.28 | high | "Secure coding" | (a) Canonical. |
| | NIST PR.PS-06 | medium | "Secure software development practices" | (b) Wants a GRC/audit eye. |
| | SOC2 CC8.1 | medium | "Change management" | (b) Proxy mapping; wants a GRC/audit eye. |
| | CIS 16.1 | medium | "Secure Application Development Process" | (b) 16.12 may fit better. |
| | OWASP A03:2021 | **low** | "Injection" (View 1347 — UNVERIFIED) | (a) Category firm; View ID unverified. |
| **misconfig** (16/1188/1004/614/668) | ISO A.8.27 | medium | "Secure system architecture and engineering principles" | (b) Wants a GRC/audit eye. |
| | NIST PR.PS-06 | medium | "Secure software development practices" | (b) Wants a GRC/audit eye. |
| | SOC2 CC6.6 | **low** | "Boundary protection" | (a) **Weak** — boundary protection is network-edge; web-misconfig is only loosely related. Unverified. |
| | CIS 16.1 | medium | "Secure Application Development Process" | (b) Wants a GRC/audit eye. |
| | OWASP A05:2021 | high | "Security Misconfiguration" (View 1349 — confirmed) | (a) Canonical; View ID confirmed. |
| **vulnerable_component** (1035/1395/937) | ISO A.8.8 | high | "Management of technical vulnerabilities" | (a) SCA *is* technical-vulnerability management. |
| | NIST ID.RA-01 | high | "Vulnerabilities in assets are identified, validated, and recorded" | (a) Direct — SCA identifies vulnerabilities. |
| | SOC2 CC7.1 | high | "Detection…to identify…susceptibilities to newly discovered vulnerabilities" | (a) Direct — vuln detection. |
| | CIS 7.1 | high | "Establish and Maintain a Vulnerability Management Process" | (a) Direct. |
| | EssentialEight PatchApplications | medium | "Patch Applications" | (a) Direct subject, **but see Essential Eight caveat — demoted, not a coverage view.** |
| | OWASP A06:2021 | medium | "Vulnerable and Outdated Components" (View 1352 — not PRD-confirmed) | (a) Category definitional; View ID unchecked. |

---

## Essential Eight — DEMOTED to a caveat (not a coverage panel)

**Essential Eight must not be presented as a per-framework "coverage" panel.** Only **1 of 8**
mitigations — **Patch Applications** — is meaningfully code-evidenced (via Trivy SCA). The
other seven (patch OS, MFA, restrict admin, app control, restrict macros, user-application
hardening, backups) are **not assessed** by a code scan at all. Presenting E8 alongside the
other frameworks invites the reader to think "CodeInspectus covers Essential Eight," which is
false.

**Required framing wherever E8 appears:** *"Only Patch Applications is meaningfully
code-evidenced; this is not an Essential Eight assessment."* Keep E8 as a footnote on the
`vulnerable_component` row, never as its own coverage view. (Matches PRD §11 and the README.)

---

## Ship recommendation — which frameworks are solid vs need an extra-loud caveat

This is a solo, free, community project; integrity rests on never over-claiming. Honest call:

| Framework | Ship as-is? | Why |
|---|---|---|
| **OWASP Web 2021** | **Yes**, with the View-ID caveat | Category mappings are canonical MITRE taxonomy. **But** A02→1346 and A03→1347 View IDs are PRD-unconfirmed — keep them flagged until the human check. |
| **OWASP LLM 2025** | **Yes** | LLM01/LLM02 mappings are direct and canonical for AI code. |
| **CIS v8.1** | **Yes** | IDs corrected and confirmed; 16.12 / 7.1 / 3.x mappings are strong. Process-vs-code (16.1 vs 16.12) is a defensibility nuance, not an error. |
| **NIST CSF 2.0** | **Yes**, with the "code-level subset" framing | IDs verbatim-verified; mappings are reasonable but several are judgment (b). |
| **ISO 27001:2022** | **Yes**, with the "code-level subset" framing | Annex A titles grounded; A.8.28 / A.8.24 / A.8.8 mappings strong. |
| **SOC 2** | **Yes, but extra-loud caveat** | No clean secure-coding control exists; **CC8.1 is a proxy** for injection/XSS. Lean hardest on the "auditor must judge coverage" disclaimer here. |
| **Essential Eight** | **No coverage view** | Demote to a footnote (above). 1/8 code-visible. |
| MITRE ATT&CK | n/a (not a control framework) | Already shown only as related-adversary context, never coverage. Correct as-is. |

---

## Coverage gaps & unused controls (honest housekeeping)

- **`A.8.25` (Secure development lifecycle)** is listed in `code_visible_controls` but is
  **not referenced** by any `cwe_map`/bucket row. Either wire it in or drop it from the
  code-visible list — a listed-but-unused control overstates the surface.
- **`CIS 2.1` (Software Inventory)** likewise listed but unused after the SBOM relabel.
- **`OWASP LLM06:2025` (Excessive Agency)** listed in `code_visible_controls` but no CWE maps
  to it yet (no excessive-agency detector exists). Listed-but-unused.
- These are **not bugs**; they are honest gaps to close before the controls are shown to a
  user as "in scope."

---

## OWASP-Web View-ID flag (re-flagged per the PRD)

The PRD (§11/§13) explicitly leaves **A02:2021→CWE-View-1346** and **A03:2021→CWE-View-1347**
as *"follow the sequential pattern — verify."* The data file claims the full table verified
on 2026-06-21; CG-08 **cannot reconcile** that offline. Until a human opens cwe.mitre.org and
confirms: **treat 1346 and 1347 as unverified (low).** Also re-check the non-PRD-confirmed
1352/1353/1355/1356 while there. The *category* assignments (A02↔crypto, A03↔injection) are
firm regardless — only the numeric View-ID citations are in doubt.

---

## What this draft does NOT do (scope honesty)

- It does **not** verify mappings against the paywalled/official standard texts beyond what
  the data-file `_verify` records. "Confirmed verbatim" applies to the **control IDs+titles**,
  not to the **mapping decision**.
- It does **not** edit `data/cwe_to_controls.json` (docs-only session).
- It does **not** settle any judgment-(b) audit-interpretation question — that is exactly
  what the human GRC/audit review and the community-verification process (CONTRIBUTING.md)
  are for.

---

## Honesty metric — three distinct states (drafted / policy-reviewed / community-verified)

Three states, not two — kept separate so the number never over-claims:
1. **AI-drafted, unverified** — the original self-audit default (CG-08).
2. **Policy-reviewed by maintainer** — reconciled in CG-10 by the Synvoya maintainer (a security
   analyst) under a conservative code-evidence policy, AI-drafted + cross-checked across two
   independent models. This is the current `reviewer` state on all retained mappings. It is
   **maintainer review, NOT third-party/community verification** — author and reviewer are the
   same party, so the honest verb stays **reviewed**, never *verified*.
3. **Community-verified** — a contributor outside the maintainer confirmed the row against the
   cited official control text via a merged mapping-change PR (CONTRIBUTING.md).

Define **community-verified ratio = (mappings with an outside contributor's attribution) /
(total retained framework-control mappings)**. That is the headline integrity number.

- Total retained mappings after CG-10/CG-11 (excluding ATT&CK): **96** (was 103; **7 cut** —
  CG-10 cut 8, CG-11 re-added 1 as the CWE-1426 → OWASP LLM05 remap).
  Per framework: ISO 27001 **28** · NIST CSF **19** · SOC 2 **9** · CIS v8.1 **18** ·
  OWASP Web **18** · OWASP LLM **3** · Essential Eight **1**.
- Policy-reviewed by maintainer: **96 / 96 (100%)**.
- **Community-verified: 0 / 96 = 0%.** Stays 0 until outside contributors confirm rows via PRs;
  maintainer policy-review improves confidence quality but does **not** count as community
  verification.

Every merged mapping-change PR that cites the official control text and a contributor basis
(CONTRIBUTING.md) moves a row to **community-verified** and nudges this number up.

_Generated from `data/cwe_to_controls.json`; regenerate if the mapping changes._
