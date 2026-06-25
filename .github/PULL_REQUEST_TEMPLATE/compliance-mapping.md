<!--
Compliance mapping change PR template.
Use this template for any PR that adds, changes, or confirms a CWE→control mapping
in data/cwe_to_controls.json (or its rationale in docs/COMPLIANCE-RATIONALE.md).
To use it, append ?template=compliance-mapping.md to the PR "compare" URL,
or pick it from the template picker.

Reminder: compliance mappings are AI-drafted, reviewed by a cybersecurity
practitioner (Synvoya) — code-level coverage only, not an audit or certification.
Community review welcome.
-->

## Mapping change

| Field | Value |
|---|---|
| CWE | `CWE-____` |
| Control | `<framework> <control_id>` (e.g. `ISO27001:2022 A.8.28`) |
| Change type | add / edit / confirm / remove |
| Proposed confidence | high / medium / low |

## 1. Official control text (REQUIRED)

Quote the control's **own wording** from its **primary source**, with a citation.
A paraphrase is not enough — the maintainer must be able to check this quote.

> _Paste the verbatim control text here._

- **Source:** (e.g. "NIST CSF 2.0 Core, PR.DS-01" / "ISO/IEC 27001:2022 Annex A 8.28" /
  "AICPA 2017 TSC, CC7.1" / "CIS Controls v8.1, Safeguard 16.12" / "cwe.mitre.org View-1345")
- **Link or document + section:**
- **Date checked:**

## 2. Your basis / credential (REQUIRED)

State why your judgment should carry weight on this mapping. All bases are welcome —
**including "none / reasoning from the published text"** — but it must be stated, because it
becomes the attribution recorded in the `reviewer` field on merge.

> _e.g. "ISO 27001 Lead Auditor" · "SOC 2 practitioner" · "CISSP" · "no formal GRC
> credential — reasoning from the published control text"._

## 3. Which judgment does this rest on?

- [ ] **(a) Technical link** — the weakness class genuinely relates to the control's subject.
- [ ] **(b) Audit-interpretation** — an auditor would accept that a *code finding constitutes
      coverage*. (If this is ticked, confidence should be **medium at most** and tagged
      "wants a GRC/audit eye".)

Explain briefly:

> _..._

## 4. Rationale (1–2 lines, for the COMPLIANCE-RATIONALE.md row)

> _..._

---

### Contributor checklist

- [ ] I quoted the **official control text** from its primary source (not a paraphrase).
- [ ] I cited the source (document + section/ID) and the date I checked it.
- [ ] I stated my **basis/credential** (or honestly "none").
- [ ] I separated the **(a) technical** vs **(b) audit-interpretation** judgment.
- [ ] I did **not** claim "expert verified" / "independently verified" anywhere.
- [ ] If I edited `data/cwe_to_controls.json`, `npm run build && npm run eval` still passes
      (eval stays green) and I did not add sibling keys that break the mapper.

### Maintainer use only

- [ ] Quote checked against the cited primary source — matches.
- [ ] On merge: `reviewer` upgraded from `"AI-drafted, unverified"` to
      `"<contributor>, <basis> — confirmed against <source>, <date>"`.
- [ ] Honesty metric (community-verified ratio) updated.
