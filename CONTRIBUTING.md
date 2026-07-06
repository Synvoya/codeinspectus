# Contributing to CodeInspectus

Thanks for helping. CodeInspectus is a solo, free, community security tool; its credibility
rests on **never over-claiming**. The contribution rules below exist to keep it honest.

> **Compliance mappings are AI-drafted, reviewed by a cybersecurity practitioner (Synvoya) —
> code-level coverage only, not an audit or certification. Community review welcome.**

Two general rules first:

1. **Local-only, offline-first.** No scan-time network egress, no telemetry. Don't add a
   dependency or code path that phones home.
2. **Under-claim.** If you can't verify something, say so in the PR. "I think" beats a
   confident-and-wrong assertion.

How this repository is generated and built from a clean clone is documented in
[`docs/BUILD.md`](docs/BUILD.md).

---

## How to contribute — fork, branch, PR

CodeInspectus is maintained by one person (Synvoya). There is **no direct push** for
outside contributors; everything lands through a reviewed pull request:

1. **Fork** the repo to your account.
2. **Branch** off `master` with a descriptive name (`fix/…`, `rule/…`, `mapping/…`).
3. **One focused change per PR.** One fix per commit; conventional commit messages
   (`feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `chore:`).
4. **Run `npm run build && npm run eval` before opening the PR** — the build must compile
   clean and eval must stay green (no regressions).
5. **Open the PR.** For mapping changes use the **Compliance mapping change** PR template
   (next section); for detection rules, follow the checklist under *Other contributions*.
6. **The maintainer reviews and merges.** The maintainer is the sole reviewer, so the honest
   verb is *reviewed*, never "independently verified" (see the honesty metric).

---

## Running locally (self-verify)

CodeInspectus ships its **full test suite** so you can verify every claim yourself from a clean
clone — nothing is hidden behind a private CI. Before opening a PR, run all three:

```bash
npm install
npm run build      # tsc --noEmit && tsup — must compile clean (zero type errors)
npm test           # vitest run — unit/regression suite (corpus fixtures, redaction, dedup, routing)
npm run eval       # drives the built MCP server over stdio against fixtures/vulnerable-app
```

- `npm test` is the fast inner loop. It runs the real analyzers over the committed
  `fixtures/secret-rls-corpus` (true-positive **and** false-positive cases) and locks redaction,
  dedup, SARIF normalization, and file-routing behaviour. It needs **no** engine binaries.
- `npm run eval` should report **17 passed, 0 failed** with the engines installed. The two
  engine-dependent evals (Opengrep SQLi, Trivy SCA) **auto-skip** if you haven't run
  `install-engines` — a **skip is acceptable, a fail is not.**
- A green `npm test` + `npm run eval` on your machine is the same gate the maintainer applies.

---

## Pushing a branch — the demo GIF and `http.postBuffer`

This repo tracks a ~1.95 MB animated demo (`assets/codeinspectus-demo.gif`) that the README
embeds. Pushing a branch to your fork over **HTTPS** has to upload that object, and git's default
`http.postBuffer` (~1 MB) is smaller than it — so the push can fail with `the remote end hung up
unexpectedly` (or `send-pack: unexpected disconnect while reading sideband packet`). It's a
transport buffer limit, not a repo-size problem.

If you hit it, raise the buffer for this clone and re-push — or push over **SSH**, which isn't
subject to `http.postBuffer`:

```bash
git config --local http.postBuffer 524288000   # 500 MB; per-clone, so a fresh clone needs it again
```

---

## Compliance-mapping changes (the part with extra rules)

The CWE→control mappings in `data/cwe_to_controls.json` are **AI-drafted and
maintainer-policy-reviewed, but not yet community-verified** (see
`docs/COMPLIANCE-RATIONALE.md`). Every mapping carries a `reviewer` field whose default is
**`"AI-drafted, unverified"`** until a community PR confirms it against its primary source. The
whole point of community review is to move mappings into the community-verified state — but only
with evidence.

### What a mapping-change PR MUST include

Use the **Compliance mapping change** PR template. A PR that changes, adds, or confirms a
CWE→control mapping is **required** to provide:

1. **The official control text.** Quote the control's own wording from its **primary source**
   (e.g. the NIST CSF 2.0 Core, ISO/IEC 27001:2022 Annex A, the AICPA 2017 TSC, CIS Controls
   v8.1, or cwe.mitre.org for an OWASP View ID) — with a citation (document + section/ID). A
   paraphrase is not enough; the maintainer must be able to check your quote against the
   source.
2. **Your basis / credential.** State *why your judgment should carry weight* on this mapping.
   Examples: "ISO 27001 Lead Auditor", "SOC 2 practitioner, 6 audits", "CISSP", or honestly
   "no formal GRC credential — reasoning from the published control text." **All bases are
   welcome, including none** — but it must be stated, because it becomes the attribution.

### How the maintainer reviews it

- The maintainer **verifies your quote against the cited primary source** before merge. If the
  quote doesn't match the source, the PR is not merged.
- The maintainer is the project's author **and** reviewer, so the honest verb is **reviewed**,
  never *verified by a third party*. No PR will be described as "expert verified" or
  "independently verified."

### What merging does to the `reviewer` field

On merge, the affected mapping's `reviewer` is **upgraded** from `"AI-drafted, unverified"` to
your attribution, in the form:

```
reviewer: "<your name/handle>, <stated basis> — confirmed against <cited source>, <date>"
```

That attribution is the record of *who stands behind the mapping and on what authority*. It is
also what increments the honesty metric below.

> **Note (current state):** the `reviewer`/`confidence` fields live in
> `docs/COMPLIANCE-RATIONALE.md` today, **not** in `data/cwe_to_controls.json` — the data file
> is read by the scanner and must not grow sibling keys that could break the mapper. Wiring
> these fields into the data file and the `compliance_report` output is a planned code change
> (tracked as CG-09). Until then, a merged mapping PR updates the rationale doc's table.

---

## The honesty metric

CodeInspectus tracks every retained CWE→control mapping through **three explicit states** and
reports the real counts, not a flattering one:

1. **AI-drafted** — the mapping's origin.
2. **Maintainer-policy-reviewed** — checked by the maintainer against a conservative policy (the
   reconciliation that retained 96 mappings). **Today: 96 / 96.**
3. **Community-verified** — a contributor confirmed the mapping against the control's primary
   source via a merged PR (bar above), upgrading its `reviewer` field. **Today: 0 / 96.**

> **community-verified ratio = (community-verified mappings) / (total retained mappings) =
> 0 / 96 = 0%.**

Every merged mapping PR that meets the bar moves a row from maintainer-policy-reviewed to
community-verified and raises this ratio. The goal is **not** to hit 100% by lowering the bar —
it is to make the *real* state legible. A low ratio honestly reported beats a high ratio that
hides AI guesses.

---

## The 10 guardrails (a PR must respect every one)

These invariants are what make CodeInspectus trustworthy. A change that violates any of them
will not be merged, however useful it otherwise is:

1. **No engine fork.** Opengrep, Gitleaks, and Trivy are called as pinned subprocesses — never
   forked or patched.
2. **SHA-pin + verify before exec.** Every engine binary is SHA256-pinned in
   `engines.lock.json` and its hash is verified before it runs.
3. **Fail-closed verification.** An unpinned or mismatched binary is refused, not run. Trust
   gates fail closed (the publish allow-list works the same way).
4. **stdout is JSON-RPC only.** All logging goes to stderr via `src/logger.ts`. **No
   `console.log` anywhere in `src/`** — it corrupts the MCP stream.
5. **Zero scan-time egress, no telemetry.** Scans do no network I/O; the only networked step is
   `install-engines`. Never add a phone-home.
6. **Compliance = code-level coverage only.** Never emit "% compliant", "you pass", or any
   certification language; always show the code-visible denominator + disclaimer.
7. **Read-only tools.** The scanner reads and reports; it never writes to or deletes the user's
   files (SBOM goes to the managed dir). The agent applies fixes.
8. **Secret redaction.** No raw secret value in any output — type + location + redacted preview.
9. **Cross-engine secret dedup.** Overlapping secret findings (e.g. Trivy ⨯ Gitleaks) are
   merged, not double-reported.
10. **AI-check scope discipline.** The custom AI checks target AI-code / vibe-coding failure
    modes the engines miss — not homegrown generic SAST (that is Opengrep's job).

---

## Other contributions

### Detection rules (`detection-db/**`, `src/ai-checks/**`)

CodeInspectus ships **35 curated detections** today (see `detection-db/manifest.json`): the
AI-code checks (`ci-ai-*`), the MIT `security-baseline` SAST rules (`ci-baseline-*`), and a few
custom secret rules (`codeinspectus-*`). The set grows through a **human-reviewed weekly
intake** — the maintainer triages proposals in batches. There is **no autonomous rule
generation**: every rule is written and reviewed by a person, with fixtures, before it ships.
(Have a footgun in mind? Open a **New detection proposal** issue — it asks for the precision
discipline below up front.)

**Precision is the merge bar.** False positives are the #1 adoption killer for a security
tool — a scanner that cries wolf gets muted, and then it catches nothing. A rule earns merge
by being *precise*, not by flagging more.

- **Ship fixtures — non-negotiable.** Include a **true-positive** fixture the rule must catch,
  **and** — wherever the rule could plausibly over-fire — a **false-positive / near-miss**
  fixture it must **not** flag. **Both directions are required:** a rule with no near-miss
  fixture for a realistic safe case will be sent back. Wire the fixtures into the vitest corpus
  so the precision check is a standing regression lock, not a one-time claim.
- **Rule ids are append-only — never rename or restructure a shipped one.**
  - **Internal ids** are lowercase-kebab, namespaced: `ci-ai-*` (AI-code checks) /
    `ci-baseline-*` (SAST baseline) / `codeinspectus-*` (secret rules).
  - **Display ids** are the uppercase sequential form users see, e.g. `CI-0001`.
  - A shipped internal `ruleId` is a **stable fingerprint**: it feeds finding dedup/suppression
    **and rescan continuity** — the `scan → fix → rescan` loop matches findings across runs by
    fingerprint. Renaming, splitting, or merging an id **silently breaks rescan**: a fixed
    finding reads as "introduced", a real one as "resolved", with **no error** to warn you.
  - **Safe vs unsafe:** *adding* a new id, or *adding* sinks/cases to an existing rule
    (additive — same id, new matches), is safe. *Renaming / merging / splitting* a shipped id is
    not. If matching must change, change the rule body **under the same id**.
- **Provenance.** Assert in the PR that your rule is **original or a convergent functional
  idiom** — *not* copied from a no-sell-licensed registry (`opengrep/opengrep-rules`, Commons
  Clause; `semgrep/semgrep-rules`, Semgrep Rules License). Converging on the one canonical
  form of a check (merger / scenes a faire) is expected and fine; copying expression is not.
  See [`docs/legal/RULE-DERIVATION-REVIEWS.md`](docs/legal/RULE-DERIVATION-REVIEWS.md) and
  [`docs/RULE-PROVENANCE.md`](docs/RULE-PROVENANCE.md).

### Bug fixes / features

One fix per commit, conventional commit messages, and `npm run build && npm run eval` must
pass (eval stays green). Don't touch files in the CLAUDE.md "Requires approval" / "Never
touch" lists without saying so.

By contributing you agree your contribution is licensed under the project's MIT license.
