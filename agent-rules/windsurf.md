# CodeInspectus security loop (Windsurf rule)

CodeInspectus REPORTS; the user DECIDES; you fix only with consent. The tool never edits or deletes
your source code or repository — the only file it writes is an optional SBOM (managed dir by
default, or a path you choose), with data under `~/.codeinspectus`. After generating or editing code:

1. **Scan** — `codeinspectus_scan` on the workspace root (absolute path); local, zero-egress;
   returns CWE-keyed findings + a `remediation` each. Inspect `engine_setup`: if it is not
   `ready`, explain the exact state (partial engine coverage only for `repair_required`; DB
   freshness/rescan continuity for `db_refresh_recommended`) and ask before running
   `npx codeinspectus repair-engines` in the user's terminal. Never download engines silently.
2. **Surface first** — present the findings to the user before any edit: grouped by severity
   (**criticals first**), each with a plain-language risk explanation, the `file:line`, and the
   recommended fix. **Never fix silently; never skip to patching.**
3. **Select one finding** — ask the user to choose exactly one finding to investigate. Triage
   `Accepted` is context only, not reproduction, checkpoint, or edit approval.
4. **Checkpoint first, then fix.** Before editing, if the scan's read-only `git_safety.state` is
   `no_git` or `dirty`, surface its `recommendation` and — **only with user approval** — offer a
   rollback point (`git init` + commit, or commit/stash current changes). **The tool never runs git;
   YOU do, only if approved** (`clean`/`unknown` → stay silent). Do not edit yet; the selected
   finding's source-and-test proposal has its own approval gate below (CodeInspectus only reports).
5. **Rescan after the contract below** — after its approved source patch and tests,
   `codeinspectus_rescan`; report honestly what is resolved, still firing, or new. Don't claim
   "fixed" without the exact-prior-scan rescan confirming it.
6. **Secrets** — a hardcoded credential is already compromised: tell the user to **rotate the
   key** at the provider (you can't), not just move it to env. Never report "fixed" without that.

Compliance: `codeinspectus_compliance_report` — code-level control coverage only; never
certification or "% compliant"; show the disclaimer.

Keep secret values redacted.

## Fix-one-finding contract

Load the selected prior `scan_id`, finding ID, and exact target. Inspect source, sink, controls, and
reachability before editing; classify it as actionable, disproven, or unverified. If disproven,
stop without calling it `resolved`. Reproduce only through an explicitly approved, bounded, local,
reversible, safe method; otherwise record unsafe-to-reproduce as a proof gap.

Identify or propose a focused regression without adding it yet. Propose the smallest source-and-test
patch for this finding only and request patch approval separately from triage, investigation,
reproduction, and checkpoint approval. Make no source or test edit before explicit patch approval;
if rejected, do not edit. After approval, add the focused regression first and capture
failing-before-fix evidence when practical. If it cannot run or does not reproduce the condition,
stop before the source patch unless that proof gap is explicitly accepted.

Then apply the source patch, run focused and relevant tests, and call `codeinspectus_rescan` on the same
target with the exact original scan ID as `prior_scan_id`. Claim scanner resolution only when CodeInspectus returns the target in
`resolved`; `remaining` is unresolved and `not_rechecked` is a proof gap. Keep unrelated findings
untouched. Report investigation, regression, test, and rescan/proof-gap evidence separately.
