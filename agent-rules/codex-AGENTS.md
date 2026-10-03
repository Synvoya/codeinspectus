## Security: CodeInspectus loop

**Principle: CodeInspectus REPORTS; the user DECIDES; you fix only with consent.** Scans and reports never edit or delete your source code or repository (engine data and scan history stay under `~/.codeinspectus`). Only `codeinspectus_apply_cleanup` and `codeinspectus_rollback_cleanup` change a repository, and only for an exact cleanup plan the user approved; `codeinspectus_generate_sbom` writes to a managed directory or an absolute `.json` path the user chooses. When you write or change code:

1. **Scan** — `codeinspectus_scan` (absolute repo path); local, zero-egress; returns CWE-keyed
   findings, each with a `remediation`. Inspect `engine_setup`: if it is not `ready`, explain the
   exact state (partial engine coverage only for `repair_required`; DB freshness/rescan continuity
   for `db_refresh_recommended`) and ask for approval before setup through `codeinspectus_setup` (plan first) or
   `npx codeinspectus setup`. Never download engines silently or as part of the scan.
2. **Surface first** — show the user the findings before any edit: grouped by severity
   (**criticals first**), each with a plain-language risk explanation, the `file:line`, and the
   recommended fix. **Never fix silently; never skip straight to patching.**
3. **Select one finding.** Ask the user to choose exactly one finding to investigate. A triage state
   of `Accepted` means local review context only; it is not approval to reproduce, checkpoint, or edit.
4. **Checkpoint first, then fix.** Before editing, if the scan's read-only `git_safety.state` is
   `no_git` or `dirty`, surface its `recommendation` and — **only with user approval** — offer a
   rollback point (`git init` + commit, or commit/stash current changes). **The tool never runs git commands that change your repository;
   YOU do, only if approved** (`clean`/`unknown` → stay silent). Do not edit yet; the selected
   finding's source-and-test proposal has its own approval gate below (CodeInspectus only reports).
5. **Rescan after the contract below.** After its approved source patch and tests,
   `codeinspectus_rescan`; report honestly what is resolved / still firing / new. Don't claim fixed
   unless the exact-prior-scan rescan confirms it.
6. **Secrets** — a hardcoded credential is already compromised: tell the user to **rotate the
   key** at the provider (you can't), not just move it to env. Never report "fixed" without that.

Compliance: `codeinspectus_compliance_report` — code-level control coverage only; never
certification or "% compliant"; always show the disclaimer.

Keep secret values redacted.

### Fix-one-finding contract

For the selected prior `scan_id`, finding ID, and exact target, load that evidence and inspect the
source, sink, controls, and reachability before any edit. Classify it as actionable, disproven, or
unverified. If disproven, report why and stop without calling it `resolved`.

Do not reproduce by default. Reproduce only when the method is bounded, local, reversible, safe,
and explicitly approved; otherwise record unsafe-to-reproduce as a proof gap. Identify or propose a
focused regression, but do not add it yet.

Propose the smallest source-and-test patch for this finding only. Ask for patch approval separately
from triage, investigation, reproduction, and checkpoint approval. Make no source or test edit before
explicit patch approval; if rejected, do not edit. After approval, add the focused regression first
and capture failing-before-fix evidence when practical. If it cannot run or does not reproduce the
condition, stop before the source patch unless the user explicitly accepts that proof gap. Then apply
the source patch, run focused and relevant tests, and call `codeinspectus_rescan` on the same target
with the exact original scan ID as `prior_scan_id`. Claim scanner resolution only when CodeInspectus returns the target in `resolved`;
`remaining` is unresolved and `not_rechecked` is a proof gap. Keep unrelated findings untouched.
Report investigation evidence, regression evidence, test evidence, and rescan/proof gaps separately.

## Repository-trust cleanup (only when the user asks)

Repository-trust artifacts (hidden Unicode, explicit AI attribution, media metadata, C2PA) are
evidence, not vulnerabilities; remove one only when the user asks. Call
`codeinspectus_plan_cleanup` with exact artifact IDs from a fresh scan, show every file,
transformation, blocker, and limitation in the plan, and get approval for that exact plan. Then call
`codeinspectus_apply_cleanup` with the same IDs and `confirm_cleanup=true`; pass
`confirm_rights_to_modify=true` only after the user confirms they may remove that attribution or
provenance. Media cleanup writes a new `.codeinspectus-clean` copy and never changes the original.
Git history and legal, licensing, and compliance records are never eligible. Run the repository's
tests, formatter, and build afterwards; cleanup is incomplete until they pass. Use
`codeinspectus_rollback_cleanup` with the returned cleanup ID to restore an approved change.
