# CodeInspectus security loop (Claude Code rule)

After you generate or substantially modify code in this repo, run the CodeInspectus
loop. **Principle: CodeInspectus REPORTS; the user DECIDES; you fix only with consent.**
Scans and reports never edit or delete your source code or repository (engine data and scan history stay under `~/.codeinspectus`). Only `codeinspectus_apply_cleanup` and `codeinspectus_rollback_cleanup` change a repository, and only for an exact cleanup plan the user approved; `codeinspectus_generate_sbom` writes to a managed directory or an absolute `.json` path the user chooses.

1. **Scan.** Call `codeinspectus_scan` with the absolute repo path. It runs locally with
   zero network egress and returns CWE-keyed findings, each with a `remediation`. Inspect
   `engine_setup`: if it is not `ready`, explain the exact state (partial engine coverage only for
   `repair_required`; DB freshness/rescan continuity for `db_refresh_recommended`) and ask for approval
   before setup through `codeinspectus_setup` (plan first) or `npx codeinspectus setup`. Never download engines
   silently or as part of the scan.
2. **Surface — always, before touching any code.** Present the findings to the user first.
   Group by severity, **criticals first**. For each finding give: (a) a plain-language
   explanation of the risk a non-expert can understand, (b) the location (`file:line`), and
   (c) the recommended fix from its `remediation`. Use `codeinspectus_explain_finding` for
   depth when useful. **Never fix silently. Never skip straight to patching.**
3. **Select one finding.** Ask the user to choose exactly one finding to investigate. A triage state
   of `Accepted` is review context, not permission to reproduce, checkpoint, or edit.
4. **Checkpoint first (git safety), then fix — only what was approved.** BEFORE applying any edit,
   check the scan's read-only `git_safety` advisory: if `state` is `no_git` or `dirty`, surface its
   `recommendation` and — **only with the user's approval** — offer to create a rollback point (`git
   init` + an initial commit, or commit/stash the current changes) so a fix can be undone cleanly.
   **CodeInspectus never runs git commands that change the repo, and scans never write to it; YOU run git, and only if the user
   approves** (`clean`/`unknown` → say nothing). Do not edit yet; the selected finding's
   source-and-test proposal has its own approval gate below. Scans never write files.
5. **Rescan after the contract below.** After its approved source patch and tests, call
   `codeinspectus_rescan` (same path) and report `resolved`, still firing, and introduced findings.
   Do not claim a fix worked unless the exact-prior-scan rescan confirms it.
6. **Hardcoded secrets need rotation — say so.** For a credential finding, removing the key
   from code is NOT enough: the exposed value is already compromised. Tell the user they must
   **rotate/revoke the key** at the provider (you cannot do this for them), in addition to
   moving it to a server-side secret store. Never remove a secret and report "fixed" without
   surfacing the required rotation.

Compliance: if the user asks, call `codeinspectus_compliance_report` and present it as
**code-level control coverage only** — never certification or a "% compliant" figure; always
show the disclaimer.

Keep secret values redacted — CodeInspectus already redacts them; never paste a raw secret
back to the user.

## Fix-one-finding contract

Load the selected prior `scan_id`, finding ID, and exact target. Inspect source, sink, controls, and
reachability before editing; classify the target as actionable, disproven, or unverified. If
disproven, explain the evidence and stop without calling it `resolved`.

Do not reproduce by default. Reproduce only with an explicitly approved, bounded, local,
reversible, safe method; record unsafe-to-reproduce as a proof gap. Identify or propose a focused
regression without adding it yet.

Propose the smallest source-and-test patch for this finding alone and request patch approval
separately from triage, investigation, reproduction, and checkpoint approval. Make no source or
test edit before explicit patch approval; do not edit if rejected. After approval, add the focused
regression first and capture failing-before-fix evidence when practical. If it cannot run or does
not reproduce the condition, stop before the source patch unless the user explicitly accepts that
proof gap. Then apply the source patch, run focused and relevant tests, and call
`codeinspectus_rescan` on the same target with the exact original scan ID as `prior_scan_id`. Claim scanner resolution only when the target is in CodeInspectus `resolved`;
`remaining` is unresolved and `not_rechecked` is a proof gap. Do not fix unrelated findings.
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
