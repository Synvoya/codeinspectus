# One-finding remediation workflow

CodeInspectus scans and rescans; it never edits a target repository. The shipped agent rules define a conservative workflow for an external coding agent to investigate and remediate exactly one user-selected finding.

"Accepted finding" in this workflow means the one finding the user selected for investigation. It does not mean the triage state `Accepted`. A triage annotation records review context and never authorizes reproduction, a checkpoint, a regression-test edit, or a source edit.

## Required sequence

1. Load one exact prior scan ID, finding ID, and target. Stop on an identity or scope mismatch.
2. Inspect the repository evidence for the source, sink, controls, and reachability. Classify the target as actionable, disproven, or unverified.
3. If a reproduction would add useful evidence, propose a bounded, local, reversible, non-destructive method. Run it only after explicit approval. Never expose secrets, attack an external system, alter production, or execute unsafe target content.
4. Identify and propose the smallest focused regression, source change, files, risks, and exclusions. Make no source or test edit yet.
5. Request explicit edit approval separately from investigation, triage, reproduction, and checkpoint approval. A rejection ends the workflow without an edit.
6. After approval, add the focused regression first. Capture failing-before-fix evidence when practical. If the test cannot run or does not demonstrate the condition, stop before the source patch unless the user explicitly accepts that proof gap.
7. Apply only the approved minimal source patch. Do not refactor adjacent code or fix another finding.
8. Run the focused regression and relevant surrounding tests.
9. Call `codeinspectus_rescan` with the same target path and the exact original scan ID as `prior_scan_id`; never rely on the most-recent-scan default. Only CodeInspectus `resolved` is scanner-resolution evidence. `remaining` is unresolved; `not_rechecked` is a proof gap.

## Outcome boundaries

| Condition | Required report |
|---|---|
| Repository context disproves the finding | Explain the control/reachability evidence; no edit; do not label it `resolved`. |
| Reproduction is unsafe or impractical | Do not run it; record the missing reproduction evidence separately. |
| Regression cannot run or fails unexpectedly | Keep the failure as regression/test evidence; do not silently continue to the source patch. |
| User rejects the patch | Stop with no source or test edit. |
| Rescan returns `not_rechecked` | Report an unresolved proof gap, even if tests pass. |
| Selected target is `resolved`, unrelated findings remain | Claim resolution only for the selected target; list unrelated findings without changing them. |

Every final report keeps four evidence lanes separate: investigation, regression, tests, and rescan/proof gaps. A test proves only its asserted behavior. A rescan proves only the scanner classification it returns. Neither substitutes for missing runtime or coverage evidence.

The primary compatibility surface is the client rule files in `agent-rules/`. The repository-contained `agent-rules/codeinspectus-fix-one/` skill carries the same workflow for skill-capable agents. Its structure validates locally, but a document-level validation alone is not proof that any particular client discovers or follows it correctly.

The synthetic, redacted scenario contract in `fixtures/agent-remediation-workflow/cases.json` covers an actionable selection, disproven finding, unsafe reproduction, `not_rechecked`, rejected patch, unusable or failing regression, and unrelated remaining findings.
