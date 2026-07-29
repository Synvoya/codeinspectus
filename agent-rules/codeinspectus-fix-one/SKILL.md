---
name: codeinspectus-fix-one
description: Investigate and remediate exactly one user-selected CodeInspectus finding with evidence-gated reproduction, a separately approved minimal patch, focused regression testing, and an exact-prior-scan rescan. Use when a user asks an agent to examine, reproduce, fix, or verify one CodeInspectus finding without batching unrelated findings or overstating resolution.
---

# Fix One CodeInspectus Finding

Treat an "accepted finding" as one finding the user selected for investigation. Do not interpret the local triage state `Accepted` as reproduction, patch, or checkpoint approval.

1. Establish the exact case.
   - Require one prior `scan_id`, one finding ID, and the exact target path.
   - Load that stored scan and finding. Stop if either identity or scope differs.
   - Keep every other finding out of the patch. Report unrelated findings separately.
2. Adjudicate before changing code.
   - Inspect the source, sink, controls, and reachability in repository context.
   - Classify the target as actionable, disproven, or unverified. A scanner match is evidence, not exploitability proof.
   - If disproven, explain the evidence and stop without editing. Do not call it `resolved`.
3. Gate reproduction independently.
   - Do not reproduce by default. Propose only a bounded, local, reversible, non-destructive reproduction.
   - Reproduce only after explicit user approval. Never expose secrets, attack external systems, alter production, or execute unsafe target content.
   - If reproduction is unsafe or impractical, record that proof gap and continue with static evidence only if a safe patch can still be justified.
4. Design a focused regression.
   - Identify or propose the smallest test that traces to this finding. Do not add it yet.
5. Propose one minimal edit set.
   - Show the intended source and test files, behavior change, test, risks, and exclusions.
   - Ask for patch approval separately from investigation, triage, reproduction, or checkpoint approval. Do not edit before approval.
   - If rejected, stop with no edit.
6. Apply only the approved test and source patch.
   - Make no source or test edit before explicit patch approval.
   - Add the focused regression first and capture failing-before-fix evidence when practical. If the test cannot run or does not reproduce the condition, stop before the source patch unless the user explicitly accepts that named proof gap.
   - Preserve unrelated behavior and findings. Do not opportunistically refactor or batch adjacent issues.
7. Verify in separate evidence lanes.
   - Run the focused regression, then relevant surrounding tests. Report failures as test evidence.
   - Call `codeinspectus_rescan` with the same target path and the exact original `scan_id` as `prior_scan_id`; never rely on the most-recent-scan default.
   - Claim scanner resolution only when the target appears in CodeInspectus `resolved`. Treat `remaining` as unresolved and `not_rechecked` as a proof gap. Never convert missing coverage into success.
8. Report four sections: investigation evidence, regression evidence, test evidence, and rescan/proof gaps. List unrelated remaining or introduced findings without fixing them.

Keep CodeInspectus itself read-only. The agent owns only the separately approved source and test edits.
