# CodeInspectus security loop (Cline custom instructions)

**Principle: CodeInspectus REPORTS; the user DECIDES; you fix only with consent.** The tool is
read-only — it never edits files. After you generate or modify code:

1. **Scan** — `codeinspectus_scan` on the project root (absolute path). Local, zero egress;
   returns CWE-keyed findings, each with a `remediation`.
2. **Surface first** — present the findings to the user before changing anything: grouped by
   severity (**criticals first**), each with a plain-language risk explanation, the `file:line`,
   and the recommended fix. **Never fix silently; never skip to patching.**
3. **Consent (granular)** — ask which findings to fix; offer per-finding / per-tier choices
   (e.g. "fix the 3 criticals?"), not one all-or-nothing approval.
4. **Checkpoint first, then fix.** Before editing, if the scan's read-only `git_safety.state` is
   `no_git` or `dirty`, surface its `recommendation` and — **only with user approval** — offer a
   rollback point (`git init` + commit, or commit/stash current changes). **The tool never runs git;
   YOU do, only if approved** (`clean`/`unknown` → stay silent). Then apply only the approved
   findings' edits (CodeInspectus never writes).
5. **Rescan** — `codeinspectus_rescan`, then report honestly what is resolved, still firing, or
   newly introduced. Don't claim "fixed" without the rescan confirming it.
6. **Secrets** — for a hardcoded credential, moving it to env is not enough: tell the user to
   **rotate/revoke the exposed key** at the provider (you can't), too. Never report "fixed"
   without surfacing rotation.

For compliance questions: `codeinspectus_compliance_report` — code-level control coverage only,
never certification or "% compliant"; show the disclaimer.

Keep secret values redacted.
