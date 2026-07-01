# CodeInspectus security loop (Windsurf rule)

CodeInspectus REPORTS; the user DECIDES; you fix only with consent. The tool is read-only
(never edits files). After generating or editing code:

1. **Scan** — `codeinspectus_scan` on the workspace root (absolute path); local, zero-egress;
   returns CWE-keyed findings + a `remediation` each.
2. **Surface first** — present the findings to the user before any edit: grouped by severity
   (**criticals first**), each with a plain-language risk explanation, the `file:line`, and the
   recommended fix. **Never fix silently; never skip to patching.**
3. **Consent (granular)** — ask which findings to fix; per-finding or per-tier (e.g. "the 3
   criticals?"), not one all-or-nothing prompt.
4. **Checkpoint first, then fix.** Before editing, if the scan's read-only `git_safety.state` is
   `no_git` or `dirty`, surface its `recommendation` and — **only with user approval** — offer a
   rollback point (`git init` + commit, or commit/stash current changes). **The tool never runs git;
   YOU do, only if approved** (`clean`/`unknown` → stay silent). Then apply only the approved
   findings' edits (CodeInspectus only reports).
5. **Rescan** — `codeinspectus_rescan`; report honestly what is resolved, still firing, or new.
   Don't claim "fixed" without the rescan confirming it.
6. **Secrets** — a hardcoded credential is already compromised: tell the user to **rotate the
   key** at the provider (you can't), not just move it to env. Never report "fixed" without that.

Compliance: `codeinspectus_compliance_report` — code-level control coverage only; never
certification or "% compliant"; show the disclaimer.

Keep secret values redacted.
