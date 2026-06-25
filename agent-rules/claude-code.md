# CodeInspectus security loop (Claude Code rule)

After you generate or substantially modify code in this repo, run the CodeInspectus
loop. **Principle: CodeInspectus REPORTS; the user DECIDES; you fix only with consent.**
CodeInspectus is read-only — it never edits or deletes files.

1. **Scan.** Call `codeinspectus_scan` with the absolute repo path. It runs locally with
   zero network egress and returns CWE-keyed findings, each with a `remediation`.
2. **Surface — always, before touching any code.** Present the findings to the user first.
   Group by severity, **criticals first**. For each finding give: (a) a plain-language
   explanation of the risk a non-expert can understand, (b) the location (`file:line`), and
   (c) the recommended fix from its `remediation`. Use `codeinspectus_explain_finding` for
   depth when useful. **Never fix silently. Never skip straight to patching.**
3. **Get consent — granular.** Ask the user which findings to fix before changing any code.
   Offer per-finding or per-severity-tier choices (e.g. "Fix the 3 criticals? the 8 highs?"),
   not a single all-or-nothing "approve 14 fixes" — the user must be able to choose.
4. **Fix — only what was approved.** YOU apply the approved edits using the finding's
   `remediation`; CodeInspectus never writes files. Do not fix anything that was not approved.
5. **Rescan + report honestly.** Call `codeinspectus_rescan` (same path) and tell the user
   what is now `resolved`, what still fires, and whether anything new was introduced. Do not
   claim a fix worked unless the rescan confirms it.
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
