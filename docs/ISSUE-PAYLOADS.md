# Safe issue-payload exports

CodeInspectus generates reviewable JSON for one exact stored finding at a time:

```bash
codeinspectus issue export SCAN_ID CI-0001 \
  --adapter github --visibility private \
  --output /safe/evidence/github-issue.json
```

Adapters are `github`, `jira`, and `linear`. Destination visibility is mandatory because a public
tracker has materially different disclosure risk from a private one. Every document contains the
declared visibility, a prominent visibility-specific warning, `review_required: true`,
`submission: "not_performed"`, and the destination fields still required before manual submission.

The command has no authentication, connector, URL, token, project lookup or submission code. It
makes no network request and cannot create a live issue. `issue submit`, organization discovery and
implicit destination selection are intentionally unsupported.

Payload content is derived from the normalized redacted V2 export, then defensively cleaned again.
It includes finding identity, rule, severity/confidence, location, CWE, producer components,
aggregate coverage, evidence text and remediation. It excludes source snippets and matched secret
values. Markdown mention/syntax characters are escaped for GitHub and Linear text. Output size,
GitHub/Jira labels, CWE values, producer lists and remediation steps are bounded deterministically.

GitHub's nested `payload` follows the create-issue body shape for a caller-selected repository. Jira
uses Atlassian Document Format for `description`. Jira and Linear payloads deliberately omit
tenant-specific project/issue-type or team identifiers; the wrapper lists those fields
under `required_destination_fields`. Reviewers must confirm authorization, visibility, disclosure
policy, access controls, integrations and retention before sending anything.

Adapter shapes are checked against the official [GitHub create-issue REST contract](https://docs.github.com/en/rest/issues/issues#create-an-issue),
[Jira Cloud v3 issue contract](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/),
and [Linear issue creation contract](https://linear.app/developers/graphql). Destination APIs and
project field configuration can change, so the required manual review remains part of the contract.

An optional `--output` is written atomically and must remain outside the scanned repository. The
versioned schema is `schemas/codeinspectus-issue-payload-1.0.0.schema.json`.
