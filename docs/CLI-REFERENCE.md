# CodeInspectus 2.1 CLI reference

Running `codeinspectus` with no arguments starts the six-tool MCP stdio server. Every explicit
subcommand is a terminal operation. Scans are local and zero-egress; only explicit engine
installation or repair may use the network.

## Current scan and readiness

```bash
codeinspectus preflight TARGET [scan options]
codeinspectus scan TARGET [scan options]
```

Shared scan options:

- `--scanner sast|secret|vuln|misconfig|license|ai` (repeatable or comma-separated)
- `--severity critical|high|medium|low|info`
- `--max-findings N`
- `--format text|json|sarif|csv`
- `--output FILE` or `--output-dir DIRECTORY`
- `--allow-output-in-target` for an explicitly approved output directory inside the target
- `--no-compliance`

Policy and Git scope options:

- `--fail-on-severity LEVEL`
- `--baseline SCAN_ID --fail-on-new-severity LEVEL`
- `--diff BASE_REVISION --head HEAD_REVISION`
- `--working-tree --base BASE_REVISION`

`preflight` never scans, repairs, downloads, authenticates, or writes. A Git-scoped scan reports
changed and supporting-context findings separately and never checks out or changes repository state.

## Export, history, and triage

```bash
codeinspectus export SCAN_ID --format json|sarif|csv [--output FILE]
codeinspectus scans list [--repository PATH] [--path PATH] [--severity LEVEL]
                         [--status clean|findings|partial|unknown] [--since DATE] [--until DATE]
                         [--limit N] [--format text|json]
codeinspectus scans show SCAN_ID [--format text|json]
codeinspectus scans rerun SCAN_ID [--format text|json|sarif|csv]
codeinspectus scans compare OLD_SCAN_ID NEW_SCAN_ID [--format text|json]

codeinspectus triage add SCAN_ID FINDING_ID --state STATE --reason TEXT [--actor LABEL]
codeinspectus triage list SCAN_ID [--limit N] [--format text|json]
codeinspectus triage show SCAN_ID ANNOTATION_ID [--format text|json]
codeinspectus triage update SCAN_ID ANNOTATION_ID --state STATE --reason TEXT [--actor LABEL]
codeinspectus triage delete SCAN_ID ANNOTATION_ID --reason TEXT [--actor LABEL]
```

Triage states are `accepted`, `false-positive`, `risk-accepted`, `needs-review`, and
`fixed-pending-verification`. Triage is append-only context: it never hides, deletes, downgrades, or
suppresses the raw finding.

## Sealed evidence

```bash
codeinspectus bundle create SCAN_ID --output-dir DIRECTORY
codeinspectus bundle verify BUNDLE_DIRECTORY
codeinspectus bundle export BUNDLE_DIRECTORY --format json|sarif|csv [--output FILE]
codeinspectus bundle compare OLD_BUNDLE NEW_BUNDLE [--format text|json]
```

Verification checks the manifest schema, allowed paths, artifact hashes, redaction boundary, and
embedded canonical scan before a bundle can be exported or compared.

## Bounded repository sets and history

```bash
codeinspectus bulk scan PARENT [--concurrency N] [--max-repositories N]
                               [--max-attempts N] [--manifest FILE] [--format text|json]

codeinspectus history scan REPOSITORY --from REVISION --to REVISION
  --since YYYY-MM-DD --until YYYY-MM-DD --max-commits N [scan options]
```

Bulk mode discovers only immediate, already-existing local Git repositories; it never clones or
discovers an account. Repository-history mode requires exact revision/date/count bounds and caps a
request at 50 commits. Shallow, truncated, omitted, failed, or cancelled work cannot report complete.

## Review-only tracker payloads

```bash
codeinspectus issue export SCAN_ID FINDING_ID --adapter github|jira|linear
  --visibility private|public [--output FILE]
```

This produces redacted deterministic JSON for manual review. It performs no authentication,
destination lookup, issue submission, or network request. `issue submit` is intentionally rejected.

## Engine lifecycle and metadata

```bash
codeinspectus repair-engines [ENGINE]
codeinspectus install-engines [ENGINE]
codeinspectus verify-engines
codeinspectus pin-engines [options]
codeinspectus --version
codeinspectus --help
```

`install-engines` remains a compatibility alias. `pin-engines` is maintainer-only. Normal scans
never repair or download engines implicitly.

## Exit status

| Status | Meaning |
|---:|---|
| `0` | Operation completed; coverage was sufficient and configured policy passed. |
| `1` | A configured severity/new-finding policy failed after sufficient coverage. |
| `2` | Invalid input, runtime failure, or partial/unknown coverage. |
| `130` | Interrupted by SIGINT. |
| `143` | Terminated by SIGTERM. |

Coverage takes precedence over finding policy. A zero-finding partial scan exits 2, never 0.

Detailed behavioral contracts live in the linked documents from the project README. Versioned
machine schemas live under `schemas/` and are the compatibility authority for JSON consumers.
