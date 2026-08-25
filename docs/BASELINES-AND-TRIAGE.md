# Baselines and local triage

CodeInspectus can compare a fresh canonical scan with an explicit stored scan and attach local review context to exact findings. Neither feature suppresses, deletes, skips, or changes raw scan findings.

## Baseline scans

```bash
codeinspectus scan . --baseline SCAN_ID
codeinspectus scan . --baseline SCAN_ID --fail-on-new-severity high
```

The first command reports `New`, `Existing`, and `Not rechecked / unknown` states. The second enables new-finding-only CI enforcement. A finding is `New` only when the baseline and current scan have the same exact target and repository identity, both persist canonical findings, aggregate coverage is complete, and the relevant producer engines and component signatures are compatible. Otherwise absence is unknown, never new.

Exit codes for `--fail-on-new-severity` are:

- `0`: compatible comparison and no proven new finding at or above the threshold.
- `1`: at least one proven new finding meets the threshold.
- `2`: invalid input, missing baseline, target/repository mismatch, partial or unknown coverage, or incompatible comparison evidence.

The output always retains the current scan's findings. JSON adds the typed baseline projection; SARIF uses the standard `baselineState` values `new` and `unchanged` and omits that property for unknown states. Existing `--fail-on-severity` enforcement cannot be combined with `--fail-on-new-severity`.

## Local triage

```bash
codeinspectus triage add SCAN_ID FINDING_ID --state needs-review --reason "Investigate data flow"
codeinspectus triage list SCAN_ID --format json
codeinspectus triage show SCAN_ID ANNOTATION_ID
codeinspectus triage update SCAN_ID ANNOTATION_ID --state accepted --reason "Validated compensating control"
codeinspectus triage delete SCAN_ID ANNOTATION_ID --reason "Superseded by a corrected annotation"
```

State slugs are `accepted`, `false-positive`, `risk-accepted`, `needs-review`, and `fixed-pending-verification`. `--actor LABEL` is optional on mutations.

Annotations are local, scoped to the exact repository and target, and matched by fingerprint, rule, file, and producer components. Every mutation appends an immutable audit event with source scan, tool version, timestamp, scope, finding identity, reason, state, and optional actor. Delete writes a tombstone; it does not remove history or alter findings.

Managed events live under `~/.codeinspectus/triage/`. Reads are bounded to 5,000 events, 16 MiB per scope, and 64 KiB per event. Invalid JSON, oversized records, symlinks, broken event chains, unavailable storage, or bound exhaustion are reported as partial. List/show can return bounded evidence with exit 2; add/update/delete refuse all mutations until the exact scope is complete and uncorrupted.

JSON list/show responses are versioned envelopes containing the exact scope, source scan, inspection limits and partial state, annotations, and (for show) the append-only audit events. Consumers should check `inspection.partial` before relying on the projection.

Recognized secrets in reason and actor fields are redacted on write and again at public output boundaries. Do not use triage annotations as a secrets store.

JSON and SARIF exports add triage context to matching findings while retaining every raw finding and original count. Current contracts are in `schemas/codeinspectus-export-3.0.0.schema.json`, `schemas/codeinspectus-sarif-3.0.0.schema.json`, `schemas/codeinspectus-repository-trust-1.0.0.schema.json`, `schemas/codeinspectus-baseline-1.0.0.schema.json`, and `schemas/codeinspectus-triage-1.0.0.schema.json`. The packaged V2 export/SARIF schemas remain available for historical validation.
