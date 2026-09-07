# V3 repository-trust migration

CodeInspectus 3.0.0 introduces a major JSON/SDK contract for repository trust and provenance. It
does not add repository-trust detectors or cleanup behavior; those remain V3.1–V3.4 work.

CodeInspectus 3.1.0 activates deterministic source-integrity inspection. CodeInspectus 3.2.0 adds
bounded explicit AI-attribution and local C2PA/asset-metadata inspection within the same compatible
export `3.0.0` and repository-trust `1.0.0` contracts. Consumers must inspect each capability's
coverage independently. Statistical-watermark verification remains `unavailable`.

## Contract versions

| Surface | V2 | V3 |
|---|---:|---:|
| Package / CLI / MCP server / SDK API | 2.6.0 | 3.2.0 |
| Canonical JSON export | 2.0.0 | 3.0.0 |
| Repository-trust document | absent | 1.0.0 |
| SARIF standard | 2.1.0 | 2.1.0 |
| Stored scan | 2.0.0 | 2.0.0 |
| Sealed bundle manifest | 1.0.0 | 1.0.0 |

The V2 packaged schemas remain in the npm artifact for historical validation. New JSON exports use
`https://codeinspectus.com/schemas/v3.0.0/export.schema.json` and require a top-level
`repository_trust` document.

## Repository-trust document

The document is non-CWE and non-severity-bearing. It contains:

- `schema_version: "1.0.0"`;
- explicit aggregate and per-capability coverage;
- summary counts for `verified`, `probable`, `informational`, and `not_verifiable`;
- artifact records with location, marker class, evidence, validator, confidence, limitations, and
  remediation eligibility;
- `requires_approval: true` on every remediation record.

V3.2 keeps overall `coverage.state: "partial"` because statistical-watermark verification is not
implemented. Source integrity, explicit attribution, and content provenance each report `ran`,
`partial`, or `not_applicable` independently. C2PA validation can also be partial when the optional
official peer validator is not explicitly installed or cannot run. An empty artifact array is
meaningful only for a specific capability that reports `ran`; it is never a general clean-authorship
claim.

## JSON consumer migration

1. Accept export `schema_version: "3.0.0"` and the V3 schema URI.
2. Require and retain `repository_trust`; do not merge its artifacts into CWE vulnerability counts.
3. Interpret artifact state independently from vulnerability severity.
4. Treat `not_run`, `partial`, `not_applicable`, and `unavailable` as coverage limits.
5. Never interpret an empty artifact array as a clean audit unless coverage is `ran` and the
   capability-specific limitations permit that conclusion.

## TypeScript SDK migration

Replace `JsonExportV2`/`SarifExportV2` annotations with `JsonExportV3`/`SarifExportV3`. New code can
import `RepositoryTrustDocumentV1` and `RepositoryArtifactV1`. Deprecated V2 aliases remain exported
as source-compatibility aliases, but `CodeInspectusClient.scan()` and `exportScan()` validate and
return export schema `3.0.0`.

`SDK_COMPATIBILITY` now reports:

```ts
{
  cli_major: 3,
  export_schema: "3.0.0",
  repository_trust_schema: "1.0.0"
}
```

## Stored scans and sealed bundles

Legacy stored scans without `repository_trust` remain readable. When rendered or exported by V3,
they receive the explicit unavailable envelope rather than fabricated provenance evidence.

New sealed bundles record export schema `3.0.0`. The V3 verifier continues to accept V2 bundle
manifests that record export schema `2.0.0`; their sealed export, findings, coverage, SARIF identity,
and artifact hashes are checked through the legacy compatibility path.

## Unchanged behavior

- Scans remain local and read-only.
- Scan-time network egress remains zero.
- CLI policy exit codes and severity semantics are unchanged.
- Remediation still requires the user's agent and explicit approval.
- V3.1 detects bounded source-integrity Unicode markers. V3.2 observes explicit attribution and
  validates supported local C2PA records, but neither version edits them or infers authorship from
  absent evidence. Statistical, pixel, visible-logo, perceptual, audio, and frame-by-frame watermark
  detection/removal remain outside the shipped implementation.
