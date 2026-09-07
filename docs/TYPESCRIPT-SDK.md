# TypeScript SDK

CodeInspectus 3.2 includes a thin typed process wrapper at `codeinspectus/sdk`:

```ts
import { CodeInspectusClient, type JsonExportV3 } from "codeinspectus/sdk";

const client = new CodeInspectusClient();
const result = await client.scan("/absolute/path/to/repository", { scanners: ["ai"] });
const report: JsonExportV3 = result.data;

// Exit 2 can still carry a valid report: inspect coverage before interpreting findings.
console.log(result.exitCode, report.coverage.aggregate);
```

The default client invokes `dist/index.js` from the exact installed `codeinspectus` package through
the current Node runtime. It never uses a shell, downloads another scanner, implements detection,
or calls a hosted service. `command` and `commandArgs` may point at another explicit local install.

Typed helpers cover JSON scan/export, stored-history list/comparison, bounded repository-history scanning, triage listing and bundle
verification. `run(args)` exposes other CLI operations without inventing a parallel API. Process
stdout/stderr, timeout and cancellation are bounded. Valid policy exits (`1` and `2`) are returned
with their typed JSON; spawn, timeout, abort, output-bound and incompatible-contract failures throw
`CodeInspectusSdkError`.

## Versioned contracts

The SDK exports explicit contract names:

- `FindingV3`, `CoverageV3`, `JsonExportV3`, `SarifExportV3`
- `RepositoryTrustDocumentV1`, `RepositoryArtifactV1`, `RepositoryArtifactState`,
  `RepositoryArtifactConfidence`, `RepositoryTrustCapability`, `RepositoryTrustChangesV1`
- `AggregateCoverageV2`, `CoverageEvidenceV2` (unchanged aggregate-coverage contracts)
- `HistoryListEntryV1`, `HistoryListResultV1`, `HistoryComparisonV1`
- `BaselineComparisonV1`
- `TriageEventV1`, `TriageAnnotationV1`, `TriageListV1`
- `BundleManifestV1`
- `BulkManifestV1`
- `RepositoryHistoryManifestV1`
- `IssuePayloadV1`, `IssueAdapter`, `DestinationVisibility`

`SDK_API_VERSION` is `3.2.0`. `SDK_COMPATIBILITY` records export schema `3.0.0` and
repository-trust schema `1.0.0`. The V3 SDK accepts those schema versions and fails closed on another version;
additive optional fields within a compatible schema do not break consumers. Removing or changing a
required field, exit meaning or command semantic requires a new contract version and SDK major.

Deprecated `FindingV2`, `CoverageV2`, `JsonExportV2`, and `SarifExportV2` aliases remain exported
to reduce source churn, but V3 typed commands return V3 documents. Migrate annotations to the V3
names and handle the required top-level `repository_trust` field.

This is prepared as a subpath of the main package so there is one install and one scanner. Do not
publish a separate SDK package until final approval and demonstrated demand justify another
compatibility surface.

## Process behavior

- Node 22 and 24 are supported.
- Default timeout: 15 minutes per command.
- Default combined stdout/stderr bound: 32 MiB.
- `AbortSignal` cancels the child process.
- Arguments are passed as an array with `shell: false`.
- The wrapper does not write scan output files; typed helpers consume stdout.
- Repository writes and network behavior remain governed by the invoked CodeInspectus command.

The release gate packs the npm tarball, installs it into a fresh independent project, imports
`codeinspectus/sdk`, invokes that installed package's CLI, and compiles a separate strict TypeScript
consumer against all contract families on Node 22 and Node 24.
