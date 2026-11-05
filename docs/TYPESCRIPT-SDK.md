# TypeScript SDK

CodeInspectus 3.3 includes a thin typed process wrapper at `codeinspectus/sdk`:

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

## Coverage gaps

Inputs no bundled engine analyzes (for example Ruby source or PHP Twig templates with no bundled SAST rules, a `deno.lock`, a
`package.json` without a lockfile, or files Opengrep could only partly parse) are declared coverage
gaps with stable ids. A gap makes `coverage.aggregate` read `partial`, so `client.scan()` exits 2 by
default. Each gap appears in `coverage.evidence` as an item with `component: "gap:<id>"`,
`category: "declared_scope"` and `state: "partial"`, and each id you accepted as an item with
`component: "accepted-gap:<id>"` and `state: "informational"`; the gap ids are listed in
[CI-POLICY.md](CI-POLICY.md#declared-coverage-gaps).

```ts
const result = await client.scan(repository, { failOnSeverity: "high", acceptGaps: ["php-sast", "deno-lock"] });
// Exit 0 or 1 is now possible although coverage.aggregate is still "partial".
```

Two gap ids are new in 4.0: `vendored-js` (vendored or CDN-loaded JavaScript libraries not checked because
osv-scanner or its OSV npm database is not installed) and `third-party-bundles` (minified or `vendors/` files
the Synvoya pack pass skipped); both are reported and accepted like any other id. The `php-sast` gap now names only Twig
templates, because the Synvoya PHP rule pack covers `.php`, `.phtml` and `.blade.php`.

`acceptGaps` maps to `--accept-gaps`. An accepted gap stays listed and partial; the policy passes
coverage only when every non-complete evidence item is a gap you named. Any other cause still exits 2,
and an unknown id makes the CLI reject the command (the SDK throws `CodeInspectusSdkError`).
`client.compareHistory()` honours a stored scan's accepted language and component gaps
(`<language>-sast`, `vue-sast`, `svelte-sast`, `astro-sast`); every other accepted gap (`sast-parse-errors`, `third-party-bundles`, `vendored-js`,
the lockfile gaps and the rest) still makes the comparison partial, because an engine may have analyzed that input in the other
scan. Gap ids are never removed: when a release closes a gap, its id is no longer reported but is still
accepted as a no-op, so a configured list keeps working across upgrades.

### Licence findings (4.0)

Licence findings are opt-in. `client.scan()` leaves them out unless you pass `includeLicenses: true`
(`--licenses`); the export then carries an informational coverage item with
`component: "scanner:license"` and the detail "Licence findings were not requested (use
include_licenses / --licenses)." That item never makes `coverage.aggregate` partial. With
`includeLicenses: true` the findings and their fingerprints are the same as in 3.x. A scanner list that
names `license` also requests them.

```ts
const result = await client.scan(repository, { includeLicenses: true });
```

## Versioned contracts

The SDK exports explicit contract names:

- `FindingV3`, `CoverageV3`, `JsonExportV3`, `SarifExportV3`
- `RepositoryTrustDocumentV1`, `RepositoryArtifactV1`, `RepositoryArtifactState`,
  `RepositoryArtifactConfidence`, `RepositoryTrustCapability`, `RepositoryTrustChangesV1`
- `CleanupPlanV1`, `CleanupResultV1`
- `AggregateCoverageV2`, `CoverageEvidenceV2` (unchanged aggregate-coverage contracts)
- `HistoryListEntryV1`, `HistoryListResultV1`, `HistoryComparisonV1`
- `BaselineComparisonV1`
- `TriageEventV1`, `TriageAnnotationV1`, `TriageListV1`
- `BundleManifestV1`
- `BulkManifestV1`
- `RepositoryHistoryManifestV1`
- `IssuePayloadV1`, `IssueAdapter`, `DestinationVisibility`

`SDK_API_VERSION` is `4.0.0`. `SDK_COMPATIBILITY` records export schema `3.0.0`,
repository-trust schema `1.0.0`, and cleanup schema `1.0.0`. The V3 SDK accepts those schema
versions and fails closed on another version; additive optional fields within a compatible schema
do not break consumers. Removing or changing a required field, exit meaning or command semantic
requires a new contract version and SDK major.

`Finding.engine` may be `synvoya` (the gap-advisory engine). MCP scan and rescan results and stored
scans may carry the optional display field `engine_family: "synvoya"` on findings from
CodeInspectus-owned detection (shown to humans as "Synvoya (CodeInspectus)"). `engine`, `rule_id`, ids
and fingerprints are never changed by it. The SDK reads the CLI's JSON output, which is export schema
`3.0.0`: that schema is immutable and has no such field, so SDK results never carry `engine_family`;
`engine` there is an open string and carries the raw id.

The set of `Finding.engine` values is open: this release emits `opengrep`, `gitleaks`, `trivy`,
`osv-scanner`, `codeinspectus-ai`, `codeinspectus-pub` and `synvoya`, and a later release may add
more. Treat an unknown value as an engine you have not seen, not an error. Where `engine_family`
appears it is optional and display-only: group by it for presentation, and key anything that must stay stable
(triage, baselines, rescan matching) on `engine`, `rule_id` and `fingerprint`. Findings the `synvoya`
engine produces describe a declared version, and the Synvoya PHP and Node.js rule packs report as
`engine: "opengrep"` with `syn-php-*` and `syn-node-*` rule ids; see [SYNVOYA.md](SYNVOYA.md).

Sealed bundles have more than one verifiable manifest version. `SDK_COMPATIBILITY.bundle_schema` is
`1.1.0`, the version this release seals (it adds osv-scanner to the commodity engines), and
`SDK_COMPATIBILITY.bundle_schemas_verified` lists every version `verifyBundle` accepts: `1.0.0`
(bundles sealed by 3.3.2 and earlier) and `1.1.0`. `BundleManifestV1` covers both; read
`schema_version` before relying on the commodity-engine list. Any other bundle version fails closed.

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
