# Synvoya gap layer

Synvoya is CodeInspectus's own, offline advisory layer for the things the commodity engines
(Opengrep, Gitleaks, Trivy, osv-scanner) do not report. It ships in the npm package, runs inside
every vulnerability scan (`vuln` scanner class), and never touches the network at scan time.

This page describes what ships today. Items planned for the rest of 4.0 are listed under
[Not covered yet](#not-covered-yet) and are not present.

## What it adds

| Gap | Example |
|---|---|
| Declared runtimes with known advisories | `.nvmrc` pins Node.js 20; `composer.json` requires `"php": "8.1.*"` |
| End-of-life lines | Node.js 20, PHP 8.1, Python 3.9, a `postgres:12` image |
| Exploited products that are not packages | Adobe Commerce / Magento (`composer.lock`), WordPress core, products named by container image |
| Malicious package versions and package CVEs the upstream databases do not list yet | an npm version of a package withdrawn for malware |

A finding always describes what the repository **declares**, never what is deployed. Every
runtime or image fix says to rebuild and redeploy, and every malware finding includes credential
rotation.

## "Synvoya (CodeInspectus)" is a display family, not a rename

Findings from detection CodeInspectus owns are grouped under the display family
**Synvoya (CodeInspectus)**: the `synvoya` engine itself, the native `codeinspectus-ai` and
`codeinspectus-pub` engines, and the Opengrep and Gitleaks rules CodeInspectus authored. The
family is a label for humans.

Machine identifiers never change. Each finding keeps its raw `engine` (`opengrep`, `gitleaks`,
`trivy`, `osv-scanner`, `codeinspectus-ai`, `codeinspectus-pub`, or `synvoya`), its `rule_id`,
its `id` and its `fingerprint`. The family appears only as the optional field
`engine_family: "synvoya"` on findings in MCP scan and rescan results and in stored scans, and on
rules in `codeinspectus_list_rules`; CLI text output shows the label next to the raw engine. It is
assigned after de-duplication, so it is never an input to fingerprints, dedup keys, baselines, triage
or rescan matching. Export schema `3.0.0` is immutable and does not carry it, so CLI
`--format json`, `export` (JSON, SARIF, CSV), bundles and the TypeScript SDK write only the raw
`engine`.

Findings the `synvoya` engine produces use rule ids of the form `SYN-<year>-<number>` (a dataset
advisory) or `SYN-EOL-<product>-<cycle>` (an end-of-life line).

## What it reads

Synvoya has three bounded, read-only readers and uses the package inventory the other engines
already produce.

| Reader | Files | Declares |
|---|---|---|
| Runtime pins | `.nvmrc`, `.node-version`, `.tool-versions`, `mise.toml`, `package.json`, `composer.json`, `composer.lock`, `.python-version`, `runtime.txt`, `.ruby-version`, `Gemfile`, `Gemfile.lock`, `global.json`, `*.csproj`, `.java-version`, `.sdkmanrc`, `pom.xml`, `go.mod`, GitHub Actions workflows (setup steps and matrices) | Node.js, PHP, Python, Ruby, Go, .NET, Java versions |
| Image tags | `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, Compose, Kubernetes and Helm YAML, GitHub Actions `container` and `services` | runtime images (`node:22.1.0-alpine`), tracked end-of-life images, and images that run a known package or product |
| Products | `composer.lock` (Adobe Commerce, Magento Open Source, WordPress core packages), `wp-includes/version.php` | product versions |
| Package inventory | the package lists osv-scanner (`--all-packages`) and Trivy (`--list-all-pkgs`) already produced in the same scan | locked package versions |

A single-file scan target is read on its own when a reader reads that kind of file (a workflow
is read under its `.github/workflows/` path, `wp-includes/version.php` under its WordPress root).
Any other file target gets the note "Synvoya reads runtime, image and product declarations from
directories; <name> was not checked", and is never recorded as checked.

Synvoya does no lockfile parsing of its own: if neither osv-scanner nor Trivy ran, package
advisories simply have no inventory to judge, and that shows in the engine note. `ARG` defaults
and workflow matrix values are resolved. A reference that stays unresolved (for example
`FROM ${BASE_IMAGE}` with no default) is an `info` note, never a finding and never lowered
coverage.

## When a declaration becomes a finding

Severity always comes from the advisory. The declaration type only sets **confidence**.

| Declaration | Rule | Finding? | Confidence |
|---|---|---|---|
| Exact (`22.1.0`, `node:22.1.0-alpine`, a locked package) | The exact version is inside an affected range | Yes | high |
| Floating on a supported line (`22`, `node:22-alpine`, `8.3.*`) | The release it resolves to can still be a fixed one | No. An `info` coverage note says to pin to the fixed release | n/a |
| Floating or range, every resolvable release affected | Every release line it can resolve to today is affected | Yes | medium |
| Floating or range on an end-of-life line (`.nvmrc 20`, `php 8.1.*`, `php:8.1`) | Every resolvable line is past its end-of-life date, and the advisory affects the newest release on it | Yes | high |
| End-of-life line, no advisory | The cycle's end-of-life date has passed | Yes, one `SYN-EOL-<product>-<cycle>` finding (high severity for a runtime, medium for a product) | high |
| Adobe Commerce / Magento on a patch-level line | The vendor fix is a hotfix that does not change the version string | Yes, **medium** "Verify \<bulletin\> is applied to ..." with the patched releases to upgrade to. A line the vendor never patches is proven by the version alone | high |
| Provisional advisory | The maintainer review could not fully confirm the entry | Yes, with `confidence: "low"` and "(provisional — verify with the vendor)" in the title. Fixed versions the review did not confirm are not listed | low |
| No fixed release exists (`no_fix_available`) | The advisory states there is no fix | Yes; the remediation says to replace or remove the package | per declaration |

Anything a version scheme cannot compare is a note, never a finding: unknown is never treated as
affected. Fixes are structured data (`fixed` versions) plus reviewed prose, never a command an
agent runs.

## Enrichment, not merging

When Trivy or osv-scanner already reports the advisory a Synvoya package finding reports, there
is **one** finding: the upstream one. Synvoya's fix is appended to that finding's remediation
steps (a step beginning `Synvoya SYN-...:`) and nothing else about it changes. Its id,
fingerprint, engine, severity, title, message and producer components stay exactly as the
upstream engine produced them, so triage and rescan matching never detach from it.

A Synvoya finding is dropped into an upstream one only when an upstream finding in the **same
file** names the same ecosystem, package and version and shares an advisory id (rule id or alias).
An advisory reported only in another lockfile stays a Synvoya finding, so its location is never
lost. Entries marked `covered` in the dataset (an upstream engine now reports them) run only
while the covering engine's local database is older than the entry's `covered_since` date.

## Coverage and rescan

- If the dataset cannot be loaded, the `synvoya` engine is `available: false, ran: false`, the
  scan carries the warning `Synvoya gap advisories unavailable: ...`, and the other engines are
  unaffected. It is never a silent zero.
- What the readers skip (a symlink, an oversized file, a template that is not a manifest, a
  deadline) is recorded as evidence in the engine note and in `coverage_notes` (component
  `engine:synvoya`). Runtime and image inputs do not lower coverage.
- Rescan confirms a Synvoya finding fixed only when **every producer** of that finding checked
  its file again. A finding records its producers as `synvoya:runtime`, `synvoya:images`,
  `synvoya:products`, `synvoya:inventory:osv-scanner` or `synvoya:inventory:trivy`. Each scan
  records, per producer, the files it fully checked (`synvoya_checked`): a file counts only when
  the producer parsed all of it and every declaration in it could be judged.
- Otherwise the prior finding is `not_rechecked` (and the rescan `partial`), never `resolved`:
  the file was skipped, read only in part, holds something Synvoya could not judge, was removed
  or moved, the reader failed, the 30-second reader deadline was reached, or the dataset was
  unavailable. A reached deadline omits all three reader sets, because a cut walk cannot name
  every file it missed.

## Dataset integrity

The dataset lives in `detection-db/synvoya/`: `advisories.json`, `aliases.json`, `eol.json` and a
`manifest.json` holding each file's SHA-256 digest. The loader reads every file once without
following symlinks, caps each at 8 MiB, verifies the digests **before** parsing anything, then
validates strict schemas. Any failure (missing file, edited byte, schema violation) makes the
engine unavailable. The npm package is the trust root: the manifest is not separately signed.

The advisory text is authored by CodeInspectus from cited sources and licensed Apache-2.0. The
end-of-life table comes from [endoflife.date](https://endoflife.date) (MIT). See
`detection-db/synvoya/LICENSE-PROVENANCE.md`. The dataset shipped with this release has 330
advisories (40 provisional; 10 gated for a later release and not evaluated yet) and 335 end-of-life
cycles for 17 products. `codeinspectus_list_rules` reports the dataset version and rule count.

## Limits and caps

| Bound | Value |
|---|---|
| Walk | depth 12, 20,000 entries, 1 MiB per file (16 MiB for `composer.lock`); no symlinks; `node_modules`, `vendor` (except the bounded WordPress core probe), `.git` and build output skipped |
| Per file | 64 declarations, 64 notes; YAML 256 documents, depth 32, 50,000 nodes; a workflow matrix expands to at most 32 values per key and 256 per file |
| Per scan | 2,000 declarations per reader; the image and product readers parse at most 64 MiB each |
| Dockerfile `ARG` | substituted values and image references are bounded to 512 characters; longer ones become unresolved |
| Reader deadline | 30 seconds for all readers together; no new file is started past it |
| Notes | at most 50 Synvoya coverage notes; priority notes (deadline, reader failure, caps) are never dropped |
| Checked-file sets | a set larger than 10,000 entries is not recorded, so a rescan confirms nothing from it |

A file that hits a bound is skipped with a reason, never read in part and never a crash.

## Not covered yet

These are planned for later in 4.0 and are not part of this release:

- Vendored and CDN-loaded JavaScript libraries.
- GitHub Actions advisories (the dataset already holds such entries; they are marked for the
  reader that arrives with that work and do not run).
- PHP and Node source rule packs.
- Noise reduction work on existing detectors.

Also outside Synvoya today: WordPress plugin and theme versions (they stay the declared gap
`wordpress-plugins`), Maven qualifiers that cannot be ordered (treated as unknown, so never
affected), and anything the deployed system does that a declaration does not show.
