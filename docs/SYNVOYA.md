# Synvoya gap layer

Synvoya is CodeInspectus's own, offline advisory layer for the things the commodity engines
(Opengrep, Gitleaks, Trivy, osv-scanner) do not report. It ships in the npm package, runs inside
every vulnerability scan (`vuln` scanner class), and never touches the network at scan time.

This page describes what ships in 4.0. Items that are not covered are listed under
[Not covered yet](#not-covered-yet). Synvoya has two parts: the gap layer (the `synvoya` engine, which
judges declarations against a bundled dataset) and two rule packs for the Opengrep engine
([Rule packs](#rule-packs-php-and-nodejs)).

## What it adds

| Gap | Example |
|---|---|
| Declared runtimes with known advisories | `.nvmrc` pins Node.js 20; `composer.json` requires `"php": "8.1.*"` |
| End-of-life lines | Node.js 20, PHP 8.1, Python 3.9, a `postgres:12` image |
| Exploited products that are not packages | Adobe Commerce / Magento (`composer.lock`), WordPress core, products named by container image |
| Malicious package versions and package CVEs the upstream databases do not list yet | an npm version of a package withdrawn for malware |
| Vendored and CDN-loaded JavaScript libraries, checked by osv-scanner | `public/js/jquery-1.12.4.min.js`, `<script src="https://code.jquery.com/jquery-1.12.4.min.js">` |

The gap layer's findings describe what the repository **declares**, never what is deployed. Every
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

Synvoya has five bounded, read-only readers and uses the package inventory the other engines
already produce.

| Reader | Files | Declares |
|---|---|---|
| Runtime pins | `.nvmrc`, `.node-version`, `.tool-versions`, `mise.toml`, `package.json`, `composer.json`, `composer.lock`, `.python-version`, `runtime.txt`, `.ruby-version`, `Gemfile`, `Gemfile.lock`, `global.json`, `*.csproj`, `.java-version`, `.sdkmanrc`, `pom.xml`, `go.mod`, GitHub Actions workflows (setup steps and matrices) | Node.js, PHP, Python, Ruby, Go, .NET, Java versions |
| Image tags | `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, Compose, Kubernetes and Helm YAML, GitHub Actions `container` and `services` | runtime images (`node:22.1.0-alpine`), tracked end-of-life images, and images that run a known package or product |
| Products | `composer.lock` (Adobe Commerce, Magento Open Source, WordPress core packages), `wp-includes/version.php` | product versions |
| Libraries | `.js`/`.mjs` banner comments in the first 4 KiB and versioned file names (`jquery-1.12.4.min.js`); versioned CDN URLs (cdnjs, jsDelivr, unpkg, code.jquery.com, Google, StackPath Bootstrap) in scripts, markup and templates. `vendor/` and `vendors/` folders are read only below a web asset root (`public/`, `static/`, `assets/`, `web/`, `wp-content/`) or as Rails `vendor/assets/` | npm packages from the reviewed table in `libraries.json`; never a name guessed from free text |
| GitHub Actions | `uses:` in workflow jobs and steps (`.github/workflows/*.yml`/`.yaml`, top level only) and composite action steps (`action.yml`/`action.yaml`); local `./` actions are skipped, `docker://` steps are seen but not declared | third-party actions (`owner/repo[/path]@ref`), judged by the Actions matcher below |
| Package inventory | the package lists osv-scanner (`--all-packages`) and Trivy (`--list-all-pkgs`) already produced in the same scan | locked package versions |

A single-file scan target is read on its own when a reader reads that kind of file (a workflow
is read under its `.github/workflows/` path, `wp-includes/version.php` under its WordPress root).
Any other file target gets the note "Synvoya reads runtime, image, product and library declarations
from directories; <name> was not checked", and is never recorded as checked.

Synvoya does no lockfile parsing of its own: if neither osv-scanner nor Trivy ran, package
advisories simply have no inventory to judge, and that shows in the engine note. `ARG` defaults
and workflow matrix values are resolved. A reference that stays unresolved (for example
`FROM ${BASE_IMAGE}` with no default) is an `info` note, never a finding and never lowered
coverage.

## GitHub Actions: the Actions matcher

osv-scanner 2.7.0 rejects `pkg:githubactions` purls and panics on `pkg:github` ones, so Actions never
go to it. Synvoya matches them itself against the OSV "GitHub Actions" database (`all.zip`, GitHub
Advisory Database records, CC-BY-4.0, about 100 KB). That database is offered only through setup
consent: `codeinspectus setup --path <repo>` lists it, with size, licence and reader, when the
repository has workflows (or name it: `--osv-ecosystems "GitHub Actions"`). Scans never download it.
The archive is read in process (bounded: 32 MiB, 50,000 entries, 2 MiB per record, nothing outside
the file, deflate or stored entries only); any record it cannot read fails the whole database closed
with a warning, never a partial read.

| Reference | Result |
|---|---|
| `x.y.z` tag (`v45.0.7`) | compared as semver (leading `v` removed) with the record's ECOSYSTEM/SEMVER ranges and listed versions: affected is a `high`-confidence finding naming the fixed release |
| major or major.minor tag (`v4`, `v3.28`) | the M1 floating rule: a `medium`-confidence finding only when every release the tag can resolve to is affected; otherwise an `info` note "pin to ≥ X" |
| a tag the record lists verbatim (`reviewdog/action-setup@v1`) | a finding: the record names that tag itself |
| full 40-hex commit SHA | a finding only when a record lists that commit (GIT `introduced`/`last_affected` events, or `versions`); the record's fixing commit is clean for that record; any other commit is a note ("pinned to a commit; … no commit list") |
| branch or any other ref | a note |
| any ref of an action no record names | clean |

Names match case-insensitively; a record for `owner/repo` covers its sub-path actions
(`github/codeql-action/init`), a record for a sub-path covers only that path, and a reusable workflow
(`owner/repo/.github/workflows/x.yml@ref`) only a record naming that exact path (otherwise, when the
repository has advisories, it is a note). `github.com/` URL names are read as `owner/repo/path`, and
withdrawn records are skipped. A range with no upper event is bounded by the entry's
`last_known_affected_version_range` (`< X` or `<= X`); any other form of that bound makes the range
unknown (a note), never open-ended. A `versions` list holding only commits says nothing about tags. Findings carry the GHSA id as their
rule id, the record's CWE ids, its CVE aliases and the producer `synvoya:actions`; they depend on the
Actions matcher and the installed database (`osv-scanner:vulnerability-db:GitHub Actions`), which is
signed only when its install record matches the archive.

**The dataset's own Actions advisories.** The bundled dataset names six version-bearing GitHub Actions
advisories (`SYN-2026-068`, `069`, `076`, `07601`, `077`, `326`: pypa/gh-action-pypi-publish, wktk/conflibot,
aquasecurity/trivy-action and setup-trivy, shivammathur/setup-php, tj-actions/changed-files). The matcher judges
them by the same rules as the database's records, with or without the database; a finding of theirs depends on the
dataset, not on the database. Where the database's record for the same action names the same advisory (a shared id or
alias) and both report a reference, the database's finding stands once, unchanged except for Synvoya's fix steps; a
dataset finding the database does not report (no record, or a record that judges the reference differently) stands on its
own. Without the database these findings and their notes still appear, but nothing is claimed as checked: the gap stays
whole and a rescan cannot confirm a fix in those files. The mutable-tag class (`SYN-2026-070`) has no version to compare
and stays waiting (`requires: "M2"`); the hygiene note below is its whole output.

- **Gap.** Without the database every third-party reference stays in `actions-unchecked`. With it, the
  gap keeps only references the matcher could not evaluate: a branch or an unlisted commit of an
  action that has advisories, a version it could not compare, a `docker://` step, an unreadable
  `uses:` value, or a reference in a file it did not read. A "pin to ≥ X" note is evaluated (no gap).
- **Rescan.** The `actions` checked set lists a workflow or action file only when the reader read it
  whole and every reference in it got a definite answer (a finding, or clean). A note, an unreadable
  reference (a YAML alias or merge key is never expanded), a missing database or a deadline keeps the
  file out, so a prior finding there reads `not_rechecked`.
- **Hygiene.** The GitHub Actions pack has no mutable-reference rule; Synvoya adds one `info` note
  naming the third-party references not pinned to a full commit SHA. It is not a finding.

## Vendored libraries: a per-scan SBOM for osv-scanner

Exact library versions are checked by osv-scanner, not by Synvoya's own dataset alone. Each scan writes
the exact declarations as a CycloneDX 1.5 SBOM (`inventory.cdx.json`) into the scan's managed temp
directory and runs osv-scanner over it with the same offline flags, managed configuration and database
overlay as the main run (`scan source -L inventory.cdx.json` in place of `-r <target>`). The SBOM is
deleted with the temp directory; findings never point at it. Each finding is an `osv-scanner` finding
(display family Synvoya) located at the declaration's file and line, with the producer component
`synvoya:sbom:osv-scanner`. An advisory the main osv-scanner or Trivy run already reports for the same
package in the same file stays that run's finding.

- One install, one finding. A library shipped as files (banner or versioned file name) is reported once
  per (library, version, advisory) per vendored root: the path up to the first directory named for the
  library (`public/libs/tinymce`, also `tinymce-6.8.4`), else the file's own directory. The finding sits
  at the root's shallowest file and its message names up to 5 other files. Its fingerprint is keyed on
  the root, not the file, so it stays stable as plugin files come and go. A CDN reference is reported at
  each declaration.

- Only exact versions are checked. A floating CDN version (`jquery@3`, `jquery@1.12`) is an `info`
  note; one with no version (`latest`, none) is a note too. Either keeps its file out of the
  `sbom:osv-scanner` checked set, so replacing an exact version with a floating one makes a prior
  finding `not_rechecked`, never `resolved` (`jquery@1.12` can still serve 1.12.4).
- With no exact library, the second run is skipped entirely.
- If osv-scanner or its OSV npm database is not installed, the declared gap `vendored-js` names the
  files; once the database is installed, the gap disappears.
- If the second run fails or times out, the scan warns `Synvoya SBOM check did not run: ...` and
  coverage is partial; the main osv-scanner run's coverage is not changed.

### Magento editions in the SBOM

GitHub advisories (and so the OSV Packagist database) file Magento Open Source under
`magento/community-edition`, a name a Composer install never locks: a store's `composer.lock` names
`magento/product-community-edition` and `magento/magento2-base`. The reviewed `packages` table in
`aliases.json` maps those two names to `magento/community-edition`, and the exact edition the products
reader found (one per lock) goes into the same SBOM under that name. Its findings point at the locked
package's line and carry the locked name as their package, so an advisory the main osv-scanner run already
reports for that package in the same file stays one finding (the main run's).

- Adobe Commerce (`magento/product-enterprise-edition`) is not aliased: the database names no Adobe
  Commerce package. A note says so, and that lock is never in the `sbom:osv-scanner` checked set.
- A lock whose edition has no exact version, or whose edition osv-scanner could not check (no OSV
  Packagist database: a note names the file), is never in that set either.

### The Go toolchain in the SBOM

The OSV Go database files Go toolchain advisories under the package `stdlib`. An exact go.mod `toolchain
goX.Y.Z` line and an exact `golang:X.Y.Z` image (any file the image reader reads) go into the SBOM as
`pkg:golang/stdlib@vX.Y.Z`, and findings point at that line.

- A go.mod `go X` line is the minimum Go the module needs, not the toolchain that builds it: it adds
  nothing to the SBOM and, belonging to the runtime producer, never decides the `sbom:osv-scanner`
  checked set. A go.mod is SBOM-checked exactly when it has an exact `toolchain` line (and the run was
  complete): a toolchain upgrade resolves its finding, while a removed toolchain line leaves the
  effective toolchain unknown, so a prior finding reads `not_rechecked`, never `resolved`. A floating
  golang image keeps its file out of the set.
- setup-go and `.tool-versions` Go versions are not SBOM inputs.
- Without the OSV Go database a note names the files that were not checked (no new gap id); the
  other components are still checked.

### Trivy and Magento `-pN` releases

Trivy orders a Magento patch release `2.4.7-p3` before `2.4.7` (as a pre-release) and compares `p11` with
`p6` as text, so it reports advisories that are fixed at the installed release. A Trivy finding on a
Magento core package (`magento/community-edition`, `product-community-edition`,
`project-community-edition`, `magento2-base`, `product-enterprise-edition`) is not reported when the
installed version has a `-pN` suffix and, under Magento ordering, is at or above every fixed release Trivy
lists on the same release line (at least one must be listed there). A fix list Magento ordering cannot read
keeps the finding. Each scan that drops one says so in `coverage_notes` (component `engine:trivy`): the
count, package, file and advisories. Kept findings are unchanged.

## Rule packs: PHP and Node.js

Two Opengrep rule packs written for CodeInspectus run in every SAST scan alongside the baseline rules.
They are plain local YAML in `detection-db/opengrep-rules/synvoya-php/` (19 rules, `syn-php-*`) and
`detection-db/opengrep-rules/synvoya-node/` (12 rules, `syn-node-*`); their per-rule inventory,
provenance and the unshipped experimental rules are in
[RULE-PROVENANCE.md](RULE-PROVENANCE.md). Findings keep `engine: "opengrep"` and their rule id, and
carry the display family Synvoya (CodeInspectus).

| Pack | Covers |
|---|---|
| PHP (`.php`, `.phtml`, `.blade.php`; plain PHP, Laravel, Symfony, WordPress) | SQL, command and code injection, file inclusion, `unserialize` and phar paths, SSRF, `extract()`, client-named uploads, Blade raw output, predictable tokens, weak password hashing, disabled TLS verification, debug settings, unchecked WordPress REST and admin-ajax writes |
| Node.js (JavaScript and TypeScript; Express, NestJS, Next.js, Nuxt/H3, Hono) | command injection, `vm`/`Function`, zip-slip, unsafe deserialization, JWT verification, cookie and session flags, `trust proxy`, NestJS validation, prototype pollution, placeholder deploy secrets |

A custom Gitleaks rule, `codeinspectus-laravel-app-key`, flags a Laravel `APP_KEY` in a deployable
`.env`, `.env.production`, `.env.prod` or `.env.staging` file (value redacted by Gitleaks); other env
files such as `.env.example`, `.env.testing` and `.env.ci` are not matched.

- **Their own pass.** Opengrep runs twice: the baseline rules over every file, then the packs and the
  taint-mode baseline rule (`ci-baseline-sql-injection-string-build`) with a 30-second per-rule timeout
  over every file except minified files and files under a `vendors/` folder, where taint rules timed out. The skipped files are the declared, acceptable gap
  `third-party-bundles` (up to 20 examples; see [CI-POLICY.md](CI-POLICY.md#declared-coverage-gaps)).
  A file named with `*`, `?`, `[`, `]` or `\` is never skipped, and a single-file target is always
  scanned. The scan checks Opengrep's report: a file skipped that routing did not choose is a coverage
  warning, not a gap. Each pass records its own invocation signature (the pack pass includes the skip
  set), so a rescan whose skipped set changed reports pack findings as not re-checked, never resolved.
- **Routing by path and content only.** The rules contain no directory-name excludes, so a project under
  `vendor/`, `includes/` or `example-template/` parent folders is scanned. Third-party code is routed
  separately for all code findings (see the README and CHANGELOG, `routing:third-party-code` and
  `routing:third-party-lowered`).
- **Precision gate.** A rule ships only when its hits on the field repositories were triaged and an
  independent second triage agreed, and when it then held on 12 holdout repositories it was never tuned
  on: at most 1 in 5 of its holdout hits false, or, with no holdout hit, no false positive on the
  tuning repositories and passing fixtures. The packs had scored 24 of 24 on their tuning repositories
  and 20 of 157 on the holdout set, so the tuning result alone over-stated precision. Held back for 4.1
  (not loaded, not in the npm package): `syn-node-sql-injection` (11 of 103 holdout hits true),
  `syn-node-path-traversal` (0/22), `syn-php-path-traversal` (0/11), `syn-php-preg-replace-eval-modifier`
  (0/5), `syn-php-laravel-mass-assignment-unguarded` (0/2), `syn-php-open-redirect` (0/1) and
  `syn-php-xxe-entity-expansion` (0/1), as well as `syn-php-xss-echo` and four Node.js rules that failed
  earlier. `syn-php-tls-verification-disabled` (2 of 4) and `syn-php-insecure-random-token` (1 of 2) are
  kept for the real issues they found; the per-rule table is in
  [RULE-PROVENANCE.md](RULE-PROVENANCE.md#holdout-precision-gate-40-final-field-run). Limits: taint rules read one file; sanitizers are matched by
  exact name per sink; a value read through a helper the rule cannot see is not tracked. Twig templates
  stay the `php-sast` gap.
- **Baseline overlap.** `ci-baseline-*` rules keep the shapes they report; `syn-node-*` rules fire on
  input or shapes the baseline does not track, and no line carries both (eval E112), so existing
  fingerprints do not change.

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
- What the readers skip (a symlink, an oversized file, a template that is not a manifest) is
  recorded as evidence in the engine note and in `coverage_notes` (component `engine:synvoya`).
  Runtime and image inputs do not lower coverage. A reached reader deadline is different: the scan
  carries the warning `Synvoya coverage partial: the readers reached their 30 s deadline; N file(s)
  or folder(s) were not read ...`, so aggregate coverage is `partial`.
- Rescan confirms a Synvoya finding fixed only when **every producer** of that finding checked
  its file again. A finding records its producers as `synvoya:runtime`, `synvoya:images`,
  `synvoya:products`, `synvoya:vendored`, `synvoya:inventory:osv-scanner`,
  `synvoya:inventory:trivy`, `synvoya:actions` or (for osv-scanner's SBOM findings: vendored libraries, Magento editions, Go toolchains)
  `synvoya:sbom:osv-scanner`. Each scan
  records, per producer, the files it fully checked (`synvoya_checked`): a file counts only when
  the producer parsed all of it and every declaration in it could be judged.
- Otherwise the prior finding is `not_rechecked` (and the rescan `partial`), never `resolved`:
  the file was skipped, read only in part, holds something Synvoya could not judge, was removed
  or moved, the reader failed, the 30-second reader deadline was reached, or the dataset was
  unavailable. A reached deadline omits every reader set and the SBOM set, because a cut walk cannot
  name every file it missed. The SBOM set lists a library file, `composer.lock`, go.mod or image file only when every
  reader that feeds the SBOM read it whole, osv-scanner checked every component from it completely (the
  run finished, each needed database is installed with a matching install record, it listed every
  package the SBOM names, and nothing it reported went unmapped), and the file holds no floating or
  unversioned library reference, no Magento edition osv-scanner could not check, and no Go toolchain
  or golang image that is not an exact release. Only these SBOM-kind declarations decide; another
  producer's declaration in the same file (a go.mod `go` minimum, a Node image) never does.

## Dataset integrity

The dataset lives in `detection-db/synvoya/`: `advisories.json`, `aliases.json`, `eol.json`, `libraries.json` (the reviewed table that maps
vendored and CDN front-end libraries to npm packages) and a
`manifest.json` holding each file's SHA-256 digest. The loader reads every file once without
following symlinks, caps each at 8 MiB, verifies the digests **before** parsing anything, then
validates strict schemas. Any failure (missing file, edited byte, schema violation) makes the
engine unavailable. The npm package is the trust root: the manifest is not separately signed.

The advisory text is authored by CodeInspectus from cited sources and licensed Apache-2.0. The
end-of-life table comes from [endoflife.date](https://endoflife.date) (MIT). See
`detection-db/synvoya/LICENSE-PROVENANCE.md`. The dataset shipped with this release has 330
advisories (40 provisional; 3 that wait for a reader that does not exist yet and are not evaluated) and 335 end-of-life
cycles for 17 products in dataset version `2026.11.05.2`. `codeinspectus_list_rules` reports the dataset
version and rule count.

## Limits and caps

| Bound | Value |
|---|---|
| Walk | depth 12, 20,000 entries, 1 MiB per file (16 MiB for `composer.lock`); no symlinks; `node_modules`, `vendor` (except the bounded WordPress core probe), `.git` and build output skipped |
| Per file | 64 declarations, 64 notes; YAML 256 documents, depth 32, 50,000 nodes; a workflow matrix expands to at most 32 values per key and 256 per file |
| Per scan | 2,000 declarations per reader; the image and product readers parse at most 64 MiB each |
| Dockerfile `ARG` | substituted values and image references are bounded to 512 characters; longer ones become unresolved |
| GitHub Actions | 256 references per file, 2,000 per scan, 16 YAML documents per file, 64 MiB read per scan; the database archive as above |
| Libraries | banners only in the first 4 KiB; 1 MiB read per file (a larger file keeps what it declares but is never a checked file); 128 MiB per scan; asset-folder `vendor/` trees share one 20,000-entry budget; the SBOM holds at most 20,000 components |
| Reader deadline | 30 seconds for all readers together; no new file is started past it |
| Notes | at most 50 Synvoya coverage notes; priority notes (reader failure, caps) are never dropped |
| Checked-file sets | a set larger than 10,000 entries is not recorded, so a rescan confirms nothing from it |

A file that hits a bound is skipped with a reason, never read in part and never a crash.

## Not covered yet

Not part of 4.0:

- `SYN-2026-070` (mutable action tags) has no version to compare; one `info` note stands in for it and the
  entry stays marked `requires: "M2"`. `SYN-2026-150` (PHP-CGI on Windows) and `SYN-2026-219`
  (CVE-2020-0601, Windows CryptoAPI; the Go change is a Windows-only workaround) wait for platform
  detection, so a Linux image never gets them. The dataset carries these three as unevaluated.
- WordPress plugin and theme versions: they stay the declared gap `wordpress-plugins`. Whether to add
  plugin advisories is undecided.
- Maven qualifiers that cannot be ordered are treated as unknown, so never affected.
- Dev-only dependency severity, fingerprint-derived display ids and package-line locations in lockfiles
  are planned after 4.0.
- The Synvoya dataset manifest is not separately signed; the npm package is the trust root.
- Anything the deployed system does that a declaration does not show.

Also in 4.0 but bounded: the PHP and Node.js packs are precision-gated rather than complete (above),
vendored library checks cover exact versions only, and Actions findings count as checked only with the
OSV GitHub Actions database installed.
