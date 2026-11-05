# Changelog

All notable changes to CodeInspectus are documented here. Versioning follows
[Semantic Versioning](https://semver.org). AI-code detections and compliance mappings are
AI-drafted and practitioner-reviewed — see the honesty notes in the [README](README.md).

## [4.0.0] — unreleased

CodeInspectus 4.0 adds Google's osv-scanner as a fourth engine, Synvoya (an offline gap-advisory layer
plus PHP and Node.js rule packs), parser-backed native JavaScript/TypeScript checks, and a quieter
default output. This release focuses on PHP and Node.js. It is not released yet. It also includes the
declared coverage gaps, engine pin updates and engine-isolation fixes prepared as 3.4.0, which was never
released, so everything below is new since 3.3.2. Upgrading from 3.3.2 changes default output,
coverage verdicts and what a baseline comparison can prove; read [Upgrade notes](#upgrade-notes-40)
first. Items planned after 4.0 are listed under
[Known limits](#known-limits-40).

### Added

#### osv-scanner, the fourth engine

- Added Google's osv-scanner 2.7.0 as a fourth managed engine, installed only after approval like
  Opengrep, Gitleaks and Trivy. `engines.lock.json` ships its binary SHA-256 for five platforms; the
  maintainer pin step recorded each one only after verifying the release's `SHA256SUMS` and its
  cosign-verified SLSA build provenance (`checksums+slsa`). When you approve the install, setup
  repeats both checks and refuses a binary whose SHA-256 differs from the shipped pin. It matches
  the package versions recorded in lockfiles and manifests against OSV.dev data, with no
  reachability or call analysis.
- osv-scanner runs fully offline: `--offline`, no dependency resolution, no call analysis, and no
  network I/O during a scan. A managed `--config` stops a repository's own `osv-scanner.toml` from
  suppressing findings. An ecosystem whose OSV database is not installed is reported `unavailable`
  with a setup warning, never as clean, and the other ecosystems still scan. If osv-scanner still
  stops at a database it cannot load, its findings are kept but its coverage reads `partial` with a
  warning, and a rescan reports findings it may have missed as not re-checked rather than resolved.
- Added OSV database setup. `codeinspectus setup --path REPOSITORY` offers only the databases for the
  ecosystems the repository's lockfiles name, and `--osv-ecosystems LIST` approves an exact list.
  `repair-engines osv-scanner --osv-ecosystems PyPI` downloads exactly that list. Databases come
  only from `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`, after
  approval, for npm, PyPI, Packagist, Go, crates.io, RubyGems, Maven, NuGet and Pub (language
  ecosystems; never distribution ones). OSV publishes no signature, so integrity is TLS plus a
  SHA-256 recorded at install time. The MCP `codeinspectus_setup` tool takes `path` and
  `osv_ecosystems` too.
- Malicious-package advisories (`MAL-`, OpenSSF Malicious Packages) are reported as critical with
  CWE-506 and credential-rotation remediation. Compliance mapping now covers `MAL-`, `PYSEC-`,
  `GO-`, `RUSTSEC-` and `OSV-` (OSS-Fuzz) advisory ids.
- Dependency findings are de-duplicated per package: osv-scanner, Trivy and the native Pub matcher
  merge when they report the same advisory for the same package, and the same advisory on two
  different packages stays two findings.
- `codeinspectus_list_rules` lists osv-scanner and one `advisory_databases` entry per installed OSV
  database, with OSV data licensing and attribution. `preflight` lists osv-scanner for dependency
  scans as additive. A missing osv-scanner does not make engine setup `repair_required`.
- Sealed bundles seal manifest `1.1.0`, which records four commodity engines (Opengrep, Gitleaks,
  Trivy and osv-scanner). Bundles sealed up to 3.3.2 use manifest `1.0.0` and still verify.
- The TypeScript SDK exposes `SDK_COMPATIBILITY.bundle_schemas_verified` (`["1.0.0", "1.1.0"]`), the
  bundle manifest versions `verifyBundle` accepts.
- `THIRD-PARTY-NOTICES.md` and `NOTICE` now attribute osv-scanner (Apache-2.0) and the OSV data
  sources and their licenses: GHSA, PyPA, OSS-Fuzz and Go (CC BY 4.0), OpenSSF Malicious Packages
  (Apache-2.0), Drupal (MIT) and RustSec (CC0 1.0). This is attribution, not a legal review.

#### Synvoya: engine, dataset and readers

- Added **Synvoya**, an offline gap-advisory layer (`engine: "synvoya"`) that runs in every
  vulnerability scan. It judges what a repository **declares** (never what is deployed) against a
  bundled dataset: Node.js, PHP, Python, Ruby, Go, .NET and Java versions read from version-manager
  pins, manifests, GitHub Actions setup steps and matrices, and container image tags (`Dockerfile`,
  Compose, Kubernetes, Helm, workflow `container`/`services`); end-of-life lines; Adobe Commerce,
  Magento Open Source and WordPress core versions from `composer.lock`; and malicious or unlisted
  package versions from the package lists osv-scanner and Trivy already produce. See
  [docs/SYNVOYA.md](docs/SYNVOYA.md).
- Composer's `config.platform.php` (and `platform-overrides` in `composer.lock`) is a
  dependency-resolution hint, not the deployed PHP, so it gives an informational note and never a
  runtime finding; `require.php` and real runtime pins (Dockerfiles, CI, `.tool-versions`) stay the
  sources.
- Version rules set confidence, never severity (severity comes from the advisory): an exact affected
  pin is high; a floating or range declaration whose every resolvable release is affected is medium;
  a floating or range declaration on an end-of-life line is high; a provisional advisory is low and
  its title says "(provisional — verify with the vendor)". A floating tag on a supported line
  (`node:22-alpine`) is an `info` coverage note, not a finding, and an unresolved `FROM ${BASE_IMAGE}`
  is a note that never lowers coverage. Adobe Commerce and Magento fixes that are hotfixes (no
  version change) are medium "Verify ... is applied" findings. Every runtime or image fix says to
  rebuild and redeploy; malware findings include credential rotation.
- The dataset (`detection-db/synvoya/`, 330 advisories and 335 end-of-life cycles in version
  `2026.11.05.2`) is checked against SHA-256 digests in `manifest.json` and a strict schema before
  use. An edited or corrupted dataset makes the engine `unavailable` with a scan warning, and a
  rescan reports its prior findings as not re-checked; it is never a silent zero. End-of-life data
  comes from endoflife.date (MIT), see `detection-db/synvoya/LICENSE-PROVENANCE.md`.
- When Trivy or osv-scanner already reports the same advisory for the same package in the same
  file, there is one finding: the upstream one, with its id, fingerprint, severity and producers
  unchanged and Synvoya's fix added to its remediation steps.
- Rescan confirms a Synvoya finding fixed only when each of its producers fully re-checked the file
  (`synvoya:runtime`, `synvoya:images`, `synvoya:products`, `synvoya:inventory:*`). A file a reader
  skipped, read in part, could not judge, or lost to the 30-second reader deadline is
  `not_rechecked`, never `resolved`. A reached reader deadline also makes aggregate coverage
  `partial`, with a scan warning that names how many files or folders were not read.
- Findings from CodeInspectus-owned detection carry the optional display field
  `engine_family: "synvoya"` ("Synvoya (CodeInspectus)"). `engine`, `rule_id`, ids and fingerprints
  are unchanged, and export schema `3.0.0` does not write the field. `codeinspectus_list_rules`
  lists the `synvoya` engine and its dataset version.
- Synvoya findings of every kind (runtime, end-of-life, product, package and malware) carry the
  vulnerable-component compliance controls (ISO 27001 A.8.8, NIST CSF ID.RA-01, SOC 2 CC7.1, CIS 7.1,
  Essential Eight Patch Applications): `SYN-` advisory ids count as dependency advisories, and
  CWE-1104 (unmaintained third-party component) joins the vulnerable-component CWE bucket.
- A single-file scan target (`.nvmrc`, a `Dockerfile`, a workflow, `composer.lock`, ...) is read by
  the Synvoya reader that reads that kind of file; any other file target gets a plain "was not
  checked" note instead of reading as a clean run.
- Evals E82-E86 cover declared Node.js, PHP and Adobe Commerce findings with fixes, a tampered
  dataset, upstream enrichment, floating-tag notes, and a rescan past the reader deadline.

#### Synvoya: vendored libraries, Magento, Go and GitHub Actions

- Vendored and CDN-loaded JavaScript libraries (banner comments, versioned file names such as
  `jquery-1.12.4.min.js`, versioned CDN URLs) are checked by osv-scanner: each scan writes the exact
  versions as a CycloneDX SBOM in its temp directory and runs osv-scanner over it offline with the main
  run's flags. Findings are `osv-scanner` findings in the Synvoya family at the declaring file and line,
  never at the SBOM. A library shipped as files is reported once per advisory per vendored root (the
  path up to the directory named for the library, else the file's folder), at its shallowest file,
  naming up to 5 other files; its fingerprint is keyed on the root, so TinyMCE's banner on every plugin
  file is one finding, not one per file. CDN references stay one per declaration. Floating versions are notes, and a file holding one is never confirmed fixed on
  rescan. Without osv-scanner or its npm database the new
  declared gap `vendored-js` names the files; a failed second run is a `Synvoya SBOM check did not
  run` warning (partial coverage). Rails `vendor/assets/` counts as a web asset folder. Eval E87 runs
  the real binary.
- Magento Open Source installed with Composer is now checked against its GitHub advisories. A
  `composer.lock` locks `magento/product-community-edition` (or `magento/magento2-base`), while the
  OSV Packagist database files Magento advisories under `magento/community-edition`, so a store got no
  Magento finding. The same SBOM run now checks the locked version under that name (a reviewed alias in
  `detection-db/synvoya/aliases.json`) and reports at the locked package's line, under its locked name.
  Adobe Commerce (`magento/product-enterprise-edition`) has no package in that database and is not
  checked this way (a note says so). An advisory the main osv-scanner run already reports for the
  locked package in the same file stays that run's finding.
- Trivy compares Magento `-pN` patch releases as pre-releases, so a store on `2.4.6-p11` got
  advisories fixed in `2.4.6-p6` (91 on one field store). A Trivy finding on a Magento core package is
  no longer reported when, under Magento ordering, the installed `-pN` release is at or above every fix
  Trivy lists for that release line; a coverage note (`engine:trivy`) gives the count, package and
  advisories. Other Trivy findings and their fingerprints are unchanged.
- The declared Go toolchain is checked against Go advisories. An exact `toolchain goX.Y.Z` line in
  `go.mod` and an exact `golang:X.Y.Z` image go into the same SBOM as the Go standard library
  (`pkg:golang/stdlib@vX.Y.Z`, the package the OSV Go database files toolchain advisories under), and
  findings point at the declaring line. A `go X` line is a minimum, not a toolchain, so it is never
  checked; a toolchain upgrade is confirmed on rescan, a removed toolchain line is not. Without the OSV Go
  database a note names the files; no new gap id.
- Eight bundled advisories that waited for a later reader now run: the Go standard library releases
  (`SYN-2026-019`, `020`) are judged against declared Go runtimes (go.mod `toolchain` lines,
  `golang` images, `.tool-versions`, setup-go steps), and the six GitHub Actions advisories (`SYN-2026-068`, `069`, `076`,
  `07601`, `077`, `326`) against `uses:` references by the Actions matcher, with or without the OSV GitHub
  Actions database. An advisory the database or osv-scanner already reports in the same file is not
  repeated: that finding stands and gains Synvoya's fix steps. Without the database these Actions findings
  appear but nothing is claimed checked, so a rescan never confirms them fixed. `SYN-2026-070` (mutable action
  tags) has no version to compare and still waits; the unpinned-reference note covers it. `SYN-2026-219`
  (CVE-2020-0601, a Windows CryptoAPI flaw whose Go change is Windows-only) waits for platform detection like
  `SYN-2026-150`, so a Linux golang image never gets it. Dataset version
  `2026.11.05.2`; a rescan after the update reports older Synvoya findings as not re-checked once.

#### Synvoya PHP and Node.js rule packs

- **Synvoya PHP pack (`syn-php-*`, 19 Opengrep rules)** for plain PHP, Laravel, Symfony and WordPress
  (`.php`, `.phtml`, `.blade.php`): SQL, command and code injection, file inclusion, `unserialize`
  and phar paths, SSRF, `extract()` on request input, client-named uploads, Blade raw output,
  predictable tokens, weak password hashing, disabled TLS verification, debug settings in deployable
  env files and Symfony front controllers, and unchecked WordPress REST and admin-ajax writes. One more rule, the
  Gitleaks rule `codeinspectus-laravel-app-key`, flags a Laravel `APP_KEY` in a `.env`,
  `.env.production`, `.env.prod` or `.env.staging` file (`.env.example`, `.env.testing` and `.env.ci` are not matched). PHP source is no longer the `php-sast` gap; that gap now names
  only Twig templates.
- **Synvoya Node.js pack (`syn-node-*`, 12 Opengrep rules)** for Express, NestJS, Next.js, Nuxt/H3
  and Hono: command injection, `vm`/`Function` code injection, zip-slip,
  unsafe deserialization, JWT verification without fixed algorithms or with decode-only use,
  cookie and session flags, unconditional `trust proxy`, NestJS `ValidationPipe` without
  `whitelist`, prototype pollution, and placeholder secrets in deploy defaults.
- Both packs were written for CodeInspectus (provenance in `docs/RULE-PROVENANCE.md`), carry
  true-positive and false-positive fixtures checked by evals E100-E103 and E110-E112, and passed a
  field precision gate: hits on the field repositories were triaged, then triaged again
  independently. A rule that did not pass is held back, not shipped: `syn-php-xss-echo` and four
  Node.js rules (`syn-node-default-credentials`, `syn-node-open-redirect`,
  `syn-node-prototype-pollution-library-merge`, `syn-node-session-secret-literal`). They live outside
  `detection-db/`, so Opengrep never loads them and the npm package does not contain them.
- **Holdout precision gate.** On the repositories they were tuned on, the packs scored 24 of 24 true
  positives. Re-measured on 12 holdout repositories none of the rules was tuned on, they scored 3 of 26
  (PHP) and 17 of 131 (Node.js): the tuning result was over-fitted. Each rule now ships only if at most 1
  in 5 of its holdout hits is a false positive, or, with no holdout hit, if it had no tuning false
  positive and its fixtures pass. Seven rules failed and are held back as experimental for 4.1, to be
  fixed and re-measured on a new holdout set: `syn-node-sql-injection` (11 of 103 holdout hits true),
  `syn-node-path-traversal` (0/22), `syn-php-path-traversal` (0/11), `syn-php-preg-replace-eval-modifier`
  (0/5), `syn-php-laravel-mass-assignment-unguarded` (0/2), `syn-php-open-redirect` (0/1) and
  `syn-php-xxe-entity-expansion` (0/1). `syn-php-tls-verification-disabled` (2 of 4) and
  `syn-php-insecure-random-token` (1 of 2) are kept for the real issues they found. With
  `syn-node-sql-injection` held back, JavaScript/TypeScript SQL injection is reported only by the
  baseline rule (request input reaching a query built in the call). Per-rule table:
  [docs/RULE-PROVENANCE.md](docs/RULE-PROVENANCE.md#holdout-precision-gate-40-final-field-run).
- The packs' rules carry no parent-folder excludes: a project under `vendor/`, `includes/` or
  `example-template/` parent folders is scanned like any other. Only a file's target-relative path and
  content route it (see `third-party-bundles` below).
- `codeinspectus_list_rules` reports the bundled Opengrep rule count per language
  (`sast_rule_languages`).

#### Parser-backed native JavaScript/TypeScript checks

- **The native JavaScript/TypeScript packs read files with a real parser**. The 3.x
  lexer is replaced by `@babel/parser` 7.25.0 (MIT, no dependencies of its own; the one new runtime
  dependency). The Express and Next.js admin-route, Supabase Edge, React Native and JavaScript baseline
  checks now see exactly the code the parser reads, so the twelve known-limitation inputs (a regex read
  as division after `extends`, `new`, `default`, `of`, `await`, or `break`/`++` on a new line, the
  identifier escape `\u0065val`, and TypeScript `!` after a string, template, `!` or `{}`) no longer
  hide a sink; `javascript-known-limitations.test.ts` is all ordinary tests now. JSX text is text: valid
  components with `Don't` or a lone `/` in JSX text parse again, and a call spelled inside JSX text is
  no longer read as a call. A TypeScript type argument such as `useState<Config>()` is no longer read
  as a JSX element. Rule ids and fingerprints are unchanged: over every fixture and the 28 field
  repositories, the native findings (484) are identical before and after, and the field files reported as
  `native-parse-errors` drop from 84 to 1 (a definite assignment on a computed class key, `[K]!: T`, which
  this parser release cannot read). Files that parse now also count toward the 1,000,000-token project
  budget, so a few later files in one large repository move to `native-token-budget`. Native-analyzer CPU
  time on those repositories is about 1.35x the 3.x lexer's (parse-only about 2.9x; each scan shares
  parses between its analyzers).
- Fail closed as before: a file the parser rejects, a file over the 200,000-token bound (now refused
  before parsing by a linear upper-bound count, so a 2 MiB file of `;` no longer allocates its token
  stream), nesting too deep for the parser, and a `.js`, `.jsx`, `.ts` or `.tsx` file that is valid
  both as a script and as a module but reads differently under each are `native-parse-errors`. Such a
  file runs as a script, or as a module in a `"type": "module"` package, so it is read under both goals:
  an HTML-like comment (`<!--`, `-->`) is a comment only in a script and `await` an operator only in a
  module, and either can hide code from one reading. `.cjs`/`.cts` are read as scripts and `.mjs`/`.mts`
  as modules only. A file valid under one goal alone is read under that goal. The
  2 MiB / 64 KiB caps are unchanged (`oversized-files`). Which tokens run conditionally is now computed
  once per file from the parser's tree; it was a rescan per assignment (23 s on a 180,000-token file of
  member assignments, now 59 ms). Parses are shared only within one scan's native analyzers, in a cache
  bounded at 250,000 tokens and 8 MiB of source that is cleared when the scan ends.


#### Declared coverage gaps and coverage notes

- Declared coverage gaps. Inputs no bundled engine analyzes now make aggregate coverage `partial` and
  are listed with a stable id, a file count and up to five example paths (`coverage_gaps`): source
  files of languages without bundled SAST rules (`php-sast`, `ruby-sast`, `java-sast`, `go-sast`, …),
  `.vue`, `.svelte` and `.astro` component files, whose script code neither Opengrep nor the native
  packs read (`vue-sast`, `svelte-sast`, `astro-sast`), server templates counted toward their
  language (`.jsp`/`.jspx`, `.erb`, `.cshtml`/`.razor`, `.twig`),
  `deno.lock` (`deno-lock`), a binary `bun.lockb` without `bun.lock` (`bun-lockb`), an
  `npm-shrinkwrap.json` without a lockfile Trivy reads (`npm-shrinkwrap-unread`), and
  `package.json`/`composer.json` without a lockfile (`no-lockfile-npm`, `no-lockfile-composer`; a
  parent lockfile counts only for a declared npm, Yarn, Bun or pnpm workspace).
  Previously coverage read `complete` for them (10 of 20 field repositories have PHP). CI exits 2
  by default; `--accept-gaps <id,…>` (MCP `accept_gaps`) accepts named gaps so they alone do not fail
  CI, while coverage still reads `partial` and the gaps stay listed (`accepted_gaps`; in the export,
  informational evidence with component `accepted-gap:<id>`); with
  `--baseline` the accepted ids apply to both scans, and `scans compare` honours a stored scan's
  accepted language and component gaps. The JSON export
  carries them as coverage evidence with component `gap:<id>`; export schema 3.0.0 is unchanged. Gap
  ids are documented in docs/CI-POLICY.md.
- New declared gaps for inputs no bundled engine has advisory data for: `wordpress-plugins`
  (`wpackagist-plugin/*` and `wpackagist-theme/*` in `composer.lock`, and `wp-content/plugins/*` with
  a plugin header) and `actions-unchecked` (third-party `uses:` references in GitHub workflows not
  checked against advisories). Without the OSV GitHub Actions database `actions-unchecked` lists every
  such reference; once that database is installed it narrows to the references the Synvoya Actions
  matcher could not evaluate (a branch, a commit the advisory data does not list, a `docker://` step,
  an unreadable reference or file).
- Native-pack limits that are deterministic analysis limits are declared gaps instead of partial coverage
  no id could accept: `native-parse-errors` (files the bounded native parsers cannot read),
  `oversized-files` (per-file size and call-count bounds and the JavaScript/TypeScript reading caps of
  2 MiB characters per file and 64 KiB per line, typically vendored bundles),
  `native-token-budget` (files left unparsed once the 1,000,000-token JavaScript/TypeScript project
  budget is spent, counted with examples; a repository can pad itself to push files past it, and Opengrep
  still scans them for its generic rules when the SAST scanner runs),
  `express-routes-unresolved` (admin-route candidates whose middleware could not be proven either way),
  `nextjs-routes-unresolved` (Next.js admin API handlers whose custom wrapper, guard or privileged
  operation could not be proven either way, such as umami's `parseRequest` routes) and
  `symlinked-paths` (links whose real target inside the repository the walker reads under its own
  path; links outside the repository, into an ignored folder such as `node_modules/` or beyond the depth
  bound stay non-acceptable). Analyzer failures, the other project-wide bounds, reconciliation
  mismatches and Opengrep timeouts stay non-acceptable.
  In the field validation, 6 of 12 repositories could not pass CI with every gap accepted.
- Scan results carry informational `coverage_notes`, shown in the text summary and exported as
  informational coverage evidence: Opengrep's default ignore list, the native JavaScript packs'
  Yarn-tooling skip, and how many shell, PowerShell and Makefile files no bundled SAST rule reads
  (not a coverage gap). Notes never lower coverage.

### Changed

- Engine pins: Opengrep 1.23.0 → 1.33.1 and Trivy 0.71.2 → 0.76.1. Gitleaks 8.30.1 is already the
  latest release. Trivy 0.76.1 is built with Go 1.27.3, which distrusts the compromised eMudhra
  intermediate CA. Opengrep 1.24–1.33 change taint analysis (switch and `case` handling, Kotlin and
  Ruby branches, Python match arms); the exact Opengrep eval corpora are unchanged.
- Opengrep releases since v1.31.0 are signed by `rolling-release.yml` on per-release
  `release-vX.Y.Z` branches instead of `main`. The lockfile pins the exact `release-v1.33.1`
  identity, and verification stays fail-closed.
- **Licence findings are now opt-in.** A scan no longer runs Trivy's licence scanner or reports licence
  findings unless you ask: MCP `codeinspectus_scan` with `include_licenses: true`, CLI `--licenses`, SDK
  `client.scan(path, { includeLicenses: true })`, or `license` named in `scanners`. They were 47% of all
  findings in field scans and none was fixable. A scan without them carries the informational coverage
  note "Licence findings were not requested (use include_licenses / --licenses)"; it does not make
  coverage partial and appears in exports and the compliance report. With the opt-in the findings,
  fingerprints and ids of the other findings are the same as 3.x. `codeinspectus_rescan` and
  `scans rerun` repeat the prior scan's choice (a scan stored before 4.0 counts as having run licences
  unless its scanner list left them out), and a licence finding from a scan that asked for them is
  reported as not re-checked, never resolved, when the new scan did not.
- **Test, fixture, example and documentation files lower generic findings.** Gitleaks' provider-less
  rules (`generic-api-key`, `curl-auth-header`, `curl-auth-user`) and generic code findings (Opengrep and
  native checks that are not secrets and not credential-class) in a test, fixture, example or
  documentation file are reported at `low` with a "Test/example context" label, never dropped; their
  ids, fingerprints and rule ids are unchanged. Context comes from the target-relative path alone:
  `test/`, `tests/`, `__tests__/`, `__snapshots__/`, `spec/`, `fixtures/` and Xcode-style `<Name>Tests/`
  folders anywhere; `docs/`, `examples/` and `example/` only as the first folder; `*.test.*`,
  `*.spec.*`, `*.e2e-spec.*`, `*.snap`, `<name>.example[.ext]`, `<name>.sample[.ext]`, `.env.dist`,
  `README[.ext]` and `*.md`; case-sensitive, and a parent folder outside the scanned target is never
  consulted. Every named-provider secret (AWS, Stripe, GitHub, Slack, private keys and others), malware
  and vulnerability finding keeps its severity everywhere. A generic secret in a test or example file
  also keeps its severity when the same value (matched by hash, across engines) is reported in a
  non-test file: its message names up to 3 of those files and the count, never the value, and the
  coverage note counts these. Gitleaks and Trivy withhold the value from their reports, so for this
  check only it is read back from the reported source line and hashed in memory; that hash is never
  stored, exported or part of a fingerprint (eval E137). The coverage note `routing:test-example-context` gives the count per rule.
- **Third-party code is routed out of SAST noise, with disclosure.** Code findings (Opengrep and native
  checks only; never secrets, credential-class findings such as CWE-798, or dependency findings) in a
  case-sensitive `vendor/` folder or a `*.min.js` file are not reported, which is the scope Opengrep's own
  default ignore list already skips; the note `routing:third-party-code` names up to 20 files. Code
  findings in scripts that only look like copied libraries (a `/*!` or `@license`/`@preserve` banner, a UMD
  wrapper, a minified body, or a `vendors/`, `third_party/`, `third-party/`, `thirdparty/`,
  `bower_components/` or `jspm_packages/` folder) are reported at `low` with a "Third-party code" label
  and the note `routing:third-party-lowered`. Both notes are informational. A repository comment cannot
  remove a file from SAST, and a first-party module with a long base64 constant is not minified.
- **The Synvoya packs run in their own Opengrep pass.** The PHP and Node Opengrep packs (`syn-php-*`,
  `syn-node-*`) run in a second Opengrep pass with
  a 30-second per-rule timeout. It skips minified files and files under a `vendors/` folder, where their
  taint rules timed out and left SAST coverage partial with nothing a user could accept. The skipped
  files are the new acceptable gap `third-party-bundles` (up to 20 examples). A `/*` inside a string on a
  long dense line (`accept:"image/*"`) does not hide the rest of a concatenated minified bundle from
  this classification. The taint-mode baseline
  rules (`*-taint.yaml` files; today `ci-baseline-sql-injection-string-build`) run in this same pass, so
  they also skip third-party bundles (the same `third-party-bundles` gap): taint analysis cost every
  JavaScript/TypeScript file and one 300 KB vendored bundle took 54 seconds. The other baseline Opengrep
  rules scan every file as before. Each pass records its own invocation signature, so a rescan whose skipped
  set changed reports pack findings as not re-checked, not resolved.
- **Non-source files over Opengrep's size limit are a coverage note, not partial SAST.** The pack pass's
  generic rules make Opengrep list every file over its 1,000,000-byte limit. A skipped image, font, audio or
  video file, archive (`.phar` included), PDF, compiled binary, lockfile (`*.lock`, `package-lock.json`,
  `pnpm-lock.yaml`), source map, `.sql` or `.csv` file is now an informational `engine:opengrep` note,
  because no bundled rule reads it as source. Any other file over the limit, JavaScript, TypeScript, Python and PHP source
  included, still makes SAST coverage partial.
- **Precision changes to the baseline Opengrep rules** (ids unchanged; the findings that remain keep
  their fingerprints, and the ones dropped are deliberate). Over the PHP and Node.js field repositories
  the old `ci-baseline-sql-injection-string-build` (37 hits), `ci-baseline-dom-xss-innerhtml` (113) and
  `ci-baseline-nosql-injection` (15) had no true positive. Now:
  - `ci-baseline-sql-injection-string-build` is a taint rule: HTTP request input (Express, Koa, Hono,
    Next.js, H3/Nuxt) must reach a concatenated or interpolated query in the same file;
    `parseInt`/`Number` and driver escape helpers sanitize.
  - `ci-baseline-dom-xss-innerhtml` needs a DOM-XSS source (location hash, search, href or pathname,
    document URL or referrer, `window.name`, a `postMessage` payload) written directly or through one or
    two variables; stored or fetched markup is a known gap. The rule's file prefilter is restored
    (matches unchanged), so files that never mention an HTML sink are not analysed.
  - `ci-baseline-nosql-injection` needs a Mongoose-style model, a driver collection or a file importing
    `mongoose`/`mongodb`; route parameters alone no longer count.
  - `ci-baseline-dangerous-eval` ignores a `Function` built only from string literals.
  - `ci-baseline-weak-hash` is demoted to hygiene: Opengrep severity `INFO` and confidence `LOW`, and
    the native `javascript-baseline` check low severity and low confidence (13 of 13 field hits were
    cache keys, checksums or ids). `ci-baseline-weak-cipher` is unchanged.
- **Gitleaks precision allowlists** (CodeInspectus Gitleaks configuration), each scoped to the rule that
  produced the hit and never covering a value that can authenticate: generated index and key names
  (`IDX_`/`UNIQ_`/`FK_`/`PK_` plus 16 hex characters) in migrations, conda pins, OAuth client and tenant
  ids that hold a UUID, reCAPTCHA site keys and Google's published test key pair, the Upstash QStash
  local development defaults, Stripe publishable keys (`pk_test_`/`pk_live_`), and Google API keys in
  `google-services.json` and `GoogleService-Info.plist`. Test, documentation and example files are not
  allowlisted (they are lowered above, not hidden). Eval E121.
- Detection database 2.0.0 (3.3.2 shipped 1.19.0): 126 custom detections, up from 94, with the Synvoya
  PHP and Node.js packs as two more Opengrep rulesets and the baseline rule changes above. Bundles and
  `codeinspectus_list_rules` report this version.
- Native pack versions: `javascript-typescript` 1.10.0, `react-native` 1.1.0, `javascript-baseline` 1.1.0
  (parser-backed reading; same rules; the `javascript-baseline` weak-hash check is demoted as above).
- `SDK_COMPATIBILITY.bundle_schema` is now `1.1.0`, the manifest version this release seals. It was
  `1.0.0`. Use `bundle_schemas_verified` for the versions `verifyBundle` accepts.
- Export schema `3.0.0` is unchanged. Exports carry no structured `package` field; the package is
  kept internally for de-duplication.
- The coverage gap `php-sast` no longer names `.php`, `.phtml` or `.blade.php` files (the Synvoya PHP pack
  covers them).
- The eval suite has 110 evals. The Synvoya, pack, routing, Gitleaks, licence and parser evals added
  in 4.0 are E82-E92, E100-E103, E110-E112, E120-E121 and E130-E137.

### Fixed

- Plain repository and URL paths are no longer redacted in finding titles, messages and coverage
  notes. The output scrub took `github/workflows/desktop-e2e` (from `.github/workflows/desktop-e2e.yml`),
  advisory links and Go module paths for high-entropy tokens, so text read
  `declared in .[redacted, 28 chars].yml`; Go pseudo-versions were masked the same way. Known secret
  shapes, credential assignments and base64 values that contain `/` are still masked. Fingerprints are
  unchanged.
- Drupal contrib findings from osv-scanner now name the fixed version. OSV keys those packages as
  `https://packages.drupal.org/8:drupal/<module>`, so the lookup never matched the Composer name and
  remediation said no version was listed. Fingerprints are unchanged.
- Opengrep now runs under a UTF-8 locale. When the MCP host set no locale, a non-ASCII byte in a
  repository's `.semgrepignore` ended the Opengrep run with no SARIF, so the scan lost all SAST
  results and read `partial`; non-ASCII snippet text was also replaced. The locale is `en_US.UTF-8`
  on macOS (releases before macOS 26 have no `C.UTF-8`) and `C.UTF-8` elsewhere.
- A repository's `.semgrepignore` no longer controls which files Opengrep scans. Opengrep read it
  from its working directory, which was the scan target, so a file naming `src/` removed that
  directory from SAST while coverage still read `complete`. Opengrep now reads a managed copy of its
  default ignore list (`detection-db/opengrep-ignore/default.semgrepignore`: `node_modules/`, `test/`,
  `tests/`, `vendor/`, `build/`, `dist/`, `*.min.js` and similar) instead, still applied inside the
  target, so a checkout under a folder named `build/` or `tests/` is scanned normally. That is the
  list every repository without a `.semgrepignore` already got. A repository whose `.semgrepignore`
  replaced those defaults to include test directories no longer gets them scanned by Opengrep. The
  managed list also skips the build-output folders where file routing already drops Opengrep
  findings (`.next/`, `_next/`, `out/`, `.nuxt/`, `.svelte-kit/`, `.output/`, `_site/`,
  `storybook-static/`, `web-build/`), taken from the same list at run time; other folders, such as a
  committed `.vercel/output`, are scanned. In a local Next.js checkout with a 21 MB git-ignored
  `.next/`, an Opengrep run took 1.6 to 2.7 s instead of 5.5 to 6.7 s, and Opengrep no longer
  reported its `.next/` chunks over 1 MB as skipped (the native JavaScript packs still read build
  output).
- Trivy dependency findings now name the package and installed version in the title and give a
  specific remediation ("Upgrade lodash from 4.17.4 to 4.17.12, then rebuild the lockfile.", or the
  list of fixed versions or constraints such as `>= 2.9.0`, or a no-fix note) instead of the
  generic CWE-1395 text. Finding ids, fingerprints and locations are unchanged; a lockfile without
  per-package line data (for example `pnpm-lock.yaml`) is still reported at line 1.
- A `.gitleaksignore` lowers secret coverage to `unverified` only when one of its entries can
  match CodeInspectus's Gitleaks run. `gitleaks dir` reports absolute paths, so relative
  `file:rule:line` entries and commit-scoped entries hide nothing there; the file is still disclosed,
  as an informational note. An entry naming an absolute path, a line with any character outside
  printable ASCII (Gitleaks trims U+0085 and other Unicode spaces), or a file that cannot be read
  keeps the `unverified` result.
- The native JavaScript loader skips Yarn's own folders (`.yarn/releases`, `plugins`, `sdks`,
  `cache`, `unplugged`) and the `.pnp.cjs`/`.pnp.loader.mjs` loaders beside a `package.json`, as it
  skips `node_modules/`. A committed `.yarn/releases/yarn-*.cjs` (2.7 MB in monicahq/monica) was
  reported as an oversized source file and made coverage `partial`. Other `.yarn` folders are still
  analyzed.
- A scanned repository can no longer configure Trivy. Trivy read `trivy.yaml`, `.trivyignore` and
  `trivy-secret.yaml` from its working directory, which was the scan target, so a repository could
  raise the severity floor, ignore CVEs and misconfigurations, or disable secret rules while coverage
  read `complete`. Trivy (scan and SBOM) now runs from an empty managed directory with an empty
  managed ignore file.
- Inherited engine settings no longer narrow a scan. Every `SEMGREP_*`, `OPENGREP_*`, `R2C_*`,
  `TRIVY_*` and `GITLEAKS_*` variable from the MCP host, shell or CI job is dropped before an engine
  starts: Semgrep's diff-aware `SEMGREP_BASELINE_REF` made Opengrep scan no files, and
  `TRIVY_SEVERITY` or `TRIVY_CONFIG` cut Trivy's results, while coverage read `complete`. Trivy also
  gets empty `--config`, `--secret-config` and `--ignorefile` values, which disable loading.
- Repository file names with control, bidi-override (U+202E), zero-width or line-separator characters
  can no longer disguise text in scan output. Gap and skip examples leave such names out (they are
  still counted); every other warning or note that names a file (native-pack, dependency and
  technology-detection notes, engine notes, repository-trust, Git-scope and history limitations)
  shows those characters as visible `\u{…}` escapes. Findings are unchanged.
- A Trivy license result for a package with a secret-like name (for example `passport-headerapikey`)
  is a license finding again, not a high-severity hard-coded secret with CWE-798. Its fingerprint
  changes once, because the misclassification had set the CWE.
- Native Pub analysis no longer reads `partial` in a repository without Dart because of a directory
  symlink that resolves inside the repository (ghostfolio's `.claude/skills/*` →
  `.agents/skills/*`): lockfile discovery walks the real path, so such a link hides nothing. Links
  that resolve outside the repository or dangle still make Pub coverage partial.
- Development dependencies are analysed where Trivy can. Trivy dropped npm, Yarn, pnpm and Bun
  devDependencies and Composer `packages-dev` unless asked, with no trace: a Nuxt app that declares
  every dependency as dev read 0 dependency findings and `complete`. Trivy now runs with
  `--include-dev-deps` (verified on 0.76.1 for those five, and for Gradle lockfile test configurations
  and uv and Poetry dev groups). Maven dependencies with a `test`, `provided` or `system` scope, with
  `<optional>true</optional>`, or with a scope set through a property are still dropped even with the
  flag (jackson-databind 2.9.1: 74 advisories without a scope, 0 in each of those cases), so each such
  dependency in a `pom.xml` is the declared gap `dev-deps-unscanned`; an unreadable `pom.xml` is one
  too. Findings for development-only packages say so in the title
  (`pkg@version, dev dependency`) and message; severity is unchanged, because front-end builds can
  bundle them. Production findings keep their fingerprints: a development copy of a CVE that a
  production package in the same lockfile also has is folded into the production finding, which dedup
  would otherwise have replaced with the development copy. License findings for development
  dependencies appear too.
- In-source Trivy ignore comments are disclosed. Trivy 0.76.1 honours `trivy:ignore:<id>` and
  `tfsec:ignore:<id>` comments in Terraform, Dockerfiles and other infrastructure files and has no flag
  to disregard them (`#trivy:ignore:*` above a Terraform resource hid all eight of its findings), while
  coverage read `complete`. A misconfiguration scan now warns with the comment count and up to five
  files, and coverage reads `partial` ("misconfiguration coverage unverified").
- Secrets are found in a target under a folder Gitleaks' default allowlist names. Gitleaks 8.30.1
  matches that allowlist against absolute paths, so scanning an installed package
  (`node_modules/<pkg>`, `bower_components/`, `vendor/bundle/`, `lib/python3.x/site-packages/<pkg>`)
  reported no secrets while secret coverage read `verified`. Such a target is now scanned through a
  managed link, so only folders inside it count; a single file there, which cannot be linked, reads
  `unverified` with a warning.
- Gitleaks now runs from an empty managed directory. Gitleaks also loads `.gitleaksignore` from its
  working directory, which for a single-file scan was the file's directory, so an entry there hid
  findings without any disclosure. A target `.gitleaks.toml`, `GITLEAKS_CONFIG` and
  `GITLEAKS_CONFIG_TOML` were already overridden by the bundled `--config` (re-verified on 8.30.1).
- Files Opengrep did not fully analyze now make SAST coverage `partial`. Opengrep still exits 0
  when it skips a file over its 1,000,000-byte limit, cannot read a file, or gives up on a file after
  a parse error, timeout or memory limit, and those files contributed no findings while coverage read
  `covered`. Files whose only errors are parser limits are the declared gap `sast-parse-errors`,
  which `--accept-gaps` can accept; the other causes are a warning with the count per cause and up to
  five example paths, which no gap id accepts.
- Opengrep now scans the same files as Trivy, Gitleaks and the native packs (`--no-git-ignore`). It
  used to ask git for the file list and silently omitted untracked git-ignored files, without listing
  them as skipped. Findings in git-ignored locations are framed by file routing as for other engines.
- Native JavaScript/TypeScript reading is bounded. The 3.3.2 lexer could rescan every later `/` on a
  line after an unterminated regex (58 s for one 1 MB line) and was quadratic on many unclosed JSX tags
  (24 s at the 200,000-token bound). A file over 2 MiB characters or with a line over 64 KiB is now not
  read and is reported under `oversized-files`.
- Four pattern arms in three bundled Opengrep rules
  (`ci-baseline-ssrf-request-from-input`, `ci-baseline-path-traversal`,
  `ci-baseline-insecure-random-security`) could never report a finding. They matched a
  template-literal `fetch`, `axios.get` or `readFile` argument, or any `x = Math.random()`, without
  binding the metavariable the rule then checks, so Opengrep 1.33.1 reported an "Internal matching
  error" for every such file, which now counts against SAST coverage. The arms are removed; findings
  are unchanged, and template-literal URLs and paths remain undetected by these rules. A corpus with
  true-positive cases for all 20 bundled rules now runs in the evals and fails on any matching error.

### Upgrade notes (4.0)

- **Run `npx codeinspectus repair-engines` after upgrading.** The Opengrep and Trivy pins changed
  (see Changed), so existing installs report the old Opengrep and Trivy binaries as a SHA256 mismatch
  and do not run them until the pinned versions are installed.
- **More scans read `partial`, so CI exits 2 on unchanged input.** Inputs no bundled engine analyzes are
  now declared coverage gaps instead of reading `complete`, and engine skips that used to be silent are
  reported. When these gaps were introduced (before the 4.0 PHP and Node.js packs), 19 of the 20 field
  repositories exited 2 (13 did with the pre-release build those changes started from, which already had
  the new engine pins; 6 changed from exit 0 to exit 2, and only 1 exited 0); 11 of the 19 were partial
  only through declared gaps.
- **To keep CI passing for known gaps, accept them by id:** `--accept-gaps php-sast,deno-lock` (CLI),
  `accept_gaps: ["php-sast"]` (MCP `codeinspectus_scan`), `acceptGaps: ["php-sast"]` (SDK `scan`). An
  accepted gap stays listed in `coverage_gaps` and coverage still reads `partial`; CI passes coverage
  only when every other cause is complete, and any other cause (an engine that did not run, an Opengrep
  timeout or size skip, an unverified `.gitleaksignore` or Trivy inline ignore) still exits 2. The same
  ids apply with `--baseline`. `scans compare` honours a stored scan's accepted language and component
  gaps (`<language>-sast`, `vue-sast`, `svelte-sast`, `astro-sast`), where no engine reports SAST
  findings; accepted `sast-parse-errors` and lockfile gaps still make it partial, because an engine may
  have analyzed that input in the other scan. An unknown id is a usage error; ids are never removed,
  and a retired id is accepted as a no-op.
- **Gap ids:** `php-sast`, `ruby-sast`, `java-sast`, `kotlin-sast`, `go-sast`, `csharp-sast`,
  `rust-sast`, `swift-sast`, `c-sast`, `cpp-sast`, `scala-sast`, `dart-sast`, `vue-sast`,
  `svelte-sast`, `astro-sast`, `objc-sast`, `elixir-sast`, `erlang-sast`, `lua-sast`, `perl-sast`,
  `groovy-sast`, `clojure-sast`, `haskell-sast`, `ocaml-sast`, `r-sast`, `julia-sast`, `zig-sast`,
  `solidity-sast`, `vb-sast`, `sast-parse-errors`, `deno-lock`, `bun-lockb`, `no-lockfile-npm`,
  `no-lockfile-composer`, `npm-shrinkwrap-unread`, `wordpress-plugins`, `actions-unchecked`,
  `native-parse-errors`, `oversized-files`, `native-token-budget`, `express-routes-unresolved`,
  `nextjs-routes-unresolved`, `symlinked-paths` and `dev-deps-unscanned`, plus `vendored-js` and
  `third-party-bundles` (below). docs/CI-POLICY.md explains each one.
- Migration: licence findings are now opt-in. If CI counts, gates on or exports licence findings, add
  `--licenses` (CLI), `includeLicenses: true` (SDK) or `include_licenses: true` (MCP). Totals,
  baselines and `--fail-on-*` thresholds that included licence findings will drop. Comparing a scan
  that ran licences with a newer one that did not (`rescan`, `scans compare`) reports those licence
  findings as not re-checked, never as resolved.
- **Re-record baselines with 4.0.** A baseline recorded with 3.3.2 or earlier cannot prove New or
  Existing for most 4.0 findings, so `scan --baseline` against it reads coverage `partial` and exits 2
  until you record a new baseline with 4.0. The engine pins changed (Opengrep 1.23.0 → 1.33.1, Trivy
  0.71.2 → 0.76.1), so the old baseline's Opengrep and Trivy signatures differ, and osv-scanner,
  Synvoya and the Synvoya packs never ran in it, so their findings read not re-checked (unknown), never
  New. It fails closed, never as a false pass. Run one 4.0 scan of the branch you compare against and
  use it as the new baseline.
- Between scans recorded with 4.0, a baseline that ran licences still gates a default scan: for
  `--baseline`, `rescan` and `scans compare` only the `license` element of Trivy's `--scanners` is
  ignored, nothing else, so a new vulnerable package is still reported New and
  `--fail-on-new-severity` still exits 1. The baseline's licence findings are not re-checked (the new
  scan has none), and licence findings in a `--licenses` scan against a baseline that never asked for
  them read Not rechecked rather than New.
- **Findings that disappear, and rescans across the upgrade.** The licence default, the precision
  changes, the Gitleaks allowlists and the routing above remove or lower findings you saw in 3.x. Each
  scan records a signature for the Opengrep ruleset and invocation, the pack pass, the Gitleaks
  configuration, the Synvoya dataset and the other detector components; where a signature differs from
  the prior scan's, the prior scan's findings from that detector read **not re-checked** rather than
  resolved. Expect this once after the upgrade, and again whenever a later release changes the dataset
  or a pack. It is noise, never a false "fixed". The Opengrep and Trivy invocation signatures, the
  bundled ruleset and the native JavaScript/TypeScript reader revisions changed as well, so an Opengrep,
  Trivy or native JavaScript/TypeScript finding that is gone reads not re-checked on the first rescan or
  baseline comparison after upgrading (the file may now be skipped or past the project token bound).
- **Opengrep now runs in two passes** when the Synvoya packs apply (see `third-party-bundles` below).
  A pre-upgrade Opengrep finding is not re-checked once.
- **Display ids are still positional.** The `CI-0001` style id is assigned by position in the scan's
  sorted finding list, so it can change when an unrelated finding appears. Triage, baselines and rescans
  match on fingerprints, which are stable; do not store display ids. Fingerprint-derived display ids
  are planned after 4.0.
- **New gap ids.** `vendored-js` (vendored or CDN libraries not checked because osv-scanner or its OSV
  npm database is not installed) and `third-party-bundles` (bundles the Synvoya pack pass skipped). Both
  make aggregate coverage `partial`, so CI exits 2 until you install the database, accept the gap with
  `--accept-gaps`, or fix the cause. The `php-sast` gap now names only Twig templates. Gap ids are
  never removed. See [docs/CI-POLICY.md](docs/CI-POLICY.md#declared-coverage-gaps).
- **The engine set is open.** `Finding.engine` is now `opengrep`, `gitleaks`, `trivy`, `osv-scanner`,
  `codeinspectus-ai`, `codeinspectus-pub` or `synvoya`, and a later release may add more. Treat an
  unknown value as an engine you have not seen. `engine_family: "synvoya"` is optional and display
  only; key stable logic on `engine`, `rule_id` and `fingerprint`. Export schema `3.0.0` does not carry
  `engine_family`.
- `npx codeinspectus repair-engines` also installs osv-scanner 2.7.0, unless you declined it in
  `setup` (then run `repair-engines osv-scanner` to install it), but downloads no new OSV database;
  OSV databases you already installed may be refreshed if they are stale or have lost their install
  record.
- To scan dependencies with osv-scanner, approve the databases your repository needs:
  `npx codeinspectus setup --select osv-scanner --path /absolute/path/to/repository`. Until you do,
  scans report each missing ecosystem as `unavailable` with a setup warning.
- Installing osv-scanner can detach existing triage annotations from dependency findings that it
  merges into. The merged finding can carry a different fingerprint, so an annotation recorded
  against the earlier finding may stop matching. The finding resurfaces for triage; nothing is
  hidden.
- The Trivy upgrade (0.71.2 → 0.76.1) moves the line of some misconfiguration findings, and the line
  is part of their fingerprint. Across the 40 field repositories, 86 Kubernetes misconfiguration
  findings changed fingerprint this way (for example KSV-0014 now points at the first initContainer,
  line 57 instead of 77). A rescan or baseline comparison across the upgrade does not match them to
  the 3.x finding by fingerprint, and triage annotations recorded against the old fingerprint stop
  matching; re-record the baseline (above).
- 3.3.2 and earlier cannot verify bundles sealed with manifest `1.1.0` (`bundle verify` exits 2).
  Bundles sealed by 3.3.2 and earlier still verify with this release.
- `SDK_COMPATIBILITY.bundle_schema` changed from `1.0.0` to `1.1.0`. Consumers that compared it to
  decide which bundles to accept should read `bundle_schemas_verified` instead.

### Known limits (4.0)

- Synvoya judges what a repository declares, never what is deployed; only exact versions are checked in
  vendored libraries; Actions findings need the OSV GitHub Actions database to count as checked; Go
  toolchain, Magento Commerce and platform-specific entries are bounded as described in
  [docs/SYNVOYA.md](docs/SYNVOYA.md#not-covered-yet).
- The PHP and Node.js packs are precision-gated, not complete: taint rules read one file, PHP Twig
  templates are the `php-sast` gap, and the experimental rules above are not shipped. See
  [docs/RULE-PROVENANCE.md](docs/RULE-PROVENANCE.md) and the SAST row of the README.
- The pack pass skips minified files and files under a `vendors/` folder (gap `third-party-bundles`);
  a first-party file that is minified or kept under `vendors/` gets no pack findings until you review
  and accept the gap.
- The native JavaScript/TypeScript parser cannot read a definite assignment on a computed class key
  (`[K]!: T`); that file is `native-parse-errors`.
- WordPress plugin and theme versions stay the declared gap `wordpress-plugins`.
- Planned after 4.0, not shipped: dev-only dependency severity scope, fingerprint-derived display ids
  with package-line locations in lockfiles, and further output de-duplication (one finding per secret
  across engines).
- Not shipped and not scheduled: WordPress plugin advisories (a decision is pending), platform detection
  for Windows-only advisories (`SYN-2026-150`, `SYN-2026-219`), advisories for mutable action tags
  (`SYN-2026-070`), and signing of the Synvoya dataset manifest.


## [3.3.2] — 2026-10-24

### Security
- `smol-toml` 1.7.1 → 1.9.1 (GHSA-r4xh-jqrq-34v2, moderate). A crafted TOML file in a scanned
  repository could make parsing take quadratic time and stall a scan. CodeInspectus parses Supabase
  `config.toml` and Python `pyproject.toml` from scan targets, so the path was reachable, and the
  exact pin meant every fresh 3.3.1 install received the vulnerable version.
- MCP TypeScript SDK floor raised to `^1.32.2` and the lockfile refreshed (`proxy-addr` 2.0.8,
  `body-parser` 2.4.0, `express` 5.3.0, `hono` 4.13.13, `ip-address` 10.7.4, `fast-uri` 3.1.9). The
  SDK advisories (GHSA-6qxp-vccf-f47h, GHSA-22jm-h49p-29qw, GHSA-6prh-2h8m-c8cw, GHSA-46jr-4wx8-v453,
  GHSA-rvq5-wwqv-78pq) and the transitive HTTP-server advisories affect HTTP and OAuth transports.
  CodeInspectus uses only the stdio transport, and fresh 3.3.1 installs already resolved patched
  versions.
- Bundled OSV Pub advisory snapshot refreshed to `2026-10-24.0b3ac85734d3`: 12 active advisories
  across 11 packages (was 11 from 2026-08-20), adding GHSA-cr65-55v9-xhvv for `dio_http2_adapter`.

### Known issue
- `zod` 3.x is affected by GHSA-mrhx-c7xc-m3w5 (memory exhaustion while validating oversized
  constrained collections). The fix exists only in zod 4.6.6 and later, a major upgrade scheduled for
  3.4.0. The inputs zod validates are local (MCP tool input over stdio, CodeInspectus's own stores)
  or size-bounded (bundle verification reads at most 16 MiB per artifact and 64 MiB per bundle).

### Changed
- Development dependencies updated to patched versions: `vitest` 4.1.12, `vite` 8.3.5,
  `brace-expansion` and `source-map-js`. They are not part of the published package.

### Documentation
- `docs/context/verify.md`: `npm audit --omit=dev` is now a release gate. Each high or critical
  runtime advisory must be fixed or recorded as a known issue before release.

## [3.3.1] — 2026-10-04

### Security
- MCP `scan`, `rescan`, `generate_sbom` and `plan_cleanup` refuse an empty or relative `path`. It
  previously resolved against the MCP server's working directory, so a client could scan (or plan
  cleanup in) a directory other than the one it meant.
- The TypeScript SDK passes scan targets, repository paths and bundle paths to the CLI as absolute
  paths, and refuses scan or finding IDs that start with `-`. Untrusted input such as
  `--working-tree` could previously be parsed as a CLI option.
- Finding snippets from configuration files (YAML, `.env`, `.npmrc`, `.pypirc`, INI, TOML, properties, HCL) mask
  unquoted lowercase values of credential-named keys, such as `client_secret: supersecretvalue`.
  In code these read as variable references and are kept; in configuration files they are literals
  and leaked. Placeholders (`${VAR}`, `$VAR`, `{{ … }}`) and booleans are kept.
- Text output renders line breaks and bidirectional controls in file names, notes and warnings as
  visible `\uXXXX` escapes. A file name containing a newline could start a fake line, such as a
  fake critical finding, in the scan summary, `scans compare` and `triage` output.
- Git child processes no longer inherit `GIT_LITERAL_PATHSPECS`, `GIT_GLOB_PATHSPECS`,
  `GIT_NOGLOB_PATHSPECS` or `GIT_ICASE_PATHSPECS` from the caller, so pathspec matching cannot be
  changed by the environment CodeInspectus runs in.
- Issue payloads (`issue export`) turn `&` and `<` from repository text into entities and show
  zero-width and bidirectional characters as visible escapes. A crafted file name or message could
  previously open raw HTML, such as a link, in tracker Markdown or render as different text.

### Fixed
- `--output` and `--output-dir` accept paths below root-owned top-level system links such as macOS
  `/tmp` (they were refused as symbolic-link components). The link is resolved first and every
  other check, including whether the output is inside the scan target, runs on the real path.
  User-created links remain refused.
- Triage annotations follow a finding that only moved lines. Fingerprints include line numbers, so
  inserting lines above a triaged finding dropped its annotation from later scans, baselines and
  exports. The annotation's source scan (same target) supplies a line-independent content anchor;
  identical occurrences carry over only while their count is unchanged, so a duplicated line never
  inherits the original's triage state.
- Rescan's implicit prior is the latest full scan of the target. A newer Git-scoped scan (changed
  paths only) or repository-history scan was selected, making unchanged findings look newly
  introduced; passing one explicitly as `prior_scan_id` is now refused with an explanation.
- Scanning a subdirectory or a single file reports AI co-author trailers only from commits that
  touched that path, not from every commit in the enclosing repository.
- Compressed PNG text chunks (`zTXt`, compressed `iTXt`) are inspected for explicit AI
  declarations with a 256 KiB inflate bound; they were silently skipped while explicit attribution
  reported `ran`. A chunk beyond the bound is a disclosed limitation. Metadata field names taken
  from a file are escaped and length-bounded in `location.field`.
- Under a severity display filter, the text headline lists only the included levels and says lower
  severities are hidden. It printed `0 medium` under `--severity high` while medium findings existed.
  JSON `summary` keeps counting the displayed set, as before.
- Engine setup advice points to `npx codeinspectus setup` or the `codeinspectus_setup` tool (plan
  first) everywhere, including `engine_setup.repair_command`, scan text, engine errors and the agent
  rules. Setup also covers hash-mismatched engines and a Trivy DB without provenance;
  `repair-engines` remains for advanced use.
- SDK errors for a CLI usage failure include the exit code and the CLI's stderr reason instead of only
  "did not return valid JSON".

### Documentation
- CLI reference: `scans rerun` supports `text|json`; `bundle export` supports `json|sarif` and writes
  to stdout; `history scan` dates are UTC RFC 3339 timestamps; `preflight` accepts text/JSON output
  and no policy or Git scope options.
- Git-scoped scans: a change set beyond the 50,000-entry limit stops with an error (exit 2) rather
  than reporting partial scope.
- The multi-review skill defaults to one review round; another needs user approval.
- Rule provenance states that the Lezer and smol-toml licenses are listed in
  `THIRD-PARTY-NOTICES.md` and ship in their own npm packages (they were described as reproduced).

### Changed
- Package, MCP server, CLI and SDK API versions are synchronized at `3.3.1`. Export `3.0.0`,
  repository-trust `1.0.0` and cleanup `1.0.0` contracts are unchanged.

## [3.3.0] — 2026-09-30

### Added
- Added `codeinspectus_plan_cleanup`, a fresh read-only planning tool that accepts exact verified
  repository-trust artifact IDs, reproduces evidence, rejects protected/ambiguous/unsupported
  records, records preimage hashes, and discloses exact transformations before approval.
- Added `codeinspectus_apply_cleanup` with exact-scope confirmation, separate attribution/provenance
  rights confirmation, managed content backups, bounded atomic text edits, same-validator rescans,
  content-free audit logs, and automatic rollback of already-applied operations on partial failure.
- Added `codeinspectus_rollback_cleanup`, which restores recorded preimages or removes generated
  cleaned copies only when their current hashes still match the applied cleanup result.
- Added copy-only metadata adapters for PNG, JPEG, MP3, WAV, MP4, MOV, M4A and M4V repository
  assets. Original assets are preserved, metadata-container removal is separately acknowledged,
  and C2PA/content-provenance cleanup requires an additional copy acknowledgement.
- Added versioned `1.0.0` cleanup plan/result JSON Schemas and public SDK type exports.

### Safety boundary
- Scanning and cleanup planning remain read-only. Apply/rollback are the only repository mutation
  tools and are accurately marked destructive in MCP annotations.
- Git history and protected legal, licensing and compliance records are never eligible. Structured
  declarations without a safe bounded adapter are returned for agent guidance instead of guessed edits.
- The mutation tool does not execute arbitrary repository commands. Tests, formatters and builds are
  explicitly `not_run` and required until the calling agent completes them.
- V3.3 does not remove visible logos, alter pixels/audio/video frames, implement statistical
  watermark detection or rewriting, or claim that cleaned content is human-authored.

### Security
- Finding snippets and messages are now scrubbed value-agnostically at one point before
  persistence and every output surface (known token patterns, URL credentials, quoted or unquoted
  values of credential-named keys, and long high-entropy tokens; UUIDs, SRI hashes, pinned commit
  SHAs, and variable/template references are kept). Earlier versions could surface neighbouring or window-truncated credentials in
  `location.snippet` (for example a generic password on the line next to a detected key, or a
  high-entropy value on the same line as a non-secret finding) through MCP `structuredContent`,
  `explain_finding`, and local scan history. Scan history written by earlier versions under
  `~/.codeinspectus/scans` may contain such snippets; delete it and rotate any affected credential.
- Git is now invoked with command-line overrides that the scanned repository's config cannot
  change, and engine processes (for example Opengrep's own `git ls-files`) inherit the same
  overrides as command-scope `GIT_CONFIG_*` environment: fsmonitor hooks, signature programs, hooks
  and pagers are disabled, and
  `--no-optional-locks` keeps `status` from rewriting `.git/index`. Working-tree comparisons (git
  safety, working-tree Git scope) are skipped or refused when the repository config defines filter
  drivers. Working-tree comparisons never descend into submodule work trees (whose own config can
  name filter drivers), and repository-location variables such as `GIT_DIR` inherited from a parent
  git hook are ignored. Earlier versions could run programs named in a scanned repository's
  `.git/config`.
- C2PA validator error text is reduced to safe prose before it becomes a coverage limitation:
  remote manifest URLs lose credentials and query strings, install paths are collapsed, and
  control characters are removed. Earlier versions could echo a remote URL's token.
- MCP text content, CLI stdout/stderr, and log lines render control characters from
  repository-controlled text (file names, metadata fields, messages) as visible `\uXXXX` escapes, so
  a crafted file name or PNG text chunk can no longer drive a terminal, including through `tee` or
  `less -R`. JSON and SARIF stay valid with identical parsed data; `--output <file>` writes exact
  bytes (use it when CSV fields must keep raw control characters).
- Sealed-bundle verification rejects manifest content outside the seal. Unknown manifest keys were
  dropped by schema parsing before the seal check, so an added claim such as an `attestation`
  object verified successfully.
- Interrupting a commit-mode Git-scoped CLI scan (SIGINT/SIGTERM) now removes the materialized
  source snapshot before exit. It was previously left under the OS temp directory, including any
  secrets in the scanned commit.

### Fixed
- CI policy no longer exits 2 on ordinary repositories because of harmless symbolic links (for
  example `CLAUDE.md -> AGENTS.md`). Links are still never followed or assumed covered elsewhere; a
  file link is ignored only when its own name is one the scanner would never analyze (documentation
  for technology detection, non-source names for language packs, anything but `pubspec.lock` for Pub
  discovery). Source-named, manifest-named, and directory links remain disclosed coverage gaps.
- Git-scoped CI enforcement can no longer be bypassed: findings that a change introduces outside
  the changed paths (for example by deleting the migration that enabled row-level security) are
  primary (within the declared target and outside git-ignored paths), found by also scanning the
  base commit; edits hidden by skip-worktree/assume-unchanged and
  files removed with `git rm --cached` but still on disk are in working-tree scope; submodule pointer
  changes are reported even with `.gitmodules ignore=all`; and diffs are measured from the merge-base,
  so changes made only on the base branch are not attributed to the change.
- Baseline, rescan and history matching can no longer be satisfied by location alone: a different
  engine's new finding at a moved finding's old location, or a different secret replacing one on the
  same line, is New rather than Existing (a `--fail-on-new-severity` gate could pass on both).
- Trivy Pub advisories that match git-sourced, custom-hosted, path or SDK packages only by name are
  excluded as name collisions (with a disclosed count), matching the native Pub exclusion contract.
- Native Pub coverage is no longer partial for every Flutter project or once the bundled snapshot is
  a week old. SDK and path packages are not applicable to Pub advisories; only git and
  custom-hosted dependencies count as skipped (`packages.skipped`); snapshot age is a freshness note,
  as for the Trivy DB, and every CLI scan prints it on stderr; and notes from a complete dependency
  run, the note about reframed git-ignored findings, and Trivy name-collision notes are
  informational in aggregate coverage (findings the file router actually drops still make it partial).
- Source integrity now detects Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) used outside
  Hangul text, the "invisible identifier" backdoor pattern; they were previously not inspected.
- Rescan, baseline and history comparison no longer report an unchanged finding as resolved plus
  introduced when lines are inserted above it. Findings are additionally matched by a
  line-independent content anchor (file, rule, CWE, secret-value hash or normalized snippet, and
  occurrence order), so a duplicated vulnerable line still counts as new. Fingerprints are unchanged.
- Rescan refuses a `prior_scan_id` taken of a different target and resolves the latest prior scan by
  canonical path, so findings from another repository can no longer be reported as resolved.
- `generate_sbom` refuses a relative `output_path` or one naming an existing non-SBOM file.
- A repository-trust artifact whose file was removed or moved is `not_rechecked`, not resolved:
  moving a file with a hidden-Unicode marker into `vendor/`, `build/` or an unsupported extension
  previously read as a fix. Source-integrity now also inspects `.cjs`, `.cts`, `.pyi`, `.ps1`,
  `.psm1`, `.bat`, `.cmd`, `.gradle`, `.groovy`, `.hcl`, `.m`, `.mm`, `.pl`, `.pm` and `.r` files,
  and explicit-attribution inspection covers `.cjs`, `.cts` and `.pyi`.
- SARIF regenerated from a sealed export uses the export's recorded `generated_by.version` as the
  driver version. It previously used the running version, so every export-3.0.0 bundle stopped
  verifying after an upgrade ("do not match the sealed canonical export"); 3.2.0 bundles verify
  under 3.3.0.
- Source-integrity `utf8_byte_offset` evidence is now relative to the file bytes when a file starts
  with a UTF-8 BOM. V3.1.0–3.2.0 reported offsets three bytes low for such files; line and column
  evidence was unaffected.

### Changed
- Package, MCP server, CLI and SDK API versions are synchronized at `3.3.0`. Compatible export
  `3.0.0` and repository-trust `1.0.0` remain unchanged; cleanup contracts are independently `1.0.0`.

## [3.2.0] — 2026-09-07

### Added
- Added bounded, read-only explicit AI-attribution inspection for source/config headers, local git
  `Co-Authored-By` trailers, and supported image EXIF/XMP/IPTC/PNG metadata. Results verify that a
  declarative record exists; they do not claim the record is truthful or prove model authorship.
- Added supported local C2PA Content Credentials inspection through the official optional
  `@contentauth/c2pa-node` validator. Artifacts distinguish valid/trusted, invalid,
  present-but-inconclusive, and remote-reference evidence and retain claim generator, declared
  digital source type, validation state, and bounded status codes.
- Added deterministic V3.2 aggregation across source integrity, explicit attribution, content
  provenance, and the still-unavailable statistical-watermark capability without changing the
  compatible export `3.0.0` or repository-trust `1.0.0` schemas.

### Safety boundary
- Scans remain read-only and perform zero network egress. Remote manifests, OCSP responses, trust
  lists, and revocation endpoints are never fetched. Symlinks, parser inputs, traversal, commit
  history, total bytes, and artifact output are bounded with explicit partial-coverage reporting.
- C2PA and protected legal/licensing attribution records are evidence-only and never
  cleanup-eligible. V3.2 does not rewrite text, strip metadata, inspect media pixels/audio/video
  frames, or implement statistical watermark detection.
- The official C2PA native binding is an optional peer dependency (not installed by default) so unsupported platforms or
  `--ignore-scripts` installs do not break CodeInspectus; candidate assets then report partial
  content-provenance coverage.

### Changed
- Package, MCP server, CLI, and SDK API versions are synchronized at `3.2.0`. Human and MCP
  summaries now display every repository-trust capability separately instead of labelling all
  artifacts as source-integrity evidence.

## [3.1.0] — 2026-08-23

### Added
- Added the first deterministic repository-trust capability: bounded, read-only source-integrity
  inspection for bidirectional overrides and unbalanced controls, zero-width/default-ignorable
  token characters, Unicode tag payloads, encoded variation-selector runs, and a reviewed subset
  of mixed Latin/Greek/Cyrillic identifier confusables.
- Source-integrity artifacts include exact file, line, code-point column, UTF-8 byte offset, escaped
  code points, Unicode names, context classification, proposed action, validator identity,
  confidence, limitations, and approval-required remediation eligibility.
- Added conservative context handling for initial BOMs, legitimate RTL controls, emoji variation
  selectors, emoji ZWJ/tag sequences, international-language joiners, short ideographic variation
  sequences, quoted/comment confusable lookalikes, protected records, symlinks, invalid UTF-8,
  oversized files, and traversal/output bounds.
- Dense marker candidates are bounded before artifact materialization. Very long tag/variation
  runs retain their exact span and total length while rendered evidence is capped at 64 code points;
  long identifier previews are capped at 128 code points and every truncation remains explicit.
- Rescans now classify repository-trust artifacts separately as resolved, remaining, introduced, or
  not re-checked. Absence is called resolved only when the capability ran completely with the same
  validator identity.

### Changed
- Package, MCP server, CLI and SDK API versions are synchronized at `3.1.0`. The compatible V3 JSON
  export remains `3.0.0`, and the independently versioned repository-trust document remains `1.0.0`.
- Human, MCP, JSON, SARIF and SDK surfaces now expose V3.1 source-integrity execution and artifacts.
  Explicit AI attribution, C2PA, statistical watermark verification and media processing remain
  unavailable and are not inferred from Unicode evidence.

### Safety boundary
- CodeInspectus still never edits source. Cleanup-eligible artifacts require explicit approval for
  the named file and code point, a reversible smallest edit by the user's coding agent, tests, and
  a CodeInspectus rescan. V3.1 does not silently normalize or remove characters.

## [3.0.0] — 2026-08-23

_Not published separately; this contract migration first shipped to npm in 3.1.0._

### Added
- Added the versioned `1.0.0` repository-trust contract for non-CWE source-integrity and
  provenance artifacts. The contract records exact location, marker class, validator,
  `verified`/`probable`/`informational`/`not_verifiable` state, confidence, limitations, and
  approval-gated remediation eligibility without treating provenance evidence as a vulnerability.
- Fresh scans and rescans now expose a `repository_trust` envelope through MCP structured output
  and human summaries. V3.0 deliberately reports all four future capability classes as
  `unavailable`; zero artifacts is explicitly not a clean-audit claim.
- Added packaged V3 JSON and SARIF schemas plus public SDK types for repository-trust documents,
  artifacts, states, confidence, and capabilities.

### Changed
- Package, MCP server, CLI, SDK API, and MCP Registry manifest versions are synchronized at
  `3.0.0`. Canonical JSON export moves to `3.0.0`; the repository-trust document is independently
  versioned at `1.0.0`. SARIF remains standard version `2.1.0` with V3 CodeInspectus metadata.
- The SDK now exposes `JsonExportV3`, `SarifExportV3`, `FindingV3`, and `CoverageV3`. Deprecated V2
  type aliases remain as source-compatibility aliases, but typed commands validate schema `3.0.0`.
- New sealed bundles identify export schema `3.0.0`. Verification continues to accept sealed V2
  bundles and validates their legacy identity, findings, coverage, and SARIF consistency.
- Legacy stored scans remain readable and receive an explicit unavailable repository-trust envelope
  at runtime; persisted storage schema remains `2.0.0`.

### Not included
- V3.0 does not detect hidden Unicode, AI attribution, C2PA, or statistical watermarks and does not
  remove anything. Those capabilities remain separately gated for V3.1–V3.4.

## [2.6.0] — 2026-08-20

### Added
- Added consent-driven first-use setup for nontechnical users. Interactive `npx codeinspectus`
  and `codeinspectus setup` explain each external engine's coverage, license, current state, and
  platform-specific download size before offering install-all or component selection.
- Added `codeinspectus_setup` for MCP clients. Planning is offline; installation requires an
  explicit `confirm_downloads=true`, writes only beneath `~/.codeinspectus`, and never changes the
  scanned repository. Declined choices persist locally and can be cleared with `setup --reset`.
- Added automatic, approval-gated Cosign 3.1.2 bootstrapping for Opengrep/Trivy verification.
  Platform binaries are immutable-SHA pinned from a Sigstore-verified upstream checksum manifest,
  removing the separate Cosign prerequisite while preserving fail-closed publisher verification.

### Changed
- Added exact release-asset byte sizes for every supported Opengrep, Gitleaks, Trivy, and Cosign
  platform. Trivy database storage is deliberately labelled as an estimate because upstream DB
  transfer and extracted size change independently of CodeInspectus releases.
- Direct file scans no longer mark the project-level Supabase Edge analyzer as an unreadable
  directory. The aggregate native engine is `5.20.0`; the 94-rule catalog is unchanged.
- Existing healthy binaries and databases remain no-download no-ops. Scans remain offline, npm
  installation has no executable-downloading lifecycle script, and manual `repair-engines` remains
  available as an advanced compatibility path.
- Package, MCP server, CLI, SDK API, MCP Registry manifest, and reference CI install versions are
  synchronized at `2.6.0`. Export/storage schema versions remain `2.0.0`.

## [2.5.0] — 2026-08-13

### Licensing
- Relicensed CodeInspectus from MIT to Apache License 2.0 with a root `NOTICE`, explicit
  contribution terms, DCO sign-off policy, and corrected third-party attribution.
- Clarified that Opengrep, Gitleaks, and Trivy are separately licensed tools downloaded from
  their upstream releases by an explicit repair command; their binaries are not included in the
  CodeInspectus npm package.

### Security
- Patched development-tooling transitive dependencies to `nanoid` 3.3.18 and `esbuild` 0.28.1,
  closing the current high-severity infinite-loop advisory and low-severity Windows development-
  server path-traversal advisory. The published runtime dependency graph was not affected.
- Added exact modern Supabase `sb_secret_<22>_<8>` coverage to client source, ordinary and
  oversized browser bundles, Flutter client initialization, redaction, and the pinned Gitleaks
  ruleset. Exact `sb_publishable_` keys are globally suppressed from inherited Gitleaks rules.
- Client-secret scanning now detects multiple providers on one source line, collapses repeated
  same-line values without hiding separate remediation lines, bounds candidate locations per file
  with an explicit coverage note, and keeps dedicated Supabase findings through final deduplication.
- Supabase RLS analysis now evaluates effective permissive/restrictive policy composition, roles,
  command phases, renames/schema moves, explicit disables, conditional DDL, ambiguous migration
  ordering, exposed schemas, and bounded loader omissions before emitting repository-state findings.
- Supabase Edge Functions now honor the platform's default `verify_jwt = true` authentication,
  structurally check explicit anonymous handlers, and separately flag privileged service-role/admin
  operations without visible server authorization. Next.js and import-proven Express admin handlers
  now receive bounded handler-scoped authentication and authorization analysis.
- Added narrow literal checks for an effective `Referrer-Policy: unsafe-url` and unrestricted
  camera, microphone, or geolocation delegation in `Permissions-Policy`. Missing, dynamic,
  conflicting, hosted, or weaker-but-valid policies remain unverified rather than findings.
- Missing SPF/DMARC and DMARC `p=none` are deliberately not static findings: they require live DNS
  state, and `p=none` is a valid monitoring policy. Email-domain posture remains an explicit external
  deployment check outside the zero-egress repository scanner.

### Changed
- Detection database `1.19.0` contains 94 curated detections: 72 first-party native rules,
  18 Opengrep-owned SAST rules, and 4 Gitleaks rules. The JavaScript/TypeScript pack is `1.9.0`
  with 12 analyzers/29 rules, the Python AI/API pack is `1.5.0`, the Flutter pack is `1.1.0`,
  and the aggregate native engine is `5.19.0`.
- API-boundary checks exclude test, fixture, sample, demo, and example paths from project-root
  scans. The Python syntax gate accepts valid bare
  `yield` and starred comprehension/loop targets that the pinned structural parser rejects.
- Native analyzer skip and uncertainty notes now make the owning pack and aggregate scan coverage
  partial instead of incorrectly claiming complete execution.
- Express admin-route analysis excludes minified, generated, build-output, and vendored assets so
  third-party bundles cannot consume the application-route call budget.
- Package, MCP server, CLI, SDK API, MCP Registry manifest, and reference CI install versions are
  synchronized at `2.5.0`. The 2.5 milestone marks the Apache-2.0 transition and expanded security
  coverage. Existing V2 export/storage schema versions remain `2.0.0` because this feature release
  does not break those contracts.

## [2.1.1] — 2026-08-05

_Not published separately; this dependency patch first shipped to npm in 2.5.0._

### Security
- Refreshed transitive production dependency resolutions within the existing declared ranges:
  `fast-uri` 3.1.5 fixes host-confusion handling, `ip-address` 10.4.0 fixes special-address
  classification paths that could bypass SSRF or trust-boundary checks, and `hono` 4.13.0 fixes
  a CORS middleware regular-expression denial of service. No direct dependency or runtime source
  API changed.

### Changed
- The GitHub Release workflow is validation-only and has no npm environment, OIDC permission, token,
  or publication step. Codex may execute the release after one explicit human approval, but npm is
  still published from an authenticated maintainer terminal as `hibin-m`.
- The release checklist now treats GitHub, npm, the official MCP Registry, and Cloudflare Pages as
  separate publication surfaces, verifies each after mutation, and invalidates approval if the
  approved version, commit, artifact, website commit, or scope changes.
- Package, MCP server, CLI, SDK API, MCP Registry manifest, and reference CI install versions are
  synchronized at `2.1.1`. Existing V2 export/storage schema versions remain `2.0.0` because this
  patch does not change those contracts.

## [2.1.0] — 2026-08-02

### Added
- `ci-ai-llm-output-dynamic-execution` follows recognized model output into JavaScript
  `eval`/`Function`, import-proven Node shell-string APIs, and import-proven Execa command-string
  APIs. The bounded intrafile rule includes a frozen 5-TP/7-safe corpus and explicit false-negative
  boundaries.
- `ci-ai-nextjs-admin-route-no-authz` checks conventional Pages Router and App Router admin API
  handlers for visible authentication plus a server-controlled role/permission decision. Supabase
  client-writable `user_metadata` is deliberately rejected as authorization evidence; the frozen
  corpus covers both router styles and safe/public near misses.
- The dangerous-HTML rule now follows one local destructured function-component prop hop into
  `dangerouslySetInnerHTML`, with sanitized/trusted/text-rendering precision cases.
- A release-on-published-GitHub-release workflow validates a GitHub-verified signed tag, runs the
  complete release gate, publishes with npm trusted publishing and provenance, and verifies the
  registry version plus SLSA attestation. Provider-side trusted-publisher/environment setup remains
  a prerequisite documented in `docs/RELEASE.md`.
- A V2.1 reproducible public-repository scan/fix/rescan script verifies two sealed evidence bundles.
  It defaults to `codeinspectus@2.1.0` and accepts an exact local tarball through
  `CODEINSPECTUS_CASE_PACKAGE` for pre-publication verification.

### Fixed
- The bounded JavaScript lexer now accepts valid regular-expression literals that begin with `=`,
  including `/=.*/s`, instead of misclassifying them as division assignment and making the full
  scan partial.
- CI now exercises the independent packed TypeScript SDK consumer and the macOS ARM64 platform
  row in addition to the existing platforms.

### Changed
- Package, MCP server, CLI, SDK API, MCP Registry manifest, and reference CI install versions are
  synchronized at `2.1.0`; existing V2 export/storage schema versions remain `2.0.0`.
- Detection database `1.15.0` contains 88 curated detections: 67 first-party native rules across
  16 packs, 18 Opengrep-owned SAST rules, and 3 Gitleaks rules. The JavaScript/TypeScript pack is
  `1.5.0` with 10 analyzers/24 rules; the aggregate native engine is `5.15.0`.

## [2.0.0] — 2026-07-30

### Added
- A first-class local CLI with offline `preflight`, current scans, JSON/SARIF/CSV export, explicit
  CI severity policy, stable exit statuses, and unchanged no-argument MCP stdio startup.
- Versioned aggregate coverage that fails closed for partial, unknown, excluded, unavailable,
  truncated, or not-rechecked work.
- Bounded scan history, arbitrary compatible comparison, append-only local triage, baselines, and
  new-finding enforcement without suppressing raw findings.
- Exact Git diff and working-tree scans with isolated snapshots, supporting repository context, and
  explicit changed/supporting/deleted/renamed/untracked coverage.
- Sealed local evidence bundles with versioned manifests and hash verification before export or
  comparison.
- A spreadsheet-safe CSV projection and the public `codeinspectus/sdk` ESM/type subpath, implemented
  as a bounded shell-free wrapper around the exact installed CLI.
- Resumable bounded scanning of existing local child repositories and explicit bounded immutable
  repository-history scanning. Neither workflow clones repositories or discovers remote accounts.
- Redacted review-only GitHub, Jira, and Linear issue payload adapters. No submission, authentication,
  destination lookup, or network client is included.
- Three shipped agent skills: approval-gated one-finding remediation, untrusted-document
  threat-model interpretation, and evidence-separated bounded multi-agent review.
- A SHA-pinned reference GitHub Actions policy workflow and a complete V2 CLI command reference.

### Changed
- Package, MCP server, CLI, SDK API, and MCP Registry manifest versions are synchronized at `2.0.0`.
- Agent-rule files are included in the npm artifact as well as the fail-closed public repository
  projection.
- The detection database remains `1.13.0`: 86 curated detections, including 65 first-party native
  rules across 16 packs. V2 expands workflow surfaces, not detection breadth.
- Node 22 remains the minimum supported runtime; Node 24 is the primary CI runtime.

### Security and compatibility
- Scans remain zero-egress and repository-read-only. Network access remains limited to explicit
  engine installation/repair and user-run external integrations outside the scanner.
- Existing six MCP tools and stored v1.x scan loading remain backward compatible.
- Output schemas are versioned independently from the npm package. V2 JSON export/storage use
  `2.0.0`; SARIF remains `2.1.0`; bounded workflow manifests use their documented `1.0.0` contracts.
- Optional agent interpretations never suppress, downgrade, override, or enter deterministic
  findings. Exact-prior deterministic rescan evidence remains required for scanner-resolution claims.
- The V2 workflow layer was independently implemented from public product concepts; see
  [workflow design provenance](docs/V2-WORKFLOW-PROVENANCE.md).

## [1.5.0] — 2026-07-29

### Added
- The Python AI/API pack now detects a proven LangChain `FAISS.load_local(...)` call with literal
  `allow_dangerous_deserialization=True` as `ci-python-faiss-dangerous-deserialization` (CWE-502).
  The rule resolves supported current and legacy LangChain imports without executing target code,
  fails closed on unresolved/dynamic/spread calls, and states that exploitability depends on the
  loaded artifact's origin and integrity.
- The Python AI/API pack now detects a complete URL derived from web request input and actually
  fetched by a proven LangChain `WebBaseLoader`. The rule requires exact current/legacy loader
  provenance plus a supported load method, and stays silent for fixed destinations, fixed-origin
  path composition, unused loaders, unresolved helpers, spreads, shadowed classes, and overwritten
  receivers.
- The Python AI/API pack now reports `ci-python-prompt-injection-sink` when framework-proven
  request input reaches OpenAI Responses `instructions` or Anthropic Messages `system`, or when
  request-controlled model input shares the same proven SDK call with configured tool access.
  Ordinary user/input content without tools stays silent; findings are explicitly heuristic at
  medium confidence, with tool-enabled calls raised to high severity.
- The frozen Python TP/FP/fixed corpus, direct analyzer tests, pack inventory, provenance,
  redaction, technology applicability, built-MCP eval, and same-path rescan contracts now cover
  all ten Python AI/API rules.
- The bounded Python lexer now uses Lezer's exact `FormatString` ranges to retain validated
  f-strings as opaque dynamic tokens. Calls inside replacement fields remain deliberately
  uninspected, while unrelated executable code in the same file is no longer discarded.
- Prompt-injection findings now use `CWE-1427` (improper neutralization of input used for LLM
  prompting) instead of the output-validation weakness `CWE-1426`, preventing compliance
  enrichment from incorrectly adding OWASP LLM05 to LLM01 prompt-injection findings.
- The JavaScript/TypeScript pack now reports `ci-ai-llm-tool-argument-command-execution` when
  model-produced tool/function arguments reach import-proven Node `child_process.exec` or
  `execSync` directly or through one local wrapper without a visible checked approval,
  allowlist, or validated replacement value. The bounded rule maps to CWE-78/CWE-1426 and
  OWASP LLM05/LLM06, with medium-confidence wording and explicit cross-module/runtime limits.
- A dedicated TP/FP/fixed corpus, public regression test, vulnerable-app MCP eval, provenance
  component, manifest ownership, explanation/remediation metadata, and pinned public positive
  and negative scans lock the unsafe tool-execution contract.
- The Python AI/API pack now reports `ci-python-llm-tool-argument-command-execution` for proven
  OpenAI/Anthropic tool arguments reaching `os.system`, other inherent shell APIs, or supported
  `subprocess` calls with literal `shell=True`, directly or through one named local wrapper.
  Checked approval/allowlist gates, schema-validated replacement values, `shell=False`, static
  commands, lookalikes, spreads, generic dispatch, and unsupported deeper/cross-module flows stay silent.
- A first-party Go AI pack adds `ci-go-llm-tool-argument-command-execution` for exact official
  OpenAI Go Chat Completions tool arguments reaching import-proven `os/exec` shell interpreters.
  The medium-confidence rule supports bounded direct aliases, JSON unmarshal, one local parser, and
  one local command wrapper; checked rejection/approval or allowlist guards and validated replacement
  values stay silent. TP/FP/fixed fixtures, direct-file parity, bounded loader tests, provenance,
  technology-gated dispatch, built-MCP E37/E38, and pinned public positive/negative scans lock the contract.
- A first-party Java AI pack adds `ci-java-llm-tool-argument-command-execution` for exact official
  OpenAI Java tool-call arguments reaching an actually-started recognized `ProcessBuilder` or
  `Runtime.getRuntime().exec` shell. The medium-confidence rule supports bounded direct aliases,
  one local parser, and one local command wrapper; checked rejection/approval or allowlist guards,
  validated replacements, non-started builders, and fixed executables stay silent. TP/FP/fixed
  fixtures, direct-file parity, bounded loader tests, provenance, technology-gated dispatch,
  built-MCP E39/E40, and pinned public positive/negative scans lock the contract.
- A first-party C# AI pack adds `ci-csharp-llm-tool-argument-command-execution` for exact official
  OpenAI .NET `ChatToolCall.FunctionArguments` reaching an actually-started recognized
  `System.Diagnostics.Process` shell. The medium-confidence rule supports bounded direct aliases,
  `System.Text.Json` dictionary/property extraction, one local parser, and one local command
  wrapper; checked rejection/approval or allowlist guards, validated replacements, non-started
  process configuration, and fixed executables stay silent. TP/FP/fixed fixtures, typed method-
  parameter flow, direct-file parity, bounded loader tests, provenance, language-gated dispatch,
  built-MCP E41/E42, and pinned public positive/negative scans lock the contract.
- A first-party PHP AI pack adds `ci-php-llm-tool-argument-command-execution` for exact
  community-maintained `openai-php/client` or `openai-php/laravel` Composer evidence and tool-call
  `function->arguments` reaching `exec`, `system`, `shell_exec`, or `passthru`. The
  medium-confidence rule supports direct aliases, associative `json_decode`, one local parser, one
  local command wrapper, and one exact mapped variadic method dispatch. Checked approval or
  full-command allowlists and validated replacements stay silent; first-token executable checks do
  not suppress shell-metacharacter risk. TP/FP/fixed fixtures, direct-file parity, bounded loader
  tests, provenance, language-gated dispatch, built-MCP E43/E44, and pinned public positive/negative
  scans lock the contract. The supported PHP clients are community maintained, not official OpenAI SDKs.
- A first-party Rust AI pack adds `ci-rust-llm-tool-argument-command-execution` for exact
  community-maintained `async-openai` Cargo evidence and model tool arguments reaching an
  import-proven standard/Tokio process shell or literal Bollard Docker exec shell vector. The
  medium-confidence rule supports direct aliases, `serde_json` extraction, one recognized
  `generate_function_call` result, and one local command wrapper; checked approval/allowlist
  rejection and validated replacements stay silent. TP/FP/fixed fixtures, multiline-string
  regression coverage, direct-file parity, bounded loader tests, provenance, language-gated
  dispatch, built-MCP E45/E46, and pinned public positive/negative scans lock the contract.
  `async-openai` is community maintained and is not represented as an official OpenAI SDK.
- A first-party Ruby AI pack adds `ci-ruby-llm-tool-argument-command-execution` for exact official
  production `openai` Gemfile or runtime gemspec evidence and Chat tool-call or explicitly typed Responses function-tool arguments
  reaching `system`, `exec`, `IO.popen`, or import-proven Open3 shell execution. The
  medium-confidence rule supports direct aliases, `JSON.parse` command extraction, one local
  parser, and one local command wrapper; checked approval/full-command allowlists and validated
  replacements stay silent. TP/FP/fixed fixtures, string-decoy and heredoc fail-closed coverage,
  direct-file parity, bounded loader tests, provenance, language-gated dispatch, built-MCP E47/E48,
  lockfile-only/development-only exclusions, and a pinned public official-SDK safe-tool scan lock
  the contract.
- A first-party Firebase configuration pack adds `ci-firebase-firestore-public-write`,
  `ci-firebase-storage-public-write`, and `ci-firebase-realtime-database-public-write` for literal
  unconditional public writes in checked-in Security Rules. Public reads and non-literal
  conditions stay silent. The bounded no-follow parser masks Rules comments/strings, requires
  exact Firestore/Storage service declarations, parses Realtime Database rules as strict JSON, and
  never runs Firebase tooling or target code. TP/FP/fixed fixtures, technology gating, provenance,
  built-MCP E49/E50, and pinned public positive/precision scans lock the contract.
- A first-party GitHub Actions workflow pack adds
  `ci-github-actions-untrusted-expression-command` for direct documented attacker-controlled
  `github` context interpolation in `run`, and `ci-github-actions-pwn-request` for the exact
  `pull_request_target` plus untrusted checkout plus checked-out-code execution chain. The bounded
  no-follow YAML 1.2 parser reads only direct workflow files and never executes target code.
  Safe `env`/`with` indirection, normal `pull_request`, checkout without execution, and protected
  checkout v7 stay silent. TP/FP/fixed fixtures, technology gating, provenance, built-MCP E51/E52,
  and pinned public positive/precision scans lock the contract.

### Changed
- Detection database `1.13.0` contains **86 curated detections**: 65 first-party native rules,
  18 Opengrep-owned SAST rules, and 3 custom Gitleaks rules. The JavaScript/TypeScript pack is
  `1.3.0`, the Python AI/API pack is `1.4.0`, the Go AI pack is
  `1.0.0`, the Java AI pack is `1.0.0`, the C# AI pack is `1.0.0`, the PHP AI pack is `1.0.0`,
  the Rust AI pack is `1.0.0`, the Ruby AI pack is `1.0.0`, the Firebase pack is `1.0.0`, the
  GitHub Actions pack is `1.0.0`, and the aggregate native engine signature is `5.13.0`.
- Updated `@modelcontextprotocol/sdk` to `1.30.0` and its Hono adapter to `2.0.12`, removing the
  prior moderate audit findings. One low, development-server-only esbuild advisory remains; the
  affected development server is not used or shipped by CodeInspectus.

## [1.0.0] — 2026-07-27

### Added
- A static native detector-pack registry now owns **49 first-party rule IDs** across eight packs and
  29 independently failing analyzers. Existing AI/framework packs retain their scanner behavior.
- A fail-closed Opengrep reconciliation layer promotes the parity-proven JavaScript/TypeScript
  weak-hash and weak-cipher rules into a native SAST pack before routing and deduplication. Exact
  matches surface native-only provenance; Opengrep remains physically active and wins on reference-
  only or metadata-mismatch cases, while native-only candidates are suppressed. If Opengrep cannot
  run, the native implementation is the explicit fallback. Shadow parity remains a release gate.
- An additive Flutter/Dart pack contributes `ci-flutter-tls-verification-disabled`,
  `ci-flutter-sensitive-shared-preferences`, `ci-flutter-webview-untrusted-content`,
  `ci-flutter-sensitive-log`, `ci-flutter-supabase-privileged-key-client`, and
  `ci-flutter-cleartext-network`. These first-party structural checks run only when Flutter is
  detected and do not replace runtime mobile testing, the separate native platform configuration
  packs, or Pub vulnerability/SBOM analysis.
- Android and iOS configuration packs add eight first-party rules for explicit production
  debuggability, cleartext/user-CA policy, exported AndroidX FileProvider, ATS exceptions/TLS policy,
  and disabled iOS data protection. They use bounded structured repository parsing, never execute
  Gradle, Xcode, or target content, and report unsupported/dynamic inputs as coverage limitations.
- Separate React Native and Expo packs add six first-party structural rules for sensitive
  AsyncStorage writes, unsafe WebView content/origin settings, public Expo configuration secrets,
  and unsigned cleartext updates. They require explicit framework evidence, never execute target
  modules/configuration, and keep bare React Native coverage distinct from Expo coverage.
- A Python AI/API pack adds six high-confidence first-party rules for hardcoded framework signing secrets,
  credentialed all-origin CORS, request-controlled file responses, redirects, and template source,
  plus unsanitized OpenAI/Anthropic output returned as HTML. Bounded Lezer-gated, source-ordered
  intrafile analysis never imports or executes target code; unsupported syntax and project bounds
  fail closed with explicit pack-coverage notes.
- A separate first-party `codeinspectus-pub` engine now analyzes bounded `pubspec.lock` files under
  the `vuln` scanner class, independently of Trivy. It matches only exact affected versions from a
  bundled, provenance-recorded OSV Pub snapshot (11 active reviewed advisories across 10 packages
  at this release), rejects ambiguous lockfiles, excludes custom registries/Git/path/SDK packages,
  and reports explicit dependency coverage instead of treating skipped input as clean.
- Native Pub SBOM support generates CycloneDX 1.6 or SPDX 2.3 inventories, merges official Pub
  components additively into Trivy output, and falls back to a Pub-only document when Trivy is
  unavailable. It preserves lockfile hashes/directness/origin without inventing licenses,
  suppliers, or a dependency graph that `pubspec.lock` does not contain.
- Scan and rescan output now includes deterministic repository technology detection and explicit
  per-pack analyzer/rule execution coverage, including `not_applicable` for an installed pack that
  does not match detected technology. Stored scans from older versions remain loadable.
- `codeinspectus_list_rules` now exposes native-pack inventory and exact manifest-to-pack ownership,
  including user-visible scope limitations that prevent a `ran` state being read as full language
  coverage.
- Detection database `1.0.0` contains **70 curated detections**: 49 first-party native rules,
  18 Opengrep-owned SAST rules, and 3 custom Gitleaks rules. The two promoted native rules retain
  active Opengrep YAML fallbacks, so 20 YAML rules still execute. The aggregate native engine
  signature is `5.0.0`; the separate Pub engine is `1.0.0`, and the built MCP stdio eval suite
  contains 36 cases. Opengrep, Gitleaks, and Trivy remain installed.

### Fixed
- Authored Opengrep confidence metadata now takes precedence over the producer's generic SARIF
  precision, preventing medium-confidence rules from being silently upgraded to high. The weak-
  cipher wording now covers deprecated password-based `createCipher` as well as DES/3DES/RC4.
- Supabase Edge Function authentication analysis now runs for projects that commit Edge Function
  source without also committing Supabase SQL migrations. The SQL project gate remains scoped to
  RLS analysis, and dedicated true-positive/false-positive fixtures lock the behavior.
- Replaced a pathological API-boundary string-masking regular expression with a bounded linear
  scanner. On the pinned Mattermost Mobile checkout, the complete native scan fell from about 69
  seconds to 7-8 seconds without changing finding identities or native-pack coverage.

### Changed
- The supported runtime floor is Node.js 22, with Node 24 LTS as the primary CI/runtime target.
  Node 22 and 24 are tested separately; the production bundle now targets Node 22 instead of the
  end-of-life Node 18 line.

## [0.4.1] — 2026-07-26

### Added
- Offline `engine_setup` health in scan and list-rules output, with stable `ready`,
  `repair_required`, `db_refresh_recommended`, and `unsupported_platform` states.
- Incremental `repair-engines` command. It downloads only unhealthy engine artifacts, verifies
  them against immutable shipped pins, installs binaries atomically, refreshes stale/missing
  Trivy DB state, and serializes concurrent repairs with a per-machine lock.

### Changed
- End-user setup no longer rewrites the npm package's `engines.lock.json`; lockfile mutation is
  restricted to the maintainer-only `pin-engines` command. `install-engines` remains as a
  backward-compatible alias.
- MCP instructions require agents to explain partial coverage and obtain approval before launching
  a networked engine repair. No npm postinstall or scan-time download was added.
- CI now exercises offline health reporting, incremental repair, a real Trivy DB refresh, and
  immutable-lockfile enforcement. The manual maintainer workflow uses `pin-engines` explicitly.

### Fixed
- Long-running MCP processes invalidate cached engine verification when a repaired binary's file
  identity changes, so a successful repair is recognized without restarting the client.
- Binary and Trivy DB updates are staged and replaced atomically; interrupted repairs leave the
  last verified installation usable and clean stale repair locks safely.

## [0.4.0] — 2026-07-26

### Added
- **Project CI Enhancement 1:** four conservative JavaScript/TypeScript API-boundary
  detections for client-visible internal error details, explicit sensitive API-response
  fields, whole unvalidated request objects passed to Prisma/Supabase/Mongoose writes, and
  sensitive request data passed to logs. Each ships with dedicated component provenance,
  CWE plus OWASP Web/API mappings, remediation, redacted snippets, rescan continuity, and
  dual-direction precision fixtures.
- **Credentialed arbitrary-origin CORS detection** for `cors` middleware approval/reflection
  and direct allow-origin header reflection, with safe allowlist/pinned-origin fixtures.
- **Project CI Enhancement 2:** four evidence-gated configuration detections for security
  response headers explicitly disabled/neutralized, production CSP with bare wildcard or
  `'unsafe-eval'` script sources, auth/session cookies with explicitly insecure attributes,
  and Supabase CAPTCHA-enabled auth calls that omit `captchaToken`.
- **Three-state runtime-control evidence** on scan results:
  `verified_in_repository`, `insecure_configuration_found`, or
  `not_verifiable_from_repository`. Only explicit insecure repository configuration enters
  findings; missing/hosted/ambiguous controls remain metadata with no posture penalty.
- Literal configuration fixtures for Next.js last-match header ordering, Vercel, Helmet,
  nginx, Cloudflare Pages `_headers`, cross-layer conflicts,
  development/report-only CSP, cookie near misses, and Supabase hosted/disabled CAPTCHA.

### Changed
- Corrected the existing wildcard-plus-credentials CORS explanation: browsers reject
  credentialed response sharing for that invalid combination; it does not itself expose an
  authenticated response. Its severity is now medium, below the high-severity arbitrary-origin
  credential exposure rule.
- Extended credentialed-CORS precision to separately declared `cors` options while keeping
  realistic `indexOf`/allow-list callbacks silent.
- Hardened API-boundary source analysis against commented examples and minified vendor code;
  added Fastify response/request-log forms, Prisma transaction clients, and lowercase Mongoose
  `*Model` variables while keeping boolean-only sensitive-data presence logging silent.
- Corrected `ci-baseline-insecure-cookie` wording to its actual narrow behavior (explicit
  `httpOnly: false`); the new AI cookie rule covers `secure: false` and
  `SameSite=None` without `Secure`.
- Detection database `0.4.0` now contains **44 curated detections**: 21 AI analyzers,
  20 Opengrep SAST rules, and 3 custom Gitleaks rules. The CodeInspectus AI engine signature
  is `1.2.0`, and the eval suite now contains 21 cases.
- Refreshed permitted transitive patch versions for `fast-uri` and Hono before publication,
  clearing all high/critical advisories from the production dependency tree.

### Known limitations
- New API-boundary analysis is JavaScript/TypeScript source-only and intrafile; build output and
  minified vendor files are excluded. It intentionally prefers silence for ambiguous validation,
  business authorization, runtime middleware, and cross-file dataflow.
- Missing security headers, hosted CAPTCHA state, gateway rate limits, runtime overrides,
  and behavioral auth remain unverified. CodeInspectus reports these as
  `not_verifiable_from_repository`, never as vulnerabilities or proof of protection.

## [0.3.2] — 2026-07-18

Correctness release for effective Supabase RLS state, secret-scan coverage honesty,
and cross-version rescan proof.

### Fixed
- **Superseded RLS policies are no longer reported as active.** Ordered migration
  sequences now reduce CREATE, ALTER, DROP, enable, and disable operations to final
  effective state. Earlier releases could report a policy that a later migration had
  dropped or safely replaced, and could miss some later final-state changes.
- **Rescan no longer treats detector changes as user fixes.** Every finding now records
  its producing detector components. A vanished finding is `resolved` only when those
  components are present with identical signatures; otherwise it is `not_rechecked`.
  The first rescan of a pre-0.3.2 scan is therefore conservative: present findings stay
  `remaining`, while vanished findings report that CodeInspectus cannot tell whether the
  user fixed them because the checks changed.
- **Target Gitleaks config can no longer silently replace bundled checks.** CodeInspectus
  always uses its bundled config and ignores target `.gitleaks.toml` files and inline
  `gitleaks:allow` comments, disclosing both behaviors in scan output.
- Machines whose Trivy DB predates 0.3.2 report vanished CVEs as `not_rechecked` until
  `install-engines` is run once to record DB provenance; scan output now surfaces this
  expected state and the next `install-engines` run self-heals it.

### Added
- **Component-scoped provenance.** Signatures cover the shared RLS reducer, independent
  AI analyzers, normalization pipeline, engine binaries, invocation flags, the Opengrep
  ruleset, bundled Gitleaks config, Trivy checks, and the Trivy vulnerability DB. Trivy
  DB content is hashed once at install time, never during an offline scan.
- **Secret-coverage status.** A target `.gitleaksignore` remains effective in Gitleaks
  8.30.1 and cannot be neutralized. CodeInspectus continues the useful portion of the
  secret scan but marks `secret_coverage: "unverified"` and warns that coverage is partial.

### Known limitations
- Both paths where final RLS state is off report `high`; sensitivity tiering is pending
  independent validation (CG-83).
- RLS reduction does not compose separate migration directories or standalone SQL
  snapshots, and does not model SQL larger than 2 MiB, dynamic SQL, or dashboard-only
  database changes.
- `.gitleaksignore` can still suppress individual Gitleaks findings. CodeInspectus detects
  and discloses the file but does not claim an unremovable secret-detection floor.

## [0.3.1] — 2026-07-16

Codex integration and cross-platform release hardening. No detection-rule
changes; the 35-rule detection set is unchanged.

### Added
- **MCP-level agent workflow instructions.** Clients now receive the recommended
  scan → explain → consent → fix → rescan workflow during initialization, including
  granular fix consent, git-safety guidance, secret-rotation reminders, and the rule
  that a finding is never called fixed until a rescan confirms it.
- **Native portability CI.** Windows x64, macOS Intel, and Linux ARM64 now build,
  run unit tests and the MCP transport smoke, install and verify the pinned engines,
  require all 17 evals to execute, run the redaction e2e, and scan the fixture app.

### Fixed
- **Windows SARIF paths.** Absolute paths emitted by Opengrep are now normalized
  against Windows backslash targets, so findings retain repository-relative file
  locations across every supported runtime.
- **Accurate Codex setup documentation.** Codex now uses its CLI command, settings
  UI, or `config.toml` instead of the Claude JSON example. The documented
  `tool_timeout_sec = 600` prevents Codex's 60-second default from ending legitimate
  large-repository scans early. Existing Claude setup remains unchanged.
- **GitHub Actions Node.js deprecation warnings.** Checkout, Node setup, and artifact
  actions now use immutable Node 24-based release SHAs. The retired `macos-13`
  Intel runner label is replaced with `macos-15-intel`.

### Internal
- The MCP stdio smoke now requires non-empty server instructions and checks that the
  critical consent/rescan guidance is present in the initialization handshake.

## [0.3.0] — 2026-07-12

Rescan now reports "resolved" only when it can prove it, plus honesty fixes to install docs and stored-scan handling.

### Changed
- **Rescan no longer over-claims "resolved."** A prior finding is reported resolved only when CodeInspectus can prove it was re-checked and is gone — the producing engine actually ran, results weren't truncated, and the original scan's scope was reproduced. When it can't confirm (an engine didn't run, results hit a limit, or the prior scan predates captured scope), the finding is reported as **`not_rechecked`** — an honest "couldn't confirm," never a false all-clear. A genuine fix still shows as resolved.
- **Severity threshold on rescan is now display-only.** It affects what's shown, not what's compared — so filtering to "medium and up" can no longer make a still-present lower-severity finding look resolved.

### Fixed
- Rescans could report a still-present finding as "resolved" when the re-scan used a narrower filter, an engine quietly didn't run, or a co-located secret's identity shifted between runs. All three paths are closed; rescan now matches findings on stable identity, not just a run-specific fingerprint.

### Docs
- Install prerequisites now stated up front: **Node.js 18+** and **cosign** on your PATH (cosign verifies the Opengrep and Trivy downloads; the install fails closed without it — Gitleaks needs none).
- Refined the write-scope wording from 0.2.0: CodeInspectus never edits or deletes your source code or repository; scan history and engines live under `~/.codeinspectus`, and an SBOM is written to a managed directory by default, or a path you choose.

### Internal
- Hardened stored-scan handling against path traversal and added validation of loaded scan files. Added continuous integration (build, tests, engine-verified evals) with dependency-pinned workflows. No change to what gets detected — the 35-rule detection set is unchanged.

### Known limitations (stated plainly)
- A rescan run with a smaller `max_findings` than the original may report some findings as `not_rechecked` rather than resolved — by design, so a truncated re-scan never produces a false all-clear.

## [0.2.1] — 2026-07-06

### Fixed
- Release provenance: 0.2.1 is published from the public repository, so the npm package's gitHead and the v0.2.1 git tag both resolve to a public commit. (0.1.0 and 0.2.0 were published from a private build repo; their gitHead values point at commits not reachable from this repository and cannot be retroactively corrected.)

### Added
- MCP Registry metadata: `mcpName` in package.json and a root `server.json`, making CodeInspectus installable/listable via the official Model Context Protocol registry.

No detection or scanner behavior changes in this release.

## [0.2.0] — 2026-07-04

### Added
- **New AI-code detection — client-writable `user_metadata` authorization** (`ci-ai-client-metadata-authz`;
  CWE-639; OWASP A01). Flags an authorization decision that trusts Supabase `user_metadata` — e.g.
  `if (user.user_metadata.role === 'admin')`, which any signed-in user can self-assign via `/auth/v1/user`.
  High severity, medium confidence; detects the inline form plus intrafile split-variable / destructured
  forms. Gate privileged logic on the server-only `app_metadata` instead.
- **New AI-code detection — unsanitized model/user output rendered as raw HTML** (`ci-ai-llm-output-dangerous-html`;
  CWE-79/CWE-116; OWASP A03 + LLM05). Flags untrusted request input **or LLM/model output** flowing into
  `dangerouslySetInnerHTML` without sanitization; a `DOMPurify.sanitize(...)` wrap silences it. Fills a React
  raw-HTML-sink gap the bundled Opengrep ruleset defers.
- Detection database now ships **35 rules** (was 33).

### Changed
- User-facing "read-only" claims reworded to the precise **"never writes to your code or repo."** The tool only
  ever writes to a managed dir outside your project (e.g. the optional SBOM), never to your repo.
- Detection-database version → `0.2.0` (2026-07-04).

### Fixed
- `codeinspectus_generate_sbom` now correctly advertises the MCP annotation **`readOnlyHint: false`** — it
  writes an SBOM file (to the managed dir by default). The other five tools remain read-only. Honesty-metadata
  correctness.
- README coverage notes corrected: client-writable `user_metadata` authorization is now **detected**
  (previously documented as "not yet detected").

### Known limitations (stated plainly)
- Both new AI-code rules are precision-gated against frozen fixture corpora (true-positive + false-positive
  cases) and are **validated synthetically** — real-world recall is not yet measured.
- `ci-ai-llm-output-dangerous-html` does **not** yet trace untrusted values arriving via component props,
  database rows, or template data (planned).

## [0.1.0] — 2026-06-21

### Added
- Initial release. Local-first, zero-egress security MCP server orchestrating **Opengrep** (SAST),
  **Gitleaks** (secrets), and **Trivy** (SCA / IaC / license / SBOM) behind one CWE-keyed schema, plus
  CodeInspectus **AI-code checks** (client-side secret/bundle exposure, Supabase RLS / inverted-auth,
  prompt-injection sinks). Compliance mapping as honest code-level control coverage. 33 detection rules.
