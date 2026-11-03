# CodeInspectus CI policy

CodeInspectus CLI scans are report-only unless `--fail-on-severity` is present. Findings alone do
not fail a report-only scan, but insufficient coverage always fails closed in both modes.

```bash
# Report-only: findings are reported; complete coverage exits 0.
codeinspectus scan . --format sarif --output results.sarif

# Enforcement: complete coverage exits 1 when high/critical findings exist.
codeinspectus scan . --format sarif --output results.sarif --fail-on-severity high
```

`--severity` controls only which findings the human-oriented display shows. It is not a CI policy.
`--fail-on-severity` evaluates the complete canonical finding set, independent of display severity
and `--max-findings`.

## Exit contract

| Exit | Meaning |
|---:|---|
| `0` | Scan completed with `complete` aggregate coverage, or `partial` coverage only through gaps named in `--accept-gaps`, and the configured policy passed. In report-only mode, findings are allowed. |
| `1` | Coverage was complete (or partial only through gaps named in `--accept-gaps`) and at least one canonical finding met or exceeded `--fail-on-severity`. |
| `2` | Invalid input, runtime failure, or aggregate coverage was `partial`/`unknown` (unless every cause is a gap named in `--accept-gaps`). Coverage takes precedence over findings. |
| `130` | Interrupted by `SIGINT`. |
| `143` | Terminated by `SIGTERM`. |

Scanner exclusions are whole-product coverage exclusions. A narrowed scan such as `--scanner ai`
therefore reports aggregate `partial` and exits 2; it is useful as evidence, but cannot prove a clean
repository-wide CI result. Missing engines, failed components, truncation, bounded/skipped inputs,
secret uncertainty and missing execution evidence likewise cannot pass as clean.

## Declared coverage gaps

Some inputs CodeInspectus can see are analyzed by no bundled engine. Each such gap has a stable id,
makes aggregate coverage `partial`, and therefore exits 2 by default:

| Gap id | Meaning |
|---|---|
| `php-sast`, `ruby-sast`, `java-sast`, `kotlin-sast`, `go-sast`, `csharp-sast`, `rust-sast`, `swift-sast`, `c-sast`, `cpp-sast`, `scala-sast`, `dart-sast`, `objc-sast`, `elixir-sast`, `erlang-sast`, `lua-sast`, `perl-sast`, `groovy-sast`, `clojure-sast`, `haskell-sast`, `ocaml-sast`, `r-sast`, `julia-sast`, `zig-sast`, `solidity-sast`, `vb-sast` | Source files of a language that has no bundled code-pattern (Opengrep) rules. Native AI-check packs do not count as SAST. Server templates count toward their language: `.jsp`/`.jspx` (Java), `.erb` (Ruby), `.cshtml`/`.razor` (C#), `.blade.php` and `.twig` (PHP). `.m` is counted as Objective-C (`objc-sast`); MATLAB files share the extension and cannot be told apart. |
| `vue-sast`, `svelte-sast`, `astro-sast` | `.vue`, `.svelte` and `.astro` component files. Opengrep does not scan them and the native JavaScript packs do not read them, so their script code gets no SAST. |
| `sast-parse-errors` | Files Opengrep's parsers could only partly read (syntax, lexical or partial-parsing errors, for example syntax newer than its parser), so its rules did not see that code. Reported by the Opengrep run. A file with a timeout, memory limit or internal matching error is not this gap: it stays a coverage warning no gap id accepts. Residual risk: a repository can add a construct Opengrep cannot parse so the rest of a file goes unmatched; that is why it is a gap and never silent. Review the listed example files before accepting it. |
| `native-parse-errors` | Files the native packs' bounded JavaScript/TypeScript or Python lexers could not read, so the native AI and SAST checks skipped them. Includes files where the lexer cannot tell a regex from division. When the SAST scanner runs, Opengrep still scans them for its generic rules; the native-only checks (admin routes, Supabase Edge, React Native) have no Opengrep equivalent. Residual risk: a repository can add such a construct to keep a file from the native checks; review the examples before accepting. Separately from this gap, the native lexer is lightweight and can be evaded by deliberately crafted code while a file reads as parsed (see [Native pack limits](#native-pack-limits)). |
| `oversized-files` | Files over a native per-file size or call-count bound, or over the native JavaScript/TypeScript lexing caps (2 MiB characters per file, 64 KiB per line), skipped by the native checks. Typically vendored or minified bundles. Residual risk: an application file grown past a bound, or given one very long line, is skipped too; the examples show which. |
| `native-token-budget` | Files the native JavaScript/TypeScript packs did not parse because the 1,000,000-token project budget was spent; discovery continues in path order and counts every later source file. Residual risk: a repository can pad itself (large vendored or generated files early in path order) to push application files past the budget; when the SAST scanner runs, Opengrep still scans them for its generic rules, but the native-only checks have no Opengrep equivalent. Review the count and examples before accepting. |
| `express-routes-unresolved` | Files with Express admin-route candidates whose middleware or handler the check could not prove either way, so no finding and no clearance is reported for them. |
| `nextjs-routes-unresolved` | Files with Next.js admin API route handlers (`app/api/admin/**/route.*`, `pages/api/admin/**`) whose custom wrapper, custom guard or privileged operation the check could not prove either way (for example a project helper such as `parseRequest`), so no finding and no clearance is reported for them. Residual risk: a route without authorization that only calls such helpers is not reported; review the example files before accepting. |
| `symlinked-paths` | Symbolic links whose real target is inside the repository and is analysed under its own path by the walker that skipped the link (the native JavaScript walker or technology detection); path-sensitive checks (for example admin-route paths or manifest names) do not see it under the link's path. A link whose target is outside the repository, under a folder that walker ignores (such as `node_modules/`) or beyond its depth bound is not this gap: it stays a partial-coverage warning no id accepts. |
| `wordpress-plugins` | WordPress plugins and themes: `wpackagist-plugin/*` and `wpackagist-theme/*` entries in a `composer.lock`, and `wp-content/plugins/*` folders or files with a `Plugin Name:` header. No bundled engine has advisory data for them, so their versions are not checked. |
| `actions-unchecked` | Third-party `uses:` references in `.github/workflows/*.yml` (local `./` actions excluded). No bundled engine checks action versions against advisories; the GitHub Actions native rules still run. |
| `dev-deps-unscanned` | Maven dependencies in a `pom.xml` that Trivy 0.76.1 drops even with `--include-dev-deps`: `test`, `provided` or `system` scope, `<optional>true</optional>`, or a scope or optional flag set through a property (`${…}`), one entry per dependency; any `pom.xml` that cannot be read counts too. Their versions are not checked. Residual risk: test-scoped and optional dependencies still run in CI, on developer machines or in consumers' builds. |
| `deno-lock` | A `deno.lock` file; no engine reads it. |
| `bun-lockb` | A binary `bun.lockb` with no text `bun.lock` beside it. |
| `no-lockfile-npm` | A `package.json` that declares dependencies with no npm, Yarn, pnpm or Bun lockfile beside it. A lockfile in a parent folder covers it only when that parent declares its folder as a workspace (`workspaces` in the parent's `package.json`, as npm, Yarn and Bun use, or `packages` in `pnpm-workspace.yaml`); nested `examples/`, `docs/` or `website/` projects that are not workspaces are gaps. |
| `npm-shrinkwrap-unread` | An `npm-shrinkwrap.json` with no `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` or `bun.lock` beside it. Trivy 0.76.1 does not read `npm-shrinkwrap.json`. |
| `no-lockfile-composer` | A `composer.json` that requires packages with no `composer.lock` beside it. |

Files under the managed ignore list (`node_modules/`, `vendor/`, `build/`, `dist/`, `test/`, `tests/`,
the build-output folders file routing drops, such as `.next/`, `out/` and `.nuxt/`, and similar) are
not counted. Each gap reports its file count and up to five example paths.

Shell scripts, PowerShell scripts and Makefiles are not gaps: almost every repository has some, and
they are build or tooling glue. When a SAST scan finds them, `coverage_notes` (and the text summary
and the export, as informational evidence `scope:scripts`) say how many no bundled rule reads.

`--accept-gaps <id[,id]>` (MCP: `accept_gaps`) is an explicit opt-in for known gaps. Coverage still
reads `partial` and every gap stays listed (accepted ones are marked); CI passes coverage only when
every cause of non-complete coverage is an accepted gap id. Any other cause, including a gap you did
not name, still exits 2. An unknown id is an input error. Gaps travel in the JSON export as coverage
evidence with component `gap:<id>`, and each accepted id as an informational evidence item with
component `accepted-gap:<id>`, so export schema 3.0.0 is unchanged.

Gap ids are never removed. When a release closes a gap (for example, by adding PHP rules), its id is
no longer reported but stays valid: `--accept-gaps` and `accept_gaps` accept it as a no-op, and stored
scans that list it still load, so CI configurations keep working.

With `--baseline`, the accepted ids apply to both scans: a baseline or current scan that is partial
only through accepted gaps is a sound foundation, so findings can be proven New or Existing and the
comparison reads `complete`. Its `notes` name the gaps; a finding in input the baseline did not
analyze (for example a file it could not parse) reads New.

`scans compare` (SDK `compareHistory`) judges each stored scan by the gaps that scan accepted, but only
by language and component gaps (`<language>-sast`, `vue-sast`, `svelte-sast`, `astro-sast`): no engine
reports SAST findings in those inputs, so when both scans are complete or partial only through such
accepted gaps, absence can prove Resolved and New, and the comparison notes name the gaps. Accepted
`sast-parse-errors` and lockfile gaps (`no-lockfile-npm`, `no-lockfile-composer`,
`npm-shrinkwrap-unread`, `bun-lockb`, `deno-lock`) still make the comparison partial: an engine may
have analyzed that input in the other scan, so a missing finding there proves nothing. A scan that did
not accept its gaps also keeps the comparison partial.

JSON records `scan.configuration.policy_mode` and optional `fail_on_severity`. SARIF records the
same policy fields plus `aggregate_coverage` and `coverage_evidence` in run properties. SARIF is
written before the policy exit is returned, including exits 1 and 2, so CI can retain evidence.

### Native pack limits

The native packs (JavaScript/TypeScript, React Native, Express and Next.js admin routes, Supabase Edge
and the other native AI checks) use a lightweight lexer, not a full parser. They are pattern checks
for ordinary, non-adversarial code. Code written to evade them can hide a call from them, or show them
a fake guard, while the file still reads as parsed, so no gap is reported. When the SAST scanner runs,
Opengrep's full parser still scans the same files for its generic sinks, but the native-only checks
have no Opengrep equivalent.
Accepting a gap never makes this stronger. A full parser replacement is planned for 4.0.

## GitHub Actions reference

The shipped [copyable workflow](examples/codeinspectus-security.yml) separates the explicit,
network-permitted install/engine-repair steps from the offline scan step. Every third-party action is
pinned to a full commit SHA. It installs the exact `codeinspectus@3.3.2` release under
`$RUNNER_TEMP` with npm lifecycle scripts disabled; it does not run the target repository's package
install, lifecycle scripts, build, tests, or other code. The job uses least privilege (`contents: read`,
`security-events: write`), checks out with `persist-credentials: false`, does not reference repository
secrets, and never uses `pull_request_target`. Copy it to
`.github/workflows/codeinspectus-security.yml` in the repository you want to scan. The read-only
scanner receives the checked-out path as data and does not receive a GitHub credential.

The workflow captures the policy status, uploads available SARIF, and then restores the exact
CodeInspectus exit. This ordering prevents a high finding or incomplete scan from suppressing its
report. GitHub Code Scanning upload requires Code Scanning availability for the repository.

### Fork and Dependabot pull requests

Fork and Dependabot PRs run the same no-secret scan with their read-only token. The write-capable
Code Scanning upload step is skipped for those events; the final policy exit still gates the job.
They receive a bounded job summary containing only aggregate coverage, severity, rule identity and
location (maximum 50 rows), never messages, snippets, remediation or raw SARIF.
Do not change this workflow to `pull_request_target` or inject secrets into install/build/scan steps.
Trusted same-repository PRs and pushes may upload SARIF.

The official C2PA validator is an optional peer and the reference workflow does not install it.
Repository security findings still run normally; candidate C2PA assets report partial
`content_provenance` coverage. Explicitly install reviewed `@contentauth/c2pa-node@0.9.3` with
lifecycle scripts enabled on a supported runner only when CI-level C2PA validation is required.

### Artifact privacy and retention

SARIF may include redacted source excerpts and repository paths. The reference workflow uploads a
raw Actions artifact only when the repository is private, retains it for seven days, and relies on
the access-controlled Code Scanning view for public repositories. For sensitive private projects,
shorten retention or remove the artifact step. Never upload unredacted scanner intermediates.

`--output results.sarif` is explicit approval to write that exact artifact, even inside the scanned
repository. Prefer `${RUNNER_TEMP}` in CI so the scan does not leave a worktree artifact.
