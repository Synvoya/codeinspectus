# CodeInspectus CLI reference

Running `codeinspectus` with no arguments starts the ten-tool MCP stdio server. Every explicit
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
- `--licenses` (scan only): include licence findings. They are off by default since 4.0 because they
  are informational and none is fixable; without the flag the scan carries the coverage note
  "Licence findings were not requested (use include_licenses / --licenses)." (informational, never a
  coverage gap). `--scanner license` also requests them. The MCP tools take `include_licenses: true`
  on `codeinspectus_scan`, and `codeinspectus_rescan` and `scans rerun` repeat the prior scan's choice.
- `--accept-gaps <id[,id]>` (scan only): accept named coverage gaps such as `php-sast`, `deno-lock`,
  `vendored-js` or `third-party-bundles` so they alone do not fail CI; coverage still reads `partial` and
  the gaps stay listed. An unknown id is an input error (exit 2). Gap ids are documented in
  [CI-POLICY.md](CI-POLICY.md#declared-coverage-gaps).

Policy and Git scope options:

- `--fail-on-severity LEVEL`
- `--baseline SCAN_ID --fail-on-new-severity LEVEL`
- `--diff BASE_REVISION --head HEAD_REVISION`
- `--working-tree --base BASE_REVISION`

`preflight` never scans, repairs, downloads, authenticates, or writes. It accepts the shared scan
options with `--format text|json` only; policy and Git scope options apply to `scan`. A Git-scoped scan reports
changed and supporting-context findings separately and never checks out or changes repository state.

## Export, history, and triage

```bash
codeinspectus export SCAN_ID --format json|sarif|csv [--output FILE]
codeinspectus scans list [--repository PATH] [--path PATH] [--severity LEVEL]
                         [--status clean|findings|partial|unknown] [--since DATE] [--until DATE]
                         [--limit N] [--format text|json]
codeinspectus scans show SCAN_ID [--format text|json]
codeinspectus scans rerun SCAN_ID [--format text|json]
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
codeinspectus bundle export BUNDLE_DIRECTORY --format json|sarif
codeinspectus bundle compare OLD_BUNDLE NEW_BUNDLE [--format text|json]
```

Verification checks the manifest schema, allowed paths, artifact hashes, redaction boundary, and
embedded canonical scan before a bundle can be exported or compared. `bundle export` writes the
sealed JSON or SARIF artifact byte-for-byte to stdout; redirect it to save a file.

## Bounded repository sets and history

```bash
codeinspectus bulk scan PARENT [--concurrency N] [--max-repositories N]
                               [--max-attempts N] [--manifest FILE] [--format text|json]

codeinspectus history scan REPOSITORY --from REVISION --to REVISION
  --since 2026-07-01T00:00:00Z --until 2026-07-31T23:59:59Z --max-commits N [scan options]
```

Bulk mode discovers only immediate, already-existing local Git repositories; it never clones or
discovers an account. Repository-history mode requires exact revision/date/count bounds (dates are explicit UTC RFC 3339
timestamps) and caps a request at 50 commits. Shallow, truncated, omitted, failed, or cancelled work cannot report complete.

## Review-only tracker payloads

```bash
codeinspectus issue export SCAN_ID FINDING_ID --adapter github|jira|linear
  --visibility private|public [--output FILE]
```

This produces redacted deterministic JSON for manual review. It performs no authentication,
destination lookup, issue submission, or network request. `issue submit` is intentionally rejected.

## Engine lifecycle and metadata

```bash
codeinspectus init [--yes] [--large] [--path DIR] [--clients LIST] [--skip-engines] [--dry-run] [--json]
codeinspectus init --update [--yes] [--large] [--dry-run] [--json]
codeinspectus setup
codeinspectus setup --status
codeinspectus setup --all
codeinspectus setup --select opengrep,gitleaks,trivy,osv-scanner
codeinspectus setup --select osv-scanner --path REPOSITORY
codeinspectus setup --select osv-scanner --osv-ecosystems npm,PyPI
codeinspectus setup --reset
codeinspectus update [--yes] [--large] [--json]
codeinspectus repair-engines [ENGINE] [--osv-ecosystems LIST]
codeinspectus install-engines [ENGINE]
codeinspectus verify-engines
codeinspectus pin-engines [options]
codeinspectus --version
codeinspectus --help
```

`init` is the one-command path. It detects AI assistants: Claude Code (`claude` on PATH), Codex
(`codex` on PATH or `~/.codex/`), Cursor (`~/.cursor/`), VS Code (`code` on PATH or the user settings
folder: macOS `~/Library/Application Support/Code/User`, Linux `~/.config/Code/User`, Windows
`%APPDATA%\Code\User`), Windsurf (`~/.codeium/windsurf/`) and Cline (its `globalStorage` folder in the
VS Code user folder). It then prints one screen: each assistant with the exact command or file, each
engine with its size and licence (an engine that cannot run on this platform is shown and skipped),
the OSV databases for `--path DIR` (default: the current folder unless it is your home folder or the filesystem root) with
their sizes, and the total download. Each single download over 100 MB (an engine binary, the Cosign
verifier on a first install, about 140–200 MB depending on platform, the Trivy DB on a first install, about
140 MB, an OSV database such as npm) is marked `(over 100 MB)`. On a
terminal it asks `Set all of this up? [y/N]`, then, when the screen lists a download over 100 MB,
`These include downloads over 100 MB (...). Download them too? [y/N]` (a no installs everything else:
the assistants are still registered, and each large download is left out with whatever needs it, such as
Trivy for the Trivy DB or the Cosign-verified engines for the verifier, and the question and the summary
name those engines); without a terminal it needs `--yes`, and `--yes` needs `--large` when the screen lists a download over 100 MB
(otherwise it exits 2 and changes nothing), as `update` does. On yes it registers the assistants, then
installs all four engines once through the `setup` install path.

- Claude Code: `claude mcp add-json --scope user codeinspectus '{"command":"npx","args":["-y","codeinspectus"]}'`
  (on native Windows the server is `{"command":"cmd","args":["/c","npx","-y","codeinspectus"]}`, as Claude
  Code requires for npx servers there; either form counts as registered). Its own `.claude.json`
  (in `$CLAUDE_CONFIG_DIR` when set, else the home folder; not read over 50 MiB) is only read, and only
  to tell whether the server is already there; only an identical entry found there is "already
  registered". If the CLI itself answers that an entry named codeinspectus already exists, that is
  reported as a conflict (left unchanged; check it with `claude mcp get codeinspectus`).
- VS Code: `code --add-mcp '{"name":"codeinspectus","command":"npx","args":["-y","codeinspectus"]}'` when
  `code` is on PATH, otherwise the user `mcp.json` (`servers` key, a `stdio` entry).
- Codex: appends the `[mcp_servers.codeinspectus]` block with `tool_timeout_sec = 600` to
  `~/.codex/config.toml` (created when absent), keeping the existing text exactly.
- Cursor (`~/.cursor/mcp.json`), Windsurf (`mcp_config.json`) and Cline (`settings/cline_mcp_settings.json`):
  the entry is merged into `mcpServers`.
- A file that is not plain JSON or valid TOML is never rewritten; the manual step is printed with at
  most a line and column, never the file's text. The same holds for JSON with a duplicate key or a number
  that rewriting would change (an integer above 2^53, `1.0`), a file that cannot be read, one over
  50 MiB, and a symbolic link to a missing file. An existing `codeinspectus` entry with the same command
  is "already registered"; a different one is left alone and reported by client and file only. Only a
  file shown as a change on the screen is written, and only if it still holds what init read: a file
  changed meanwhile (checked again just before the rename) is skipped with "run init again". Before the
  first change to an existing file, a copy is kept at `<file>.codeinspectus-backup` (never overwritten).
  Writes are atomic and keep the file mode and CRLF line endings; a new file is created only if nobody
  created it meanwhile.
- `--clients LIST` limits registration to `claude`, `codex`, `cursor`, `vscode`, `windsurf`, `cline`;
  `--skip-engines` registers only; `--dry-run` prints the screen and changes nothing; `--json` prints
  one JSON document and needs `--yes` (plus `--large` for downloads over 100 MB) or `--dry-run`.
- Exit status: 0 done, declined or nothing to do (a skipped or conflicting file is reported with the
  manual step); 1 when an assistant's CLI or a file write failed, or the engine install failed; 2 for
  an invalid option, when `--yes` is missing without a terminal, or when `--large` is missing for a
  download over 100 MB.

`init --update` downloads new engine pins and missing binaries for the engines enabled in `setup`,
then refreshes the installed databases exactly as `update` does (same `--yes` and `--large` rules,
same second question on a terminal). Every download over 100 MB counts, including a Trivy DB or OSV
database the engine repair itself fetches (for example a missing Trivy binary and DB). A database the
engine repair refreshed is not downloaded again by the database refresh. When npm has a newer CodeInspectus it says to run
`npx codeinspectus@latest init --update`, because npx may run a cached copy. It never registers
assistants. Exit status as `update`: 1 names the engine or database that failed.

Bare `codeinspectus` starts guided setup only when stdin and stdout are interactive terminals;
piped stdio still starts the MCP server. Its first line points to `npx codeinspectus init`. `setup` shows exact pinned binary asset sizes and a clearly
labelled Trivy database disk estimate before approval. `--all` and `--select` are explicit
noninteractive approvals. Saved choices prevent repeat prompting; `--reset` removes them.

osv-scanner needs one OSV database per package ecosystem, downloaded only after approval from
`osv-vulnerabilities.storage.googleapis.com`. The plan lists each database with its estimated size.

- `--path REPOSITORY` reads lockfile and manifest file names under that directory (read-only and
  bounded) and offers only the databases for the ecosystems it finds. It is a shortcut for naming
  them, not a scan.
- `--osv-ecosystems LIST` approves exactly the listed ecosystems and overrides `--path`. The list is
  comma-separated and case-insensitive; the allowed names are `npm`, `PyPI`, `Packagist`, `Go`,
  `crates.io`, `RubyGems`, `Maven`, `NuGet`, `Pub`, and `GitHub Actions` (a small database read by the
  Synvoya Actions matcher, not by osv-scanner; quote the name). Distribution ecosystems are not allowed.
  Databases are downloaded only when `osv-scanner` is among the selected components;
  `--osv-ecosystems` without it is an error.
- With neither option, `setup` installs the osv-scanner binary and downloads no database, except
  that it refreshes any OSV database already installed that has gone stale.
- `repair-engines --osv-ecosystems LIST` downloads exactly the listed OSV databases when they are
  absent or not ready, and no other OSV database; which engines the same command repairs is the
  next point. A bare `repair-engines` (no list) only refreshes OSV databases that are already
  installed and stale; it never adds an ecosystem.
- With no engine named, `repair-engines` covers every engine, so it can also install other
  engines and refresh the Trivy database (about 1 GB on disk). Name the engine to avoid that:
  `repair-engines osv-scanner --osv-ecosystems PyPI` touches only osv-scanner and the PyPI database.
  The one exception is a missing osv-scanner that you declined in `setup`: a bare `repair-engines`
  does not install it. Naming it, or passing `--osv-ecosystems`, installs it; once it is installed,
  a bare `repair-engines` maintains it and its databases like any other engine.

`update` re-downloads the managed databases that are installed (the Trivy DB through the pinned
Trivy binary, and each installed OSV database as a full export, after counting the OSV records
changed since its download from that ecosystem's `modified_id.csv`), then asks the npm registry
whether a newer CodeInspectus is published and reports it; it never installs one. It refreshes
databases only: when Trivy or osv-scanner itself is not ready (missing, hash mismatch, a new pin), that
engine's databases are listed as skipped and `codeinspectus setup` must repair the engine first.

It prints the plan first (download sizes; the Trivy DB's on-disk size is labelled "on disk") and asks
`Download these updates? [y/N]` on a terminal. A database over 100 MB (the Trivy DB, about 140 MB, and
the OSV npm export, about 220 MB) gets a second question; answering no to either question downloads
nothing and prints `No update downloaded.` `--yes` approves without asking and is required when stdin
is not a terminal: without it, `update` prints the plan, prints `Re-run with --yes to download.` and
exits 2. `--yes` does not approve a database over 100 MB; that needs `--yes --large`, or the command
exits 2. `--json` needs `--yes` and never asks: without `--yes` it prints an error to stderr, nothing
to stdout, and exits 2. With `--yes`, stdout is exactly one JSON document (the plan, plus the result
when it ran) and progress goes to stderr.

Exit status: 0 when the update succeeded, there was nothing to update, or a question was answered no;
1 when a refresh failed (the old database is kept); 2 when the download was not approved or an option
is invalid. Scans never run this step and never print the question; MCP agents relay it from
`database_update` instead.

A scan that finds a lockfile for an ecosystem whose OSV database is not installed reports that
ecosystem as `unavailable` and warns that setup is needed. It never reports it as clean.

`install-engines` remains a compatibility alias. `pin-engines` is maintainer-only. Normal scans
never repair or download engines or OSV databases implicitly. The managed Opengrep, Gitleaks,
Trivy, osv-scanner, and Cosign executables are never installed by npm lifecycle scripts. The
official C2PA validator is an optional peer and is not installed by a normal CodeInspectus
installation. Users may explicitly install `@contentauth/c2pa-node@0.9.3` alongside CodeInspectus
when C2PA validation is required; without it, scans keep working and report candidate C2PA asset
coverage as partial.
The pinned Linux Opengrep release assets require glibc. On Alpine/musl, setup blocks Opengrep
before download while leaving native rules, Gitleaks, and Trivy available; scans report the missing
Opengrep surface as partial coverage.

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
