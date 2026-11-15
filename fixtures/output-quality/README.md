# Output-quality fixtures (4.1 M5)

Hand-written minimal manifests and real, offline engine output for the 4.1 output-quality fixes
(Trivy lockfile lines, dependency scope, RubyGems CVE/GHSA aliases, `requirements.txt` declared minimums).
No third-party lockfile is copied; every manifest here was written by hand.

| Path | Content |
|---|---|
| `pnpm/package.json`, `pnpm/pnpm-lock.yaml` | lockfile v9: production `lodash@4.17.20`, development `handlebars@4.7.9` (the packages of `coverage-honesty-corpus/dev-deps`) |
| `ruby/Gemfile.lock` | `crass (1.0.7)`, `shopify_app (23.0.2)` |
| `python/requirements.txt` | `urllib3>=2.2.2`, `requests==2.31.0`, `setuptools~=78.1` |
| `trivy-pnpm.json` | Trivy JSON report for `pnpm/` |
| `trivy-ruby.json` | Trivy JSON report for `ruby/` |
| `osv-dev-deps.json` | osv-scanner JSON for `coverage-honesty-corpus/dev-deps` |

## Provenance

Captured 2026-11-14, offline, with the engines CodeInspectus installs: Trivy 0.76.1 and osv-scanner 2.7.0
(osv-scalibr 0.5.3).

- Trivy: the wrapper's flags (`fs --scanners vuln --format json --list-all-pkgs --include-dev-deps`, the
  offline flags, empty `--config`/`--secret-config`/`--ignorefile`) plus `--cache-backend memory`, against the
  installed vulnerability database. Edits: `Description` removed from each vulnerability, `Metadata` emptied,
  `ArtifactName` replaced, `CreatedAt` normalised. `VulnerabilityID`, `PkgName`, `InstalledVersion`,
  `DataSource`, `References`, `Packages[].Dev` and `Packages[].Locations` are as Trivy wrote them.
  Trivy reports no `Locations` for `pnpm-lock.yaml` (every pnpm finding sits at line 1).
- osv-scanner: the wrapper's flags (`scan source --offline --no-resolve --no-ignore --allow-no-lockfiles
  --all-packages --no-call-analysis=all --format json`, a comment-only `--config`) with
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` at the installed OSV databases (npm only; no Packagist database).
  The `package-lock.json` result comes from a run on a copy holding only `package.json` and
  `package-lock.json` (so the npm database matched); the `composer.lock` result comes from the run on the
  whole directory, which stopped before matching because the Packagist database is not installed, so it lists
  packages and `dependency_groups` without vulnerabilities. Edits: `source.path` rewritten to
  `/fixture/dev-deps/<file>`, `details` removed from each advisory. `dependency_groups` are as written:
  `["dev"]` on development packages, absent otherwise.

Checked with the repository's `gitleaks` configuration: no leaks.
