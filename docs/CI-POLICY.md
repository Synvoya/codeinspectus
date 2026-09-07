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
| `0` | Scan completed with `complete` aggregate coverage and the configured policy passed. In report-only mode, findings are allowed. |
| `1` | Coverage was complete and at least one canonical finding met or exceeded `--fail-on-severity`. |
| `2` | Invalid input, runtime failure, or aggregate coverage was `partial`/`unknown`. Coverage takes precedence over findings. |
| `130` | Interrupted by `SIGINT`. |
| `143` | Terminated by `SIGTERM`. |

Scanner exclusions are whole-product coverage exclusions. A narrowed scan such as `--scanner ai`
therefore reports aggregate `partial` and exits 2; it is useful as evidence, but cannot prove a clean
repository-wide CI result. Missing engines, failed components, truncation, bounded/skipped inputs,
secret uncertainty and missing execution evidence likewise cannot pass as clean.

JSON records `scan.configuration.policy_mode` and optional `fail_on_severity`. SARIF records the
same policy fields plus `aggregate_coverage` and `coverage_evidence` in run properties. SARIF is
written before the policy exit is returned, including exits 1 and 2, so CI can retain evidence.

## GitHub Actions reference

The shipped [copyable workflow](examples/codeinspectus-security.yml) separates the explicit,
network-permitted install/engine-repair steps from the offline scan step. Every third-party action is
pinned to a full commit SHA. It installs the exact `codeinspectus@3.1.0` release under
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
