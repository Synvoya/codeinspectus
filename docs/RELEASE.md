# Release process

Codex may prepare and execute the complete CodeInspectus release, but it must stop at one explicit
human approval gate before making any externally visible change. Before approval, Codex may edit,
test, build, pack, create local commits, and prepare a signed local tag. It must not push either
repository, push a tag, create a GitHub Release, publish npm, publish the MCP Registry entry, or
deploy the website.

The approval must identify the exact version, public commit, release scope, npm artifact identity,
and any website commit. One approval authorizes only the ordered publication batch below. A content,
version, target, or scope change after approval invalidates it and requires a new approval.

## Account and automation boundary

- GitHub repositories and Releases use the `Synvoya` account.
- npm publication runs from the maintainer terminal only after `npm whoami` reports `hibin-m`.
- `.github/workflows/release.yml` validates the signed public tag and rebuilds/tests it. It has
  read-only repository permission and never publishes npm.
- Do not add npm credentials, a trusted-publisher mapping, an npm environment, or OIDC publication
  permission to the GitHub workflow.
- Terminal-published versions do not carry GitHub Actions SLSA provenance. Do not claim otherwise.
- MCP Registry publication uses `mcp-publisher publish` from the exact verified public checkout.
- The private website repository remains a separate deploy-only surface. When release claims change,
  push its approved commit, then verify the resulting Cloudflare Pages production deployment.

Protect public `master`, `v*` tags, and the release workflow through repository rules.

## Before requesting approval

1. Run the complete release checklist in `docs/context/verify.md` on the intended public commit.
2. Set and reconcile the package, lockfile, server, CLI, SDK, changelog, and registry-manifest version.
3. Re-seed the public repository through the fail-closed seed process and verify the intended diff.
4. Build the public checkout, run its tests/evals/smokes, and inspect `npm pack --dry-run --json`.
5. Validate `server.json` with `mcp-publisher validate` without publishing it.
6. When website claims change, run `git diff --check`, local desktop/mobile render checks, link/console
   checks, and compare every version/count claim with the public artifact.
7. Prepare local commits and the annotated signed public tag: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
8. Present the exact private/public/website commits, tag, tarball integrity/shasum/file count, completed
   checks, intended external actions, and remaining unknowns. Request explicit publication approval.

## After explicit approval

Execute in order and stop on the first failure or mismatch:

1. Reconfirm that every approved commit/tag still matches the evidence bundle and that all involved
   worktrees are clean.
2. Push the approved private tool commit, public commit, signed public tag, and—when applicable—the
   approved website commit. Push nothing else.
3. Wait for normal CI on the exact private and public commits. Require every mandatory job to pass.
4. Create the GitHub Release from the exact signed public tag. Wait for the validation-only `release`
   workflow to pass on that tag.
5. From a clean checkout of that exact public tag, run `npm whoami` and require `hibin-m`; refuse an
   existing package version; then run `npm publish --access public` and complete npm's browser/2FA
   approval if requested.
6. Verify npm reports the version as `latest`, and record the published integrity, shasum, file count,
   unpacked size, repository URL, and Node engine. Compare them with the approved candidate.
7. From the same public checkout, run `mcp-publisher publish`. Query the official Registry until the
   exact version is present and marked latest with the expected npm package metadata.
8. When the website commit was pushed, poll `wrangler pages deployment list`, fetch
   `https://codeinspectus.com/`, and verify the approved release strings, absence of stale strings,
   response headers, links, console, and representative desktop/mobile renders.
9. Re-fetch GitHub Release, npm, MCP Registry, and website state. Report each surface separately;
   never infer one surface from another.

Published package versions and public tags are immutable release evidence. Do not rewrite an existing
tag. A failed later surface does not roll back earlier publication; stop, report the partial release
state, and repair only the failed surface with fresh evidence.
