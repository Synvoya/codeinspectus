# Release process

CodeInspectus GitHub releases and npm publications are deliberately separate operations. Publishing a
GitHub Release triggers `.github/workflows/release.yml`, which validates the signed tag and independently
rebuilds and tests the exact public commit. The workflow has read-only repository permission and never
publishes to npm.

The public GitHub repository is owned by `Synvoya`; the npm package is maintained by `hibin-m`.
Publishing to npm is therefore performed from an authenticated maintainer terminal after the GitHub
release validation succeeds. Do not add an npm token, npm trusted-publisher mapping, GitHub `npm`
environment, or OIDC publishing permission to the release workflow.

Protect `v*` tags and the release workflow through repository rules.

## Per-release sequence

1. Run the complete release checklist in `docs/context/verify.md` on the intended public commit.
2. Set and reconcile the package, lockfile, server, CLI, SDK, changelog, and registry-manifest version.
3. Create an annotated signed tag: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
4. Push the commit and signed tag, then confirm normal CI is green for the tagged commit.
5. Publish a GitHub Release from that exact tag. This triggers the validation-only release workflow.
6. Require that workflow to pass before publishing the package.
7. From a clean checkout of the exact public tagged commit, authenticate with `npm login --auth-type=web`
   if needed and verify `npm whoami` reports `hibin-m`.
8. Confirm `codeinspectus@X.Y.Z` does not already exist, then run `npm publish --access public` and
   complete npm's browser/2FA approval.
9. Verify the registry reports `X.Y.Z` as both the package version and `latest`, and record the registry
   integrity and shasum.

Published package versions and public tags are immutable release evidence. Do not rewrite an existing
tag. Terminal publications do not carry GitHub Actions SLSA provenance, so do not claim that provenance
for those package versions.
