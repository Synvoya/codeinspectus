# Release process

CodeInspectus releases are published from the public GitHub repository by
`.github/workflows/release.yml`. The workflow fails closed unless the release tag is annotated,
cryptographically signed, verified by GitHub, and exactly matches the package version and checked-out
commit. It independently rebuilds and verifies the package before publishing through npm trusted
publishing with provenance.

## One-time provider configuration

In the npm settings for `codeinspectus`, configure a GitHub Actions trusted publisher with these exact
values:

- owner: `Synvoya`
- repository: `codeinspectus`
- workflow filename: `release.yml`
- environment: `npm`
- allowed action: `npm publish`

Create the GitHub `npm` environment and require manual approval. Do not add a long-lived `NPM_TOKEN`;
the workflow uses GitHub OIDC (`id-token: write`). Protect `v*` tags and the release workflow through
repository rules.

## Per-release sequence

1. Run the complete release checklist in `docs/context/verify.md` on the intended public commit.
2. Set and reconcile the package, lockfile, server, CLI, SDK, changelog, and registry-manifest version.
3. Create an annotated signed tag: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
4. Push the commit and signed tag, then confirm normal CI is green for the tagged commit.
5. Publish a GitHub Release from that exact tag. This triggers the release workflow.
6. Require the workflow to verify the npm version and SLSA provenance attestation before calling the
   release complete.

Published package versions and public tags are immutable release evidence. Do not rewrite an existing
tag or imply that an older package gained provenance retroactively.
