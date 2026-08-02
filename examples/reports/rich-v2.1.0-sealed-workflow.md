# Reproducible V2.1 scan → fix → rescan → sealed-evidence case study

This scanner-derived case study was recorded on 2 August 2026 from an exact
`codeinspectus@2.1.0` release-candidate tarball. It scans the public
[`Textualize/rich`](https://github.com/Textualize/rich) repository at immutable commit
[`6d30ad0f30028210124c149811cbbe2b183711f9`](https://github.com/Textualize/rich/tree/6d30ad0f30028210124c149811cbbe2b183711f9),
applies one local fix inside a temporary clone, rescans the same path with the original scan ID,
and creates and verifies sealed V2 bundles for both states.

The case uses only CodeInspectus's first-party `ai` scanner class to isolate stable native behavior
from external engine and vulnerability-database drift. It proves this exact workflow; it is not a
complete security assessment of Rich.

## Reproduce it

Prerequisites: Node.js 22 or newer, `git`, `npx`, and network access for the pinned clone and initial
npm package resolution.

```bash
git clone https://github.com/Synvoya/codeinspectus.git
cd codeinspectus
git checkout v2.1.0
node scripts/reproduce-v2.1-case-study.mjs
```

Before npm publication, a maintainer can verify the exact candidate tarball instead:

```bash
npm run build
npm pack --pack-destination /absolute/safe/temp-directory
CODEINSPECTUS_CASE_PACKAGE=/absolute/safe/temp-directory/codeinspectus-2.1.0.tgz \
  node scripts/reproduce-v2.1-case-study.mjs
```

The script fails unless all of these claims hold:

1. the MCP handshake reports `2.1.0`;
2. the pinned repository produces exactly one target finding at the expected workflow line;
3. the GitHub Actions pack reports 1/1 analyzer and 2/2 rule execution;
4. the documented intermediate-environment-variable fix passes `git diff --check`;
5. same-path rescan moves the target finding exclusively to `resolved` and is not partial; and
6. both persisted scan states create sealed bundles whose schemas, hashes, scan IDs, detection DB,
   and native-engine metadata verify through the installed V2.1 CLI.

The isolated package launch and repository clone may use the network. Both CodeInspectus scan calls
are local and zero-egress. Pass `--keep` to retain the temporary workspace and inspect the evidence.

## Recorded result

| Field | Recorded value |
| --- | --- |
| Package tested | exact `codeinspectus-2.1.0.tgz` release candidate |
| Packed artifact | 41 files; 396,269 bytes; SHA-1 `8b6020a82ba2146e78862046357337640a908502` |
| MCP server version | `2.1.0` |
| Target commit | `6d30ad0f30028210124c149811cbbe2b183711f9` |
| Scanner scope | `ai` only |
| GitHub Actions pack | `ran`; 1/1 analyzer, 2/2 rules |
| Baseline findings | 1 |
| Target finding | `ci-github-actions-untrusted-expression-command` |
| Severity / confidence | high / high |
| CWE / OWASP | CWE-78, CWE-94 / A03:2021 |
| Location | `.github/workflows/newissue.yml:17` |
| Rescan | 1 resolved; 0 remaining; 0 introduced; 0 not rechecked; `partial=false` |
| Sealed evidence | 2 bundles verified; 6 artifacts each |
| Bundle schema | `1.0.0` |
| Detection DB | `1.15.0` dated `2026-08-02` |
| Native engine | `codeinspectus-ai@5.15.0` |

The workflow directly interpolated attacker-controlled issue-title text into a shell script:

```yaml
- name: Run Suggest
  run: faqtory suggest "${{ github.event.issue.title }}" > suggest.md
```

The reproduction applies this patch only to its temporary clone:

```diff
 - name: Run Suggest
-  run: faqtory suggest "${{ github.event.issue.title }}" > suggest.md
+  env:
+    ISSUE_TITLE: ${{ github.event.issue.title }}
+  run: faqtory suggest "$ISSUE_TITLE" > suggest.md
```

GitHub recommends moving untrusted expression values into an intermediate environment variable for
inline scripts. See [Script injections](https://docs.github.com/en/actions/concepts/security/script-injections)
and the [secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use#use-an-intermediate-environment-variable).

## Scope and limitations

- The case does not execute the workflow, prove exploitability, inspect deployed repository
  settings, or certify the repository as secure.
- `scanners: ["ai"]` excludes Opengrep, Gitleaks, Trivy, SCA, IaC, license, and SBOM coverage.
  Use a normal full scan for broad repository review.
- Sealed-bundle verification proves the bundle schema, allowlisted paths, artifact hashes,
  redaction boundary, and embedded scan record at verification time. It is not a third-party
  signature or timestamp.
- The pre-publication run used an exact local tarball, not the npm registry. The same script defaults
  to `codeinspectus@2.1.0` after publication.
