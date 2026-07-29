# Reproducible V1.5 scan → fix → rescan case study

This is a scanner-derived case study from the published npm package
`codeinspectus@1.5.0`, recorded on 29 July 2026. It scans the public
[`Textualize/rich`](https://github.com/Textualize/rich) repository at immutable commit
[`6d30ad0f30028210124c149811cbbe2b183711f9`](https://github.com/Textualize/rich/tree/6d30ad0f30028210124c149811cbbe2b183711f9),
applies one local fix inside a temporary clone, and rescans the same path with the
original scan ID.

The case deliberately uses only CodeInspectus's first-party `ai` scanner class. That
isolates one stable native detector from external engine and vulnerability-database
drift. It is evidence for this exact scan → fix → rescan behavior, not a complete
security assessment of Rich.

## Reproduce it

Prerequisites: Node.js 22 or newer, `git`, and `npx`.

```bash
git clone https://github.com/Synvoya/codeinspectus.git
cd codeinspectus
node scripts/reproduce-v1.5-case-study.mjs
```

The script:

1. clones Rich and checks out the exact commit above;
2. launches `npx -y codeinspectus@1.5.0` over MCP stdio;
3. confirms the MCP handshake reports server version `1.5.0`;
4. scans the clone with `scanners: ["ai"]`;
5. applies the documented intermediate-environment-variable remediation;
6. calls `codeinspectus_rescan` with the baseline `scan_id`; and
7. fails unless the target finding moves to `resolved` with no remaining,
   introduced, or `not_rechecked` copy.

Cloning the repository and resolving the npm package can use the network. The two
CodeInspectus scan calls themselves run locally without scan-time network access. Pass
`--keep` to retain the temporary clone and inspect the patch after the assertions pass.

## Baseline result

| Field | Recorded value |
| --- | --- |
| Package requested | `codeinspectus@1.5.0` |
| MCP server version | `1.5.0` |
| Target commit | `6d30ad0f30028210124c149811cbbe2b183711f9` |
| Scanner scope | `ai` only |
| GitHub Actions pack | `ran`; 1/1 analyzer, 2/2 rules |
| Total findings | 1 |
| Finding | `ci-github-actions-untrusted-expression-command` |
| Severity / confidence | high / high |
| CWE / OWASP | CWE-78, CWE-94 / A03:2021 |
| Location | `.github/workflows/newissue.yml:17` |

The workflow directly interpolated attacker-controlled issue-title text into a shell
script:

```yaml
- name: Run Suggest
  run: faqtory suggest "${{ github.event.issue.title }}" > suggest.md
```

GitHub documents `github.event.issue.title` as potentially untrusted input and recommends
using an intermediate environment variable for inline scripts. See
[Script injections](https://docs.github.com/en/actions/concepts/security/script-injections)
and the [secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use#use-an-intermediate-environment-variable).

## Applied fix

The case-study script changes only the temporary clone:

```diff
 - name: Run Suggest
-  run: faqtory suggest "${{ github.event.issue.title }}" > suggest.md
+  env:
+    ISSUE_TITLE: ${{ github.event.issue.title }}
+  run: faqtory suggest "$ISSUE_TITLE" > suggest.md
```

The GitHub expression is now evaluated into data passed through `env`; it is no longer
substituted into the generated shell script. The shell variable remains quoted.

## Rescan result

| Bucket | Count |
| --- | ---: |
| Resolved | 1 |
| Remaining | 0 |
| Introduced | 0 |
| Not rechecked | 0 |
| Partial | `false` |

The sole resolved rule ID was
`ci-github-actions-untrusted-expression-command`. The reproduction script asserts these
results from structured MCP output; it does not infer success from process exit status or
from a hand-written expected report.

## Scope and limitations

- This proves one bounded, static GitHub Actions source pattern at one pinned commit.
- It does not execute the workflow, prove exploitability, inspect deployed repository
  settings, or certify the repository as secure.
- `scanners: ["ai"]` excludes Opengrep, Gitleaks, Trivy, SCA, IaC, license, and SBOM
  coverage. Use a normal full scan for repository review.
- The upstream branch may change; the immutable commit keeps this recorded case stable.
