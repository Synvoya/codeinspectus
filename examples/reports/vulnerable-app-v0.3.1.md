# Reproducible v0.3.1 fixture scan

This is a scanner-derived report from CodeInspectus v0.3.1 running against the
repository's intentionally vulnerable [`fixtures/vulnerable-app`](../../fixtures/vulnerable-app)
on 17 July 2026. It replaces illustrative reports whose findings could not be
reproduced from a committed fixture.

## Reproduce it

```bash
npm install
npm run build
npx tsx scripts/dev-scan.ts fixtures/vulnerable-app
```

The engine binaries must already be installed and verified. See the main README for
`install-engines` and `verify-engines`.

## Recorded environment

| Component | Version or value |
| --- | --- |
| CodeInspectus package | 0.3.1 |
| Opengrep | 1.23.0 |
| Gitleaks | 8.30.1 |
| Trivy | 0.71.2 |
| CodeInspectus AI checks | 1.0.0 |
| Trivy database | 2026-07-15T23:36:30.755301Z |

## Result

CodeInspectus normalized 21 raw engine results into 18 findings: **4 critical,
8 high, 5 medium, and 1 low**. The lower normalized count is expected because the
same hard-coded client secret was detected by Gitleaks, Trivy, and the CodeInspectus
AI checks, then deduplicated into one finding with all three engines retained as evidence.

| Severity | Rule | Location | Engine evidence |
| --- | --- | --- | --- |
| Critical | `CVE-2019-10744` | `package-lock.json:15` | Trivy |
| Critical | `CVE-2021-44906` | `package-lock.json:20` | Trivy |
| Critical | `ci-ai-client-hardcoded-secret` | `src/config.ts:5` | Gitleaks + Trivy + CodeInspectus AI |
| Critical | `ci-ai-rls-using-true` | `supabase/migrations/0001_init.sql:18` | CodeInspectus AI |
| High | `CVE-2018-16487` | `package-lock.json:15` | Trivy |
| High | `CVE-2020-8203` | `package-lock.json:15` | Trivy |
| High | `CVE-2021-23337` | `package-lock.json:15` | Trivy |
| High | `CVE-2026-4800` | `package-lock.json:15` | Trivy |
| High | `ci-ai-public-env-secret` | `src/components/PaymentForm.tsx:6` | CodeInspectus AI |
| High | `ci-baseline-sql-injection-string-build` | `src/db.ts:11` | Opengrep |
| High | `ci-ai-prompt-injection-sink` | `src/llm.ts:11` | CodeInspectus AI |
| High | `ci-ai-rls-missing` | `supabase/migrations/0001_init.sql:22` | CodeInspectus AI |
| Medium | `CVE-2019-1010266` | `package-lock.json:15` | Trivy |
| Medium | `CVE-2020-28500` | `package-lock.json:15` | Trivy |
| Medium | `CVE-2025-13465` | `package-lock.json:15` | Trivy |
| Medium | `CVE-2026-2950` | `package-lock.json:15` | Trivy |
| Medium | `CVE-2020-7598` | `package-lock.json:20` | Trivy |
| Low | `CVE-2018-3721` | `package-lock.json:15` | Trivy |

## What is stable and what can drift

The committed fixture, CodeInspectus rule IDs, file locations, and engine versions above
make this run auditable. CVE findings are database-dependent: a newer local Trivy database
may add, remove, or reclassify dependency findings. That is expected and should not be
hidden behind a permanently frozen marketing number.
