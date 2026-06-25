# CodeInspectus fixtures

Test corpus of planted vulnerabilities (true positives) plus safe equivalents
(false-positive guards). This is the regression suite for the weekly intake
(PRD §9, §13): every detection is gated on precision against these fixtures.

## `vulnerable-app/` — planted true positives

| # | Issue | File | Detector | CWE |
|---|-------|------|----------|-----|
| 1 | Hard-coded Stripe **live** secret in client-reachable source | `src/config.ts` | `ci-ai-client-hardcoded-secret` + Gitleaks | CWE-798 / CWE-312 |
| 2a | RLS policy `USING (true)` (CVE-2025-48757 class) | `supabase/migrations/0001_init.sql` | `ci-ai-rls-using-true` | CWE-863 |
| 2b | Public table created without RLS | same | `ci-ai-rls-missing` | CWE-862 |
| 3 | SQL injection via string-built query | `src/db.ts` | Opengrep `ci-baseline-sql-injection-string-build` | CWE-89 |
| 4 | Outdated vulnerable dependency (lodash 4.17.4, minimist 1.2.0) | `package-lock.json` | Trivy (SCA) | CWE-1321/CWE-400 etc. |
| 5 | Prompt-injection sink + tool access | `src/llm.ts` | `ci-ai-prompt-injection-sink` | CWE-1426 |
| + | Secret behind client-exposed env prefix | `src/components/PaymentForm.tsx` | `ci-ai-public-env-secret` | CWE-798 |

## Safe equivalents — must NOT be flagged (precision)

- `src/db.ts` `safeGetUserById` — parameterized query.
- `0001_init.sql` `public.accounts` — RLS enabled with `auth.uid()` policies for all operations.
- `PaymentForm.tsx` `publishable()` — a publishable (non-secret) key behind a public prefix.

Engines 3 and 4 require the bundled binaries + Trivy DB (`codeinspectus install-engines`).
Detectors 1, 2, 5, + are pure-TypeScript and run with no external binary.
