# secret-rls-corpus — §6.1 / §6.2 false-positive regression fixtures (CG-18)

Locks the four dogfood-confirmed FP classes (see CG-17). Verify by scanning this dir:
`npx tsx scripts/dev-scan.ts fixtures/secret-rls-corpus` (full) and
`npx tsx scripts/dev-scan.ts fixtures/secret-rls-corpus ai` (AI-only, no cross-engine dedup).
NOT part of the eval suite (eval scans only `fixtures/vulnerable-app`), so it never changes the
17/17 count. All secrets here are INTENTIONAL fakes (allowlisted in `/.gitleaks.toml`).

## TP — must fire
- `tp/client-hardcoded-service-role.tsx` → **ci-ai-supabase-service-role-client (critical)**.
  A real (non-demo, iss=acme-prod) service_role JWT VALUE in a client component. (In a full scan
  this dedups with gitleaks/trivy under a `jwt` label, but the AI rule fires — see the AI-only scan.)
- `tp/public-env-usage.ts` → **ci-ai-public-env-secret (high)**. `import.meta.env.VITE_STRIPE_SECRET`.
- `tp/supabase/migrations/0001_missing_rls.sql` → **ci-ai-rls-missing (high)** on `profiles`.

## FP — must NOT fire (CodeInspectus rules)
- `fp/app/api/admin/route.ts` — Next.js server route reading `process.env.SUPABASE_SERVICE_ROLE_KEY`
  (correct server use). Fix 1: server context (`app/api/`, `route.ts`) excluded from client checks.
- `fp/src/service-role-in-error-string.ts` — the token in an error string. Fix 1: we match the JWT
  VALUE, not the bare token.
- `fp/src/supabase-demo-local-key.ts` — the PUBLIC Supabase local-dev demo key (iss=supabase-demo).
  Fix 2: allowlisted in gitleaks (global, covers the default `jwt` rule) AND skipped by both AI
  checks (#1 hardcoded-secret, #3 service_role). **Known residual: trivy's built-in `jwt-token`
  secret rule still flags it** — that is a third-party engine; suppressing it needs a trivy
  secret-config allowlist (out of scope here; flagged for follow-up).
- `fp/src/public-env-in-error-string.ts` — a public-prefixed env NAME inside a help string. Fix 3:
  public-env requires a real env ACCESS (`process.env.`/`import.meta.env.`/`env.`), not a mention.
- `fp/test/migrations/0001_test_schema.sql` — a public table without RLS, in a `/test/` path. Fix 4:
  rls-missing skips test/example fixture paths (and platform-managed system schemas like `auth.`).
