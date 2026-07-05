# Example report — Next.js + Supabase SaaS app

> **This is an illustrative example/demo report, not a real audit.** The findings,
> paths, and values below are synthetic and exist only to show the *shape* of
> CodeInspectus output. Run `codeinspectus_scan` on your own repo for real results.
> Secret values are always redacted in real output.

**Target:** `example-saas/` (synthetic) · **Profile:** Next.js (App Router) + Supabase
**Scan:** local · zero network egress at scan time

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 2 |
| Medium   | 1 |

## Findings (CWE-keyed)

### 1. `service_role` key reachable from client code — **critical**
- **Rule:** `ci-ai-client-secret-exposure` · **CWE-798** · confidence: high
- **Where:** `lib/supabaseAdmin.ts:4`
- **What:** Supabase `service_role` key value present in a module imported by client
  components. This key bypasses Row Level Security.
- **Fix:** Move all `service_role` usage to server-only code (Route Handlers / Server
  Actions); never import it into a client bundle. Rotate the leaked key.

### 2. Authorization decision trusts client-writable `user_metadata` — **high**
- **Rule:** `ci-ai-client-metadata-authz` · **CWE-639** · confidence: medium
- **Where:** `middleware.ts:22` — `if (user.user_metadata.role === 'admin')`
- **What:** `user_metadata` is editable by the signed-in user via Supabase's
  `/auth/v1/user` endpoint, so anyone can self-assign `role: 'admin'`.
- **Fix:** Gate privileged logic on server-controlled `app_metadata.role` instead.

### 3. `service_role` key behind a client-exposed env prefix — **high**
- **Rule:** `ci-ai-client-secret-exposure` · **CWE-522** · confidence: high
- **Where:** `.env.local` — `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=<redacted>`
- **What:** The `NEXT_PUBLIC_` prefix inlines this value into the browser bundle.
- **Fix:** Remove the prefix; keep the service key server-side only.

### 4. Supabase RLS not enabled on a user-data table — **medium**
- **Rule:** `ci-ai-supabase-rls` · **CWE-284** · confidence: medium
- **Where:** `supabase/migrations/0002_profiles.sql:1`
- **What:** `profiles` table has no `enable row level security` — reads/writes are
  unrestricted with the anon key.
- **Fix:** `alter table profiles enable row level security;` and add explicit policies.

## Compliance (code-visible subset — not certification)

Findings above touch code-visible controls under OWASP Top 10 (2021) A01/A05/A07 and
map to related CWE→control entries for SOC 2 and ISO/IEC 27001:2022. CodeInspectus
reports **code-level control coverage only** — never a "% compliant" or pass/fail
verdict. See [`docs/COMPLIANCE-RATIONALE.md`](../../docs/COMPLIANCE-RATIONALE.md).

## Next step

Apply fixes, then run `codeinspectus_rescan` to diff against this scan
(resolved / remaining / introduced).
