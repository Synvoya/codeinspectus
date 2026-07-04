# Good first issue — detect authorization decisions that trust `user_metadata`

**Status:** open · **Type:** new detection rule · **Difficulty:** medium (a great first rule)
**Proposed rule id:** `ci-ai-client-metadata-authz` (new, additive — do not reuse an existing id)
**Area:** `src/ai-checks/**` + a fixture in `fixtures/` + a vitest lock

This is the **first community-intake detection** for CodeInspectus. It is fully specced here so a
new contributor can pick it up end-to-end. Read [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
first — especially the **fixture/precision gate** and the **rule-id invariants**.

> **Shipped (CG-50).** This rule now ships as `ci-ai-client-metadata-authz` (severity **high**,
> confidence **medium**, **CWE-639** primary + CWE-284/CWE-863, OWASP A01:2021). Inline **and**
> split-variable/destructured (intrafile taint) both landed. Corpus + vitest lock live at
> `fixtures/metadata-authz-corpus/` + `src/ai-checks/metadata-authz.test.ts`. This doc is kept as
> the design record; the open follow-ups are the V2 extensions called out below (cross-file taint,
> whole-object metadata alias).

---

## The footgun

AI coding agents very frequently emit Supabase authorization checks like this:

```ts
// VULNERABLE — trusts client-writable metadata for an authorization decision
if (user.user_metadata.role === 'admin') {
  // admin-only action
}
```

`user_metadata` (a.k.a. `raw_user_meta_data` in the database) is **writable by the signed-in user
themselves** — Supabase exposes it on the `PUT /auth/v1/user` endpoint and via
`supabase.auth.updateUser({ data: { ... } })`. So **any** authenticated user can set
`user_metadata.role = 'admin'` on their own account and walk straight through the check above.

The correct field is **`app_metadata`** (`raw_app_meta_data`), which is **server-only** — it
cannot be changed by the client, only by the service role / admin API:

```ts
// CORRECT — app_metadata is server-controlled
if (user.app_metadata.role === 'admin') { /* … */ }
```

### Why it matters
This is a **privilege-escalation** bug (CWE-862 Missing Authorization / CWE-863 Incorrect
Authorization / CWE-284). It is common in AI-generated code and — per the discussion that
prompted this issue — most people don't know `user_metadata` is self-writable. A precise
detector here is high-value and squarely in the CodeInspectus moat (AI-code footguns the generic
engines miss). It is **not** caught today (verified — see the recon note below).

> **Related, already covered (don't duplicate):** a Supabase **`service_role` key value** in
> client-reachable code fires `ci-ai-supabase-service-role-client` (**critical**), and a
> `service_role` key behind a **client-exposed env prefix** (`NEXT_PUBLIC_…`) fires
> `ci-ai-public-env-secret` (**high**). A *bare* non-prefixed `process.env.SUPABASE_SERVICE_ROLE_KEY`
> reference is intentionally **not** flagged (non-prefixed env vars aren't inlined into the
> browser bundle, so there's no leak). This issue is only about the `user_metadata` **authz**
> pattern.

---

## The honest target (and why it's narrow)

Flag **`user_metadata` / `raw_user_meta_data` feeding an authorization decision** — a comparison
that gates a privileged branch or action. **Do NOT flag a plain read** (a display name or avatar
is the overwhelmingly common, legitimate use). A naive "any `user_metadata` access" rule false-
positives heavily and would get the scanner muted — precision is the whole game.

### Discriminators the rule can rely on
1. **Source field:** `user_metadata` **or** `raw_user_meta_data` — and crucially **NOT**
   `app_metadata` / `raw_app_meta_data` (the correct, server-only field is the clean negative).
2. **A role/permission-ish key:** `role`, `roles`, `is_admin`, `isAdmin`, `admin`, `permission`,
   `permissions`, `claims`, `is_staff`, `is_superuser`. **Shipped decision:** `tier` / `plan` are
   NOT in this auto-fire set — they are entitlement fields (feature gates). They fire only via the
   privileged-literal arm below, so the common `plan === 'pro'` feature gate stays silent.
3. **A comparison / guard context:** inside an `if (...)`, a ternary, or a `=== / !== / .includes(...)`
   — i.e. it gates control flow, not just renders a value. **Shipped arm B:** ANY field compared to
   a *privileged literal* (`admin`, `superadmin`, `owner`, `root`, `staff`, …) fires regardless of
   field name, catching an authz check keyed off an arbitrary field. (`&&`/`||` are deliberately NOT
   guard signals — they false-positive on default-value expressions like `role || 'guest'`.)

### What the rule **cannot** know (so it must under-claim)
Static analysis can see "a client-writable field is being compared in a guard." It **cannot**
reliably tell whether the gated branch is a real **security boundary** (`deleteAllUsers()`) vs.
something cosmetic (an admin badge) or a **client-side feature gate** (`plan === 'pro'` to show
UI). So:

- Ship the finding at **`confidence: medium`**, severity **high** (a privilege-escalation bypass) —
  the honest hedge lives in the wording, not a dropped severity. **Never critical** (static analysis
  can't prove the gated branch is a real boundary).
- Use **confirm wording**, following the §6.3 "scope honestly" discipline already used for
  prompt-injection and the inverted-auth heuristic — the shipped message ends
  *"Verify whether this check protects a real boundary."*
- **Shipped CWEs:** `CWE-639` (Authorization Bypass Through User-Controlled Key) primary — the most
  precise fit, since the authz check EXISTS but trusts a user-controlled key — plus `CWE-284` /
  `CWE-863`; OWASP `A01:2021`.

---

## Detectability — scope it honestly

- **Inline form** (`if (user.user_metadata.role === 'admin')`): reliably matchable with a
  regex/metavariable pattern using the three discriminators. Start here.
- **Split-variable form** (`const role = user.user_metadata.role; … if (role === 'admin')`) and the
  **destructured form** (`const { role } = user.user_metadata; …`): **SHIPPED** via a lightweight
  intrafile taint pass (a metadata field read seeds a tainted var carrying its origin field; a later
  comparison / `.includes()` / `if()` on that var fires). Passed the frozen FP fixtures clean, so it
  was NOT degraded to inline-only.
- **Cross-file form** (role read in one module, checked in another): **out of scope for v1** (no
  cross-file taint) — a documented false-negative, not silently implied as covered.
- **Whole-object alias** (`const m = user.user_metadata; if (m.role === 'admin')`): **documented
  false-negative for v1** (the taint pass tracks per-field reads/destructures, not a whole-object
  alias). A good V2 follow-up.

---

## The corpus gate (required before merge)

Per CONTRIBUTING, a rule merges **only** after passing a precision corpus with **both**
directions. For this rule, the corpus must include at least these five cases:

| # | Case | Fixture shape | Rule must… |
|---|------|---------------|-----------|
| 1 | **TP — inline** | `if (user.user_metadata.role === 'admin') { …privileged… }` | **fire** (medium) |
| 2 | **TP — split variable** | `const r = user.user_metadata.role; if (r === 'admin') {…}` | **fire** (medium) — **shipped** via intrafile taint (+ a destructured variant) |
| 3 | **FP — feature gate** | `if (user.user_metadata.plan === 'pro') { showProUI() }` (cosmetic, no security boundary) | **stay silent** (or be explicitly out of the role-ish key set) |
| 4 | **FP — display read** | `const name = user.user_metadata.full_name` / `user.user_metadata.avatar_url` | **stay silent** |
| 5 | **TN — correct field** | `if (user.app_metadata.role === 'admin') {…}` | **stay silent** |

Wire these into the vitest corpus (mirror `src/ai-checks/client-secrets.test.ts` /
`supabase-rls.test.ts`, which run the analyzer over `fixtures/secret-rls-corpus` and assert both
TP-fires and FP-silent). The PR is judged on **precision against this corpus**, not on catching
more.

---

## Suggested steps

1. Open (or comment on) a **New detection proposal** issue if you want to refine scope first.
2. Add the analyzer logic under `src/ai-checks/` (new id `ci-ai-client-metadata-authz`), and
   register it in `detection-db/manifest.json` (additive — never rename a shipped id).
3. Add the 5-case corpus and the vitest lock.
4. Run `npm run build && npm test && npm run eval` — all green; eval stays **17/17**.
5. Open the PR with the TP/FP fixtures front and center and an honest note on the
   split-variable / cross-file scope.

Questions are welcome — under-claiming and asking beats a confident-but-wrong rule.
