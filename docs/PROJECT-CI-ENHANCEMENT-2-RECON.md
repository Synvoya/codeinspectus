# Project CI Enhancement 2 — runtime security-control recon

Status: **implemented in CodeInspectus 0.4.0; no missing-control vulnerability detector is shipped**.

## Decision

Repository absence is not evidence that a runtime control is absent. Cloudflare, Vercel,
nginx, an API gateway, Supabase, or another hosted layer may supply headers, CAPTCHA, and
rate limits. Enhancement 2 must model evidence before it adds findings.

Every evaluated control needs one of three states:

| State | Meaning | Vulnerability finding? |
|---|---|---|
| `verified_in_repository` | Recognized repository configuration passes the rule's narrow literal check; this is not runtime or complete policy proof. | No |
| `insecure_configuration_found` | Repository evidence contains an explicit unsafe literal configuration or behavior matched by the rule. | **Yes** |
| `not_verifiable_from_repository` | No authoritative repository evidence proves the runtime value. | No; metadata only, with no posture penalty |

This state is separate from `Finding`. The `security_control_evidence` scan field carries
the control id, state, evidence locations, recognized provider/layer, and a limitation note.
Only `insecure_configuration_found` enters the vulnerability list.

## Shipped implementation

Enhancement 2 ships four stable AI rule ids:

- `ci-ai-security-header-disabled`
- `ci-ai-unsafe-production-csp`
- `ci-ai-insecure-session-cookie`
- `ci-ai-supabase-captcha-token-missing`

The evidence resolver evaluates HSTS, X-Content-Type-Options, X-Frame-Options, CSP,
auth/session-cookie attributes, and the Supabase CAPTCHA-token integration. It recognizes
literal repository configuration in Next.js, Vercel, Express/Helmet, nginx, Cloudflare Pages
`_headers`, common JavaScript/TypeScript cookie APIs, and `supabase/config.toml`.
Test/fixture/example trees, `*.test.*`/`*.spec.*` files, and explicitly development-named
nginx configs are excluded from production-control evidence.

Next.js same-source duplicates use the documented last matching header value. Cross-provider,
dynamic, report-only, or otherwise unresolved conflicts remain `not_verifiable_from_repository`.
An explicit insecure route/auth/cookie path is not hidden by a separate safe path.
Evidence metadata is separate from findings and does not affect compliance/posture scoring.

## Candidate security-header findings

The first implementation batch detects only explicit insecure configurations:

- credentialed arbitrary-origin CORS (already shipped in Enhancement 1);
- a security header explicitly disabled or removed in a recognized repository-controlled
  serving layer;
- a clearly unsafe production CSP directive, initially high-signal cases such as a wildcard
  script source or `unsafe-eval` outside an explicit development-only branch;
- an auth/session cookie explicitly configured with `httpOnly: false`, `secure: false`, or
  `SameSite=None` without `Secure`.

Do **not** report missing CSP, HSTS, X-Frame-Options, frame-ancestors, or other headers merely
because they are absent from application source. Do not convert `not_verifiable_from_repository`
into a warning, low-severity vulnerability, failed control, or posture-score deduction.

The implementation recognizes literal configuration for Next.js, Vercel, Express/Helmet,
nginx, and Cloudflare Pages. It resolves documented Next.js same-source ordering; provider
precedence, nginx inheritance, and other conflicts that cannot be resolved from the modeled
syntax remain not verifiable.

## OWASP acceptance requirement

OWASP is a cross-cutting mapping and documentation requirement, not a detector named "OWASP
review".

- Every vulnerability finding has a primary CWE.
- Relevant OWASP Web and OWASP API category tags describe the exact detected failure pattern.
- Rule documentation states the source, sink/configuration, safe guards, and code-visible limits.
- Product language remains "code-visible coverage" and never says OWASP compliant, complete
  OWASP review, or certification.
- OWASP API tags remain finding context until a separately designed framework denominator and
  rationale exist; they are not silently added to the compliance score.

## CAPTCHA recon

Generic CAPTCHA absence is out of scope. Hosted bot protection is commonly invisible to the
repository and a generic rule would be noisy.

The shipped Supabase-specific rule fires only when both sides are repository-visible:

1. authoritative local Supabase configuration explicitly enables CAPTCHA for the relevant auth
   flow; and
2. a recognized `signUp`, `signInWithPassword`, `signInWithOtp`, `signInWithSSO`,
   `signInWithWeb3`, or `resetPasswordForEmail` call omits the required `captchaToken`
   option.

Safe fixtures include a supplied token, CAPTCHA disabled, a non-Supabase/hosted-unknown auth
flow, and hosted state that is not present locally. `supabase/config.toml` proves local or
self-hosted configuration, not the hosted Dashboard setting. When the evidence contract is not
met, the result is `not_verifiable_from_repository`, not a finding. When it is met, the finding
states that Supabase should reject the tokenless request; it does not claim CAPTCHA bypass.

## Rate limits and behavioral auth

Defer route-level rate-limit findings until CodeInspectus can resolve framework middleware,
route groups, gateway configuration, and provider-managed limits into effective state. The same
boundary applies to behavioral authorization: static patterns can flag explicit unsafe code but
cannot prove end-to-end runtime correctness.

## Implementation gates

1. Freeze per-framework TP, safe near-miss, conflicting-layer, and unknown-state fixtures.
2. Implement evidence-state resolution separately from vulnerability normalization.
3. Emit findings only for `insecure_configuration_found`.
4. Add stable ids, CWE/OWASP mappings, remediation, redaction, component provenance, and rescan
   continuity for every vulnerability rule.
5. Dogfood across real applications and require acceptable precision before public claims.
6. Update the manifest, rule provenance, README, and website only for shipped detectors; document
   `not_verifiable_from_repository` as a limitation, never as protection.

## Explicit non-claims

Enhancement 2 will not prove runtime headers, CAPTCHA deployment, gateway rate limits, legal
compliance, complete OWASP coverage, or behavioral authentication correctness unless the relevant
effective configuration is directly evidenced and modeled.
