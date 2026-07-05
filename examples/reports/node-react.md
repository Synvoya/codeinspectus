# Example report — Node/React app

> **This is an illustrative example/demo report, not a real audit.** The findings,
> paths, and values below are synthetic and exist only to show the *shape* of
> CodeInspectus output. Run `codeinspectus_scan` on your own repo for real results.
> Secret values are always redacted in real output.

**Target:** `example-app/` (synthetic) · **Profile:** Node/Express API + React SPA
**Scan:** local · zero network egress at scan time

## Summary

| Severity | Count |
|----------|-------|
| High     | 2 |
| Medium   | 1 |
| Low      | 1 |

## Findings (CWE-keyed)

### 1. Untrusted value rendered as raw HTML — **high**
- **Rule:** `ci-ai-llm-output-dangerous-html` · **CWE-79** · confidence: medium
- **Where:** `src/components/Bio.jsx:27` — a component prop rendered via React's raw inner-HTML prop
- **What:** User-supplied `bio` text is rendered as raw HTML without sanitization — an XSS sink.
- **Fix:** Sanitize with `DOMPurify.sanitize(...)` before rendering, or render as plain text.

### 2. Server-side request to a user-controlled URL — **high**
- **Rule:** `security-baseline/ssrf-user-url` · **CWE-918** · confidence: medium
- **Where:** `server/routes/proxy.js:14` — `fetch(req.query.url)`
- **What:** A request parameter is passed directly into a server-side `fetch()` — SSRF: an attacker
  can reach internal services or cloud metadata endpoints.
- **Fix:** Allow-list destinations; reject private/link-local address ranges; never fetch raw user input.

### 3. Hard-coded credential in source — **medium**
- **Rule:** Gitleaks · **CWE-798** · confidence: high
- **Where:** `server/db.js:3` — `const dbPassword = "<redacted>"`
- **What:** A database password is committed in source. Secret value is redacted in output.
- **Fix:** Move to an environment variable / secret manager; rotate the exposed credential.

### 4. Vulnerable dependency — **low**
- **Rule:** Trivy (SCA) · **CVE-EXAMPLE-0000** · confidence: high
- **Where:** `package-lock.json` — `example-lib@1.2.3`
- **What:** A transitive dependency has a known advisory with a fixed version available.
- **Fix:** Upgrade to the patched release; re-run the scan to confirm resolution.

## Compliance (code-visible subset — not certification)

These findings touch code-visible controls under OWASP Top 10 (2021) A03/A06/A10 and map to
related CWE→control entries for SOC 2 and ISO/IEC 27001:2022. CodeInspectus reports
**code-level control coverage only** — never a "% compliant" verdict.
See [`docs/COMPLIANCE-RATIONALE.md`](../../docs/COMPLIANCE-RATIONALE.md).

## Next step

Apply fixes, then run `codeinspectus_rescan` to diff against this scan
(resolved / remaining / introduced).
