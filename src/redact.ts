/**
 * Secret redaction (PRD §5: "Redact actual secret values in all output — show
 * type + location + redacted preview only").
 *
 * The raw secret value is NEVER returned to the agent. We keep only:
 *  - a redacted preview (a few leading chars + […redacted]),
 *  - the SHA256 of the value (a hash, safe) for cross-engine dedup (§4.4).
 */

import { sha256Hex } from "./util/hash.js";

/** Known secret token patterns (provider-recognizable prefixes + shapes). */
export const SECRET_PATTERNS: Array<{ name: string; re: RegExp; live?: boolean }> = [
  { name: "Stripe live secret key", re: /\bsk_live_[A-Za-z0-9]{10,}\b/g, live: true },
  { name: "Stripe restricted live key", re: /\brk_live_[A-Za-z0-9]{10,}\b/g, live: true },
  { name: "Stripe test secret key", re: /\bsk_test_[A-Za-z0-9]{10,}\b/g },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, live: true },
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g, live: true },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, live: true },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, live: true },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, live: true },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, live: true },
  // Must cover everything the JWT DETECTOR (client-secrets.ts JWT_RE) can match, or a
  // detected service_role token leaks raw in the snippet (CG-23 A4-1). Kept a strict
  // superset of JWT_RE: {8,}-char segments and no \b anchors (the detector has neither).
  { name: "JSON Web Token", re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  // Span the WHOLE block BEGIN…END (CG-24 A3-2) — matching only the BEGIN marker left
  // the key body in the snippet. A truncated block with no END won't match here and
  // falls through to redactSecretText's value-agnostic drop.
  { name: "Generic private key block", re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, live: true },
];

export interface SecretMatch {
  value: string;
  typeName: string;
  live: boolean;
}

/** First recognizable secret in a string, if any. */
export function findSecret(text: string): SecretMatch | undefined {
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (m) return { value: m[0], typeName: p.name, live: Boolean(p.live) };
  }
  return undefined;
}

/** Redacted preview: leading chars + marker. Never returns the full value. */
export function secretPreview(value: string): string {
  const lead = value.slice(0, Math.min(6, Math.max(2, Math.floor(value.length / 6))));
  return `${lead}…[redacted, ${value.length} chars]`;
}

/** Replace any recognized secret values inside a snippet with their preview. */
export function redactSnippet(snippet: string): string {
  let out = snippet;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(p.re, (m) => secretPreview(m));
  }
  return out;
}

/**
 * Value-agnostic scrub for any free-text field surfaced on an is_secret finding
 * (snippet / message). First mask every KNOWN secret pattern in place — this preserves
 * surrounding prose plus a redacted preview when we can localize the value. If NOTHING
 * matched, the field may still carry a secret whose shape is not in the allowlist
 * (Gitleaks default rules, entropy hits) and whose position we cannot localize, so we
 * DROP the raw text entirely and return a generic marker rather than echo a possible
 * secret value (CG-24 A3-1 / A6-2). This must NOT depend on the allowlist matching.
 * Empty / whitespace-only input is returned unchanged.
 */
export function redactSecretText(text: string, typeHint?: string): string {
  if (!text || !text.trim()) return text;
  const masked = redactSnippet(text);
  if (masked !== text) return masked; // a known pattern was found and masked in place
  return typeHint ? `[redacted potential secret: ${typeHint}]` : "[redacted potential secret value]";
}

export function hashSecret(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}
