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
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: "Generic private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, live: true },
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

export function hashSecret(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}
