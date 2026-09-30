/**
 * Secret redaction (PRD §5: "Redact actual secret values in all output — show
 * type + location + redacted preview only").
 *
 * The raw secret value is NEVER returned to the agent. We keep only:
 *  - a redacted preview (a few leading chars + […redacted]),
 *  - the SHA256 of the value (a hash, safe) for cross-engine dedup (§4.4).
 */

import { sha256Hex } from "./util/hash.js";

/**
 * Modern Supabase elevated API key: a 22-character URL-safe body followed by an
 * underscore and an 8-character checksum. Explicit URL-safe boundaries avoid matching
 * prefixes embedded in a longer token. This exact detector is shared by the native
 * analyzers and redactor so detector ⊆ redactor.
 */
export const SUPABASE_SECRET_KEY_RE =
  /(?<![A-Za-z0-9_-])sb_secret_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}(?![A-Za-z0-9_-])/g;

export function isSupabaseSecretKey(value: string): boolean {
  SUPABASE_SECRET_KEY_RE.lastIndex = 0;
  return SUPABASE_SECRET_KEY_RE.test(value);
}

/** Known secret token patterns (provider-recognizable prefixes + shapes). */
export const SECRET_PATTERNS: Array<{ name: string; re: RegExp; live?: boolean }> = [
  { name: "Supabase secret API key", re: SUPABASE_SECRET_KEY_RE, live: true },
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
    // These regexes are global and shared. Reset state so repeated fields are all scrubbed;
    // otherwise a prior replacement can leave lastIndex past the start of the next string.
    p.re.lastIndex = 0;
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

// Credential-named keys: `dbPassword`, `DB_PASSWORD`, `headers["x-api-key"]`, `client_secret`, …
// Bounded and anchored at an identifier boundary so long identifier/hex runs stay linear-time.
const CREDENTIAL_NAME = String.raw`(?<![A-Za-z0-9_$.-])[A-Za-z0-9_$.-]{0,256}?(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|auth(?:orization)?|bearer)[A-Za-z0-9_-]{0,64}`;
// Quoted value: only the same quote character closes it, and escaped characters stay inside.
const QUOTED_CREDENTIAL_RE = new RegExp(String.raw`(${CREDENTIAL_NAME}["'\]]*\s*[:=]\s*)(["'` + "`" + String.raw`])((?:\\.|(?!\2)[^\\\r\n]){4,4096}?)\2`, "gi");
// Unquoted value (.env, YAML, INI).
const UNQUOTED_CREDENTIAL_RE = new RegExp(String.raw`(${CREDENTIAL_NAME}\s*[:=]\s*)(?![\s"'` + "`" + String.raw`])([^\s,;"'` + "`" + String.raw`(){}\[\]]{6,4096})(?![\w(])`, "gi");
const URL_CREDENTIAL_RE = /\b([a-z][a-z0-9+.-]{0,63}:\/\/[^\s:@/"'`]{1,1024}:)([^\s@/"'`]{1,1024})(@)/gi;
// `Authorization: Bearer <token>` and similar scheme-prefixed credentials.
const AUTH_SCHEME_RE = /\b(Bearer|Basic|Token|Digest)(\s+)([A-Za-z0-9._~+/=-]{8,4096})/g;
const TOKEN_RE = /[A-Za-z0-9+/_=-]{20,}/g;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SRI_RE = /^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/;
const COMMIT_SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) entropy -= (count / value.length) * Math.log2(count / value.length);
  return entropy;
}

/**
 * An unquoted value that is a reference or literal rather than a secret: `userPassword`,
 * `process.env.X`, `null`. Env-style keys (no lowercase letters, e.g. `DB_PASSWORD=`) always hold
 * literal values, so their values are never treated as references.
 */
function isReference(value: string, key: string): boolean {
  if (!/[a-z]/.test(key)) return /^(?:true|false|null)$/i.test(value);
  if (/^(?:Bearer|Basic|Token|Digest)$/.test(value)) return true;
  return /^[A-Za-z_$][\w$]*(?:\.[\w$]+)+$/.test(value) ||
    /^(?:true|false|null|undefined|none|nil)$/i.test(value) ||
    /^[a-z_$][A-Za-z_$]*$/.test(value);
}

/**
 * A value after Bearer/Basic/Token/Digest is a credential unless it reads as a plain lowercase word
 * ("Token revocation", "Basic middleware"). Basic values are base64, whose length is a multiple of 4.
 */
function looksLikeSchemeCredential(scheme: string, token: string): boolean {
  if (scheme === "Basic" && token.length % 4 === 0) return true;
  return /[0-9]/.test(token) || token.length >= 20 || /[._~+/=-]/.test(token) || /[A-Z]/.test(token.slice(1));
}

function masked(length: number): string {
  return `[redacted, ${length} chars]`;
}

/**
 * Value-agnostic scrub for ANY snippet or message surfaced in scan output. Finding context windows
 * can include neighbouring or truncated secrets that no known pattern recognizes, so this also masks
 * URL credentials, values assigned to credential-named keys (quoted or unquoted), and long
 * high-entropy tokens that mix letters and digits. UUIDs, SRI hashes, pinned commit SHAs,
 * template interpolations, and variable/member references are kept so the context stays useful.
 */
export function scrubCredentialContext(text: string): string {
  if (!text) return text;
  let out = redactSnippet(text).replace(URL_CREDENTIAL_RE, (_match, prefix: string, password: string, at: string) =>
    `${prefix}${masked(password.length)}${at}`);
  out = out.replace(AUTH_SCHEME_RE, (match, scheme: string, space: string, token: string) =>
    token.includes("[redacted") || !looksLikeSchemeCredential(scheme, token) ? match : `${scheme}${space}${masked(token.length)}`);
  out = out.replace(QUOTED_CREDENTIAL_RE, (match, prefix: string, quote: string, value: string) =>
    value.includes("[redacted") || value.includes("${") ? match : `${prefix}${quote}${masked(value.length)}${quote}`);
  out = out.replace(UNQUOTED_CREDENTIAL_RE, (match, prefix: string, value: string) =>
    value.includes("[redacted") || isReference(value, prefix.replace(/["'\]\s:=]+$/, "")) ? match : `${prefix}${masked(value.length)}`);
  return out.replace(TOKEN_RE, (token, offset: number, whole: string) => {
    if (UUID_RE.test(token) || SRI_RE.test(token)) return token;
    if (whole[offset - 1] === "@" && COMMIT_SHA_RE.test(token)) return token;
    return /[0-9]/.test(token) && /[A-Za-z]/.test(token) && shannonEntropy(token) >= 3.5 ? masked(token.length) : token;
  });
}

export function hashSecret(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}
