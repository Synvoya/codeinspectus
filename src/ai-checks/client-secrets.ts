/**
 * §6.1 — Client-side secret / .env exposure (CodeInspectus AI-code check).
 * CWE-798, CWE-312; OWASP A07:2021, OWASP LLM02:2025.
 *
 * Scope discipline (§9): this is NOT a generic secret scanner (Gitleaks/Trivy
 * cover that). It flags the AI-code-specific angle the engines miss:
 *   - hard-coded secrets in CLIENT-REACHABLE source (ships to the browser),
 *   - secrets behind client-exposed env prefixes (VITE_/NEXT_PUBLIC_/REACT_APP_…),
 *   - secrets compiled into BUILT bundles (dist/build/.next),
 *   - Supabase service_role key value present client-side (bypasses RLS).
 */

import type { Finding, Severity } from "../types.js";
import { readFile } from "node:fs/promises";
import { BUILD_DIRS } from "../config.js";
import { collectFiles, collectOversizedBuildFiles, lineOf, lineText } from "./walk.js";
import { findSecret, hashSecret, SECRET_PATTERNS } from "../redact.js";
import { makeAiFinding } from "./finding.js";
import { remediationForCwe } from "../remediation.js";

// CG-23 B-1: §6.1's main value-decode pass caps file size for perf (skips files larger than this).
// CG-32: a separate BOUNDED scan re-covers build chunks ABOVE this cap (the cap is NOT lifted).
const CLIENT_SECRET_CAP_BYTES = 4 * 1024 * 1024;

const FRONTEND_EXTS = ["tsx", "jsx", "vue", "svelte", "astro", "html"];
const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "vue", "svelte", "astro", "html"];

const CLIENT_PATH_RE = /(^|\/)(src|app|pages|components|client|frontend|public|assets|routes|views|ui|web)(\/|$)/i;

// CG-18 dogfood FP: server-only contexts do NOT ship to the browser, so a secret /
// service_role reference there is correct server usage, not a client exposure. Exclude
// Next.js route handlers (app/api, pages/api, files named route.*), *.server.* modules,
// and "use server" files from the client-reachable checks.
const SERVER_PATH_RE =
  /(^|\/)(app|pages)\/api(\/|$)|(^|\/)route\.(ts|tsx|js|jsx|mjs|cjs)$|\.server\.(ts|tsx|js|jsx|mjs|cjs)$/i;

// CG-18: require a real env ACCESS (process.env.X / import.meta.env.X / env.X), not the
// bare name appearing inside a string or error message (dogfood FP). Group 1 = env name.
const PUBLIC_ENV_SECRET_RE =
  /(?:process\.env\.|import\.meta\.env\.|(?<![\w$.])env\.)((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_|PUBLIC_)[A-Z0-9_]*(?:SECRET|PRIVATE|API[_]?KEY|ACCESS[_]?KEY|TOKEN|PASSWORD|SERVICE[_]?ROLE)[A-Z0-9_]*)\b/g;

// CG-18: match the service_role key VALUE (a JWT whose payload role is service_role), NOT
// the bare token — the word "service_role" legitimately appears in library source, type
// definitions, comments, and error strings (dogfood FP). The public local-dev demo key
// (payload iss: supabase-demo) is published + identical everywhere, so it is skipped.
// Exported for the redaction-invariant test (G7): every token this detector matches
// MUST be redactable by redactSnippet's SECRET_PATTERNS (detector ⊆ redactor).
export const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

// Known PUBLIC-by-design keys: a client-exposed prefix on these is correct, not a
// leak. Firebase web API keys are explicitly public (Google docs: not a secret;
// access is gated by Firebase Security Rules, not key secrecy). Skip them so the
// public-env-secret check doesn't false-fire (CG-05 dogfooding fix).
const KNOWN_PUBLIC_KEY_RE = /FIREBASE[_]?API[_]?KEY/i;

// CG-25b B-11: `dangerouslyAllowBrowser: true` is the OpenAI/Anthropic-compatible SDK flag
// whose ONLY purpose is to permit running the client in the browser — which ships the
// provider API key to every visitor. The flag is unambiguous (near-zero FP), so we flag
// the literal set to `true` wherever it appears. `false` / a variable does not match.
const DANGEROUSLY_ALLOW_BROWSER_RE = /dangerouslyAllowBrowser\s*:\s*true\b/g;

function isBuilt(rel: string): boolean {
  return rel.split("/").some((seg) => BUILD_DIRS.has(seg));
}

function isClientReachable(rel: string, ext: string): boolean {
  if (isBuilt(rel)) return true;
  if (FRONTEND_EXTS.includes(ext)) return true;
  return CLIENT_PATH_RE.test(rel);
}

function isServerContext(rel: string, content: string): boolean {
  if (SERVER_PATH_RE.test(rel)) return true;
  // "use server" directive (server actions / server-only modules).
  if (/^\s*["']use server["']\s*;?\s*$/m.test(content)) return true;
  return false;
}

export async function runClientSecretsCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: true, maxBytes: CLIENT_SECRET_CAP_BYTES });

  for (const f of files) {
    const built = isBuilt(f.rel);
    // Built bundles ship to the browser (client); otherwise a server-only context is excluded.
    const server = !built && isServerContext(f.rel, f.content);
    const client = !server && isClientReachable(f.rel, f.ext);

    // 1. Hard-coded secret values in client-reachable source / built bundles.
    if (client) {
      const seen = new Set<string>();
      for (const pat of SECRET_SCAN(f.content)) {
        const key = `${pat.line}:${pat.value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (isSupabaseDemoJwt(pat.value)) continue; // public Supabase local-dev demo key (CG-18)
        // CG-31 (2A): a JWT whose TOP-LEVEL role is anon/authenticated/public is a Supabase
        // public key, shipped to the browser by design — suppress it here. A service_role key,
        // or any JWT we cannot cleanly decode / has no public role, KEEPS firing (fail-open:
        // never suppress a possible real secret on ambiguity). The dedicated service_role arm
        // below still flags real service_role keys.
        if (pat.typeName === "JSON Web Token" && isPublicRoleJwt(pat.value)) continue;
        // CG-31 (2B): a Google apiKey (AIza) inside a Firebase web-config context is public.
        if (pat.typeName === "Google API key" && isFirebaseConfigContext(f.content, pat.value)) continue;
        findings.push(
          makeSecretValueFinding({
            file: f.rel,
            typeName: pat.typeName,
            line: pat.line,
            snippet: lineText(f.content, pat.line),
            value: pat.value,
            built,
            live: pat.live,
          }),
        );
      }
    }

    // 2. Secret behind a client-exposed env prefix (deliberately browser-shipped).
    for (const m of f.content.matchAll(PUBLIC_ENV_SECRET_RE)) {
      const envName = m[1] ?? m[0];
      // Public-by-design keys (e.g. Firebase web API key) behind a public prefix
      // are correct, not a leak — don't flag them.
      if (KNOWN_PUBLIC_KEY_RE.test(envName)) continue;
      const line = lineOf(f.content, m.index ?? 0);
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-public-env-secret",
          title: "Secret exposed via client-visible env prefix",
          severity: "high",
          cwe: ["CWE-798", "CWE-312"],
          owasp_web: ["A07:2021"],
          owasp_llm: ["LLM02:2025"],
          file: f.rel,
          startLine: line,
          snippet: lineText(f.content, line),
          message: `Env var '${envName}' uses a client-exposed prefix but names a secret — frameworks ship these to the browser. Move it to a server-only variable.`,
          remediation: {
            summary: "Rename to a server-only env var (no public prefix) and read it only in server code; rotate if it ever shipped.",
            steps: [
              "Remove the client-exposed prefix; use a server-only env var.",
              "Access the value only in server-side code (API route / server action / edge function).",
              "Rotate the secret if a build with this prefix was ever shipped.",
            ],
            references: ["CWE-798", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
          },
          confidence: "medium",
        }),
      );
    }

    // 2b. LLM SDK client constructed with dangerouslyAllowBrowser: true (B-11). The flag
    // exists only to allow browser use, which ships the provider key to clients. Flag the
    // literal set to true anywhere (near-zero FP); not gated on client-reachability.
    for (const m of f.content.matchAll(DANGEROUSLY_ALLOW_BROWSER_RE)) {
      const idx = m.index ?? 0;
      // Skip a match that sits in a `//` line comment (e.g. docs mentioning the flag).
      const before = f.content.slice(f.content.lastIndexOf("\n", idx) + 1, idx);
      if (before.includes("//")) continue;
      const line = lineOf(f.content, idx);
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-llm-key-browser-exposed",
          title: "LLM SDK allows browser use (dangerouslyAllowBrowser: true) — API key shipped to the browser",
          severity: "high",
          cwe: ["CWE-798", "CWE-312"],
          owasp_web: ["A07:2021"],
          owasp_llm: ["LLM02:2025"],
          file: f.rel,
          startLine: line,
          snippet: lineText(f.content, line),
          message:
            "An LLM SDK client is constructed with dangerouslyAllowBrowser: true. This flag exists only to permit running the client in the browser, which ships your provider API key to every visitor. Move all LLM calls to a server route/proxy and remove this flag.",
          remediation: {
            summary:
              "Never call the LLM provider directly from the browser. Remove dangerouslyAllowBrowser and route requests through a server endpoint that holds the key.",
            steps: [
              "Delete the dangerouslyAllowBrowser: true option.",
              "Create a server route / edge function that holds the API key and calls the provider.",
              "Have the browser call that server route instead of the provider directly.",
              "Rotate the key if a build carrying it ever shipped to clients.",
            ],
            references: ["CWE-798", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
          },
          confidence: "high",
        }),
      );
    }

    // 3. Supabase service_role key VALUE present in client-reachable code (bypasses RLS).
    if (client) {
      for (const hit of findServiceRoleJwts(f.content)) {
        findings.push(
          makeServiceRoleFinding({ file: f.rel, line: hit.line, snippet: lineText(f.content, hit.line), value: hit.value }),
        );
      }
    }
  }

  // CG-32: bounded, cap-INDEPENDENT scan of build chunks ABOVE the §6.1 size cap (the cap stays).
  findings.push(...(await scanOversizedBuildChunks(target)));

  return findings;
}

// ── §6.1 finding builders (one source of truth for the main pass + the CG-32 oversized scan) ──

/** A hard-coded secret VALUE in client-reachable source or a shipped bundle. Build output ⇒
 * critical (it ships); other client source ⇒ critical only when the value is a live-key shape. */
function makeSecretValueFinding(args: {
  file: string;
  typeName: string;
  line: number;
  snippet: string;
  value: string;
  built: boolean;
  live: boolean;
}): Finding {
  const { file, typeName, line, snippet, value, built, live } = args;
  const severity: Severity = built ? "critical" : live ? "critical" : "high";
  const where = built
    ? "compiled into a shipped bundle"
    : "in client-reachable source (ships to the browser)";
  return makeAiFinding({
    ruleId: built ? "ci-ai-secret-in-bundle" : "ci-ai-client-hardcoded-secret",
    title: built ? "Secret compiled into shipped bundle" : "Hard-coded secret in client-reachable code",
    severity,
    cwe: ["CWE-798", "CWE-312"],
    owasp_web: ["A07:2021"],
    owasp_llm: ["LLM02:2025"],
    file,
    startLine: line,
    snippet,
    message: `${typeName} ${where}. Anyone who loads the app can read this value.`,
    remediation: remediationForCwe(["CWE-798"]),
    confidence: "high",
    isSecret: true,
    secretValueHash: hashSecret(value),
  });
}

/** A Supabase service_role key value present in client-reachable code (bypasses RLS). */
function makeServiceRoleFinding(args: { file: string; line: number; snippet: string; value: string }): Finding {
  const { file, line, snippet, value } = args;
  return makeAiFinding({
    ruleId: "ci-ai-supabase-service-role-client",
    title: "Supabase service_role key referenced in client-reachable code",
    severity: "critical",
    cwe: ["CWE-798", "CWE-285"],
    owasp_web: ["A01:2021", "A07:2021"],
    owasp_llm: ["LLM02:2025"],
    file,
    startLine: line,
    snippet,
    message:
      "A Supabase service_role key value appears in client-reachable code. The service_role key bypasses Row Level Security; if it reaches the client, any user gains full admin access to your database. It must be server-side only.",
    remediation: {
      summary: "Never expose service_role to the client. Use the anon key on the client and the service_role key only in trusted server code.",
      steps: [
        "Replace client-side service_role usage with the anon/public key.",
        "Move any privileged operation behind a server endpoint or Edge Function that holds service_role.",
        "Rotate the service_role key immediately if it was ever shipped.",
      ],
      references: ["CWE-285", "https://supabase.com/docs/guides/api/api-keys"],
    },
    confidence: "high",
    isSecret: true,
    secretValueHash: hashSecret(value),
  });
}

// ── CG-32: bounded cap-independent build-chunk scan ───────────────────────────────────────────
// §6.1's main pass caps file size (CLIENT_SECRET_CAP_BYTES) for perf, so a structured secret inside
// a >4MB minified BUILD chunk was invisible: the main pass skips it (cap) and CG-31 routing drops
// the anon-ambiguous classes a generic engine might surface (jwt/gcp-api-key/…) — CG-31 Flag 4.
// This carve re-covers ONLY oversized build output: pattern-locate the §6.1-detectable VALUES, then
// reuse §6.1's EXACT public-key suppression so anon/authenticated/public JWTs, the supabase-demo key,
// pk_ publishable and Firebase apiKeys STAY SILENT (no anon flood). Bounded work — O(content) regex +
// O(1) decode per candidate — safe on a 10 MB+ chunk; the global 4MB cap is NOT lifted.

// Safety ceiling: read one oversized chunk at a time, but never a pathological multi-hundred-MB file
// into memory whole. 64 MB is ~16× the cap and far above any real build chunk (bundlers split well
// before this); a chunk beyond it is a named residual, not a silent gap in a realistic bundle.
const BOUNDED_SCAN_CEILING_BYTES = 64 * 1024 * 1024;
// A short window around a located secret — never the whole (minified, possibly multi-MB) line. The
// value-agnostic scrub on makeAiFinding then redacts the secret inside it (value never emitted raw).
const SNIPPET_PAD = 48;

function boundedSnippet(content: string, index: number, length: number): string {
  const start = Math.max(0, index - SNIPPET_PAD);
  const end = Math.min(content.length, index + length + SNIPPET_PAD);
  return content.slice(start, end);
}

/** Findings for ONE oversized build chunk: arm 1 (every recognizable secret value, with §6.1's
 * public-key suppression) + arm 3 (service_role). Build output ⇒ critical, shipped-to-browser. */
function boundedBundleSecretFindings(rel: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of content.matchAll(p.re)) {
      const value = m[0];
      const idx = m.index ?? 0;
      const key = `${idx}:${value}`;
      if (seen.has(key)) continue; // a value matched by two patterns (e.g. sk-ant) counts once
      seen.add(key);
      if (isSupabaseDemoJwt(value)) continue; // published local-dev demo key
      if (p.name === "JSON Web Token" && isPublicRoleJwt(value)) continue; // anon/authenticated/public
      if (p.name === "Google API key" && isFirebaseConfigContext(content, value)) continue; // Firebase web key
      findings.push(
        makeSecretValueFinding({
          file: rel,
          typeName: p.name,
          line: lineOf(content, idx),
          snippet: boundedSnippet(content, idx, value.length),
          value,
          built: true,
          live: Boolean(p.live),
        }),
      );
    }
  }
  for (const hit of findServiceRoleJwts(content)) {
    findings.push(
      makeServiceRoleFinding({
        file: rel,
        line: hit.line,
        snippet: boundedSnippet(content, content.indexOf(hit.value), hit.value.length),
        value: hit.value,
      }),
    );
  }
  return findings;
}

/** Run the bounded scan over every build chunk above the §6.1 cap (read one at a time). */
async function scanOversizedBuildChunks(target: string): Promise<Finding[]> {
  const oversized = await collectOversizedBuildFiles(target, {
    exts: CODE_EXTS,
    minBytes: CLIENT_SECRET_CAP_BYTES,
    maxBytes: BOUNDED_SCAN_CEILING_BYTES,
  });
  const findings: Finding[] = [];
  for (const file of oversized) {
    let content: string;
    try {
      content = await readFile(file.abs, "utf8");
    } catch {
      continue; // unreadable/binary — skip
    }
    findings.push(...boundedBundleSecretFindings(file.rel, content));
  }
  return findings;
}

interface SecretHit {
  value: string;
  typeName: string;
  live: boolean;
  line: number;
}

/** All recognizable secret occurrences across the content (per line). */
function SECRET_SCAN(content: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const s = findSecret(lines[i] ?? "");
    if (s) hits.push({ value: s.value, typeName: s.typeName, live: s.live, line: i + 1 });
  }
  return hits;
}

/** The public Supabase local-dev demo key (payload iss: supabase-demo) is published and
 * identical for every local install — not a real credential. Skip it everywhere (CG-18). */
function isSupabaseDemoJwt(value: string): boolean {
  if (!value.startsWith("eyJ")) return false;
  const seg = value.split(".")[1];
  if (!seg) return false;
  try {
    return /"iss"\s*:\s*"supabase-demo"/.test(Buffer.from(seg, "base64url").toString("utf8"));
  } catch {
    return false;
  }
}

/** Cleanly-parsed JWT payload object, or undefined. base64url decoding never throws on
 * garbage, so JSON.parse is the real gate — undefined means "couldn't decode" (CG-31 fail-open). */
function jwtPayload(value: string): Record<string, unknown> | undefined {
  const seg = value.split(".")[1];
  if (!seg) return undefined;
  try {
    const obj = JSON.parse(Buffer.from(seg, "base64url").toString("utf8")) as unknown;
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** TOP-LEVEL `role` claim only (a nested app_metadata.role is intentionally ignored — it FP'd
 * the old substring check, e.g. {app_metadata:{role:"service_role"},role:"anon"}). */
function jwtTopRole(value: string): string | undefined {
  const role = jwtPayload(value)?.role;
  return typeof role === "string" ? role : undefined;
}

const PUBLIC_JWT_ROLES = new Set(["anon", "authenticated", "public"]);
/** CG-31 (2A): a cleanly-decoded JWT whose TOP-LEVEL role is a known public Supabase role
 * (shipped to the browser by design). Garbled / role-less / unknown-role / service_role JWTs
 * are NOT public → caller keeps firing (fail-open: never suppress a possible real secret). */
function isPublicRoleJwt(value: string): boolean {
  const role = jwtTopRole(value);
  return role !== undefined && PUBLIC_JWT_ROLES.has(role);
}

/** TOP-LEVEL role === service_role. Falls back to a substring scan only when the payload can't
 * be parsed, so a truncated/minified real service_role key is still flagged (fail-open). */
function isServiceRoleJwt(value: string): boolean {
  const role = jwtTopRole(value);
  if (role !== undefined) return role === "service_role";
  const seg = value.split(".")[1] ?? "";
  try {
    return /"role"\s*:\s*"service_role"/.test(Buffer.from(seg, "base64url").toString("utf8"));
  } catch {
    return false;
  }
}

// A *.firebaseapp.com / *.firebaseio.com authDomain literal — the one firebase signal that
// survives minification (the domain string isn't renamed, unlike the `authDomain` key).
const FIREBASE_DOMAIN_RE = /[a-z0-9-]+\.(?:firebaseapp\.com|firebaseio\.com)/i;
/**
 * CG-31 (2B): a Google apiKey (AIza) is the PUBLIC Firebase web key iff it sits in a Firebase
 * config — a STRUCTURAL signal, not bare proximity: either a firebase domain literal near the
 * value, OR the value is the `apiKey` field of an object that also carries authDomain AND a
 * second firebase sibling. A bare AIza, an AIza on a non-apiKey field, or a real GCP key far
 * from any firebase block still fires (not over-suppressed).
 */
function isFirebaseConfigContext(content: string, value: string): boolean {
  const idx = content.indexOf(value);
  const W = 400;
  const win = idx < 0 ? content : content.slice(Math.max(0, idx - W), idx + value.length + W);
  if (FIREBASE_DOMAIN_RE.test(win)) return true;
  const isApiKeyField = /apiKey\s*[:=]\s*["'`]?$/i.test(content.slice(Math.max(0, idx - 40), idx));
  const siblings = /authDomain/i.test(win) && /(projectId|messagingSenderId|appId|storageBucket)/i.test(win);
  return isApiKeyField && siblings;
}

/**
 * Service_role JWTs (TOP-LEVEL payload role = service_role) present as VALUES; skips the public
 * local-dev demo key (iss: supabase-demo). Matching the value — not the bare token — avoids the
 * dogfood FP where "service_role" appears in library source / comments / strings (CG-18); keying
 * on the top-level role avoids the nested-app_metadata FP (CG-31).
 */
function findServiceRoleJwts(content: string): { value: string; line: number }[] {
  const hits: { value: string; line: number }[] = [];
  for (const m of content.matchAll(JWT_RE)) {
    if (!isServiceRoleJwt(m[0])) continue;
    if (isSupabaseDemoJwt(m[0])) continue; // public local-dev demo key
    hits.push({ value: m[0], line: lineOf(content, m.index ?? 0) });
  }
  return hits;
}
