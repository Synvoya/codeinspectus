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
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { BUILD_DIRS } from "../config.js";
import { collectFiles, collectOversizedBuildFiles, lineOf, lineText } from "./walk.js";
import {
  hashSecret,
  SECRET_PATTERNS,
  SUPABASE_SECRET_KEY_RE,
} from "../redact.js";
import { makeAiFinding } from "./finding.js";
import { remediationForCwe } from "../remediation.js";

// CG-23 B-1: §6.1's main value-decode pass caps file size for perf (skips files larger than this).
// CG-32: a separate BOUNDED scan re-covers build chunks ABOVE this cap (the cap is NOT lifted).
const CLIENT_SECRET_CAP_BYTES = 4 * 1024 * 1024;
const MAX_SECRET_LOCATIONS_PER_FILE = 1024;
const MAX_SECRET_NOTES = 24;

export interface ClientSecretsAnalysis {
  findings: Finding[];
  notes: string[];
}

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

// Known PUBLIC-by-design keys: a client-exposed prefix on these is correct, not a leak.
// 4.1 M9 (Ruling 8): a closed table. Each entry names a provider whose own documentation says the key is
// meant for client use; the pattern is matched against the env name without its public prefix, anchored at
// the end. Any doubt → left out (Segment's write key is left out: its name says WRITE).
const PUBLIC_SDK_KEYS: ReadonlyArray<{ provider: string; reason: string; re: RegExp }> = [
  { provider: "Firebase", reason: "web API keys identify the project; access is gated by Security Rules (CG-05)", re: /FIREBASE_?API_?KEY/i },
  { provider: "Google Maps Platform", reason: "Maps JavaScript/Places browser keys are used in the page and restricted by HTTP referrer", re: /(?:^|_)(?:GOOGLE_?MAPS?|GOOGLE_?PLACES|GMAPS?)(?:_(?:JS|JAVASCRIPT|BROWSER|WEB|EMBED))?_?API_?KEY$/i },
  { provider: "reCAPTCHA / hCaptcha / Turnstile", reason: "site keys are embedded in the page; the secret key is separate", re: /(?:^|_)(?:RECAPTCHA|HCAPTCHA|TURNSTILE|CAPTCHA)_?SITE_?(?:API_?)?KEY$/i },
  { provider: "Stripe", reason: "publishable keys (pk_) are for Stripe.js in the browser", re: /(?:^|_)STRIPE_?(?:PUBLISHABLE|PUBLIC)_?(?:API_?)?KEY$/i },
  { provider: "Mixpanel", reason: "the project token is sent by the browser SDK with every event", re: /(?:^|_)MIXPANEL_?(?:PROJECT_?)?TOKEN$/i },
  { provider: "PostHog", reason: "the project API key (phc_) is for the browser SDK; personal API keys are not matched", re: /(?:^|_)POSTHOG_?(?:PROJECT_?)?(?:API_?)?KEY$/i },
  { provider: "Amplitude", reason: "the project API key is used by the browser SDK; the secret key is separate", re: /(?:^|_)AMPLITUDE_?API_?KEY$/i },
  { provider: "Algolia", reason: "search-only API keys are meant for front-end search", re: /(?:^|_)ALGOLIA_?SEARCH(?:_?ONLY)?_?(?:API_?)?KEY$/i },
  { provider: "Mapbox", reason: "public access tokens (pk.) are for map clients; the name must say PUBLIC or a client platform (a bare MAPBOX_ACCESS_TOKEN may hold a secret sk. token)", re: /(?:^|_)MAPBOX_?(?:PUBLIC|WEB|IOS|ANDROID|GL|JS)_?(?:ACCESS_?)?TOKEN$/i },
  { provider: "RevenueCat", reason: "public app-specific SDK keys are for the mobile and web SDKs; the name must say PUBLIC or a platform (a bare REVENUECAT_API_KEY may be the secret key)", re: /(?:^|_)REVENUE_?CAT_?(?:IOS|APPLE|ANDROID|GOOGLE|AMAZON|WEB|STRIPE|PUBLIC)_?(?:SDK_?)?API_?KEY$/i },
];
/** A name that also says any of these is never treated as a public key (Ruling 8). */
const NEVER_PUBLIC_RE = /SECRET|PRIVATE|SERVICE_?ROLE|ADMIN|AUTH_?TOKEN|MANAGEMENT|WRITE|SERVER|MASTER|PERSONAL/i;
const PUBLIC_ENV_PREFIX_RE = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_|PUBLIC_)/;

export function isPublicSdkKeyName(envName: string): boolean {
  if (NEVER_PUBLIC_RE.test(envName)) return false;
  const name = envName.replace(PUBLIC_ENV_PREFIX_RE, "");
  return PUBLIC_SDK_KEYS.some((entry) => entry.re.test(name));
}

/**
 * 4.1 M9: PM2 `ecosystem.config.*` holds server process env; it never ships to a browser. Exempt only a file
 * outside build output, at the scan root or a package root (a `package.json` beside it), with PM2's shape
 * (`module.exports = { … apps: [ … ] }`, `export default { … apps: [ … ] }`); any other file is scanned.
 */
const SERVER_ONLY_CONFIG_RE = /(?:^|\/)ecosystem\.config\.(?:js|cjs|mjs|ts|json)$/;
const PM2_EXPORT_RE = /(?:\bmodule\.exports\s*=|\bexport\s+default)\s*\{/;
const PM2_APPS_RE = /(?:^|[{,\s])["']?apps["']?\s*:\s*\[/m;

async function isPm2EcosystemFile(target: string, rel: string, content: string, built: boolean): Promise<boolean> {
  if (built || !SERVER_ONLY_CONFIG_RE.test(rel)) return false;
  if (!PM2_EXPORT_RE.test(content) || !PM2_APPS_RE.test(content)) return false;
  const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "";
  if (dir === "") return true;
  try {
    return (await stat(join(target, ...dir.split("/"), "package.json"))).isFile();
  } catch {
    return false;
  }
}

const NUXT_CONFIG_RE = /(?:^|\/)nuxt\.config\.(?:js|cjs|mjs|ts|mts)$/;
/** The Nuxt runtimeConfig analysis runs only on configs up to this size; a larger file is scanned normally. */
const NUXT_ANALYSIS_MAX_BYTES = 256 * 1024;
/** Direct children of `runtimeConfig` that Nuxt exposes to the client. */
const NUXT_CLIENT_KEYS = new Set(["public", "app"]);

/**
 * One linear pass: blank comments and string contents (offsets preserved). A quoted object key
 * (`'public':`, `"app":`) keeps its identifier text so key lookup sees it. Returns undefined for an
 * unterminated string or comment.
 */
function maskCodeText(content: string): string | undefined {
  const out = content.split("");
  let i = 0;
  const n = content.length;
  while (i < n) {
    const ch = content[i]!;
    const next = content[i + 1];
    if (ch === "/" && next === "/") {
      while (i < n && content[i] !== "\n") out[i++] = " ";
      continue;
    }
    if (ch === "/" && next === "*") {
      const close = content.indexOf("*/", i + 2);
      if (close < 0) return undefined;
      for (let j = i; j < close + 2; j++) if (content[j] !== "\n") out[j] = " ";
      i = close + 2;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      const open = i;
      let j = i + 1;
      while (j < n && content[j] !== ch) {
        if (content[j] === "\\") j++;
        else if (ch !== "`" && content[j] === "\n") return undefined;
        j++;
      }
      if (j >= n) return undefined;
      const inner = content.slice(open + 1, j);
      let after = j + 1;
      while (after < n && (content[after] === " " || content[after] === "\t")) after++;
      const quotedKey = ch !== "`" && /^[A-Za-z_$][\w$]*$/.test(inner) && content[after] === ":";
      for (let k = open; k <= j; k++) {
        if (quotedKey && k > open && k < j) continue;
        if (content[k] !== "\n") out[k] = " ";
      }
      i = j + 1;
      continue;
    }
    i++;
  }
  return out.join("");
}

interface ObjectSpan { key: string; open: number; close: number; parent?: ObjectSpan }

/** The object literal key before `{` at `open` (`key: {`), read backwards over a bounded window. */
function keyBefore(masked: string, open: number, floor: number): string {
  let i = open - 1;
  while (i > floor && /\s/.test(masked[i]!)) i--;
  if (masked[i] !== ":") return "";
  i--;
  while (i > floor && /\s/.test(masked[i]!)) i--;
  const end = i + 1;
  while (i >= floor && /[\w$]/.test(masked[i]!)) i--;
  return masked.slice(i + 1, end);
}

/** All `{…}` spans in one linear pass with a stack; undefined at the first unbalanced brace. */
function objectSpans(masked: string): ObjectSpan[] | undefined {
  const spans: ObjectSpan[] = [];
  const stack: ObjectSpan[] = [];
  let lastBrace = 0;
  for (let i = 0; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === "{") {
      const span: ObjectSpan = { key: keyBefore(masked, i, lastBrace), open: i, close: -1, ...(stack.length ? { parent: stack.at(-1)! } : {}) };
      stack.push(span);
      lastBrace = i;
    } else if (ch === "}") {
      const span = stack.pop();
      if (!span) return undefined;
      span.close = i;
      spans.push(span);
      lastBrace = i;
    }
  }
  return stack.length ? undefined : spans;
}

/**
 * 4.1 M9: in a Nuxt config, a value assigned inside `runtimeConfig` but outside its client-exposed direct
 * children (`public`, `app`, quoted or not) is server-only, whatever the env name says. Large, malformed or
 * unbalanced configs get no exemption.
 */
function nuxtPrivateRuntimeConfigOffsets(content: string): (index: number) => boolean {
  if (content.length > NUXT_ANALYSIS_MAX_BYTES) return () => false;
  const masked = maskCodeText(content);
  const spans = masked === undefined ? undefined : objectSpans(masked);
  if (!spans) return () => false;
  const runtime = spans.filter((span) => span.key === "runtimeConfig");
  if (!runtime.length) return () => false;
  const exposed = spans.filter((span) => span.parent?.key === "runtimeConfig" && runtime.includes(span.parent) &&
    NUXT_CLIENT_KEYS.has(span.key));
  const inside = (index: number, span: ObjectSpan) => index > span.open && index < span.close;
  return (index) => runtime.some((span) => inside(index, span)) && !exposed.some((span) => inside(index, span));
}

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

export async function runClientSecretsAnalysis(target: string): Promise<ClientSecretsAnalysis> {
  const findings: Finding[] = [];
  const notes: string[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: true, maxBytes: CLIENT_SECRET_CAP_BYTES });

  for (const f of files) {
    const built = isBuilt(f.rel);
    // Built bundles ship to the browser (client); otherwise a server-only context is excluded.
    const server = !built && isServerContext(f.rel, f.content);
    const client = !server && isClientReachable(f.rel, f.ext);

    // 1. Hard-coded secret values in client-reachable source / built bundles.
    if (client) {
      const scanned = SECRET_SCAN(f.content);
      if (scanned.truncated) notes.push(secretCandidateLimitNote(f.rel, "provider-secret"));
      for (const pat of scanned.hits) {
        if (isSupabaseDemoJwt(pat.value)) continue; // public Supabase local-dev demo key (CG-18)
        // CG-31 (2A): a JWT whose TOP-LEVEL role is anon/authenticated/public is a Supabase
        // public key, shipped to the browser by design — suppress it here. A service_role key,
        // or any JWT we cannot cleanly decode / has no public role, KEEPS firing (fail-open:
        // never suppress a possible real secret on ambiguity). The dedicated service_role arm
        // below still flags real service_role keys.
        if (pat.typeName === "JSON Web Token" && isPublicRoleJwt(pat.value)) continue;
        // Dedicated findings own privileged Supabase formats. Emitting a generic finding
        // at the same location lets the final secret deduplicator hide the more actionable
        // rule/message/remediation.
        if (pat.typeName === "Supabase secret API key") continue;
        if (pat.typeName === "JSON Web Token" && isServiceRoleJwt(pat.value)) continue;
        // CG-31 (2B): a Google apiKey (AIza) inside a Firebase web-config context is public.
        if (pat.typeName === "Google API key" && isFirebaseConfigContext(f.content, pat.value)) continue;
        findings.push(
          makeSecretValueFinding({
            file: f.rel,
            typeName: pat.typeName,
            line: pat.line,
            snippet: boundedSnippet(f.content, pat.index, pat.value.length),
            value: pat.value,
            built,
            live: pat.live,
          }),
        );
      }
    }

    // 2. Secret behind a client-exposed env prefix (deliberately browser-shipped).
    // 4.1 M9: PM2 process env and Nuxt private runtimeConfig are server-only.
    const serverOnlyConfig = await isPm2EcosystemFile(target, f.rel, f.content, built);
    const nuxtPrivate = NUXT_CONFIG_RE.test(f.rel) ? nuxtPrivateRuntimeConfigOffsets(f.content) : () => false;
    for (const m of serverOnlyConfig ? [] : f.content.matchAll(PUBLIC_ENV_SECRET_RE)) {
      const envName = m[1] ?? m[0];
      // Public-by-design keys (the closed table above) behind a public prefix
      // are correct, not a leak — don't flag them.
      if (isPublicSdkKeyName(envName)) continue;
      if (nuxtPrivate(m.index ?? 0)) continue;
      const line = lineOf(f.content, m.index ?? 0);
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-public-env-secret",
          title: "Secret exposed via client-visible env prefix",
          severity: "low", // 4.1 M9 fresh-set gate: 3 hits, 0 true (Ruling 3)
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
          confidence: "low",
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
      const serviceRole = findServiceRoleJwts(f.content);
      if (serviceRole.truncated) notes.push(secretCandidateLimitNote(f.rel, "service-role JWT"));
      for (const hit of serviceRole.hits) {
        findings.push(
          makeServiceRoleFinding({
            file: f.rel,
            line: hit.line,
            snippet: boundedSnippet(f.content, hit.index, hit.value.length),
            value: hit.value,
          }),
        );
      }

      // 4. Modern Supabase sb_secret_ key present in client-reachable code. These opaque
      // keys replace legacy service_role JWTs and carry the same elevated/BYPASSRLS access.
      const opaque = findSupabaseSecretKeys(f.content);
      if (opaque.truncated) notes.push(secretCandidateLimitNote(f.rel, "Supabase secret key"));
      for (const hit of opaque.hits) {
        findings.push(
          makeSupabaseSecretKeyFinding({
            file: f.rel,
            line: hit.line,
            snippet: boundedSnippet(f.content, hit.index, hit.value.length),
            value: hit.value,
          }),
        );
      }
    }
  }

  // CG-32: bounded, cap-INDEPENDENT scan of build chunks ABOVE the §6.1 size cap (the cap stays).
  const oversized = await scanOversizedBuildChunks(target);
  findings.push(...oversized.findings);
  notes.push(...oversized.notes);

  return { findings, notes: boundedSecretNotes(notes) };
}

export async function runClientSecretsCheck(target: string): Promise<Finding[]> {
  return (await runClientSecretsAnalysis(target)).findings;
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

/** A modern Supabase sb_secret_ key present in client-reachable code (bypasses RLS). */
function makeSupabaseSecretKeyFinding(args: {
  file: string;
  line: number;
  snippet: string;
  value: string;
}): Finding {
  const { file, line, snippet, value } = args;
  return makeAiFinding({
    ruleId: "ci-ai-supabase-secret-key-client",
    title: "Supabase secret API key referenced in client-reachable code",
    severity: "critical",
    cwe: ["CWE-798", "CWE-285"],
    owasp_web: ["A01:2021", "A07:2021"],
    owasp_llm: ["LLM02:2025"],
    file,
    startLine: line,
    snippet,
    message:
      "A modern Supabase sb_secret_ API key appears in client-reachable code. Secret keys use the service_role database role, bypass Row Level Security, and provide full data access. Browser-side rejection is not protection because an attacker can reuse the extracted key outside a browser.",
    remediation: {
      summary:
        "Never expose a Supabase secret key to a client. Use an anon or sb_publishable_ key on clients and keep sb_secret_ keys only in trusted backends.",
      steps: [
        "Replace the client-side key with the project's anon or sb_publishable_ key.",
        "Move privileged operations behind a server endpoint or Edge Function that authenticates and authorizes every request.",
        "Delete or rotate the exposed sb_secret_ key immediately, then verify no source, bundle, history, or log still contains it.",
      ],
      references: [
        "CWE-285",
        "CWE-798",
        "https://supabase.com/docs/guides/getting-started/api-keys",
      ],
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
function boundedBundleSecretFindings(rel: string, content: string): ClientSecretsAnalysis {
  const findings: Finding[] = [];
  const notes: string[] = [];
  const generic = SECRET_SCAN(content);
  if (generic.truncated) notes.push(secretCandidateLimitNote(rel, "provider-secret"));
  for (const hit of generic.hits) {
    if (isSupabaseDemoJwt(hit.value)) continue; // published local-dev demo key
    if (hit.typeName === "JSON Web Token" && isPublicRoleJwt(hit.value)) continue; // anon/authenticated/public
    if (hit.typeName === "Supabase secret API key") continue; // dedicated arm below
    if (hit.typeName === "JSON Web Token" && isServiceRoleJwt(hit.value)) continue; // dedicated arm below
    if (hit.typeName === "Google API key" && isFirebaseConfigContext(content, hit.value)) continue; // Firebase web key
    findings.push(
      makeSecretValueFinding({
        file: rel,
        typeName: hit.typeName,
        line: hit.line,
        snippet: boundedSnippet(content, hit.index, hit.value.length),
        value: hit.value,
        built: true,
        live: hit.live,
      }),
    );
  }
  const serviceRole = findServiceRoleJwts(content);
  if (serviceRole.truncated) notes.push(secretCandidateLimitNote(rel, "service-role JWT"));
  for (const hit of serviceRole.hits) {
    findings.push(
      makeServiceRoleFinding({
        file: rel,
        line: hit.line,
        snippet: boundedSnippet(content, hit.index, hit.value.length),
        value: hit.value,
      }),
    );
  }
  const opaque = findSupabaseSecretKeys(content);
  if (opaque.truncated) notes.push(secretCandidateLimitNote(rel, "Supabase secret key"));
  for (const hit of opaque.hits) {
    findings.push(
      makeSupabaseSecretKeyFinding({
        file: rel,
        line: hit.line,
        snippet: boundedSnippet(content, hit.index, hit.value.length),
        value: hit.value,
      }),
    );
  }
  return { findings, notes };
}

/** Run the bounded scan over every build chunk above the §6.1 cap (read one at a time). */
async function scanOversizedBuildChunks(target: string): Promise<ClientSecretsAnalysis> {
  const oversized = await collectOversizedBuildFiles(target, {
    exts: CODE_EXTS,
    minBytes: CLIENT_SECRET_CAP_BYTES,
    maxBytes: BOUNDED_SCAN_CEILING_BYTES,
  });
  const findings: Finding[] = [];
  const notes: string[] = [];
  for (const file of oversized) {
    let content: string;
    try {
      content = await readFile(file.abs, "utf8");
    } catch {
      continue; // unreadable/binary — skip
    }
    const scanned = boundedBundleSecretFindings(file.rel, content);
    findings.push(...scanned.findings);
    notes.push(...scanned.notes);
  }
  return { findings, notes };
}

interface SecretHit {
  value: string;
  typeName: string;
  live: boolean;
  line: number;
  index: number;
}

interface BoundedSecretHits {
  hits: Array<{ value: string; line: number; index: number }>;
  truncated: boolean;
}

function lineLookup(content: string): (index: number) => number {
  let line = 1;
  let newline = content.indexOf("\n");
  return (index: number) => {
    while (newline >= 0 && newline < index) {
      line++;
      newline = content.indexOf("\n", newline + 1);
    }
    return line;
  };
}

function secretCandidateLimitNote(file: string, kind: string): string {
  return `${file}: ${kind} analysis reached the ${MAX_SECRET_LOCATIONS_PER_FILE}-location per-file limit; additional locations were not evaluated.`;
}

function boundedSecretNotes(input: readonly string[]): string[] {
  const unique = [...new Set(input)].sort();
  if (unique.length <= MAX_SECRET_NOTES) return unique;
  return [
    ...unique.slice(0, MAX_SECRET_NOTES - 1),
    `${unique.length - MAX_SECRET_NOTES + 1} additional client-secret limitations omitted.`,
  ];
}

/** All recognizable secret occurrences across the content, including multiple providers
 * on one minified/source line. Identical same-line values collapse, while the same value
 * on different lines retains every remediation location up to an explicit bounded limit. */
function SECRET_SCAN(content: string): { hits: SecretHit[]; truncated: boolean } {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  let truncated = false;
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.name === "Supabase secret API key") continue; // owned by the dedicated arm
    pattern.re.lastIndex = 0;
    const lineAt = lineLookup(content);
    for (const match of content.matchAll(pattern.re)) {
      let index = match.index ?? 0;
      let value = match[0];
      // 4.1 M9: the lazy PEM match starts at the FIRST header; a header-only decoy before a real key must not
      // hide it, so the block is re-read from the last header inside the span.
      if (pattern.name === "Generic private key block") {
        const last = value.lastIndexOf("-----BEGIN ");
        if (last > 0) {
          index += last;
          value = value.slice(last);
        }
      }
      const line = lineAt(index);
      if (isSupabaseDemoJwt(value)) continue;
      if (pattern.name === "JSON Web Token" && isPublicRoleJwt(value)) continue;
      if (pattern.name === "JSON Web Token" && isServiceRoleJwt(value)) continue;
      if (pattern.name === "Generic private key block" && !hasPemKeyBody(value)) continue;
      const key = `${line}:${value}`;
      if (seen.has(key)) continue;
      if (hits.length >= MAX_SECRET_LOCATIONS_PER_FILE) {
        truncated = true;
        break;
      }
      seen.add(key);
      hits.push({
        value,
        typeName: pattern.name,
        live: Boolean(pattern.live),
        line,
        index,
      });
    }
    if (truncated) break;
  }
  return { hits, truncated };
}

/**
 * 4.1 M9: a PEM block is a key only when at least 64 base64 characters of key body sit between its
 * header and footer in the same literal or template (whitespace and `\n` escapes allowed). Markers in
 * `replace()` calls, a regex or a builder array carry no key material.
 */
const PEM_MIN_BODY_CHARS = 64;
function hasPemKeyBody(block: string): boolean {
  const body = block
    .replace(/^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, "")
    .replace(/-----END [A-Z0-9 ]*PRIVATE KEY-----$/, "")
    // Fix round 1: escaped line breaks at any escaping depth (`\\n`, `\\\\n`) and escaped slashes (`\\/`) in JSON.
    .replace(/\\+[nr]/g, "\n")
    .replace(/\\+\//g, "/")
    // RFC 1421 header lines of an encrypted key (Proc-Type, DEK-Info).
    .replace(/^[\s"'`+,[]*[A-Za-z][A-Za-z-]*:[^\n]*$/gm, "")
    // String concatenation and array syntax around a key split across literals.
    .replace(/["'`+,[\]\s]+/g, "");
  return /^[A-Za-z0-9+/]+={0,2}$/.test(body) && body.replace(/=+$/, "").length >= PEM_MIN_BODY_CHARS;
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
function findServiceRoleJwts(content: string): BoundedSecretHits {
  const hits: Array<{ value: string; line: number; index: number }> = [];
  const seen = new Set<string>();
  let truncated = false;
  const lineAt = lineLookup(content);
  for (const m of content.matchAll(JWT_RE)) {
    if (!isServiceRoleJwt(m[0])) continue;
    if (isSupabaseDemoJwt(m[0])) continue; // public local-dev demo key
    const index = m.index ?? 0;
    const line = lineAt(index);
    const key = `${line}:${m[0]}`;
    if (seen.has(key)) continue;
    if (hits.length >= MAX_SECRET_LOCATIONS_PER_FILE) {
      truncated = true;
      break;
    }
    seen.add(key);
    hits.push({ value: m[0], line, index });
  }
  return { hits, truncated };
}

/**
 * Modern opaque Supabase secret keys. Reuses the redactor's exact expression so a newly
 * detected value can never be surfaced raw in a finding snippet.
 */
function findSupabaseSecretKeys(content: string): BoundedSecretHits {
  const hits: Array<{ value: string; line: number; index: number }> = [];
  const seen = new Set<string>();
  let truncated = false;
  const lineAt = lineLookup(content);
  SUPABASE_SECRET_KEY_RE.lastIndex = 0;
  for (const match of content.matchAll(SUPABASE_SECRET_KEY_RE)) {
    const index = match.index ?? 0;
    const line = lineAt(index);
    const key = `${line}:${match[0]}`;
    if (seen.has(key)) continue;
    if (hits.length >= MAX_SECRET_LOCATIONS_PER_FILE) {
      truncated = true;
      break;
    }
    seen.add(key);
    hits.push({ value: match[0], line, index });
  }
  return { hits, truncated };
}
