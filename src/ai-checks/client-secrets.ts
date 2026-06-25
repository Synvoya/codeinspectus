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

import type { Finding } from "../types.js";
import { collectFiles, lineOf, lineText } from "./walk.js";
import { findSecret, hashSecret } from "../redact.js";
import { makeAiFinding } from "./finding.js";
import { remediationForCwe } from "../remediation.js";

const FRONTEND_EXTS = ["tsx", "jsx", "vue", "svelte", "astro", "html"];
const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "vue", "svelte", "astro", "html"];
const BUILD_SEGMENTS = ["dist", "build", ".next", "out", ".output"];

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
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

// Known PUBLIC-by-design keys: a client-exposed prefix on these is correct, not a
// leak. Firebase web API keys are explicitly public (Google docs: not a secret;
// access is gated by Firebase Security Rules, not key secrecy). Skip them so the
// public-env-secret check doesn't false-fire (CG-05 dogfooding fix).
const KNOWN_PUBLIC_KEY_RE = /FIREBASE[_]?API[_]?KEY/i;

function isBuilt(rel: string): boolean {
  return rel.split("/").some((seg) => BUILD_SEGMENTS.includes(seg));
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
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: true, maxBytes: 4 * 1024 * 1024 });

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
        const severity = built ? "critical" : pat.live ? "critical" : "high";
        const where = built
          ? "compiled into a shipped bundle"
          : "in client-reachable source (ships to the browser)";
        findings.push(
          makeAiFinding({
            ruleId: built ? "ci-ai-secret-in-bundle" : "ci-ai-client-hardcoded-secret",
            title: built ? "Secret compiled into shipped bundle" : "Hard-coded secret in client-reachable code",
            severity,
            cwe: ["CWE-798", "CWE-312"],
            owasp_web: ["A07:2021"],
            owasp_llm: ["LLM02:2025"],
            file: f.rel,
            startLine: pat.line,
            snippet: lineText(f.content, pat.line),
            message: `${pat.typeName} ${where}. Anyone who loads the app can read this value.`,
            remediation: remediationForCwe(["CWE-798"]),
            confidence: "high",
            isSecret: true,
            secretValueHash: hashSecret(pat.value),
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

    // 3. Supabase service_role key VALUE present in client-reachable code (bypasses RLS).
    if (client) {
      for (const hit of findServiceRoleJwts(f.content)) {
        findings.push(
          makeAiFinding({
            ruleId: "ci-ai-supabase-service-role-client",
            title: "Supabase service_role key referenced in client-reachable code",
            severity: "critical",
            cwe: ["CWE-798", "CWE-285"],
            owasp_web: ["A01:2021", "A07:2021"],
            owasp_llm: ["LLM02:2025"],
            file: f.rel,
            startLine: hit.line,
            snippet: lineText(f.content, hit.line),
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
            secretValueHash: hashSecret(hit.value),
          }),
        );
      }
    }
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

/**
 * Service_role JWTs (payload role = service_role) present as VALUES; skips the public
 * local-dev demo key (iss: supabase-demo). Matching the value — not the bare token —
 * avoids the dogfood FP where "service_role" appears in library source / comments / strings.
 */
function findServiceRoleJwts(content: string): { value: string; line: number }[] {
  const hits: { value: string; line: number }[] = [];
  for (const m of content.matchAll(JWT_RE)) {
    const seg = m[0].split(".")[1] ?? "";
    let payload = "";
    try {
      payload = Buffer.from(seg, "base64url").toString("utf8");
    } catch {
      continue;
    }
    if (!/"role"\s*:\s*"service_role"/.test(payload)) continue;
    if (/"iss"\s*:\s*"supabase-demo"/.test(payload)) continue; // public local-dev demo key
    hits.push({ value: m[0], line: lineOf(content, m.index ?? 0) });
  }
  return hits;
}
