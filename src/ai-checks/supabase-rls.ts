/**
 * §6.2 — Supabase RLS / inverted-auth (CodeInspectus AI-code check).
 * CWE-285, CWE-862, CWE-863; OWASP A01:2021. The Lovable / CVE-2025-48757 class.
 *
 * Heuristic SQL analysis (regex, not a full parser):
 *   - public-schema CREATE TABLE with no ENABLE ROW LEVEL SECURITY  → CWE-862
 *   - `USING (true)` / `WITH CHECK (true)` policy — severity tiered  → CWE-863
 *     by table sensitivity (per-user/PII = critical, public catalog = low)
 *   - Edge Function serving requests with no auth/JWT verification   → CWE-862 (medium)
 *   - inverted-auth heuristic: policy tests aud/role, not auth.uid() → CWE-863 (medium)
 */

import type { Finding, Severity, Confidence } from "../types.js";
import { collectFiles, lineOf, lineText } from "./walk.js";
import { makeAiFinding } from "./finding.js";

// CG-18: capture an optional schema so system-schema tables (auth.*, storage.*, …) can be
// skipped — they are platform-managed, not the app's public API surface (dogfood FP).
const CREATE_TABLE_RE =
  /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:["`]?([a-zA-Z0-9_]+)["`]?\s*\.\s*)?["`]?([a-zA-Z0-9_]+)["`]?/gi;
const ENABLE_RLS_RE =
  /alter\s+table\s+(?:"?public"?\.)?["`]?([a-zA-Z0-9_]+)["`]?\s+enable\s+row\s+level\s+security/gi;
const CREATE_POLICY_RE =
  /create\s+policy\s+[^;]*?\bon\s+(?:"?public"?\.)?["`]?([a-zA-Z0-9_]+)["`]?([^;]*);/gis;
const USING_TRUE_RE = /\b(?:using|with\s+check)\s*\(\s*true\s*\)/gi;

// CG-18 dogfood FP: skip RLS-missing on platform-managed schemas (Supabase manages RLS
// for these) and on test/example fixture migrations (not a real app's exposed tables).
const SYSTEM_SCHEMAS = new Set([
  "auth", "storage", "realtime", "vault", "extensions", "graphql", "graphql_public",
  "pgbouncer", "net", "cron", "pgsodium", "supabase_functions", "supabase_migrations",
  "information_schema", "pg_catalog", "pg_temp",
]);
const TEST_FIXTURE_PATH_RE =
  /(^|\/)(tests?|__tests__|spec|specs|examples?|fixtures?|__fixtures__|mocks?|demo|sandbox)(\/)/i;

// CG-04 sensitivity heuristic: tier a permissive (USING/WITH CHECK (true)) policy
// by the sensitivity of the table it protects — sensitive/per-user tables stay
// CRITICAL; obvious public catalogs drop to low with confirm wording. Never miss a
// real exposure; stop screaming CRITICAL at product/price catalogs.
const OWNERSHIP_COL_RE = /\b(user_id|owner_id|account_id|profile_id|owner)\b/i;
const PII_COL_RE =
  /\b(email|phone|address|dob|ssn|password|password_hash|token|secret|api_key|stripe_customer\w*)\b|\b\w+_key\b/i;
const CATALOG_TABLES = new Set([
  "products", "product", "prices", "price", "plans", "plan", "categories", "category",
  "tags", "tag", "currencies", "countries", "regions", "languages", "locales",
]);
const TABLE_COLS_RE =
  /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?["`]?([a-zA-Z0-9_]+)["`]?\s*\(([\s\S]*?)\)\s*;/gi;

type Sensitivity = "strong" | "catalog" | "unknown";

/** Classify a table's data sensitivity from its column-definition text. */
function tableSensitivity(table: string, cols: string | undefined): Sensitivity {
  const text = cols ?? "";
  if (OWNERSHIP_COL_RE.test(text) || PII_COL_RE.test(text)) return "strong";
  if (CATALOG_TABLES.has(table)) return "catalog";
  return "unknown";
}

/**
 * Blank out SQL comments (-- line and block) while preserving length and
 * newlines, so regex matches never fire inside comments but line numbers
 * computed against the result still map to the original source.
 */
function blankSqlComments(sql: string): string {
  let out = sql.replace(/--[^\n]*/g, (m) => " ".repeat(m.length));
  out = out.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
  return out;
}

interface PolicyInfo {
  table: string;
  body: string;
  index: number;
  endIndex: number; // absolute end of the CREATE POLICY ... ; statement
  commands: string[]; // select/insert/update/delete/all
}

function parsePolicies(sql: string): PolicyInfo[] {
  const policies: PolicyInfo[] = [];
  for (const m of sql.matchAll(CREATE_POLICY_RE)) {
    const table = (m[1] ?? "").toLowerCase();
    const body = m[2] ?? "";
    const cmds: string[] = [];
    const forMatch = body.match(/\bfor\s+(select|insert|update|delete|all)\b/i);
    if (forMatch && forMatch[1]) cmds.push(forMatch[1].toLowerCase());
    else cmds.push("all"); // policy with no FOR applies to ALL
    const index = m.index ?? 0;
    policies.push({ table, body, index, endIndex: index + m[0].length, commands: cmds });
  }
  return policies;
}

export async function runSupabaseRlsCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const sqlFiles = await collectFiles(target, { exts: ["sql"], includeBuilt: false });

  // GATE (dogfooding precision fix, CG-03): RLS is a Supabase/PostgREST concern —
  // tables are exposed directly to clients via the anon key, so a too-permissive
  // policy is a real vuln. A plain server-side-ORM Postgres app (Drizzle/Prisma/
  // node-postgres) does NOT use RLS; its DB is reached only through the trusted
  // server, so "missing RLS" is a false positive there. Only run the RLS checks
  // when the project shows real Supabase signals: SQL living under a supabase/
  // directory, or SQL that references Supabase's auth schema (auth.uid/users/jwt).
  const looksLikeSupabase =
    sqlFiles.some((f) => /(^|\/)supabase\//i.test(f.rel)) ||
    sqlFiles.some((f) => /\bauth\.(uid|users|jwt|role)\b/i.test(f.content));
  if (!looksLikeSupabase) return findings;

  for (const f of sqlFiles) {
    // Match against a comment-blanked copy (line numbers preserved); use the
    // original f.content only for snippet text.
    const sql = blankSqlComments(f.content);

    // Tables created in public.
    const created = new Map<string, number>(); // table → line
    for (const m of sql.matchAll(CREATE_TABLE_RE)) {
      const schema = (m[1] ?? "").toLowerCase();
      const t = (m[2] ?? "").toLowerCase();
      if (schema && SYSTEM_SCHEMAS.has(schema)) continue; // platform-managed schema
      if (t) created.set(t, lineOf(sql, m.index ?? 0));
    }
    // Tables with RLS enabled.
    const rlsEnabled = new Set<string>();
    for (const m of sql.matchAll(ENABLE_RLS_RE)) {
      const t = (m[1] ?? "").toLowerCase();
      if (t) rlsEnabled.add(t);
    }
    const policies = parsePolicies(sql);

    // Per-table column text (for the CG-04 sensitivity heuristic), built from the
    // comment-blanked SQL so commented-out columns don't count.
    const tableColumns = new Map<string, string>();
    for (const m of sql.matchAll(TABLE_COLS_RE)) {
      const t = (m[1] ?? "").toLowerCase();
      if (t) tableColumns.set(t, m[2] ?? "");
    }

    // (a) Permissive RLS: USING (true) / WITH CHECK (true). The pattern is always
    // detected; CG-04 TIERS the severity by what the table protects, so a sensitive
    // / per-user table stays CRITICAL (the CVE-2025-48757 class) while a genuine
    // public catalog drops to low with human-confirm wording. A permissive policy
    // covering WRITES outranks SELECT-only regardless of table.
    for (const m of sql.matchAll(USING_TRUE_RE)) {
      const mi = m.index ?? 0;
      const line = lineOf(sql, mi);
      const matchedWithCheck = m[0].toLowerCase().startsWith("with");
      const policy = policies.find((p) => mi >= p.index && mi < p.endIndex);
      // Skip a USING/WITH CHECK (true) that isn't inside a real CREATE POLICY (e.g.
      // it appears as a quoted argument to a helper function) — matching there
      // produces a bogus finding on a non-existent table (CG-04 dogfooding FP).
      if (!policy) continue;
      // Skip policies granted ONLY to privileged roles (e.g. TO service_role):
      // service_role bypasses RLS, so a permissive policy scoped to it is a no-op
      // for the anon/authenticated client and not a real exposure (CG-04 FP).
      const toMatch = policy.body.match(/\bto\s+([a-z_]+(?:\s*,\s*[a-z_]+)*)/i);
      if (
        toMatch &&
        !(toMatch[1] ?? "")
          .toLowerCase()
          .split(/\s*,\s*/)
          .some((r) => r === "anon" || r === "authenticated" || r === "public")
      ) {
        continue;
      }
      const table = policy.table;
      const command = policy.commands[0] ?? "all";
      const isWrite = command !== "select" || matchedWithCheck;
      const sensitivity = tableSensitivity(table, tableColumns.get(table));
      const tableLabel = table || "table";

      let severity: Severity;
      let title: string;
      let message: string;
      let confidence: Confidence;
      if (isWrite) {
        severity = "critical";
        title = `Permissive RLS write policy on '${tableLabel}' — anyone can write`;
        message =
          "This Row Level Security policy applies to writes (INSERT/UPDATE/DELETE/ALL) and evaluates to TRUE for everyone, so any client with the anon key can insert, modify, or delete rows. This is the CVE-2025-48757 failure pattern.";
        confidence = "high";
      } else if (sensitivity === "strong") {
        severity = "critical";
        title = `Permissive RLS read policy on sensitive table '${tableLabel}' — USING (true) exposes per-user/PII data`;
        message =
          "This SELECT policy evaluates to TRUE for everyone, so any client with the anon key can read every row. The table has per-user ownership or PII columns, so this exposes private data — the CVE-2025-48757 failure pattern.";
        confidence = "high";
      } else if (sensitivity === "catalog") {
        severity = "low";
        title = `Public read policy on catalog-like table '${tableLabel}' — confirm intended`;
        message =
          "This SELECT policy is world-readable (USING (true)). The table has no ownership/PII columns and a catalog-like name, so public read may be intentional (e.g. a product/price catalog). Potential public exposure — confirm this table is intended to be world-readable.";
        confidence = "medium";
      } else {
        severity = "medium";
        title = `World-readable RLS policy on '${tableLabel}' — verify intended`;
        message =
          "This SELECT policy evaluates to TRUE for everyone, so any client with the anon key can read every row. No per-user ownership or PII columns were detected, but confirm this table is intended to be world-readable.";
        confidence = "medium";
      }

      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-rls-using-true",
          title,
          severity,
          cwe: ["CWE-863", "CWE-285"],
          owasp_web: ["A01:2021"],
          file: f.rel,
          startLine: line,
          snippet: lineText(f.content, line),
          message,
          remediation: {
            summary:
              "If this table is not meant to be world-readable/writable, replace USING (true) with a real ownership predicate, e.g. USING (auth.uid() = user_id). If it is an intentional public catalog, you can confirm and ignore.",
            steps: [
              "Decide whether the table is meant to be public (catalog) or per-user/private.",
              "If private: rewrite as USING (auth.uid() = user_id) (and WITH CHECK for writes).",
              "Add separate policies per command (SELECT/INSERT/UPDATE/DELETE) as needed.",
            ],
            references: ["CWE-863", "https://supabase.com/docs/guides/database/postgres/row-level-security"],
          },
          confidence,
        }),
      );
    }

    // (b) public table created without RLS enabled. Skip on test/example fixture
    // migrations — not a real app's exposed tables (dogfood FP, CG-18).
    const isTestFixture = TEST_FIXTURE_PATH_RE.test(f.rel);
    for (const [table, line] of created) {
      if (isTestFixture) break;
      if (!rlsEnabled.has(table)) {
        findings.push(
          makeAiFinding({
            ruleId: "ci-ai-rls-missing",
            title: `Table '${table}' created without Row Level Security`,
            severity: "high",
            cwe: ["CWE-862", "CWE-285"],
            owasp_web: ["A01:2021"],
            file: f.rel,
            startLine: line,
            snippet: lineText(f.content, line),
            message: `Table '${table}' is created in the public schema but never has ENABLE ROW LEVEL SECURITY. Without RLS, the Supabase auto-generated API exposes the whole table to any client with the anon key.`,
            remediation: {
              summary: `Enable RLS on '${table}' and add per-operation policies.`,
              steps: [
                `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`,
                "Add SELECT/INSERT/UPDATE/DELETE policies with real ownership predicates.",
              ],
              references: ["CWE-862", "https://supabase.com/docs/guides/database/postgres/row-level-security"],
            },
            confidence: "medium",
          }),
        );
      }
    }

    // (c) [REMOVED in CG-03 dogfooding] "write-open" — flagged a table that has a
    // SELECT policy but no INSERT/UPDATE/DELETE policy. That logic was inverted:
    // with RLS enabled and no write policy, Postgres DENIES all writes (only the
    // table owner / service_role bypass RLS). "No write policy" is therefore
    // secure-by-default, not CWE-862. The rule produced only false positives on
    // real read-mostly tables (catalogs, webhook-synced data) — removed.

    // (e) inverted-auth heuristic: policy compares aud/role rather than auth.uid().
    for (const p of policies) {
      const usesUid = /auth\.uid\s*\(\s*\)/i.test(p.body);
      const usesAudOrRole = /auth\.(jwt\s*\(\s*\)\s*->>?\s*'?(aud|role)'?|role\s*\(\s*\))/i.test(p.body);
      if (usesAudOrRole && !usesUid && !/\btrue\b/i.test(p.body)) {
        const line = lineOf(sql, p.index);
        findings.push(
          makeAiFinding({
            ruleId: "ci-ai-rls-inverted-auth",
            title: `Policy on '${p.table}' may test the wrong condition (aud/role, not user identity)`,
            severity: "medium",
            cwe: ["CWE-863"],
            owasp_web: ["A01:2021"],
            file: f.rel,
            startLine: line,
            snippet: lineText(f.content, line),
            message: `This RLS policy keys off the JWT aud/role claim rather than auth.uid(). That often grants access to any authenticated user instead of the row's owner. Verify this is intentional.`,
            remediation: {
              summary: "Verify the policy tests the row owner (auth.uid()), not a broad claim like aud/role.",
              steps: ["Confirm the predicate ties rows to the acting user via auth.uid()."],
              references: ["CWE-863"],
            },
            confidence: "medium",
          }),
        );
      }
    }
  }

  // (d) Edge Functions serving requests without auth verification.
  const fnFiles = await collectFiles(target, { exts: ["ts", "js"], includeBuilt: false });
  for (const f of fnFiles) {
    if (!/(^|\/)supabase\/functions\//i.test(f.rel)) continue;
    const servesRequests = /\b(Deno\.serve|serve\s*\(|export\s+default\s+async)/.test(f.content);
    const hasAuth =
      /authorization/i.test(f.content) ||
      /auth\.getUser|getUser\s*\(|verifyJWT|jwtVerify|verify_jwt|createClient\([^)]*service_role/i.test(
        f.content,
      );
    if (servesRequests && !hasAuth) {
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-edge-fn-no-auth",
          title: "Supabase Edge Function handles requests without auth verification",
          severity: "high",
          cwe: ["CWE-862"],
          owasp_web: ["A01:2021"],
          file: f.rel,
          startLine: 1,
          snippet: lineText(f.content, 1),
          message:
            "This Edge Function serves HTTP requests but contains no visible JWT/Authorization verification. Unless it is intentionally public, it can be invoked by anyone.",
          remediation: {
            summary: "Verify the caller's JWT (Authorization header) and reject unauthenticated requests, unless the function is intentionally public.",
            steps: [
              "Read the Authorization header and verify the Supabase JWT.",
              "Return 401 for missing/invalid tokens.",
              "Set verify_jwt=true in the function config where appropriate.",
            ],
            references: ["CWE-862", "https://supabase.com/docs/guides/functions/auth"],
          },
          confidence: "medium",
        }),
      );
    }
  }

  return findings;
}
