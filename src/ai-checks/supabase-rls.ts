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
import { collectFiles, lineText } from "./walk.js";
import { makeAiFinding } from "./finding.js";
import { reduceRlsEffectiveState } from "./supabase-migration-state.js";

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
type Sensitivity = "strong" | "catalog" | "unknown";

/** Classify a table's data sensitivity from its column-definition text. */
function tableSensitivity(table: string, cols: string | undefined): Sensitivity {
  const text = cols ?? "";
  if (OWNERSHIP_COL_RE.test(text) || PII_COL_RE.test(text)) return "strong";
  if (CATALOG_TABLES.has(table)) return "catalog";
  return "unknown";
}

function snapshotConfidence(confidence: Confidence, isSnapshot: boolean): Confidence {
  if (!isSnapshot) return confidence;
  return confidence === "high" ? "medium" : "low";
}

function snapshotMessage(message: string, isSnapshot: boolean, subject: string): string {
  if (!isSnapshot) return message;
  return `${subject} found in standalone SQL. If this file represents deployed state, ${message.charAt(0).toLowerCase()}${message.slice(1)} However, effective deployment state could not be verified.`;
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

  for (const state of reduceRlsEffectiveState(sqlFiles)) {
    const isSnapshot = state.kind === "snapshot";

    // (a) Only policies active at the end of this sequence/snapshot are evaluated.
    for (const policy of state.policies.values()) {
      if (
        policy.roles.length > 0 &&
        !policy.roles.some((role) =>
          ["anon", "authenticated", "public"].includes(role.toLowerCase()),
        )
      ) {
        continue;
      }
      const tableState = state.tables.get(policy.tableKey);
      for (const clause of policy.permissiveClauses) {
        const table = policy.table;
        const command = policy.commands[0] ?? "all";
        const isWrite = command !== "select" || clause.matchedWithCheck;
        const location = clause.source;

        // CG-25b B-12: platform-managed schemas stay skipped except storage.objects.
        if (SYSTEM_SCHEMAS.has(policy.schema)) {
          if (policy.schema === "storage" && table === "objects") {
            const baseMessage = isWrite
              ? "This Supabase Storage policy on storage.objects evaluates to TRUE for everyone and covers writes, so any client with the anon key can upload, overwrite, or delete files in your buckets — the CVE-2025-48757 failure pattern applied to storage."
              : "This Supabase Storage policy on storage.objects is world-readable (USING (true)), so any client with the anon key can list and download every file in your buckets (uploads, invoices, ID scans). Confirm the bucket is intended to be fully public.";
            findings.push(
              makeAiFinding({
                ruleId: "ci-ai-storage-rls-public",
                title: isWrite
                  ? "Permissive RLS write policy on storage.objects — anyone can modify your files"
                  : "Public read policy on storage.objects — anyone can download every stored file",
                severity: isWrite ? "critical" : "high",
                cwe: ["CWE-863", "CWE-285"],
                owasp_web: ["A01:2021"],
                file: location.file,
                startLine: location.line,
                snippet: lineText(location.content, location.line),
                message: snapshotMessage(
                  baseMessage,
                  isSnapshot,
                  "Permissive storage policy declaration",
                ),
                remediation: {
                  summary:
                    "Scope the storage.objects policy to the owner/bucket (e.g. bucket_id + auth.uid() = owner); leave it fully public only for genuinely public assets.",
                  steps: [
                    "Decide which buckets are truly public (e.g. avatars) vs private (uploads, documents).",
                    "For private buckets, replace USING (true) with an owner/bucket predicate, e.g. (bucket_id = '...' AND auth.uid() = owner).",
                    "Make the bucket itself private if it should not be world-listable.",
                  ],
                  references: [
                    "CWE-863",
                    "https://supabase.com/docs/guides/storage/security/access-control",
                  ],
                },
                confidence: snapshotConfidence("medium", isSnapshot),
              }),
            );
          }
          continue;
        }

        const sensitivity = tableSensitivity(table, tableState?.columns);
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
            file: location.file,
            startLine: location.line,
            snippet: lineText(location.content, location.line),
            message: snapshotMessage(message, isSnapshot, "Permissive policy declaration"),
            remediation: {
              summary:
                "If this table is not meant to be world-readable/writable, replace USING (true) with a real ownership predicate, e.g. USING (auth.uid() = user_id). If it is an intentional public catalog, you can confirm and ignore.",
              steps: [
                "Decide whether the table is meant to be public (catalog) or per-user/private.",
                "If private: rewrite as USING (auth.uid() = user_id) (and WITH CHECK for writes).",
                "Add separate policies per command (SELECT/INSERT/UPDATE/DELETE) as needed.",
              ],
              references: [
                "CWE-863",
                "https://supabase.com/docs/guides/database/postgres/row-level-security",
              ],
            },
            confidence: snapshotConfidence(confidence, isSnapshot),
          }),
        );
      }

      // (e) Inverted-auth evaluates only the final active policy definition.
      const invertedPattern =
        /auth\.(jwt\s*\(\s*\)\s*->>?\s*'?(aud|role)'?|role\s*\(\s*\))/i;
      const isInverted = (clause: string | undefined): boolean =>
        Boolean(
          clause &&
            invertedPattern.test(clause) &&
            !/auth\.uid\s*\(\s*\)/i.test(clause) &&
            !/\btrue\b/i.test(clause),
        );
      const invertedUsing = isInverted(policy.usingClause);
      const invertedCheck = isInverted(policy.withCheckClause);
      if (invertedUsing || invertedCheck) {
        const location = invertedUsing
          ? (policy.usingSource ?? policy.source)
          : (policy.withCheckSource ?? policy.source);
        const message = `This RLS policy keys off the JWT aud/role claim rather than auth.uid(). That often grants access to any authenticated user instead of the row's owner. Verify this is intentional.`;
        findings.push(
          makeAiFinding({
            ruleId: "ci-ai-rls-inverted-auth",
            title: `Policy on '${policy.table}' may test the wrong condition (aud/role, not user identity)`,
            severity: "medium",
            cwe: ["CWE-863"],
            owasp_web: ["A01:2021"],
            file: location.file,
            startLine: location.line,
            snippet: lineText(location.content, location.line),
            message: snapshotMessage(message, isSnapshot, "RLS policy declaration"),
            remediation: {
              summary: "Verify the policy tests the row owner (auth.uid()), not a broad claim like aud/role.",
              steps: ["Confirm the predicate ties rows to the acting user via auth.uid()."],
              references: ["CWE-863"],
            },
            confidence: snapshotConfidence("medium", isSnapshot),
          }),
        );
      }
    }

    // (b) Tables that exist without RLS at the end of the sequence/snapshot.
    for (const table of state.tables.values()) {
      if (!table.created || table.rlsEnabled || SYSTEM_SCHEMAS.has(table.schema)) continue;
      if (TEST_FIXTURE_PATH_RE.test(table.created.file)) continue;
      const disabledLater = table.lastRlsChange?.enabled === false;
      const location = disabledLater ? table.lastRlsChange!.source : table.created;
      const title = disabledLater
        ? `Table '${table.table}' has Row Level Security disabled in final migration state`
        : `Table '${table.table}' created without Row Level Security`;
      const baseMessage = disabledLater
        ? `The ALTER TABLE ... DISABLE ROW LEVEL SECURITY statement at ${location.file}:${location.line} explicitly disables RLS on '${table.table}'. In the final migration state, the Supabase auto-generated API can expose the whole table to clients with the anon key.`
        : `Table '${table.table}' is created in the public schema but never has ENABLE ROW LEVEL SECURITY. Without RLS, the Supabase auto-generated API exposes the whole table to any client with the anon key.`;
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-rls-missing",
          title,
          severity: "high",
          cwe: ["CWE-862", "CWE-285"],
          owasp_web: ["A01:2021"],
          file: location.file,
          startLine: location.line,
          snippet: lineText(location.content, location.line),
          message: snapshotMessage(
            baseMessage,
            isSnapshot,
            disabledLater ? "RLS-disabling statement" : "Table declaration",
          ),
          remediation: {
            summary: `Enable RLS on '${table.table}' and add per-operation policies.`,
            steps: [
              `ALTER TABLE ${table.table} ENABLE ROW LEVEL SECURITY;`,
              "Add SELECT/INSERT/UPDATE/DELETE policies with real ownership predicates.",
            ],
            references: [
              "CWE-862",
              "https://supabase.com/docs/guides/database/postgres/row-level-security",
            ],
          },
          confidence: snapshotConfidence("medium", isSnapshot),
        }),
      );
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
