/**
 * CG-25b B-12 — Supabase Storage RLS (ci-ai-storage-rls-public).
 *
 * A permissive USING(true) policy on storage.objects exposes every file in the bucket
 * (the storage arm of CVE-2025-48757). Carved out of the system-schema skip so it IS
 * analyzed — WITHOUT reintroducing the CG-18 system-schema FP (auth.* policies stay
 * skipped). Dual-direction lock against the committed corpus.
 */

import { afterEach, describe, test, expect } from "vitest";
import { join } from "node:path";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { runSupabaseRlsAnalysis, runSupabaseRlsCheck } from "./supabase-rls.js";
import { runAiChecks } from "./index.js";
import type { Finding } from "../types.js";
import type { SourceFile } from "./walk.js";
import { buildRlsAnalysisUnits } from "./supabase-migration-state.js";

const CORPUS = join(process.cwd(), "fixtures", "secret-rls-corpus");
const STORAGE = "ci-ai-storage-rls-public";
const USING_TRUE = "ci-ai-rls-using-true";
const INVERTED_AUTH = "ci-ai-rls-inverted-auth";
const MISSING = "ci-ai-rls-missing";

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((f) => f.location.file.endsWith(suffix));
const sourceFile = (rel: string): SourceFile => ({ abs: `/${rel}`, rel, content: "", ext: "sql" });
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporarySupabaseProject(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codeinspectus-rls-"));
  temporaryRoots.push(root);
  for (const [relativePath, content] of Object.entries(files)) {
    const path = join(root, relativePath);
    await mkdir(path.slice(0, path.lastIndexOf("/")), { recursive: true });
    await writeFile(path, content, "utf8");
  }
  return root;
}

describe("B-12 storage.objects RLS (ci-ai-storage-rls-public)", () => {
  test("public storage.objects policies fire; owner-scoped + system-table policies do not", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);

    // TP: public read + public write on storage.objects.
    const tp = atFile(findings, "tp/supabase/migrations/0002_storage_public.sql");
    const tpStorage = tp.filter((f) => f.rule_id === STORAGE);
    expect(tpStorage.length).toBe(2);
    expect(tpStorage.some((f) => f.severity === "high")).toBe(true); // public read
    expect(tpStorage.some((f) => f.severity === "critical")).toBe(true); // public write
    // The generic USING(true) rule must no longer mislabel storage.objects.
    expect(tp.filter((f) => f.rule_id === USING_TRUE).length).toBe(0);

    // FP: owner-scoped storage policy + a USING(true) policy on a system table (auth.*).
    const fp = atFile(findings, "fp/supabase/migrations/0003_storage_owner_scoped.sql");
    expect(fp.filter((f) => f.rule_id === STORAGE).length).toBe(0);
    expect(fp.filter((f) => f.rule_id === USING_TRUE).length).toBe(0); // system schema stays skipped
  });

  test("a real public-schema table still fires the generic USING(true) rule (no regression)", async () => {
    // The existing corpus fixture proves the generic path is unchanged for app tables.
    const findings = await runSupabaseRlsCheck(CORPUS);
    const missing = findings.filter((f) => f.rule_id === "ci-ai-rls-missing");
    expect(missing.some((f) => f.location.file.endsWith("tp/supabase/migrations/0001_missing_rls.sql"))).toBe(true);
  });
});

describe("ordered Supabase migration state", () => {
  test("a permissive policy dropped and replaced safely is not active", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const obsolete = atFile(
      findings,
      "state/superseded-permissive/supabase/migrations/0001_create_policy.sql",
    );

    expect(obsolete.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
  });

  test("a safe policy replaced permissively fires at the active declaration", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const active = atFile(findings, "state/safe-to-permissive/supabase/migrations/0002_replace_policy.sql");
    const permissive = active.filter((f) => f.rule_id === USING_TRUE);

    expect(permissive).toHaveLength(1);
    expect(permissive[0]).toMatchObject({ severity: "critical", confidence: "high" });
  });

  test("RLS enabled later clears missing; RLS disabled later creates a final-state finding", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const enabledLater = findings.filter((f) =>
      f.location.file.includes("state/enable-later/supabase/migrations/"),
    );
    const disabledLater = atFile(
      findings,
      "state/disable-later/supabase/migrations/0002_disable_rls.sql",
    );

    expect(enabledLater.filter((f) => f.rule_id === MISSING)).toHaveLength(0);
    const disabledFinding = disabledLater.find((f) => f.rule_id === MISSING);
    expect(disabledFinding).toMatchObject({
      rule_id: MISSING,
      severity: "high",
      fingerprint: "sha256:ad7815dc2fa42551509600e36db7b3f8c716a8b54efe6c335115520593690429",
      title: "Repository migration explicitly disables Row Level Security on public table 'audit_entries'",
    });
    expect(disabledFinding?.message).toContain("ALTER TABLE ... DISABLE ROW LEVEL SECURITY");
    expect(disabledFinding?.message).toContain("does not prove deployed API reachability");
  });

  test("RLS-off severity stays coherent across disabled, catalog-like, and never-enabled paths", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const sensitive = atFile(
      findings,
      "state/disable-later/supabase/migrations/0002_disable_rls.sql",
    ).find((f) => f.rule_id === MISSING);
    const catalog = atFile(
      findings,
      "state/disable-catalog/supabase/migrations/0002_disable_rls.sql",
    ).find((f) => f.rule_id === MISSING);
    const neverEnabled = atFile(
      findings,
      "state/never-enabled-coherence/supabase/migrations/0001_create_table.sql",
    ).find((f) => f.rule_id === MISSING);

    expect(sensitive?.severity).toBe("high");
    expect(catalog?.severity).toBe("high");
    expect(sensitive?.severity).toBe(neverEnabled?.severity);
  });

  test("dropping and recreating a table resets its RLS state", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const oldPolicy = atFile(
      findings,
      "state/recreated-unprotected/supabase/migrations/0001_create_table.sql",
    );
    const recreated = atFile(
      findings,
      "state/recreated-unprotected/supabase/migrations/0002_recreate_table.sql",
    );

    expect(oldPolicy.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
    expect(recreated.filter((f) => f.rule_id === MISSING)).toHaveLength(1);
  });

  test("superseded storage and inverted-auth policies are silent", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const storage = findings.filter((f) =>
      f.location.file.includes("state/storage-superseded/supabase/migrations/"),
    );
    const inverted = findings.filter((f) =>
      f.location.file.includes("state/inverted-superseded/supabase/migrations/"),
    );

    expect(storage.filter((f) => f.rule_id === STORAGE)).toHaveLength(0);
    expect(inverted.filter((f) => f.rule_id === INVERTED_AUTH)).toHaveLength(0);
  });

  test("a safe policy replaced by inverted auth fires at the later migration", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const active = atFile(findings, "state/safe-to-inverted/supabase/migrations/0002_replace_policy.sql");

    expect(active.filter((f) => f.rule_id === INVERTED_AUTH)).toHaveLength(1);
  });

  test("an authenticated-role OR branch does not hide behind an ownership branch", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);
    const active = atFile(
      analysis.findings,
      "state/inverted-or/supabase/migrations/0001_policy.sql",
    );
    expect(active.filter((finding) => finding.rule_id === INVERTED_AUTH)).toHaveLength(1);
  });

  test("ALTER POLICY updates effective predicate state", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const altered = findings.filter((f) =>
      f.location.file.includes("state/alter-policy/supabase/migrations/"),
    );

    expect(altered.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
  });

  test("an open WITH CHECK does not make UPDATE open when USING remains ownership-scoped", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const partial = atFile(
      findings,
      "state/alter-policy-partial/supabase/migrations/0001_create.sql",
    );

    expect(partial.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
  });

  test("DROP POLICY CASCADE removes the active policy", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const dropped = findings.filter((f) =>
      f.location.file.includes("state/drop-cascade/supabase/migrations/"),
    );

    expect(dropped.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
  });

  test("multi-relation DROP TABLE removes every table and policy in the list", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const dropped = findings.filter((f) =>
      f.location.file.includes("state/drop-multiple/supabase/migrations/"),
    );

    expect(dropped.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
  });

  test("temporary tables are session-local and do not produce missing-RLS findings", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const temporary = findings.filter((f) =>
      f.location.file.includes("state/temp-table/supabase/migrations/"),
    );

    expect(temporary.filter((f) => f.rule_id === MISSING)).toHaveLength(0);
  });

  test("statements reduce in source order within one file", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const dropped = atFile(findings, "state/same-file-dropped/supabase/migrations/0001_policy.sql");
    const createdLast = atFile(
      findings,
      "state/same-file-unsafe-last/supabase/migrations/0001_policy.sql",
    );

    expect(dropped.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
    expect(createdLast.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(1);
  });

  test("quoted policy names, schema-qualified tables, and multiple policies keep exact identity", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const removed = atFile(
      findings,
      "state/quoted-multiple/supabase/migrations/0001_create_policies.sql",
    ).filter((f) => f.rule_id === USING_TRUE);

    expect(removed).toHaveLength(1);
    expect(removed[0]?.location.start_line).toBe(16);
  });

  test("active policy roles are preserved and privileged-only policies stay silent", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const roles = atFile(findings, "state/roles/supabase/migrations/0001_roles.sql").filter(
      (f) => f.rule_id === USING_TRUE,
    );

    expect(roles).toHaveLength(1);
    expect(roles[0]?.location.start_line).toBe(10);
    expect(roles[0]?.message).toContain("anonymous and authenticated clients");
  });

  test("migration files use numeric-prefix order rather than lexical order", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const numericOrder = findings.filter((f) =>
      f.location.file.includes("state/numeric-order/supabase/migrations/"),
    );

    expect(numericOrder.filter((f) => f.rule_id === USING_TRUE)).toHaveLength(0);
  });

  test("DDL text inside a block comment does not mutate state", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const ignored = findings.filter((f) =>
      f.location.file.includes("state/block-comment/supabase/migrations/"),
    );

    expect(ignored).toHaveLength(0);
  });

  test("DDL text inside a dollar-quoted helper body does not mutate state", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const ignored = findings.filter((f) =>
      f.location.file.includes("state/dollar-quoted/supabase/migrations/"),
    );

    expect(ignored).toHaveLength(0);
  });

  test("mixed block-comment and dollar-quoted helper text stays ignored", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const ignored = findings.filter((f) =>
      f.location.file.includes("state/sql-lexing/supabase/migrations/"),
    );

    expect(ignored).toHaveLength(0);
  });

  test("standalone SQL is an independent snapshot with retained severity and lower confidence", async () => {
    const findings = await runSupabaseRlsCheck(CORPUS);
    const snapshot = atFile(findings, "state/snapshot/schema.sql").find(
      (f) => f.rule_id === USING_TRUE,
    );

    expect(snapshot).toMatchObject({ severity: "critical", confidence: "medium" });
    expect(snapshot?.message).toContain("If this file represents applied state");
    expect(snapshot?.message).toContain("Deployed database state remains unverified");
  });

  test("sort ties, ambiguous names, and nested sequence boundaries are deterministic", () => {
    const units = buildRlsAnalysisUnits([
      sourceFile("app/migrations/0002_second.sql"),
      sourceFile("app/migrations/0001_b.sql"),
      sourceFile("app/migrations/0001_a.sql"),
      sourceFile("app/migrations/z_last.sql"),
      sourceFile("app/migrations/a_first.sql"),
      sourceFile("app/migrations/archive/0003_archived.sql"),
      sourceFile("schema.sql"),
    ]);
    const main = units.find((unit) => unit.key === "sequence:app/migrations");

    expect(main?.files.map((file) => file.rel)).toEqual([
      "app/migrations/0001_a.sql",
      "app/migrations/0001_b.sql",
      "app/migrations/0002_second.sql",
      "app/migrations/a_first.sql",
      "app/migrations/z_last.sql",
    ]);
    expect(main?.ambiguouslyOrderedFiles).toEqual([
      "app/migrations/0001_a.sql",
      "app/migrations/0001_b.sql",
      "app/migrations/a_first.sql",
      "app/migrations/z_last.sql",
    ]);
    expect(units.map((unit) => unit.key)).toContain("sequence:app/migrations/archive");
    expect(units.map((unit) => unit.key)).toContain("snapshot:schema.sql");
  });

  test("evaluates permissive OR, restrictive AND, command phases, roles, and masked constants", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);
    const fileFindings = atFile(
      analysis.findings,
      "state/effective-composition/supabase/migrations/0001_policies.sql",
    ).filter((finding) => finding.rule_id === USING_TRUE);

    const anonOnly = fileFindings.find((finding) => finding.title.includes("anon_only_open"));
    expect(anonOnly?.message).toContain("anonymous clients");
    expect(anonOnly?.message).not.toContain("anonymous and authenticated clients");
    expect(fileFindings.some((finding) => finding.title.includes("restrictive_blocks"))).toBe(false);
    expect(fileFindings.some((finding) => finding.title.includes("or_composition"))).toBe(true);
    expect(fileFindings.some((finding) => finding.title.includes("no_permissive"))).toBe(false);
    expect(fileFindings.some((finding) => finding.title.includes("literal_decoys"))).toBe(false);
    expect(fileFindings.some((finding) => finding.title.includes("invalid_clause_shapes"))).toBe(false);
    expect(fileFindings.some((finding) => finding.title.includes("default_open"))).toBe(true);
    expect(fileFindings.some((finding) => finding.title.includes("partial_update"))).toBe(false);
    expect(fileFindings.some((finding) => finding.title.includes("numeric_true"))).toBe(true);
    const openUpdate = fileFindings.find((finding) => finding.title.includes("open_update"));
    expect(openUpdate?.title).toContain("UPDATE");
    expect(openUpdate?.message).toContain("authenticated clients");
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/USING is not valid for a FOR INSERT/i),
      expect.stringMatching(/WITH CHECK is not valid for a FOR SELECT/i),
    ]));
  });

  test("explicit DISABLE on a pre-existing public table is reported and suppresses policy findings", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);
    const disabled = atFile(
      analysis.findings,
      "state/disable-preexisting/supabase/migrations/0001_disable.sql",
    );

    expect(disabled.filter((finding) => finding.rule_id === MISSING)).toHaveLength(1);
    expect(disabled.filter((finding) => finding.rule_id === USING_TRUE)).toHaveLength(0);
    expect(disabled[0]?.title).toContain("external_audit");
    expect(disabled[0]?.message).toContain("hosted configuration");
  });

  test("table and policy identities transfer across RENAME and SET SCHEMA", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);
    const moved = analysis.findings.filter((finding) =>
      finding.location.file.includes("state/rename-and-schema/supabase/migrations/"),
    );

    expect(moved.some((finding) => finding.title.includes("renamed_private_notes"))).toBe(true);
    expect(moved.some((finding) => finding.title.includes("internal_events"))).toBe(true);
    expect(moved.some((finding) => finding.title.includes("moved_out"))).toBe(false);
    expect(moved.some((finding) =>
      finding.rule_id === MISSING && finding.title.includes("renamed_unprotected")
    )).toBe(true);
  });

  test("CREATE TABLE IF NOT EXISTS remains unknown unless an earlier DROP proves absence", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);
    const unknown = analysis.findings.filter((finding) =>
      finding.location.file.includes("state/if-not-exists-unknown/"),
    );
    const proven = analysis.findings.filter((finding) =>
      finding.location.file.includes("state/if-not-exists-proven/"),
    );

    expect(unknown.filter((finding) => finding.rule_id === MISSING)).toHaveLength(0);
    expect(proven.filter((finding) => finding.rule_id === MISSING)).toHaveLength(1);
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/CREATE TABLE IF NOT EXISTS may refer to a pre-existing table/i),
    ]));
  });

  test("ALTER TABLE IF EXISTS and command-invalid ALTER POLICY remain unknown", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);

    expect(analysis.findings.some((finding) => finding.location.file.includes("state/if-exists-unknown/"))).toBe(false);
    expect(analysis.findings.some((finding) => finding.location.file.includes("state/alter-policy-invalid/"))).toBe(false);
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/ALTER TABLE IF EXISTS does not prove the table exists/i),
      expect.stringMatching(/ALTER POLICY uses a predicate clause that is invalid for FOR SELECT/i),
    ]));
  });

  test("ambiguous ordering, custom schemas, and test/example SQL produce no exposure finding", async () => {
    const analysis = await runSupabaseRlsAnalysis(CORPUS);

    expect(analysis.findings.some((finding) => finding.location.file.includes("state/ambiguous-order/"))).toBe(false);
    expect(analysis.findings.some((finding) => finding.location.file.includes("state/custom-schema/"))).toBe(false);
    expect(analysis.findings.some((finding) => finding.location.file.includes("fp/test/"))).toBe(false);
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/migration order is ambiguous/i),
      expect.stringMatching(/schema 'api_private' API exposure is not proven/i),
    ]));
  });

  test("an omitted oversized migration suppresses conclusions for its sequence", async () => {
    const root = await temporarySupabaseProject({
      "supabase/migrations/0001_open.sql": [
        "create table public.omitted_later (id uuid primary key);",
        "alter table public.omitted_later enable row level security;",
        "create policy open_policy on public.omitted_later for select to anon using (true);",
      ].join("\n"),
      "supabase/migrations/0002_oversized.sql": `-- ${"x".repeat(2 * 1024 * 1024)}\n`,
    });

    const analysis = await runSupabaseRlsAnalysis(root);
    expect(analysis.findings).toHaveLength(0);
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/exceeds the .*byte bound/i),
      expect.stringMatching(/omitted SQL could change final RLS state/i),
    ]));
    const integrated = await runAiChecks(root);
    const coverage = integrated.packCoverage.find((pack) => pack.pack_id === "javascript-typescript");
    expect(coverage?.note).toMatch(/omitted SQL could change final RLS state/i);
  });

  test("caps findings and notes with exact omission summaries", async () => {
    const findingsSql = Array.from({ length: 513 }, (_, index) => [
      `create table public.cap_${index} (id uuid primary key);`,
      `alter table public.cap_${index} enable row level security;`,
      `create policy cap_policy_${index} on public.cap_${index} for insert to anon with check (true);`,
    ].join("\n")).join("\n");
    const findingRoot = await temporarySupabaseProject({
      "supabase/migrations/0001_caps.sql": findingsSql,
    });
    const findingAnalysis = await runSupabaseRlsAnalysis(findingRoot);
    expect(findingAnalysis.findings).toHaveLength(512);
    expect(findingAnalysis.notes.at(-1)).toMatch(/1 additional Supabase RLS finding.*512-finding bound/i);

    const notesSql = Array.from({ length: 30 }, (_, index) => [
      `create table private_${index}.records (id uuid primary key);`,
      `alter table private_${index}.records enable row level security;`,
      `create policy open_${index} on private_${index}.records for select to anon using (true);`,
    ].join("\n")).join("\n");
    const noteRoot = await temporarySupabaseProject({
      "supabase/migrations/0001_notes.sql": notesSql,
    });
    const noteAnalysis = await runSupabaseRlsAnalysis(noteRoot);
    expect(noteAnalysis.findings).toHaveLength(0);
    expect(noteAnalysis.notes).toHaveLength(24);
    expect(noteAnalysis.notes.at(-1)).toMatch(/additional Supabase RLS coverage note.*omitted/i);
  });
});
