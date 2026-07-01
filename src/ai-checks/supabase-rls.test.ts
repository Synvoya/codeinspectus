/**
 * CG-25b B-12 — Supabase Storage RLS (ci-ai-storage-rls-public).
 *
 * A permissive USING(true) policy on storage.objects exposes every file in the bucket
 * (the storage arm of CVE-2025-48757). Carved out of the system-schema skip so it IS
 * analyzed — WITHOUT reintroducing the CG-18 system-schema FP (auth.* policies stay
 * skipped). Dual-direction lock against the committed corpus.
 */

import { describe, test, expect } from "vitest";
import { join } from "node:path";
import { runSupabaseRlsCheck } from "./supabase-rls.js";
import type { Finding } from "../types.js";

const CORPUS = join(process.cwd(), "fixtures", "secret-rls-corpus");
const STORAGE = "ci-ai-storage-rls-public";
const USING_TRUE = "ci-ai-rls-using-true";

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((f) => f.location.file.endsWith(suffix));

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
