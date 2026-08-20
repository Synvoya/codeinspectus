import { afterEach, describe, expect, test } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runSupabaseEdgeAuthAnalysis,
  runSupabaseEdgeAuthCheck,
} from "./supabase-edge-auth.js";

const CORPUS = join(process.cwd(), "fixtures", "supabase-edge-auth-corpus");
const NO_AUTH = "ci-ai-edge-fn-no-auth";
const PRIVILEGED = "ci-ai-edge-fn-privileged-no-authz";
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const locations = (ruleId: string, findings: Awaited<ReturnType<typeof runSupabaseEdgeAuthCheck>>) =>
  findings
    .filter((finding) => finding.rule_id === ruleId)
    .map((finding) => finding.location.file)
    .sort();

async function tempProject(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codeinspectus-edge-auth-"));
  temporaryRoots.push(root);
  return root;
}

describe("Supabase Edge deployment and handler-root authentication", () => {
  test("treats a direct file target as outside project-level Edge deployment analysis", async () => {
    const root = await tempProject();
    const file = join(root, "route.ts");
    await writeFile(file, "export const value = 1;\n");

    await expect(runSupabaseEdgeAuthAnalysis(file)).resolves.toEqual({ findings: [], notes: [] });
  });

  test("reports only request-reachable privileged sinks without authentication", async () => {
    const findings = await runSupabaseEdgeAuthCheck(CORPUS);

    expect(locations(NO_AUTH, findings)).toEqual([
      "supabase/external-entrypoint.ts",
      "supabase/functions/auth-after-admin/index.ts",
      "supabase/functions/conditional-guard-admin/index.ts",
      "supabase/functions/conditional-stripe-catch/index.ts",
      "supabase/functions/deploy-override/index.ts",
      "supabase/functions/fake-context-admin/index.ts",
      "supabase/functions/fixed-get-user-admin/index.ts",
      "supabase/functions/github-constant-admin/index.ts",
      "supabase/functions/ignored-wrapper-admin/index.ts",
      "supabase/functions/jose-public-key-admin/index.ts",
      "supabase/functions/mixed-request-token-admin/index.ts",
      "supabase/functions/mixed-webhook-token-admin/index.ts",
      "supabase/functions/nested-wrapper-admin/index.ts",
      "supabase/functions/public-admin/index.ts",
      "supabase/functions/query-builder-admin/index.ts",
      "supabase/functions/reverse-user-guard-admin/index.ts",
      "supabase/functions/stripe-constant-admin/index.ts",
      "supabase/functions/unrelated-auth-guard-admin/index.ts",
    ]);
    expect(findings.filter((finding) => finding.rule_id === NO_AUTH).every((finding) =>
      finding.severity === "high" && finding.confidence === "high"
    )).toBe(true);
  });

  test("requires authz on every user-reachable mixed-mode privileged path", async () => {
    const findings = await runSupabaseEdgeAuthCheck(CORPUS);

    expect(locations(PRIVILEGED, findings)).toEqual([
      "supabase/functions/arbitrary-admin-alias/index.ts",
      "supabase/functions/body-owner-admin/index.ts",
      "supabase/functions/conjunction-role-admin/index.ts",
      "supabase/functions/context-user-admin/index.ts",
      "supabase/functions/ctx-destructure-admin/index.ts",
      "supabase/functions/dynamic-authmode-admin/index.ts",
      "supabase/functions/dynamic-role-admin/index.ts",
      "supabase/functions/manual-user-admin/index.ts",
      "supabase/functions/mixed-user-secret-admin/index.ts",
      "supabase/functions/request-controlled-role-admin/index.ts",
      "supabase/functions/unrelated-metadata-admin/index.ts",
      "supabase/functions/user-metadata-admin/index.ts",
      "supabase/functions/with-user-admin/index.ts",
    ]);
    expect(findings.filter((finding) => finding.rule_id === PRIVILEGED).every((finding) =>
      finding.severity === "critical" && finding.confidence === "high"
    )).toBe(true);
  });

  test("accepts root wrappers, current-request proofs, exact authz, and official signed webhooks", async () => {
    const findings = await runSupabaseEdgeAuthCheck(CORPUS);
    const flagged = new Set(findings.map((finding) => finding.location.file));

    for (const safe of [
      "supabase/functions/context-secret-admin/index.ts",
      "supabase/functions/context-user/index.ts",
      "supabase/functions/ctx-destructure-authorized/index.ts",
      "supabase/functions/default-dead-source/index.ts",
      "supabase/functions/github-webhook/index.ts",
      "supabase/functions/manual-get-user/index.ts",
      "supabase/functions/mere-key-mention/index.ts",
      "supabase/functions/mixed-user-secret-mode-guard/index.ts",
      "supabase/functions/named-handler/index.ts",
      "supabase/functions/named-wrapper/index.ts",
      "supabase/functions/nested-dead-admin/index.ts",
      "supabase/functions/stripe-webhook/index.ts",
      "supabase/functions/user-admin-owned/index.ts",
      "supabase/functions/with-none-stripe-official/index.ts",
      "supabase/functions/with-secret-admin/index.ts",
      "supabase/functions/with-user-admin-authorized/index.ts",
    ]) expect(flagged.has(safe), safe).toBe(false);
  });

  test("uses configured/default entrypoints and ignores dead sibling sources", async () => {
    const findings = await runSupabaseEdgeAuthCheck(CORPUS);

    expect(findings.some((finding) =>
      finding.location.file.endsWith("custom-entrypoint/index.ts") ||
      finding.location.file.endsWith("default-dead-source/old.ts")
    )).toBe(false);
    expect(findings.some((finding) => finding.location.file === "supabase/external-entrypoint.ts")).toBe(true);
    expect(findings.some((finding) => finding.location.file.endsWith("deploy-override/index.ts"))).toBe(true);
  });

  test("names cross-module handler/client provenance as coverage, never silent proof", async () => {
    const result = await runSupabaseEdgeAuthAnalysis(CORPUS);

    expect(result.findings.some((finding) =>
      finding.location.file.includes("imported-handler") || finding.location.file.includes("imported-client")
    )).toBe(false);
    expect(result.notes).toEqual(expect.arrayContaining([
      expect.stringContaining("imported handler 'handler' crosses a module boundary"),
      expect.stringContaining("call through imported 'db' crosses a module boundary"),
    ]));
  });

  test("keeps intentional public handlers as bounded unknown coverage, not high findings", async () => {
    const result = await runSupabaseEdgeAuthAnalysis(CORPUS);

    for (const publicFile of [
      "supabase/functions/public-handler/index.ts",
      "supabase/functions/with-none/index.ts",
      "supabase/functions/with-publishable/index.ts",
    ]) {
      expect(result.findings.some((finding) => finding.location.file === publicFile)).toBe(false);
      expect(result.notes.some((note) => note.includes(publicFile) && note.includes("intent is not statically verifiable"))).toBe(true);
    }
  });

  test("does not treat invalid/dynamic or skipped configuration as platform proof", async () => {
    const result = await runSupabaseEdgeAuthAnalysis(CORPUS);
    expect(result.notes).toEqual(expect.arrayContaining([
      expect.stringContaining("invalid/supabase/config.toml: invalid TOML"),
      expect.stringContaining("dynamic/supabase/config.toml: verify_jwt for function 'dynamic' is not a literal boolean"),
      expect.stringContaining("--no-verify-jwt for 'deploy-override'"),
    ]));

    const root = await tempProject();
    await mkdir(join(root, "supabase", "functions", "oversized"), { recursive: true });
    await writeFile(
      join(root, "supabase", "config.toml"),
      `[functions.oversized]\nverify_jwt = false\n${"# padding\n".repeat(240_000)}`,
    );
    await writeFile(
      join(root, "supabase", "functions", "oversized", "index.ts"),
      `import { createClient } from "npm:@supabase/supabase-js";\n` +
      `const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);\n` +
      `Deno.serve(async () => Response.json(await db.from("accounts").select()));\n`,
    );
    const oversized = await runSupabaseEdgeAuthAnalysis(root);
    expect(locations(NO_AUTH, oversized.findings)).toEqual(["supabase/functions/oversized/index.ts"]);
    expect(oversized.notes.some((note) => note.includes("bounded source loader"))).toBe(true);

    const ambiguousRoot = await tempProject();
    await mkdir(join(ambiguousRoot, "apps", "nested", "supabase", "functions", "ambiguous"), { recursive: true });
    await mkdir(join(ambiguousRoot, "supabase"), { recursive: true });
    await writeFile(join(ambiguousRoot, "supabase", "config.toml"), "[functions.root]\nverify_jwt = true\n");
    await writeFile(
      join(ambiguousRoot, "apps", "nested", "supabase", "config.toml"),
      "[functions.ambiguous]\nverify_jwt = true\n",
    );
    await writeFile(
      join(ambiguousRoot, "apps", "nested", "package.json"),
      '{"scripts":{"deploy":"supabase functions deploy ambiguous --no-verify-jwt"}}',
    );
    await writeFile(
      join(ambiguousRoot, "apps", "nested", "supabase", "functions", "ambiguous", "index.ts"),
      "Deno.serve(async () => Response.json({ ok: true }));\n",
    );
    const ambiguous = await runSupabaseEdgeAuthAnalysis(ambiguousRoot);
    expect(ambiguous.notes.some((note) =>
      note.includes("not unambiguously resolved") && note.includes("config state was not overridden")
    )).toBe(true);
  });

  test("bounds findings and reports every omitted finding/note class", async () => {
    const root = await tempProject();
    const functionRoot = join(root, "supabase", "functions", "many");
    await mkdir(functionRoot, { recursive: true });
    const saturatedConfig = ["[functions.many]\nverify_jwt = false\n"];
    for (let index = 0; index < 40; index++) {
      const slug = `saturation_${index}`;
      saturatedConfig.push(`[functions.${slug}]\nverify_jwt = false\n`);
      const directory = join(root, "supabase", "functions", slug);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, "index.ts"), "Deno.serve(async () => Response.json({ ok: true }));\n");
    }
    await writeFile(join(root, "supabase", "config.toml"), saturatedConfig.join("\n"));
    const handlers = Array.from({ length: 129 }, (_, index) =>
      `Deno.serve(async () => Response.json(await db.from("table_${index}").select()));`
    ).join("\n");
    await writeFile(
      join(functionRoot, "index.ts"),
      `import { createClient } from "npm:@supabase/supabase-js";\n` +
      `const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);\n` +
      handlers,
    );

    const result = await runSupabaseEdgeAuthAnalysis(root);
    expect(result.findings).toHaveLength(128);
    expect(result.notes.some((note) => note.includes("omitted 1 finding(s)"))).toBe(true);

    const noteRoot = await tempProject();
    const configLines: string[] = [];
    for (let index = 0; index < 40; index++) {
      const slug = `public_${index}`;
      configLines.push(`[functions.${slug}]\nverify_jwt = false\n`);
      const directory = join(noteRoot, "supabase", "functions", slug);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, "index.ts"), "Deno.serve(async () => Response.json({ ok: true }));\n");
    }
    await writeFile(join(noteRoot, "supabase", "config.toml"), configLines.join("\n"));
    const noteResult = await runSupabaseEdgeAuthAnalysis(noteRoot);
    expect(noteResult.notes.some((note) => note.includes("omitted 8 additional bounded note(s)"))).toBe(true);
  });
});
