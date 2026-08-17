import { beforeAll, describe, expect, test } from "vitest";
import { join } from "node:path";

import type { Finding } from "../types.js";
import {
  runNextjsAdminRouteAnalysis,
  runNextjsAdminRouteCheck,
  type NextjsAdminRouteAnalysis,
} from "./nextjs-admin-route.js";

const CORPUS = join(process.cwd(), "fixtures", "nextjs-admin-route-corpus");
const RULE = "ci-ai-nextjs-admin-route-no-authz";
const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((finding) => finding.location.file.endsWith(suffix) && finding.rule_id === RULE);

describe("Next.js admin route authentication and authorization", () => {
  let analysis: NextjsAdminRouteAnalysis;
  beforeAll(async () => {
    analysis = await runNextjsAdminRouteAnalysis(CORPUS);
  });

  test.each([
    ["tp/pages/api/admin/users.ts", 3, "authentication and authorization"],
    ["tp/pages/api/admin/organizations/users.ts", 7, "authentication and authorization"],
    ["tp/app/api/admin/reports/route.ts", 3, "authorization"],
    ["tp/src/app/api/admin/billing/route.ts", 3, "authorization"],
    ["tp/app/api/admin/helper-definitions/route.ts", 7, "authentication and authorization"],
    ["tp/app/api/admin/mixed/route.ts", 12, "authentication and authorization"],
    ["tp/app/api/admin/lookup-no-rejection/route.ts", 3, "authentication"],
    ["tp/app/api/admin/comparison-no-denial/route.ts", 3, "authorization"],
    ["tp/app/api/admin/late-guard/route.ts", 3, "authentication and authorization"],
  ])("TP %s fires once with the missing boundary", (file, line, missing) => {
    const hits = atFile(analysis.findings, file as string);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
      cwe: ["CWE-862", "CWE-863", "CWE-306"],
      owasp_web: ["A01:2021"],
      owasp_api: ["API5:2023"],
      location: { start_line: line },
      engine: "codeinspectus-ai",
    });
    expect(hits[0]!.message).toContain(`in-handler ${missing} boundary`);
  });

  test("analyzes App Router verbs independently", () => {
    const hits = atFile(analysis.findings, "tp/app/api/admin/mixed/route.ts");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.message).toContain("The POST handler");
    expect(hits[0]!.location.start_line).toBe(12);
  });

  test.each([
    "fp/pages/api/admin/settings.ts",
    "fp/pages/api/admin/teams/index.ts",
    "fp/pages/api/admin/auth0-alias/users.ts",
    "fp/pages/api/admin/custom-wrapper/report.ts",
    "fp/src/app/api/admin/audit/route.ts",
    "fp/app/api/admin/multiline-role/route.ts",
    "fp/app/api/admin/is-admin/route.ts",
    "fp/app/api/admin/clerk-alias/route.ts",
    "fp/app/api/admin/supabase-client-alias/route.ts",
    "fp/app/api/admin/local-helper/route.ts",
    "fp/app/api/admin/imported-guard/route.ts",
    "fp/app/api/admin/unknown-wrapper/route.ts",
    "fp/app/api/admin/export-alias/route.ts",
    "fp/app/api/admin/config-only/route.ts",
    "fp/app/api/admin/malformed/route.ts",
    "fp/app/api/admin/bounded-out/route.ts",
    "fixed/pages/api/admin/users.ts",
    "fp/pages/api/health.ts",
    "fp/app/api/profile/route.ts",
  ])("FP/fixed/unknown %s stays silent", (file) => {
    expect(atFile(analysis.findings, file)).toHaveLength(0);
  });

  test("comments, strings, and dead recognized-name helpers do not suppress", () => {
    expect(atFile(analysis.findings, "tp/app/api/admin/helper-definitions/route.ts")).toHaveLength(1);
  });

  test("reports malformed, bounded-out, and custom guard coverage instead of guessing", () => {
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/bounded-out\/route\.ts:.*nesting bound exceeded/),
      expect.stringMatching(/malformed\/route\.ts:.*unbalanced/),
      expect.stringMatching(/unknown-wrapper\/route\.ts: GET uses secureAdmin/),
      expect.stringMatching(/custom-wrapper\/report\.ts: default uses companyAdminBoundary/),
      expect.stringMatching(/imported-guard\/route\.ts: GET calls requireAdmin/),
    ]));
  });

  test("compatibility wrapper returns the analysis findings", async () => {
    expect(await runNextjsAdminRouteCheck(CORPUS)).toEqual(analysis.findings);
  });

  test("does not flag a server-only service client setup with no privileged operation", async () => {
    const fixture = join(process.cwd(), "fixtures", "secret-rls-corpus", "fp", "app", "api", "admin");
    expect(await runNextjsAdminRouteCheck(fixture)).toEqual([]);
  });

  test("emits exactly the planted handler findings", () => {
    expect(analysis.findings).toHaveLength(81);
  });

  test.each([
    "tp/app/api/admin/conditional-auth-and/route.ts",
    "tp/app/api/admin/conditional-authz-and/route.ts",
    "tp/app/api/admin/nested-conditional/route.ts",
    "tp/app/api/admin/untrusted-role/route.ts",
    "tp/app/api/admin/untrusted-claims/route.ts",
    "tp/app/api/admin/role-existence/route.ts",
    "tp/app/api/admin/ignored-helper-result/route.ts",
    "tp/app/api/admin/conditional-helper/route.ts",
    "tp/app/api/admin/fake-supabase/route.ts",
    "tp/app/api/admin/fake-auth0/route.ts",
    "tp/app/api/admin/unawaited-session/route.ts",
    "tp/app/api/admin/loose-clerk-window/route.ts",
    "tp/app/api/admin/imported-guard-after/route.ts",
    "tp/app/api/admin/imported-guard-conditional/route.ts",
    "tp/app/api/admin/guard-before-binding/route.ts",
    "tp/app/api/admin/identity-overwrite/route.ts",
    "tp/app/api/admin/nested-handler-termination/route.ts",
    "tp/app/api/admin/nested-helper-termination/route.ts",
    "tp/app/api/admin/identity-member-overwrite/route.ts",
    "tp/app/api/admin/identity-role-mutation/route.ts",
    "tp/app/api/admin/conditional-clerk-protect/route.ts",
    "tp/app/api/admin/mixed-supabase-client/route.ts",
    "tp/app/api/admin/fallback-nextauth-result/route.ts",
    "tp/app/api/admin/conditional-nextauth-result/route.ts",
    "tp/app/api/admin/conditional-clerk-result/route.ts",
    "tp/app/api/admin/conditional-supabase-result/route.ts",
    "tp/app/api/admin/object-assign-identity/route.ts",
    "tp/app/api/admin/reflect-set-identity/route.ts",
    "tp/app/api/admin/supabase-method-overwrite/route.ts",
    "tp/app/api/admin/supabase-object-assign/route.ts",
    "tp/app/api/admin/authz-role-alias-overwrite/route.ts",
    "tp/app/api/admin/authz-is-admin-alias-overwrite/route.ts",
    "tp/app/api/admin/supabase-reflect-set/route.ts",
    "tp/app/api/admin/supabase-computed-overwrite/route.ts",
    "tp/app/api/admin/supabase-auth-alias-overwrite/route.ts",
    "tp/app/api/admin/authz-role-for-of-overwrite/route.ts",
    "tp/app/api/admin/authz-role-destructure-overwrite/route.ts",
    "tp/app/api/admin/authz-role-iife-overwrite/route.ts",
    "tp/app/api/admin/supabase-auth-alias-object-assign/route.ts",
    "tp/app/api/admin/supabase-auth-alias-reflect-set/route.ts",
    "tp/app/api/admin/supabase-auth-alias-chain/route.ts",
    "tp/app/api/admin/supabase-auth-destructured-alias/route.ts",
    "tp/app/api/admin/supabase-define-property/route.ts",
    "tp/app/api/admin/authz-role-array-rest-overwrite/route.ts",
    "tp/app/api/admin/authz-role-object-overwrite/route.ts",
    "tp/app/api/admin/authz-role-object-alias-overwrite/route.ts",
    "tp/app/api/admin/authz-role-for-array-overwrite/route.ts",
    "tp/app/api/admin/authz-role-for-object-overwrite/route.ts",
    "tp/app/api/admin/supabase-define-properties-direct/route.ts",
    "tp/app/api/admin/supabase-define-properties-chain/route.ts",
    "tp/app/api/admin/supabase-define-properties-destructured/route.ts",
    "tp/app/api/admin/supabase-reflect-define-direct/route.ts",
    "tp/app/api/admin/supabase-reflect-define-chain/route.ts",
    "tp/app/api/admin/supabase-reflect-define-destructured/route.ts",
    "tp/app/api/admin/supabase-define-properties-dynamic/route.ts",
    "tp/app/api/admin/supabase-reflect-define-dynamic/route.ts",
    "tp/app/api/admin/authz-role-deep-array/route.ts",
    "tp/app/api/admin/authz-role-deep-object/route.ts",
    "tp/app/api/admin/authz-role-deep-for-of/route.ts",
    "tp/app/api/admin/supabase-auth-alias-over-bound/route.ts",
    "tp/app/api/admin/supabase-auth-alias-conditional/route.ts",
    "tp/app/api/admin/supabase-auth-helper-mutation/route.ts",
    "tp/app/api/admin/supabase-auth-iife-mutation/route.ts",
    "tp/app/api/admin/supabase-auth-helper-alias/route.ts",
    "tp/app/api/admin/supabase-auth-helper-wrapper/route.ts",
    "tp/app/api/admin/supabase-auth-helper-optional/route.ts",
    "tp/app/api/admin/supabase-auth-iife-wrapped/route.ts",
    "tp/app/api/admin/supabase-auth-helper-alias-conditional/route.ts",
    "tp/app/api/admin/supabase-auth-expression-chain/route.ts",
    "tp/app/api/admin/supabase-auth-expression-wrapper/route.ts",
    "tp/app/api/admin/supabase-auth-forward-expression/route.ts",
    "tp/app/api/admin/supabase-auth-forward-braced/route.ts",
  ])("adversarial %s remains a finding", (file) => {
    expect(atFile(analysis.findings, file)).toHaveLength(1);
  });

  test.each([
    "fp/app/api/admin/or-denials/route.ts",
    "fp/app/api/admin/helper-throws/route.ts",
    "fp/app/api/admin/helper-result-checked/route.ts",
    "fp/app/api/admin/clerk-protect/route.ts",
    "fp/app/api/admin/supabase-property-unrelated/route.ts",
    "fp/app/api/admin/supabase-property-shadowed/route.ts",
    "fp/app/api/admin/authz-role-deep-control/route.ts",
    "fp/app/api/admin/supabase-auth-post-lookup-mutation/route.ts",
    "fp/app/api/admin/supabase-auth-unrelated-reassignment/route.ts",
    "fp/app/api/admin/supabase-auth-uncalled-helper/route.ts",
    "fp/app/api/admin/supabase-auth-over-bound-control/route.ts",
    "fp/app/api/admin/supabase-auth-helper-alias-reassigned/route.ts",
    "fp/app/api/admin/supabase-auth-helper-inner-conditional/route.ts",
    "fp/app/api/admin/supabase-auth-helper-optional-conditional/route.ts",
    "fp/app/api/admin/supabase-auth-iife-over-wrapped/route.ts",
    "fp/app/api/admin/supabase-auth-helper-post-lookup/route.ts",
    "fp/app/api/admin/supabase-auth-expression-conditional/route.ts",
    "fp/app/api/admin/supabase-auth-expression-post-lookup/route.ts",
    "fp/app/api/admin/supabase-auth-forward-unrelated/route.ts",
    "fp/app/api/admin/supabase-auth-forward-inner-conditional/route.ts",
    "fp/app/api/admin/supabase-auth-forward-outer-conditional/route.ts",
    "fp/app/api/admin/supabase-auth-forward-post-lookup/route.ts",
  ])("sound adversarial guard %s stays silent", (file) => {
    expect(atFile(analysis.findings, file)).toHaveLength(0);
  });

  test("direct imported guard before the boundary stays unknown, but later/conditional calls do not", () => {
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/imported-guard\/route\.ts: GET calls requireAdmin/),
      expect.stringMatching(/local-auth-unknown\/route\.ts: GET calls auth/),
    ]));
    expect(analysis.notes.some((note) => /imported-guard-after|imported-guard-conditional/.test(note))).toBe(false);
    expect(atFile(analysis.findings, "fp/app/api/admin/local-auth-unknown/route.ts")).toHaveLength(0);
  });

  test("unsupported awaited calls become coverage notes instead of privileged-operation findings", () => {
    expect(atFile(analysis.findings, "fp/app/api/admin/unsupported-awaited/route.ts")).toHaveLength(0);
    expect(analysis.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/unsupported-awaited\/route\.ts: GET calls parseRequest; privileged-operation semantics were not verified/),
    ]));
  });
});
