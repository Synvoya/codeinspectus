import { beforeAll, describe, expect, test } from "vitest";
import { join } from "node:path";

import type { Finding } from "../types.js";
import { runNextjsAdminRouteCheck } from "./nextjs-admin-route.js";

const CORPUS = join(process.cwd(), "fixtures", "nextjs-admin-route-corpus");
const RULE = "ci-ai-nextjs-admin-route-no-authz";
const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((finding) => finding.location.file.endsWith(suffix) && finding.rule_id === RULE);

describe("Next.js admin route authentication and authorization", () => {
  let findings: Finding[];
  beforeAll(async () => {
    findings = await runNextjsAdminRouteCheck(CORPUS);
  });

  test.each([
    ["tp/pages/api/admin/users.ts", 3, "authentication and authorization"],
    ["tp/app/api/admin/reports/route.ts", 3, "authorization"],
    ["tp/src/app/api/admin/billing/route.ts", 3, "authorization"],
    ["tp/app/api/admin/helper-definitions/route.ts", 4, "authentication and authorization"],
  ])("TP %s fires once with the missing boundary", (file, line, missing) => {
    const hits = atFile(findings, file as string);
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
    expect(hits[0]!.message).toContain(missing);
  });

  test.each([
    "fp/pages/api/admin/settings.ts",
    "fp/src/app/api/admin/audit/route.ts",
    "fixed/pages/api/admin/users.ts",
    "fp/pages/api/health.ts",
    "fp/app/api/profile/route.ts",
  ])("FP/fixed %s stays silent", (file) => {
    expect(atFile(findings, file)).toHaveLength(0);
  });

  test("emits exactly the four planted findings", () => {
    expect(findings).toHaveLength(4);
  });
});
