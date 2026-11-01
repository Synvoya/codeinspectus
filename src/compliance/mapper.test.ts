import { describe, expect, test } from "vitest";

import type { Finding } from "../types.js";
import { loadComplianceData, tagFinding } from "./mapper.js";

function osvFinding(ruleId: string, cwe: string[]): Finding {
  return {
    id: ruleId,
    fingerprint: ruleId,
    title: ruleId,
    severity: "high",
    engine: "osv-scanner",
    engines: ["osv-scanner"],
    rule_id: ruleId,
    cwe,
    location: { file: "requirements.txt", start_line: 1, end_line: 1 },
    message: "m",
    remediation: { summary: "s", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    finding_kind: "vulnerability",
    package: { ecosystem: "PyPI", name: "example", version: "1.0.0" },
  };
}

describe("dependency-vulnerability compliance tags", () => {
  test.each(["MAL-2026-2144", "PYSEC-2024-1", "GO-2024-1234", "RUSTSEC-2024-0001", "OSV-2021-1234", "mal-2026-2144"])(
    "MAL-, PYSEC-, GO-, RUSTSEC-, OSV- rule ids get the dependency-vulnerability controls (%s)",
    async (ruleId) => {
      const data = await loadComplianceData();
      // CWE-506 has no direct mapping, so the controls can only come from the rule-id context bucket.
      const tagged = tagFinding(osvFinding(ruleId, ["CWE-506"]), data);
      expect(tagged.frameworks).toEqual(expect.arrayContaining([
        { framework: "ISO27001:2022", controls: expect.arrayContaining(["A.8.8"]) },
        { framework: "NIST_CSF_2.0", controls: expect.arrayContaining(["ID.RA-01"]) },
        { framework: "EssentialEight", controls: expect.arrayContaining(["PatchApplications"]) },
      ]));
      expect(tagged.owasp_web).toContain("A06:2021");
    },
  );

  test("an advisory-looking id on a non-vulnerability finding gets no dependency controls", async () => {
    const data = await loadComplianceData();
    const tagged = tagFinding({ ...osvFinding("GO-2024-1234", ["CWE-506"]), finding_kind: "sast", engine: "opengrep", engines: ["opengrep"] }, data);
    expect(tagged.frameworks).toEqual([]);
  });
});
