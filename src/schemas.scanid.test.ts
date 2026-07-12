/**
 * CG-75 / Claim 2 — scan_id input hardening.
 * Every tool input that accepts a scan_id (rescan.prior_scan_id, compliance_report.scan_id,
 * explain_finding.scan_id) must accept a real CodeInspectus-generated id and REJECT traversal /
 * absolute / arbitrary strings at the Zod boundary. The generated shape is `scan-${randomUUID()}`
 * (UUIDv4, lowercase hex) — see src/scan.ts. The regex must match that exactly and nothing looser.
 */

import { describe, test, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { rescanInput, complianceReportInput, explainFindingInput } from "./schemas.js";

const realId = (): string => `scan-${randomUUID()}`;

describe("scan_id regex — legitimate generated ids round-trip", () => {
  test("a real generated id passes on all three scan_id inputs", () => {
    const id = realId();
    expect(complianceReportInput.safeParse({ scan_id: id }).success).toBe(true);
    expect(explainFindingInput.safeParse({ scan_id: id, finding_id: "CI-0001" }).success).toBe(true);
    expect(rescanInput.safeParse({ path: "/tmp/x", prior_scan_id: id }).success).toBe(true);
  });

  test("prior_scan_id stays optional on rescan (omitted → still valid)", () => {
    expect(rescanInput.safeParse({ path: "/tmp/x" }).success).toBe(true);
  });

  test("100 freshly generated ids all pass (no flaky nibble constraint)", () => {
    for (let i = 0; i < 100; i++) {
      expect(complianceReportInput.safeParse({ scan_id: realId() }).success).toBe(true);
    }
  });
});

describe("scan_id regex — traversal / absolute / arbitrary all REJECT", () => {
  const bad = [
    "../../etc/passwd",
    "scan-../x",
    "/etc/passwd",
    "/absolute/scan-00000000-0000-4000-8000-000000000000",
    "arbitrary-string",
    "scan-not-a-uuid",
    "scan-<uuid>",
    `scan-${randomUUID()}/../x`,
    `../${"scan-00000000-0000-4000-8000-000000000000"}`,
    "",
  ];
  for (const b of bad) {
    test(`rejects ${JSON.stringify(b)} on all three inputs`, () => {
      expect(complianceReportInput.safeParse({ scan_id: b }).success).toBe(false);
      expect(explainFindingInput.safeParse({ scan_id: b, finding_id: "CI-0001" }).success).toBe(false);
      expect(rescanInput.safeParse({ path: "/tmp/x", prior_scan_id: b }).success).toBe(false);
    });
  }
});
