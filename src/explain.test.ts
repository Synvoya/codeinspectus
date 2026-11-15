import { beforeEach, describe, expect, test, vi } from "vitest";

import type { StoredScanResult } from "./store.js";
import type { Finding } from "./types.js";

const stored = new Map<string, StoredScanResult>();
vi.mock("./store.js", () => ({ getScan: async (id: string) => stored.get(id) }));

const { explainFinding } = await import("./explain.js");

const LEGACY_SCAN = "scan-00000000-0000-4000-8000-000000000040";
const NEW_SCAN = "scan-00000000-0000-4000-8000-000000000041";

function finding(id: string): Finding {
  return {
    id, fingerprint: `fp-${id}`, title: "Dangerous eval", severity: "high", engine: "opengrep", engines: ["opengrep"],
    rule_id: "ci-baseline-dangerous-eval", cwe: ["CWE-95"], location: { file: "app.js", start_line: 3, end_line: 3 },
    message: "eval of request input", remediation: { summary: "Remove eval.", steps: [], references: [] }, frameworks: [], confidence: "high",
  };
}

function scan(scanId: string, ids: string[]): StoredScanResult {
  return { scan_id: scanId, findings: ids.map(finding) } as unknown as StoredScanResult;
}

describe("explain_finding across the 4.1 display-id change", () => {
  beforeEach(() => {
    stored.clear();
    stored.set(LEGACY_SCAN, scan(LEGACY_SCAN, ["CI-0001", "CI-0002"]));
    stored.set(NEW_SCAN, scan(NEW_SCAN, ["CI-4b53368c3f", "CI-94ec2858d9"]));
  });

  test("a stored 4.0-style scan still resolves its positional id", async () => {
    const result = await explainFinding({ scan_id: LEGACY_SCAN, finding_id: "CI-0001" });
    expect(result.finding.id).toBe("CI-0001");
  });

  test("a 4.1 scan resolves its fingerprint-derived id", async () => {
    const result = await explainFinding({ scan_id: NEW_SCAN, finding_id: "CI-94ec2858d9" });
    expect(result.finding.fingerprint).toBe("fp-CI-94ec2858d9");
  });

  test("a 4.0 id asked of a 4.1 scan errors with the hint before the available ids", async () => {
    await expect(explainFinding({ scan_id: NEW_SCAN, finding_id: "CI-0007" })).rejects.toThrow(
      `Finding 'CI-0007' not found in scan '${NEW_SCAN}'. Ids like CI-0007 come from scans stored before CodeInspectus 4.1; ` +
        "this scan's ids are derived from each finding's fingerprint. Available ids: CI-4b53368c3f, CI-94ec2858d9.",
    );
  });

  test("a 4.1 id asked of a 4.0 scan errors with the other hint", async () => {
    await expect(explainFinding({ scan_id: LEGACY_SCAN, finding_id: "CI-4b53368c3f" })).rejects.toThrow(
      "This scan was stored before CodeInspectus 4.1 and uses positional ids such as CI-0001. Available ids: CI-0001, CI-0002.",
    );
  });
});
