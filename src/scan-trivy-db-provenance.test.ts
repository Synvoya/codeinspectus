import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { TRIVY_DB_PROVENANCE_MESSAGE } from "./trivy-db-provenance.js";

let trivyComponentSignatures: Record<string, string> = {};

vi.mock("./engines/trivy.js", () => ({
  runTrivy: vi.fn(async () => ({
    engine: "trivy",
    version: "0.71.2",
    available: true,
    ran: true,
    sarif: { version: "2.1.0", runs: [] },
    durationMs: 1,
    trivyDbDate: "2026-07-15T19:04:37.151625466Z",
    componentSignatures: {
      "trivy:binary": "sha256:binary",
      ...trivyComponentSignatures,
    },
  })),
}));

vi.mock("./store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

const { runScan } = await import("./scan.js");
const { summarizeScan } = await import("./summarize.js");

async function target(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-trivy-provenance-scan-"));
  await writeFile(join(dir, "app.ts"), "export const safe = true;\n", "utf8");
  return dir;
}

beforeEach(() => {
  trivyComponentSignatures = {};
});

describe("scan orchestrator Trivy DB provenance wiring", () => {
  test("completed vuln scan without digest emits structured + human advisory and does not affect counts", async () => {
    const result = await runScan({ path: await target(), scanners: ["vuln"] });

    expect(result.trivy_db_provenance?.state).toBe("unrecorded");
    expect(summarizeScan(result)).toContain(TRIVY_DB_PROVENANCE_MESSAGE);
    expect(result.summary.total).toBe(result.findings.length);
  });

  test("completed vuln scan with digest does not nag", async () => {
    trivyComponentSignatures = { "trivy:vulnerability-db": "sha256:database" };
    const result = await runScan({ path: await target(), scanners: ["vuln"] });

    expect(result.trivy_db_provenance).toBeUndefined();
    expect(summarizeScan(result)).not.toContain(TRIVY_DB_PROVENANCE_MESSAGE);
  });

  test("AI-only scan without Trivy digest does not emit an inapplicable advisory", async () => {
    const result = await runScan({ path: await target(), scanners: ["ai"] });

    expect(result.trivy_db_provenance).toBeUndefined();
    expect(summarizeScan(result)).not.toContain(TRIVY_DB_PROVENANCE_MESSAGE);
  });
});
