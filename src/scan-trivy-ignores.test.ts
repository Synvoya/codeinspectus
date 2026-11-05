import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";

vi.mock("./engines/trivy.js", () => ({
  readTrivyDbDate: vi.fn(async () => undefined),
  runTrivy: vi.fn(async () => ({
    engine: "trivy", version: "0.76.1", available: true, ran: true,
    sarif: { version: "2.1.0", runs: [] }, durationMs: 1, componentSignatures: { "trivy:binary": "sha256:binary" },
  })),
}));
vi.mock("./store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

const { executeScan } = await import("./scan.js");
const { createJsonExport } = await import("./export/model.js");

async function target(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-trivy-ignores-scan-"));
  await writeFile(join(dir, "main.tf"), "#trivy:ignore:*\nresource \"aws_s3_bucket\" \"a\" {}\n", "utf8");
  return dir;
}

// Review I-6: an in-source Trivy ignore is disclosed like gitleaks:allow and lowers coverage.
describe("Trivy inline ignores in a scan", () => {
  test("a misconfiguration scan warns and reads partial", async () => {
    const { canonical } = await executeScan({ path: await target(), scanners: ["misconfig"] }, { persist: false });
    const warning = "Trivy misconfiguration coverage unverified: 1 trivy:ignore or tfsec:ignore comment(s) in 1 file(s) " +
      "can hide misconfiguration findings, and Trivy cannot be told to disregard them: main.tf.";

    expect(canonical.warnings).toContain(warning);
    const coverage = createJsonExport({ ...canonical, storage_schema_version: "2.0.0", canonical_findings: true }).coverage;
    expect(coverage.evidence).toContainEqual(expect.objectContaining({ component: "scan-pipeline", state: "partial", detail: warning }));
  });

  test("a scan without the misconfiguration scanner does not look", async () => {
    const { canonical } = await executeScan({ path: await target(), scanners: ["vuln"] }, { persist: false });
    expect(canonical.warnings.some((warning) => warning.startsWith("Trivy misconfiguration coverage"))).toBe(false);
  });
});
