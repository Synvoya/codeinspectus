/**
 * Git-sourced, custom-hosted, path and SDK Pub packages are not pub.dev packages. A Trivy or
 * osv-scanner advisory for a pub.dev package with the same name is a name collision, not a finding
 * (corpus contract).
 */
import { resolve } from "node:path";
import { describe, expect, test, vi } from "vitest";
import type { Finding } from "../types.js";

// osv-scanner is mocked (absent unless a test supplies its result); Trivy runs for real when installed.
vi.mock("../engines/osv-scanner.js", () => ({
  runOsvScanner: vi.fn(async () => ({
    info: { engine: "osv-scanner", version: "unknown", available: false, ran: false, finding_count: 0, duration_ms: 0 },
    applicable: false,
    findings: [],
    coverage: [],
    componentSignatures: {},
    warnings: [],
  })),
}));

const { runScan, executeScan } = await import("../scan.js");
const { runOsvScanner } = await import("../engines/osv-scanner.js");
const { osvScannerFindingComponents } = await import("../provenance.js");

const TP = resolve(process.cwd(), "fixtures/pub-sca-corpus/tp");

function osvPubFinding(name: string, version: string, ruleId: string): Finding {
  return {
    id: `osv-${name}-${ruleId}`,
    fingerprint: `sha256:osv-${name}-${ruleId}`,
    title: `Advisory (${name}@${version})`,
    severity: "high",
    engine: "osv-scanner",
    engines: ["osv-scanner"],
    rule_id: ruleId,
    cwe: ["CWE-1395"],
    location: { file: "pubspec.lock", start_line: 1, end_line: 1 },
    message: `pubspec.lock resolves Pub package ${name}@${version}.`,
    remediation: { summary: "upgrade", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    producer_components: osvScannerFindingComponents("Pub"),
    finding_kind: "vulnerability",
    package: { ecosystem: "Pub", name, version },
  };
}

describe("Trivy Pub advisories respect native Pub source exclusions", () => {
  test("no Trivy finding is reported for a git-sourced or custom-hosted Pub package", async () => {
    const result = await runScan({ path: TP, scanners: ["vuln"] });
    if (!result.engine_details.some((engine) => engine.engine === "trivy" && engine.ran)) return; // Trivy not installed

    const collisions = result.findings.filter((finding) =>
      finding.engines.includes("trivy") && /^Package: (dio|http)\n/.test(finding.message));

    expect(collisions).toEqual([]);
    expect(result.warnings.join(" ")).toMatch(/name collision/i);
  }, 120_000);

  test("osv-scanner Pub matches on non-official packages are excluded too", async () => {
    vi.mocked(runOsvScanner).mockResolvedValueOnce({
      info: { engine: "osv-scanner", version: "2.7.0", available: true, ran: true, finding_count: 3, duration_ms: 1 },
      applicable: true,
      findings: [
        osvPubFinding("dio", "4.0.4", "CVE-2021-31402"), // git-sourced
        osvPubFinding("http", "0.9.2+3", "CVE-2020-35669"), // custom-hosted
        osvPubFinding("archive", "3.3.7", "GHSA-9v85-q87q-g4vg"), // official pub.dev: a real match
      ],
      coverage: [{
        ecosystem: "Pub",
        engine: "osv-scanner",
        state: "ran",
        lockfiles: { discovered: 1, analyzed: 1 },
        packages: { resolved: 9, eligible: 9, skipped: 0 },
        matching: "osv-scanner-offline",
        limitations: [],
      }],
      lockfiles: ["pubspec.lock"],
      componentSignatures: {},
      warnings: [],
    });

    const result = (await executeScan({ path: TP, scanners: ["vuln"] }, { persist: false })).canonical;

    const collisions = result.findings.filter((finding) =>
      (finding.engines.includes("trivy") || finding.engines.includes("osv-scanner")) &&
      ["dio", "http"].includes(finding.package?.name ?? ""));
    expect(collisions).toEqual([]);
    const archive = result.findings.filter((finding) =>
      finding.engines.includes("osv-scanner") && finding.package?.name === "archive");
    expect(archive).toHaveLength(1);
    expect(archive[0]!.engines).toContain("codeinspectus-pub");
    expect(result.warnings.join(" ")).toMatch(/name collision/i);
  }, 120_000);
});
