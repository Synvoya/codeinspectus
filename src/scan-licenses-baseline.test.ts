/**
 * A 3.x scan (licences always on) is the baseline or prior of a 4.0 default scan (licences off). The Trivy
 * invocation differs only by the `license` element of `--scanners`, which must not make every Trivy absence
 * unprovable; licence findings themselves stay not re-checked. Trivy is mocked but records the real
 * invocation signatures; the other engines "ran" with nothing to report so coverage reads complete.
 */
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, test, vi } from "vitest";

import type { SarifLog } from "./sarif/types.js";

const fault = vi.hoisted(() => ({ extraVulnerability: false }));

function vulnerability(name: string, version: string, rule: string, line: number): unknown {
  return {
    ruleId: rule, ruleIndex: 0, level: "error",
    message: { text: `Package: ${name}\nInstalled Version: ${version}\nVulnerability ${rule}\nSeverity: HIGH\nFixed Version: 9.9.9\nLink: [${rule}](https://example.invalid)` },
    locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: line, endLine: line + 2 } } }],
  };
}

function licence(name: string, line: number): unknown {
  return {
    ruleId: `${name}:MIT`, ruleIndex: 1, level: "note",
    message: { text: `Artifact: package-lock.json\nLicense MIT\nPkgName: ${name}\n Classification: notice\n Path: package-lock.json` },
    locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: line, endLine: line } } }],
  };
}

vi.mock("./engines/trivy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./engines/trivy.js")>();
  return {
    ...actual,
    readTrivyDbDate: vi.fn(async () => undefined),
    runTrivy: vi.fn(async (target: string, tmp: string, scanners: Array<"vuln" | "misconfig" | "secret" | "license">) => {
      const results = [
        ...(scanners.includes("vuln") ? [vulnerability("lodash", "4.17.20", "CVE-2026-0001", 10)] : []),
        ...(scanners.includes("vuln") && fault.extraVulnerability ? [vulnerability("minimist", "0.0.8", "CVE-2026-0002", 30)] : []),
        ...(scanners.includes("license") ? [licence("handlebars", 3), licence("lodash", 5)] : []),
      ];
      return {
        engine: "trivy", version: "0.76.1", available: true, ran: true, durationMs: 1,
        componentSignatures: {
          "trivy:binary": "sha256:binary", "trivy:checks": "sha256:checks", "trivy:vulnerability-db": "sha256:db",
          ...actual.trivyInvocationSignatures(target, join(tmp, "trivy.json"), join(tmp, "trivy.sarif"), scanners),
        },
        sarif: {
          version: "2.1.0",
          runs: [{
            tool: { driver: { name: "Trivy", rules: [
              { id: "CVE-2026-0001", name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "HIGH"] } },
              { id: "CVE-2026-0002", name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "HIGH"] } },
              { id: "handlebars:MIT", name: "License", properties: { tags: ["license"] } },
              { id: "lodash:MIT", name: "License", properties: { tags: ["license"] } },
            ] } },
            results,
          }],
        } as SarifLog,
      };
    }),
  };
});
const emptyRun = (engine: string) => async () => ({
  engine, version: "1.0.0", available: true, ran: true, durationMs: 1,
  sarif: { version: "2.1.0", runs: [] } as SarifLog,
  componentSignatures: { [`${engine}:invocation`]: "sha256:invocation" },
  ...(engine === "gitleaks" ? { secretSuppression: { channels: [] } } : {}),
});
vi.mock("./engines/opengrep.js", () => ({ runOpengrep: vi.fn(emptyRun("opengrep")) }));
vi.mock("./engines/gitleaks.js", () => ({ runGitleaks: vi.fn(emptyRun("gitleaks")) }));
vi.mock("./engines/osv-scanner.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./engines/osv-scanner.js")>()),
  runOsvScanner: vi.fn(async () => ({
    info: { engine: "osv-scanner", version: "none", available: false, ran: false, finding_count: 0, duration_ms: 0 },
    applicable: false, findings: [], coverage: [], lockfiles: [], packages: [], warnings: [], componentSignatures: {},
  })),
  runOsvScannerOnSbom: vi.fn(),
}));
vi.mock("./store.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./store.js")>()),
  saveScan: vi.fn(async () => undefined),
}));

const { executeScan } = await import("./scan.js");
const { diffRescan } = await import("./rescan.js");
const { compareAgainstBaseline, evaluateNewFindingPolicy } = await import("./baseline.js");
const { assessAggregateCoverage } = await import("./export/model.js");
const { componentSignaturesMatch, TRIVY_LICENSE_TOGGLED_INVOCATION } = await import("./provenance.js");
const { trivyInvocationSignatures } = await import("./engines/trivy.js");

async function repo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-licences-baseline-"));
  await writeFile(join(dir, "package-lock.json"), "{}\n", "utf8");
  return dir;
}

type Stored = Awaited<ReturnType<typeof executeScan>>["canonical"] & { storage_schema_version: "2.0.0"; canonical_findings: true };
const stored = (scan: Awaited<ReturnType<typeof executeScan>>["canonical"]): Stored => ({ ...scan, storage_schema_version: "2.0.0", canonical_findings: true });

/** What a 3.x scan stored: no licence choice and no toggled-invocation signature. */
function as3x(scan: Stored): Stored {
  const { [TRIVY_LICENSE_TOGGLED_INVOCATION]: _toggled, ...signatures } = scan.component_signatures ?? {};
  const { include_licenses: _choice, ...config } = scan.scan_config!;
  return { ...scan, component_signatures: signatures, scan_config: config };
}

beforeEach(() => { fault.extraVulnerability = false; });

describe("a 3.x baseline against a default 4.0 scan", () => {
  test("a new vulnerable package is New and fails the policy; licence findings are not rechecked", async () => {
    const path = await repo();
    const baseline = as3x(stored((await executeScan({ path, include_licenses: true }, { persist: false })).canonical));
    fault.extraVulnerability = true;
    const fresh = stored((await executeScan({ path }, { persist: false })).canonical);
    expect(assessAggregateCoverage(baseline).aggregate, JSON.stringify(assessAggregateCoverage(baseline).evidence.filter((e) => e.state !== "covered" && e.state !== "informational"))).toBe("complete");
    expect(assessAggregateCoverage(fresh).aggregate).toBe("complete");

    const comparison = compareAgainstBaseline(baseline, fresh);

    expect(comparison.items.map((item) => [item.finding.rule_id, item.state])).toEqual(expect.arrayContaining([
      ["CVE-2026-0001", "Existing"],
      ["CVE-2026-0002", "New"],
    ]));
    expect(comparison.coverage).toBe("complete");
    expect(evaluateNewFindingPolicy(comparison, "high").exit_code).toBe(1);
  });

  test("the default 4.0 scan against a default 4.0 baseline still proves a new package New", async () => {
    const path = await repo();
    const baseline = stored((await executeScan({ path }, { persist: false })).canonical);
    fault.extraVulnerability = true;
    const fresh = stored((await executeScan({ path }, { persist: false })).canonical);

    expect(evaluateNewFindingPolicy(compareAgainstBaseline(baseline, fresh), "high").exit_code).toBe(1);
  });

  test("a licence finding the baseline never checked reads Not rechecked, not New", async () => {
    const path = await repo();
    const baseline = stored((await executeScan({ path }, { persist: false })).canonical);
    const fresh = stored((await executeScan({ path, include_licenses: true }, { persist: false })).canonical);

    const states = compareAgainstBaseline(baseline, fresh).items
      .filter((item) => item.finding.finding_kind === "license").map((item) => item.state);
    expect(states).toEqual(["Not rechecked / unknown", "Not rechecked / unknown"]);
  });
});

describe("a 3.x prior against a default 4.0 rescan", () => {
  test("a fixed vulnerability resolves while licence findings stay not_rechecked", async () => {
    const path = await repo();
    fault.extraVulnerability = true;
    const prior = as3x(stored((await executeScan({ path, include_licenses: true }, { persist: false })).canonical));
    fault.extraVulnerability = false;
    const fresh = stored((await executeScan({ path }, { persist: false })).canonical);

    const diff = diffRescan(prior, fresh);

    expect(diff.resolved.map((finding) => finding.rule_id)).toEqual(["CVE-2026-0002"]);
    expect(diff.remaining.map((finding) => finding.rule_id)).toEqual(["CVE-2026-0001"]);
    expect(diff.not_rechecked.map((finding) => finding.finding_kind)).toEqual(["license", "license"]);
  });
});

describe("the licence element of the Trivy invocation is the only thing ignored", () => {
  const sign = (scanners: Array<"vuln" | "misconfig" | "secret" | "license">) => trivyInvocationSignatures("/t", "/m/trivy.json", "/m/trivy.sarif", scanners);

  test("with and without license match; any other scanner difference does not", () => {
    const withLicence = sign(["vuln", "misconfig", "secret", "license"]);
    const without = sign(["vuln", "misconfig", "secret"]);
    const narrower = sign(["vuln", "license"]);

    expect(withLicence["trivy:invocation"]).not.toBe(without["trivy:invocation"]);
    expect(componentSignaturesMatch("trivy:invocation", withLicence, without)).toBe(true);
    expect(componentSignaturesMatch("trivy:invocation", without, withLicence)).toBe(true);
    expect(componentSignaturesMatch("trivy:invocation", withLicence, narrower)).toBe(false);
    expect(componentSignaturesMatch("trivy:invocation", without, narrower)).toBe(false);
    // A 3.x scan has only the exact signature.
    expect(componentSignaturesMatch("trivy:invocation", { "trivy:invocation": withLicence["trivy:invocation"]! }, without)).toBe(true);
  });

  test("no other component is compared leniently", () => {
    const a = { "trivy:binary": "x", [TRIVY_LICENSE_TOGGLED_INVOCATION]: "y" };
    const b = { "trivy:binary": "y", [TRIVY_LICENSE_TOGGLED_INVOCATION]: "x" };
    expect(componentSignaturesMatch("trivy:binary", a, b)).toBe(false);
    expect(componentSignaturesMatch("trivy:invocation", {}, {})).toBe(false);
  });
});
