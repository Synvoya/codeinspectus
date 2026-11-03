/**
 * The shipped seed dataset through the real Synvoya scanner (readers, evaluator, scanner), one true-positive
 * and one false-positive fixture per kind under fixtures/synvoya/seed/. Package kinds (vulnerability,
 * malware) take the inventory the upstream engines would list; line 0 makes the scanner locate the package
 * in the fixture lockfile, as in a real scan.
 */

import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import type { Finding } from "../types.js";
import { loadSynvoyaDataset } from "./dataset.js";
import type { InventoryPackage, PackageInventory } from "./evaluate.js";
import { runSynvoyaScan } from "./scanner.js";

const NOW = new Date("2026-11-03T12:00:00Z");
const SEED = join(process.cwd(), "fixtures", "synvoya", "seed");
const NONE: PackageInventory = { packages: [] };

let requiresM2: Set<string>;

beforeAll(async () => {
  const loaded = await loadSynvoyaDataset();
  if (!loaded.ok) throw new Error(loaded.reason);
  requiresM2 = new Set(loaded.dataset.advisories.filter((a) => a.requires === "M2").map((a) => a.id));
});

function pkg(ecosystem: string, name: string, version: string, file: string): PackageInventory {
  const entry: InventoryPackage = { ecosystem, name, version, file, line: 0, producer: "inventory:osv-scanner" };
  return { packages: [entry] };
}

async function scan(fixture: string, inventory: PackageInventory = NONE): Promise<Finding[]> {
  const result = await runSynvoyaScan(join(SEED, fixture), inventory, {}, { now: NOW });
  expect(result.info).toMatchObject({ engine: "synvoya", available: true, ran: true });
  // Nothing that needs a later milestone's reader ever produces a finding.
  for (const finding of result.findings) expect(requiresM2.has(finding.rule_id), finding.rule_id).toBe(false);
  return result.findings;
}

const ids = (findings: Finding[]): string[] => findings.map((finding) => finding.rule_id);

describe("seed dataset on the real scanner", () => {
  it("runtime: Node.js 22.20.0 is affected by the October 2026 releases; 22.23.4 is not", async () => {
    const tp = await scan("runtime-tp");
    expect(ids(tp)).toEqual(expect.arrayContaining(["SYN-2026-009", "SYN-2026-012"]));
    const node2shell = tp.find((finding) => finding.rule_id === "SYN-2026-009")!;
    expect(node2shell).toMatchObject({ severity: "critical", confidence: "high", location: { file: ".nvmrc", start_line: 1 } });
    expect(node2shell.remediation.summary).toBe("Upgrade the declared Node.js to 22.23.4 or 24.22.1 or 26.12.1 or later, then rebuild and redeploy.");
    expect(await scan("runtime-fp")).toEqual([]);
  });

  it("eol: Python 3.9 is end-of-life; 3.12.16 is supported and patched", async () => {
    const tp = await scan("eol-tp");
    const eol = tp.find((finding) => finding.rule_id === "SYN-2026-018");
    expect(eol, ids(tp).join(", ")).toBeDefined();
    expect(eol!.location.file).toBe(".python-version");
    expect(await scan("eol-fp")).toEqual([]);
  });

  it("product: a Confluence image below 8.5.4 is a finding; 9.2.26 is not", async () => {
    const tp = await scan("product-tp");
    expect(ids(tp)).toContain("SYN-2026-258");
    expect(tp.find((finding) => finding.rule_id === "SYN-2026-258")).toMatchObject({ severity: "critical", location: { file: "Dockerfile" } });
    expect(await scan("product-fp")).toEqual([]);
  });

  it("product (Adobe Commerce): a hotfix-patched line is a medium verify finding naming the bulletin", async () => {
    const tp = await scan("product-hotfix-tp");
    const sessionReaper = tp.find((finding) => finding.rule_id === "SYN-2026-084");
    expect(sessionReaper, ids(tp).join(", ")).toBeDefined();
    expect(sessionReaper!.severity).toBe("medium");
    expect(sessionReaper!.title).toMatch(/^Verify APSB25-88 is applied to Adobe Commerce 2\.4\.7-p7/);
    // Every verify-hotfix finding on a line Adobe patches is medium: a patched store is never a permanent critical.
    for (const finding of tp) expect(finding.severity, finding.rule_id).toBe("medium");
  });

  it("product (Magento Open Source): a line with no patch at all is proven by the version alone", async () => {
    const tp = await scan("product-nopatch-tp");
    const unpatched = tp.find((finding) => finding.rule_id === "SYN-2026-00701");
    expect(unpatched, ids(tp).join(", ")).toBeDefined();
    expect(unpatched!.severity).toBe("critical");
    expect(unpatched!.title).not.toMatch(/^Verify/);
    // SessionReaper is fixed in 2.4.6-p13.
    expect(ids(tp)).not.toContain("SYN-2026-08401");
  });

  it("image alias: a jenkins/jenkins tag is checked as jenkins-core; the fixed tag is not", async () => {
    const tp = await scan("image-alias-tp");
    expect(ids(tp)).toEqual(["SYN-2026-107"]);
    expect(tp[0]).toMatchObject({ package: { ecosystem: "Maven", name: "org.jenkins-ci.main:jenkins-core", version: "2.426.2" } });
    expect(await scan("image-alias-fp")).toEqual([]);
  });

  it("eol service image: postgres 13 is end-of-life; 17 is not", async () => {
    const tp = await scan("eol-image-tp");
    expect(ids(tp)).toEqual(["SYN-EOL-postgres-13"]);
    expect(await scan("eol-image-fp")).toEqual([]);
  });

  it("vulnerability: node-forge 1.3.1 is affected; 1.4.1 is fixed", async () => {
    const tp = await scan("vulnerability-tp", pkg("npm", "node-forge", "1.3.1", "package-lock.json"));
    expect(ids(tp)).toEqual(["SYN-2026-057"]);
    expect(tp[0]).toMatchObject({ location: { file: "package-lock.json", start_line: 5 }, package: { name: "node-forge", version: "1.3.1" } });
    expect(await scan("vulnerability-fp", pkg("npm", "node-forge", "1.4.1", "package-lock.json"))).toEqual([]);
  });

  it("malware: litellm 1.107.0 is malicious and says to rotate credentials; 1.106.2 is clean", async () => {
    const tp = await scan("malware-tp", pkg("PyPI", "litellm", "1.107.0", "requirements.txt"));
    expect(ids(tp)).toEqual(["SYN-2026-001"]);
    expect(tp[0]!.severity).toBe("critical");
    expect(tp[0]!.remediation.steps.some((step) => /rotate/i.test(step))).toBe(true);
    expect(await scan("malware-fp", pkg("PyPI", "litellm", "1.106.2", "requirements.txt"))).toEqual([]);
  });

  it("config and other M2 entries never fire: a mutable action tag and a Go toolchain the stdlib entries would flag", async () => {
    // golang:1.26.5 is below SYN-2026-019's 1.26.6, and tj-actions/changed-files@v45 below SYN-2026-326's 46.0.1;
    // both need M2 readers, so neither is reported.
    expect(await scan("config-fp")).toEqual([]);
  });
});
