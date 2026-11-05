/**
 * The shipped seed dataset through the real Synvoya scanner (readers, evaluator, scanner), one true-positive
 * and one false-positive fixture per kind under fixtures/synvoya/seed/. Package kinds (vulnerability,
 * malware) take the inventory the upstream engines would list; line 0 makes the scanner locate the package
 * in the fixture lockfile, as in a real scan.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Finding } from "../types.js";
import { loadSynvoyaDataset } from "./dataset.js";
import type { InventoryPackage, PackageInventory } from "./evaluate.js";
import { runSynvoyaScan, type SynvoyaScanOptions } from "./scanner.js";
import { writeActionsFixtureDb } from "./actions-osv-fixture.js";

const NOW = new Date("2026-11-03T12:00:00Z");
const SEED = join(process.cwd(), "fixtures", "synvoya", "seed");
const NONE: PackageInventory = { packages: [] };

/** Entries still waiting for a reader (SYN-2026-070, SYN-2026-150): they never produce a finding. */
let waiting: Set<string>;
const scratch: string[] = [];
/** The developer's installed GitHub Actions database is never read: no database unless a test installs the fixture one. */
let noActionsDb: NonNullable<SynvoyaScanOptions["actionsDb"]>;

beforeAll(async () => {
  const loaded = await loadSynvoyaDataset();
  if (!loaded.ok) throw new Error(loaded.reason);
  waiting = new Set(loaded.dataset.advisories.filter((a) => a.requires !== undefined).map((a) => a.id));
  const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-seed-actions-"));
  scratch.push(dir);
  noActionsDb = { zipPath: join(dir, "no-such-db", "all.zip"), readRecord: async () => undefined };
});

afterAll(async () => {
  await Promise.all(scratch.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function pkg(ecosystem: string, name: string, version: string, file: string): PackageInventory {
  const entry: InventoryPackage = { ecosystem, name, version, file, line: 0, producer: "inventory:osv-scanner" };
  return { packages: [entry] };
}

async function scanFull(fixture: string, inventory: PackageInventory = NONE, options: SynvoyaScanOptions = {}) {
  const result = await runSynvoyaScan(join(SEED, fixture), inventory, {}, { now: NOW, actionsDb: noActionsDb, ...options });
  expect(result.info).toMatchObject({ engine: "synvoya", available: true, ran: true });
  // An entry that still waits for a reader never produces a finding.
  for (const finding of result.findings) expect(waiting.has(finding.rule_id), finding.rule_id).toBe(false);
  return result;
}

async function scan(fixture: string, inventory: PackageInventory = NONE): Promise<Finding[]> {
  return (await scanFull(fixture, inventory)).findings;
}

const placed = (findings: Finding[]): string[] => findings.map((finding) => `${finding.rule_id} ${finding.location.file}:${finding.location.start_line}`).sort();

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

  it("go stdlib: golang:1.26.5 is below the August and October 2026 fixes; 1.27.3 is not", async () => {
    const tp = await scan("go-tp");
    expect(placed(tp)).toEqual(["SYN-2026-019 Dockerfile:1", "SYN-2026-020 Dockerfile:1"]);
    const august = tp.find((finding) => finding.rule_id === "SYN-2026-019")!;
    expect(august).toMatchObject({ severity: "high", confidence: "high" });
    expect(august.package).toBeUndefined();
    expect(august.vulnerability_aliases).toEqual(expect.arrayContaining(["GO-2026-6088", "CVE-2026-56859"]));
    expect(august.remediation.summary).toBe("Upgrade the declared Go to 1.25.13 or 1.26.6 or 1.27.0 or later, then rebuild and redeploy.");
    expect(await scan("go-fp")).toEqual([]);
  });

  it("go stdlib: a go.mod toolchain line is declared at its own line; the go minimum is not", async () => {
    // toolchain go1.26.5 (line 5) is a toolchain the stdlib advisories flag; `go 1.26` (line 3) names no toolchain.
    expect(placed(await scan("go-mod-tp"))).toEqual(["SYN-2026-019 go.mod:5", "SYN-2026-020 go.mod:5"]);
  });

  it("go stdlib (CVE-2020-0601) is Windows-only and waits for platform detection: a Linux golang image never gets it", async () => {
    for (const fixture of ["go-windows-tp", "go-windows-fp"]) {
      expect((await scan(fixture)).map((finding) => finding.rule_id), fixture).not.toContain("SYN-2026-219");
    }
    // The image is still judged by the entries that do not depend on the OS: 1.12.9 is below the 2026 fixes.
    expect(placed(await scan("go-windows-tp"))).toEqual(expect.arrayContaining(["SYN-2026-019 Dockerfile:1"]));
  });

  it("github actions without the OSV database: the dataset's own entries are findings at the uses: line; fixed releases and the fixing commit are not", async () => {
    const tp = await scanFull("actions-tp");
    expect(placed(tp.findings)).toEqual([
      "SYN-2026-068 .github/workflows/ci.yml:6", "SYN-2026-069 .github/workflows/ci.yml:7", "SYN-2026-07601 .github/workflows/ci.yml:9",
      "SYN-2026-076 .github/workflows/ci.yml:8", "SYN-2026-077 .github/workflows/ci.yml:10", "SYN-2026-326 .github/workflows/ci.yml:11",
    ].sort());
    const publish = tp.findings.find((finding) => finding.rule_id === "SYN-2026-068")!;
    expect(publish).toMatchObject({ engine: "synvoya", severity: "critical", confidence: "high", package: { ecosystem: "GitHub Actions", name: "pypa/gh-action-pypi-publish", version: "v1.14.2" } });
    expect(publish.remediation.summary).toBe("Update pypa/gh-action-pypi-publish to 1.14.3 or later, pinned by its full commit SHA.");
    expect(publish.producer_components).toContain("synvoya:actions");
    expect(publish.vulnerability_aliases).toContain("GHSA-5xjx-3w67-w9x9");
    // No database was read, so nothing about these workflow files is claimed as re-checked and no coverage is reported.
    expect(tp.evidence.checked.actions).toEqual([]);
    expect(tp.actionsCoverage).toBeUndefined();
    const fp = await scanFull("actions-fp");
    expect(fp.findings).toEqual([]);
  });

  it("github actions with the OSV database: the database's finding stands once and gains Synvoya's fix; entries the database lacks stand alone", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-seed-actions-db-"));
    scratch.push(dir);
    const { zipPath, record } = await writeActionsFixtureDb(dir);
    const tp = await scanFull("actions-tp", NONE, { actionsDb: { zipPath, readRecord: async () => record } });
    // pypa/gh-action-pypi-publish and tj-actions/changed-files are in the database (GHSA); the other four are not.
    expect(placed(tp.findings)).toEqual([
      "GHSA-5xjx-3w67-w9x9 .github/workflows/ci.yml:6", "GHSA-mrrh-fwg8-r2c3 .github/workflows/ci.yml:11",
      "SYN-2026-069 .github/workflows/ci.yml:7", "SYN-2026-07601 .github/workflows/ci.yml:9",
      "SYN-2026-076 .github/workflows/ci.yml:8", "SYN-2026-077 .github/workflows/ci.yml:10",
    ].sort());
    const upstream = tp.findings.find((finding) => finding.rule_id === "GHSA-mrrh-fwg8-r2c3")!;
    expect(upstream.remediation.steps).toEqual(expect.arrayContaining([expect.stringMatching(/^Synvoya SYN-2026-326: /)]));
    expect(upstream.producer_components).toContain("osv-scanner:vulnerability-db:GitHub Actions");
    // The dataset's own finding does not depend on the installed database.
    const own = tp.findings.find((finding) => finding.rule_id === "SYN-2026-069")!;
    expect(own.producer_components).toContain("synvoya:dataset");
    expect(own.producer_components).not.toContain("osv-scanner:vulnerability-db:GitHub Actions");
    expect((await scanFull("actions-fp", NONE, { actionsDb: { zipPath, readRecord: async () => record } })).findings).toEqual([]);
  });

  it("github actions: a commit pin is never a guessed finding", async () => {
    const result = await scanFull("actions-sha-fp");
    expect(result.findings).toEqual([]);
    expect(result.notes.join("\n")).toMatch(/tj-actions\/changed-files@0e58ed8671d6 is pinned to a commit; SYN-2026-326 has no commit list/);
    expect(result.evidence.checked.actions).toEqual([]);
  });

  it("config and the other entries still waiting never fire: mutable action tags of actions without advisories", async () => {
    // SYN-2026-070 (mutable tags) is reported as one info note by the Actions reader, never as a finding.
    const result = await scanFull("config-fp");
    expect(result.findings).toEqual([]);
    expect(result.notes.join("\n")).toMatch(/2 third-party GitHub Actions reference\(s\) are not pinned to a full commit SHA/);
  });
});
