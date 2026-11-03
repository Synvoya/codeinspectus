import { cp, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SYNVOYA_DATASET_COMPONENT, synvoyaFindingComponents } from "../provenance.js";
import { findingSchema } from "../schemas.js";
import type { DependencyCoverage } from "../types.js";
import { dedupFindings } from "../dedup.js";
import { sha256Hex } from "../util/hash.js";
import { INTERNAL_SYNVOYA_DEADLINE_ENV, SYNVOYA_MAX_CHECKED_FILES, synvoyaReaderDeadlineMs } from "./constants.js";
import { loadSynvoyaDataset } from "./dataset.js";
import type { PackageInventory } from "./evaluate.js";
import { capSynvoyaNotes, runSynvoyaScan, synvoyaUpstreamInputs } from "./scanner.js";

const readerFault = vi.hoisted(() => ({ images: false }));
vi.mock("./readers/images.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./readers/images.js")>();
  return {
    ...actual,
    readImageTags: vi.fn((...args: Parameters<typeof actual.readImageTags>) =>
      readerFault.images ? Promise.reject(new Error("injected reader failure")) : actual.readImageTags(...args)),
  };
});

const NOW = new Date("2026-11-03T12:00:00Z");
/**
 * The fixture-grade dataset these mechanism tests were written against (node 20 < 20.18.1, PHP 8.0 EOL,
 * Adobe Commerce verify-hotfix): kept apart so the shipped seed (checked in seed.test.ts) can change freely.
 */
const TEST_DATASET = join(process.cwd(), "fixtures", "synvoya", "dataset");

/** No Synvoya finding, message or note ever points at line 0. */
function expectNoLineZero(result: { findings: Array<{ message: string; title: string; location: { start_line: number } }>; notes: string[] }): void {
  for (const finding of result.findings) {
    expect(finding.location.start_line).toBeGreaterThanOrEqual(1);
    expect(finding.message).not.toMatch(/:0\b/);
    expect(finding.title).not.toMatch(/:0\b/);
  }
  for (const note of result.notes) expect(note).not.toMatch(/:0\b/);
}
const NONE: PackageInventory = { packages: [] };
const roots: string[] = [];

async function repo(files: Record<string, string>): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "ci-synvoya-scan-")));
  roots.push(root);
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(root, ...path.split("/").slice(0, -1)), { recursive: true });
    await writeFile(join(root, ...path.split("/")), content, "utf8");
  }
  return root;
}

/** A copy of the bundled dataset with extra advisories, re-digested so the loader accepts it. */
async function datasetWith(extra: Array<Record<string, unknown>>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-dataset-"));
  roots.push(dir);
  await cp(TEST_DATASET, dir, { recursive: true });
  const file = JSON.parse(await readFile(join(dir, "advisories.json"), "utf8")) as { advisories: unknown[] };
  file.advisories.push(...extra);
  const text = `${JSON.stringify(file, null, 2)}\n`;
  await writeFile(join(dir, "advisories.json"), text);
  const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { files: Record<string, string> };
  manifest.files["advisories.json"] = `sha256:${sha256Hex(text)}`;
  await writeFile(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return dir;
}

function lodashAdvisory(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "SYN-2026-900",
    slug: "lodash-test-gap",
    title: "lodash before 4.17.21 is affected by a test gap",
    kind: "vulnerability",
    aliases: ["CVE-2026-1000"],
    target: { type: "package", ecosystem: "npm", name: "lodash" },
    affected: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    fixed: ["4.17.21"],
    severity: "high",
    exploited: false,
    remediation_steps: ["Upgrade lodash to 4.17.21 or later."],
    sources: ["https://example.com/lodash-advisory"],
    status: "active",
    provisional: false,
    ...over,
  };
}

const PACKAGE_LOCK = [
  "{",
  '  "name": "app",',
  '  "lockfileVersion": 3,',
  '  "packages": {',
  '    "node_modules/lodash": {',
  '      "version": "4.17.4"',
  "    }",
  "  }",
  "}",
  "",
].join("\n");

afterEach(async () => {
  readerFault.images = false;
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("runSynvoyaScan", () => {
  it("reports declared runtime findings on a fixture repository with the engine row and dataset signature", async () => {
    const target = await repo({ ".nvmrc": "20.1.0\n", "Dockerfile": "FROM php:8.0.30-fpm\n" });
    const loaded = await loadSynvoyaDataset(TEST_DATASET);
    if (!loaded.ok) throw new Error(loaded.reason);

    const result = await runSynvoyaScan(target, Promise.resolve(NONE), {}, { datasetDir: TEST_DATASET, now: NOW });

    expect(result.info).toMatchObject({ engine: "synvoya", version: loaded.dataset.version, available: true, ran: true, finding_count: 2 });
    expect(result.info.note).toContain(`Dataset ${loaded.dataset.version}`);
    expect(result.findings.map((finding) => [finding.rule_id, finding.location.file])).toEqual([
      ["SYN-2026-001", ".nvmrc"],
      ["SYN-EOL-php-8.0", "Dockerfile"],
    ]);
    for (const finding of result.findings) expect(findingSchema.safeParse(finding).success).toBe(true);
    // Each finding records the reader that produced it.
    expect(result.findings.map((finding) => finding.producer_components)).toEqual([
      [...synvoyaFindingComponents(), "synvoya:runtime"],
      [...synvoyaFindingComponents(), "synvoya:images"],
    ]);
    expect(result.componentSignatures[SYNVOYA_DATASET_COMPONENT]).toBe(loaded.digest);
    for (const component of result.findings.flatMap((finding) => finding.producer_components ?? [])) {
      expect(result.componentSignatures[component]).toMatch(/^sha256:/);
    }
    expect(result.evidence.parsed).toEqual([".nvmrc", "Dockerfile"]);
    expect(result.evidence.checked).toEqual({
      runtime: [".nvmrc"],
      images: ["Dockerfile"],
      products: [],
      "inventory:osv-scanner": [],
      "inventory:trivy": [],
    });
    expect(result.warnings).toEqual([]);
    expectNoLineZero(result);
  });

  it("a tampered dataset makes the engine unavailable with a warning, never a silent zero", async () => {
    const dir = await datasetWith([]);
    await writeFile(join(dir, "eol.json"), `${await readFile(join(dir, "eol.json"), "utf8")} `);
    const target = await repo({ ".nvmrc": "20.1.0\n" });

    const result = await runSynvoyaScan(target, Promise.resolve(NONE), {}, { datasetDir: dir, now: NOW });

    expect(result.findings).toEqual([]);
    expect(result.info).toMatchObject({ engine: "synvoya", available: false, ran: false, finding_count: 0 });
    expect(result.info.note).toMatch(/^Synvoya gap advisories unavailable: eol\.json does not match the SHA-256 digest/);
    expect(result.warnings).toEqual([result.info.note]);
    expect(result.componentSignatures).toEqual({});
  });

  it("does not leave a rejected inventory unhandled when the dataset is unavailable", async () => {
    const dir = await datasetWith([]);
    await rm(join(dir, "aliases.json"));
    const target = await repo({});
    const result = await runSynvoyaScan(target, Promise.reject(new Error("boom")), Promise.reject(new Error("boom")), { datasetDir: dir });
    expect(result.info.available).toBe(false);
  });

  it("evaluates the engines' package inventory and points the finding at the lockfile line", async () => {
    const dir = await datasetWith([lodashAdvisory()]);
    const target = await repo({ "web/package-lock.json": PACKAGE_LOCK });
    const inventory = {
      packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "web/package-lock.json", line: 0, producer: "inventory:osv-scanner" as const }],
    };

    const result = await runSynvoyaScan(target, Promise.resolve(inventory), {}, { datasetDir: dir, now: NOW });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      rule_id: "SYN-2026-900",
      vulnerability_aliases: ["CVE-2026-1000"],
      package: { ecosystem: "npm", name: "lodash", version: "4.17.4" },
      location: { file: "web/package-lock.json", start_line: 5, end_line: 5 },
    });
    expect(result.findings[0]!.message).toMatch(/^web\/package-lock\.json:5 locks lodash@4\.17\.4\./);
    expect(result.info.note).toContain("1 locked package(s) checked");
    expect(result.findings[0]!.producer_components).toContain("synvoya:inventory:osv-scanner");
    expect(result.evidence.checked["inventory:osv-scanner"]).toEqual(["web/package-lock.json"]);
    expect(result.evidence.checked["inventory:trivy"]).toEqual([]);
    expectNoLineZero(result);
  });

  it("notes about inventory packages name the located line, never line 0", async () => {
    // An affected range the npm scheme cannot compare yields a "could not compare" note for the package.
    const dir = await datasetWith([lodashAdvisory({ affected: [{ events: [{ introduced: "0" }, { fixed: "not-a-version" }] }] })]);
    const target = await repo({ "package-lock.json": PACKAGE_LOCK });
    const inventory = { packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 0 }] };
    const result = await runSynvoyaScan(target, inventory, {}, { datasetDir: dir, now: NOW });
    expect(result.notes.some((note) => note.startsWith("package-lock.json:5: could not compare"))).toBe(true);
    expectNoLineZero(result);
  });

  it("a package whose lockfile cannot be read is reported at line 1", async () => {
    const dir = await datasetWith([lodashAdvisory()]);
    const target = await repo({});
    const inventory = { packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "gone/package-lock.json", line: 0 }] };
    const result = await runSynvoyaScan(target, inventory, {}, { datasetDir: dir, now: NOW });
    expect(result.findings[0]).toMatchObject({ location: { file: "gone/package-lock.json", start_line: 1 } });
    expect(result.findings[0]!.message).toMatch(/^gone\/package-lock\.json:1 locks/);
    expectNoLineZero(result);
  });

  it("a reader that rejects loses only its own inputs: the others are kept, with a priority note", async () => {
    readerFault.images = true;
    const target = await repo({ ".nvmrc": "20.1.0\n", "Dockerfile": "FROM php:8.0.30-fpm\n" });
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW });
    expect(result.info).toMatchObject({ available: true, ran: true });
    expect(result.findings.map((finding) => finding.rule_id)).toEqual(["SYN-2026-001"]);
    expect(result.evidence.parsed).toEqual([".nvmrc"]);
    expect(result.evidence.skipped).toContainEqual({ file: ".", reason: "malformed" });
    expect(result.notes[0]).toBe("The Synvoya image reader stopped unexpectedly; the files it reads were not checked.");
    // The failed reader has no checked set; the others keep theirs.
    expect(result.evidence.checked.images).toBeUndefined();
    expect(result.evidence.checked.runtime).toEqual([".nvmrc"]);
  });

  it("a lockfile whose packages came from a source outside the target is never a checked inventory lockfile", async () => {
    const target = await repo({ "package-lock.json": PACKAGE_LOCK });
    const inventory = {
      packages: [
        { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 1, outside: true as const, producer: "inventory:osv-scanner" as const },
        { ecosystem: "npm", name: "left-pad", version: "1.3.0", file: "app/package-lock.json", line: 2, producer: "inventory:osv-scanner" as const },
      ],
    };
    const result = await runSynvoyaScan(target, inventory, {}, { datasetDir: TEST_DATASET, now: NOW });
    expect(result.evidence.checked["inventory:osv-scanner"]).toEqual(["app/package-lock.json"]);
  });

  it("omits a checked set over the cap and says so in a priority note", async () => {
    const target = await repo({ ".nvmrc": "20.1.0\n" });
    const packages = Array.from({ length: SYNVOYA_MAX_CHECKED_FILES + 1 }, (_, index) => ({
      ecosystem: "npm",
      name: "left-pad",
      version: "1.3.0",
      file: `p${index}/package-lock.json`,
      line: 1,
      producer: "inventory:trivy" as const,
    }));
    const result = await runSynvoyaScan(target, { packages }, {}, { datasetDir: TEST_DATASET, now: NOW });
    expect(result.evidence.checked.runtime).toEqual([".nvmrc"]);
    expect(result.evidence.checked["inventory:trivy"]).toBeUndefined();
    expect(result.evidence.checked["inventory:osv-scanner"]).toEqual([]);
    expect(result.notes[0]).toBe(
      `Synvoya checked more than ${SYNVOYA_MAX_CHECKED_FILES} Trivy inventory lockfiles; they are not recorded, so a rescan cannot confirm any of their Synvoya findings fixed.`,
    );
  });

  it.each(["M2", "platform-detection"])("never evaluates an entry with requires: %s", async (requires) => {
    const dir = await datasetWith([lodashAdvisory({ requires })]);
    const target = await repo({ "package-lock.json": PACKAGE_LOCK });
    const inventory = { packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 5 }] };
    const result = await runSynvoyaScan(target, inventory, {}, { datasetDir: dir, now: NOW });
    expect(result.findings).toEqual([]);
    expect(result.info.ran).toBe(true);
  });

  it("passes the upstream DB dates: a covered entry is silent once the engine's DB is newer than covered_since", async () => {
    const covered = lodashAdvisory({ status: "covered", covered_by: "osv-scanner", covered_since: "2026-10-01" });
    const dir = await datasetWith([covered]);
    const target = await repo({ "package-lock.json": PACKAGE_LOCK });
    const inventory = { packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 5 }] };

    const fresh = await runSynvoyaScan(target, inventory, Promise.resolve({ osv: { npm: "2026-10-30T09:00:00.000Z" } }), { datasetDir: dir, now: NOW });
    expect(fresh.findings).toEqual([]);
    const stale = await runSynvoyaScan(target, inventory, { osv: { npm: "2026-09-01T00:00:00.000Z" } }, { datasetDir: dir, now: NOW });
    expect(stale.findings.map((finding) => finding.rule_id)).toEqual(["SYN-2026-900"]);
    const unknown = await runSynvoyaScan(target, inventory, {}, { datasetDir: dir, now: NOW });
    expect(unknown.findings.map((finding) => finding.rule_id)).toEqual(["SYN-2026-900"]);
  });

  describe("reader deadline", () => {
    let target: string;
    beforeEach(async () => {
      target = await repo({ ".nvmrc": "20.1.0\n", "Dockerfile": "FROM php:8.0.30-fpm\n" });
    });

    it("an expired deadline reads nothing, keeps the run, and says so in a priority note and the engine note", async () => {
      const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, deadlineMs: 0 });
      expect(result.findings).toEqual([]);
      expect(result.info).toMatchObject({ available: true, ran: true });
      expect(result.evidence.parsed).toEqual([]);
      expect(result.evidence.skipped.every((entry) => entry.reason === "deadline")).toBe(true);
      expect(result.notes[0]).toMatch(/^Synvoya readers reached their 0 s deadline; \d+ file\(s\) or folder\(s\) were not read/);
      expect(result.info.note).toMatch(/input\(s\) skipped \(\d+ deadline\)/);
    });

    it("a generous deadline changes nothing", async () => {
      const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, deadlineMs: 60_000 });
      expect(result.findings).toHaveLength(2);
      expect(result.evidence.skipped).toEqual([]);
      expect(result.notes.some((note) => note.includes("deadline"))).toBe(false);
    });
  });
});

describe("single-file targets", () => {
  const scanFile = async (files: Record<string, string>, file: string) => {
    const root = await repo(files);
    return runSynvoyaScan(join(root, ...file.split("/")), Promise.resolve(NONE), {}, { datasetDir: TEST_DATASET, now: NOW });
  };
  const notChecked = (name: string) => `Synvoya reads runtime, image and product declarations from directories; ${name} was not checked.`;

  it("reads a version-pin file target and records it as checked", async () => {
    const result = await scanFile({ ".nvmrc": "20.1.0\n", "Dockerfile": "FROM php:8.0.30-fpm\n" }, ".nvmrc");
    expect(result.findings.map((finding) => [finding.rule_id, finding.location.file, finding.location.start_line])).toEqual([["SYN-2026-001", ".nvmrc", 1]]);
    expect(result.evidence.parsed).toEqual([".nvmrc"]);
    expect(result.evidence.skipped).toEqual([]);
    expect(result.evidence.checked).toMatchObject({ runtime: [".nvmrc"], images: [], products: [] });
    expect(result.notes).not.toContain(notChecked(".nvmrc"));
  });

  it("reads a Dockerfile target", async () => {
    const result = await scanFile({ "Dockerfile": "FROM php:8.0.30-fpm\n" }, "Dockerfile");
    expect(result.findings.map((finding) => [finding.rule_id, finding.location.file])).toEqual([["SYN-EOL-php-8.0", "Dockerfile"]]);
    expect(result.evidence.checked).toMatchObject({ runtime: [], images: ["Dockerfile"], products: [] });
  });

  it("reads a workflow target as a workflow, under its .github/workflows path", async () => {
    const workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20.1.0\n";
    const result = await scanFile({ ".github/workflows/ci.yml": workflow }, ".github/workflows/ci.yml");
    expect(result.findings.map((finding) => [finding.rule_id, finding.location.file, finding.location.start_line])).toEqual([
      ["SYN-2026-001", ".github/workflows/ci.yml", 8],
    ]);
    expect(result.evidence.checked.runtime).toEqual([".github/workflows/ci.yml"]);
  });

  it("reads a wp-includes/version.php target", async () => {
    const result = await scanFile({ "wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n" }, "wp-includes/version.php");
    expect(result.evidence.parsed).toEqual(["wp-includes/version.php"]);
    expect(result.evidence.checked.products).toEqual(["wp-includes/version.php"]);
  });

  it("a file target no reader knows is a plain note, never a checked file", async () => {
    const result = await scanFile({ "README.md": "node 20.1.0\n", ".nvmrc": "20.1.0\n" }, "README.md");
    expect(result.findings).toEqual([]);
    expect(result.notes).toContain(notChecked("README.md"));
    expect(result.evidence.parsed).toEqual([]);
    expect(result.evidence.skipped).toEqual([]);
    expect(result.evidence.checked).toMatchObject({ runtime: [], images: [], products: [] });
  });

  it("a symlinked file target is skipped, not followed, and not checked", async () => {
    const root = await repo({ "real.txt": "20.1.0\n" });
    await symlink(join(root, "real.txt"), join(root, ".nvmrc"));
    const result = await runSynvoyaScan(join(root, ".nvmrc"), Promise.resolve(NONE), {}, { datasetDir: TEST_DATASET, now: NOW });
    expect(result.findings).toEqual([]);
    expect(result.evidence.skipped).toEqual([{ file: ".nvmrc", reason: "symlink" }]);
    expect(result.evidence.checked).toMatchObject({ runtime: [] });
  });
});

describe("Synvoya findings through dedup", () => {
  it("setup-node 22.1.0 and setup-dotnet 8.0.4 in one workflow: every finding survives dedup, even with a shared alias", async () => {
    const target = await repo({
      ".github/workflows/ci.yml": [
        "name: ci",
        "on: push",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/setup-node@v4",
        "        with:",
        "          node-version: 22.1.0",
        "      - uses: actions/setup-dotnet@v4",
        "        with:",
        "          dotnet-version: 8.0.4",
        "",
      ].join("\n"),
    });
    // The shipped dataset: the collision comes from real alias overlap between advisories.
    const result = await runSynvoyaScan(target, Promise.resolve(NONE), {}, { now: NOW });
    expect(result.findings).toHaveLength(4);
    const aliases = result.findings.map((finding) => new Set(finding.vulnerability_aliases ?? []));
    expect(aliases.some((left, i) => aliases.some((right, j) => i !== j && [...left].some((alias) => right.has(alias))))).toBe(true);
    const shown = dedupFindings(result.findings).findings;
    expect(shown.map((finding) => finding.fingerprint).sort()).toEqual(result.findings.map((finding) => finding.fingerprint).sort());
    for (const finding of shown) {
      const original = result.findings.find((candidate) => candidate.fingerprint === finding.fingerprint)!;
      expect(finding.vulnerability_aliases).toEqual(original.vulnerability_aliases);
      expect(finding.remediation).toEqual(original.remediation);
    }
  });
});

describe("capSynvoyaNotes", () => {
  it("keeps priority notes first and beyond the cap, deduplicates, and counts what it drops", () => {
    const others = Array.from({ length: 10 }, (_, index) => `note ${index}`);
    expect(capSynvoyaNotes(["cap", "deadline", "cap"], [...others, "note 1", "cap"], 5)).toEqual([
      "cap",
      "deadline",
      "note 0",
      "note 1",
      "… 8 more Synvoya note(s) not shown.",
    ]);
    const many = Array.from({ length: 7 }, (_, index) => `priority ${index}`);
    expect(capSynvoyaNotes(many, others, 5)).toEqual([...many, "… 10 more Synvoya note(s) not shown."]);
    expect(capSynvoyaNotes([], ["a", "b"], 5)).toEqual(["a", "b"]);
  });
});

describe("synvoyaUpstreamInputs", () => {
  const coverage = (ecosystem: string, over: Partial<DependencyCoverage> = {}): DependencyCoverage => ({
    ecosystem,
    engine: "osv-scanner",
    state: "ran",
    lockfiles: { discovered: 1, analyzed: 1 },
    packages: { resolved: 1, eligible: 1, skipped: 0 },
    database_version: "2026-10-30T09:00:00.000Z",
    matching: "osv-scanner-offline",
    limitations: [],
    ...over,
  });
  const osvInfo = { engine: "osv-scanner" as const, version: "2.7.0", available: true, ran: true, finding_count: 0, duration_ms: 1 };

  it("keeps each engine's packages under its own producer, and passes DB dates only for what ran", () => {
    const { inventory, dates } = synvoyaUpstreamInputs({
      osv: {
        info: osvInfo,
        coverage: [coverage("npm"), coverage("PyPI", { state: "unavailable", database_version: undefined }), coverage("Go", { database_version: undefined })],
        packages: [
          { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json" },
          { ecosystem: "PyPI", name: "requests", version: "2.19.0", file: "requirements.txt" },
          // A source outside the target keeps osv-scanner's file name and is never looked up: line 1.
          { ecosystem: "Go", name: "golang.org/x/net", version: "0.1.0", file: "go.mod", outside: true },
        ],
      },
      trivy: {
        ran: true,
        trivyDbDate: "2026-10-29T00:00:00Z",
        packages: [
          { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 9 },
          { ecosystem: "Packagist", name: "magento/framework", version: "103.0.7", file: "composer.lock", line: 0 },
        ],
      },
      trivyVulnerabilityScan: true,
    });
    // A package both engines list stays twice, once per producer: its finding then needs both on rescan.
    expect(inventory.packages).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 0, producer: "inventory:osv-scanner" },
      { ecosystem: "PyPI", name: "requests", version: "2.19.0", file: "requirements.txt", line: 0, producer: "inventory:osv-scanner" },
      { ecosystem: "Go", name: "golang.org/x/net", version: "0.1.0", file: "go.mod", line: 1, outside: true, producer: "inventory:osv-scanner" },
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "package-lock.json", line: 9, producer: "inventory:trivy" },
      { ecosystem: "Packagist", name: "magento/framework", version: "103.0.7", file: "composer.lock", line: 0, producer: "inventory:trivy" },
    ]);
    expect(dates).toEqual({ trivy: "2026-10-29T00:00:00Z", osv: { npm: "2026-10-30T09:00:00.000Z" } });
  });

  it("an engine that did not run contributes no packages and no DB date", () => {
    const { inventory, dates } = synvoyaUpstreamInputs({
      osv: { info: { ...osvInfo, ran: false }, coverage: [coverage("npm")], packages: [] },
      trivy: { ran: false, trivyDbDate: "2026-10-29T00:00:00Z", packages: [{ ecosystem: "npm", name: "a", version: "1.0.0", file: "yarn.lock", line: 1 }] },
      trivyVulnerabilityScan: true,
    });
    expect(inventory.packages).toEqual([]);
    expect(dates).toEqual({});
    expect(synvoyaUpstreamInputs({}).inventory.packages).toEqual([]);
  });
});

describe("internal reader-deadline override", () => {
  it("takes a whole number of milliseconds (0 is expired) and ignores anything else", () => {
    expect(synvoyaReaderDeadlineMs({})).toBe(30_000);
    expect(synvoyaReaderDeadlineMs({ [INTERNAL_SYNVOYA_DEADLINE_ENV]: "0" })).toBe(0);
    expect(synvoyaReaderDeadlineMs({ [INTERNAL_SYNVOYA_DEADLINE_ENV]: "250" })).toBe(250);
    for (const bad of ["", "-1", "1.5", "soon", "1e3", "9999999999"]) {
      expect(synvoyaReaderDeadlineMs({ [INTERNAL_SYNVOYA_DEADLINE_ENV]: bad }), bad).toBe(30_000);
    }
  });
});
