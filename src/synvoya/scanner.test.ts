import { cp, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
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
import { runOsvScannerOnSbom } from "../engines/osv-scanner.js";
import { writeActionsFixtureDb, zipEntries } from "./actions-osv-fixture.js";

const readerFault = vi.hoisted(() => ({ images: false, libraries: false, actions: false }));
vi.mock("./readers/actions.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./readers/actions.js")>();
  return {
    ...actual,
    readActionReferences: vi.fn((...args: Parameters<typeof actual.readActionReferences>) =>
      readerFault.actions ? Promise.reject(new Error("injected reader failure")) : actual.readActionReferences(...args)),
  };
});
vi.mock("./readers/libraries.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./readers/libraries.js")>();
  return {
    ...actual,
    readLibraries: vi.fn((...args: Parameters<typeof actual.readLibraries>) =>
      readerFault.libraries ? Promise.reject(new Error("injected reader failure")) : actual.readLibraries(...args)),
  };
});
vi.mock("./readers/images.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./readers/images.js")>();
  return {
    ...actual,
    readImageTags: vi.fn((...args: Parameters<typeof actual.readImageTags>) =>
      readerFault.images ? Promise.reject(new Error("injected reader failure")) : actual.readImageTags(...args)),
  };
});

/**
 * The osv-scanner process boundary for the vendored-library SBOM: what the fake saw, and what it answers. The
 * real argument building, overlay and output mapping are tested in osv-scanner.test.ts and by eval E87.
 */
const sbomRun = vi.hoisted(() => ({
  answer: "ran" as "ran" | "failed" | "unavailable" | "incomplete",
  vulnerable: ["jquery@1.12.4"],
  /** Ecosystems whose OSV database is not installed. */
  missing: [] as string[],
  seen: [] as Array<{
    sbomPath: string;
    workDir: string;
    components: Array<{ name: string; version: string; purl: string; "bom-ref": string }>;
    options: { ecosystems: readonly string[]; expected: ReadonlyArray<{ ecosystem: string; name: string; version: string }> };
  }>,
}));
vi.mock("../engines/osv-scanner.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../engines/osv-scanner.js")>();
  const { readFile } = await import("node:fs/promises");
  const { osvSbomFindingComponents } = await import("../provenance.js");
  return {
    ...actual,
    runOsvScannerOnSbom: vi.fn(async (sbomPath: string, workDir: string, options: Parameters<typeof actual.runOsvScannerOnSbom>[2]) => {
      const components = (JSON.parse(await readFile(sbomPath, "utf8")) as { components: Array<{ name: string; version: string; purl: string; "bom-ref": string }> }).components;
      sbomRun.seen.push({ sbomPath, workDir, components, options: { ecosystems: options.ecosystems, expected: options.expected } });
      const missingDatabases = options.ecosystems.filter((ecosystem) => sbomRun.missing.includes(ecosystem) || sbomRun.answer === "unavailable");
      const base = { version: "2.7.0", missingDatabases, findings: [], warnings: [] as string[], complete: false };
      if (missingDatabases.length === options.ecosystems.length) return { ...base, state: "unavailable" as const, reason: `the OSV ${missingDatabases.join(", ")} database is not installed` };
      if (sbomRun.answer === "failed") return { ...base, state: "failed" as const, reason: `osv-scanner timed out before producing results (in ${workDir}).`.replace(workDir, "<managed-temp>") };
      const ECOSYSTEMS: Record<string, string> = { npm: "npm", composer: "Packagist", golang: "Go" };
      const findings = [...new Map(components.map((c) => [`${c.name}@${c.version}`, ECOSYSTEMS[c.purl.slice(4, c.purl.indexOf("/"))]!])).entries()]
        .filter(([label, ecosystem]) => sbomRun.vulnerable.includes(label) && !missingDatabases.includes(ecosystem as never))
        .flatMap(([label, ecosystem]) => {
          const [name, version] = [label.slice(0, label.lastIndexOf("@")), label.slice(label.lastIndexOf("@") + 1)];
          return options.locate({ ecosystem, name, version }).map((at) => ({
            id: `fp-${at.file}`, fingerprint: `fp-${at.file}`, title: `XSS in ${label}`, severity: "medium" as const,
            engine: "osv-scanner" as const, engines: ["osv-scanner" as const], rule_id: "CVE-2020-11022", cwe: ["CWE-1395"], owasp_web: ["A06:2021"],
            location: { file: at.file, start_line: at.line, end_line: at.line }, message: `${at.lead} CVE-2020-11022 ...`,
            remediation: { summary: "Upgrade.", steps: ["Upgrade."], references: [] }, frameworks: [], confidence: "high" as const,
            producer_components: osvSbomFindingComponents(ecosystem), finding_kind: "vulnerability" as const,
            package: { ecosystem, name: at.declaredName ?? name, version },
          }));
        });
      if (sbomRun.answer === "incomplete") return { ...base, state: "ran" as const, findings, warnings: ["osv-scanner stopped at an OSV database it could not load"] };
      return { ...base, state: "ran" as const, findings, complete: true };
    }),
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
  readerFault.libraries = false;
  readerFault.actions = false;
  sbomRun.answer = "ran";
  sbomRun.vulnerable = ["jquery@1.12.4"];
  sbomRun.missing = [];
  sbomRun.seen = [];
  vi.mocked(runOsvScannerOnSbom).mockClear();
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
      vendored: [],
      // The image reader feeds the SBOM (golang images): a Dockerfile with no Go image is checked trivially.
      "sbom:osv-scanner": ["Dockerfile"],
      actions: [],
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

    // Field run 2026-11-05: a deadline hit lost 7 findings on a rerun while coverage still read complete for Synvoya.
    it("an expired deadline reads nothing, keeps the run, and says so in a partial-coverage warning and the engine note", async () => {
      const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, deadlineMs: 0 });
      expect(result.findings).toEqual([]);
      expect(result.info).toMatchObject({ available: true, ran: true });
      expect(result.evidence.parsed).toEqual([]);
      expect(result.evidence.skipped.every((entry) => entry.reason === "deadline")).toBe(true);
      const deadline = result.warnings.filter((warning) => warning.includes("deadline"));
      expect(deadline).toHaveLength(1);
      expect(deadline[0]).toMatch(/^Synvoya coverage partial: the readers reached their 0 s deadline; \d+ file\(s\) or folder\(s\) were not read/);
      expect(result.notes.some((note) => note.includes("deadline"))).toBe(false);
      expect(result.info.note).toMatch(/input\(s\) skipped \(\d+ deadline\)/);
    });

    it("a generous deadline changes nothing", async () => {
      const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, deadlineMs: 60_000 });
      expect(result.findings).toHaveLength(2);
      expect(result.evidence.skipped).toEqual([]);
      expect(result.notes.some((note) => note.includes("deadline"))).toBe(false);
      expect(result.warnings.some((warning) => warning.includes("deadline"))).toBe(false);
    });
  });
});

describe("single-file targets", () => {
  const scanFile = async (files: Record<string, string>, file: string) => {
    const root = await repo(files);
    return runSynvoyaScan(join(root, ...file.split("/")), Promise.resolve(NONE), {}, { datasetDir: TEST_DATASET, now: NOW });
  };
  const notChecked = (name: string) => `Synvoya reads runtime, image, product and library declarations from directories; ${name} was not checked.`;

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

describe("vendored libraries", () => {
  const LIBRARY_REPO = {
    "public/js/jquery-1.12.4.min.js": "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nvar a;\n",
    "public/index.html": '<html>\n<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"></script>\n' +
      '<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script>\n</html>\n',
    "public/old.html": '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>\n',
    "public/latest.html": '<script src="https://unpkg.com/jquery@latest/dist/jquery.js"></script>\n',
  };
  const exportCoverageWarning = /partial|unavailable|did not run|excluded|bounded|truncat|dropped|unverified|incompat|not.re.?check/i;
  const scanIn = async (files: Record<string, string>, options: { tmpDir?: string; deadlineMs?: number } = {}) => {
    const target = await repo(files);
    const tmpDir = options.tmpDir ?? (await mkdtemp(join(tmpdir(), "ci-synvoya-scan-tmp-")));
    roots.push(tmpDir);
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, tmpDir, ...(options.deadlineMs !== undefined ? { deadlineMs: options.deadlineMs } : {}) });
    return { result, tmpDir, target };
  };
  const noTmpPath = (result: Awaited<ReturnType<typeof runSynvoyaScan>>, tmpDir: string) => {
    const text = JSON.stringify({ findings: result.findings, sbom: result.sbomFindings, notes: result.notes, warnings: result.warnings, gaps: result.coverageGaps, info: result.info });
    expect(text).not.toContain(tmpDir);
    expect(text).not.toContain("inventory.cdx.json");
  };

  it("sends exact libraries to osv-scanner as an SBOM in the scan's temp dir and reports findings at their declarations", async () => {
    const { result, tmpDir } = await scanIn(LIBRARY_REPO);
    expect(sbomRun.seen).toHaveLength(1);
    expect(sbomRun.seen[0]!.sbomPath).toBe(join(tmpDir, "synvoya-sbom", "inventory.cdx.json"));
    expect(sbomRun.seen[0]!.workDir).toBe(join(tmpDir, "synvoya-sbom"));
    expect(sbomRun.seen[0]!.components.map((c) => c.purl)).toEqual([
      "pkg:npm/%40popperjs/core@2.11.8",
      "pkg:npm/jquery@1.12.4",
      "pkg:npm/jquery@1.12.4",
    ]);
    // Each package osv-scanner names once is reported at every declaration, never at the SBOM.
    expect(result.sbomFindings.map((f) => `${f.rule_id}@${f.location.file}:${f.location.start_line}`)).toEqual([
      "CVE-2020-11022@public/js/jquery-1.12.4.min.js:1",
      "CVE-2020-11022@public/old.html:1",
    ]);
    expect(result.sbomFindings[0]!.message).toMatch(/^public\/js\/jquery-1\.12\.4\.min\.js:1 ships npm package jquery@1\.12\.4 as a vendored or CDN-loaded library \(banner\)\./);
    expect(result.sbomFindings.every((f) => f.producer_components?.includes("synvoya:sbom:osv-scanner"))).toBe(true);
    // The floating @3 is a note and keeps its file out of the SBOM set (osv-scanner never checked it, review C1);
    // the unresolved `latest` keeps its file out of both sets.
    expect(result.notes.some((n) => n.startsWith('public/index.html:3: cdn-url names jquery "3", not an exact version'))).toBe(true);
    expect(result.evidence.checked.vendored).toEqual(["public/index.html", "public/js/jquery-1.12.4.min.js", "public/old.html"]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["public/js/jquery-1.12.4.min.js", "public/old.html"]);
    expect(result.componentSignatures["osv-scanner:sbom-invocation"]).toMatch(/^sha256:/);
    expect(result.coverageGaps).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.info.note).toContain("osv-scanner checked 3 exact vendored libraries");
    noTmpPath(result, tmpDir);
  });

  it("reports a library once per vendored root, at its shallowest file, naming up to 5 others (BookStack TinyMCE)", async () => {
    sbomRun.vulnerable = ["tinymce@6.8.4"];
    const banner = "/**\n * TinyMCE version 6.8.4 (2024-06-19)\n */\n!function(){}();\n";
    const plugins = ["anchor", "code", "image", "link", "lists", "media", "table"];
    const { result } = await scanIn({
      "public/libs/tinymce/tinymce.min.js": banner,
      "public/libs/tinymce/models/dom/model.min.js": banner,
      ...Object.fromEntries(plugins.map((name) => [`public/libs/tinymce/plugins/${name}/plugin.min.js`, banner])),
      // A second install under another root is its own finding.
      "static/tinymce/tinymce.min.js": banner,
    });
    expect(result.sbomFindings.map((f) => `${f.location.file}:${f.location.start_line}`)).toEqual([
      "public/libs/tinymce/tinymce.min.js:1",
      "static/tinymce/tinymce.min.js:1",
    ]);
    const [bookstack, other] = result.sbomFindings;
    expect(bookstack!.message).toMatch(
      /^public\/libs\/tinymce\/tinymce\.min\.js:1 ships npm package tinymce@6\.8\.4 as a vendored or CDN-loaded library \(banner\); 8 more files under public\/libs\/tinymce\/ ship the same version: public\/libs\/tinymce\/models\/dom\/model\.min\.js:1, public\/libs\/tinymce\/plugins\/anchor\/plugin\.min\.js:1, public\/libs\/tinymce\/plugins\/code\/plugin\.min\.js:1, public\/libs\/tinymce\/plugins\/image\/plugin\.min\.js:1, public\/libs\/tinymce\/plugins\/link\/plugin\.min\.js:1 and 3 more\./,
    );
    expect(other!.message).toMatch(/^static\/tinymce\/tinymce\.min\.js:1 ships npm package tinymce@6\.8\.4 as a vendored or CDN-loaded library \(banner\)\. /);
    // Every declaring file is still in the checked set.
    expect(result.evidence.checked["sbom:osv-scanner"]).toHaveLength(10);
  });

  it("skips the second run entirely when there is no exact library, and still records what the reader checked", async () => {
    const { result } = await scanIn({
      "public/index.html": '<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script>\n',
      "public/plain.html": "<p>no library</p>\n",
      ".nvmrc": "20.1.0\n",
    });
    expect(runOsvScannerOnSbom).not.toHaveBeenCalled();
    // A file whose only library is floating was never checked by osv-scanner (review C1); a file with none is.
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["public/plain.html"]);
    expect(result.coverageGaps).toEqual([]);
    expect(result.componentSignatures["osv-scanner:sbom-invocation"]).toMatch(/^sha256:/);
  });

  it("no osv-scanner or npm database: the vendored-js gap names the inputs, and the SBOM set is omitted", async () => {
    sbomRun.answer = "unavailable";
    const { result, tmpDir } = await scanIn(LIBRARY_REPO);
    expect(result.coverageGaps).toEqual([{
      id: "vendored-js",
      files: 3,
      examples: ["public/index.html (@popperjs/core@2.11.8)", "public/js/jquery-1.12.4.min.js (jquery@1.12.4)", "public/old.html (jquery@1.12.4)"],
    }]);
    expect(result.sbomFindings).toEqual([]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
    expect(result.evidence.checked.vendored).toBeDefined();
    expect(result.info.note).toContain("3 exact vendored libraries not checked");
    noTmpPath(result, tmpDir);
  });

  it("a failed run is a warning the export counts as partial, never findings or a checked set; the reader set stays", async () => {
    sbomRun.answer = "failed";
    const { result, tmpDir } = await scanIn(LIBRARY_REPO);
    expect(result.warnings).toEqual(["Synvoya SBOM check did not run: osv-scanner timed out before producing results (in <managed-temp>)."]);
    expect(result.warnings[0]).toMatch(exportCoverageWarning);
    expect(result.sbomFindings).toEqual([]);
    expect(result.coverageGaps).toEqual([]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
    expect(result.evidence.checked.vendored).toEqual(["public/index.html", "public/js/jquery-1.12.4.min.js", "public/old.html"]);
    noTmpPath(result, tmpDir);
  });

  it("an incomplete run keeps its findings but is a partial warning and records no SBOM set", async () => {
    sbomRun.answer = "incomplete";
    const { result } = await scanIn(LIBRARY_REPO);
    expect(result.sbomFindings).toHaveLength(2);
    expect(result.warnings).toEqual(["Synvoya SBOM check partial: osv-scanner stopped at an OSV database it could not load"]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
  });

  it("a library reader that rejects omits the library and SBOM sets and runs no SBOM check (review m5)", async () => {
    readerFault.libraries = true;
    const { result } = await scanIn({ ...LIBRARY_REPO, ".nvmrc": "20.1.0\n" });
    expect(runOsvScannerOnSbom).not.toHaveBeenCalled();
    expect(result.evidence.checked.vendored).toBeUndefined();
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
    expect(result.evidence.checked.runtime).toEqual([".nvmrc"]);
    expect(result.notes).toContain("The Synvoya library reader stopped unexpectedly; the files it reads were not checked.");
  });

  it("a deadline skip omits the library and SBOM sets", async () => {
    const { result } = await scanIn(LIBRARY_REPO, { deadlineMs: 0 });
    expect(result.evidence.checked.vendored).toBeUndefined();
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
    expect(result.warnings[0]).toContain("runtime, image, product, library and GitHub Actions declarations");
  });

  it("a library file read only in part is in neither set", async () => {
    const big = `/*! jQuery v1.12.4 | (c) jQuery Foundation */\n${"var a=1;\n".repeat(140_000)}`;
    const { result } = await scanIn({ "public/js/jquery.min.js": big });
    expect(result.evidence.skipped).toContainEqual({ file: "public/js/jquery.min.js", reason: "capped" });
    expect(result.sbomFindings.map((f) => f.location.file)).toEqual(["public/js/jquery.min.js"]);
    expect(result.evidence.checked.vendored).toEqual([]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual([]);
  });

  it("without a scan temp dir it uses a private one and removes it", async () => {
    const target = await repo(LIBRARY_REPO);
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW });
    expect(result.sbomFindings).toHaveLength(2);
    const workDir = sbomRun.seen[0]!.workDir;
    await expect(lstat(workDir)).rejects.toThrow();
  });

  it("a Synvoya npm advisory for a vendored library records the vendored producer", async () => {
    const dir = await datasetWith([lodashAdvisory({ id: "SYN-2026-901", target: { type: "package", ecosystem: "npm", name: "jquery" }, aliases: ["CVE-2026-1001"], affected: [{ events: [{ introduced: "0" }, { fixed: "3.5.0" }] }], fixed: ["3.5.0"] })]);
    const target = await repo({ "public/js/jquery-1.12.4.min.js": "var a;\n" });
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: dir, now: NOW });
    expect(result.findings.map((f) => [f.rule_id, f.location.file, f.producer_components?.at(-1)])).toEqual([
      ["SYN-2026-901", "public/js/jquery-1.12.4.min.js", "synvoya:vendored"],
    ]);
  });
});

describe("Magento editions through the SBOM", () => {
  const lock = (packages: Array<[string, string]>): string => `${JSON.stringify({
    _readme: ["This file locks the dependencies of your project to a known state"],
    packages: packages.map(([name, version]) => ({ name, version, type: "metapackage" })),
    "packages-dev": [],
  }, null, 4)}\n`;
  const STORE = lock([["magento/magento2-base", "2.4.7-p2"], ["magento/product-community-edition", "2.4.7-p2"]]);
  /** The test dataset with the shipped Magento package aliases, re-digested. */
  async function datasetWithAliases(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-dataset-"));
    roots.push(dir);
    await cp(TEST_DATASET, dir, { recursive: true });
    const shipped = JSON.parse(await readFile(join(process.cwd(), "detection-db", "synvoya", "aliases.json"), "utf8")) as { packages: Record<string, string> };
    const file = JSON.parse(await readFile(join(dir, "aliases.json"), "utf8")) as { packages: Record<string, string> };
    file.packages = shipped.packages;
    const text = `${JSON.stringify(file, null, 2)}\n`;
    await writeFile(join(dir, "aliases.json"), text);
    const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { files: Record<string, string> };
    manifest.files["aliases.json"] = `sha256:${sha256Hex(text)}`;
    await writeFile(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    return dir;
  }
  const scanStore = async (files: Record<string, string>) => {
    const target = await repo(files);
    const tmpDir = await mkdtemp(join(tmpdir(), "ci-synvoya-scan-tmp-"));
    roots.push(tmpDir);
    return runSynvoyaScan(target, NONE, {}, { datasetDir: await datasetWithAliases(), now: NOW, tmpDir });
  };
  /** 1-based line of the `"name": "<name>"` key in a lock. */
  const lineOf = (text: string, name: string): number => text.split("\n").findIndex((line) => line.includes(`"name": "${name}"`)) + 1;

  it("the shipped alias table maps the locked Magento Open Source packages to the advisory package name", async () => {
    const shipped = JSON.parse(await readFile(join(process.cwd(), "detection-db", "synvoya", "aliases.json"), "utf8")) as { packages: Record<string, string> };
    expect(shipped.packages).toEqual({
      "Packagist:magento/magento2-base": "Packagist:magento/community-edition",
      "Packagist:magento/product-community-edition": "Packagist:magento/community-edition",
    });
  });

  it("magento/product-community-edition 2.4.7-p2 is checked as magento/community-edition and reported at its own lock line", async () => {
    sbomRun.vulnerable = ["magento/community-edition@2.4.7-p2"];
    const result = await scanStore({ "src/composer.lock": STORE });
    expect(sbomRun.seen).toHaveLength(1);
    expect(sbomRun.seen[0]!.components.map((c) => [c.name, c.version, c.purl])).toEqual([
      ["magento/community-edition", "2.4.7-p2", "pkg:composer/magento/community-edition@2.4.7-p2"],
    ]);
    expect(sbomRun.seen[0]!.options.ecosystems).toEqual(["Packagist"]);
    expect(sbomRun.seen[0]!.options.expected).toEqual([{ ecosystem: "Packagist", name: "magento/community-edition", version: "2.4.7-p2" }]);
    const line = lineOf(STORE, "magento/product-community-edition");
    expect(result.sbomFindings.map((f) => [f.location.file, f.location.start_line, f.package?.name])).toEqual([
      ["src/composer.lock", line, "magento/product-community-edition"],
    ]);
    expect(result.sbomFindings[0]!.message).toMatch(new RegExp(
      `^src/composer\\.lock:${line} locks Packagist package magento/product-community-edition 2\\.4\\.7-p2, which GitHub advisories list as magento/community-edition; osv-scanner checked it under that name\\.`,
    ));
    expect(result.sbomFindings[0]!.producer_components).toContain("synvoya:sbom:osv-scanner");
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["src/composer.lock"]);
    expect(result.warnings).toEqual([]);
    expect(result.coverageGaps).toEqual([]);
    expect(result.info.note).toContain("osv-scanner checked 1 Magento edition");
  });

  it("an Adobe Commerce lock is not checked through osv-scanner, so its file is never SBOM-checked", async () => {
    const result = await scanStore({ "composer.lock": lock([["magento/magento2-base", "2.4.7-p2"], ["magento/product-enterprise-edition", "2.4.7-p2"]]) });
    expect(runOsvScannerOnSbom).not.toHaveBeenCalled();
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual([]);
    expect(result.notes.some((note) => note.includes("magento/product-enterprise-edition 2.4.7-p2 has no package name in the OSV Packagist database"))).toBe(true);
  });

  it("a lock with no Magento package is SBOM-checked, so a removed edition's finding can resolve", async () => {
    const result = await scanStore({ "composer.lock": lock([["monolog/monolog", "2.9.1"]]) });
    expect(runOsvScannerOnSbom).not.toHaveBeenCalled();
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["composer.lock"]);
  });

  it("no OSV Packagist database: the edition is not checked and says so, while vendored libraries still are", async () => {
    sbomRun.missing = ["Packagist"];
    const result = await scanStore({ "src/composer.lock": STORE, "public/js/jquery-1.12.4.min.js": "/*! jQuery v1.12.4 */\n" });
    expect(sbomRun.seen[0]!.options.ecosystems).toEqual(["npm", "Packagist"]);
    expect(result.sbomFindings.map((f) => f.location.file)).toEqual(["public/js/jquery-1.12.4.min.js"]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["public/js/jquery-1.12.4.min.js"]);
    expect(result.coverageGaps).toEqual([]);
    expect(result.notes).toContain("1 Magento edition(s) were not checked by osv-scanner: the OSV Packagist database is not installed (src/composer.lock).");
  });

  it("no osv-scanner at all: the edition is not checked and says so, with no vendored-js gap when no library was found", async () => {
    sbomRun.answer = "unavailable";
    const result = await scanStore({ "src/composer.lock": STORE });
    expect(result.coverageGaps).toEqual([]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
    expect(result.notes).toContain("1 Magento edition(s) were not checked by osv-scanner: the OSV Packagist database is not installed (src/composer.lock).");
  });
});

describe("the Go toolchain through the SBOM", () => {
  const scanGo = async (files: Record<string, string>) => {
    const target = await repo(files);
    const tmpDir = await mkdtemp(join(tmpdir(), "ci-synvoya-scan-tmp-"));
    roots.push(tmpDir);
    return runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, tmpDir });
  };
  const GO_MOD = "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.5\n";

  it("an exact toolchain is checked as the Go standard library and reported at the toolchain line; go.mod is SBOM-checked despite its `go` minimum", async () => {
    sbomRun.vulnerable = ["stdlib@v1.22.5"];
    const result = await scanGo({ "go.mod": GO_MOD });
    expect(sbomRun.seen[0]!.components.map((c) => [c.name, c.version, c.purl])).toEqual([["stdlib", "v1.22.5", "pkg:golang/stdlib@v1.22.5"]]);
    expect(sbomRun.seen[0]!.options.ecosystems).toEqual(["Go"]);
    expect(result.sbomFindings.map((f) => [f.location.file, f.location.start_line, f.package?.ecosystem, f.package?.name])).toEqual([["go.mod", 5, "Go", "stdlib"]]);
    expect(result.sbomFindings[0]!.message).toMatch(/^go\.mod:5 declares Go 1\.22\.5 \(go\.mod toolchain\); osv-scanner checked the Go standard library \(stdlib\) at that version\./);
    expect(result.sbomFindings[0]!.producer_components).toContain("synvoya:sbom:osv-scanner");
    // The `go` minimum belongs to the runtime producer; only the toolchain decides SBOM checked-ness (ruling).
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["go.mod"]);
    expect(result.info.note).toContain("osv-scanner checked 1 Go toolchain");
  });

  it("an exact golang image is checked and its Dockerfile is SBOM-checked; a floating one is neither", async () => {
    sbomRun.vulnerable = ["stdlib@v1.22.5"];
    const result = await scanGo({ "Dockerfile": "FROM golang:1.22.5 AS build\nRUN go build\n", "tools/Dockerfile": "FROM golang:1.23\n" });
    expect(sbomRun.seen[0]!.components.map((c) => c.purl)).toEqual(["pkg:golang/stdlib@v1.22.5"]);
    expect(result.sbomFindings.map((f) => `${f.location.file}:${f.location.start_line}`)).toEqual(["Dockerfile:1"]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["Dockerfile"]);
  });

  it("a go.mod with only a `go` minimum adds nothing to the SBOM and is never SBOM-checked (its toolchain is unknown)", async () => {
    const result = await scanGo({ "go.mod": "module example.com/app\n\ngo 1.22\n" });
    expect(runOsvScannerOnSbom).not.toHaveBeenCalled();
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual([]);
    expect(result.evidence.checked.runtime).toEqual(["go.mod"]);
  });

  it("an unresolved toolchain keeps go.mod out of the SBOM set", async () => {
    const result = await scanGo({ "go.mod": "module example.com/app\n\ngo 1.22\n\ntoolchain go${GO}\n" });
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual([]);
  });

  it("no OSV Go database: the toolchain is not checked and says so, never a gap; other components still are", async () => {
    sbomRun.missing = ["Go"];
    const result = await scanGo({ "Dockerfile": "FROM golang:1.22.5\n", "public/js/jquery-1.12.4.min.js": "/*! jQuery v1.12.4 */\n" });
    expect(sbomRun.seen[0]!.options.ecosystems).toEqual(["npm", "Go"]);
    expect(result.sbomFindings.map((f) => f.location.file)).toEqual(["public/js/jquery-1.12.4.min.js"]);
    expect(result.evidence.checked["sbom:osv-scanner"]).toEqual(["public/js/jquery-1.12.4.min.js"]);
    expect(result.coverageGaps).toEqual([]);
    expect(result.notes).toContain("1 Go toolchain declaration(s) were not checked by osv-scanner: the OSV Go database is not installed (Dockerfile).");
    expect(result.info.note).toContain("1 Go toolchain not checked");
  });

  it("an image reader that rejects omits the SBOM set (a golang image could not be read)", async () => {
    readerFault.images = true;
    const result = await scanGo({ "Dockerfile": "FROM golang:1.22.5\n" });
    expect(result.evidence.checked["sbom:osv-scanner"]).toBeUndefined();
  });
});

describe("third-party GitHub Actions", () => {
  /** Real GHSA records (CC-BY-4.0) copied from the installed OSV GitHub Actions database (actions-osv-fixture.ts). */
  async function fixtureDb() {
    const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-actions-db-"));
    roots.push(dir);
    return writeActionsFixtureDb(dir);
  }
  async function actionsZip(): Promise<string> {
    return (await fixtureDb()).zipPath;
  }
  async function signedDb() {
    const { zipPath, record } = await fixtureDb();
    return { zipPath, readRecord: async () => record };
  }

  const CI = [
    "on: push",
    "jobs:",
    "  t:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: tj-actions/changed-files@v45.0.7",
    "",
  ].join("\n");
  const SLUG = "jobs:\n  t:\n    steps:\n      - uses: rlespinasse/github-slug-action@v4\n";

  it("checks references against the installed database: findings carry the actions producer and the database signature", async () => {
    const target = await repo({ ".github/workflows/ci.yml": CI, ".github/workflows/slug.yml": SLUG });
    const actionsDb = await signedDb();
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb });
    const finding = result.findings.find((f) => f.rule_id === "GHSA-mrrh-fwg8-r2c3");
    expect(finding).toMatchObject({ engine: "synvoya", location: { file: ".github/workflows/ci.yml", start_line: 7 } });
    expect(finding!.producer_components).toContain("synvoya:actions");
    expect(findingSchema.safeParse(finding).success).toBe(true);
    expect(result.componentSignatures["osv-scanner:vulnerability-db:GitHub Actions"]).toBe((await actionsDb.readRecord()).signature);
    expect(result.componentSignatures["synvoya:actions"]).toMatch(/^sha256:/);
    // ci.yml got definite answers (a finding and a clean checkout); slug.yml's v4 note is not definite.
    expect(result.evidence.checked.actions).toEqual([".github/workflows/ci.yml"]);
    expect(result.notes.join("\n")).toMatch(/slug\.yml:4: rlespinasse\/github-slug-action@v4 is a moving tag .* ≥ 4\.4\.1/);
    expect(result.notes.join("\n")).toMatch(/3 third-party GitHub Actions reference\(s\) are not pinned to a full commit SHA/);
    expect(result.info.note).toMatch(/3 GitHub Actions reference\(s\) checked against the OSV GitHub Actions database \(2026-10-30\)/);
    expect([...result.actionsCoverage!.evaluated].sort()).toEqual([
      ".github/workflows/ci.yml\0actions/checkout@v4", ".github/workflows/ci.yml\0tj-actions/changed-files@v45.0.7",
      ".github/workflows/slug.yml\0rlespinasse/github-slug-action@v4",
    ]);
    expect(result.warnings).toEqual([]);
    // The SBOM never sees an Actions reference (osv-scanner 2.7.0 rejects or panics on them).
    expect(sbomRun.seen).toEqual([]);
    expectNoLineZero(result);
  });

  it("without the database: no Actions finding, no matcher coverage (the gap stays), and only reference-free files are checked", async () => {
    const target = await repo({ ".github/workflows/ci.yml": CI, ".github/workflows/empty.yml": "on: push\njobs: {}\n" });
    const absent = join(target, "no-such-db", "all.zip");
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb: { zipPath: absent, readRecord: async () => undefined } });
    expect(result.findings.filter((f) => f.producer_components?.includes("synvoya:actions"))).toEqual([]);
    expect(result.actionsCoverage).toBeUndefined();
    expect(result.evidence.checked.actions).toEqual([".github/workflows/empty.yml"]);
    expect(result.info.note).toMatch(/2 GitHub Actions reference\(s\) not checked \(the OSV GitHub Actions database is not installed\)/);
    expect(result.warnings).toEqual([]);
  });

  it("an unreadable database is a warning and leaves the gap; an unrecorded one runs unsigned with a warning", async () => {
    const target = await repo({ ".github/workflows/ci.yml": CI });
    const bad = join(target, "bad.zip");
    await writeFile(bad, Buffer.alloc(64));
    const failed = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb: { zipPath: bad, readRecord: async () => undefined } });
    expect(failed.warnings.join("\n")).toMatch(/Synvoya GitHub Actions check did not run: the OSV GitHub Actions database could not be read/);
    expect(failed.actionsCoverage).toBeUndefined();
    expect(failed.evidence.checked.actions).toEqual([]);
    const unsigned = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb: { zipPath: await actionsZip(), readRecord: async () => undefined } });
    expect(unsigned.findings.some((f) => f.rule_id === "GHSA-mrrh-fwg8-r2c3")).toBe(true);
    expect(unsigned.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:GitHub Actions");
    expect(unsigned.warnings.join("\n")).toMatch(/no install record that matches it/);
  });

  it("a deadline skip or a rejected Actions reader leaves no Actions checked set", async () => {
    const target = await repo({ ".github/workflows/ci.yml": CI });
    const actionsDb = await signedDb();
    const late = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, deadlineMs: 0, actionsDb });
    expect(late.evidence.checked).not.toHaveProperty("actions");
    readerFault.actions = true;
    const rejected = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb });
    expect(rejected.evidence.checked).not.toHaveProperty("actions");
    expect(rejected.actionsCoverage).toBeUndefined();
    expect(rejected.notes.join("\n")).toMatch(/GitHub Actions reader stopped unexpectedly/);
    // The other readers' sets are untouched by it.
    expect(rejected.evidence.checked).toHaveProperty("runtime");
  });

  // Review C2, probe P1b: a record with commit-only data must never make a tag reference's file checked.
  it("a commit-only record leaves a tag reference's file out of the actions checked set, so a prior finding cannot resolve", async () => {
    const target = await repo({ ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: evil/act@v1.2.3\n" });
    const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-actions-db-"));
    roots.push(dir);
    const zipPath = join(dir, "all.zip");
    const record = { id: "GHSA-test-test-tst4", affected: [{
      package: { ecosystem: "GitHub Actions", name: "evil/act" },
      ranges: [{ type: "GIT", repo: "https://github.com/evil/act", events: [{ introduced: "a".repeat(40) }, { fixed: "b".repeat(40) }] }],
      versions: ["a".repeat(40)],
    }] };
    await writeFile(zipPath, zipEntries([{ name: "GHSA-test-test-tst4.json", data: Buffer.from(JSON.stringify(record)) }]));
    const result = await runSynvoyaScan(target, NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb: { zipPath, readRecord: async () => undefined } });
    expect(result.evidence.checked.actions).toEqual([]);
    expect(result.actionsCoverage!.evaluated).toEqual(new Set());
  });

  it("a single workflow file target is read alone and checked", async () => {
    const target = await repo({ ".github/workflows/ci.yml": CI });
    const result = await runSynvoyaScan(join(target, ".github", "workflows", "ci.yml"), NONE, {}, { datasetDir: TEST_DATASET, now: NOW, actionsDb: await signedDb() });
    expect(result.findings.map((f) => f.rule_id)).toContain("GHSA-mrrh-fwg8-r2c3");
    expect(result.evidence.checked.actions).toEqual([".github/workflows/ci.yml"]);
  });
});
