import { lstat, mkdir, mkdtemp, readFile, readlink, readdir, rename, rm, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OsvDbRecord } from "../osv/database.js";
import type { OsvEcosystem } from "../osv/ecosystems.js";
import { normalizePackageName, OSV_ECOSYSTEMS, OSV_OVERLAY_ECOSYSTEMS } from "../osv/ecosystems.js";
import { invocationSignature, PIPELINE_COMPONENT, signature } from "../provenance.js";
import { findingSchema } from "../schemas.js";
import { fingerprint as makeFingerprint } from "../util/hash.js";

// Unit tests never run the real binary, touch the network, or touch the user's managed directory:
// execBinary and resolveEngine are mocked, and the managed OSV paths point at a per-process temp root.
const state = vi.hoisted(() => ({ records: new Map<string, unknown>() }));
const execBinary = vi.hoisted(() => vi.fn());
// Filesystem fault injection for the overlay links: an errno code makes that call throw.
const fsFaults = vi.hoisted(() => ({
  symlink: undefined as string | undefined,
  link: undefined as string | undefined,
  rename: undefined as string | undefined,
  /** writeFile throws EIO for a path that matches. */
  writeFileMatching: undefined as RegExp | undefined,
  linkCalls: 0,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const fail = (code: string) => Object.assign(new Error(`${code}: injected`), { code });
  return {
    ...actual,
    symlink: async (...args: Parameters<typeof actual.symlink>) => {
      if (fsFaults.symlink) throw fail(fsFaults.symlink);
      return actual.symlink(...args);
    },
    link: async (...args: Parameters<typeof actual.link>) => {
      fsFaults.linkCalls += 1;
      if (fsFaults.link) throw fail(fsFaults.link);
      return actual.link(...args);
    },
    rename: async (...args: Parameters<typeof actual.rename>) => {
      if (fsFaults.rename) throw fail(fsFaults.rename);
      return actual.rename(...args);
    },
    writeFile: async (...args: Parameters<typeof actual.writeFile>) => {
      if (fsFaults.writeFileMatching?.test(String(args[0]))) throw fail("EIO");
      return actual.writeFile(...args);
    },
  };
});

vi.mock("../config.js", async (importOriginal) => {
  const root = join(tmpdir(), `codeinspectus-osv-wrapper-test-${process.pid}`);
  return {
    ...(await importOriginal<typeof import("../config.js")>()),
    MANAGED_OSV_DB: join(root, "osv-db"),
    MANAGED_OSV_CONFIG: join(root, "osv-scanner.toml"),
  };
});

vi.mock("./resolve.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./resolve.js")>()),
  resolveEngine: vi.fn(async () => ({ path: "/test/osv-scanner", version: "2.7.0", sha256: "a".repeat(64) })),
}));

vi.mock("./exec.js", () => ({ execBinary }));

vi.mock("../osv/database.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../osv/database.js")>()),
  readOsvDbRecord: vi.fn(async (ecosystem: string) => state.records.get(ecosystem)),
}));

const { MANAGED_OSV_DB, MANAGED_OSV_CONFIG } = await import("../config.js");
const { EngineUnavailableError, resolveEngine } = await import("./resolve.js");
const { osvDbZipPath } = await import("../osv/database.js");
const { buildOsvScannerArgs, buildOsvScannerSbomArgs, OSV_SBOM_FILE_NAME, osvSbomInvocationSignature, runOsvScanner, runOsvScannerOnSbom } = await import("./osv-scanner.js");
const { osvSbomFindingComponents, osvScannerFindingComponents } = await import("../provenance.js");

const FIXTURES = resolve(process.cwd(), "fixtures/osv");
const STOPPED_EARLY =
  "osv-scanner stopped at an OSV database it could not load, so packages it would have matched after that point " +
  "may be missing from its results; they are partial and cannot prove a fix on rescan.";
const REQUIREMENTS = "litellm==1.107.0\nBrotli==1.2.0\nbrotlicffi==1.2.0.2\nrequests==2.19.0\n";
const PACKAGE_LOCK = '{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.4"}}}';

const cleanup: string[] = [];

/**
 * `mismatched`: a valid record whose `bytes` is not the archive's size (it describes other bytes).
 * `undated`: installed, but the server sent no Last-Modified.
 */
type DbMode = "installed" | "record-only" | "archive-only" | "mismatched" | "undated";

interface RunOptions {
  /** Raw osv-scanner output with `<target>` standing for the scan target. `null` writes no file. */
  output?: string | object | null;
  code?: number | null;
  timedOut?: boolean;
  stderr?: string;
  lockfiles?: Record<string, string>;
  db?: Partial<Record<OsvEcosystem, DbMode>>;
  /** Scan a single file instead of a directory. */
  targetFile?: string;
  /** Runs on the target after the lockfiles are written. */
  prepare?: (target: string) => Promise<void>;
  /** Decide the run from the database cache directory osv-scanner was given (overrides code/stderr/output). */
  respond?: (cacheDirectory: string) => Promise<Pick<RunOptions, "code" | "stderr" | "output">>;
}

function dbRecord(ecosystem: OsvEcosystem): OsvDbRecord {
  return {
    component: `osv-scanner:vulnerability-db:${ecosystem}`,
    ecosystem,
    signature: `sha256:${ecosystem.length.toString(16).repeat(64).slice(0, 64)}`,
    source_url: `https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/all.zip`,
    bytes: 4,
    last_modified: "2026-10-30T09:00:00.000Z",
    recorded_at: "2026-10-30T10:00:00.000Z",
  };
}

async function fixtureText(name: string): Promise<string> {
  return readFile(join(FIXTURES, name), "utf8");
}

async function scan(options: RunOptions = {}) {
  const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-run-"));
  cleanup.push(base);
  const target = join(base, "repo");
  const tmpDir = join(base, "tmp");
  await mkdir(target, { recursive: true });
  await mkdir(tmpDir, { recursive: true });
  for (const [path, content] of Object.entries(options.lockfiles ?? {})) {
    await mkdir(join(target, path, ".."), { recursive: true });
    await writeFile(join(target, path), content, "utf8");
  }
  await options.prepare?.(target);
  const scanTarget = options.targetFile ? join(target, options.targetFile) : target;

  state.records.clear();
  for (const [ecosystem, mode] of Object.entries(options.db ?? {}) as Array<[OsvEcosystem, DbMode]>) {
    if (mode === "undated") state.records.set(ecosystem, { ...dbRecord(ecosystem), last_modified: undefined });
    else if (mode !== "archive-only") state.records.set(ecosystem, dbRecord(ecosystem));
    if (mode !== "record-only") {
      await mkdir(join(osvDbZipPath(ecosystem), ".."), { recursive: true });
      await writeFile(osvDbZipPath(ecosystem), mode === "mismatched" ? "zip!+" : "zip!", "utf8");
    }
  }

  execBinary.mockImplementation(async (_binary: string, args: string[], execOptions: { env: Record<string, string> }) => {
    const outputPath = args[args.indexOf("--output-file") + 1]!;
    const run = options.respond ? await options.respond(execOptions.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY!) : options;
    if (run.output !== null && run.output !== undefined) {
      const text = typeof run.output === "string" ? run.output : JSON.stringify(run.output);
      await writeFile(outputPath, text.replaceAll("<target>", scanTarget.replace(/\\/g, "\\\\")), "utf8");
    }
    return { code: run.code ?? 0, stdout: "", stderr: run.stderr ?? "", timedOut: options.timedOut ?? false };
  });
  const result = await runOsvScanner(scanTarget, tmpDir);
  return { result, target: scanTarget, tmpDir };
}

function doc(source: string, packages: unknown[]): object {
  return { results: [{ source: { path: `<target>/${source}`, type: "lockfile" }, packages }], experimental_config: {} };
}

function pkg(
  ecosystem: string,
  name: string,
  version: string,
  groups: Array<{ ids: string[]; aliases?: string[]; max_severity?: string }> = [],
  vulnerabilities: unknown[] = [],
): object {
  return {
    package: { name, version, ecosystem, purl: `pkg:test/${name}@${version}` },
    groups: groups.map((group) => ({ aliases: [], max_severity: "", ...group })),
    vulnerabilities,
  };
}

beforeEach(async () => {
  execBinary.mockReset();
  fsFaults.symlink = undefined;
  fsFaults.link = undefined;
  fsFaults.rename = undefined;
  fsFaults.writeFileMatching = undefined;
  fsFaults.linkCalls = 0;
  await rm(join(MANAGED_OSV_CONFIG, ".."), { recursive: true, force: true });
});

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
  await rm(join(MANAGED_OSV_CONFIG, ".."), { recursive: true, force: true });
});

describe("osv-scanner invocation", () => {
  it("argv is offline, managed-config, no-ignore, and never enables networked or build-running flags", () => {
    const args = buildOsvScannerArgs("/repo", "/managed-temp/osv.json", "/managed/osv-scanner.toml");

    expect(args).toEqual([
      "scan", "source",
      "--offline",
      "--no-resolve",
      "--no-ignore",
      "--allow-no-lockfiles",
      "--all-packages",
      "--no-call-analysis=all",
      "--format", "json",
      "--output-file", "/managed-temp/osv.json",
      "--config", "/managed/osv-scanner.toml",
      "-r", "/repo",
    ]);
    for (const forbidden of [
      "--call-analysis", "--licenses", "--download-offline-databases", "--offline-vulnerabilities",
      "--data-source", "--serve",
    ]) {
      expect(args).not.toContain(forbidden);
    }
    // 2.7.0 runs Go call analysis (govulncheck, which invokes the Go toolchain) unless it is turned off.
    expect(args.filter((arg) => arg.includes("call-analysis"))).toEqual(["--no-call-analysis=all"]);
  });

  it("refuses a relative scan target", () => {
    for (const target of ["repo", "./repo", ""]) {
      expect(() => buildOsvScannerArgs(target, "/managed-temp/osv.json", "/managed/osv-scanner.toml")).toThrow(/absolute scan target/);
    }
  });

  it("env points OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY at a per-scan overlay in the temp dir and runs offline in the target", async () => {
    const { target, tmpDir } = await scan({ output: await fixtureText("raw-vulnerable.json"), code: 1, lockfiles: { "requirements.txt": REQUIREMENTS } });

    expect(execBinary).toHaveBeenCalledTimes(1);
    const [binary, args, options] = execBinary.mock.calls[0]!;
    expect(binary).toBe("/test/osv-scanner");
    expect(args).toEqual(buildOsvScannerArgs(target, join(tmpDir, "osv-scanner.json"), MANAGED_OSV_CONFIG));
    expect(options).toEqual({
      cwd: target,
      offline: true,
      env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: join(tmpDir, "osv-db-overlay") },
    });
    // The managed directory itself is never the one osv-scanner reads.
    expect(options.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY).not.toBe(MANAGED_OSV_DB);
  });

  it("overlay links each installed archive and substitutes a valid empty zip for every other published ecosystem", async () => {
    const { tmpDir } = await scan({
      output: doc("requirements.txt", []),
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed", Packagist: "archive-only", npm: "record-only" },
    });
    const overlay = join(tmpDir, "osv-db-overlay", "osv-scalibr");

    // Every ecosystem OSV publishes or its schema names, not only the allow-list: osv-scanner fails the run over any it cannot load.
    expect((await readdir(overlay)).sort()).toEqual([...OSV_OVERLAY_ECOSYSTEMS].sort());
    expect(await readdir(overlay)).toContain("ConanCenter");
    for (const ecosystem of OSV_OVERLAY_ECOSYSTEMS) {
      const entry = join(overlay, ecosystem, "all.zip");
      const metadata = await lstat(entry);
      if (ecosystem === "PyPI" || ecosystem === "Packagist") {
        // Installed (and an archive with no record): a link to the managed archive, never a copy. Windows
        // without symlink privilege falls back to a hard link: the very same file.
        if (metadata.isSymbolicLink()) expect(await readlink(entry)).toBe(osvDbZipPath(ecosystem));
        else expect([process.platform, metadata.ino]).toEqual(["win32", (await stat(osvDbZipPath(ecosystem))).ino]);
      } else {
        // Missing, not allow-listed, or a record whose archive is gone: an empty zip (only an end-of-central-directory record).
        expect(metadata.isFile()).toBe(true);
        const bytes = await readFile(entry);
        expect(bytes.length).toBe(22);
        expect(bytes.readUInt32LE(0)).toBe(0x06054b50);
        expect([...bytes.subarray(4)].every((byte) => byte === 0)).toBe(true);
      }
    }
    // Nothing was written into the managed database directory.
    await expect(lstat(join(MANAGED_OSV_DB, "osv-scalibr", "npm"))).rejects.toThrow();
  });

  it.each(["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"])(
    "falls back to a hard link of the installed archive when the symlink fails with %s",
    async (code) => {
      fsFaults.symlink = code;
      const { result, tmpDir } = await scan({
        output: await fixtureText("raw-vulnerable.json"),
        code: 1,
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
      });

      const entry = join(tmpDir, "osv-db-overlay", "osv-scalibr", "PyPI", "all.zip");
      const metadata = await lstat(entry);
      expect(metadata.isSymbolicLink()).toBe(false);
      expect(metadata.isFile()).toBe(true);
      // The very same file as the managed archive, not a copy.
      expect(metadata.ino).toBe((await stat(osvDbZipPath("PyPI"))).ino);
      expect(fsFaults.linkCalls).toBe(1); // only the installed ecosystem needs a link
      expect(result.info.ran).toBe(true);
      expect(result.findings).toHaveLength(8);
      expect(result.coverage[0]).toMatchObject({ ecosystem: "PyPI", state: "ran" });
    },
  );

  it("when the symlink and the hard link both fail, reports the cause and never copies or reports clean", async () => {
    fsFaults.symlink = "EPERM";
    fsFaults.link = "EXDEV";
    const { result, tmpDir } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "installed" },
    });

    expect(result.info).toMatchObject({ engine: "osv-scanner", available: true, ran: false, finding_count: 0 });
    expect(result.info.note).toContain("could not link the OSV PyPI database into the scan overlay: EXDEV");
    expect(result.applicable).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.coverage).toEqual([]);
    expect(result.warnings).toEqual([result.info.note]);
    expect(execBinary).not.toHaveBeenCalled();
    // No fallback to a copy: the overlay holds no regular file the size of the archive.
    await expect(lstat(join(tmpDir, "osv-db-overlay", "osv-scalibr", "PyPI", "all.zip"))).rejects.toThrow();
  });

  it("does not fall back to a hard link for a symlink failure that is not a privilege problem", async () => {
    fsFaults.symlink = "ENOSPC";
    const { result } = await scan({
      output: doc("requirements.txt", []),
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });

    expect(fsFaults.linkCalls).toBe(0);
    expect(result.info.ran).toBe(false);
    // Reported by its code alone: the errno message names the managed and temporary paths.
    expect(result.info.note).toBe("could not link the OSV PyPI database into the scan overlay: ENOSPC");
    expect(execBinary).not.toHaveBeenCalled();
  });

  it("writes a comment-only managed config when absent", async () => {
    await scan({ output: doc("requirements.txt", []) });
    const created = await readFile(MANAGED_OSV_CONFIG, "utf8");
    expect(created.trim().length).toBeGreaterThan(0);
    expect(created.split("\n").filter((line) => line.trim() && !line.trim().startsWith("#"))).toEqual([]);
  });

  it("when the config cannot be replaced, runs only if it already holds the managed content", async () => {
    await scan({ output: doc("requirements.txt", []) });
    const managed = await readFile(MANAGED_OSV_CONFIG, "utf8");
    fsFaults.rename = "EPERM"; // Windows, while another scan's osv-scanner has the file open

    const unchanged = await scan({ output: doc("requirements.txt", []) });
    expect(unchanged.result.info.ran).toBe(true);
    expect(unchanged.result.componentSignatures["osv-scanner:config"]).toBe(signature(managed));

    await writeFile(MANAGED_OSV_CONFIG, '[[IgnoredVulns]]\nid = "MAL-2026-2144"\n', "utf8");
    execBinary.mockClear();
    const edited = await scan({ output: doc("requirements.txt", []) });
    expect(edited.result.info.ran).toBe(false);
    expect(edited.result.info.note).toContain("EPERM");
    expect(execBinary).not.toHaveBeenCalled();
    expect((await readdir(join(MANAGED_OSV_CONFIG, ".."))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  it("replaces an edited managed config before the run, so its IgnoredVulns are never honoured", async () => {
    await scan({ output: doc("requirements.txt", []) });
    const managed = await readFile(MANAGED_OSV_CONFIG, "utf8");
    const edited = '[[IgnoredVulns]]\nid = "MAL-2026-2144"\nreason = "edited"\n';
    await writeFile(MANAGED_OSV_CONFIG, edited, "utf8");

    let seenByRun: string | undefined;
    const { result } = await scan({
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "installed" },
      respond: async () => {
        seenByRun = await readFile(MANAGED_OSV_CONFIG, "utf8");
        return { code: 1, output: await fixtureText("raw-vulnerable.json") };
      },
    });

    expect(seenByRun).toBe(managed);
    expect(await readFile(MANAGED_OSV_CONFIG, "utf8")).toBe(managed);
    expect(result.componentSignatures["osv-scanner:config"]).toBe(signature(managed));
    expect(result.findings.some((item) => item.rule_id === "MAL-2026-2144")).toBe(true);
    // Written through a temporary file and a rename: nothing is left beside it.
    expect((await readdir(join(MANAGED_OSV_CONFIG, ".."))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });
});

describe("osv-scanner result mapping", () => {
  const vulnerable = async () => scan({
    output: await fixtureText("raw-vulnerable.json"),
    code: 1,
    lockfiles: { "requirements.txt": REQUIREMENTS },
    db: { PyPI: "installed" },
  });

  it("maps MAL records to critical CWE-506 with credential-rotation remediation", async () => {
    const { result } = await vulnerable();
    const finding = result.findings.find((item) => item.package?.name === "litellm")!;

    expect(finding).toBeDefined();
    expect(finding.rule_id).toBe("MAL-2026-2144");
    expect(finding.severity).toBe("critical");
    expect(finding.cwe).toContain("CWE-506");
    expect(finding.package).toEqual({ ecosystem: "PyPI", name: "litellm", version: "1.107.0" });
    expect(finding.finding_kind).toBe("vulnerability");
    expect(finding.engine).toBe("osv-scanner");
    expect(finding.engines).toEqual(["osv-scanner"]);
    expect(finding.remediation.steps.some((step) => /rotate every credential/i.test(step))).toBe(true);
    expect(finding.remediation.references).toContain("https://osv.dev/vulnerability/MAL-2026-2144");
    expect(finding.vulnerability_aliases).toEqual(["PYSEC-2026-2"]);
    expect(finding.owasp_web).toEqual(["A06:2021"]);
    expect(finding.message).toContain("proves dependency presence, not");
    expect(finding.message).toContain("reachability");
    expect(finding.confidence).toBe("high");
  });

  it("prefers CVE then GHSA as rule_id and keeps every group alias", async () => {
    const { result } = await vulnerable();
    const brotli = result.findings.find((item) => item.package?.name === "brotli")!;

    expect(brotli.rule_id).toBe("CVE-2026-111497");
    expect(brotli.vulnerability_aliases).toEqual(expect.arrayContaining(["GHSA-9v8h-qqgm-4m35", "PYSEC-2026-4322"]));
    expect(brotli.vulnerability_aliases).not.toContain("CVE-2026-111497");
    expect(brotli.severity).toBe("critical");
    expect(brotli.cwe).toEqual(expect.arrayContaining(["CWE-1395", "CWE-252"]));
    expect(brotli.title).toContain("Out-of-bounds write in the Brotli decoder");
    expect(brotli.title).toContain("brotli@1.2.0");
    expect(brotli.message).not.toContain("\n");
  });

  it("keeps one advisory on two packages in one lockfile as two findings (shared CVE, distinct packages)", async () => {
    const { result } = await vulnerable();
    const shared = result.findings.filter((item) => item.rule_id === "CVE-2026-111497");

    expect(shared.map((item) => item.package?.name).sort()).toEqual(["brotli", "brotlicffi"]);
    expect(new Set(shared.map((item) => item.fingerprint)).size).toBe(2);
  });

  it("emits one finding per group and nothing for the whole fixture beyond the groups", async () => {
    const { result } = await vulnerable();

    expect(result.findings.map((item) => `${item.package?.name}:${item.rule_id}`).sort()).toEqual([
      "brotli:CVE-2026-111497",
      "brotlicffi:CVE-2026-111497",
      "litellm:MAL-2026-2144",
      "requests:CVE-2018-18074",
      "requests:CVE-2023-32681",
      "requests:CVE-2024-35195",
      "requests:CVE-2024-47081",
      "requests:CVE-2026-25645",
    ]);
    expect(result.info.finding_count).toBe(8);
  });

  it("derives severity from each group's max_severity score", async () => {
    const { result } = await vulnerable();
    const bySeverity = Object.fromEntries(result.findings.map((item) => [item.rule_id, item.severity]));

    expect(bySeverity["CVE-2018-18074"]).toBe("high"); // 7.5
    expect(bySeverity["CVE-2023-32681"]).toBe("medium"); // 6.1
    expect(bySeverity["CVE-2024-47081"]).toBe("medium"); // 5.3
  });

  it("uses an upstream fixed version in the remediation and a stable fingerprint", async () => {
    const { result } = await vulnerable();
    const finding = result.findings.find((item) => item.rule_id === "CVE-2018-18074")!;

    expect(finding.remediation.summary).toContain("requests");
    expect(finding.remediation.summary).toContain("2.20.0");
    // GIT ranges carry commit hashes, not installable versions.
    expect(finding.remediation.summary).not.toContain("c45d7c49");
    // An advisory that also lists a sibling package must not lend that package's fixed version.
    const brotli = result.findings.find((item) => item.package?.name === "brotli")!;
    expect(brotli.remediation.summary).toContain("1.2.1");
    expect(brotli.remediation.summary).not.toContain("1.2.1.0");
    expect(finding.fingerprint).toBe(finding.id);
    expect(finding.fingerprint).toBe(
      makeFingerprint(["osv-scanner", "requirements.txt", normalizePackageName("requests"), "2.19.0", "CVE-2018-18074"]),
    );
  });

  describe("Drupal contrib repository prefix", () => {
    const REPO = "https://packages.drupal.org/8:";
    const vuln = (id: string, ecosystem: string, name: string, fixed: string) => ({
      id,
      summary: "x",
      aliases: [],
      affected: [{ package: { ecosystem, name }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }] }],
    });
    const drupalAndNpm = () => doc("composer.lock", [
      pkg("Packagist", "drupal/ai", "1.4.0", [{ ids: ["DRUPAL-CONTRIB-2026-254"] }], [
        vuln("DRUPAL-CONTRIB-2026-254", "Packagist", `${REPO}drupal/ai`, "1.4.11"),
      ]),
      pkg("npm", "lodash", "4.17.4", [{ ids: ["GHSA-aaaa-bbbb-cccc"] }], [
        vuln("GHSA-aaaa-bbbb-cccc", "npm", "lodash", "4.17.21"),
      ]),
    ]);
    const scanBoth = (output: object) => scan({ output, code: 1, lockfiles: { "composer.lock": "{}" }, db: { Packagist: "installed", npm: "installed" } });

    it("names the fixed version when OSV keys the package with a repository prefix", async () => {
      const { result } = await scanBoth(drupalAndNpm());
      const drupal = result.findings.find((item) => item.package?.name === "drupal/ai")!;

      expect(drupal.remediation.summary).toContain("1.4.11");
      expect(drupal.remediation.summary).not.toContain("not listed as affected");
    });

    it("strips the prefix from a fixed version string too", async () => {
      const output = doc("composer.lock", [
        pkg("Packagist", "drupal/ai", "1.4.0", [{ ids: ["DRUPAL-CONTRIB-2026-254"] }], [
          vuln("DRUPAL-CONTRIB-2026-254", "Packagist", "drupal/ai", `${REPO}1.4.11`),
        ]),
      ]);
      const { result } = await scanBoth(output);

      expect(result.findings[0]!.remediation.summary).toContain("Upgrade drupal/ai to 1.4.11,");
    });

    it("leaves other findings' remediation and every fingerprint unchanged", async () => {
      const { result } = await scanBoth(drupalAndNpm());
      const byName = Object.fromEntries(result.findings.map((item) => [item.package?.name, item]));

      expect(byName["lodash"]!.remediation.summary).toContain("4.17.21");
      expect(byName["drupal/ai"]!.fingerprint).toBe(
        makeFingerprint(["osv-scanner", "composer.lock", "drupal/ai", "1.4.0", "DRUPAL-CONTRIB-2026-254"]),
      );
      expect(byName["lodash"]!.fingerprint).toBe(
        makeFingerprint(["osv-scanner", "composer.lock", "lodash", "4.17.4", "GHSA-aaaa-bbbb-cccc"]),
      );
    });

    it("does not strip a prefix from another ecosystem's names", async () => {
      const output = doc("package-lock.json", [
        pkg("npm", "drupal/ai", "1.4.0", [{ ids: ["GHSA-aaaa-bbbb-cccc"] }], [
          vuln("GHSA-aaaa-bbbb-cccc", "npm", `${REPO}drupal/ai`, "1.4.11"),
        ]),
      ]);
      const { result } = await scan({ output, code: 1, lockfiles: { "package-lock.json": "{}" }, db: { npm: "installed" } });

      expect(result.findings[0]!.remediation.summary).toContain("not listed as affected");
    });
  });

  it("passes the finding schema, including the structured package field", async () => {
    const { result } = await vulnerable();

    for (const finding of result.findings) expect(() => findingSchema.parse(finding)).not.toThrow();
    expect(findingSchema.parse(result.findings[0]).package).toEqual(result.findings[0]!.package);
  });

  it("reports location.file relative to the scan target, not the absolute lockfile path", async () => {
    const { result, target } = await vulnerable();

    expect(new Set(result.findings.map((item) => item.location.file))).toEqual(new Set(["requirements.txt"]));
    expect(JSON.stringify(result.findings)).not.toContain(target);
  });

  it("uses the file name when the scan target is a single lockfile", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      targetFile: "requirements.txt",
      db: { PyPI: "installed" },
    });

    expect(new Set(result.findings.map((item) => item.location.file))).toEqual(new Set(["requirements.txt"]));
  });

  it("locates the package line in the lockfile", async () => {
    const { result } = await vulnerable();
    const line = (name: string) => result.findings.find((item) => item.package?.name === name)!.location;

    expect(line("litellm")).toMatchObject({ start_line: 1, end_line: 1 });
    expect(line("brotli")).toMatchObject({ start_line: 2, end_line: 2 });
    expect(line("brotlicffi")).toMatchObject({ start_line: 3, end_line: 3 });
    expect(line("requests")).toMatchObject({ start_line: 4, end_line: 4 });
  });

  it("locates the package's own versioned entry, never a longer name containing it (PicGo tar)", async () => {
    const lockfile = [
      "lockfileVersion: '9.0'", "packages:", "  '@babel/helper-compilation-targets@7.27.2':", "    resolution: {}",
      "  tar@6.2.1:", "    resolution: {}", "  tar@7.5.2:", "    resolution: {}",
    ].join("\n");
    const output = doc("pnpm-lock.yaml", [pkg("npm", "tar", "7.5.2", [{ ids: ["GHSA-aaaa-bbbb-cccc"] }])]);
    const { result } = await scan({ code: 1, output, lockfiles: { "pnpm-lock.yaml": lockfile }, db: { npm: "installed" } });

    expect(result.findings[0]!.location).toMatchObject({ start_line: 7, end_line: 7 });
    // The line is not a fingerprint input.
    expect(result.findings[0]!.fingerprint).toBe(makeFingerprint(["osv-scanner", "pnpm-lock.yaml", "tar", "7.5.2", "GHSA-aaaa-bbbb-cccc"]));
  });

  it("falls back to line 1 when the lockfile cannot be read", async () => {
    const { result } = await scan({ output: await fixtureText("raw-vulnerable.json"), code: 1, db: { PyPI: "installed" } });

    expect(result.findings.length).toBeGreaterThan(0);
    expect(new Set(result.findings.map((item) => item.location.start_line))).toEqual(new Set([1]));
  });

  it("never reads a symlinked or oversized lockfile to find a line", async () => {
    const lockfile = "# pinned\nflask==3.0.0\nlitellm==1.107.0\n";
    const output = doc("requirements.txt", [pkg("PyPI", "litellm", "1.107.0", [{ ids: ["MAL-2026-2144"] }])]);
    const run = (prepare?: RunOptions["prepare"]) =>
      scan({ code: 1, output, lockfiles: { "requirements.txt": lockfile }, db: { PyPI: "installed" }, prepare });
    const outside = await mkdtemp(join(tmpdir(), "codeinspectus-osv-outside-"));
    cleanup.push(outside);
    await writeFile(join(outside, "requirements.txt"), lockfile, "utf8");

    expect((await run()).result.findings[0]!.location.start_line).toBe(3);
    // A link to a file outside the target: lstat sees the link, so the line search never follows it. A Windows
    // runner without symlink privilege cannot create the link; only there is this half skipped.
    let linkRefused = false;
    const linked = await run(async (target) => {
      try {
        await symlink(join(outside, "requirements.txt"), join(target, "linked-requirements.txt"), "file");
      } catch (error) {
        if (process.platform !== "win32" || !["EPERM", "EACCES"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
        linkRefused = true;
        return;
      }
      await rm(join(target, "requirements.txt"));
      await rename(join(target, "linked-requirements.txt"), join(target, "requirements.txt"));
    });
    if (!linkRefused) expect(linked.result.findings[0]!.location.start_line).toBe(1);
    // Over the 16 MiB bound (sparse, so the test stays cheap).
    const oversized = await run((target) => truncate(join(target, "requirements.txt"), 16 * 1024 * 1024 + 1));
    expect(oversized.result.findings[0]!.location.start_line).toBe(1);
  });

  it("matches package names in the lockfile across case and separator differences", async () => {
    const { result } = await scan({
      output: doc("requirements.txt", [
        pkg("PyPI", "typing-extensions", "4.0.0", [{ ids: ["CVE-2030-1"], max_severity: "5.0" }]),
      ]),
      code: 1,
      lockfiles: { "requirements.txt": "# pinned\nflask==3.0.0\nTyping_Extensions==4.0.0\n" },
      db: { PyPI: "installed" },
    });

    expect(result.findings[0]!.location.start_line).toBe(3);
  });

  it("maps scores to severities at the documented boundaries", async () => {
    const scores: Array<[string, string]> = [
      ["9.0", "critical"], ["8.9", "high"], ["7.0", "high"], ["6.9", "medium"],
      ["4.0", "medium"], ["3.9", "low"], ["0.1", "low"], ["0.0", "medium"], ["", "medium"],
    ];
    const packages = scores.map(([score], index) =>
      pkg("PyPI", `p${index}`, "1.0.0", [{ ids: [`CVE-2030-${index}`], max_severity: score }]));
    const { result } = await scan({
      output: doc("requirements.txt", packages),
      code: 1,
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });

    expect(result.findings.map((item) => item.severity)).toEqual(scores.map(([, severity]) => severity));
  });

  it("falls back to the advisory's database_specific severity, then to medium", async () => {
    const withSeverity = (id: string, severity: string | undefined) => ({
      id,
      summary: `summary ${id}`,
      aliases: [],
      ...(severity ? { database_specific: { severity } } : {}),
      affected: [],
    });
    const { result } = await scan({
      output: doc("requirements.txt", [
        pkg("PyPI", "a", "1.0.0", [{ ids: ["GHSA-aaaa-aaaa-aaaa"] }], [withSeverity("GHSA-aaaa-aaaa-aaaa", "HIGH")]),
        pkg("PyPI", "b", "1.0.0", [{ ids: ["GHSA-bbbb-bbbb-bbbb"] }], [withSeverity("GHSA-bbbb-bbbb-bbbb", "MODERATE")]),
        pkg("PyPI", "c", "1.0.0", [{ ids: ["GHSA-cccc-cccc-cccc"] }], [withSeverity("GHSA-cccc-cccc-cccc", "LOW")]),
        pkg("PyPI", "d", "1.0.0", [{ ids: ["GHSA-dddd-dddd-dddd"] }], [withSeverity("GHSA-dddd-dddd-dddd", undefined)]),
        pkg("PyPI", "e", "1.0.0", [{ ids: ["OSV-2030-1"] }], []),
      ]),
      code: 1,
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });

    expect(result.findings.map((item) => [item.package?.name, item.severity])).toEqual([
      ["a", "high"], ["b", "medium"], ["c", "low"], ["d", "medium"], ["e", "medium"],
    ]);
  });

  it("keeps lockfile- and database-supplied text to one printable line", async () => {
    const { result } = await scan({
      output: doc("requirements.txt", [
        pkg(
          "PyPI",
          "evil\nname",
          "1.0.0\r\n",
          [{ ids: ["CVE-2030-2", "bad id\nwith newline", "../../etc/passwd"], aliases: ["GHSA-ffff-ffff-ffff", "x y"], max_severity: "5.0" }],
          [{ id: "CVE-2030-2", summary: "line one\nline two\u0007 end", aliases: [], affected: [] }],
        ),
      ]),
      code: 1,
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });

    const finding = result.findings[0]!;
    expect(finding.package).toEqual({ ecosystem: "PyPI", name: "evilname", version: "1.0.0" });
    expect(finding.title).toBe("line one line two end (evilname@1.0.0)");
    expect(finding.vulnerability_aliases).toEqual(["GHSA-ffff-ffff-ffff"]);
    expect(finding.remediation.references.filter((url) => url.startsWith("https://osv.dev/"))).toEqual([
      "https://osv.dev/vulnerability/CVE-2030-2",
    ]);
    for (const value of [finding.title, finding.message, ...finding.remediation.steps]) expect(value).not.toMatch(/[\r\n]/);
  });

  it("still reports advisories that carry vulnerabilities but no groups", async () => {
    const { result } = await scan({
      output: doc("requirements.txt", [
        {
          package: { name: "x", version: "1.0.0", ecosystem: "PyPI", purl: "pkg:pypi/x@1.0.0" },
          vulnerabilities: [{ id: "GHSA-eeee-eeee-eeee", aliases: ["CVE-2030-9"], summary: "ungrouped", affected: [] }],
        },
      ]),
      code: 1,
      lockfiles: { "requirements.txt": "x==1.0.0\n" },
      db: { PyPI: "installed" },
    });

    expect(result.findings.map((item) => item.rule_id)).toEqual(["CVE-2030-9"]);
  });
});

describe("osv-scanner provenance", () => {
  it("lists the binary, invocation, config and that ecosystem's database as producer components", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "installed" },
    });

    const expected = [
      PIPELINE_COMPONENT,
      "osv-scanner:binary",
      "osv-scanner:invocation",
      "osv-scanner:config",
      "osv-scanner:vulnerability-db:PyPI",
    ];
    expect(osvScannerFindingComponents("PyPI")).toEqual(expected);
    for (const finding of result.findings) expect(finding.producer_components).toEqual(expected);
  });

  it("signs the binary, the placeholder-normalised invocation, the config and each installed database", async () => {
    const first = await scan({
      output: doc("requirements.txt", []),
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed", Packagist: "installed", npm: "record-only", Go: "archive-only" },
    });
    const second = await scan({ output: doc("requirements.txt", []), lockfiles: { "requirements.txt": "x\n" } });

    const sigs = first.result.componentSignatures;
    expect(sigs["osv-scanner:binary"]).toBe(`sha256:${"a".repeat(64)}`);
    expect(sigs["osv-scanner:config"]).toBe(signature(await readFile(MANAGED_OSV_CONFIG, "utf8")));
    expect(sigs["osv-scanner:vulnerability-db:PyPI"]).toBe(dbRecord("PyPI").signature);
    expect(sigs["osv-scanner:vulnerability-db:Packagist"]).toBe(dbRecord("Packagist").signature);
    // No archive on disk, or no record: nothing to prove, so no signature.
    expect(sigs).not.toHaveProperty("osv-scanner:vulnerability-db:npm");
    expect(sigs).not.toHaveProperty("osv-scanner:vulnerability-db:Go");

    // The invocation signature uses placeholders, so it is identical for different targets and temp dirs.
    expect(sigs["osv-scanner:invocation"]).toBe(invocationSignature("osv-scanner", [
      "scan", "source", "--offline", "--no-resolve", "--no-ignore", "--allow-no-lockfiles", "--all-packages",
      "--no-call-analysis=all",
      "--format", "json", "--output-file", "<managed-temp>", "--config", "<managed-config>", "-r", "<target>",
    ]));
    expect(second.result.componentSignatures["osv-scanner:invocation"]).toBe(sigs["osv-scanner:invocation"]);
  });
});

describe("osv-scanner dependency coverage", () => {
  it("reports an installed database as ran with its snapshot and counts", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "installed" },
    });

    expect(result.applicable).toBe(true);
    expect(result.info).toMatchObject({ engine: "osv-scanner", version: "2.7.0", available: true, ran: true, finding_count: 8 });
    expect(result.coverage).toHaveLength(1);
    expect(result.coverage[0]).toMatchObject({
      ecosystem: "PyPI",
      engine: "osv-scanner",
      state: "ran",
      lockfiles: { discovered: 1, analyzed: 1 },
      packages: { resolved: 4, eligible: 4, skipped: 0 },
      database_version: "2026-10-30T09:00:00.000Z",
      database_checked_at: "2026-10-30T10:00:00.000Z",
      matching: "osv-scanner-offline",
    });
    expect(result.coverage[0]!.limitations.join(" ")).toContain("--no-resolve");
    expect(result.warnings).toEqual([]);
    // The files the JSON listed packages from, so the scan can note a detected lockfile it did not list.
    expect(result.lockfiles).toEqual(["requirements.txt"]);
  });

  it("exposes every package it listed, vulnerable or not, with its target-relative file (the Synvoya inventory)", async () => {
    const { result } = await scan({
      output: {
        results: [
          {
            source: { path: "<target>/web/package-lock.json", type: "lockfile" },
            packages: [pkg("npm", "lodash", "4.17.4", [{ ids: ["GHSA-x"], aliases: ["CVE-1"] }]), pkg("npm", "left-pad", "1.3.0")],
          },
          { source: { path: "<target>/requirements.txt", type: "lockfile" }, packages: [pkg("PyPI", "requests", "2.19.0")] },
        ],
      },
      code: 1,
      lockfiles: { "web/package-lock.json": PACKAGE_LOCK, "requirements.txt": REQUIREMENTS },
      db: { npm: "installed", PyPI: "installed" },
    });
    expect(result.packages).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "web/package-lock.json" },
      { ecosystem: "npm", name: "left-pad", version: "1.3.0", file: "web/package-lock.json" },
      { ecosystem: "PyPI", name: "requests", version: "2.19.0", file: "requirements.txt" },
    ]);
  });

  it("marks a package whose source is outside the target, so its line is never looked up in a same-named file", async () => {
    const { result } = await scan({
      output: { results: [{ source: { path: "/elsewhere/package-lock.json", type: "lockfile" }, packages: [pkg("npm", "left-pad", "1.3.0")] }] },
      code: 0,
      lockfiles: { "package-lock.json": PACKAGE_LOCK },
      db: { npm: "installed" },
    });
    expect(result.packages).toEqual([{ ecosystem: "npm", name: "left-pad", version: "1.3.0", file: "package-lock.json", outside: true }]);
  });

  it("lists no packages for a run that did not complete", async () => {
    const { result } = await scan({ output: null, code: 2, lockfiles: { "requirements.txt": REQUIREMENTS }, db: { PyPI: "installed" } });
    expect(result.info.ran).toBe(false);
    expect(result.packages ?? []).toEqual([]);
  });

  it("reports no database_version when the install recorded no upstream date, never the archive hash", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "undated" },
    });

    expect(result.coverage[0]).toMatchObject({ ecosystem: "PyPI", state: "ran", database_checked_at: "2026-10-30T10:00:00.000Z" });
    expect(result.coverage[0]).not.toHaveProperty("database_version");
    expect(result.componentSignatures["osv-scanner:vulnerability-db:PyPI"]).toBe(dbRecord("PyPI").signature);
  });

  it("missing ecosystem DB is unavailable, not clean", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-missing-db.json"),
      lockfiles: { "package-lock.json": PACKAGE_LOCK },
    });

    expect(result.findings).toEqual([]);
    expect(result.applicable).toBe(true);
    expect(result.coverage).toHaveLength(1);
    expect(result.coverage[0]).toMatchObject({
      ecosystem: "npm",
      engine: "osv-scanner",
      state: "unavailable",
      packages: { resolved: 1, eligible: 0, skipped: 1 },
    });
    expect(result.warnings.join("\n")).toContain("codeinspectus setup");
    expect(result.warnings.join("\n")).toContain("npm");
    // Nothing was checked, so the engine did not effectively run.
    expect(result.info.ran).toBe(false);
    expect(result.info.note).toContain("codeinspectus setup");
  });

  it("a missing database next to an installed one still yields the installed ecosystem's findings", async () => {
    // Real 2.7.0 output for two lockfiles: PyPI findings (database installed) and an npm package
    // (no npm database). The overlay keeps osv-scanner from failing the whole scan over npm.
    const pypi = JSON.parse(await fixtureText("raw-vulnerable.json")) as { results: unknown[] };
    const npm = JSON.parse(await fixtureText("raw-missing-db.json")) as { results: unknown[] };
    const { result } = await scan({
      output: { ...pypi, results: [...pypi.results, ...npm.results] },
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS, "package-lock.json": PACKAGE_LOCK },
      db: { PyPI: "installed" },
    });

    expect(result.findings).toHaveLength(8);
    expect(new Set(result.findings.map((item) => item.package?.ecosystem))).toEqual(new Set(["PyPI"]));
    expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([
      ["npm", "unavailable"],
      ["PyPI", "ran"],
    ]);
    expect(result.coverage[0]).toMatchObject({ packages: { resolved: 1, eligible: 0, skipped: 1 } });
    expect(result.info.ran).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("npm");
    expect(result.warnings[0]).toContain("codeinspectus setup");
    // Coverage comes from the managed archive and record, not from the overlay's placeholder zips.
    expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:npm");
    expect(result.componentSignatures["osv-scanner:vulnerability-db:PyPI"]).toBe(dbRecord("PyPI").signature);
  });

  it("a lockfile from an ecosystem outside the allow-list (SwiftURL) does not fail the run", async () => {
    // Real 2.7.0 output for requirements.txt plus a Package.resolved, run with an empty SwiftURL archive.
    const pypi = JSON.parse(await fixtureText("raw-vulnerable.json")) as { results: unknown[] };
    const swift = JSON.parse(await fixtureText("raw-swifturl.json")) as { results: unknown[] };
    const { result, tmpDir } = await scan({
      lockfiles: { "requirements.txt": REQUIREMENTS, "Package.resolved": "{}\n" },
      db: { PyPI: "installed" },
      // What the real binary does: with no SwiftURL archive in its cache directory it exits 127 and reports nothing.
      respond: async (cacheDirectory) =>
        await lstat(join(cacheDirectory, "osv-scalibr", "SwiftURL", "all.zip")).then(() => true, () => false)
          ? { code: 1, output: { ...pypi, results: [...pypi.results, ...swift.results] } }
          : {
            code: 127,
            output: null,
            stderr: "could not load db for SwiftURL ecosystem: unable to fetch OSV database: no offline version of the OSV database is available",
          },
    });

    const entry = join(tmpDir, "osv-db-overlay", "osv-scalibr", "SwiftURL", "all.zip");
    const bytes = await readFile(entry);
    expect(bytes.length).toBe(22);
    expect(bytes.readUInt32LE(0)).toBe(0x06054b50);
    expect(result.info).toMatchObject({ available: true, ran: true, finding_count: 8 });
    expect(result.findings.find((item) => item.rule_id === "MAL-2026-2144")?.package).toEqual({ ecosystem: "PyPI", name: "litellm", version: "1.107.0" });
    expect(new Set(result.findings.map((item) => item.package?.ecosystem))).toEqual(new Set(["PyPI"]));
    expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "ran"], ["SwiftURL", "unavailable"]]);
    expect(result.coverage[1]!.note).toMatch(/"SwiftURL" ecosystem is not supported by CodeInspectus/);
    expect(result.coverage[1]).toMatchObject({ packages: { resolved: 1, eligible: 0, skipped: 1 } });
    expect(result.warnings).toEqual([result.coverage[1]!.note]);
    expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:SwiftURL");
  });

  it("a Conan lockfile (ConanCenter: in the OSV schema, not in the bucket list) does not fail the run", async () => {
    // Real 2.7.0 output for conan.lock, run with an empty ConanCenter archive.
    const pypi = JSON.parse(await fixtureText("raw-vulnerable.json")) as { results: unknown[] };
    const conan = JSON.parse(await fixtureText("raw-conan.json")) as { results: unknown[] };
    const { result, tmpDir } = await scan({
      lockfiles: { "requirements.txt": REQUIREMENTS, "conan.lock": "{}\n" },
      db: { PyPI: "installed" },
      // What the real binary does without a ConanCenter archive: it stops at that database (exit 127 here).
      respond: async (cacheDirectory) =>
        await lstat(join(cacheDirectory, "osv-scalibr", "ConanCenter", "all.zip")).then(() => true, () => false)
          ? { code: 1, output: { ...pypi, results: [...pypi.results, ...conan.results] } }
          : {
            code: 127,
            output: null,
            stderr: "could not load db for ConanCenter ecosystem: unable to fetch OSV database: no offline version of the OSV database is available",
          },
    });

    expect(execBinary).toHaveBeenCalledTimes(1);
    expect((await readFile(join(tmpDir, "osv-db-overlay", "osv-scalibr", "ConanCenter", "all.zip"))).length).toBe(22);
    expect(result.info).toMatchObject({ available: true, ran: true, finding_count: 8 });
    expect(result.findings.find((item) => item.rule_id === "MAL-2026-2144")?.package).toEqual({ ecosystem: "PyPI", name: "litellm", version: "1.107.0" });
    expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "ran"], ["ConanCenter", "unavailable"]]);
    expect(result.coverage[1]!.note).toMatch(/"ConanCenter" ecosystem is not supported by CodeInspectus/);
    expect(result.warnings).toEqual([result.coverage[1]!.note]);
    expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:ConanCenter");
  });

  describe("an ecosystem newer than both overlay snapshots", () => {
    const missing = (name: string) =>
      `could not load db for ${name} ecosystem: unable to fetch OSV database: no offline version of the OSV database is available`;
    const exists = (path: string) => lstat(path).then(() => true, () => false);
    const newlang = (doc("newlang.lock", [pkg("Newlang", "left-pad", "1.0.0")]) as { results: unknown[] }).results;

    it.each([
      ["exit 127 with no result", { code: 127, output: null }],
      // Once it has found vulnerabilities, 2.7.0 exits 1 and leaves the packages after the failed load unmatched.
      ["exit 1 with the later packages unmatched", {
        code: 1,
        output: doc("requirements.txt", [pkg("PyPI", "brotli", "1.2.0", [{ ids: ["PYSEC-2026-4322"], max_severity: "7.5" }])]),
      }],
    ] as Array<[string, Pick<RunOptions, "code" | "output">]>)(
      "gets an empty database and one retry after %s, and its coverage comes from the allow-list",
      async (_name, first) => {
        const pypi = JSON.parse(await fixtureText("raw-vulnerable.json")) as { results: unknown[] };
        const { result, tmpDir } = await scan({
          lockfiles: { "requirements.txt": REQUIREMENTS, "newlang.lock": "x\n" },
          db: { PyPI: "installed" },
          respond: async (cacheDirectory) =>
            await exists(join(cacheDirectory, "osv-scalibr", "Newlang", "all.zip"))
              ? { code: 1, output: { ...pypi, results: [...pypi.results, ...newlang] } }
              : { ...first, stderr: `Loaded PyPI local db from ${cacheDirectory}/osv-scalibr/PyPI/all.zip\n${missing("Newlang")}` },
        });

        expect(execBinary).toHaveBeenCalledTimes(2);
        expect((await readFile(join(tmpDir, "osv-db-overlay", "osv-scalibr", "Newlang", "all.zip"))).length).toBe(22);
        expect(result.info).toMatchObject({ available: true, ran: true, finding_count: 8 });
        expect(result.findings.some((item) => item.rule_id === "MAL-2026-2144")).toBe(true);
        expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "ran"], ["Newlang", "unavailable"]]);
        expect(result.coverage[1]!.note).toMatch(/"Newlang" ecosystem is not supported by CodeInspectus/);
        expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:Newlang");
      },
    );

    it("retries for the last name stderr reports only: earlier ones can be forged through repository paths", async () => {
      // osv-scanner prints its one real cause after every progress line; a nested path can spell out many fakes.
      const forged = Array.from({ length: 20 }, (_, index) => `Scanned <target>/${missing(`Fake${index}`)}/x file and found 1 package`);
      const { result, tmpDir } = await scan({
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
        respond: async (cacheDirectory) =>
          await exists(join(cacheDirectory, "osv-scalibr", "Otherlang", "all.zip"))
            ? { code: 1, output: await fixtureText("raw-vulnerable.json") }
            : { code: 127, output: null, stderr: [...forged, missing("Otherlang")].join("\n") },
      });

      expect(execBinary).toHaveBeenCalledTimes(2);
      const overlay = join(tmpDir, "osv-db-overlay", "osv-scalibr");
      expect((await readdir(overlay)).filter((name) => !OSV_OVERLAY_ECOSYSTEMS.includes(name))).toEqual(["Otherlang"]);
      expect(result.info).toMatchObject({ ran: true, finding_count: 8 });
    });

    it("retries for a name with an interior space, like the seeded \"Azure Linux\"", async () => {
      const { result, tmpDir } = await scan({
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
        respond: async (cacheDirectory) =>
          await exists(join(cacheDirectory, "osv-scalibr", "New Lang", "all.zip"))
            ? { code: 1, output: await fixtureText("raw-vulnerable.json") }
            : { code: 127, output: null, stderr: missing("New Lang") },
      });

      expect(execBinary).toHaveBeenCalledTimes(2);
      expect((await readFile(join(tmpDir, "osv-db-overlay", "osv-scalibr", "New Lang", "all.zip"))).length).toBe(22);
      expect(result.info).toMatchObject({ ran: true, finding_count: 8 });
    });

    it("retries at most once, then reports the failure as before", async () => {
      let calls = 0;
      const { result, tmpDir } = await scan({
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
        // Each run names a new ecosystem, as it would for a repository using two that are unknown here.
        respond: async () => ({ code: 127, output: null, stderr: missing(`Newlang${++calls}`) }),
      });

      expect(execBinary).toHaveBeenCalledTimes(2);
      expect(await exists(join(tmpDir, "osv-db-overlay", "osv-scalibr", "Newlang1", "all.zip"))).toBe(true);
      expect(await exists(join(tmpDir, "osv-db-overlay", "osv-scalibr", "Newlang2"))).toBe(false);
      expect(result.info).toMatchObject({ available: true, ran: false });
      expect(result.info.note).toContain("exited with code 127");
      expect(result.info.note).toContain("could not load db for Newlang2 ecosystem");
      expect(result.info.note).toContain("does not support");
      expect(result.findings).toEqual([]);
      expect(result.coverage).toEqual([]);
    });

    it.each([
      ["a path traversal", "../escape"],
      ["a double dot", "a..b"],
      ["a trailing dot, which Windows would map onto a seeded directory", "Go."],
      ["a Windows reserved device name", "NUL"],
      ["a Windows reserved device name with an extension", "com1.db"],
      ["more than 64 characters", `L${"a".repeat(64)}`],
      ["an ecosystem the overlay already seeds (a corrupt installed archive)", "PyPI"],
      ["another spelling of a seeded one, which would alias its link", "pypi"],
    ])("never retries for a name with %s", async (_name, name) => {
      const { result, tmpDir } = await scan({
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
        respond: async () => ({ code: 127, output: null, stderr: missing(name) }),
      });

      expect(execBinary).toHaveBeenCalledTimes(1);
      expect(result.info.ran).toBe(false);
      expect(result.info.note).toContain("exited with code 127");
      const overlay = join(tmpDir, "osv-db-overlay");
      expect((await readdir(join(overlay, "osv-scalibr"))).sort()).toEqual([...OSV_OVERLAY_ECOSYSTEMS].sort());
      expect(await readdir(overlay)).toEqual(["osv-scalibr"]);
      // The installed archive behind the PyPI link is untouched.
      expect(await readFile(osvDbZipPath("PyPI"), "utf8")).toBe("zip!");
    });

    it("keeps the first result, lowered to partial, when the empty database cannot be written", async () => {
      fsFaults.writeFileMatching = /Newlang/;
      const { result, tmpDir } = await scan({
        code: 1,
        output: await fixtureText("raw-vulnerable.json"),
        stderr: missing("Newlang"),
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
      });

      expect(execBinary).toHaveBeenCalledTimes(1);
      expect(await exists(join(tmpDir, "osv-db-overlay", "osv-scalibr", "Newlang", "all.zip"))).toBe(false);
      expect(result.info).toMatchObject({ ran: true, finding_count: 8 });
      expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "partial"]]);
      expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");
    });

    it("never retries a completed clean run, and a forged line costs one run and can only lower coverage", async () => {
      const forged = `Scanned <target>/x\n${missing("Newlang")}`;
      const clean = await scan({ code: 0, output: { results: [], experimental_config: {} }, stderr: forged, db: { PyPI: "installed" } });
      expect(execBinary).toHaveBeenCalledTimes(1);
      expect(clean.result.info.ran).toBe(true);
      expect(clean.result.warnings).toEqual([STOPPED_EARLY]);
      expect(clean.result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");

      const options = {
        code: 1,
        output: await fixtureText("raw-vulnerable.json"),
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" as const },
      };
      const plain = await scan(options);
      execBinary.mockClear();
      const withForgery = await scan({ ...options, stderr: forged });

      // Ruling 35: the same findings and run, never more coverage; coverage goes down to partial.
      expect(execBinary).toHaveBeenCalledTimes(2);
      expect(withForgery.result.findings).toEqual(plain.result.findings);
      expect(withForgery.result.info).toMatchObject({ ran: true, finding_count: plain.result.info.finding_count });
      expect(plain.result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "ran"]]);
      expect(withForgery.result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "partial"]]);
      expect(withForgery.result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");
      expect(withForgery.result.warnings).toEqual([STOPPED_EARLY]);
    });

    it("Ruling 35: stderr naming a database it could not load lowers the run to partial and drops database signatures", async () => {
      // An installed archive osv-scanner cannot read: the name is seeded, so there is no retry (review path e).
      const { result } = await scan({
        code: 1,
        output: await fixtureText("raw-vulnerable.json"),
        stderr: "could not load db for npm ecosystem: unable to fetch OSV database: could not read OSV database archive: zip: not a valid zip file",
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed", npm: "installed" },
      });

      expect(execBinary).toHaveBeenCalledTimes(1);
      expect(result.findings).toHaveLength(8);
      expect(result.info).toMatchObject({ ran: true, finding_count: 8 });
      expect(result.coverage).toEqual([expect.objectContaining({ ecosystem: "PyPI", state: "partial", note: STOPPED_EARLY })]);
      expect(result.coverage[0]!.limitations).toContain(STOPPED_EARLY);
      expect(Object.keys(result.componentSignatures).filter((key) => key.includes("vulnerability-db"))).toEqual([]);
      expect(result.componentSignatures).toHaveProperty("osv-scanner:binary");
      expect(result.warnings).toEqual([STOPPED_EARLY]);
    });

    it("Ruling 35: output naming an ecosystem with no overlay entry lowers the run to partial, with no stderr at all", async () => {
      const pypi = JSON.parse(await fixtureText("raw-vulnerable.json")) as { results: unknown[] };
      const unknown = (doc("future.lock", [pkg("Futurelang:v2", "left-pad", "1.0.0")]) as { results: unknown[] }).results;
      const { result } = await scan({
        code: 1,
        output: { ...pypi, results: [...pypi.results, ...unknown] },
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
      });

      expect(result.findings).toHaveLength(8);
      expect(result.info.ran).toBe(true);
      // The unknown ecosystem stays unavailable; nothing is added or raised.
      expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([["PyPI", "partial"], ["Futurelang:v2", "unavailable"]]);
      expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");
      expect(result.warnings).toContain(STOPPED_EARLY);
    });

    it("Ruling 35: a retry that stops at a second unknown ecosystem is partial, never ran", async () => {
      const pypi = JSON.parse(await fixtureText("raw-vulnerable.json")) as { results: unknown[] };
      const second = (doc("second.lock", [pkg("Secondlang", "x", "1.0.0")]) as { results: unknown[] }).results;
      const { result, tmpDir } = await scan({
        lockfiles: { "requirements.txt": REQUIREMENTS },
        db: { PyPI: "installed" },
        respond: async (cacheDirectory) =>
          await exists(join(cacheDirectory, "osv-scalibr", "Newlang", "all.zip"))
            ? { code: 1, output: { ...pypi, results: [...pypi.results, ...newlang, ...second] }, stderr: missing("Secondlang") }
            : { code: 127, output: null, stderr: missing("Newlang") },
      });

      expect(execBinary).toHaveBeenCalledTimes(2);
      expect(await exists(join(tmpDir, "osv-db-overlay", "osv-scalibr", "Secondlang"))).toBe(false);
      expect(result.info).toMatchObject({ ran: true, finding_count: 8 });
      expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([
        ["PyPI", "partial"], ["Newlang", "unavailable"], ["Secondlang", "unavailable"],
      ]);
      expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");
    });
  });

  it("treats a recorded database whose archive is gone as unavailable (osv-scanner would report nothing)", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-missing-db.json"),
      lockfiles: { "package-lock.json": PACKAGE_LOCK },
      db: { npm: "record-only" },
    });

    expect(result.coverage[0]).toMatchObject({ ecosystem: "npm", state: "unavailable" });
    expect(result.warnings.join("\n")).toContain("codeinspectus setup");
    expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:npm");
  });

  it("reports findings from an archive with no provenance record as partial, with no database signature", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "archive-only" },
    });

    expect(result.findings).toHaveLength(8);
    expect(result.coverage[0]).toMatchObject({ ecosystem: "PyPI", state: "partial" });
    expect(result.coverage[0]!.database_version).toBeUndefined();
    expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");
    expect(result.warnings.join("\n")).toContain("codeinspectus setup");
    expect(result.info.ran).toBe(true);
  });

  it("treats a record that does not describe the archive on disk like no record: partial, no database signature", async () => {
    const { result } = await scan({
      output: await fixtureText("raw-vulnerable.json"),
      code: 1,
      lockfiles: { "requirements.txt": REQUIREMENTS },
      db: { PyPI: "mismatched" },
    });

    expect(result.findings).toHaveLength(8);
    expect(result.coverage[0]).toMatchObject({ ecosystem: "PyPI", state: "partial" });
    expect(result.coverage[0]!.database_version).toBeUndefined();
    expect(result.coverage[0]!.database_checked_at).toBeUndefined();
    expect(result.componentSignatures).not.toHaveProperty("osv-scanner:vulnerability-db:PyPI");
    expect(result.findings.every((item) => !item.message.includes("database recorded"))).toBe(true);
    expect(result.warnings.join("\n")).toContain("codeinspectus setup");
    expect(result.info.ran).toBe(true);
  });

  it("covers every ecosystem seen, in allow-list order, and marks unsupported ecosystems unavailable", async () => {
    const { result } = await scan({
      output: {
        results: [
          ...(doc("requirements.txt", [pkg("PyPI", "a", "1.0.0")]) as { results: unknown[] }).results,
          ...(doc("package-lock.json", [pkg("npm", "b", "1.0.0")]) as { results: unknown[] }).results,
          ...(doc("pnpm-lock.yaml", [pkg("npm", "c", "1.0.0")]) as { results: unknown[] }).results,
          ...(doc("odd.lock", [pkg("Alpine:v3.18", "d", "1.0.0"), pkg("", "e", "abc123")]) as { results: unknown[] }).results,
        ],
      },
      lockfiles: { "requirements.txt": "a\n" },
      db: { PyPI: "installed", npm: "installed" },
    });

    expect(result.coverage.map((entry) => [entry.ecosystem, entry.state])).toEqual([
      ["npm", "ran"],
      ["PyPI", "ran"],
      ["Alpine:v3.18", "unavailable"],
      ["unknown", "unavailable"],
    ]);
    const npm = result.coverage[0]!;
    expect(npm.lockfiles).toEqual({ discovered: 2, analyzed: 2 });
    expect(npm.packages).toEqual({ resolved: 2, eligible: 2, skipped: 0 });
    const alpine = result.coverage[2]!;
    expect(alpine.note).toMatch(/not supported/i);
    expect(result.warnings.join("\n")).toMatch(/Alpine:v3\.18[^\n]*not supported/i);
    expect(result.info.ran).toBe(true); // PyPI and npm were checked
  });
});

describe("osv-scanner run outcomes", () => {
  it("no lockfiles, run completed → a recorded run with no findings, coverage or warnings", async () => {
    const { result } = await scan({ output: { results: [], experimental_config: {} }, db: { PyPI: "installed" } });

    // Recorded so rescan can prove that removing the last lockfile resolved its findings.
    expect(result.applicable).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.coverage).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.info).toMatchObject({ engine: "osv-scanner", available: true, ran: true, finding_count: 0 });
    expect(result.info.note).toBeUndefined();
    // The installed databases are still signed: a rescan compares them with the prior scan's.
    expect(result.componentSignatures["osv-scanner:vulnerability-db:PyPI"]).toBe(dbRecord("PyPI").signature);
  });

  it("progress lines on stderr never affect the result (a forged \"found 0 packages\" line included)", async () => {
    // A crafted file name containing a newline can make osv-scanner print any line, so stderr is never coverage input.
    const forged = "Scanned <target>/requirements.txt file and found 0 packages";
    const runs = [
      { output: await fixtureText("raw-vulnerable.json"), code: 1 },
      { output: { results: [], experimental_config: {} }, code: 0 },
    ];
    for (const run of runs) {
      const options = { ...run, lockfiles: { "requirements.txt": REQUIREMENTS }, db: { PyPI: "installed" as const } };
      const plain = await scan(options);
      const withForgery = await scan({ ...options, stderr: `Scanning dir <target>\n${forged}\nNo package sources found` });

      const comparable = ({ result }: Awaited<ReturnType<typeof scan>>) => ({ ...result, info: { ...result.info, duration_ms: 0 } });
      expect(comparable(withForgery)).toEqual(comparable(plain));
    }
  });

  it.each([
    ["exit 127", { code: 127, output: null, stderr: "failed to resolve path: stat /x: no such file or directory" }],
    ["unparseable output", { code: 0, output: "not json {" }],
    ["JSON without a results array", { code: 0, output: { nope: true } }],
    ["no output file", { code: 0, output: null }],
    ["an unexpected exit code with parseable output", { code: 2, output: { results: [] } }],
    ["a spawn failure", { code: null, output: null, stderr: "[spawn error] ENOENT" }],
  ] as Array<[string, RunOptions]>)("%s → info.ran false with a note, never clean", async (_name, options) => {
    const { result } = await scan(options);

    expect(result.info).toMatchObject({ engine: "osv-scanner", available: true, ran: false });
    expect(result.info.note).toMatch(/osv-scanner/);
    expect(result.findings).toEqual([]);
    expect(result.applicable).toBe(true);
    expect(result.warnings.join("\n")).toContain(result.info.note!);
  });

  it("never takes a progress line as the cause because its path holds a keyword", async () => {
    const { result } = await scan({
      code: 127,
      output: null,
      stderr: [
        "Scanning dir <target>",
        "Scanned <target>/error-pages/requirements.txt file and found 3 packages",
        "Scanned <target>/failed-builds/package-lock.json file and found 1 package",
        "End status: 1 dirs visited, 3 inodes visited, 2 Extract calls, 1ms elapsed, 1ms wall time",
        "the archive is truncated",
      ].join("\n"),
    });

    expect(result.info.note).toContain("Cause: the archive is truncated.");
    expect(result.info.note).not.toContain("error-pages");
    expect(result.info.note).not.toContain("failed-builds");
  });

  it("ends a truncated cause with the ellipsis alone", async () => {
    const { result } = await scan({ code: 127, output: null, stderr: `error: ${"x".repeat(600)}` });

    expect(result.info.note).toMatch(/x…$/);
    expect(result.info.note).not.toContain("….");
  });

  it("includes truncated stderr in the exit-127 note", async () => {
    const { result } = await scan({ code: 127, output: null, stderr: "failed to resolve path" });

    expect(result.info.note).toContain("127");
    expect(result.info.note).toContain("failed to resolve path");
  });

  it("keeps the cause of a corrupt-database failure, hints at setup, and does not echo the target path", async () => {
    // Shape of a real 2.7.0 run against a corrupt PyPI archive: exit 127, progress lines first, the cause last.
    const progress = Array.from({ length: 6 }, (_, index) =>
      `Scanned <target>/services/api-${index}/requirements.txt file and found ${index + 4} packages`).join("\n");
    const stderr = [
      "Scanning dir <target>",
      "Starting filesystem walk for root: /",
      progress,
      "End status: 1 dirs visited, 2 inodes visited, 1 Extract calls, 435.709µs elapsed, 435µs wall time",
      "could not load db for PyPI ecosystem: unable to fetch OSV database: could not read OSV database archive: zip: not a valid zip file",
      "Error during extraction: (extracting as vulnmatch/osvlocal) unable to fetch OSV database: could not read OSV database archive: zip: not a valid zip file",
    ].join("\n");
    expect(stderr.indexOf("could not load db")).toBeGreaterThan(300);
    let target = "";
    execBinary.mockImplementation(async (_binary: string, args: string[]) => {
      target = args[args.length - 1]!;
      return { code: 127, stdout: "", stderr: stderr.replaceAll("<target>", target), timedOut: false };
    });
    const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-run-"));
    cleanup.push(base);

    const result = await runOsvScanner(base, base);

    expect(result.info.ran).toBe(false);
    expect(result.info.note).toContain("127");
    expect(result.info.note).toContain("could not load db for PyPI ecosystem");
    expect(result.info.note).toContain("zip: not a valid zip file");
    expect(result.info.note).toContain("codeinspectus setup");
    expect(result.info.note).not.toContain(target);
    expect(result.info.note).not.toContain("Starting filesystem walk");
    expect(result.warnings.join("\n")).toContain("could not load db");
    expect(result.info.note!.length).toBeLessThan(900);
  });

  it("redacts every local path, longest first and only at path boundaries", async () => {
    const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-run-"));
    cleanup.push(base);
    const home = join(base, "home", "someuser");
    const tmpDir = join(home, "work", "tmp");
    await mkdir(tmpDir, { recursive: true });
    const failure = (path: string) => `error: cannot open ${path}`;
    const stderr = [
      failure(`${tmpDir}/osv-db-overlay/osv-scalibr/PyPI/all.zip`),
      failure(`${MANAGED_OSV_DB}/osv-scalibr/npm/all.zip`),
      failure(`${home}/work2/requirements.txt`),
      failure(`${home}/.cache/x`),
    ].join("\n");
    execBinary.mockResolvedValue({ code: 2, stdout: "", stderr, timedOut: false });
    // os.homedir() reads HOME on POSIX and USERPROFILE on Windows: set both, restore both exactly.
    const previous = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    let result;
    try {
      // The target is an ancestor of the temp directory and of the home directory.
      result = await runOsvScanner(base, tmpDir);
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }

    const note = result.info.note!;
    expect(note).toContain("<managed-temp>/osv-db-overlay/osv-scalibr/PyPI/all.zip");
    expect(note).toContain("<managed-osv-db>/osv-scalibr/npm/all.zip");
    // `${home}/work` is not a prefix of `${home}/work2`: the home directory is what matches there.
    expect(note).toContain("~/work2/requirements.txt");
    expect(note).toContain("~/.cache/x");
    expect(note).not.toContain("someuser");
    expect(note).not.toContain(base);
  });

  it("redacts a path that ends a sentence, but not a longer name that starts with it", async () => {
    const { result, target } = await scan({
      code: 2,
      output: null,
      respond: async (cacheDirectory) => {
        const repo = join(cacheDirectory, "..", "..", "repo");
        return { code: 2, output: null, stderr: `error: could not scan ${repo}.\nerror: skipped ${repo}.bak/requirements.txt` };
      },
    });

    expect(result.info.note).toContain("error: could not scan <target>.");
    expect(result.info.note).toContain(`${target}.bak/requirements.txt`);
    expect(result.info.note).not.toContain("<target>.bak");
  });

  it("redacts local paths in an unexpected wrapper error", async () => {
    const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-run-"));
    cleanup.push(base);
    await mkdir(join(base, "repo"));
    execBinary.mockRejectedValueOnce(Object.assign(new Error(`ENOENT: no such file or directory, open '${base}/osv-scanner.json'`), { code: "ENOENT" }));

    const result = await runOsvScanner(join(base, "repo"), base);

    expect(result.info.ran).toBe(false);
    expect(result.info.note).toContain("osv-scanner failed: ENOENT: no such file or directory, open '<managed-temp>/osv-scanner.json'");
    expect(result.info.note).not.toContain(base);
  });

  it("adds no setup hint to an unrelated failure and still redacts managed paths", async () => {
    const { result } = await scan({
      code: 2,
      output: null,
      stderr: `unexpected flag\nerror: cannot open ${MANAGED_OSV_DB}/osv-scalibr/PyPI/all.zip`,
    });

    expect(result.info.note).toContain("cannot open <managed-osv-db>/osv-scalibr/PyPI/all.zip");
    expect(result.info.note).not.toContain(MANAGED_OSV_DB);
    expect(result.info.note).not.toContain("codeinspectus setup");
  });

  it("does not suggest setup when the database osv-scanner could not load is for an unsupported ecosystem", async () => {
    const { result } = await scan({
      code: 127,
      output: null,
      stderr: "could not load db for Newlang ecosystem: unable to fetch OSV database: no offline version of the OSV database is available",
    });

    expect(result.info.ran).toBe(false);
    expect(result.info.note).toContain("could not load db for Newlang ecosystem");
    expect(result.info.note).toContain("does not support");
    expect(result.info.note).not.toContain("reinstall");
  });

  it("exit 1 with nothing mappable is a failure, never a clean result", async () => {
    const unmappable: Array<[string, object]> = [
      ["a package with no name", doc("requirements.txt", [
        { package: { version: "1.0.0", ecosystem: "PyPI" }, groups: [{ ids: ["CVE-2030-1"], aliases: [], max_severity: "9.0" }] },
      ])],
      ["groups whose ids are not identifiers", doc("requirements.txt", [
        pkg("PyPI", "x", "1.0.0", [{ ids: ["bad id", "../../etc/passwd"], max_severity: "5.0" }]),
      ])],
      ["an empty results array", { results: [], experimental_config: {} }],
    ];
    for (const [, output] of unmappable) {
      const { result } = await scan({ code: 1, output, lockfiles: { "requirements.txt": "x\n" }, db: { PyPI: "installed" } });

      expect(result.info.ran).toBe(false);
      expect(result.info.note).toContain("osv-scanner reported vulnerabilities that could not be mapped");
      expect(result.findings).toEqual([]);
      expect(result.applicable).toBe(true);
      expect(result.coverage).toEqual([]);
      expect(result.warnings.join("\n")).toContain("could not be mapped");
    }
  });

  it("warns about advisory groups it could not map when others were mapped", async () => {
    const { result } = await scan({
      code: 1,
      output: doc("requirements.txt", [
        pkg("PyPI", "x", "1.0.0", [{ ids: ["CVE-2030-1"], max_severity: "5.0" }, { ids: ["bad id"], max_severity: "9.0" }]),
        { package: { version: "1.0.0", ecosystem: "PyPI" }, groups: [{ ids: ["CVE-2030-2"], aliases: [], max_severity: "9.0" }] },
      ]),
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });

    expect(result.info.ran).toBe(true);
    expect(result.findings.map((item) => item.rule_id)).toEqual(["CVE-2030-1"]);
    expect(result.warnings).toEqual([
      "osv-scanner reported 2 advisory groups that could not be mapped (an unreadable package name or advisory id); they are not in the findings.",
    ]);
  });

  it("exit 0 with no findings stays clean, and exit 1 with some mapped findings is reported", async () => {
    const clean = await scan({
      code: 0,
      output: doc("requirements.txt", [pkg("PyPI", "x", "1.0.0")]),
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });
    expect(clean.result.info.ran).toBe(true);
    expect(clean.result.coverage[0]).toMatchObject({ ecosystem: "PyPI", state: "ran" });

    const found = await scan({
      code: 1,
      output: doc("requirements.txt", [pkg("PyPI", "x", "1.0.0", [{ ids: ["CVE-2030-1"], max_severity: "5.0" }])]),
      lockfiles: { "requirements.txt": "x\n" },
      db: { PyPI: "installed" },
    });
    expect(found.result.info.ran).toBe(true);
    expect(found.result.findings).toHaveLength(1);
    expect(found.result.warnings).toEqual([]);
  });

  it("logs a completed run's stderr at debug level, redacted", async () => {
    const { log } = await import("../logger.js");
    const debug = vi.spyOn(log, "debug").mockImplementation(() => undefined);
    try {
      const { target } = await scan({
        code: 0,
        output: { results: [], experimental_config: {} },
        respond: async (cacheDirectory) => ({
          code: 0,
          output: { results: [], experimental_config: {} },
          stderr: `Loaded PyPI local db from ${cacheDirectory}/osv-scalibr/PyPI/all.zip\nwarning: something unexpected`,
        }),
      });
      const logged = debug.mock.calls.map(([message]) => String(message)).filter((message) => message.startsWith("osv-scanner stderr"));
      expect(logged).toEqual(["osv-scanner stderr (exit 0): warning: something unexpected"]);
      expect(logged.join("")).not.toContain(target);
    } finally {
      debug.mockRestore();
    }
  });

  it("a timeout is a note even when partial output parses", async () => {
    const { result } = await scan({ timedOut: true, code: null, output: { results: [] } });

    expect(result.info.ran).toBe(false);
    expect(result.info.note).toMatch(/timed out/i);
  });

  it("an engine that is not installed is a warning with no engine_details entry", async () => {
    vi.mocked(resolveEngine).mockRejectedValueOnce(
      new EngineUnavailableError("osv-scanner", "missing", "Engine 'osv-scanner' is not available. Run `codeinspectus setup`."),
    );
    const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-run-"));
    cleanup.push(base);

    const result = await runOsvScanner(base, base);

    expect(result.applicable).toBe(false);
    expect(result.info).toMatchObject({ engine: "osv-scanner", available: false, ran: false });
    expect(result.info.note).toContain("codeinspectus setup");
    expect(result.warnings.join("\n")).toContain("codeinspectus setup");
    expect(execBinary).not.toHaveBeenCalled();
  });

  it("removes a stale output file before running so an old result is never read as fresh", async () => {
    const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-run-"));
    cleanup.push(base);
    await writeFile(join(base, "osv-scanner.json"), JSON.stringify(doc("requirements.txt", [pkg("PyPI", "stale", "1.0.0", [{ ids: ["CVE-2030-1"] }])])), "utf8");
    execBinary.mockResolvedValue({ code: 0, stdout: "", stderr: "", timedOut: false });

    const result = await runOsvScanner(base, base);

    expect(result.findings).toEqual([]);
    expect(result.info.ran).toBe(false);
  });
});

describe("osv-scanner over the per-scan SBOM", () => {
  const JQUERY = pkg("npm", "jquery", "1.12.4", [{ ids: ["GHSA-6c3j-c64m-qhgq"], aliases: ["CVE-2019-11358"], max_severity: "6.1" }], [
    { id: "GHSA-6c3j-c64m-qhgq", summary: "Prototype Pollution in jQuery", affected: [{ package: { ecosystem: "npm", name: "jquery" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.4.0" }] }] }] },
  ]);
  const declared = (file: string, line: number) => ({ file, line, lead: `${file}:${line} ships npm package jquery@1.12.4.` });

  async function sbomRun(options: {
    output?: object | null;
    code?: number;
    timedOut?: boolean;
    stderr?: string;
    db?: Partial<Record<OsvEcosystem, DbMode>>;
    ecosystems?: OsvEcosystem[];
    locate?: Parameters<typeof runOsvScannerOnSbom>[2]["locate"];
    expected?: Parameters<typeof runOsvScannerOnSbom>[2]["expected"];
  } = {}) {
    const base = await mkdtemp(join(tmpdir(), "codeinspectus-osv-sbom-"));
    cleanup.push(base);
    const workDir = join(base, "synvoya-sbom");
    await mkdir(workDir, { recursive: true });
    const sbomPath = join(workDir, OSV_SBOM_FILE_NAME);
    await writeFile(sbomPath, "{}", "utf8");
    state.records.clear();
    for (const [ecosystem, mode] of Object.entries(options.db ?? { npm: "installed" }) as Array<[OsvEcosystem, DbMode]>) {
      if (mode !== "archive-only") state.records.set(ecosystem, dbRecord(ecosystem));
      if (mode !== "record-only") {
        await mkdir(join(osvDbZipPath(ecosystem), ".."), { recursive: true });
        await writeFile(osvDbZipPath(ecosystem), mode === "mismatched" ? "zip!+" : "zip!", "utf8");
      }
    }
    execBinary.mockImplementation(async (_binary: string, args: string[]) => {
      const outputPath = args[args.indexOf("--output-file") + 1]!;
      if (options.output !== null) {
        const document = options.output ?? { results: [{ source: { path: sbomPath, type: "sbom" }, packages: [JQUERY] }] };
        await writeFile(outputPath, JSON.stringify(document), "utf8");
      }
      return { code: options.code ?? 1, stdout: "", stderr: options.stderr ?? "", timedOut: options.timedOut ?? false };
    });
    const result = await runOsvScannerOnSbom(sbomPath, workDir, {
      ecosystems: options.ecosystems ?? ["npm"],
      expected: options.expected ?? [],
      locate: options.locate ?? ((found) => (found.name === "jquery" && found.version === "1.12.4" ? [declared("public/js/jquery-1.12.4.min.js", 1), declared("index.html", 3)] : [])),
    });
    return { result, workDir, base };
  }

  it("takes the main run's flags with -L and the SBOM's own name, never -r", () => {
    const args = buildOsvScannerSbomArgs(OSV_SBOM_FILE_NAME, "/managed-temp/out.json", "/managed/osv-scanner.toml");
    expect(args).toEqual([
      ...buildOsvScannerArgs("/repo", "/managed-temp/out.json", "/managed/osv-scanner.toml").slice(0, -2),
      "-L", "inventory.cdx.json",
    ]);
    expect(args).not.toContain("-r");
    expect(() => buildOsvScannerSbomArgs("sbom.json", "/o", "/c")).toThrow(/inventory\.cdx\.json/);
    expect(osvSbomInvocationSignature()).toBe(invocationSignature("osv-scanner", buildOsvScannerSbomArgs(OSV_SBOM_FILE_NAME, "<managed-temp>", "<managed-config>")));
  });

  it("runs offline in the SBOM's folder with its own overlay, and reports each package at every declaration, never at the SBOM", async () => {
    const { result, workDir, base } = await sbomRun();
    const [binary, args, execOptions] = execBinary.mock.calls[0]!;
    expect(binary).toBe("/test/osv-scanner");
    expect(args.at(-1)).toBe(OSV_SBOM_FILE_NAME);
    expect(execOptions).toMatchObject({ cwd: workDir, offline: true, env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: join(workDir, "osv-db-overlay") } });
    expect(result).toMatchObject({ state: "ran", complete: true, warnings: [], missingDatabases: [] });
    expect(result.findings.map((finding) => `${finding.rule_id}@${finding.location.file}:${finding.location.start_line}`)).toEqual([
      "CVE-2019-11358@public/js/jquery-1.12.4.min.js:1",
      "CVE-2019-11358@index.html:3",
    ]);
    for (const finding of result.findings) {
      expect(findingSchema.parse(finding)).toBeTruthy();
      expect(finding).toMatchObject({ engine: "osv-scanner", engines: ["osv-scanner"], package: { ecosystem: "npm", name: "jquery", version: "1.12.4" } });
      expect(finding.producer_components).toEqual(osvSbomFindingComponents("npm"));
      expect(finding.message.startsWith(`${finding.location.file}:${finding.location.start_line} ships npm package jquery@1.12.4. `)).toBe(true);
      expect(JSON.stringify(finding)).not.toContain(base);
      expect(JSON.stringify(finding)).not.toContain(OSV_SBOM_FILE_NAME);
    }
  });

  it("a location grouped by vendored root keys its fingerprint on the root, not on the file it is shown at", async () => {
    const at = (file: string) => ({ ...declared(file, 1), fingerprintScope: "public/libs/jquery" });
    const fingerprintAt = async (file: string) =>
      (await sbomRun({ locate: (found) => (found.name === "jquery" ? [at(file)] : []) })).result.findings[0]!;
    const first = await fingerprintAt("public/libs/jquery/jquery.min.js");
    const moved = await fingerprintAt("public/libs/jquery/a/jquery.min.js");
    expect(first.location.file).toBe("public/libs/jquery/jquery.min.js");
    expect(moved.fingerprint).toBe(first.fingerprint);
    expect(first.id).toBe(first.fingerprint);
    expect(first.fingerprint).toBe(makeFingerprint(["osv-scanner", "vendored-root", "public/libs/jquery", "jquery", "1.12.4", "CVE-2019-11358"]));
  });

  it("never runs without the needed database: unavailable, naming it", async () => {
    const { result } = await sbomRun({ db: { PyPI: "installed" } });
    expect(execBinary).not.toHaveBeenCalled();
    expect(result).toMatchObject({ state: "unavailable", missingDatabases: ["npm"], complete: false, findings: [] });
  });

  it("a missing database for one needed ecosystem does not stop the others: the run goes ahead and names it", async () => {
    const { result } = await sbomRun({
      db: { npm: "installed" },
      ecosystems: ["npm", "Packagist"],
      expected: [{ ecosystem: "npm", name: "jquery", version: "1.12.4" }, { ecosystem: "Packagist", name: "magento/community-edition", version: "2.4.7-p2" }],
    });
    expect(execBinary).toHaveBeenCalledTimes(1);
    // Complete for what it could check; the caller treats the missing ecosystem's packages as not checked.
    expect(result).toMatchObject({ state: "ran", complete: true, missingDatabases: ["Packagist"], warnings: [] });
    expect(result.findings).toHaveLength(2);
  });

  it("a package checked under its advisory name is reported under the name the repository declares, with the advisory's fixes", async () => {
    const magento = pkg("Packagist", "magento/community-edition", "2.4.7-p2", [{ ids: ["GHSA-2qhq-fw98-h6wg"], aliases: ["CVE-2024-45115"], max_severity: "9.8" }], [{
      id: "GHSA-2qhq-fw98-h6wg",
      summary: "Magento Open Source allows Improper Authentication",
      affected: [{ package: { ecosystem: "Packagist", name: "magento/community-edition" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.4.7-beta1" }, { fixed: "2.4.7-p3" }] }] }],
    }]);
    const { result } = await sbomRun({
      db: { Packagist: "installed" },
      ecosystems: ["Packagist"],
      output: { results: [{ source: { path: "<sbom>", type: "sbom" }, packages: [magento] }] },
      expected: [{ ecosystem: "Packagist", name: "magento/community-edition", version: "2.4.7-p2" }],
      locate: (found) => found.name === "magento/community-edition"
        ? [{ file: "src/composer.lock", line: 17142, lead: "src/composer.lock:17142 locks magento/product-community-edition 2.4.7-p2.", declaredName: "magento/product-community-edition" }]
        : [],
    });
    expect(result).toMatchObject({ state: "ran", complete: true });
    const [finding] = result.findings;
    expect(findingSchema.parse(finding)).toBeTruthy();
    expect(finding).toMatchObject({
      rule_id: "CVE-2024-45115",
      vulnerability_aliases: ["GHSA-2qhq-fw98-h6wg"],
      location: { file: "src/composer.lock", start_line: 17142, end_line: 17142 },
      package: { ecosystem: "Packagist", name: "magento/product-community-edition", version: "2.4.7-p2" },
      title: "Magento Open Source allows Improper Authentication (magento/product-community-edition@2.4.7-p2)",
      producer_components: osvSbomFindingComponents("Packagist"),
    });
    expect(finding!.remediation.summary).toBe("Upgrade magento/product-community-edition to 2.4.7-p3, the fixed release listed upstream, or remove the package.");
    expect(finding!.message.startsWith("src/composer.lock:17142 locks magento/product-community-edition 2.4.7-p2. CVE-2024-45115")).toBe(true);
    // The fingerprint is the main run's formula over the declared package, so the main run's own finding
    // for the same advisory on that package in that file is the same finding (the caller folds it).
    expect(finding!.fingerprint).toBe(makeFingerprint(["osv-scanner", "src/composer.lock", "magento/product-community-edition", "2.4.7-p2", "CVE-2024-45115"]));
  });

  it("an engine that is not installed is unavailable", async () => {
    vi.mocked(resolveEngine).mockRejectedValueOnce(new EngineUnavailableError("osv-scanner", "missing", "Engine 'osv-scanner' is not available."));
    const { result } = await sbomRun();
    expect(result).toMatchObject({ state: "unavailable", reason: "osv-scanner is not installed", findings: [] });
  });

  it.each([
    ["a timeout", { timedOut: true }, /timed out/],
    ["an unexpected exit", { code: 2, stderr: "boom: failed to read" }, /exited with code 2/],
    ["no output file", { output: null, code: 0 }, /no output file/],
    ["output that is not a result", { output: { nope: true }, code: 0 }, /not the expected JSON/],
    ["exit 1 with nothing mappable", { locate: () => [] }, /could not be mapped/],
  ])("%s is a failed run with a reason that names no local path", async (_label, options, reason) => {
    const { result, base } = await sbomRun(options as Parameters<typeof sbomRun>[0]);
    expect(result.state).toBe("failed");
    expect(result.reason).toMatch(reason);
    expect(result.reason).not.toContain(base);
    expect(result.complete).toBe(false);
  });

  it("a package the SBOM names that osv-scanner does not list makes the run incomplete (review m1)", async () => {
    const clean = pkg("npm", "bootstrap", "3.3.7");
    const listedAll = await sbomRun({
      output: { results: [{ source: { path: "<sbom>" }, packages: [JQUERY, clean] }] },
      expected: [{ ecosystem: "npm", name: "jquery", version: "1.12.4" }, { ecosystem: "npm", name: "bootstrap", version: "3.3.7" }],
    });
    expect(listedAll.result).toMatchObject({ state: "ran", complete: true, warnings: [] });

    const skipped = await sbomRun({
      output: { results: [{ source: { path: "<sbom>" }, packages: [JQUERY] }] },
      expected: [{ ecosystem: "npm", name: "jquery", version: "1.12.4" }, { ecosystem: "npm", name: "bootstrap", version: "3.3.7" }],
    });
    expect(skipped.result).toMatchObject({ state: "ran", complete: false });
    expect(skipped.result.findings).toHaveLength(2);
    expect(skipped.result.warnings).toEqual(["osv-scanner did not list 1 package the SBOM names, so it was not checked."]);

    // A clean run (exit 0) that lists nothing at all is incomplete too, never a clean check.
    const empty = await sbomRun({ output: { results: [] }, code: 0, expected: [{ ecosystem: "npm", name: "bootstrap", version: "3.3.7" }] });
    expect(empty.result).toMatchObject({ state: "ran", complete: false, findings: [] });
  });

  it("an advisory for a package the SBOM did not name, a stop at a database, or an unrecorded database makes the run incomplete", async () => {
    const other = pkg("npm", "left-pad", "1.0.0", [{ ids: ["GHSA-xxxx-yyyy-zzzz"] }]);
    const sbomPath = "<sbom>";
    const unnamed = await sbomRun({ output: { results: [{ source: { path: sbomPath }, packages: [JQUERY, other] }] } });
    expect(unnamed.result).toMatchObject({ state: "ran", complete: false });
    expect(unnamed.result.findings).toHaveLength(2);
    expect(unnamed.result.warnings.join(" ")).toContain("did not name");

    const stopped = await sbomRun({ stderr: "could not load db for npm ecosystem" });
    expect(stopped.result).toMatchObject({ state: "ran", complete: false });
    expect(stopped.result.warnings).toContain(STOPPED_EARLY);

    const unrecorded = await sbomRun({ db: { npm: "mismatched" } });
    expect(unrecorded.result).toMatchObject({ state: "ran", complete: false });
    expect(unrecorded.result.warnings.join(" ")).toContain("no install record");
  });
});
