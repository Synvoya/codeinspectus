/**
 * Rescan through the real osv-scanner wrapper, scan orchestrator and diff: removing the last lockfile is
 * the "remove the package" remediation for a malicious package, and rescan must be able to prove it.
 * Only the osv-scanner binary (execBinary), its resolution, Trivy and the managed OSV paths are stubbed;
 * scans stay in the in-memory store (vitest.config.ts disables persistence).
 */
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { OsvDbRecord } from "./osv/database.js";

const execBinary = vi.hoisted(() => vi.fn());
/**
 * The Synvoya dataset the scans load: the fixture-grade one by default, so these tests isolate the osv-scanner
 * path (the shipped seed also lists litellm 1.107.0, SYN-2026-001); `shipped` uses the bundled dataset.
 */
const synvoya = vi.hoisted(() => ({ shipped: false }));
const ARCHIVE = "zip!";
/** A valid install record that describes the stand-in archive. */
const PYPI_RECORD = vi.hoisted((): OsvDbRecord => ({
  component: "osv-scanner:vulnerability-db:PyPI",
  ecosystem: "PyPI",
  signature: `sha256:${"b".repeat(64)}`,
  source_url: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
  bytes: 4,
  recorded_at: "2026-10-30T10:00:00.000Z",
}));

vi.mock("./config.js", async (importOriginal) => {
  const root = join(tmpdir(), `codeinspectus-rescan-osv-test-${process.pid}`);
  return {
    ...(await importOriginal<typeof import("./config.js")>()),
    MANAGED_OSV_DB: join(root, "osv-db"),
    MANAGED_OSV_CONFIG: join(root, "osv-scanner.toml"),
  };
});
vi.mock("./engines/resolve.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./engines/resolve.js")>()),
  resolveEngine: vi.fn(async () => ({ path: "/test/osv-scanner", version: "2.7.0", sha256: "a".repeat(64) })),
}));
vi.mock("./engines/exec.js", () => ({ execBinary }));
vi.mock("./engines/trivy.js", () => ({
  runTrivy: vi.fn(async () => ({ engine: "trivy", version: "0.76.1", available: false, ran: false, durationMs: 1, note: "test fixture: Trivy unavailable" })),
  readTrivyDbDate: vi.fn(async () => undefined),
}));
vi.mock("./osv/database.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./osv/database.js")>()),
  readOsvDbRecord: vi.fn(async (ecosystem: string) => (ecosystem === "PyPI" ? PYPI_RECORD : undefined)),
}));

vi.mock("./synvoya/dataset.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./synvoya/dataset.js")>();
  return {
    ...actual,
    loadSynvoyaDataset: vi.fn(async (dir?: string) =>
      actual.loadSynvoyaDataset(synvoya.shipped ? dir : join(process.cwd(), "fixtures", "synvoya", "dataset")),
    ),
  };
});

const { MANAGED_OSV_CONFIG } = await import("./config.js");
const { osvDbZipPath } = await import("./osv/database.js");
const { runScan } = await import("./scan.js");
const { runRescan } = await import("./rescan.js");

const roots: string[] = [];

afterEach(async () => {
  synvoya.shipped = false;
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  await rm(join(MANAGED_OSV_CONFIG, ".."), { recursive: true, force: true });
});

/**
 * The fixture's `<target>` placeholder sits inside JSON strings: a Windows path's backslashes must be
 * escaped there, as the real osv-scanner writes them (public CI, win32-x64: the raw path made the
 * stubbed output invalid JSON, so no finding was read).
 */
function withTarget(raw: string, root: string): string {
  return raw.replaceAll("<target>", JSON.stringify(root).slice(1, -1));
}

/** osv-scanner's answer for the tree as it is now: the real 2.7.0 result while requirements.txt exists. */
function answerFromTree(root: string, vulnerable: string): void {
  execBinary.mockImplementation(async (_binary: string, args: string[]) => {
    const present = await readFile(join(root, "requirements.txt"), "utf8").then(() => true, () => false);
    const output = present ? withTarget(vulnerable, root) : JSON.stringify({ results: [], experimental_config: {} });
    await writeFile(args[args.indexOf("--output-file") + 1]!, output, "utf8");
    return { code: present ? 1 : 0, stdout: "", stderr: present ? "" : "No package sources found", timedOut: false };
  });
}

describe("rescan with osv-scanner", () => {
  it("removing the requirements file that held a malicious package resolves its finding", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "ci-rescan-osv-")));
    roots.push(root);
    await writeFile(join(root, "requirements.txt"), "litellm==1.107.0\nBrotli==1.2.0\nbrotlicffi==1.2.0.2\nrequests==2.19.0\n", "utf8");
    await mkdir(join(osvDbZipPath("PyPI"), ".."), { recursive: true });
    await writeFile(osvDbZipPath("PyPI"), ARCHIVE, "utf8");
    answerFromTree(root, await readFile(resolve(process.cwd(), "fixtures/osv/raw-vulnerable.json"), "utf8"));

    const prior = await runScan({ path: root, scanners: ["vuln"] });
    const malware = prior.findings.find((finding) => finding.rule_id === "MAL-2026-2144");
    expect(malware?.engines).toEqual(["osv-scanner"]);

    await rm(join(root, "requirements.txt"));
    const rescan = await runRescan({ path: root, prior_scan_id: prior.scan_id });

    expect(rescan.resolved.map((finding) => finding.fingerprint)).toContain(malware!.fingerprint);
    expect(rescan.not_rechecked).toEqual([]);
    expect(rescan.summary).toMatchObject({ resolved: prior.findings.length, remaining: 0, introduced: 0, not_rechecked: 0 });
  });

  it("a rescan whose osv-scanner run stopped at a database it could not load never resolves the findings it lost", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "ci-rescan-osv-")));
    roots.push(root);
    await writeFile(join(root, "requirements.txt"), "litellm==1.107.0\nBrotli==1.2.0\nbrotlicffi==1.2.0.2\nrequests==2.19.0\n", "utf8");
    await mkdir(join(osvDbZipPath("PyPI"), ".."), { recursive: true });
    await writeFile(osvDbZipPath("PyPI"), ARCHIVE, "utf8");
    const vulnerable = await readFile(resolve(process.cwd(), "fixtures/osv/raw-vulnerable.json"), "utf8");
    answerFromTree(root, vulnerable);
    const prior = await runScan({ path: root, scanners: ["vuln"] });
    const malware = prior.findings.find((finding) => finding.rule_id === "MAL-2026-2144")!;
    expect(malware).toBeDefined();

    // Real 2.7.0 behaviour: it stopped at a database it could not load after matching other packages, exited 1,
    // and listed litellm with nothing matched. The file did not change.
    const partial = JSON.parse(withTarget(vulnerable, root)) as {
      results: Array<{ packages: Array<{ package: { name: string }; groups?: unknown[]; vulnerabilities?: unknown[] }> }>;
    };
    for (const pkg of partial.results.flatMap((result) => result.packages)) {
      if (pkg.package.name === "litellm") {
        pkg.groups = [];
        pkg.vulnerabilities = [];
      }
    }
    execBinary.mockImplementation(async (_binary: string, args: string[]) => {
      await writeFile(args[args.indexOf("--output-file") + 1]!, JSON.stringify(partial), "utf8");
      return {
        code: 1,
        stdout: "",
        stderr: "could not load db for SwiftURL ecosystem: unable to fetch OSV database: could not read OSV database archive",
        timedOut: false,
      };
    });

    const rescan = await runRescan({ path: root, prior_scan_id: prior.scan_id });

    expect(rescan.resolved.map((finding) => finding.fingerprint)).not.toContain(malware.fingerprint);
    expect(rescan.not_rechecked.map((finding) => finding.fingerprint)).toContain(malware.fingerprint);
    expect(rescan.summary.resolved).toBe(0);
    expect(rescan.partial).toBe(true);
  });

  it("with the shipped Synvoya seed, a malicious package osv-scanner lost is still reported: Synvoya re-checks it", async () => {
    synvoya.shipped = true;
    const root = await realpath(await mkdtemp(join(tmpdir(), "ci-rescan-osv-")));
    roots.push(root);
    await writeFile(join(root, "requirements.txt"), "litellm==1.107.0\nBrotli==1.2.0\nbrotlicffi==1.2.0.2\nrequests==2.19.0\n", "utf8");
    await mkdir(join(osvDbZipPath("PyPI"), ".."), { recursive: true });
    await writeFile(osvDbZipPath("PyPI"), ARCHIVE, "utf8");
    const vulnerable = await readFile(resolve(process.cwd(), "fixtures/osv/raw-vulnerable.json"), "utf8");
    answerFromTree(root, vulnerable);
    const prior = await runScan({ path: root, scanners: ["vuln"] });
    const malware = prior.findings.find((finding) => finding.rule_id === "MAL-2026-2144")!;
    // SYN-2026-001 names the same malware: it enriches the osv-scanner finding instead of duplicating it.
    expect(prior.findings.filter((finding) => finding.rule_id === "SYN-2026-001")).toEqual([]);
    expect(malware.remediation.steps.some((step) => step.startsWith("Synvoya SYN-2026-001:"))).toBe(true);

    const partial = JSON.parse(withTarget(vulnerable, root)) as {
      results: Array<{ packages: Array<{ package: { name: string }; groups?: unknown[]; vulnerabilities?: unknown[] }> }>;
    };
    for (const pkg of partial.results.flatMap((result) => result.packages)) {
      if (pkg.package.name === "litellm") {
        pkg.groups = [];
        pkg.vulnerabilities = [];
      }
    }
    execBinary.mockImplementation(async (_binary: string, args: string[]) => {
      await writeFile(args[args.indexOf("--output-file") + 1]!, JSON.stringify(partial), "utf8");
      return { code: 1, stdout: "", stderr: "could not load db for SwiftURL ecosystem", timedOut: false };
    });

    const rescan = await runRescan({ path: root, prior_scan_id: prior.scan_id });

    expect(rescan.resolved.map((finding) => finding.fingerprint)).not.toContain(malware.fingerprint);
    expect(rescan.summary.resolved).toBe(0);
    expect(rescan.remaining.map((finding) => finding.rule_id)).toContain("SYN-2026-001");
  });
});
