import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../engines/trivy.js", () => ({
  runTrivy: vi.fn(async () => ({
    engine: "trivy",
    version: "0.71.2",
    available: false,
    ran: false,
    durationMs: 1,
    note: "test fixture: Trivy unavailable",
  })),
  readTrivyDbDate: vi.fn(async () => undefined),
}));
vi.mock("../store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

const { runScan } = await import("../scan.js");
const { scanResultSchema } = await import("../schemas.js");

const CORPUS = resolve(process.cwd(), "fixtures/pub-sca-corpus");
const originalFetch = globalThis.fetch;
const roots: string[] = [];

afterEach(async () => {
  globalThis.fetch = originalFetch;
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("scan orchestrator native Pub integration", () => {
  it("reports native Pub findings when Trivy is unavailable", async () => {
    const result = await runScan({ path: resolve(CORPUS, "tp"), scanners: ["vuln"] });
    expect(scanResultSchema.parse(result)).toEqual(result);
    expect(result.findings).toHaveLength(6);
    expect(result.findings.every((finding) => finding.engine === "codeinspectus-pub")).toBe(true);
    expect(result.engine_details).toContainEqual(expect.objectContaining({
      engine: "codeinspectus-pub",
      available: true,
      ran: true,
      finding_count: 6,
    }));
    expect(result.dependency_coverage?.[0]).toMatchObject({
      ecosystem: "Pub",
      state: "partial",
      lockfiles: { discovered: 1, analyzed: 1 },
    });
    expect(result.component_signatures?.["codeinspectus-pub:osv-snapshot"])
      .toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("is fully offline even if fetch is trapped", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("network access forbidden in scan");
    }) as typeof fetch;
    const result = await runScan({ path: resolve(CORPUS, "fixed"), scanners: ["vuln"] });
    expect(result.findings).toEqual([]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("reports Pub not_run for an ai-only Flutter scan", async () => {
    const result = await runScan({ path: resolve(CORPUS, "fixed"), scanners: ["ai"] });
    expect(result.dependency_coverage?.[0]).toMatchObject({
      engine: "codeinspectus-pub",
      state: "not_run",
    });
    expect(result.engine_details.some((engine) => engine.engine === "codeinspectus-pub")).toBe(false);
  });

  it("reports a symlink-only Pub lockfile as partial rather than not applicable", async () => {
    const project = await mkdtemp(join(tmpdir(), "ci-pub-symlink-project-"));
    const outside = await mkdtemp(join(tmpdir(), "ci-pub-symlink-outside-"));
    roots.push(project, outside);
    const real = join(outside, "pubspec.lock");
    await writeFile(real, "packages: {}\n", "utf8");
    await symlink(real, join(project, "pubspec.lock"));

    const result = await runScan({ path: project, scanners: ["vuln"] });

    expect(result.detected_technologies).toContainEqual(expect.objectContaining({ id: "dart" }));
    expect(result.dependency_coverage?.[0]).toMatchObject({
      engine: "codeinspectus-pub",
      state: "partial",
      lockfiles: { discovered: 1, analyzed: 0 },
    });
    expect(result.dependency_coverage?.[0]?.limitations.join(" ")).toMatch(/symbolic-link/i);
  });

  it("reports a symlinked directory as ambiguous partial Pub coverage", async () => {
    const project = await mkdtemp(join(tmpdir(), "ci-pub-symlink-dir-project-"));
    roots.push(project);
    await symlink(resolve(CORPUS, "tp"), join(project, "mobile"));

    const result = await runScan({ path: project, scanners: ["vuln"] });

    expect(result.detected_technologies.some((technology) => technology.id === "dart")).toBe(false);
    expect(result.dependency_coverage?.[0]).toMatchObject({
      engine: "codeinspectus-pub",
      state: "partial",
      lockfiles: { discovered: 0, analyzed: 0 },
    });
    expect(result.dependency_coverage?.[0]?.limitations.join(" ")).toMatch(/symbolic-link path mobile/i);
    expect(result.warnings.join(" ")).toMatch(/Technology detection was partial.*mobile.*symlink_skipped/i);
  });

  it("maps a complete no-lockfile probe back to not_applicable", async () => {
    const project = await mkdtemp(join(tmpdir(), "ci-pub-not-applicable-"));
    roots.push(project);
    await writeFile(join(project, "index.js"), "export {};\n", "utf8");

    const result = await runScan({ path: project, scanners: ["vuln"] });

    expect(result.dependency_coverage?.[0]).toMatchObject({
      engine: "codeinspectus-pub",
      state: "not_applicable",
    });
    expect(result.engine_details.some((engine) => engine.engine === "codeinspectus-pub")).toBe(false);
  });
});
