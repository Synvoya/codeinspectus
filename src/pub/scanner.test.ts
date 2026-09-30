import { mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { runPubScan } from "./scanner.js";

const CORPUS = resolve(process.cwd(), "fixtures/pub-sca-corpus");

describe("native Pub SCA corpus", () => {
  it("reports exact affected versions and keeps two archive advisories distinct", async () => {
    const result = await runPubScan(resolve(CORPUS, "tp"));
    expect(result.info).toMatchObject({ engine: "codeinspectus-pub", available: true, ran: true });
    expect(result.applicability).toBe("applicable");
    expect(result.findings).toHaveLength(6);
    expect(result.findings.filter((finding) => finding.location.file === "pubspec.lock"))
      .toHaveLength(6);
    expect(result.findings.filter((finding) => finding.title.includes("archive@3.3.7"))
      .map((finding) => finding.rule_id).sort()).toEqual([
        "GHSA-9v85-q87q-g4vg",
        "GHSA-r285-q736-9v95",
      ]);
    expect(result.findings.every((finding) =>
      finding.producer_components?.includes("codeinspectus-pub:osv-snapshot"),
    )).toBe(true);
    expect(result.coverage).toMatchObject({
      state: "partial",
      lockfiles: { discovered: 1, analyzed: 1 },
      packages: { resolved: 9, eligible: 5, skipped: 2 }, // git + custom-hosted; SDK/path are not applicable
      matching: "exact-enumerated-versions",
    });
  });

  it("does not match fixed public versions, and SDK packages or snapshot age alone are not a coverage gap", async () => {
    const result = await runPubScan(resolve(CORPUS, "fixed"));
    expect(result.findings).toEqual([]);
    // The only unmatched package is the Flutter SDK, which has no Pub advisories; a stale bundled
    // snapshot is disclosed as a freshness note, like the Trivy DB, not as incomplete coverage.
    expect(result.coverage).toMatchObject({
      state: "ran",
      lockfiles: { discovered: 1, analyzed: 1 },
      packages: { resolved: 6, eligible: 5, skipped: 0 },
    });
  });

  it("does not treat custom-hosted, git, path, SDK, or pre-introduction versions as public matches", async () => {
    const result = await runPubScan(resolve(CORPUS, "fp"));
    expect(result.findings).toEqual([]);
    expect(result.coverage.state).toBe("partial");
    expect(result.coverage.packages).toEqual({ resolved: 5, eligible: 1, skipped: 2 });
  });

  it("reports malformed lockfiles as partial and never as a clean zero", async () => {
    const result = await runPubScan(resolve(CORPUS, "malformed"));
    expect(result.findings).toEqual([]);
    expect(result.info.ran).toBe(false);
    expect(result.coverage).toMatchObject({
      state: "partial",
      lockfiles: { discovered: 1, analyzed: 0 },
    });
    expect(result.coverage.limitations.join(" ")).toMatch(/malformed|duplicate package/i);
  });

  it("normalizes a direct lockfile target to the same basename identity as external SARIF", async () => {
    const result = await runPubScan(resolve(CORPUS, "tp", "pubspec.lock"));
    expect(result.findings).toHaveLength(6);
    expect(result.findings.every((finding) => finding.location.file === "pubspec.lock")).toBe(true);
  });

  it("a repository without Dart is not a Pub project just because it contains a symlink", async () => {
    const root = await mkdtemp(join(await realpath(tmpdir()), "ci-pub-symlink-"));
    await writeFile(join(root, "AGENTS.md"), "# agents\n");
    await writeFile(join(root, "app.js"), "export const x = 1;\n");
    try {
      await symlink("AGENTS.md", join(root, "CLAUDE.md"));
    } catch {
      return;
    }

    const result = await runPubScan(root);

    expect(result.applicability).toBe("not_applicable");
  });
});
