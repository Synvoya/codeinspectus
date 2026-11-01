import { chmod, mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";

import type { ScanResult } from "./types.js";

// Fix round 3: every warning or note that can embed a repository path goes through
// src/display-path.ts. A bidi override (U+202E) in a name is shown as a visible \u{202e} escape.
const RLO = String.fromCodePoint(0x202e);
const ESCAPED = "\\u{202e}";

vi.mock("./engines/opengrep.js", () => ({
  runOpengrep: vi.fn(async () => ({
    engine: "opengrep", version: "1.33.1", available: false, ran: false, durationMs: 1,
    note: `Opengrep produced no SARIF (exit 2). stderr: …could not read src/evil${String.fromCodePoint(0x202e)}sj.js`,
  })),
}));
vi.mock("./engines/trivy.js", () => ({
  readTrivyDbDate: vi.fn(async () => undefined),
  runTrivy: vi.fn(async () => ({ engine: "trivy", version: "0.76.1", available: true, ran: true, sarif: { version: "2.1.0", runs: [] }, durationMs: 1 })),
}));
vi.mock("./store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

const { executeScan } = await import("./scan.js");
const { escapeScanDisplayText } = await import("./display-path.js");

describe("repository paths in scan warnings and notes", () => {
  test("each surface shows a bidi-override name escaped", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-display-text-"));
    const outside = await mkdtemp(join(tmpdir(), "ci-display-text-outside-"));
    await writeFile(join(dir, "package.json"), "{}\n", "utf8");
    await writeFile(join(dir, "app.js"), "export const ok = 1;\n", "utf8");
    await mkdir(join(dir, `app${RLO}x`));
    await writeFile(join(dir, `app${RLO}x`, "pubspec.yaml"), "name: x\n", "utf8");
    // Unreadable source and folder: partial causes that stay warnings and pack notes.
    await writeFile(join(dir, `locked${RLO}.js`), "export const x = 1;\n", "utf8");
    await chmod(join(dir, `locked${RLO}.js`), 0o000);
    await mkdir(join(dir, `closed${RLO}dir`));
    await chmod(join(dir, `closed${RLO}dir`), 0o000);
    // A link outside the target: a Pub and technology-detection limitation (Ruling 30: not a gap).
    await symlink(outside, join(dir, `out${RLO}link`));
    // A link to a file inside the target: the symlinked-paths gap counts it but never shows it.
    await symlink(join(dir, "app.js"), join(dir, `in${RLO}link`));
    // A file the native lexer cannot read: the native-parse-errors gap counts it but never shows it.
    await writeFile(join(dir, `evil${RLO}sj.js`), "function broken( {\n  return eval(x;\n", "utf8");

    try {
      const { canonical } = await executeScan({ path: dir, scanners: ["ai", "sast", "vuln"] }, { persist: false });

      // Technology detection warning and evidence.
      expect(canonical.warnings.find((warning) => warning.startsWith("Technology detection was partial"))).toContain(`closed${ESCAPED}dir (directory_unreadable)`);
      expect(canonical.warnings.find((warning) => warning.startsWith("Technology detection was partial"))).toContain(`out${ESCAPED}link (symlink_skipped)`);
      expect(canonical.detected_technologies.flatMap((technology) => technology.evidence)).toContain(`app${ESCAPED}x/pubspec.yaml`);
      // Native-pack notes and the warnings built from them.
      const baseline = canonical.pack_coverage.find((pack) => pack.pack_id === "javascript-baseline")!;
      expect(baseline.note).toContain(`Skipped unreadable JavaScript/TypeScript source locked${ESCAPED}.js.`);
      expect(canonical.warnings.some((warning) => warning.startsWith("Native pack javascript-baseline partial") && warning.includes(`locked${ESCAPED}.js`))).toBe(true);
      // Dependency coverage limitations.
      expect(canonical.dependency_coverage?.flatMap((dependency) => dependency.limitations))
        .toContain(`Skipped symbolic-link path out${ESCAPED}link during Pub lockfile discovery.`);
      // Gaps count unsafe names but never show them.
      expect(canonical.coverage_gaps).toEqual(expect.arrayContaining([
        { id: "native-parse-errors", files: 1, examples: [] },
        { id: "symlinked-paths", files: 1, examples: [] },
      ]));
      // Engine notes and the "did not run" warning.
      expect(canonical.engine_details.find((engine) => engine.engine === "opengrep")?.note).toMatch(new RegExp(`src/evil\\\\u\\{202e\\}sj\\.js$`));
      expect(canonical.warnings.some((warning) => warning.startsWith("opengrep did not run") && warning.includes(`evil${ESCAPED}sj.js`))).toBe(true);
      // Nothing shown carries the raw character.
      const shown = JSON.stringify([canonical.warnings, canonical.engine_details, canonical.detected_technologies,
        canonical.pack_coverage, canonical.dependency_coverage, canonical.repository_trust.coverage, canonical.coverage_notes, canonical.coverage_gaps]);
      expect(shown.includes(RLO)).toBe(false);
    } finally {
      await chmod(join(dir, `locked${RLO}.js`), 0o644);
      await chmod(join(dir, `closed${RLO}dir`), 0o755);
    }
  });

  test("Git-scope, repository-trust and coverage notes are escaped, findings are not", () => {
    const finding = { id: "CI-0001", location: { file: `src/evil${RLO}.js`, start_line: 1, end_line: 1 } };
    const result = {
      warnings: [], engine_details: [], detected_technologies: [], pack_coverage: [],
      findings: [finding],
      repository_trust: {
        schema_version: "1.0.0",
        coverage: { state: "partial", limitations: [`a${RLO}.png: EXIF/XMP metadata could not be parsed.`], capabilities: [{ capability: "x", state: "partial", validators: [], limitations: [`b${RLO}`] }] },
        summary: { verified: 0, probable: 0, informational: 0, not_verifiable: 0, total: 0 },
        artifacts: [{ limitations: [`c${RLO}`] }],
      },
      coverage_notes: [{ component: "scope:scripts", detail: `d${RLO}.sh` }],
      git_scope: { limitations: [`Symbolic link e${RLO} was not materialized.`], entries: [{ path: `f${RLO}`, note: `g${RLO}` }] },
      history_revision: { limitations: [`h${RLO}`] },
    } as unknown as ScanResult;

    const escaped = escapeScanDisplayText(result);

    expect(escaped.repository_trust.coverage.limitations).toEqual([`a${ESCAPED}.png: EXIF/XMP metadata could not be parsed.`]);
    expect(escaped.repository_trust.coverage.capabilities[0]!.limitations).toEqual([`b${ESCAPED}`]);
    expect(escaped.repository_trust.artifacts[0]!.limitations).toEqual([`c${ESCAPED}`]);
    expect(escaped.coverage_notes).toEqual([{ component: "scope:scripts", detail: `d${ESCAPED}.sh` }]);
    expect(escaped.git_scope!.limitations).toEqual([`Symbolic link e${ESCAPED} was not materialized.`]);
    expect(escaped.git_scope!.entries[0]).toEqual({ path: `f${RLO}`, note: `g${ESCAPED}` });
    expect(escaped.history_revision!.limitations).toEqual([`h${ESCAPED}`]);
    expect(escaped.findings[0]).toBe(finding);
    expect(escapeScanDisplayText(escaped)).toEqual(escaped);
  });
});
