import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, test, vi } from "vitest";

import type { EngineOutput } from "./engines/types.js";

// Ruling 14: files Opengrep could only partly parse are the declared gap `sast-parse-errors`,
// acceptable by id; a timeout or internal matching error stays a warning no gap id accepts.
let opengrep: Partial<EngineOutput> = {};

vi.mock("./engines/opengrep.js", () => ({
  runOpengrep: vi.fn(async () => ({
    engine: "opengrep",
    version: "1.33.1",
    available: true,
    ran: true,
    sarif: { version: "2.1.0", runs: [] },
    durationMs: 1,
    ...opengrep,
  })),
}));
vi.mock("./store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

const { executeScan } = await import("./scan.js");
const { createJsonExport } = await import("./export/model.js");
const { summarizeScan } = await import("./summarize.js");

const PARSE_GAP = { id: "sast-parse-errors" as const, files: 2, examples: ["src/new-syntax.ts", "src/old.js"] };

async function target(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-engine-gaps-scan-"));
  await writeFile(join(dir, "app.ts"), "export const safe = true;\n", "utf8");
  await writeFile(join(dir, "index.php"), "<?php echo 1;\n", "utf8");
  return dir;
}

/** Partial coverage evidence, as the CI policy reads it (excluded scanner classes aside). */
async function scan(acceptGaps?: Array<"sast-parse-errors" | "php-sast">) {
  const { canonical } = await executeScan(
    { path: await target(), scanners: ["sast"], ...(acceptGaps ? { accept_gaps: acceptGaps } : {}) },
    { persist: false },
  );
  const document = createJsonExport({ ...canonical, storage_schema_version: "2.0.0", canonical_findings: true });
  const partial = document.coverage.evidence.filter((item) => item.state === "partial" || item.state === "unknown");
  return { canonical, partial: partial.map((item) => item.component) };
}

beforeEach(() => {
  opengrep = {};
});

describe("engine-reported coverage gaps", () => {
  test("Opengrep's parse-error gap is listed with the discovered gaps, in id order, as gap evidence only", async () => {
    opengrep = { coverageGaps: [PARSE_GAP] };
    const { canonical, partial } = await scan(["sast-parse-errors"]);

    expect(canonical.coverage_gaps).toEqual([
      { id: "php-sast", files: 1, examples: ["index.php"] },
      PARSE_GAP,
    ]);
    expect(canonical.accepted_gaps).toEqual(["sast-parse-errors"]);
    expect(canonical.warnings.some((warning) => warning.startsWith("Opengrep SAST coverage partial"))).toBe(false);
    // Only declared gaps are partial, so accepting both ids is what lets CI pass.
    expect(partial).toEqual(["gap:php-sast", "gap:sast-parse-errors"]);
  });

  test("a timeout or internal matching error is partial evidence no gap id covers", async () => {
    opengrep = {
      coverageGaps: [PARSE_GAP],
      coverageWarnings: ["Opengrep SAST coverage partial: 1 with a timeout, memory limit or engine error: src/big.ts."],
    };
    const { partial } = await scan(["sast-parse-errors", "php-sast"]);

    expect(partial.filter((component) => !component.startsWith("gap:")).length).toBeGreaterThan(0);
  });

  test("a gap from an engine that did not run is ignored", async () => {
    opengrep = { ran: false, note: "Opengrep is not installed.", coverageGaps: [PARSE_GAP] };
    const { canonical } = await scan();

    expect(canonical.coverage_gaps?.map((gap) => gap.id)).toEqual(["php-sast"]);
  });

  // Ruling 15: shell, PowerShell and Makefiles are disclosed outside warnings and never lower coverage.
  test("scope notes reach the scan result, the summary and the export as informational", async () => {
    const dir = await target();
    await writeFile(join(dir, "release.sh"), "#!/bin/sh\n", "utf8");
    const { canonical } = await executeScan({ path: dir, scanners: ["sast"] }, { persist: false });
    const note = "No bundled SAST rules read 1 shell file(s) (informational, not a coverage gap): release.sh.";

    // Review M1: Opengrep's default skips reach the MCP result and the summary, not only the export.
    expect(canonical.coverage_notes).toEqual([
      { component: "engine:opengrep", detail: expect.stringMatching(/^Opengrep skips its default ignore list in every repository/) },
      { component: "pack:javascript-baseline", detail: expect.stringMatching(/^The native JavaScript packs skip node_modules\//) },
      { component: "scope:scripts", detail: note },
    ]);
    expect(canonical.warnings).not.toContain(note);
    expect(summarizeScan(canonical)).toMatch(
      /Coverage notes \(informational; not gaps\):\n {2}- Opengrep skips its default ignore list[^\n]*\n {2}- The native JavaScript packs skip[^\n]*\n {2}- No bundled SAST rules read 1 shell file/,
    );
    const evidence = createJsonExport({ ...canonical, storage_schema_version: "2.0.0", canonical_findings: true }).coverage.evidence;
    expect(evidence).toContainEqual({ category: "declared_scope", component: "scope:scripts", state: "informational", detail: note });
  });

  test("a scan without SAST carries no script note", async () => {
    const dir = await target();
    await writeFile(join(dir, "release.sh"), "#!/bin/sh\n", "utf8");
    const { canonical } = await executeScan({ path: dir, scanners: ["secret"] }, { persist: false });
    expect(canonical.coverage_notes).toBeUndefined();
  });

  // Pre-release field validation item 3: a pack limited only by declared native gaps is not partial,
  // so accepting those ids lets CI pass while the gaps stay listed.
  test("native parse errors and symbolic links are gaps, not partial packs", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-native-gaps-scan-"));
    await writeFile(join(dir, "package.json"), "{}\n", "utf8");
    await writeFile(join(dir, "app.ts"), "export const safe = true;\n", "utf8");
    await writeFile(join(dir, "broken.ts"), "function broken( {\n  return eval(x;\n", "utf8");
    await mkdir(join(dir, "real"));
    await writeFile(join(dir, "real", "util.ts"), "export const u = 1;\n", "utf8");
    await symlink(join(dir, "real"), join(dir, "linked"));
    const { canonical } = await executeScan({ path: dir, scanners: ["ai", "sast"] }, { persist: false });

    expect(canonical.coverage_gaps).toEqual(expect.arrayContaining([
      { id: "native-parse-errors", files: 1, examples: ["broken.ts"] },
      { id: "symlinked-paths", files: 1, examples: ["linked"] },
    ]));
    for (const pack of ["javascript-baseline", "javascript-typescript"]) {
      expect(canonical.pack_coverage.find((entry) => entry.pack_id === pack)?.state).toBe("ran");
    }
    expect(canonical.warnings.filter((warning) => /Native pack|Technology detection/.test(warning))).toEqual([]);
    const document = createJsonExport({ ...canonical, storage_schema_version: "2.0.0", canonical_findings: true });
    const partial = document.coverage.evidence.filter((item) => item.state === "partial" || item.state === "unknown");
    expect(partial.map((item) => item.component).sort()).toEqual(["gap:native-parse-errors", "gap:symlinked-paths"]);
  });

  // Ruling 30 (review I-3): a link is the acceptable gap symlinked-paths only when its real target is
  // inside the root and visited. A link into node_modules/ or outside the root stays non-acceptable.
  test.each([
    ["into node_modules", (dir: string) => join(dir, "node_modules", "pkg")],
    ["outside the root", (_dir: string) => tmpdir()],
  ])("a symlink %s is not an acceptable gap", async (_name, targetOf) => {
    const dir = await mkdtemp(join(tmpdir(), "ci-native-gaps-link-"));
    await writeFile(join(dir, "package.json"), "{}\n", "utf8");
    await writeFile(join(dir, "app.ts"), "export const safe = true;\n", "utf8");
    await mkdir(join(dir, "node_modules", "pkg"), { recursive: true });
    await writeFile(join(dir, "node_modules", "pkg", "index.js"), "module.exports = 1;\n", "utf8");
    await symlink(targetOf(dir), join(dir, "lib"));
    const { canonical } = await executeScan({ path: dir, scanners: ["ai", "sast"], accept_gaps: ["symlinked-paths"] }, { persist: false });

    expect(canonical.coverage_gaps?.some((gap) => gap.id === "symlinked-paths") ?? false).toBe(false);
    expect(canonical.warnings.join(" ")).toMatch(/lib/);
  });

  // Security review: gaps come only from structured records. A file whose name spells a gap note, next
  // to a genuine failure, still leaves the pack partial with no gap id to accept. The failure is a
  // non-UTF-8 source, which every OS produces (public CI: chmod 000 does not deny reads on Windows).
  test("a path that spells a gap note cannot turn a real failure into an acceptable gap", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-native-gaps-forged-"));
    await writeFile(join(dir, "package.json"), "{}\n", "utf8");
    await writeFile(join(dir, "app.ts"), "export const safe = true;\n", "utf8");
    const forged = join(dir, "Skipped oversized JavaScript", "TypeScript source x.js");
    await mkdir(join(dir, "Skipped oversized JavaScript"));
    await writeFile(forged, Buffer.from([0x65, 0x78, 0x70, 0xff, 0xfe, 0x0a]));
    const { canonical } = await executeScan({ path: dir, scanners: ["ai", "sast"] }, { persist: false });
    const baseline = canonical.pack_coverage.find((pack) => pack.pack_id === "javascript-baseline");
    expect(baseline?.state).toBe("partial");
    expect(baseline?.note).toContain("Skipped non-UTF-8 JavaScript/TypeScript source");
    expect(canonical.coverage_gaps ?? []).toEqual([]);
    const document = createJsonExport({ ...canonical, storage_schema_version: "2.0.0", canonical_findings: true });
    const partial = document.coverage.evidence.filter((item) => item.state === "partial");
    expect(partial.some((item) => !item.component.startsWith("gap:"))).toBe(true);
  });
});
