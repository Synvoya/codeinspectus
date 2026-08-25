import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { executeScan } from "../scan.js";

const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("V3.1 scan integration", () => {
  test("runs source integrity independently of the vulnerability scanner selection", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-source-scan-"));
    cleanup.push(root);
    const file = join(root, "app.ts");
    await writeFile(file, `const admin\u200BRole = "owner";\n`, "utf8");
    const before = await readFile(file);

    const execution = await executeScan({ path: root, scanners: ["ai"], max_findings: 50 }, { persist: false });
    for (const result of [execution.canonical, execution.display]) {
      expect(result.repository_trust.coverage.capabilities.find((entry) => entry.capability === "source_integrity"))
        .toMatchObject({ state: "ran", validators: ["codeinspectus-source-integrity@1.0.0"] });
      expect(result.repository_trust.artifacts).toEqual([
        expect.objectContaining({
          kind: "source_integrity",
          state: "verified",
          marker_class: "unicode_zero_width_token",
          location: expect.objectContaining({ file: "app.ts", start_line: 1 }),
          remediation: expect.objectContaining({ eligible: true, requires_approval: true }),
        }),
      ]);
    }
    expect(await readFile(file)).toEqual(before);
  });
});
