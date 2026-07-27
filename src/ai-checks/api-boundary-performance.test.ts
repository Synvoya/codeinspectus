import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { runApiBoundaryChecks } from "./api-boundary.js";

const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("API-boundary scanner performance regression", () => {
  test("masks quote-heavy TypeScript in linear time without losing a real sink", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-api-boundary-performance-"));
    temporaryRoots.push(root);
    const quote = String.fromCharCode(96);
    const noise = Array.from({ length: 12_000 }, (_, index) =>
      `const pattern${index} = /(["'${quote}])(?:\\\\.|.)*?/g; const label${index} = "safe";`,
    ).join("\n");
    await writeFile(
      join(root, "route.ts"),
      `${noise}\nexport function route(error: Error) { return Response.json({ error: error.message }); }\n`,
      "utf8",
    );

    const started = performance.now();
    const findings = await runApiBoundaryChecks(root);
    const duration = performance.now() - started;

    expect(findings.map((finding) => finding.rule_id)).toEqual(["ci-ai-client-error-leak"]);
    expect(duration).toBeLessThan(2_000);
  }, 5_000);
});
