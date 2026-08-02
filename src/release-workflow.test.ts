import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { parse } from "yaml";

describe("GitHub release validation workflow", () => {
  test("requires signed-tag alignment and the full release gate without npm publishing authority", async () => {
    const source = await readFile(".github/workflows/release.yml", "utf8");
    const workflow = parse(source) as {
      on: { release: { types: string[] } };
      jobs: Record<string, {
        environment?: string;
        permissions: Record<string, string>;
        steps: Array<{ name?: string; run?: string; env?: Record<string, string> }>;
      }>;
    };
    expect(workflow.on.release.types).toEqual(["published"]);
    const job = workflow.jobs["verify-release"]!;
    expect(job.environment).toBeUndefined();
    expect(job.permissions).toEqual({ contents: "read" });
    const commands = job.steps.map((step) => step.run ?? "").join("\n");
    expect(commands).toContain("verification.verified");
    expect(commands).toContain('execFileSync("git", ["rev-list"');
    expect(commands).toContain("npm run build");
    expect(commands).toContain("npm test");
    expect(commands).toContain("npm run eval");
    expect(commands).toContain("node scripts/smoke-stdio.mjs");
    expect(commands).toContain("npm run test:sdk-consumer");
    expect(commands).not.toContain("npm publish");
    expect(commands).not.toContain("registry.npmjs.org");
    expect(source).not.toContain("id-token");
    expect(source).not.toContain("NPM_TOKEN");
    expect(job.steps.every((step) => !Object.keys(step.env ?? {}).some((key) => key === "NODE_AUTH_TOKEN"))).toBe(true);
  });
});
