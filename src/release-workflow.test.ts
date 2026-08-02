import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { parse } from "yaml";

describe("npm release workflow", () => {
  test("requires signed-tag alignment, OIDC publishing, verification, and no long-lived token", async () => {
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
    const job = workflow.jobs["publish-npm"]!;
    expect(job.environment).toBe("npm");
    expect(job.permissions).toMatchObject({ contents: "read", "id-token": "write" });
    const commands = job.steps.map((step) => step.run ?? "").join("\n");
    expect(commands).toContain("verification.verified");
    expect(commands).toContain('execFileSync("git", ["rev-list"');
    expect(commands).toContain("npm run test:sdk-consumer");
    expect(commands).toContain("npm publish --provenance --access public");
    expect(commands).toContain("https://slsa.dev/provenance/v1");
    expect(source).not.toContain("NPM_TOKEN");
    expect(job.steps.every((step) => !Object.keys(step.env ?? {}).some((key) => key === "NODE_AUTH_TOKEN"))).toBe(true);
  });
});
