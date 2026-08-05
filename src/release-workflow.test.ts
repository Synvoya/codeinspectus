import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { parse } from "yaml";

describe("release workflow", () => {
  test("validates the signed GitHub release without npm publication authority", async () => {
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
    expect(commands).toContain("npm run test:sdk-consumer");
    expect(commands).not.toContain("npm publish");
    expect(commands).not.toContain("slsa.dev/provenance");
    expect(source).not.toContain("id-token: write");
    expect(source).not.toContain("NPM_TOKEN");
    expect(job.steps.every((step) => !Object.keys(step.env ?? {}).some((key) => key === "NODE_AUTH_TOKEN"))).toBe(true);
  });

  test("documents one explicit approval gate and all post-approval release surfaces", async () => {
    const release = (await readFile("docs/RELEASE.md", "utf8")).replace(/\r\n/g, "\n");
    expect(release).toMatch(/one explicit\s+human approval gate/);
    expect(release).toContain("npm whoami");
    expect(release).toContain("hibin-m");
    expect(release).toContain("npm publish --access public");
    expect(release).toContain("mcp-publisher publish");
    expect(release).toContain("wrangler pages deployment list");
    expect(release).toContain("A content,\nversion, target, or scope change after approval invalidates it");
  });
});
