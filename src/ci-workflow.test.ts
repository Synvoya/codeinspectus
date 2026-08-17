import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import { describe, expect, test } from "vitest";

const path = "docs/examples/codeinspectus-security.yml";

describe("shipped GitHub Actions policy workflow", () => {
  test("is valid YAML, least-privilege, credential-free for repository code, and SHA-pinned", async () => {
    const source = await readFile(path, "utf8");
    const workflow = parse(source) as {
      permissions: Record<string, string>;
      jobs: { scan: { steps: Array<{ uses?: string; with?: Record<string, unknown> }> } };
    };
    expect(workflow.permissions).toEqual({ contents: "read", "security-events": "write" });
    const uses = workflow.jobs.scan.steps.flatMap((step) => step.uses ? [step.uses] : []);
    expect(uses.length).toBeGreaterThan(0);
    expect(uses.every((value) => /@[0-9a-f]{40}$/.test(value))).toBe(true);
    const executable = source.replace(/^\s*#.*$/gm, "");
    expect(executable).not.toMatch(/pull_request_target|secrets\.|github\.token|GITHUB_TOKEN/);
    expect(executable).not.toMatch(/npm ci|npm run|npx /);
    expect(executable).toMatch(/--ignore-scripts/);
    expect(executable).toMatch(/codeinspectus@2\.5\.0/);
    expect(executable).toMatch(/\$RUNNER_TEMP\/codeinspectus-cli/);
    expect(source).toMatch(/persist-credentials:\s*false/);
  });

  test("repairs before the offline scan, uploads evidence, then restores policy status", async () => {
    const source = await readFile(path, "utf8");
    const repair = source.indexOf("repair-engines --refresh-db");
    const scan = source.indexOf("--fail-on-severity high");
    const summary = source.indexOf("Add bounded policy summary");
    const sarif = source.indexOf("github/codeql-action/upload-sarif@");
    const enforce = source.indexOf("Enforce the CodeInspectus exit contract");
    expect(repair).toBeGreaterThan(0);
    expect(repair).toBeLessThan(scan);
    expect(scan).toBeLessThan(summary);
    expect(summary).toBeLessThan(sarif);
    expect(sarif).toBeLessThan(enforce);
    expect(source).toMatch(/github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
    expect(source).toMatch(/github\.actor != 'dependabot\[bot\]'/);
    expect(source).toMatch(/github\.event\.repository\.private/);
    expect(source).toMatch(/retention-days:\s*7/);
    expect(source).toMatch(/results\.slice\(0, 50\)/);
    expect(source).toMatch(/1\).*exit 1/);
    expect(source).toMatch(/2\).*exit 2/);
    expect(source).toMatch(/130\|143/);
  });
});
