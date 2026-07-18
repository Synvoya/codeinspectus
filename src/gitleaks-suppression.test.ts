import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { GITLEAKS_CONFIG } from "./config.js";
import { buildGitleaksArgs } from "./engines/gitleaks.js";
import {
  detectGitleaksSuppression,
  hasUnverifiedSecretCoverage,
  secretSuppressionWarnings,
} from "./gitleaks-suppression.js";
import { summarizeScan } from "./summarize.js";
import type { ScanResult } from "./types.js";

const dirs: string[] = [];

async function temp(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-gitleaks-floor-"));
  dirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("Gitleaks floor invocation", () => {
  test("always passes the bundled config, never the target config", async () => {
    const target = await temp();
    await writeFile(join(target, ".gitleaks.toml"), "title = 'target'\n", "utf8");
    const args = buildGitleaksArgs(target, join(target, "out.sarif"));
    const configIndex = args.indexOf("--config");

    expect(configIndex).toBeGreaterThan(-1);
    expect(args[configIndex + 1]).toBe(GITLEAKS_CONFIG);
    expect(args).not.toContain(join(target, ".gitleaks.toml"));
  });

  test("always disables inline gitleaks:allow suppression", async () => {
    const target = await temp();
    expect(buildGitleaksArgs(target, join(target, "out.sarif"))).toContain("--ignore-gitleaks-allow");
  });
});

describe("Gitleaks suppression disclosure", () => {
  test("detects all three channels without retaining contents and marks ignore coverage unverified", async () => {
    const target = await temp();
    await writeFile(join(target, ".gitleaks.toml"), "title = 'private custom config'\n", "utf8");
    await writeFile(join(target, ".gitleaksignore"), "path:rule:1\n", "utf8");
    await writeFile(
      join(target, "app.ts"),
      "const first = 'redacted'; // gitleaks:allow\nconst second = 'redacted'; // gitleaks:allow\n",
      "utf8",
    );

    const metadata = await detectGitleaksSuppression(target);
    expect(metadata.channels).toEqual([
      { channel: "target_config", count: 1, paths: [".gitleaks.toml"], handling: "ignored_by_codeinspectus" },
      { channel: "gitleaks_ignore", count: 1, paths: [".gitleaksignore"], handling: "coverage_unverified" },
      { channel: "inline_allow", count: 2, paths: ["app.ts"], handling: "ignored_by_codeinspectus" },
    ]);
    expect(hasUnverifiedSecretCoverage(metadata)).toBe(true);

    const warnings = secretSuppressionWarnings(metadata);
    expect(warnings).toHaveLength(3);
    expect(warnings.join("\n")).toContain("Secret coverage here is partial and cannot be guaranteed");
    expect(JSON.stringify(metadata)).not.toContain("private custom config");
    expect(JSON.stringify(metadata)).not.toContain("redacted");
  });

  test("absent surfaces produce no disclosure", async () => {
    const target = await temp();
    await writeFile(join(target, "app.ts"), "export const safe = true;\n", "utf8");
    const metadata = await detectGitleaksSuppression(target);
    expect(metadata.channels).toEqual([]);
    expect(secretSuppressionWarnings(metadata)).toEqual([]);
    expect(hasUnverifiedSecretCoverage(metadata)).toBe(false);
  });

  test("human and structured halves disclose unverified coverage without changing finding counts", async () => {
    const target = await temp();
    await writeFile(join(target, ".gitleaksignore"), "path:rule:1\n", "utf8");
    const secret_suppression = await detectGitleaksSuppression(target);
    const warnings = secretSuppressionWarnings(secret_suppression);
    const result: ScanResult = {
      scan_id: "scan-test",
      target,
      started_at: "2026-07-18T00:00:00.000Z",
      duration_ms: 1,
      engines_run: ["gitleaks@8.30.1"],
      engine_details: [],
      offline: true,
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      findings: [],
      truncated: false,
      total_findings_before_limit: 0,
      disclaimer: "code-level coverage only",
      warnings,
      secret_coverage: "unverified",
      secret_suppression,
      git_safety: { state: "clean" },
    };

    expect(result.secret_coverage).toBe("unverified");
    expect(result.secret_suppression?.channels[0]?.paths).toEqual([".gitleaksignore"]);
    expect(result.summary.total).toBe(result.findings.length);
    const human = summarizeScan(result);
    expect(human).toContain("secret coverage: UNVERIFIED");
    expect(human).toContain("Secret coverage here is partial and cannot be guaranteed");
  });
});
