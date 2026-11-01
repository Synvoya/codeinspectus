import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { GITLEAKS_CONFIG } from "./config.js";
import { buildGitleaksArgs } from "./engines/gitleaks.js";
import {
  detectGitleaksSuppression,
  gitleaksIgnoreEntryCanMatch,
  hasUnverifiedSecretCoverage,
  secretSuppressionWarnings,
} from "./gitleaks-suppression.js";
import { summarizeScan } from "./summarize.js";
import type { ScanResult } from "./types.js";
import { createUnavailableRepositoryTrust } from "./repository-trust/schemas.js";

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
    await writeFile(join(target, ".gitleaksignore"), `${join(target, "path")}:rule:1\n`, "utf8");
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

  // Field re-test G8c: Gitleaks 8.30.1 `dir <absolute target>` reports absolute paths, so relative and
  // commit-scoped entries (ministryofjustice/intranet, cap-collectif) hid nothing yet read partial.
  test("a .gitleaksignore whose entries cannot match the directory scan is disclosed but not partial", async () => {
    const target = await temp();
    await writeFile(
      join(target, ".gitleaksignore"),
      "# reviewed\r\nconfig.yml:generic-api-key:2\r\n0123456789abcdef0123456789abcdef01234567:config.yml:generic-api-key:2\n\n",
      "utf8",
    );
    const metadata = await detectGitleaksSuppression(target);
    expect(metadata.channels).toEqual([
      { channel: "gitleaks_ignore", count: 1, paths: [".gitleaksignore"], handling: "ignored_by_codeinspectus" },
    ]);
    expect(hasUnverifiedSecretCoverage(metadata)).toBe(false);
    const [warning] = secretSuppressionWarnings(metadata);
    expect(warning).toContain("hides no secret findings here");
    // The aggregate-coverage classifier treats these words as a gap (src/export/model.ts).
    expect(warning).not.toMatch(/partial|unavailable|did not run|excluded|bounded|truncat|dropped|unverified|incompat|not.re.?check/i);
  });

  test("classifies .gitleaksignore entries the way Gitleaks 8.30.1 matches a directory scan", () => {
    expect(gitleaksIgnoreEntryCanMatch("  /repo/config.yml:generic-api-key:2\r")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("\\\\server\\repo\\config.yml:generic-api-key:2")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("C:\\repo\\config.yml:generic-api-key:2")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("odd:shape")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("./config.yml:generic-api-key:2")).toBe(false);
    expect(gitleaksIgnoreEntryCanMatch(":/repo/config.yml:generic-api-key:2")).toBe(false);
    expect(gitleaksIgnoreEntryCanMatch("# /repo/config.yml:generic-api-key:2")).toBe(false);
  });

  // Go's strings.TrimSpace (Gitleaks) strips U+0085 and JavaScript's trim() does not: on the real
  // 8.30.1 binary a NEL-prefixed absolute entry hides the finding. Non-ASCII lines fail closed.
  test("treats a line with characters outside printable ASCII as able to match", () => {
    expect(gitleaksIgnoreEntryCanMatch("\u0085/repo/config.yml:generic-api-key:2")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("\u00a0/repo/config.yml:generic-api-key:2")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("\u0085config.yml:generic-api-key:2")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("config.yml:generic-api-key:2")).toBe(false);
    expect(gitleaksIgnoreEntryCanMatch("\tconfig.yml:generic-api-key:2\r")).toBe(false);
    expect(gitleaksIgnoreEntryCanMatch("# reviewed by caf\u00e9 \u2014 no secrets")).toBe(false);
  });

  test("a byte-order mark on the first line keeps secret coverage unverified", async () => {
    const target = await temp();
    await writeFile(join(target, ".gitleaksignore"), "\ufeffconfig.yml:generic-api-key:2\n", "utf8");
    expect(hasUnverifiedSecretCoverage(await detectGitleaksSuppression(target))).toBe(true);
  });

  // Review C2, measured on the real 8.30.1 binary: Gitleaks looks up the whole absolute
  // "<file>:<rule>:<line>", so an absolute entry with ':' in its path still hides the finding.
  test("an absolute entry can match however many ':' its path contains", () => {
    expect(gitleaksIgnoreEntryCanMatch("/work/colon:target/config.yml:generic-api-key:3")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("/work/plain/sub:dir/config.yml:generic-api-key:3")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("\\\\?\\C:\\repo\\config.yml:generic-api-key:3")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("C:/repo/config.yml:generic-api-key:3")).toBe(true);
    expect(gitleaksIgnoreEntryCanMatch("deadbeef:config.yml:generic-api-key:2")).toBe(false);
    expect(gitleaksIgnoreEntryCanMatch(":config.yml:generic-api-key:2")).toBe(false);
    expect(gitleaksIgnoreEntryCanMatch("sub:dir/config.yml:generic-api-key:3")).toBe(true);
  });

  test("an empty or comment-only .gitleaksignore is disclosed without claiming what its entries name", async () => {
    const target = await temp();
    await writeFile(join(target, ".gitleaksignore"), "# nothing ignored yet\n", "utf8");
    const metadata = await detectGitleaksSuppression(target);
    expect(hasUnverifiedSecretCoverage(metadata)).toBe(false);
    expect(secretSuppressionWarnings(metadata)[0]).toBe(
      "This repo has a .gitleaksignore file, but none of its entries can match CodeInspectus's directory scan, so it hides no secret findings here.",
    );
  });

  test("an unreadable or oversized .gitleaksignore keeps secret coverage unverified", async () => {
    const target = await temp();
    await writeFile(join(target, ".gitleaksignore"), `${"x".repeat(1024 * 1024)}\n`, "utf8");
    expect(hasUnverifiedSecretCoverage(await detectGitleaksSuppression(target))).toBe(true);
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
    await writeFile(join(target, ".gitleaksignore"), `${join(target, "path")}:rule:1\n`, "utf8");
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
      detected_technologies: [],
      pack_coverage: [],
      repository_trust: createUnavailableRepositoryTrust(),
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

  // Security review: inline-allow paths keep every file (the warning counts them) but escape unsafe names.
  test("a gitleaks:allow file with a bidi-override name is listed escaped", async () => {
    const target = await temp();
    await writeFile(join(target, "evil\u202egnp.ts"), "const x = 'redacted'; // gitleaks:allow\n", "utf8");
    const metadata = await detectGitleaksSuppression(target);
    expect(metadata.channels).toEqual([
      { channel: "inline_allow", count: 1, paths: ["evil\\u{202e}gnp.ts"], handling: "ignored_by_codeinspectus" },
    ]);
  });
});
