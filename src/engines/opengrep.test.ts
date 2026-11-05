import { describe, expect, test } from "vitest";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import { isOpengrepPackRule, OPENGREP_BUNDLE_SKIPPING_BASELINE_RULES } from "../provenance.js";

import { MANAGED_OPENGREP_CACHE, OPENGREP_RULES_DIR } from "../config.js";
import {
  buildOpengrepArgs,
  effectiveOpengrepIgnoreList,
  OPENGREP_EFFECTIVE_IGNORE_NAME,
  OPENGREP_PACK_IGNORE_NAME,
  opengrepExecEnvironment,
  opengrepRuleSets,
} from "./opengrep.js";

describe("Opengrep offline invocation", () => {
  test("disables version checks and routes all writable runtime paths outside the target", () => {
    const target = "/repository";
    const temporary = "/managed-temporary";
    const args = buildOpengrepArgs(target, `${temporary}/result.sarif`, `${temporary}/report.json`);
    const env = opengrepExecEnvironment(temporary, "linux");

    expect(args).toContain("--disable-version-check");
    expect(args).toContain("--no-git-ignore");
    expect(args).toContain(OPENGREP_RULES_DIR);
    expect(args).not.toContain("--timeout");
    expect(args.at(-1)).toBe(target);
    expect(env).toEqual({
      XDG_CACHE_HOME: MANAGED_OPENGREP_CACHE,
      SEMGREP_LOG_FILE: join(temporary, "opengrep.log"),
      SEMGREP_VERSION_CACHE_PATH: join(temporary, "opengrep-version-cache"),
      OPENGREP_ENABLE_VERSION_CHECK: "0",
      SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE: join(temporary, OPENGREP_EFFECTIVE_IGNORE_NAME),
      LC_ALL: "C.UTF-8",
      LANG: "C.UTF-8",
    });
    expect(Object.values(env).some((value) => value.startsWith(target))).toBe(false);
  });

  test("runs under a UTF-8 locale whatever the host locale is", () => {
    // Field re-test: an em dash in a repository .semgrepignore ended the run with no SARIF when
    // the MCP host set no locale. The engine environment overrides the inherited one.
    const env = opengrepExecEnvironment("/managed-temporary", "linux");
    expect(env.LC_ALL).toBe("C.UTF-8");
    expect(env.LANG).toBe("C.UTF-8");
  });

  // Public CI (darwin-arm64, eval E62): GitHub's macOS runner has no C.UTF-8 locale, so Opengrep fell
  // back to ASCII and replaced non-ASCII snippet text. Every macOS release ships en_US.UTF-8.
  test("uses a UTF-8 locale that exists on macOS", () => {
    const env = opengrepExecEnvironment("/managed-temporary", "darwin");
    expect(env.LC_ALL).toBe("en_US.UTF-8");
    expect(env.LANG).toBe("en_US.UTF-8");
  });

  // Public CI (PR #12, win32-x64): a Windows git checkout has CRLF line endings, so the managed defaults
  // reached Opengrep as `node_modules/\r` beside LF lines. The list Opengrep reads is LF only.
  test("the effective ignore list has LF line endings whatever the defaults file has", () => {
    const list = effectiveOpengrepIgnoreList("node_modules/\r\nbuild/\r\n*.min.js\r\n");
    expect(list).not.toContain("\r");
    const lines = list.split("\n");
    expect(lines).toEqual(expect.arrayContaining(["node_modules/", "build/", "*.min.js", "dist/"]));
    expect(lines.filter((line) => line === "build/")).toHaveLength(1);
  });

  test("the pack pass reads its own ignore list and log", () => {
    const env = opengrepExecEnvironment("/managed-temporary", "linux", "pack");
    expect(env.SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE).toBe(join("/managed-temporary", OPENGREP_PACK_IGNORE_NAME));
    expect(env.SEMGREP_LOG_FILE).toBe(join("/managed-temporary", "opengrep-pack.log"));
  });
});

// M4 Task 4: every bundled rule runs in exactly one pass, and the folder split agrees with the rule ids
// rescan uses to pick a finding's invocation component (isOpengrepPackRule).
describe("Opengrep rule passes", () => {
  async function ruleIds(config: string): Promise<string[]> {
    const files = /\.ya?ml$/i.test(config) ? [config]
      : (await readdir(config, { recursive: true })).filter((name) => /\.ya?ml$/i.test(name)).map((name) => join(config, name));
    const ids: string[] = [];
    for (const file of files) {
      const parsed = parseYaml(await readFile(file, "utf8")) as { rules?: Array<{ id: string }> };
      for (const rule of parsed.rules ?? []) ids.push(rule.id);
    }
    return ids;
  }

  test("splits the bundled ruleset into baseline and bundle-skipping (Synvoya pack) passes", async () => {
    const sets = await opengrepRuleSets();
    const baselineDir = join(OPENGREP_RULES_DIR, "security-baseline");
    const baselineFiles = (await readdir(baselineDir)).filter((name) => /\.ya?ml$/.test(name)).sort();
    // M4 perf fix: a taint-mode baseline file runs in the bundle-skipping pass; the other baseline files stay.
    expect(sets.baseline).toEqual(baselineFiles.filter((name) => name !== "injection-taint.yaml").map((name) => join(baselineDir, name)));
    expect(sets.pack).toEqual([
      join(baselineDir, "injection-taint.yaml"),
      join(OPENGREP_RULES_DIR, "synvoya-node"),
      join(OPENGREP_RULES_DIR, "synvoya-php"),
    ]);
    const entries = [
      ...baselineFiles.map((name) => join(baselineDir, name)),
      ...(await readdir(OPENGREP_RULES_DIR)).filter((name) => name !== "security-baseline").map((name) => join(OPENGREP_RULES_DIR, name)),
    ].sort();
    expect([...sets.baseline, ...sets.pack].sort()).toEqual(entries);

    const baselineIds = (await Promise.all(sets.baseline.map(ruleIds))).flat();
    const packIds = (await Promise.all(sets.pack.map(ruleIds))).flat();
    expect(baselineIds.length).toBeGreaterThan(0);
    expect(packIds.length).toBeGreaterThan(0);
    expect(baselineIds.filter(isOpengrepPackRule)).toEqual([]);
    expect(packIds.filter((id) => !isOpengrepPackRule(id))).toEqual([]);
    expect(packIds).toContain("ci-baseline-sql-injection-string-build");
    // The id list rescan uses names exactly the baseline rules of the pack pass.
    expect([...OPENGREP_BUNDLE_SKIPPING_BASELINE_RULES].sort()).toEqual(packIds.filter((id) => !/^syn-(?:php|node)-/.test(id)).sort());
  });

  // M4 perf fix: taint analysis of a minified bundle is not bounded by the per-rule timeout (54 s on one
  // 300 KB bundle in the field), so no taint-mode rule may run in the baseline pass, which scans bundles.
  test("no taint-mode rule runs in the baseline pass", async () => {
    const sets = await opengrepRuleSets();
    const taint: string[] = [];
    for (const config of sets.baseline) {
      const files = config.endsWith(".yaml") || config.endsWith(".yml") ? [config]
        : (await readdir(config, { recursive: true })).filter((name) => /\.ya?ml$/i.test(name)).map((name) => join(config, name));
      for (const file of files) {
        const parsed = parseYaml(await readFile(file, "utf8")) as { rules?: Array<{ id: string; mode?: string }> };
        for (const rule of parsed.rules ?? []) if (rule.mode === "taint") taint.push(rule.id);
      }
    }
    expect(taint).toEqual([]);
  });

  test("only the pack pass sets an explicit per-rule timeout", () => {
    const args = buildOpengrepArgs("/repository", "/t/r.sarif", "/t/r.json", ["/rules/synvoya-php"], { timeoutSeconds: 30 });
    expect(args.slice(args.indexOf("--timeout"), args.indexOf("--timeout") + 2)).toEqual(["--timeout", "30"]);
    expect(args.at(-1)).toBe("/repository");
  });
});
