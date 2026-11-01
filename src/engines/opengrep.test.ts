import { describe, expect, test } from "vitest";
import { join } from "node:path";

import { MANAGED_OPENGREP_CACHE, OPENGREP_RULES_DIR } from "../config.js";
import { buildOpengrepArgs, effectiveOpengrepIgnoreList, OPENGREP_EFFECTIVE_IGNORE_NAME, opengrepExecEnvironment } from "./opengrep.js";

describe("Opengrep offline invocation", () => {
  test("disables version checks and routes all writable runtime paths outside the target", () => {
    const target = "/repository";
    const temporary = "/managed-temporary";
    const args = buildOpengrepArgs(target, `${temporary}/result.sarif`, `${temporary}/report.json`);
    const env = opengrepExecEnvironment(temporary, "linux");

    expect(args).toContain("--disable-version-check");
    expect(args).toContain("--no-git-ignore");
    expect(args).toContain(OPENGREP_RULES_DIR);
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
});

