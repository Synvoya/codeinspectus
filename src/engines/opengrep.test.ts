import { describe, expect, test } from "vitest";
import { join } from "node:path";

import { MANAGED_OPENGREP_CACHE, OPENGREP_RULES_DIR } from "../config.js";
import { buildOpengrepArgs, opengrepExecEnvironment } from "./opengrep.js";

describe("Opengrep offline invocation", () => {
  test("disables version checks and routes all writable runtime paths outside the target", () => {
    const target = "/repository";
    const temporary = "/managed-temporary";
    const args = buildOpengrepArgs(target, `${temporary}/result.sarif`);
    const env = opengrepExecEnvironment(temporary);

    expect(args).toContain("--disable-version-check");
    expect(args).toContain(OPENGREP_RULES_DIR);
    expect(args.at(-1)).toBe(target);
    expect(env).toEqual({
      XDG_CACHE_HOME: MANAGED_OPENGREP_CACHE,
      SEMGREP_LOG_FILE: join(temporary, "opengrep.log"),
      SEMGREP_VERSION_CACHE_PATH: join(temporary, "opengrep-version-cache"),
      OPENGREP_ENABLE_VERSION_CHECK: "0",
    });
    expect(Object.values(env).some((value) => value.startsWith(target))).toBe(false);
  });
});
