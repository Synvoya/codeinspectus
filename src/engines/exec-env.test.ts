import { afterEach, describe, expect, test } from "vitest";

import { execBinary } from "./exec.js";

const INHERITED = {
  SEMGREP_BASELINE_REF: "HEAD",
  SEMGREP_RULES: "p/none",
  OPENGREP_TIMEOUT: "1",
  R2C_INTERNAL_EXPLICIT: "x",
  TRIVY_SEVERITY: "CRITICAL",
  TRIVY_CONFIG: "/repo/trivy.yaml",
  trivy_skip_dirs: "/",
  GITLEAKS_CONFIG: "/repo/.gitleaks.toml",
};

afterEach(() => {
  for (const key of Object.keys(INHERITED)) delete process.env[key];
});

describe("engine subprocess environment", () => {
  // Review C-1 (real binaries): SEMGREP_BASELINE_REF=HEAD made Opengrep scan 0 files and TRIVY_SEVERITY /
  // TRIVY_CONFIG cut Trivy's results while coverage read complete. Inherited engine settings are dropped.
  test("inherited engine settings never reach an engine; the wrapper's own settings do", async () => {
    Object.assign(process.env, INHERITED);
    const result = await execBinary(process.execPath, ["-e", "process.stdout.write(JSON.stringify(process.env))"], {
      env: { SEMGREP_LOG_FILE: "/managed/opengrep.log" },
    });
    const env = JSON.parse(result.stdout) as Record<string, string>;
    for (const key of Object.keys(INHERITED)) expect(env[key]).toBeUndefined();
    expect(env.SEMGREP_LOG_FILE).toBe("/managed/opengrep.log");
    expect(env.PATH).toBe(process.env.PATH);
  });
});
