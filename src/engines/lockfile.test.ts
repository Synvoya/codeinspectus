import { describe, expect, test } from "vitest";

import { platformRuntimeIssue, type PlatformEntry } from "./lockfile.js";

const entry: PlatformEntry = {
  asset: "engine",
  archive: "raw",
  binary: "engine",
  sha256: "0".repeat(64),
  runtime: { libc: "glibc" },
};

describe("engine runtime requirements", () => {
  test("blocks glibc-only Linux assets on non-glibc and unknown runtimes", () => {
    expect(platformRuntimeIssue(entry, "linux", "non-glibc")).toMatch(/requires glibc/i);
    expect(platformRuntimeIssue(entry, "linux", "unknown")).toMatch(/could not be verified/i);
  });

  test("accepts a verified glibc runtime and ignores libc requirements off Linux", () => {
    expect(platformRuntimeIssue(entry, "linux", "glibc")).toBeUndefined();
    expect(platformRuntimeIssue(entry, "darwin", "unknown")).toBeUndefined();
  });
});
