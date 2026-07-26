import { createHash } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { Lockfile } from "./lockfile.js";

const harness = vi.hoisted(() => ({
  root: `${process.env.TMPDIR ?? process.env.TEMP ?? "/tmp"}/ci-resolve-test-${process.pid}-${Date.now()}`,
  lock: undefined as Lockfile | undefined,
}));

vi.mock("../config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config.js")>();
  return {
    ...actual,
    MANAGED_BIN: join(harness.root, "bin"),
    PKG_ROOT: join(harness.root, "pkg"),
  };
});

vi.mock("./lockfile.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./lockfile.js")>();
  return {
    ...actual,
    platformKey: () => "test-x64",
    loadLockfile: vi.fn(async () => {
      if (!harness.lock) throw new Error("resolver test lockfile was not initialized");
      return harness.lock;
    }),
    getPlatformEntry: (lock: Lockfile, engine: "opengrep" | "gitleaks" | "trivy") =>
      lock.engines[engine]?.platforms["test-x64"],
  };
});

const { resolveEngine } = await import("./resolve.js");

const original = Buffer.from("verified-engine-v1");
const replacement = Buffer.from("untrusted-engine2");
const originalSha = createHash("sha256").update(original).digest("hex");
const binaryName = process.platform === "win32" ? "opengrep.exe" : "opengrep";

beforeEach(async () => {
  await rm(harness.root, { recursive: true, force: true });
  await mkdir(join(harness.root, "bin"), { recursive: true });
  harness.lock = {
    schema_version: 1,
    generated_at: null,
    engines: {
      opengrep: {
        version: "1.23.0",
        repo: "example/opengrep",
        release_base: "https://example.invalid",
        signature: "cosign",
        checksums_asset: null,
        platforms: {
          "test-x64": {
            asset: "opengrep",
            archive: "raw",
            binary: "opengrep",
            sha256: originalSha,
          },
        },
      },
      gitleaks: {
        version: "8.30.1",
        repo: "example/gitleaks",
        release_base: "https://example.invalid",
        signature: "checksums",
        checksums_asset: "checksums.txt",
        platforms: {},
      },
      trivy: {
        version: "0.71.2",
        repo: "example/trivy",
        release_base: "https://example.invalid",
        signature: "checksums+sigstore",
        checksums_asset: "checksums.txt",
        platforms: {},
      },
    },
  };
  await writeFile(join(harness.root, "bin", binaryName), original, { mode: 0o755 });
});

afterEach(async () => {
  await rm(harness.root, { recursive: true, force: true });
});

describe("engine resolution cache", () => {
  test("an atomically replaced managed binary is re-hashed and rejected", async () => {
    await expect(resolveEngine("opengrep")).resolves.toMatchObject({ sha256: originalSha });

    const staged = join(harness.root, "bin", `.new-${binaryName}`);
    await writeFile(staged, replacement, { mode: 0o755 });
    await rename(staged, join(harness.root, "bin", binaryName));

    await expect(resolveEngine("opengrep")).rejects.toMatchObject({
      reason: "hash_mismatch",
    });
  });
});
