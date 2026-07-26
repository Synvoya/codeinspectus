import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { Lockfile } from "./engines/lockfile.js";
import type { EngineSetupStatus } from "./types.js";

const harness = vi.hoisted(() => ({
  root: `${process.env.TMPDIR ?? process.env.TEMP ?? "/tmp"}/ci-repair-test-${process.pid}-${Date.now()}`,
  lock: undefined as Lockfile | undefined,
  statuses: [] as EngineSetupStatus[],
  saveLockfile: vi.fn(),
  inspectEngineSetup: vi.fn(async () => {
    const next = harness.statuses.shift();
    if (!next) throw new Error("repair test exhausted engine setup states");
    return next;
  }),
}));

vi.mock("./config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./config.js")>();
  return {
    ...actual,
    MANAGED_ROOT: harness.root,
    MANAGED_BIN: join(harness.root, "bin"),
    MANAGED_TRIVY_CACHE: join(harness.root, "trivy-cache"),
    MANAGED_PROVENANCE: join(harness.root, "provenance"),
    MANAGED_TRIVY_DB: join(harness.root, "trivy-cache", "db", "trivy.db"),
    MANAGED_TRIVY_DB_META: join(harness.root, "trivy-cache", "db", "metadata.json"),
    MANAGED_TRIVY_DB_PROVENANCE: join(harness.root, "provenance", "trivy", "vulnerability-db.json"),
  };
});

vi.mock("./engine-health.js", () => ({
  inspectEngineSetup: harness.inspectEngineSetup,
}));

vi.mock("./engines/lockfile.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./engines/lockfile.js")>();
  return {
    ...actual,
    loadLockfile: vi.fn(async () => {
      if (!harness.lock) throw new Error("repair test lockfile was not initialized");
      return harness.lock;
    }),
    saveLockfile: harness.saveLockfile,
    platformKey: () => "test-x64",
  };
});

vi.mock("./engines/signature.js", () => ({
  hasCosign: vi.fn(async () => true),
  verifyCertSig: vi.fn(async () => ({ ok: true, detail: "verified test signature" })),
  verifyBundle: vi.fn(async () => ({ ok: true, detail: "verified test bundle" })),
}));

const { repairEngines } = await import("./install.js");

const asset = Buffer.from("verified-opengrep-test-binary");
const assetSha = createHash("sha256").update(asset).digest("hex");

function setup(state: EngineSetupStatus["state"], opengrep: "ready" | "missing"): EngineSetupStatus {
  return {
    state,
    platform: "test-x64",
    engines: [
      { engine: "opengrep", version: "1.23.0", state: opengrep },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.71.2", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: "2026-07-25T00:00:00.000Z" },
    ...(state === "ready" ? {} : { repair_command: "npx codeinspectus repair-engines" }),
    network_required: state !== "ready",
  };
}

beforeEach(async () => {
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  await rm(harness.root, { recursive: true, force: true });
  harness.saveLockfile.mockClear();
  harness.inspectEngineSetup.mockClear();
  harness.statuses = [
    setup("repair_required", "missing"),
    setup("repair_required", "missing"),
    setup("ready", "ready"),
  ];
  harness.lock = {
    schema_version: 1,
    generated_at: "2026-07-01T00:00:00.000Z",
    sigstore_identities: {
      issuer: "https://issuer.example",
      opengrep: "https://identity.example/opengrep",
    },
    engines: {
      opengrep: {
        version: "1.23.0",
        repo: "example/opengrep",
        release_base: "https://downloads.example/opengrep",
        signature: "cosign",
        checksums_asset: null,
        platforms: {
          "test-x64": {
            asset: "opengrep-test",
            archive: "raw",
            binary: "opengrep",
            sha256: assetSha,
            provenance: { method: "cosign", verified: true, at: "2026-07-01T00:00:00.000Z" },
          },
        },
      },
      gitleaks: {
        version: "8.30.1",
        repo: "example/gitleaks",
        release_base: "https://downloads.example/gitleaks",
        signature: "checksums",
        checksums_asset: "checksums.txt",
        platforms: {},
      },
      trivy: {
        version: "0.71.2",
        repo: "example/trivy",
        release_base: "https://downloads.example/trivy",
        signature: "checksums+sigstore",
        checksums_asset: "checksums.txt",
        platforms: {},
      },
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      const body = url.endsWith("opengrep-test") ? asset : Buffer.from("test-signature-material");
      return new Response(body, { status: 200 });
    }),
  );
});

afterEach(async () => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  await rm(harness.root, { recursive: true, force: true });
});

describe("user engine repair", () => {
  test("installs a verified artifact without mutating the shipped lockfile", async () => {
    const before = JSON.stringify(harness.lock);

    await repairEngines(["opengrep"]);

    expect(await readFile(join(harness.root, "bin", "opengrep"))).toEqual(asset);
    expect(JSON.stringify(harness.lock)).toBe(before);
    expect(harness.saveLockfile).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(3); // binary + detached signature + certificate
    await expect(readFile(join(harness.root, ".repair-engines.lock", "owner.json"))).rejects.toThrow();
  });

  test.skipIf(process.platform === "win32")(
    "stages and swaps a DB-only refresh before recording the new provenance",
    async () => {
      const dbNeedsRefresh: EngineSetupStatus = {
        ...setup("db_refresh_recommended", "ready"),
        trivy_db: {
          state: "provenance_missing",
          downloaded_at: "2026-07-15T00:00:00.000Z",
        },
      };
      harness.statuses = [dbNeedsRefresh, dbNeedsRefresh, setup("ready", "ready")];

      const binDir = join(harness.root, "bin");
      const oldDbDir = join(harness.root, "trivy-cache", "db");
      await mkdir(binDir, { recursive: true });
      await mkdir(oldDbDir, { recursive: true });
      await writeFile(join(oldDbDir, "trivy.db"), "old-db", "utf8");
      await writeFile(join(oldDbDir, "metadata.json"), JSON.stringify({ DownloadedAt: "2026-07-15T00:00:00.000Z" }), "utf8");
      const fakeTrivy = join(binDir, "trivy");
      await writeFile(
        fakeTrivy,
        [
          "#!/usr/bin/env node",
          "const fs = require('node:fs');",
          "const path = require('node:path');",
          "const i = process.argv.indexOf('--cache-dir');",
          "const db = path.join(process.argv[i + 1], 'db');",
          "fs.mkdirSync(db, { recursive: true });",
          "fs.writeFileSync(path.join(db, 'trivy.db'), 'new-verified-db');",
          "fs.writeFileSync(path.join(db, 'metadata.json'), JSON.stringify({ DownloadedAt: '2026-07-26T00:00:00.000Z' }));",
        ].join("\n"),
        "utf8",
      );
      await chmod(fakeTrivy, 0o755);

      await repairEngines(["trivy"]);

      expect(await readFile(join(oldDbDir, "trivy.db"), "utf8")).toBe("new-verified-db");
      const provenance = JSON.parse(
        await readFile(join(harness.root, "provenance", "trivy", "vulnerability-db.json"), "utf8"),
      ) as { signature: string };
      expect(provenance.signature).toBe(
        `sha256:${createHash("sha256").update("new-verified-db").digest("hex")}`,
      );
      expect(harness.saveLockfile).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    },
  );
});
