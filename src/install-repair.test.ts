import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { EngineName } from "./config.js";
import type { Lockfile } from "./engines/lockfile.js";
import type { EngineSetupStatus } from "./types.js";

const harness = vi.hoisted(() => ({
  root: `${process.env.TMPDIR ?? process.env.TEMP ?? "/tmp"}/ci-repair-test-${process.pid}-${Date.now()}`,
  lock: undefined as Lockfile | undefined,
  statuses: [] as EngineSetupStatus[],
  saveLockfile: vi.fn(),
  verifySlsa: vi.fn(async (_input: unknown) => ({ ok: true, detail: "verified test attestation" })),
  inspectEngineSetup: vi.fn(async () => {
    const next = harness.statuses.shift();
    if (!next) throw new Error("repair test exhausted engine setup states");
    return next;
  }),
  installOsvEcosystemDb: vi.fn(async (ecosystem: string, _io?: unknown) => ({ ecosystem })),
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
    MANAGED_SETUP_PREFERENCES: join(harness.root, "setup-preferences.json"),
  };
});

vi.mock("./engine-health.js", () => ({
  inspectEngineSetup: harness.inspectEngineSetup,
}));

vi.mock("./osv/database.js", () => ({
  installOsvEcosystemDb: harness.installOsvEcosystemDb,
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
  verifySlsaAttestation: harness.verifySlsa,
}));

const { repairEngines, pinEnginePlatform, verifyEnginesCli } = await import("./install.js");

const asset = Buffer.from("verified-opengrep-test-binary");
const assetSha = createHash("sha256").update(asset).digest("hex");

const osvAsset = Buffer.from("verified-osv-scanner-test-binary");
const osvSha = createHash("sha256").update(osvAsset).digest("hex");
const osvAttestation = Buffer.from('{"mediaType":"test-intoto-bundle"}');

function setup(state: EngineSetupStatus["state"], opengrep: "ready" | "missing"): EngineSetupStatus {
  return {
    state,
    platform: "test-x64",
    engines: [
      { engine: "opengrep", version: "1.33.1", state: opengrep },
      { engine: "gitleaks", version: "8.30.1", state: "ready" },
      { engine: "trivy", version: "0.76.1", state: "ready" },
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
  harness.verifySlsa.mockClear();
  harness.installOsvEcosystemDb.mockClear();
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
      "osv-scanner": "https://identity.example/slsa-generator",
    },
    engines: {
      opengrep: {
        version: "1.33.1",
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
        version: "0.76.1",
        repo: "example/trivy",
        release_base: "https://downloads.example/trivy",
        signature: "checksums+sigstore",
        checksums_asset: "checksums.txt",
        platforms: {},
      },
      "osv-scanner": {
        version: "2.7.0",
        repo: "example/osv-scanner",
        release_base: "https://downloads.example/osv-scanner",
        signature: "checksums+slsa",
        checksums_asset: "osv-scanner_SHA256SUMS",
        attestation_asset: "multiple.intoto.jsonl",
        platforms: {
          "test-x64": { asset: "osv-test", archive: "raw", binary: "osv-scanner", sha256: null },
          "test-arm64": { asset: "osv-test-arm", archive: "raw", binary: "osv-scanner", sha256: null },
        },
      },
    },
    slsa_workflow_repositories: { "osv-scanner": "example/osv-scanner" },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      const body = url.endsWith("opengrep-test")
        ? asset
        : url.endsWith("/osv-test") || url.endsWith("/osv-test-arm")
          ? osvAsset
          : url.endsWith("osv-scanner_SHA256SUMS")
            ? Buffer.from(`${osvSha}  osv-test\n${osvSha}  osv-test-arm\n`)
            : url.endsWith("multiple.intoto.jsonl")
              ? osvAttestation
              : Buffer.from("test-signature-material");
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

describe("OSV database repair", () => {
  const withOsv = (osv_databases: NonNullable<EngineSetupStatus["osv_databases"]>, state: EngineSetupStatus["state"] = "ready") => ({
    ...setup(state, "ready"),
    engines: [...setup(state, "ready").engines, { engine: "osv-scanner" as const, version: "2.7.0", state: "ready" as const }],
    osv_databases,
  });
  const io = () => {
    const lines: string[] = [];
    return { lines, stdout: (text: string) => void lines.push(text), stderr: (text: string) => void lines.push(text) };
  };

  test("downloads exactly the requested ecosystems under the repair lock, then re-checks readiness", async () => {
    const before = withOsv([], "db_refresh_recommended");
    harness.statuses = [
      before,
      before,
      withOsv([
        { ecosystem: "npm", state: "ready", downloaded_at: "2026-10-30T00:00:00.000Z" },
        { ecosystem: "PyPI", state: "ready", downloaded_at: "2026-10-30T00:00:00.000Z" },
      ]),
    ];
    const output = io();

    await repairEngines(["osv-scanner", "--osv-ecosystems", "PyPI,npm"], output);

    expect(harness.installOsvEcosystemDb.mock.calls.map(([ecosystem]) => ecosystem)).toEqual(["npm", "PyPI"]);
    expect(harness.installOsvEcosystemDb.mock.calls[0]?.[1]).toBe(output);
    expect(output.lines.join("\n")).toContain("OSV databases npm, PyPI");
    expect(fetch).not.toHaveBeenCalled(); // no engine binary was unhealthy
    await expect(readFile(join(harness.root, ".repair-engines.lock", "owner.json"))).rejects.toThrow();
  });

  test("does nothing, and downloads nothing, when the requested databases are already ready", async () => {
    const installed = withOsv([{ ecosystem: "PyPI", state: "ready", downloaded_at: "2026-10-30T00:00:00.000Z" }]);
    harness.statuses = [installed];
    const output = io();

    await repairEngines(["osv-scanner", "--osv-ecosystems", "PyPI"], output);

    expect(harness.installOsvEcosystemDb).not.toHaveBeenCalled();
    expect(output.lines.join("\n")).toContain("no download needed");
  });

  test("fails when the databases are still not ready after the download", async () => {
    const before = withOsv([], "db_refresh_recommended");
    harness.statuses = [before, before, before];

    await expect(repairEngines(["osv-scanner", "--osv-ecosystems", "Go"], io())).rejects.toThrow(
      /Repair finished but preflight is still/,
    );
    expect(harness.installOsvEcosystemDb).toHaveBeenCalledTimes(1);
    await expect(readFile(join(harness.root, ".repair-engines.lock", "owner.json"))).rejects.toThrow();
  });

  test("a failed database download aborts the repair and still releases the lock", async () => {
    const before = withOsv([], "db_refresh_recommended");
    harness.statuses = [before, before];
    harness.installOsvEcosystemDb.mockRejectedValueOnce(new Error("OSV Go database download failed (503)"));

    await expect(repairEngines(["osv-scanner", "--osv-ecosystems", "Go"], io())).rejects.toThrow("503");
    await expect(readFile(join(harness.root, ".repair-engines.lock", "owner.json"))).rejects.toThrow();
  });
});

describe("osv-scanner in a bare repair (an additive engine)", () => {
  const withOsvEngine = (state: "ready" | "missing"): EngineSetupStatus => ({
    ...setup("ready", "ready"),
    engines: [...setup("ready", "ready").engines, { engine: "osv-scanner", version: "2.7.0", state }],
  });
  const output = () => {
    const lines: string[] = [];
    return { lines, stdout: (text: string) => void lines.push(text), stderr: (text: string) => void lines.push(text) };
  };
  const choose = async (choice: "enabled" | "declined") => {
    await mkdir(harness.root, { recursive: true });
    await writeFile(join(harness.root, "setup-preferences.json"), JSON.stringify({
      schema_version: 1,
      updated_at: "2026-10-31T00:00:00.000Z",
      choices: { opengrep: "enabled", gitleaks: "enabled", trivy: "enabled", "osv-scanner": choice },
    }), "utf8");
  };

  beforeEach(() => {
    harness.lock!.engines["osv-scanner"]!.platforms["test-x64"]!.sha256 = osvSha;
  });

  test("skips an osv-scanner that setup recorded as declined, and downloads nothing", async () => {
    await choose("declined");
    harness.statuses = [withOsvEngine("missing")];
    const io = output();

    await repairEngines([], io);

    expect(fetch).not.toHaveBeenCalled();
    expect(io.lines.join("\n")).toContain("osv-scanner was declined in setup");
    expect(io.lines.join("\n")).toContain("Engine setup ready");
    await expect(readFile(join(harness.root, "bin", "osv-scanner"))).rejects.toThrow();
  });

  test("still maintains an osv-scanner that is installed although setup recorded a decline", async () => {
    await choose("declined");
    const mismatched = { ...withOsvEngine("ready"), engines: [...withOsvEngine("ready").engines.slice(0, 3), { engine: "osv-scanner" as const, version: "2.7.0", state: "hash_mismatch" as const }] };
    harness.statuses = [mismatched, mismatched, withOsvEngine("ready")];
    const io = output();

    await repairEngines([], io);

    expect(await readFile(join(harness.root, "bin", "osv-scanner"))).toEqual(osvAsset);
    expect(io.lines.join("\n")).not.toContain("declined");

    // Installed and healthy, with a stale database: the bare repair refreshes it.
    const stale = { ...withOsvEngine("ready"), state: "db_refresh_recommended" as const, osv_databases: [{ ecosystem: "PyPI" as const, state: "stale" as const, downloaded_at: "2026-10-01T00:00:00.000Z" }] };
    harness.statuses = [stale, stale, { ...withOsvEngine("ready"), osv_databases: [{ ecosystem: "PyPI" as const, state: "ready" as const, downloaded_at: "2026-10-31T00:00:00.000Z" }] }];
    await repairEngines([], output());
    expect(harness.installOsvEcosystemDb.mock.calls.map(([ecosystem]) => ecosystem)).toEqual(["PyPI"]);
  });

  test.each([
    ["names it", "declined", ["osv-scanner"]],
    ["passes an OSV list", "declined", ["--osv-ecosystems", "PyPI"]],
    ["has no saved decline", "enabled", []],
  ] as Array<[string, "enabled" | "declined", string[]]>)("still installs osv-scanner when the repair %s", async (_name, choice, args) => {
    await choose(choice);
    const after = { ...withOsvEngine("ready"), osv_databases: [{ ecosystem: "PyPI" as const, state: "ready" as const, downloaded_at: "2026-10-31T00:00:00.000Z" }] };
    harness.statuses = [withOsvEngine("missing"), withOsvEngine("missing"), after];
    const io = output();

    await repairEngines(args, io);

    expect(await readFile(join(harness.root, "bin", "osv-scanner"))).toEqual(osvAsset);
    expect(io.lines.join("\n")).not.toContain("declined");
  });
});

describe("checksums+slsa engine pinning", () => {
  const io = { stdout: () => {}, stderr: () => {} };

  function pin(platform: string, cache = new Map<EngineName, Map<string, string>>(), cosign = true, install = false) {
    return pinEnginePlatform(
      "osv-scanner",
      platform,
      harness.lock!,
      harness.lock!.sigstore_identities!,
      cosign,
      join(harness.root, "stage"),
      cache,
      install,
      true,
      io,
    );
  }

  test("checksums+slsa engine fails closed when attestation verification fails", async () => {
    harness.verifySlsa.mockResolvedValueOnce({ ok: false, detail: "cosign FAILED: no matching attestation" });

    await expect(pin("test-x64")).rejects.toThrow(/attestation verification FAILED.*no matching attestation/s);

    expect(harness.lock!.engines["osv-scanner"].platforms["test-x64"]?.sha256).toBeNull();
    expect(harness.lock!.engines["osv-scanner"].platforms["test-x64"]?.provenance).toBeUndefined();
  });

  test("records slsa provenance after the checksum and attestation both verify", async () => {
    await pin("test-x64", new Map(), true, true);

    const entry = harness.lock!.engines["osv-scanner"].platforms["test-x64"];
    expect(entry?.sha256).toBe(osvSha);
    expect(entry?.download_size_bytes).toBe(osvAsset.length);
    expect(entry?.provenance).toMatchObject({
      method: "slsa",
      verified: true,
      identity: "https://identity.example/slsa-generator",
      issuer: "https://issuer.example",
    });
    expect(harness.verifySlsa).toHaveBeenCalledTimes(1);
    expect(harness.verifySlsa.mock.calls[0]?.[0]).toMatchObject({
      blob: join(harness.root, "stage", "osv-scanner-test-x64", "osv-test"),
      bundlePath: join(harness.root, "stage", "osv-scanner-multiple.intoto.jsonl"),
      identity: "https://identity.example/slsa-generator",
      issuer: "https://issuer.example",
      workflowRepository: "example/osv-scanner",
    });
    // Cached so `verify-engines --deep` can re-run the attestation offline-from-GitHub.
    expect(await readFile(join(harness.root, "provenance", "osv-scanner", "multiple.intoto.jsonl"))).toEqual(osvAttestation);
  });

  test("downloads the attestation once per engine across platforms", async () => {
    const cache = new Map<EngineName, Map<string, string>>();
    await pin("test-x64", cache);
    await pin("test-arm64", cache);

    const attestationFetches = vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith("multiple.intoto.jsonl"));
    expect(attestationFetches).toHaveLength(1);
    expect(harness.verifySlsa).toHaveBeenCalledTimes(2);
  });

  test("refuses to pin without cosign or without a pinned workflow repository", async () => {
    await expect(pin("test-x64", new Map(), false)).rejects.toThrow(/requires cosign.*fail-closed/s);

    delete harness.lock!.slsa_workflow_repositories;
    await expect(pin("test-x64")).rejects.toThrow(/no pinned.*workflow repository.*fail-closed/s);

    expect(harness.verifySlsa).not.toHaveBeenCalled();
    expect(harness.lock!.engines["osv-scanner"].platforms["test-x64"]?.sha256).toBeNull();
  });

  test("refuses to pin without a pinned sigstore identity or issuer", async () => {
    const identities = harness.lock!.sigstore_identities!;
    for (const key of ["osv-scanner", "issuer"]) {
      const saved = identities[key];
      delete identities[key];
      await expect(pin("test-x64")).rejects.toThrow(/no pinned cosign identity\/issuer \(fail-closed\)/);
      identities[key] = saved!;
    }

    expect(harness.verifySlsa).not.toHaveBeenCalled();
    expect(harness.lock!.engines["osv-scanner"].platforms["test-x64"]?.sha256).toBeNull();
  });

  test("does not call the attestation verifier when the SHA256SUMS check fails", async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("osv-scanner_SHA256SUMS")) return new Response(`${"0".repeat(64)}  osv-test\n`, { status: 200 });
      return new Response(url.endsWith("osv-test") ? osvAsset : osvAttestation, { status: 200 });
    });

    await expect(pin("test-x64")).rejects.toThrow(/checksum MISMATCH/);

    expect(harness.verifySlsa).not.toHaveBeenCalled();
    expect(harness.lock!.engines["osv-scanner"].platforms["test-x64"]?.sha256).toBeNull();
  });
});

describe("verify-engines --deep", () => {
  test.skipIf(process.platform === "win32")(
    "re-runs the osv-scanner SLSA check against the installed binary and cached attestation, failing closed",
    async () => {
      const osv = harness.lock!.engines["osv-scanner"];
      // getPlatformEntry's default key is the real platform (the mock only replaces the exported platformKey).
      const { platformKey } = await vi.importActual<typeof import("./engines/lockfile.js")>("./engines/lockfile.js");
      osv.platforms[platformKey()] = {
        ...osv.platforms["test-x64"]!,
        sha256: osvSha,
        provenance: {
          method: "slsa",
          verified: true,
          at: "2026-10-30T00:00:00.000Z",
          identity: "https://identity.example/slsa-generator",
          issuer: "https://issuer.example",
        },
      };
      await mkdir(join(harness.root, "bin"), { recursive: true });
      await writeFile(join(harness.root, "bin", "osv-scanner"), osvAsset, { mode: 0o755 });
      const written = (stream: NodeJS.WriteStream) => vi.mocked(stream.write).mock.calls.map(([text]) => String(text)).join("");
      const argv = process.argv;
      const exitCode = process.exitCode;
      process.argv = [...argv, "--deep"];
      try {
        await verifyEnginesCli();
        expect(harness.verifySlsa).toHaveBeenCalledTimes(1);
        expect(harness.verifySlsa.mock.calls[0]?.[0]).toEqual({
          blob: join(harness.root, "bin", "osv-scanner"),
          bundlePath: join(harness.root, "provenance", "osv-scanner", "multiple.intoto.jsonl"),
          identity: "https://identity.example/slsa-generator",
          issuer: "https://issuer.example",
          workflowRepository: "example/osv-scanner",
        });
        expect(written(process.stdout)).toContain("osv-scanner: deep signature re-verification passed");

        harness.verifySlsa.mockResolvedValueOnce({ ok: false, detail: "no matching attestation" });
        await verifyEnginesCli();
        expect(written(process.stderr)).toContain("osv-scanner: deep cosign re-verification FAILED");

        // Without a pinned workflow repository the check fails closed and never calls the verifier.
        delete harness.lock!.slsa_workflow_repositories;
        harness.verifySlsa.mockClear();
        vi.mocked(process.stderr.write).mockClear();
        await verifyEnginesCli();
        expect(harness.verifySlsa).not.toHaveBeenCalled();
        expect(written(process.stderr)).toContain("osv-scanner: deep cosign re-verification FAILED");
        expect(process.exitCode).toBe(1);
      } finally {
        process.argv = argv;
        process.exitCode = exitCode;
      }
    },
  );
});
