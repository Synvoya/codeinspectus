import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { SERVER_VERSION } from "./config.js";
import { SDK_API_VERSION, SDK_COMPATIBILITY } from "./sdk/index.js";

const RELEASE_VERSION = "2.0.0";

describe("V2 release source synchronization", () => {
  test("package, lockfile, server, CLI, and SDK versions agree", async () => {
    const packageJson = JSON.parse(await readFile("package.json", "utf8")) as { version: string; files: string[] };
    const packageLock = JSON.parse(await readFile("package-lock.json", "utf8")) as {
      version: string;
      packages: Record<string, { version?: string }>;
    };
    const server = JSON.parse(await readFile("server.json", "utf8")) as {
      version: string;
      packages: Array<{ identifier: string; version: string }>;
    };

    expect(packageJson.version).toBe(RELEASE_VERSION);
    expect(packageLock.version).toBe(RELEASE_VERSION);
    expect(packageLock.packages[""]?.version).toBe(RELEASE_VERSION);
    expect(server.version).toBe(RELEASE_VERSION);
    expect(server.packages).toEqual([
      expect.objectContaining({ identifier: "codeinspectus", version: RELEASE_VERSION }),
    ]);
    expect(SERVER_VERSION).toBe(RELEASE_VERSION);
    expect(SDK_API_VERSION).toBe(RELEASE_VERSION);
    expect(SDK_COMPATIBILITY).toMatchObject({ cli_major: 2, export_schema: "2.0.0" });
    expect(packageJson.files).toContain("agent-rules");
  });

  test("detection breadth stays independently reconciled", async () => {
    const manifest = JSON.parse(await readFile("detection-db/manifest.json", "utf8")) as {
      version: string;
      custom_rules: Array<{ engine: string; pack_id?: string }>;
    };
    const native = manifest.custom_rules.filter((rule) => rule.engine === "codeinspectus-ai");
    expect(manifest.version).toBe("1.13.0");
    expect(manifest.custom_rules).toHaveLength(86);
    expect(native).toHaveLength(65);
    expect(new Set(native.map((rule) => rule.pack_id)).size).toBe(16);
  });

  test("release documentation and public projection include V2 surfaces", async () => {
    const readme = await readFile("README.md", "utf8");
    const changelog = await readFile("CHANGELOG.md", "utf8");
    const cliReference = await readFile("docs/CLI-REFERENCE.md", "utf8");
    const provenance = await readFile("docs/V2-WORKFLOW-PROVENANCE.md", "utf8");

    expect(changelog).toContain("## [2.0.0] — 2026-07-30");
    expect(readme).toContain("CLI command reference");
    for (const command of ["scan", "preflight", "export", "scans", "triage", "bundle", "bulk", "history", "issue"]) {
      expect(cliReference).toMatch(new RegExp(`codeinspectus ${command}\\b`));
    }
    expect(provenance).toContain("No Codex Security source code or documentation text was copied");
    if (existsSync("scripts/seed-public.mjs")) {
      const seed = await readFile("scripts/seed-public.mjs", "utf8");
      expect(seed).toContain('"docs/CLI-REFERENCE.md"');
      expect(seed).toContain('"docs/V2-WORKFLOW-PROVENANCE.md"');
    } else {
      expect(existsSync("docs/CLI-REFERENCE.md")).toBe(true);
      expect(existsSync("docs/V2-WORKFLOW-PROVENANCE.md")).toBe(true);
    }
  });
});
