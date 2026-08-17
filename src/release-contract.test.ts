import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { SERVER_VERSION } from "./config.js";
import { SDK_API_VERSION, SDK_COMPATIBILITY } from "./sdk/index.js";

const RELEASE_VERSION = "2.5.0";

describe("V2 release source synchronization", () => {
  test("package, lockfile, server, CLI, and SDK versions agree", async () => {
    const packageJson = JSON.parse(await readFile("package.json", "utf8")) as {
      version: string;
      license: string;
      files: string[];
    };
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
    expect(packageJson.license).toBe("Apache-2.0");
    expect(packageJson.files).toContain("agent-rules");
    expect(packageJson.files).toContain("LICENSE");
    expect(packageJson.files).toContain("NOTICE");
    expect(packageJson.files).toContain("THIRD-PARTY-NOTICES.md");
    expect(await readFile("LICENSE", "utf8")).toContain("Apache License");
    expect(await readFile("NOTICE", "utf8")).toContain("Copyright 2026 Synvoya");
    expect(await readFile("THIRD-PARTY-NOTICES.md", "utf8")).toContain("Opengrep 1.23.0");
  });

  test("detection breadth stays independently reconciled", async () => {
    const manifest = JSON.parse(await readFile("detection-db/manifest.json", "utf8")) as {
      version: string;
      custom_rules: Array<{ engine: string; pack_id?: string }>;
    };
    const native = manifest.custom_rules.filter((rule) => rule.engine === "codeinspectus-ai");
    expect(manifest.version).toBe("1.19.0");
    expect(manifest.custom_rules).toHaveLength(94);
    expect(native).toHaveLength(72);
    expect(new Set(native.map((rule) => rule.pack_id)).size).toBe(16);
  });

  test("Glama ownership metadata identifies the public maintainer", async () => {
    const glama = JSON.parse(await readFile("glama.json", "utf8")) as {
      $schema: string;
      maintainers: string[];
    };

    expect(glama).toEqual({
      $schema: "https://glama.ai/mcp/schemas/server.json",
      maintainers: ["Synvoya"],
    });
    if (existsSync("scripts/seed-public.mjs")) {
      const seed = await readFile("scripts/seed-public.mjs", "utf8");
      expect(seed).toContain('"glama.json"');
    }
  });

  test("release documentation and public projection include V2 surfaces", async () => {
    const readme = await readFile("README.md", "utf8");
    const changelog = await readFile("CHANGELOG.md", "utf8");
    const cliReference = await readFile("docs/CLI-REFERENCE.md", "utf8");
    const provenance = await readFile("docs/V2-WORKFLOW-PROVENANCE.md", "utf8");
    const licenseTransition = await readFile("docs/LICENSE-TRANSITION.md", "utf8");

    expect(changelog).toContain("## [2.0.0] — 2026-07-30");
    expect(changelog).toContain("## [2.1.0] — 2026-08-02");
    expect(changelog).toContain("## [2.5.0] — 2026-08-13");
    expect(readme).toContain("CLI command reference");
    expect(readme).toContain("reproduce-v2.1-case-study.mjs");
    expect(changelog).toContain("CODEINSPECTUS_CASE_PACKAGE");
    for (const command of ["scan", "preflight", "export", "scans", "triage", "bundle", "bulk", "history", "issue"]) {
      expect(cliReference).toMatch(new RegExp(`codeinspectus ${command}\\b`));
    }
    expect(provenance).toContain("No Codex Security source code or documentation text was copied");
    expect(licenseTransition).toContain("2.5.0 and later");
    if (existsSync("scripts/seed-public.mjs")) {
      const seed = await readFile("scripts/seed-public.mjs", "utf8");
      expect(seed).toContain('"docs/CLI-REFERENCE.md"');
      expect(seed).toContain('"docs/V2-WORKFLOW-PROVENANCE.md"');
      expect(seed).toContain('"docs/LICENSE-TRANSITION.md"');
    } else {
      expect(existsSync("docs/CLI-REFERENCE.md")).toBe(true);
      expect(existsSync("docs/V2-WORKFLOW-PROVENANCE.md")).toBe(true);
    }
  });
});
