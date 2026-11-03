import { describe, expect, test, vi } from "vitest";

// Review I-5: on Windows, `node:path` defaults are win32, so joining a target-relative POSIX path
// gave `frontend\package-lock.json` and never matched the discovered `frontend/package-lock.json`.
// Run the classifier with win32 defaults (POSIX still available as `posix`).
vi.mock("node:path", async () => {
  const actual = await vi.importActual<typeof import("node:path")>("node:path");
  return { ...actual.win32, posix: actual.posix, win32: actual.win32, default: { ...actual.win32, posix: actual.posix, win32: actual.win32 } };
});

const { gapsFromFiles } = await import("./coverage-gaps.js");

describe("coverage-gap classification under win32 path semantics", () => {
  test("nested lockfiles still lock their manifests", async () => {
    const manifests: Record<string, Record<string, unknown>> = {
      "frontend/package.json": { dependencies: { react: "19.0.0" } },
      "apps/api/composer.json": { require: { "monolog/monolog": "^3" } },
      "tools/package.json": { dependencies: { lodash: "4.17.4" } },
    };
    const { gaps } = await gapsFromFiles([
      "frontend/package.json", "frontend/package-lock.json",
      "apps/api/composer.json", "apps/api/composer.lock",
      "web/bun.lockb", "web/bun.lock",
      "cli/npm-shrinkwrap.json", "cli/package-lock.json",
      "tools/package.json",
    ], async (rel) => (manifests[rel] ? JSON.stringify(manifests[rel]) : undefined));

    expect(gaps).toEqual([{ id: "no-lockfile-npm", files: 1, examples: ["tools/package.json"] }]);
  });
});
