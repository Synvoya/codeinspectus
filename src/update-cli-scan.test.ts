/**
 * `codeinspectus scan` (and CI) never shows the database update prompt and never calls the update code, even
 * when the prompt is due: the prompt module is replaced by one that is always due, and every update entry
 * point and the global fetch are spies that must stay untouched.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

const spies = vi.hoisted(() => ({
  prompt: vi.fn(async () => ({
    due: true as const,
    question: "Security databases were last updated 3 days ago. Check for updates and download them now?",
    databases: [{ id: "trivy-db", detail: "test" }],
    package_content: [],
    large_downloads: [],
    answers: [],
  })),
  update: vi.fn(async () => {
    throw new Error("the update must not run during a scan");
  }),
}));

vi.mock("./update-prompt.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./update-prompt.js")>()),
  databaseUpdatePrompt: spies.prompt,
}));
vi.mock("./update.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./update.js")>()),
  runDatabaseUpdate: spies.update,
}));

import { runCli } from "./cli.js";

const roots: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("CLI scan and the database update prompt", () => {
  test.each([["text"], ["json"]])("a %s CLI scan prints no prompt, calls no update code and uses no network", async (format) => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-cli-update-"));
    roots.push(root);
    await writeFile(join(root, "app.js"), "export const answer = 42;\n", "utf8");
    const globalFetch = vi.fn(async () => {
      throw new Error("the network must not be used");
    });
    vi.stubGlobal("fetch", globalFetch);
    let out = "";
    let err = "";
    const code = await runCli(["scan", root, "--scanner", "ai", "--format", format], {
      stdout: (text) => { out += text; },
      stderr: (text) => { err += text; },
    });
    // 2 is the CI policy for partial coverage (an ai-only scan); it is unrelated to the update prompt.
    expect([0, 2]).toContain(code);
    expect(out.length).toBeGreaterThan(0);
    for (const text of [out, err]) {
      expect(text).not.toContain("Security databases were last updated");
      expect(text).not.toContain("database_update");
    }
    expect(spies.prompt).not.toHaveBeenCalled();
    expect(spies.update).not.toHaveBeenCalled();
    expect(globalFetch).not.toHaveBeenCalled();
  });
});
