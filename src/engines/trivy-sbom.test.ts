import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  mode: "success" as "success" | "fail" | "fail_with_partial" | "success_without_output",
  stagedPath: "",
}));

vi.mock("../config.js", () => ({
  MANAGED_TRIVY_CACHE: join(tmpdir(), `codeinspectus-trivy-sbom-cache-${process.pid}`),
  MANAGED_TRIVY_DB_META: join(tmpdir(), `codeinspectus-trivy-sbom-cache-${process.pid}`, "metadata.json"),
}));

vi.mock("./resolve.js", () => ({
  EngineUnavailableError: class EngineUnavailableError extends Error {},
  resolveEngine: vi.fn(async () => ({ path: "/test/trivy", version: "0.71.2", sha256: "a".repeat(64) })),
}));

vi.mock("./exec.js", () => ({
  execBinary: vi.fn(async (_binary: string, args: string[]) => {
    const outputIndex = args.indexOf("--output");
    state.stagedPath = args[outputIndex + 1] ?? "";
    if (state.mode === "success" || state.mode === "fail_with_partial") {
      await writeFile(state.stagedPath, state.mode === "success" ? "{\"fresh\":true}\n" : "partial", "utf8");
    }
    if (state.mode === "fail" || state.mode === "fail_with_partial") {
      return { code: 1, stdout: "", stderr: "synthetic failure", timedOut: false };
    }
    return { code: 0, stdout: "", stderr: "", timedOut: false };
  }),
}));

const { runTrivySbom } = await import("./trivy.js");

const roots: string[] = [];

beforeEach(() => {
  state.mode = "success";
  state.stagedPath = "";
});

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(): Promise<{ root: string; output: string }> {
  const root = await mkdtemp(join(tmpdir(), "codeinspectus-trivy-sbom-"));
  roots.push(root);
  return { root, output: join(root, "sbom.json") };
}

describe("Trivy SBOM staging", () => {
  it.each(["fail", "fail_with_partial"] as const)(
    "never reuses a pre-existing artifact when the current run is %s",
    async (mode) => {
      const { root, output } = await fixture();
      await writeFile(output, "{\"stale\":true}\n", "utf8");
      state.mode = mode;

      const result = await runTrivySbom(root, "cyclonedx", output);

      expect(result).toMatchObject({ ran: false, version: "0.71.2" });
      expect(result.note).toMatch(/failed.*synthetic failure/i);
      expect(await readFile(output, "utf8")).toBe("{\"stale\":true}\n");
      expect(await readdir(root)).toEqual(["sbom.json"]);
    },
  );

  it("returns only fresh bounded staged content for caller-side validation", async () => {
    const { root, output } = await fixture();
    await writeFile(output, "{\"stale\":true}\n", "utf8");

    const result = await runTrivySbom(root, "spdx", output);

    expect(result).toEqual({ ran: true, version: "0.71.2", content: "{\"fresh\":true}\n" });
    expect(state.stagedPath).not.toBe(output);
    expect(await readFile(output, "utf8")).toBe("{\"stale\":true}\n");
    expect(await readdir(root)).toEqual(["sbom.json"]);
  });

  it("fails without replacing the old artifact when exit is zero but no new file exists", async () => {
    const { root, output } = await fixture();
    await writeFile(output, "{\"stale\":true}\n", "utf8");
    state.mode = "success_without_output";

    const result = await runTrivySbom(root, "cyclonedx", output);

    expect(result.ran).toBe(false);
    expect(result.note).toMatch(/no fresh output/i);
    expect(await readFile(output, "utf8")).toBe("{\"stale\":true}\n");
    expect(await readdir(root)).toEqual(["sbom.json"]);
  });
});
