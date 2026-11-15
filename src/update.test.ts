import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

import { SERVER_VERSION } from "./config.js";
import type { InstallIo } from "./install.js";
import type { EngineSetupStatus } from "./types.js";
import { databaseUpdatePrompt, ENGINE_NEEDS_SETUP, readUpdatePromptState, writeUpdatePromptState } from "./update-prompt.js";
import { NPM_LATEST_URL, planDatabaseUpdate, runDatabaseUpdate, runUpdateCli, type UpdateCliIo } from "./update.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const T = Date.parse("2026-11-01T00:00:00.000Z");
const NOW = T + 3 * DAY;
const iso = (ms: number): string => new Date(ms).toISOString();

const directories: string[] = [];
async function statePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-update-"));
  directories.push(directory);
  return join(directory, "update-prompt.json");
}
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const READY_ENGINES: EngineSetupStatus["engines"] = [
  { engine: "trivy", version: "test", state: "ready" },
  { engine: "osv-scanner", version: "test", state: "ready" },
];

function status(overrides: Partial<EngineSetupStatus> = {}): EngineSetupStatus {
  return {
    state: "ready",
    platform: "test",
    engines: READY_ENGINES,
    trivy_db: { state: "missing" },
    osv_databases: [],
    network_required: false,
    ...overrides,
  };
}
const installed = (downloadedAt: number, ecosystems: Array<"npm" | "PyPI" | "Go"> = ["PyPI"], trivy = true): EngineSetupStatus => status({
  ...(trivy ? { trivy_db: { state: "ready", downloaded_at: iso(downloadedAt) } } : {}),
  osv_databases: ecosystems.map((ecosystem) => ({ ecosystem, state: "ready" as const, downloaded_at: iso(downloadedAt) })),
});

/** Before the repair the first status, after it the second. */
function inspector(before: EngineSetupStatus, after: EngineSetupStatus = before): () => Promise<EngineSetupStatus> {
  let calls = 0;
  return async () => (calls++ === 0 ? before : after);
}

const quietIo: InstallIo = { stdout: () => undefined, stderr: () => undefined };

const CSV = [
  `${iso(T + 2 * DAY)},PYSEC-2026-3`,
  `${iso(T + DAY)},GHSA-aaaa-bbbb-cccc`,
  `${iso(T + 1)},PYSEC-2026-2`,
  `${iso(T)},PYSEC-2026-1`,
  `${iso(T - DAY)},PYSEC-2025-9`,
  "",
].join("\n");

function fakeFetch(routes: Record<string, () => Response>): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    const route = routes[url];
    if (!route) throw new Error(`unexpected fetch ${url}`);
    return route();
  });
}
const npmLatest = (version: string) => () => new Response(JSON.stringify({ name: "codeinspectus", version }), { status: 200 });
const PYPI_CSV = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv";

describe("planDatabaseUpdate", () => {
  test("lists the installed Trivy DB and OSV databases, flags those over 100 MB as large, plus the npm check", () => {
    const plan = planDatabaseUpdate(installed(T, ["npm", "PyPI"]));
    expect(plan.databases.map((database) => [database.id, database.approx_size, database.large])).toEqual([
      ["trivy-db", "133.5 MiB", true],
      ["osv:npm", "209.4 MiB", true],
      ["osv:PyPI", "35.8 MiB", false],
    ]);
    expect(plan.databases[0]?.on_disk).toMatch(/on disk$/);
    expect(plan.databases.slice(1).every((database) => database.on_disk === undefined)).toBe(true);
    expect(plan.skipped).toEqual([]);
    expect(plan.large_downloads).toEqual([
      { id: "trivy-db", approx_size: "133.5 MiB" },
      { id: "osv:npm", approx_size: "209.4 MiB" },
    ]);
    expect(plan.package_check).toEqual({ source: NPM_LATEST_URL, running: SERVER_VERSION });
  });

  test("nothing installed: no databases to update", () => {
    expect(planDatabaseUpdate(status()).databases).toEqual([]);
  });

  test("a database whose engine is not ready is skipped, never repaired", () => {
    const plan = planDatabaseUpdate(status({
      ...installed(T),
      engines: [{ engine: "trivy", version: "test", state: "hash_mismatch" }, { engine: "osv-scanner", version: "test", state: "ready" }],
    }));
    expect(plan.databases.map((database) => database.id)).toEqual(["osv:PyPI"]);
    expect(plan.skipped).toEqual([{ id: "trivy-db", detail: ENGINE_NEEDS_SETUP }]);
    expect(plan.large_downloads).toEqual([]);
  });
});

describe("runDatabaseUpdate", () => {
  test("without confirm_downloads it throws before any network call or repair", async () => {
    const fetchSpy = fakeFetch({});
    const repair = vi.fn(async () => undefined);
    await expect(runDatabaseUpdate({
      confirmDownloads: false, confirmLargeDownloads: true, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T)), statePath: await statePath(), nowMs: NOW,
    })).rejects.toThrow(/confirm/i);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test("a large database without confirm_large_downloads throws naming it, before any network call", async () => {
    const fetchSpy = fakeFetch({});
    const repair = vi.fn(async () => undefined);
    await expect(runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: false, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T, ["npm"])), statePath: await statePath(), nowMs: NOW,
    })).rejects.toThrow(/osv:npm/);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test("the Trivy DB alone is a large download", async () => {
    const fetchSpy = fakeFetch({});
    await expect(runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: false, fetch: fetchSpy, repair: vi.fn(async () => undefined), io: quietIo,
      inspect: inspector(installed(T, [])), statePath: await statePath(), nowMs: NOW,
    })).rejects.toThrow(/trivy-db/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("an engine that is not ready is left out of the repair and reported skipped", async () => {
    const broken = (downloadedAt: number): EngineSetupStatus => status({
      ...installed(downloadedAt),
      engines: [{ engine: "trivy", version: "test", state: "hash_mismatch" }, { engine: "osv-scanner", version: "test", state: "ready" }],
    });
    const repair = vi.fn(async () => undefined);
    const result = await runDatabaseUpdate({
      // No large confirmation: the only large database (the Trivy DB) is skipped.
      confirmDownloads: true, confirmLargeDownloads: false,
      fetch: fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair, io: quietIo, inspect: inspector(broken(T), status({ ...broken(T), osv_databases: installed(NOW).osv_databases })),
      statePath: await statePath(), nowMs: NOW,
    });
    expect(repair).toHaveBeenCalledWith(["osv-scanner", "--refresh-db", "--osv-ecosystems", "PyPI"], quietIo);
    expect(JSON.stringify(repair.mock.calls)).not.toContain("trivy");
    expect(result.outcome).toBe("updated");
    expect(result.databases.map((database) => database.id)).toEqual(["osv:PyPI"]);
    expect(result.skipped).toEqual([{ id: "trivy-db", detail: ENGINE_NEEDS_SETUP }]);
    expect(result.message).toContain("trivy-db");
  });

  test("excluded databases (just refreshed elsewhere) are neither downloaded nor gated as large", async () => {
    const repair = vi.fn(async () => undefined);
    const result = await runDatabaseUpdate({
      // The Trivy DB is large, but it is excluded, so no large confirmation is needed.
      confirmDownloads: true, confirmLargeDownloads: false, exclude: ["trivy-db"],
      fetch: fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair, io: quietIo, inspect: inspector(installed(T), installed(NOW)), statePath: await statePath(), nowMs: NOW,
    });
    expect(repair).toHaveBeenCalledWith(["osv-scanner", "--refresh-db", "--osv-ecosystems", "PyPI"], quietIo);
    expect(JSON.stringify(repair.mock.calls)).not.toContain("trivy");
    expect(result.databases.map((database) => database.id)).toEqual(["osv:PyPI"]);
  });

  test("every database excluded: it throws before any network call", async () => {
    const fetchSpy = fakeFetch({});
    const repair = vi.fn(async () => undefined);
    await expect(runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, exclude: ["trivy-db", "osv:PyPI"], fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T)), statePath: await statePath(), nowMs: NOW,
    })).rejects.toThrow(/nothing left to update/i);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test("nothing an update can refresh: it throws instead of reporting an update", async () => {
    const fetchSpy = fakeFetch({});
    await expect(runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair: vi.fn(async () => undefined), io: quietIo,
      inspect: inspector(status()), statePath: await statePath(), nowMs: NOW,
    })).rejects.toThrow(/nothing to update/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("every fetch carries a timeout signal; a timed-out change list is unavailable and the refresh still runs", async () => {
    const abort = (): never => {
      throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
    };
    const fetchSpy = vi.fn<typeof fetch>(async (input) => {
      if (String(input) === PYPI_CSV) throw new DOMException("This operation was aborted", "AbortError");
      return abort();
    });
    const repair = vi.fn(async () => undefined);
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T), installed(NOW)), statePath: await statePath(), nowMs: NOW,
    });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    for (const [, init] of fetchSpy.mock.calls) expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(repair).toHaveBeenCalledTimes(1);
    expect(result.outcome).toBe("updated");
    expect(result.databases.find((database) => database.id === "osv:PyPI")?.changed).toBe("unavailable");
    expect(result.package).toMatchObject({ newer: false });
    expect(result.package.note).toMatch(/could not check/i);
  });

  test("a prompt state that cannot be written after a successful refresh is a warning, not a failure", async () => {
    const directory = dirname(await statePath());
    const blocker = join(directory, "not-a-directory");
    await writeFile(blocker, "", "utf8");
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true,
      fetch: fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair: vi.fn(async () => undefined), io: quietIo,
      inspect: inspector(installed(T), installed(NOW)), statePath: join(blocker, "update-prompt.json"), nowMs: NOW,
    });
    expect(result.outcome).toBe("updated");
    expect(result.warning).toMatch(/could not record/i);
    expect(result.message).toMatch(/could not record/i);
  });

  test("counts OSV records changed since the download, refreshes through repairEngines and records success", async () => {
    const path = await statePath();
    const fetchSpy = fakeFetch({ [PYPI_CSV]: () => new Response(CSV, { status: 200 }), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) });
    const repair = vi.fn(async () => undefined);
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T), installed(NOW)), statePath: path, nowMs: NOW,
    });
    expect(repair).toHaveBeenCalledTimes(1);
    expect(repair).toHaveBeenCalledWith(["trivy", "osv-scanner", "--refresh-db", "--osv-ecosystems", "PyPI"], quietIo);
    expect(result.outcome).toBe("updated");
    expect(result.databases).toEqual([
      { id: "trivy-db", before: iso(T), after: iso(NOW) },
      { id: "osv:PyPI", before: iso(T), after: iso(NOW), changed: 3 },
    ]);
    for (const [, init] of fetchSpy.mock.calls) expect(init).toMatchObject({ redirect: "error" });
    const state = (await readUpdatePromptState(path)).state;
    expect(state?.last_update_at).toBe(iso(NOW));
    expect(state?.next_prompt_at).toBe(iso(NOW + DAY));
  });

  test("omits the parts that are not installed from the repair arguments", async () => {
    const fetchSpy = fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) });
    const repair = vi.fn(async () => undefined);
    await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T, ["PyPI"], false), installed(NOW, ["PyPI"], false)), statePath: await statePath(), nowMs: NOW,
    });
    expect(repair).toHaveBeenCalledWith(["osv-scanner", "--refresh-db", "--osv-ecosystems", "PyPI"], quietIo);

    const trivyOnly = vi.fn(async () => undefined);
    await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fakeFetch({ [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair: trivyOnly, io: quietIo, inspect: inspector(installed(T, []), installed(NOW, [])), statePath: await statePath(), nowMs: NOW,
    });
    expect(trivyOnly).toHaveBeenCalledWith(["trivy", "--refresh-db"], quietIo);
  });

  test("an unreadable change list gives changed=unavailable and the refresh still runs", async () => {
    const fetchSpy = fakeFetch({
      [PYPI_CSV]: () => new Response("nope", { status: 503, statusText: "Service Unavailable" }),
      [NPM_LATEST_URL]: npmLatest(SERVER_VERSION),
    });
    const repair = vi.fn(async () => undefined);
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T), installed(NOW)), statePath: await statePath(), nowMs: NOW,
    });
    expect(repair).toHaveBeenCalledTimes(1);
    expect(result.outcome).toBe("updated");
    expect(result.databases.find((database) => database.id === "osv:PyPI")?.changed).toBe("unavailable");
  });

  test("a change list over the 64 MiB limit is refused, not read", async () => {
    const fetchSpy = fakeFetch({
      [PYPI_CSV]: () => new Response(CSV, { headers: { "content-length": String(64 * 1024 * 1024 + 1) } }),
      [NPM_LATEST_URL]: npmLatest(SERVER_VERSION),
    });
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair: vi.fn(async () => undefined), io: quietIo,
      inspect: inspector(installed(T), installed(NOW)), statePath: await statePath(), nowMs: NOW,
    });
    expect(result.databases.find((database) => database.id === "osv:PyPI")?.changed).toBe("unavailable");
  });

  test("a failed refresh asks again in about an hour, reports failed and names the error", async () => {
    const path = await statePath();
    const before = { schema_version: 1 as const, next_prompt_at: iso(T + DAY), last_answer: "not_now" as const, answered_at: iso(T) };
    await writeUpdatePromptState(before, path);
    const fetchSpy = fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) });
    const repair = vi.fn(async () => {
      throw new Error("Trivy DB download failed (network unreachable)");
    });
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true, fetch: fetchSpy, repair, io: quietIo,
      inspect: inspector(installed(T)), statePath: path, nowMs: NOW,
    });
    expect(result.outcome).toBe("failed");
    expect(result.databases.every((database) => database.error?.includes("network unreachable"))).toBe(true);
    expect(result.databases.every((database) => database.after === iso(T))).toBe(true);
    expect(result.message).toMatch(/network unreachable/);
    expect(result.message).toContain("The previous databases were kept, and CodeInspectus will ask again in about an hour.");
    expect((await readUpdatePromptState(path)).state).toEqual({
      schema_version: 1, next_prompt_at: iso(NOW + HOUR), last_answer: "yes", answered_at: iso(NOW), last_update_outcome: "failed",
    });
    expect(before.next_prompt_at).not.toBe(iso(NOW + HOUR));
    // Nothing was refreshed, so the prompt is due again an hour later, not 24 hours later.
    expect(await databaseUpdatePrompt(installed(T), NOW + HOUR - 1, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(installed(T), NOW + HOUR, path)).toBeDefined();
  });

  test("a refresh that failed after some databases updated is partial and asks again in about an hour", async () => {
    const path = await statePath();
    const repair = vi.fn(async () => {
      throw new Error("OSV PyPI database download failed (500)");
    });
    const afterStatus = status({
      trivy_db: { state: "ready", downloaded_at: iso(NOW) },
      osv_databases: [{ ecosystem: "PyPI", state: "ready", downloaded_at: iso(T) }],
    });
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true,
      fetch: fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair, io: quietIo, inspect: inspector(installed(T), afterStatus), statePath: path, nowMs: NOW,
    });
    expect(result.outcome).toBe("partial");
    expect(result.databases.find((database) => database.id === "trivy-db")).toEqual({ id: "trivy-db", before: iso(T), after: iso(NOW) });
    expect(result.databases.find((database) => database.id === "osv:PyPI")?.error).toMatch(/500/);
    expect(result.message).toContain("CodeInspectus will ask again in about an hour.");
    expect((await readUpdatePromptState(path)).state).toMatchObject({ next_prompt_at: iso(NOW + HOUR), last_update_outcome: "partial" });
    // The Trivy DB was just refreshed, yet the PyPI database that failed brings the prompt back an hour later.
    expect(await databaseUpdatePrompt(afterStatus, NOW + HOUR - 1, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(afterStatus, NOW + HOUR, path)).toBeDefined();
  });

  test("a partial refresh of databases downloaded 2 hours ago names the real due time, not an hour", async () => {
    // Review case: the PyPI database that failed is only 2 hours old, so the prompt is due 22 hours from now.
    const path = await statePath();
    const twoHoursAgo = NOW - 2 * HOUR;
    const afterStatus = status({
      trivy_db: { state: "ready", downloaded_at: iso(NOW) },
      osv_databases: [{ ecosystem: "PyPI", state: "ready", downloaded_at: iso(twoHoursAgo) }],
    });
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true,
      fetch: fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair: vi.fn(async () => { throw new Error("OSV PyPI database download failed (500)"); }),
      io: quietIo, inspect: inspector(installed(twoHoursAgo), afterStatus), statePath: path, nowMs: NOW,
    });
    expect(result.outcome).toBe("partial");
    expect(result.message).toContain("CodeInspectus will ask again in about 22 hours.");
    expect(result.message).not.toContain("about an hour");
    expect(await databaseUpdatePrompt(afterStatus, NOW + 22 * HOUR - 1, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(afterStatus, NOW + 22 * HOUR, path)).toBeDefined();
  });

  test("a refresh that throws after every download time moved is partial, with no per-database error, and no early prompt", async () => {
    const path = await statePath();
    const repair = vi.fn(async () => {
      throw new Error("Repair finished but preflight is still repair_required");
    });
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true,
      fetch: fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) }),
      repair, io: quietIo, inspect: inspector(installed(T), installed(NOW)), statePath: path, nowMs: NOW,
    });
    expect(result.outcome).toBe("partial");
    expect(result.databases.every((database) => database.error === undefined && database.after === iso(NOW))).toBe(true);
    expect(result.message).toContain(
      "Updated trivy-db, osv:PyPI (3 changed record(s)), but the refresh then reported an error " +
      "(Repair finished but preflight is still repair_required).",
    );
    expect(result.message).not.toContain("about an hour");
    expect((await readUpdatePromptState(path)).state).toMatchObject({ next_prompt_at: iso(NOW + HOUR), last_update_outcome: "partial" });
    // Every database is fresh, so the prompt still waits 24 hours after the refresh.
    expect(await databaseUpdatePrompt(installed(NOW), NOW + HOUR, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(installed(NOW), NOW + DAY, path)).toBeDefined();
  });

  test.each([
    ["9.9.9", true],
    [SERVER_VERSION, false],
    ["0.0.1", false],
  ])("npm latest %s reports newer=%s", async (latest, newer) => {
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true,
      fetch: fakeFetch({ [NPM_LATEST_URL]: npmLatest(latest) }), repair: vi.fn(async () => undefined), io: quietIo,
      inspect: inspector(installed(T, [])), statePath: await statePath(), nowMs: NOW,
    });
    expect(result.package.running).toBe(SERVER_VERSION);
    expect(result.package.latest).toBe(latest);
    expect(result.package.newer).toBe(newer);
    if (newer) {
      expect(result.package.note).toContain(`CodeInspectus ${latest} is available with newer Synvoya advisories and rules`);
      // The same guidance as init: npx may run a cached copy, so restarting the client is not enough.
      expect(result.package.note).toContain("`npx codeinspectus@latest init --update`");
      expect(result.package.note).not.toMatch(/restart/);
    }
    else expect(result.package.note).not.toContain("is available");
  });

  test("an unreachable npm registry is reported, never treated as a database failure", async () => {
    const result = await runDatabaseUpdate({
      confirmDownloads: true, confirmLargeDownloads: true,
      fetch: fakeFetch({ [NPM_LATEST_URL]: () => new Response("", { status: 404, statusText: "Not Found" }) }),
      repair: vi.fn(async () => undefined), io: quietIo,
      inspect: inspector(installed(T, []), installed(NOW, [])), statePath: await statePath(), nowMs: NOW,
    });
    expect(result.outcome).toBe("updated");
    expect(result.package).toMatchObject({ newer: false });
    expect(result.package.latest).toBeUndefined();
    expect(result.package.note).toMatch(/could not check/i);
  });
});

describe("codeinspectus update (CLI)", () => {
  function cliIo(tty: boolean, answers: string[] = []): UpdateCliIo & { out: string; err: string; questions: string[] } {
    const io = {
      stdinIsTTY: tty,
      out: "",
      err: "",
      questions: [] as string[],
      stdout(text: string) { io.out += text; },
      stderr(text: string) { io.err += text; },
      async question(prompt: string) { io.questions.push(prompt); return answers.shift() ?? ""; },
    };
    return io;
  }
  async function run(args: string[], io: UpdateCliIo, before: EngineSetupStatus, after: EngineSetupStatus = before) {
    const fetchSpy = fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) });
    const repair = vi.fn(async () => undefined);
    const code = await runUpdateCli(args, { io, fetch: fetchSpy, repair, inspect: inspector(before, after), statePath: await statePath(), nowMs: NOW });
    return { code, fetchSpy, repair };
  }

  test("non-TTY without --yes prints the plan, exits 2 and downloads nothing", async () => {
    const io = cliIo(false);
    const { code, fetchSpy, repair } = await run([], io, installed(T));
    expect(code).toBe(2);
    expect(io.out).toContain("trivy-db");
    expect(io.out).toContain("osv:PyPI");
    expect(io.err).toContain("Re-run with --yes to download.");
    expect(io.questions).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test("--yes does not imply large downloads: a large database without --large exits 2", async () => {
    const io = cliIo(false);
    const { code, fetchSpy, repair } = await run(["--yes"], io, installed(T, ["npm"]));
    expect(code).toBe(2);
    expect(io.err).toContain("--yes --large");
    expect(io.err).toContain("osv:npm");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test("--yes --large --json downloads and prints the result as JSON", async () => {
    const io = cliIo(false);
    const { code, repair } = await run(["--yes", "--large", "--json"], io, installed(T, ["npm"]), installed(NOW, ["npm"]));
    expect(code).toBe(0);
    expect(repair).toHaveBeenCalledWith(["trivy", "osv-scanner", "--refresh-db", "--osv-ecosystems", "npm"], expect.anything());
    const printed = JSON.parse(io.out);
    expect(printed.result.outcome).toBe("updated");
    expect(printed.plan.large_downloads).toEqual([
      { id: "trivy-db", approx_size: "133.5 MiB" },
      { id: "osv:npm", approx_size: "209.4 MiB" },
    ]);
  });

  test("on a TTY it asks first: no downloads nothing, yes updates", async () => {
    const declined = cliIo(true, ["n"]);
    const first = await run([], declined, installed(T));
    expect(first.code).toBe(0);
    expect(declined.questions).toEqual(["Download these updates? [y/N] "]);
    expect(first.fetchSpy).not.toHaveBeenCalled();
    expect(first.repair).not.toHaveBeenCalled();

    const accepted = cliIo(true, ["y", "y"]);
    const second = await run([], accepted, installed(T), installed(NOW));
    expect(second.code).toBe(0);
    expect(accepted.questions[1]).toContain("trivy-db");
    expect(second.repair).toHaveBeenCalledTimes(1);
    expect(accepted.out).toContain("Database update updated");
  });

  test("on a TTY, declining the large-download question downloads nothing and exits 0", async () => {
    const io = cliIo(true, ["y", "n"]);
    const { code, fetchSpy, repair } = await run([], io, installed(T, ["npm"]));
    expect(code).toBe(0);
    expect(io.questions).toHaveLength(2);
    expect(io.out).toContain("No update downloaded.");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test.each([[true], [false]])("--json without --yes (TTY %s) exits 2 with nothing on stdout and asks nothing", async (tty) => {
    const io = cliIo(tty, ["y", "y"]);
    const { code, fetchSpy, repair } = await run(["--json"], io, installed(T));
    expect(code).toBe(2);
    expect(io.out).toBe("");
    expect(io.err).toContain("--json needs --yes");
    expect(io.questions).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(repair).not.toHaveBeenCalled();
  });

  test("--json --yes without an approved large download prints exactly one JSON document", async () => {
    const io = cliIo(false);
    const { code, fetchSpy } = await run(["--json", "--yes"], io, installed(T));
    expect(code).toBe(2);
    expect(JSON.parse(io.out).plan.large_downloads.map((item: { id: string }) => item.id)).toEqual(["trivy-db"]);
    expect(io.err).toContain("--yes --large");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("a failed refresh exits 1", async () => {
    const io = cliIo(false);
    const fetchSpy = fakeFetch({ [PYPI_CSV]: () => new Response(CSV), [NPM_LATEST_URL]: npmLatest(SERVER_VERSION) });
    const code = await runUpdateCli(["--yes", "--large"], {
      io, fetch: fetchSpy, repair: vi.fn(async () => { throw new Error("offline"); }),
      inspect: inspector(installed(T)), statePath: await statePath(), nowMs: NOW,
    });
    expect(code).toBe(1);
    expect(io.out).toContain("offline");
  });

  test("unknown options exit 2 without a network call", async () => {
    const io = cliIo(false);
    const { code, fetchSpy } = await run(["--force"], io, installed(T));
    expect(code).toBe(2);
    expect(io.err).toContain("--force");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
