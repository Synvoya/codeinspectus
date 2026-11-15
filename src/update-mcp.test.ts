/**
 * The 24-hour database update prompt over MCP: scan, rescan and list_rules carry `database_update` when it is
 * due, computing it never touches the network, and setup's update/snooze actions act only on an explicit call.
 * Every state path, the clock, fetch and repair are injected; nothing here reaches ~/.codeinspectus or the network.
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { createServer } from "./server.js";
import type { EngineSetupStatus } from "./types.js";
import { writeUpdatePromptState } from "./update-prompt.js";
import { NPM_LATEST_URL } from "./update.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const NOW = Date.parse("2026-11-10T12:00:00.000Z");
const iso = (ms: number): string => new Date(ms).toISOString();

function status(ecosystems: Array<"npm" | "PyPI"> = ["PyPI"], downloadedAt = NOW - 3 * DAY): EngineSetupStatus {
  return {
    state: "ready",
    platform: "test",
    engines: [
      { engine: "trivy", version: "test", state: "ready" },
      { engine: "osv-scanner", version: "test", state: "ready" },
    ],
    trivy_db: { state: "ready", downloaded_at: iso(downloadedAt) },
    osv_databases: ecosystems.map((ecosystem) => ({ ecosystem, state: "ready" as const, downloaded_at: iso(downloadedAt) })),
    network_required: false,
  };
}

interface Harness {
  client: Client;
  root: string;
  statePath: string;
  injectedFetch: ReturnType<typeof vi.fn<typeof fetch>>;
  globalFetch: ReturnType<typeof vi.fn<typeof fetch>>;
  repair: ReturnType<typeof vi.fn>;
}

let harness: Harness | undefined;
let current: { before: EngineSetupStatus; after: EngineSetupStatus; calls: number; repairError?: string };

async function connect(): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "codeinspectus-update-mcp-"));
  await writeFile(join(root, "app.js"), "export const answer = 42;\n", "utf8");
  const statePath = join(root, "state", "update-prompt.json");
  const injectedFetch = vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    if (url === NPM_LATEST_URL) return new Response(JSON.stringify({ version: "0.0.1" }));
    if (url.endsWith("/modified_id.csv")) return new Response(`${iso(NOW - DAY)},PYSEC-1\n`);
    throw new Error(`unexpected fetch ${url}`);
  });
  const globalFetch = vi.fn<typeof fetch>(async () => {
    throw new Error("the network must not be used");
  });
  vi.stubGlobal("fetch", globalFetch);
  const repair = vi.fn(async () => {
    current.calls++;
    if (current.repairError) throw new Error(current.repairError);
  });
  const server = createServer({
    update: {
      statePath,
      now: () => NOW,
      fetch: injectedFetch,
      repair,
      inspect: async () => (current.calls > 0 ? current.after : current.before),
    },
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "update-mcp-test", version: "1.0.0" });
  await client.connect(clientTransport);
  return { client, root, statePath, injectedFetch, globalFetch, repair };
}

beforeEach(async () => {
  current = { before: status(), after: status(["PyPI"], NOW), calls: 0 };
  harness = await connect();
});
afterEach(async () => {
  await harness?.client.close();
  if (harness) await rm(harness.root, { recursive: true, force: true });
  harness = undefined;
  vi.unstubAllGlobals();
});

type Structured = Record<string, any>;
async function call(name: string, args: Record<string, unknown>): Promise<{ structured: Structured; text: string; isError: boolean }> {
  const result = await harness!.client.callTool({ name, arguments: args });
  const text = (result.content as Array<{ type: string; text?: string }>).map((item) => item.text ?? "").join("\n");
  return { structured: (result.structuredContent ?? {}) as Structured, text, isError: result.isError === true };
}

/** Real scans over MCP: generous, so a loaded CI runner does not time them out. */
const SCAN_TEST_TIMEOUT_MS = 30_000;

const QUESTION_START = "Security databases were last updated 3 days ago. Check for updates and download them now?";

describe("database_update over MCP", { timeout: SCAN_TEST_TIMEOUT_MS }, () => {
  test("scan, rescan and list_rules carry a due prompt and make no network call", async () => {
    const scan = await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    expect(scan.isError).toBe(false);
    expect(scan.structured.database_update?.question).toMatch(new RegExp(`^${QUESTION_START}`));
    expect(scan.structured.database_update?.answers.map((answer: any) => answer.answer)).toEqual(["yes", "not_now", "not_for_a_week"]);
    expect(scan.text).toContain(QUESTION_START);

    const rescan = await call("codeinspectus_rescan", { path: harness!.root, scanners: ["ai"] });
    expect(rescan.isError).toBe(false);
    expect(rescan.structured.database_update?.due).toBe(true);

    const rules = await call("codeinspectus_list_rules", {});
    expect(rules.isError).toBe(false);
    expect(rules.structured.database_update?.due).toBe(true);

    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.globalFetch).not.toHaveBeenCalled();
    expect(harness!.repair).not.toHaveBeenCalled();
    // Showing the prompt never answers it.
    await expect(readFile(harness!.statePath, "utf8")).rejects.toThrow();
  });

  test("an invalid prompt state is named in the due notice's warning; the text is unchanged", async () => {
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: iso(NOW + HOUR) }, harness!.statePath);
    await writeFile(harness!.statePath, "{ not json", "utf8");
    const scan = await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    expect(scan.isError).toBe(false);
    expect(scan.structured.database_update?.warning).toMatch(/Ignored an invalid database update prompt state/);
    expect(scan.text).not.toContain("Ignored an invalid");
  });

  test("the initialize instructions tell the agent to get a separate yes for large downloads", () => {
    expect(harness!.client.getInstructions()).toContain(
      "If an update plan lists large downloads, get a separate yes for them before passing confirm_large_downloads=true.",
    );
  });

  test("no prompt when it is not due", async () => {
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: iso(NOW + HOUR) }, harness!.statePath);
    const scan = await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    expect(scan.structured.database_update).toBeUndefined();
    expect(scan.text).not.toContain("Security databases were last updated");
  });

  test("a dedicated rescan carries the prompt in its structured result and its text", async () => {
    await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    const rescan = await call("codeinspectus_rescan", { path: harness!.root, scanners: ["ai"] });
    expect(rescan.isError).toBe(false);
    expect(rescan.structured.prior_scan_id).toMatch(/^scan-/);
    expect(rescan.structured.database_update?.question).toMatch(new RegExp(`^${QUESTION_START}`));
    expect(rescan.text).toContain(QUESTION_START);
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.globalFetch).not.toHaveBeenCalled();
  });

  test("large databases are named in the question; the yes call never includes confirm_large_downloads", async () => {
    current.before = status(["npm"]);
    const scan = await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    expect(scan.structured.database_update?.large_downloads).toEqual([
      { id: "trivy-db", approx_size: "133.5 MiB" },
      { id: "osv:npm", approx_size: "209.4 MiB" },
    ]);
    expect(scan.structured.database_update?.question).toContain("This includes trivy-db (~133.5 MiB), osv:npm (~209.4 MiB), each over 100 MB.");
    expect(scan.structured.database_update?.answers[0].call).toBe('codeinspectus_setup with action="update" and confirm_downloads=true');
    expect(scan.text).not.toContain("confirm_large_downloads=true:");
    expect(scan.text).toContain("osv:npm");
  });

  test("the prompt's yes call with Trivy installed returns the plan naming the large download and asks for a separate yes", async () => {
    // The default status has the Trivy DB installed: a download over 100 MB.
    const scan = await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    expect(scan.structured.database_update?.answers[0].call).not.toContain("confirm_large_downloads");
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("planned");
    expect(update.structured.update).toBeUndefined();
    expect(update.structured.update_plan.large_downloads).toEqual([{ id: "trivy-db", approx_size: "133.5 MiB" }]);
    expect(update.structured.next_step).toMatch(/trivy-db \(~133\.5 MiB\)/);
    expect(update.structured.next_step).toMatch(/separate/);
    expect(update.structured.next_step).toContain("confirm_large_downloads=true");
    expect(update.structured.next_step).toContain(
      'If the user declines the large downloads, call codeinspectus_setup with action="update", confirm_downloads=true and ' +
      'skip_large_downloads=true to refresh only the smaller databases, or action="snooze".',
    );
    expect(update.text).toContain(update.structured.next_step);
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.globalFetch).not.toHaveBeenCalled();
    expect(harness!.repair).not.toHaveBeenCalled();
    await expect(readFile(harness!.statePath, "utf8")).rejects.toThrow();
  });

  test("setup snooze writes the state and silences the prompt for exactly that long", async () => {
    const snooze = await call("codeinspectus_setup", { action: "snooze", snooze: "not_for_a_week" });
    expect(snooze.isError).toBe(false);
    expect(snooze.structured.outcome).toBe("snoozed");
    const state = JSON.parse(await readFile(harness!.statePath, "utf8"));
    expect(state).toMatchObject({ schema_version: 1, next_prompt_at: iso(NOW + 7 * DAY), last_answer: "not_for_a_week" });
    const scan = await call("codeinspectus_scan", { path: harness!.root, scanners: ["ai"] });
    expect(scan.structured.database_update).toBeUndefined();
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
  });

  test("setup snooze without a snooze answer is an error and writes nothing", async () => {
    const snooze = await call("codeinspectus_setup", { action: "snooze" });
    expect(snooze.isError).toBe(true);
    expect(snooze.text).toMatch(/snooze/);
    await expect(readFile(harness!.statePath, "utf8")).rejects.toThrow();
  });

  test("setup update without confirm_downloads returns the offline plan and makes no network call", async () => {
    const update = await call("codeinspectus_setup", { action: "update" });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("planned");
    expect(update.structured.update_plan.databases.map((database: any) => database.id)).toEqual(["trivy-db", "osv:PyPI"]);
    expect(update.structured.update).toBeUndefined();
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.globalFetch).not.toHaveBeenCalled();
    expect(harness!.repair).not.toHaveBeenCalled();
  });

  test("a failed refresh is top-level update_failed with isError, and the prompt comes back in about an hour", async () => {
    current.repairError = "Trivy DB download failed (network unreachable)";
    current.after = current.before; // nothing was refreshed
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, confirm_large_downloads: true });
    expect(update.isError).toBe(true);
    expect(update.structured.outcome).toBe("update_failed");
    expect(update.structured.update.outcome).toBe("failed");
    expect(update.text).toContain("network unreachable");
    expect(update.text).toContain("ask again in about an hour");
    const state = JSON.parse(await readFile(harness!.statePath, "utf8"));
    expect(state).toMatchObject({ next_prompt_at: iso(NOW + HOUR), last_answer: "yes", last_update_outcome: "failed" });
  });

  test("a refresh that failed after some databases updated is top-level update_partial", async () => {
    current.repairError = "OSV PyPI database download failed (500)";
    current.after = { ...status(), trivy_db: { state: "ready", downloaded_at: iso(NOW) } };
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, confirm_large_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("update_partial");
    expect(update.structured.update.outcome).toBe("partial");
  });

  test("setup update with nothing to update returns the plan, not an update", async () => {
    current.before = { ...status([]), trivy_db: { state: "missing" } };
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, confirm_large_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("planned");
    expect(update.structured.update).toBeUndefined();
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.repair).not.toHaveBeenCalled();
  });

  test("setup update with a large database and no confirm_large_downloads returns the plan, before any network call", async () => {
    current.before = status(["npm"]);
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("planned");
    expect(update.structured.next_step).toContain("trivy-db (~133.5 MiB), osv:npm (~209.4 MiB)");
    expect(update.text).toContain("osv:npm");
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.repair).not.toHaveBeenCalled();
  });

  test("skip_large_downloads refreshes only the databases under 100 MB, and the prompt comes back like a partial update", async () => {
    // Before: Trivy DB (large) and PyPI, both 3 days old. After: only PyPI refreshed.
    current.after = { ...status(), osv_databases: [{ ecosystem: "PyPI", state: "ready", downloaded_at: iso(NOW) }] };
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, skip_large_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("updated");
    expect(harness!.repair).toHaveBeenCalledTimes(1);
    expect(harness!.repair).toHaveBeenCalledWith(["osv-scanner", "--refresh-db", "--osv-ecosystems", "PyPI"], expect.anything());
    expect(update.structured.update.databases.map((database: any) => database.id)).toEqual(["osv:PyPI"]);
    expect(update.structured.update.skipped).toEqual([{ id: "trivy-db", detail: expect.stringMatching(/over 100 MB/) }]);
    expect(update.text).toContain("ask again in about an hour");
    const state = JSON.parse(await readFile(harness!.statePath, "utf8"));
    expect(state).toMatchObject({ next_prompt_at: iso(NOW + HOUR), last_answer: "yes", last_update_outcome: "partial" });
    expect(harness!.globalFetch).not.toHaveBeenCalled();
  });

  test("skip_large_downloads with nothing over 100 MB is a plain update", async () => {
    current.before = { ...status(["PyPI"]), trivy_db: { state: "missing" } };
    current.after = { ...status(["PyPI"], NOW), trivy_db: { state: "missing" } };
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, skip_large_downloads: true });
    expect(update.structured.outcome).toBe("updated");
    const state = JSON.parse(await readFile(harness!.statePath, "utf8"));
    expect(state).toEqual({ schema_version: 1, next_prompt_at: iso(NOW + DAY), last_update_at: iso(NOW), last_answer: "yes", answered_at: iso(NOW) });
  });

  test("skip_large_downloads when every database is over 100 MB downloads nothing and returns the plan", async () => {
    current.before = status([]);
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, skip_large_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("planned");
    expect(update.structured.update).toBeUndefined();
    expect(update.text).toMatch(/over 100 MB/);
    expect(harness!.injectedFetch).not.toHaveBeenCalled();
    expect(harness!.repair).not.toHaveBeenCalled();
    await expect(readFile(harness!.statePath, "utf8")).rejects.toThrow();
  });

  test("setup update with confirm_downloads refreshes through repair, reports, and moves the prompt 24 hours", async () => {
    const update = await call("codeinspectus_setup", { action: "update", confirm_downloads: true, confirm_large_downloads: true });
    expect(update.isError).toBe(false);
    expect(update.structured.outcome).toBe("updated");
    expect(update.structured.update.outcome).toBe("updated");
    expect(update.structured.update.databases.find((database: any) => database.id === "osv:PyPI").changed).toBe(1);
    expect(harness!.repair).toHaveBeenCalledWith(["trivy", "osv-scanner", "--refresh-db", "--osv-ecosystems", "PyPI"], expect.anything());
    expect(harness!.globalFetch).not.toHaveBeenCalled();
    const state = JSON.parse(await readFile(harness!.statePath, "utf8"));
    expect(state).toMatchObject({ next_prompt_at: iso(NOW + DAY), last_update_at: iso(NOW), last_answer: "yes" });
  });
});
