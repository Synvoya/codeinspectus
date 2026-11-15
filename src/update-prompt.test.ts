import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { SERVER_VERSION } from "./config.js";
import { loadSynvoyaDataset } from "./synvoya/dataset.js";
import type { EngineSetupStatus } from "./types.js";
import {
  databaseUpdatePrompt,
  largeDownloads,
  readUpdatePromptState,
  recordUpdateDone,
  snoozeUpdatePrompt,
  writeUpdatePromptState,
} from "./update-prompt.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const T = Date.parse("2026-11-01T00:00:00.000Z");

const directories: string[] = [];
async function statePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-update-prompt-"));
  directories.push(directory);
  return join(directory, "nested", "update-prompt.json");
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
const withTrivy = (downloadedAt: number): Partial<EngineSetupStatus> => ({
  trivy_db: { state: "ready", downloaded_at: new Date(downloadedAt).toISOString() },
});

/** The question; `large` is the sentence naming downloads over 100 MB (the Trivy DB alone by default). */
const QUESTION = (age: string, large = " This includes trivy-db (~133.5 MiB), each over 100 MB."): string =>
  `Security databases were last updated ${age} ago. Check for updates and download them now? CodeInspectus uses the ` +
  `network only after you say yes, only to public update sources, and never sends your code.${large}`;

describe("databaseUpdatePrompt", () => {
  test("no managed database installed: never a prompt, however old the state", async () => {
    const path = await statePath();
    expect(await databaseUpdatePrompt(status(), T + 365 * DAY, path)).toBeUndefined();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(T).toISOString() }, path);
    expect(await databaseUpdatePrompt(status(), T + DAY, path)).toBeUndefined();
  });

  test("without a state file: not due before 24 hours after the download, due at 24 hours", async () => {
    const path = await statePath();
    expect(await databaseUpdatePrompt(status(withTrivy(T)), T + DAY - 1, path)).toBeUndefined();
    const prompt = await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path);
    expect(prompt?.due).toBe(true);
    expect(prompt?.question).toBe(QUESTION("24 hours"));
    expect(prompt?.databases.map((database) => database.id)).toEqual(["trivy-db"]);
    expect(prompt?.databases[0]?.updated_at).toBe(new Date(T).toISOString());
  });

  test("the first prompt waits for the NEWEST download; the age names the OLDEST one", async () => {
    const path = await statePath();
    const current = status({
      ...withTrivy(T),
      osv_databases: [{ ecosystem: "PyPI", state: "ready", downloaded_at: new Date(T + 10 * HOUR).toISOString() }],
    });
    expect(await databaseUpdatePrompt(current, T + 34 * HOUR - 1, path)).toBeUndefined();
    const prompt = await databaseUpdatePrompt(current, T + 34 * HOUR, path);
    expect(prompt?.question).toBe(QUESTION("34 hours"));
    expect(prompt?.databases.map((database) => database.id)).toEqual(["trivy-db", "osv:PyPI"]);
  });

  test("ages are rounded to hours below two days and to days above", async () => {
    const path = await statePath();
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + 26 * HOUR, path))?.question).toBe(QUESTION("26 hours"));
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + 3 * DAY + 5 * HOUR, path))?.question).toBe(QUESTION("3 days"));
  });

  test("the state file decides when a prompt is due once it exists", async () => {
    const path = await statePath();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(T + 5 * DAY).toISOString() }, path);
    expect(await databaseUpdatePrompt(status(withTrivy(T)), T + 5 * DAY - 1, path)).toBeUndefined();
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + 5 * DAY, path))?.question).toBe(QUESTION("5 days"));
  });

  test("answers name the exact setup calls; large databases (Trivy DB, OSV npm) are named in the question, never pre-approved", async () => {
    const path = await statePath();
    const small = await databaseUpdatePrompt(status({
      osv_databases: [{ ecosystem: "PyPI", state: "ready", downloaded_at: new Date(T).toISOString() }],
    }), T + 2 * DAY, path);
    expect(small?.large_downloads).toEqual([]);
    expect(small?.answers).toEqual([
      { answer: "yes", call: 'codeinspectus_setup with action="update" and confirm_downloads=true' },
      { answer: "not_now", call: 'codeinspectus_setup with action="snooze" and snooze="not_now"' },
      { answer: "not_for_a_week", call: 'codeinspectus_setup with action="snooze" and snooze="not_for_a_week"' },
    ]);

    const large = await databaseUpdatePrompt(status({
      ...withTrivy(T),
      osv_databases: [
        { ecosystem: "npm", state: "ready", downloaded_at: new Date(T).toISOString() },
        { ecosystem: "PyPI", state: "ready", downloaded_at: new Date(T).toISOString() },
      ],
    }), T + 2 * DAY, path);
    expect(large?.large_downloads).toEqual([
      { id: "trivy-db", approx_size: "133.5 MiB" },
      { id: "osv:npm", approx_size: "209.4 MiB" },
    ]);
    // The yes covers the update; downloads over 100 MB get their own, separate yes (setup's update returns a plan first).
    expect(large?.answers[0]).toEqual({ answer: "yes", call: 'codeinspectus_setup with action="update" and confirm_downloads=true' });
    expect(large?.question).toBe(QUESTION("2 days", " This includes trivy-db (~133.5 MiB), osv:npm (~209.4 MiB), each over 100 MB."));
    expect(small?.question).toBe(QUESTION("2 days", ""));
  });

  test("package content versions come from the Synvoya dataset manifest and the package version", async () => {
    const loaded = await loadSynvoyaDataset();
    expect(loaded.ok).toBe(true);
    const prompt = await databaseUpdatePrompt(status(withTrivy(T)), T + 2 * DAY, await statePath());
    expect(prompt?.package_content).toEqual([
      { id: "synvoya", version: loaded.ok ? loaded.dataset.version : "unreachable" },
      { id: "opengrep-rules", version: SERVER_VERSION },
      { id: "gitleaks-rules", version: SERVER_VERSION },
    ]);
  });

  test("an invalid state file gives a warning and the due logic falls back to the download time", async () => {
    const path = await statePath();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(T).toISOString() }, path);
    await writeFile(path, "{ not json", "utf8");
    const read = await readUpdatePromptState(path);
    expect(read.state).toBeUndefined();
    expect(read.warning).toMatch(/invalid/i);
    expect(await databaseUpdatePrompt(status(withTrivy(T)), T + DAY - 1, path)).toBeUndefined();
    // The due notice says the state was ignored, so a user whose snooze "did nothing" can see why.
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path))?.warning).toBe(read.warning);

    // Schema-valid JSON with the wrong shape is invalid too.
    await writeFile(path, JSON.stringify({ schema_version: 2, next_prompt_at: "soon" }), "utf8");
    expect((await readUpdatePromptState(path)).warning).toMatch(/invalid/i);
  });

  test("a state path that is not a regular file is invalid, with a warning, and never read", async () => {
    const path = await statePath();
    await mkdir(path, { recursive: true });
    const read = await readUpdatePromptState(path);
    expect(read.state).toBeUndefined();
    expect(read.warning).toMatch(/not a regular file/);
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path))?.warning).toMatch(/not a regular file/);
  });

  test("a hand-edited far-future next_prompt_at cannot silence the prompt forever", async () => {
    const path = await statePath();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: "9999-01-01T00:00:00.000Z" }, path);
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path))?.warning).toMatch(/more than 7 days ahead/);
  });

  test("a valid or missing state file adds no warning", async () => {
    const path = await statePath();
    expect((await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path))?.warning).toBeUndefined();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(T).toISOString() }, path);
    const prompt = await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path);
    expect(prompt).toBeDefined();
    expect(prompt && "warning" in prompt).toBe(false);
  });

  test("a week's snooze survives a clock stepped back by less than an hour", async () => {
    const path = await statePath();
    const now = T + 3 * DAY;
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(now + 7 * DAY + 30 * 60 * 1000).toISOString() }, path);
    expect(await databaseUpdatePrompt(status(withTrivy(T)), now, path)).toBeUndefined();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(now + 7 * DAY + 2 * HOUR).toISOString() }, path);
    expect(await databaseUpdatePrompt(status(withTrivy(T)), now, path)).toBeDefined();
  });

  test("a state file over 64 KiB is invalid, with a warning", async () => {
    const path = await statePath();
    await mkdir(dirname(path), { recursive: true });
    const padded = JSON.stringify({ schema_version: 1, next_prompt_at: new Date(T + 5 * DAY).toISOString(), pad: "x".repeat(64 * 1024) });
    await writeFile(path, padded, "utf8");
    const read = await readUpdatePromptState(path);
    expect(read.state).toBeUndefined();
    expect(read.warning).toMatch(/64 KiB/);
    expect(await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path)).toBeDefined();
  });

  test("a database refreshed by other means after a snooze is not prompted for until 24 hours after that refresh", async () => {
    const path = await statePath();
    await snoozeUpdatePrompt("not_now", T + DAY, path); // asks again at T + 2 days
    const refreshed = status(withTrivy(T + 2 * DAY - 4 * HOUR)); // setup / repair-engines refreshed it meanwhile
    expect(await databaseUpdatePrompt(refreshed, T + 2 * DAY, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(refreshed, T + 3 * DAY - 4 * HOUR - 1, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(refreshed, T + 3 * DAY - 4 * HOUR, path)).toBeDefined();
  });

  test("a leftover state file never prompts for a freshly downloaded database", async () => {
    const path = await statePath();
    await writeUpdatePromptState({ schema_version: 1, next_prompt_at: new Date(T - 300 * DAY).toISOString(), last_answer: "yes" }, path);
    expect(await databaseUpdatePrompt(status(withTrivy(T)), T + HOUR, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(status(withTrivy(T)), T + DAY, path)).toBeDefined();
  });

  test("databases whose engine needs setup are left out; with none left there is no prompt", async () => {
    const path = await statePath();
    const brokenTrivy: EngineSetupStatus["engines"] = [
      { engine: "trivy", version: "test", state: "hash_mismatch" },
      { engine: "osv-scanner", version: "test", state: "ready" },
    ];
    expect(await databaseUpdatePrompt(status({ ...withTrivy(T), engines: brokenTrivy }), T + 3 * DAY, path)).toBeUndefined();
    const mixed = await databaseUpdatePrompt(status({
      ...withTrivy(T),
      engines: brokenTrivy,
      osv_databases: [{ ecosystem: "PyPI", state: "ready", downloaded_at: new Date(T).toISOString() }],
    }), T + 3 * DAY, path);
    expect(mixed?.databases.map((database) => database.id)).toEqual(["osv:PyPI"]);
    expect(mixed?.large_downloads).toEqual([]);
  });
});

describe("largeDownloads", () => {
  test("over 100 MB (decimal) is large; exactly 100 MB is not", () => {
    const database = (id: string, bytes: number) => ({ id, kind: "osv" as const, detail: "test", download_bytes: bytes });
    expect(largeDownloads([database("at", 100_000_000), database("over", 100_000_001)]).map((item) => item.id)).toEqual(["over"]);
  });
});

describe("prompt state writes", () => {
  test("not_now moves the prompt 24 hours, not_for_a_week exactly 7 days", async () => {
    const path = await statePath();
    const now = T + 3 * DAY;
    const later = await snoozeUpdatePrompt("not_now", now, path);
    expect(Date.parse(later.next_prompt_at)).toBe(now + DAY);
    expect(later.last_answer).toBe("not_now");
    expect(await databaseUpdatePrompt(status(withTrivy(T)), now + DAY - 1, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(status(withTrivy(T)), now + DAY, path)).toBeDefined();

    const week = await snoozeUpdatePrompt("not_for_a_week", now, path);
    expect(Date.parse(week.next_prompt_at)).toBe(now + 7 * DAY);
    expect(week.last_answer).toBe("not_for_a_week");
    expect(week.answered_at).toBe(new Date(now).toISOString());
    expect(await databaseUpdatePrompt(status(withTrivy(T)), now + 7 * DAY - 1, path)).toBeUndefined();
    expect(await databaseUpdatePrompt(status(withTrivy(T)), now + 7 * DAY, path)).toBeDefined();
  });

  test("a snooze keeps the last successful update time", async () => {
    const path = await statePath();
    await recordUpdateDone(T, path);
    const snoozed = await snoozeUpdatePrompt("not_now", T + 2 * DAY, path);
    expect(snoozed.last_update_at).toBe(new Date(T).toISOString());
  });

  test("recordUpdateDone stamps the update and asks again 24 hours later", async () => {
    const path = await statePath();
    const state = await recordUpdateDone(T, path);
    expect(state).toEqual({
      schema_version: 1,
      next_prompt_at: new Date(T + DAY).toISOString(),
      last_update_at: new Date(T).toISOString(),
      last_answer: "yes",
      answered_at: new Date(T).toISOString(),
    });
    expect((await readUpdatePromptState(path)).state).toEqual(state);
  });

  test.skipIf(process.platform === "win32")("the state file is written atomically with mode 0600", async () => {
    const path = await statePath();
    await recordUpdateDone(T, path);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(path, "utf8")).schema_version).toBe(1);
  });
});
