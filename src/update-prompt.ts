/**
 * The 24-hour database update prompt: when to ask, and what the question says.
 *
 * Everything here is offline: a small JSON state file under ~/.codeinspectus plus the engine status a scan
 * already computed. Nothing in this module touches the network; the update itself (src/update.ts) runs only
 * after the user says yes. CLI scans never call this module.
 */

import { randomUUID } from "node:crypto";
import { lstat, mkdir, open, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { z } from "zod";

import { MANAGED_ROOT, SERVER_VERSION } from "./config.js";
import { log } from "./logger.js";
import { approxSize } from "./osv/database.js";
import { OSV_DB_SIZE_ESTIMATES, type OsvEcosystem } from "./osv/ecosystems.js";
import { TRIVY_DB_ESTIMATED_DISK_BYTES } from "./setup.js";
import { loadSynvoyaDataset } from "./synvoya/dataset.js";
import type { EngineSetupStatus } from "./types.js";

export const UPDATE_PROMPT_STATE = join(MANAGED_ROOT, "update-prompt.json");

const HOUR_MS = 60 * 60 * 1000;
export const UPDATE_PROMPT_INTERVAL_MS = 24 * HOUR_MS;
export const UPDATE_SNOOZE_WEEK_MS = 7 * UPDATE_PROMPT_INTERVAL_MS;
/** After a partial or failed update the prompt comes back this soon. */
export const UPDATE_RETRY_MS = HOUR_MS;
/** A database whose download is over 100 MB (decimal, Ruling 3) needs a second yes. */
export const LARGE_DOWNLOAD_BYTES = 100_000_000;
/**
 * Compressed Trivy DB transfer: 133.8 MiB, measured 2026-11-14 from the ghcr.io/aquasecurity/trivy-db:2 OCI
 * manifest layer size; rounded up to 140 MB. An estimate only (the database grows); on disk it is far larger.
 */
export const TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE = 140_000_000;
/** The prompt state is a few hundred bytes; anything over this was not written by CodeInspectus. */
const MAX_STATE_BYTES = 64 * 1024;
/** Tolerance for a clock stepped back a little after a "not for a week" snooze. */
const CLOCK_TOLERANCE_MS = HOUR_MS;
export const ENGINE_NEEDS_SETUP = "engine needs setup first: run `npx codeinspectus setup` (or codeinspectus_setup with action=install)";

export type UpdateAnswer = "yes" | "not_now" | "not_for_a_week";

export interface UpdatePromptState {
  schema_version: 1;
  next_prompt_at: string;
  last_update_at?: string;
  last_answer?: UpdateAnswer;
  answered_at?: string;
  /** Set when the last yes ended partial or failed: the prompt then waits for the stale databases only. */
  last_update_outcome?: "partial" | "failed";
}

export interface DatabaseUpdatePrompt {
  due: true;
  question: string;
  databases: Array<{ id: string; updated_at?: string; detail: string }>;
  package_content: Array<{ id: "synvoya" | "opengrep-rules" | "gitleaks-rules"; version: string }>;
  large_downloads: Array<{ id: string; approx_size: string }>;
  answers: Array<{ answer: UpdateAnswer; call: string }>;
  /** Set when the prompt state file was ignored (unreadable, invalid or edited), so the due time fell back. */
  warning?: string;
}

/** One managed database that is installed on this machine. */
export interface InstalledDatabase {
  id: string;
  kind: "trivy" | "osv";
  ecosystem?: OsvEcosystem;
  updated_at?: string;
  detail: string;
  /** Estimated transfer size of a refresh. */
  download_bytes: number;
  /** Set when the engine that refreshes it is not ready: an update leaves it alone (it never repairs engines). */
  skip_reason?: string;
}

const timestamp = z.string().refine((value) => Number.isFinite(Date.parse(value)), "not a timestamp");
const stateSchema = z.object({
  schema_version: z.literal(1),
  next_prompt_at: timestamp,
  last_update_at: timestamp.optional(),
  last_answer: z.enum(["yes", "not_now", "not_for_a_week"]).optional(),
  answered_at: timestamp.optional(),
  last_update_outcome: z.enum(["partial", "failed"]).optional(),
});

/** The state file, or undefined plus a warning when it is unreadable or invalid (then it counts as missing). */
export async function readUpdatePromptState(
  path: string = UPDATE_PROMPT_STATE,
): Promise<{ state?: UpdatePromptState; warning?: string }> {
  let raw: string;
  try {
    // A directory, FIFO, device or symlink is never a state file CodeInspectus wrote, and opening a FIFO
    // would block the scan that reads it, so anything but a regular file is refused before it is opened.
    if (!(await lstat(path)).isFile()) {
      return { warning: `Ignored a database update prompt state at ${path} that is not a regular file; using the database download time instead.` };
    }
    const handle = await open(path, "r");
    try {
      if ((await handle.stat()).size > MAX_STATE_BYTES) {
        return { warning: `Ignored a database update prompt state over 64 KiB at ${path}; using the database download time instead.` };
      }
      raw = await handle.readFile("utf8");
    } finally {
      await handle.close().catch(() => undefined);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    return { warning: `Could not read the database update prompt state at ${path}; using the database download time instead.` };
  }
  try {
    const parsed = stateSchema.safeParse(JSON.parse(raw));
    if (parsed.success) return { state: parsed.data };
  } catch {
    // Not JSON: reported below like any other invalid file.
  }
  return { warning: `Ignored an invalid database update prompt state at ${path}; using the database download time instead.` };
}

/** Atomic write: a fresh temporary file (`wx`, 0600) renamed over the old one. */
export async function writeUpdatePromptState(state: UpdatePromptState, path: string = UPDATE_PROMPT_STATE): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

/** "Not now" asks again in 24 hours, "not for a week" in exactly 7 days. There is no "never". */
export async function snoozeUpdatePrompt(
  answer: "not_now" | "not_for_a_week",
  nowMs: number,
  path: string = UPDATE_PROMPT_STATE,
): Promise<UpdatePromptState> {
  const previous = (await readUpdatePromptState(path)).state;
  const state: UpdatePromptState = {
    schema_version: 1,
    next_prompt_at: new Date(nowMs + (answer === "not_now" ? UPDATE_PROMPT_INTERVAL_MS : UPDATE_SNOOZE_WEEK_MS)).toISOString(),
    ...(previous?.last_update_at ? { last_update_at: previous.last_update_at } : {}),
    last_answer: answer,
    answered_at: new Date(nowMs).toISOString(),
  };
  await writeUpdatePromptState(state, path);
  return state;
}

/** A successful update: ask again 24 hours from now. */
export async function recordUpdateDone(nowMs: number, path: string = UPDATE_PROMPT_STATE): Promise<UpdatePromptState> {
  const now = new Date(nowMs).toISOString();
  const state: UpdatePromptState = {
    schema_version: 1,
    next_prompt_at: new Date(nowMs + UPDATE_PROMPT_INTERVAL_MS).toISOString(),
    last_update_at: now,
    last_answer: "yes",
    answered_at: now,
  };
  await writeUpdatePromptState(state, path);
  return state;
}

/**
 * A partial or failed update: ask again in about an hour. The last successful update time is kept, and the
 * prompt then waits for the oldest database only, so one refreshed in the same run does not hold it back.
 */
export async function recordUpdateIncomplete(
  outcome: "partial" | "failed",
  nowMs: number,
  path: string = UPDATE_PROMPT_STATE,
): Promise<UpdatePromptState> {
  const previous = (await readUpdatePromptState(path)).state;
  const state: UpdatePromptState = {
    schema_version: 1,
    next_prompt_at: new Date(nowMs + UPDATE_RETRY_MS).toISOString(),
    ...(previous?.last_update_at ? { last_update_at: previous.last_update_at } : {}),
    last_answer: "yes",
    answered_at: new Date(nowMs).toISOString(),
    last_update_outcome: outcome,
  };
  await writeUpdatePromptState(state, path);
  return state;
}

function engineReady(status: EngineSetupStatus, engine: "trivy" | "osv-scanner"): boolean {
  return status.engines.some((item) => item.engine === engine && item.state === "ready");
}

/**
 * The managed databases installed on this machine, Trivy DB first, then OSV in allow-list order. A database
 * whose engine (Trivy, or osv-scanner for every OSV database) is not ready carries `skip_reason`.
 */
export function installedManagedDatabases(status: EngineSetupStatus): InstalledDatabase[] {
  const databases: InstalledDatabase[] = [];
  if (status.trivy_db.state !== "missing" && status.trivy_db.downloaded_at) {
    databases.push({
      id: "trivy-db",
      kind: "trivy",
      updated_at: status.trivy_db.downloaded_at,
      detail:
        `Trivy vulnerability database (~${approxSize(TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE)} download; ` +
        `~${approxSize(TRIVY_DB_ESTIMATED_DISK_BYTES)} on disk), refreshed through the pinned Trivy binary`,
      download_bytes: TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE,
      ...(engineReady(status, "trivy") ? {} : { skip_reason: ENGINE_NEEDS_SETUP }),
    });
  }
  const osvReady = engineReady(status, "osv-scanner");
  for (const database of status.osv_databases ?? []) {
    databases.push({
      id: `osv:${database.ecosystem}`,
      kind: "osv",
      ecosystem: database.ecosystem,
      ...(database.downloaded_at ? { updated_at: database.downloaded_at } : {}),
      detail:
        `OSV ${database.ecosystem} advisories, full export (~${approxSize(OSV_DB_SIZE_ESTIMATES[database.ecosystem])} download) ` +
        `from osv-vulnerabilities.storage.googleapis.com${database.downloaded_at ? "" : "; download time not recorded"}`,
      download_bytes: OSV_DB_SIZE_ESTIMATES[database.ecosystem],
      ...(osvReady ? {} : { skip_reason: ENGINE_NEEDS_SETUP }),
    });
  }
  return databases;
}

/** The installed databases an update refreshes: those whose engine is ready. */
export function updatableDatabases(status: EngineSetupStatus): InstalledDatabase[] {
  return installedManagedDatabases(status).filter((database) => !database.skip_reason);
}

/**
 * When the prompt is next due for these (updatable) databases and this state; undefined when none has a recorded
 * download. Normally 24 hours after the NEWEST download; after a partial or failed update, 24 hours after the
 * OLDEST one, so a database that failed brings the prompt back at next_prompt_at unless it was refreshed since.
 */
export function promptDueAt(databases: readonly InstalledDatabase[], state: UpdatePromptState | undefined): number | undefined {
  const downloaded = databases.map((database) => Date.parse(database.updated_at ?? "")).filter(Number.isFinite);
  if (!downloaded.length) return undefined;
  const anchor = state?.last_update_outcome ? Math.min(...downloaded) : Math.max(...downloaded);
  return Math.max(anchor + UPDATE_PROMPT_INTERVAL_MS, state ? Date.parse(state.next_prompt_at) : 0);
}

/** "in about an hour" up to 1 h 5 min ahead, else "in about N hours" (rounded). */
export function formatPromptDue(dueAt: number, nowMs: number): string {
  const ms = dueAt - nowMs;
  if (ms <= HOUR_MS + 5 * 60 * 1000) return "in about an hour";
  return `in about ${Math.round(ms / HOUR_MS)} hours`;
}

/** Databases whose download is over LARGE_DOWNLOAD_BYTES (estimated transfer sizes). */
export function largeDownloads(databases: readonly InstalledDatabase[]): Array<{ id: string; approx_size: string }> {
  return databases
    .filter((database) => database.download_bytes > LARGE_DOWNLOAD_BYTES)
    .map((database) => ({ id: database.id, approx_size: approxSize(database.download_bytes) }));
}

function formatAge(ms: number): string {
  const hours = Math.max(1, Math.round(ms / HOUR_MS));
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"}`;
  return `${Math.round(ms / UPDATE_PROMPT_INTERVAL_MS)} days`;
}

async function packageContent(): Promise<DatabaseUpdatePrompt["package_content"]> {
  const loaded = await loadSynvoyaDataset().catch(() => undefined);
  return [
    { id: "synvoya", version: loaded?.ok ? loaded.dataset.version : "unknown" },
    { id: "opengrep-rules", version: SERVER_VERSION },
    { id: "gitleaks-rules", version: SERVER_VERSION },
  ];
}

/** "trivy-db (~133.5 MiB), osv:npm (~209.4 MiB)". */
export function largeDownloadNames(large: ReadonlyArray<{ id: string; approx_size: string }>): string {
  return large.map((item) => `${item.id} (~${item.approx_size})`).join(", ");
}

/** The prompt as text for a tool result: the question, any large download, and the call for each answer. */
export function formatDatabaseUpdatePrompt(prompt: DatabaseUpdatePrompt): string {
  return [
    `Database update (ask the user before continuing): ${prompt.question}`,
    ...(prompt.large_downloads.length
      ? [`  Over 100 MB each (the update asks for a separate yes before these): ${largeDownloadNames(prompt.large_downloads)}.`]
      : []),
    ...prompt.answers.map((answer) => `  ${answer.answer}: ${answer.call}`),
  ].join("\n");
}

/**
 * The prompt when it is due, else undefined. Offline: one small file read (plus the bundled Synvoya manifest
 * when due). Due once both 24 hours have passed since the newest database download (so never on a fresh install,
 * nor right after setup or repair-engines refreshed one; after a partial or failed update, the oldest download)
 * and the state file's next_prompt_at has passed. Only
 * databases an update can refresh count: none installed, none whose engine is ready, or none with a recorded
 * download time means no prompt (setup handles installs, engine repairs and unrecorded databases).
 */
export async function databaseUpdatePrompt(
  status: EngineSetupStatus,
  nowMs: number,
  statePath: string = UPDATE_PROMPT_STATE,
): Promise<DatabaseUpdatePrompt | undefined> {
  const databases = updatableDatabases(status);
  if (promptDueAt(databases, undefined) === undefined) return undefined;

  const read = await readUpdatePromptState(statePath);
  let state = read.state;
  let warning = read.warning;
  // No answer moves the prompt more than 7 days ahead, so a later date was edited in and must not silence it.
  if (state && Date.parse(state.next_prompt_at) > nowMs + UPDATE_SNOOZE_WEEK_MS + CLOCK_TOLERANCE_MS) {
    warning = `Ignored a database update prompt date more than 7 days ahead in ${statePath}; using the database download time instead.`;
    state = undefined;
  }
  if (warning) log.warn(warning);
  const dueAt = promptDueAt(databases, state)!;
  if (nowMs < dueAt) return undefined;
  const downloaded = databases.map((database) => Date.parse(database.updated_at ?? "")).filter(Number.isFinite);

  const large = largeDownloads(databases);
  return {
    due: true,
    question:
      `Security databases were last updated ${formatAge(nowMs - Math.min(...downloaded))} ago. Check for updates and ` +
      "download them now? CodeInspectus uses the network only after you say yes, only to public update sources, and " +
      "never sends your code." +
      (large.length ? ` This includes ${largeDownloadNames(large)}, each over 100 MB.` : ""),
    databases: databases.map(({ id, updated_at, detail }) => ({ id, ...(updated_at ? { updated_at } : {}), detail })),
    package_content: await packageContent(),
    large_downloads: large,
    answers: [
      // Never pre-approves a download over 100 MB: setup's update then returns the plan and asks for a separate yes.
      { answer: "yes", call: 'codeinspectus_setup with action="update" and confirm_downloads=true' },
      { answer: "not_now", call: 'codeinspectus_setup with action="snooze" and snooze="not_now"' },
      { answer: "not_for_a_week", call: 'codeinspectus_setup with action="snooze" and snooze="not_for_a_week"' },
    ],
    ...(warning ? { warning } : {}),
  };
}
