/**
 * Database updates after the user said yes to the 24-hour prompt (or ran `codeinspectus update`).
 *
 * Network access happens only inside runDatabaseUpdate, only after confirmation, and only to public update
 * sources: the OSV bucket (change lists and full exports), the Trivy DB through the pinned Trivy binary, and
 * the npm registry's `codeinspectus/latest` document. No project data is ever sent. The refresh itself reuses
 * repairEngines, so a failed download keeps the old database exactly as repair always has.
 */

import { createInterface } from "node:readline/promises";
import { stdin as processStdin, stdout as processStdout } from "node:process";

import { SERVER_VERSION } from "./config.js";
import { inspectEngineSetup } from "./engine-health.js";
import { repairEngines, type InstallIo } from "./install.js";
import { approxSize, OSV_DB_BASE_URL } from "./osv/database.js";
import type { OsvEcosystem } from "./osv/ecosystems.js";
import { TRIVY_DB_ESTIMATED_DISK_BYTES } from "./setup.js";
import { compareVersions } from "./synvoya/versions.js";
import type { EngineSetupStatus } from "./types.js";
import {
  ENGINE_NEEDS_SETUP,
  installedManagedDatabases,
  largeDownloadNames,
  largeDownloads,
  LARGE_DOWNLOAD_BYTES,
  recordUpdateDone,
  recordUpdateIncomplete,
  formatPromptDue,
  promptDueAt,
  updatableDatabases,
  UPDATE_PROMPT_STATE,
} from "./update-prompt.js";

export const NPM_LATEST_URL = "https://registry.npmjs.org/codeinspectus/latest";
const MODIFIED_ID_LIMIT_BYTES = 64 * 1024 * 1024;
const NPM_LIMIT_BYTES = 1024 * 1024;
const FETCH_TIMEOUT_MS = 60_000;

export interface DatabaseUpdatePlan {
  databases: Array<{
    id: string;
    kind: "trivy" | "osv";
    ecosystem?: OsvEcosystem;
    updated_at?: string;
    /** Estimated download (transfer) size. */
    approx_size: string;
    /** On-disk estimate, labelled as such, where it differs a lot from the download (the Trivy DB). */
    on_disk?: string;
    large: boolean;
    source: string;
  }>;
  /** Installed databases an update leaves alone because their engine needs setup first. */
  skipped: Array<{ id: string; detail: string }>;
  large_downloads: Array<{ id: string; approx_size: string }>;
  package_check: { source: string; running: string };
  message: string;
}

export interface DatabaseUpdateResult {
  outcome: "updated" | "partial" | "failed";
  databases: Array<{ id: string; before?: string; after?: string; changed?: number | "unavailable"; error?: string }>;
  skipped: Array<{ id: string; detail: string }>;
  package: { running: string; latest?: string; newer: boolean; note: string };
  message: string;
  /** Set when the refresh succeeded but the prompt state could not be recorded. */
  warning?: string;
}

export interface DatabaseUpdateOptions {
  confirmDownloads: boolean;
  confirmLargeDownloads: boolean;
  fetch?: typeof fetch;
  repair?: typeof repairEngines;
  io: InstallIo;
  nowMs?: number;
  statePath?: string;
  /** Engine status before and after the refresh (default: the offline inspectEngineSetup). */
  inspect?: () => Promise<EngineSetupStatus>;
  /**
   * Database ids (`trivy-db`, `osv:<ecosystem>`) to leave alone, e.g. because `init --update` just refreshed them
   * while repairing their engine. They are neither downloaded nor counted for the large-download confirmation.
   */
  exclude?: readonly string[];
  /**
   * Refresh only the databases under 100 MB (the user declined the large ones). They are excluded like `exclude`,
   * reported in `skipped`, and the prompt then comes back as after a partial update.
   */
  skipLargeDownloads?: boolean;
}

function modifiedIdUrl(ecosystem: OsvEcosystem): string {
  return `${OSV_DB_BASE_URL}/${encodeURIComponent(ecosystem)}/modified_id.csv`;
}

/** Offline: what an update would download, with sizes, and which downloads need a second confirmation. */
export function planDatabaseUpdate(status: EngineSetupStatus): DatabaseUpdatePlan {
  const installed = installedManagedDatabases(status);
  const updatable = installed.filter((database) => !database.skip_reason);
  const databases = updatable.map((database): DatabaseUpdatePlan["databases"][number] => ({
    id: database.id,
    kind: database.kind,
    ...(database.ecosystem ? { ecosystem: database.ecosystem } : {}),
    ...(database.updated_at ? { updated_at: database.updated_at } : {}),
    approx_size: approxSize(database.download_bytes),
    ...(database.kind === "trivy" ? { on_disk: `~${approxSize(TRIVY_DB_ESTIMATED_DISK_BYTES)} on disk` } : {}),
    large: database.download_bytes > LARGE_DOWNLOAD_BYTES,
    source: database.ecosystem
      ? `${modifiedIdUrl(database.ecosystem)} (change count), then the full export`
      : "the pinned Trivy binary's vulnerability DB download",
  }));
  const skipped = installed.flatMap((database) => (database.skip_reason ? [{ id: database.id, detail: database.skip_reason }] : []));
  const large = largeDownloads(updatable);
  const skippedNote = skipped.length ? ` Skipped ${skipped.map((item) => item.id).join(", ")}: ${ENGINE_NEEDS_SETUP}.` : "";
  return {
    databases,
    skipped,
    large_downloads: large,
    package_check: { source: NPM_LATEST_URL, running: SERVER_VERSION },
    message: databases.length
      ? `Updating re-downloads ${databases.length} database(s) and checks npm for a newer CodeInspectus. ` +
        "Nothing is downloaded until the user approves (confirm_downloads=true)." +
        (large.length
          ? ` ${largeDownloadNames(large)} ${large.length > 1 ? "are" : "is"} over 100 MB and need${large.length > 1 ? "" : "s"} a separate yes ` +
            "(confirm_large_downloads=true)."
          : "")
        + skippedNote
      : skipped.length
        ? `Nothing to update now.${skippedNote}`
        : "No managed database is installed, so there is nothing to update. Use setup to install one.",
  };
}

/** GET with redirects refused and a hard size limit, counted as the body streams. */
async function fetchTextLimited(fetchImpl: typeof fetch, url: string, limit: number): Promise<string> {
  const response = await fetchImpl(url, { redirect: "error", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`${url} returned ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`);
  }
  const advertised = Number(response.headers.get("content-length"));
  if (Number.isSafeInteger(advertised) && advertised > limit) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`${url} is larger than the ${approxSize(limit)} limit`);
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > limit) {
      await reader.cancel().catch(() => undefined);
      throw new Error(`${url} is larger than the ${approxSize(limit)} limit`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Rows of an OSV `modified_id.csv` (`<modified ISO time>,<id>`) modified after `sinceMs`. */
function countModifiedSince(csv: string, sinceMs: number): number {
  let count = 0;
  for (const line of csv.split("\n")) {
    const comma = line.indexOf(",");
    if (comma <= 0) continue;
    const modified = Date.parse(line.slice(0, comma));
    if (Number.isFinite(modified) && modified > sinceMs) count++;
  }
  return count;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function checkPackage(fetchImpl: typeof fetch): Promise<DatabaseUpdateResult["package"]> {
  const running = SERVER_VERSION;
  try {
    const document = JSON.parse(await fetchTextLimited(fetchImpl, NPM_LATEST_URL, NPM_LIMIT_BYTES)) as { version?: unknown };
    const latest = typeof document.version === "string" ? document.version : undefined;
    const order = latest === undefined ? undefined : compareVersions("semver", latest, running);
    if (latest === undefined || order === undefined) throw new Error("the registry did not return a valid version");
    return order > 0
      ? {
          running,
          latest,
          newer: true,
          note: `CodeInspectus ${latest} is available with newer Synvoya advisories and rules (running ${running}). ` +
            "Update the package yourself (for example `npm install -g codeinspectus@latest`; with npx, run " +
            "`npx codeinspectus@latest init --update`, because npx may run a cached copy); CodeInspectus never updates itself.",
        }
      : { running, latest, newer: false, note: `CodeInspectus ${running} is current; its bundled Synvoya advisories and rules are the latest published.` };
  } catch (error) {
    return { running, newer: false, note: `Could not check the npm registry for a newer CodeInspectus (${errorMessage(error)}).` };
  }
}

function repairArguments(plan: DatabaseUpdatePlan): string[] {
  const trivy = plan.databases.some((database) => database.kind === "trivy");
  const ecosystems = plan.databases.flatMap((database) => (database.ecosystem ? [database.ecosystem] : []));
  if (!trivy && !ecosystems.length) return [];
  return [
    ...(trivy ? ["trivy"] : []),
    ...(ecosystems.length ? ["osv-scanner"] : []),
    "--refresh-db",
    ...(ecosystems.length ? ["--osv-ecosystems", ecosystems.join(",")] : []),
  ];
}

/**
 * Check for and download database updates. Network access: call only after the user said yes.
 * Refreshes databases only: one whose engine is not ready is skipped (setup repairs engines), so this never
 * downloads an engine binary. Throws without confirmDownloads, without confirmLargeDownloads when a database is
 * over 100 MB, and when nothing can be updated.
 * On success the prompt is moved 24 hours ahead; after a partial or failed refresh it comes back in about an hour.
 */
export async function runDatabaseUpdate(options: DatabaseUpdateOptions): Promise<DatabaseUpdateResult> {
  if (!options.confirmDownloads) {
    throw new Error("Download confirmation is required. Show the update plan, ask the user, then retry with confirm_downloads=true.");
  }
  const inspect = options.inspect ?? (() => inspectEngineSetup());
  const before = await inspect();
  const excluded = new Set(options.exclude ?? []);
  const fullPlan = planDatabaseUpdate(before);
  const skippedLarge = options.skipLargeDownloads ? fullPlan.large_downloads.filter((item) => !excluded.has(item.id)) : [];
  for (const item of skippedLarge) excluded.add(item.id);
  const plan: DatabaseUpdatePlan = excluded.size
    ? {
        ...fullPlan,
        databases: fullPlan.databases.filter((database) => !excluded.has(database.id)),
        skipped: [
          ...fullPlan.skipped,
          ...skippedLarge.map((item) => ({ id: item.id, detail: `~${item.approx_size}, over 100 MB and not approved; not downloaded` })),
        ],
        large_downloads: fullPlan.large_downloads.filter((item) => !excluded.has(item.id)),
      }
    : fullPlan;
  if (!plan.databases.length) {
    throw new Error(
      skippedLarge.length
        ? "Every database in this update is over 100 MB; skipping them leaves nothing to refresh."
        : excluded.size && fullPlan.databases.length ? "Nothing left to update: every database was just refreshed." : plan.message,
    );
  }
  if (plan.large_downloads.length && !options.confirmLargeDownloads) {
    throw new Error(
      `Large download confirmation is required for ${plan.large_downloads.map((item) => `${item.id} (~${item.approx_size})`).join(", ")}. ` +
      "Ask the user, then retry with confirm_large_downloads=true.",
    );
  }
  const fetchImpl = options.fetch ?? fetch;
  const nowMs = options.nowMs ?? Date.now();

  // 1. How many OSV records changed since each database was downloaded (best effort, never blocks the refresh).
  const changed = new Map<string, number | "unavailable">();
  for (const database of plan.databases) {
    if (!database.ecosystem) continue;
    const since = Date.parse(database.updated_at ?? "");
    try {
      if (!Number.isFinite(since)) throw new Error("the database's download time is not recorded");
      changed.set(database.id, countModifiedSince(
        await fetchTextLimited(fetchImpl, modifiedIdUrl(database.ecosystem), MODIFIED_ID_LIMIT_BYTES),
        since,
      ));
    } catch (error) {
      options.io.stderr(`Could not count changed OSV ${database.ecosystem} records: ${errorMessage(error)}`);
      changed.set(database.id, "unavailable");
    }
  }

  // 2. Refresh through the existing repair path (full exports; a failed download keeps the old database).
  const args = repairArguments(plan);
  let repairError: string | undefined;
  if (args.length) {
    try {
      await (options.repair ?? repairEngines)(args, options.io);
    } catch (error) {
      repairError = errorMessage(error);
      options.io.stderr(`Database update failed: ${repairError}`);
    }
  }
  const afterStatus = await inspect().catch(() => before);
  const after = installedManagedDatabases(afterStatus);
  const databases = plan.databases.map((database): DatabaseUpdateResult["databases"][number] => {
    const updatedAt = after.find((item) => item.id === database.id)?.updated_at;
    const refreshed = updatedAt !== undefined && updatedAt !== database.updated_at;
    return {
      id: database.id,
      ...(database.updated_at ? { before: database.updated_at } : {}),
      ...(updatedAt ? { after: updatedAt } : {}),
      ...(changed.has(database.id) ? { changed: changed.get(database.id) } : {}),
      ...(repairError && !refreshed ? { error: repairError } : {}),
    };
  });
  const outcome: DatabaseUpdateResult["outcome"] = !repairError
    ? "updated"
    : databases.some((database) => !database.error) ? "partial" : "failed";

  // 3. The npm package carries the Synvoya advisories and the Opengrep and Gitleaks rules: report, never install.
  const pkg = await checkPackage(fetchImpl);

  let warning: string | undefined;
  /** When the prompt asks again, as the prompt itself computes it ("" when the state could not be recorded). */
  let askAgain = "";
  // A refresh that left out declined large databases counts as done only when nothing was left out.
  const incomplete = outcome === "updated" && skippedLarge.length ? "partial" as const : outcome === "updated" ? undefined : outcome;
  if (!incomplete) {
    try {
      await recordUpdateDone(nowMs, options.statePath ?? UPDATE_PROMPT_STATE);
    } catch (error) {
      // The databases are updated either way; at worst the prompt comes back early.
      warning = `The databases were updated, but CodeInspectus could not record the update time (${errorMessage(error)}); it may ask again early.`;
      options.io.stderr(warning);
    }
  } else {
    try {
      const state = await recordUpdateIncomplete(incomplete, nowMs, options.statePath ?? UPDATE_PROMPT_STATE);
      const dueAt = promptDueAt(updatableDatabases(afterStatus), state);
      if (dueAt !== undefined) askAgain = ` ${formatPromptDue(dueAt, nowMs)}`;
    } catch (error) {
      // The old prompt state stays; the prompt is still due by the old databases' download times.
      options.io.stderr(`Could not record the failed update time (${errorMessage(error)}).`);
    }
  }

  const updated = databases.filter((database) => !database.error).map((database) =>
    typeof database.changed === "number" ? `${database.id} (${database.changed} changed record(s))` : database.id);
  const failedIds = databases.filter((database) => database.error).map((database) => database.id);
  const summary = outcome === "updated"
    ? `Updated ${updated.join(", ")}.`
    : !failedIds.length
      ? `Updated ${updated.join(", ")}, but the refresh then reported an error (${repairError}).`
      : `${outcome === "partial" ? `Updated ${updated.join(", ")}; failed` : "Update failed"}: ` +
      `${databases.filter((database) => database.error).map((database) => database.id).join(", ")} (${repairError}). ` +
      `The previous databases were kept, and CodeInspectus will ask again${askAgain}.`;
  const needsSetup = plan.skipped.filter((item) => !skippedLarge.some((large) => large.id === item.id));
  const skippedNote = (needsSetup.length ? ` Skipped ${needsSetup.map((item) => item.id).join(", ")}: ${ENGINE_NEEDS_SETUP}.` : "") +
    (skippedLarge.length
      ? ` Skipped ${largeDownloadNames(skippedLarge)}: over 100 MB and not approved. CodeInspectus will ask again${askAgain}.`
      : "");
  return {
    outcome,
    databases,
    skipped: plan.skipped,
    package: pkg,
    message: `${summary}${skippedNote}${warning ? ` ${warning}` : ""} ${pkg.note}`,
    ...(warning ? { warning } : {}),
  };
}

/** The offline plan as text (CLI and the setup tool's text block). */
export function formatDatabaseUpdatePlan(plan: DatabaseUpdatePlan): string {
  return [
    plan.message,
    ...plan.databases.map((database) =>
      `  ${database.id}: ~${database.approx_size} download${database.large ? " (large)" : ""}${database.on_disk ? ` (${database.on_disk})` : ""}; ` +
      `last updated ${database.updated_at ?? "unknown"}; ${database.source}`),
    ...plan.skipped.map((item) => `  ${item.id}: skipped; ${item.detail}`),
    `  package check: ${plan.package_check.source} (running ${plan.package_check.running})`,
  ].join("\n");
}

export function formatDatabaseUpdateResult(result: DatabaseUpdateResult): string {
  return [
    `Database update ${result.outcome}. ${result.message}`,
    ...result.databases.map((database) =>
      `  ${database.id}: ${database.before ?? "unknown"} -> ${database.after ?? "unknown"}` +
      `${database.changed === undefined ? "" : `; changed records: ${database.changed}`}${database.error ? `; error: ${database.error}` : ""}`),
  ].join("\n");
}

export interface UpdateCliIo {
  stdinIsTTY: boolean;
  stdout(text: string): void;
  stderr(text: string): void;
  question(prompt: string): Promise<string>;
}

export function updateHelp(): string {
  return [
    "Usage: codeinspectus update [--yes] [--large] [--json]",
    "",
    "  (no option)   Show what would be downloaded, then ask before downloading (terminal only).",
    "  --yes         Download without asking. Needed when stdin is not a terminal.",
    "  --large       Also approve databases over 100 MB (the Trivy DB, about 140 MB; the OSV npm export, about 220 MB).",
    "                --yes alone never does.",
    "  --json        Print the plan and result as one JSON document (needs --yes; never asks).",
    "",
    "Re-downloads the installed Trivy DB and OSV databases from their public sources and checks the npm registry",
    "for a newer CodeInspectus (never installs it). Nothing about your code is sent. Scans never update.",
    "",
  ].join("\n");
}

function defaultUpdateIo(): UpdateCliIo {
  return {
    stdinIsTTY: Boolean(process.stdin.isTTY && process.stdout.isTTY),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    question: async (prompt) => {
      const readline = createInterface({ input: processStdin, output: processStdout });
      try {
        return await readline.question(prompt);
      } finally {
        readline.close();
      }
    },
  };
}

/** `codeinspectus update`: plan, ask (or --yes), then update. Exit 0 updated or declined, 1 partial/failed, 2 not approved. */
export async function runUpdateCli(
  args: readonly string[],
  options: Omit<DatabaseUpdateOptions, "confirmDownloads" | "confirmLargeDownloads" | "io"> & { io?: UpdateCliIo } = {},
): Promise<number> {
  const io = options.io ?? defaultUpdateIo();
  try {
    if (args.includes("--help") || args.includes("-h")) {
      io.stdout(updateHelp());
      return 0;
    }
    const known = new Set(["--yes", "--large", "--json"]);
    const unknown = args.find((arg) => !known.has(arg));
    if (unknown) throw new Error(`Unknown update option: ${unknown}. See \`codeinspectus update --help\`.`);
    const json = args.includes("--json");
    let yes = args.includes("--yes");
    let large = yes && args.includes("--large");
    // JSON mode never asks: stdout must hold exactly one JSON document, and a question would break that.
    if (json && !yes) {
      io.stderr("--json needs --yes (and --large for databases over 100 MB); run without --json to review the plan and be asked.\n");
      return 2;
    }

    const status = await (options.inspect ?? (() => inspectEngineSetup()))();
    const plan = planDatabaseUpdate(status);
    const print = (value: object, text: string): void => io.stdout(json ? `${JSON.stringify(value, null, 2)}\n` : `${text}\n`);
    if (!plan.databases.length) {
      print({ plan }, plan.message);
      return 0;
    }
    if (!json) io.stdout(`${formatDatabaseUpdatePlan(plan)}\n`);
    if (!yes) {
      if (!io.stdinIsTTY) {
        io.stderr("Re-run with --yes to download.\n");
        return 2;
      }
      const answer = (await io.question("Download these updates? [y/N] ")).trim().toLowerCase();
      if (answer !== "y" && answer !== "yes") {
        io.stdout("No update downloaded.\n");
        return 0;
      }
      yes = true;
      if (plan.large_downloads.length && !args.includes("--large")) {
        const names = plan.large_downloads.map((item) => `${item.id} (~${item.approx_size})`).join(", ");
        const second = (await io.question(`${names} is over 100 MB. Download it too? [y/N] `)).trim().toLowerCase();
        if (second !== "y" && second !== "yes") {
          io.stdout("No update downloaded.\n");
          return 0;
        }
        large = true;
      } else {
        large = true;
      }
    }
    if (plan.large_downloads.length && !large) {
      if (json) print({ plan }, "");
      io.stderr(
        `${plan.large_downloads.map((item) => `${item.id} (~${item.approx_size})`).join(", ")} is over 100 MB and was not approved. ` +
        "Re-run with --yes --large to download it.\n",
      );
      return 2;
    }
    // Progress goes to stderr under --json so stdout stays one JSON document.
    const progress: InstallIo = json
      ? { stdout: (text) => io.stderr(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) }
      : { stdout: (text) => io.stdout(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) };
    const result = await runDatabaseUpdate({ ...options, confirmDownloads: yes, confirmLargeDownloads: large, io: progress });
    print({ plan, result }, formatDatabaseUpdateResult(result));
    return result.outcome === "updated" ? 0 : 1;
  } catch (error) {
    io.stderr(`CodeInspectus update: ${errorMessage(error)}\n`);
    return 2;
  }
}
