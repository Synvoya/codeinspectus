/**
 * `codeinspectus init`: one command that registers CodeInspectus in the user's AI assistants and, after one
 * confirmation, downloads the four open-source engines and the OSV databases the current project needs.
 *
 * Nothing is written, run or downloaded before the yes (or `--yes`); `--dry-run` only prints the screen.
 * Engines install through installSetupComponents (cosign bootstrap, pins, preferences), never directly.
 * CLI only: the MCP server never imports this module.
 */

import { stat } from "node:fs/promises";
import { parse, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin as processStdin, stdout as processStdout } from "node:process";

import type { EngineName } from "../config.js";
import { loadLockfile } from "../engines/lockfile.js";
import { engineNeedsCosign, planEngineRepair, type InstallIo } from "../install.js";
import { approxSize } from "../osv/database.js";
import { OSV_DB_SIZE_ESTIMATES, type OsvEcosystem } from "../osv/ecosystems.js";
import {
  buildSetupPlan,
  installSetupComponents,
  SETUP_COMPONENTS,
  type SetupComponentId,
  type SetupPlan,
} from "../setup.js";
import { inspectEngineSetup } from "../engine-health.js";
import type { EngineSetupStatus } from "../types.js";
import { installedManagedDatabases, LARGE_DOWNLOAD_BYTES, TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE } from "../update-prompt.js";
import {
  formatDatabaseUpdatePlan,
  formatDatabaseUpdateResult,
  planDatabaseUpdate,
  runDatabaseUpdate,
  type DatabaseUpdatePlan,
  type DatabaseUpdateResult,
} from "../update.js";
import {
  applyRegistration,
  CLIENT_IDS,
  CLIENT_NAMES,
  detectClients,
  MANUAL_JSON_BLOCK,
  planRegistration,
  type ClientId,
  type InitEnv,
  type RegistrationOutcome,
  type RegistrationStep,
} from "./clients.js";
import { defaultInitEnv } from "./run.js";

export interface InitCliIo {
  stdinIsTTY: boolean;
  stdout(text: string): void;
  stderr(text: string): void;
  question(prompt: string): Promise<string>;
}

export interface InitCliOptions {
  io?: InitCliIo;
  env?: InitEnv;
  cwd?: string;
  buildPlan?: typeof buildSetupPlan;
  install?: typeof installSetupComponents;
  /** Offline engine status (default inspectEngineSetup). */
  inspect?: () => Promise<EngineSetupStatus>;
  /** `--update`: the M2 database refresh (default runDatabaseUpdate). */
  runUpdate?: typeof runDatabaseUpdate;
}

export interface InitPlan {
  clients: Array<RegistrationStep & { detected_by: string }>;
  /** Clients named in --clients that are not on this machine. */
  not_found: ClientId[];
  /** The setup plan for the engines (null with --skip-engines). */
  engines: SetupPlan | null;
  /** Components this plan installs (all four minus any that cannot run here). */
  engine_selection: SetupComponentId[];
  /** Project folder whose lockfiles choose the OSV databases. */
  target?: string;
  /** The engine install also downloads the Trivy DB. */
  trivy_db_download: boolean;
  /** Single downloads over 100 MB: a terminal asks about them separately; `--yes` needs `--large`. */
  large_downloads: LargeDownload[];
  estimated_download_bytes: number;
  manual_json: string;
}

export interface LargeDownload {
  id: string;
  approx_size: string;
}

export interface InitResult {
  clients: RegistrationOutcome[];
  engines?: { outcome: "installed" | "failed" | "not_needed" | "skipped"; message: string };
}

export function initHelp(): string {
  return [
    "Usage: codeinspectus init [--yes] [--large] [--path <dir>] [--clients <list>] [--skip-engines] [--dry-run] [--json]",
    "",
    "Registers CodeInspectus in the AI assistants found on this machine (Claude Code, Codex, Cursor, VS Code,",
    "Windsurf, Cline), then downloads the four open-source engines (Opengrep, Gitleaks, Trivy, OSV-Scanner) and the",
    "OSV databases your project needs. One screen shows every change first; nothing happens before you say yes.",
    "",
    "  --yes                Set everything up without asking. Needed when stdin is not a terminal.",
    "  --large              With --yes, also approve single downloads over 100 MB: the Cosign verifier (about 140-200 MB",
    "                       depending on platform) and the Trivy DB (about 140 MB) on a first install, and the OSV npm",
    "                       export (about 220 MB).",
    "                       On a terminal a second question asks about them; a no installs everything else.",
    "  --path <dir>         Project whose lockfiles choose the OSV databases (default: the current folder unless it",
    "                       is your home folder or the filesystem root).",
    "  --clients <list>     Only these assistants: claude,codex,cursor,vscode,windsurf,cline.",
    "  --skip-engines       Register the assistants only; download nothing.",
    "  --dry-run            Print the screen and change nothing.",
    "  --json               Print the plan and result as one JSON document (needs --yes or --dry-run; never asks).",
    "  --update             Refresh installed engines and databases after a release (see `init --update --help`).",
    "",
    "Config files are merged, never replaced: a file that is not plain JSON (comments, trailing commas) is left",
    "alone and the manual step is printed; an existing different `codeinspectus` entry is left alone; the first",
    "change to a file keeps a copy at <file>.codeinspectus-backup.",
    "",
  ].join("\n");
}

function defaultIo(): InitCliIo {
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class UsageError extends Error {}

interface ParsedArgs {
  yes: boolean;
  dryRun: boolean;
  json: boolean;
  skipEngines: boolean;
  update: boolean;
  large: boolean;
  help: boolean;
  path?: string;
  clients?: ClientId[];
}

function parseArgs(args: readonly string[]): ParsedArgs {
  const parsed: ParsedArgs = { yes: false, dryRun: false, json: false, skipEngines: false, update: false, large: false, help: false };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    switch (arg) {
      case "--yes": parsed.yes = true; break;
      case "--dry-run": parsed.dryRun = true; break;
      case "--json": parsed.json = true; break;
      case "--skip-engines": parsed.skipEngines = true; break;
      case "--update": parsed.update = true; break;
      case "--large": parsed.large = true; break;
      case "--help": case "-h": parsed.help = true; break;
      case "--path":
      case "--clients": {
        const value = args[index + 1];
        if (!value || value.startsWith("--")) throw new UsageError(`${arg} needs a value.`);
        index++;
        if (arg === "--path") {
          parsed.path = value;
        } else {
          const names = [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
          const unknown = names.find((name) => !(CLIENT_IDS as readonly string[]).includes(name));
          if (unknown || !names.length) throw new UsageError(`Unknown client: ${unknown ?? value}. Choose from ${CLIENT_IDS.join(",")}.`);
          parsed.clients = names as ClientId[];
        }
        break;
      }
      default:
        throw new UsageError(`Unknown init option: ${arg}. See \`codeinspectus init --help\`.`);
    }
  }
  return parsed;
}

/** The folder whose lockfiles choose OSV databases: `--path`, else the current folder unless it is home or a root. */
function projectTarget(cwd: string, home: string): string | undefined {
  const folder = resolve(cwd);
  if (folder === resolve(home) || folder === parse(folder).root) return undefined;
  return folder;
}

function engineWork(plan: SetupPlan, selection: readonly SetupComponentId[]): boolean {
  return plan.components.some((item) => selection.includes(item.id) && item.action !== "none" && item.action !== "blocked") ||
    plan.osv_databases.some((database) => database.selected && database.state !== "installed");
}

interface EngineDownloads {
  trivy_db: boolean;
  osv_ecosystems: OsvEcosystem[];
  large: LargeDownload[];
}

/**
 * What installSetupComponents(selection, true, { plan }) will download: the engine binaries and verifier the plan
 * names, plus the databases its repair fetches (the OSV list mirrors installSetupComponents, and planEngineRepair
 * decides the Trivy DB and OSV refreshes exactly as repair will). Every single download over 100 MB is listed.
 */
function engineDownloads(plan: SetupPlan, selection: readonly SetupComponentId[], status: EngineSetupStatus): EngineDownloads {
  if (!selection.length || !engineWork(plan, selection)) return { trivy_db: false, osv_ecosystems: [], large: [] };
  const offered = selection.includes("osv-scanner") ? plan.osv_databases.filter((database) => database.selected) : [];
  const pending = offered.filter((database) => database.state !== "installed");
  const list = (pending.length ? pending : offered).map((database) => database.ecosystem);
  const repair = planEngineRepair(status, [...selection] as EngineName[], false, list);
  const large: LargeDownload[] = [];
  const add = (id: string, bytes: number | undefined): void => {
    if (bytes !== undefined && bytes > LARGE_DOWNLOAD_BYTES) large.push({ id, approx_size: approxSize(bytes) });
  };
  for (const component of plan.components) {
    if (selection.includes(component.id) && (component.action === "download" || component.action === "redownload")) {
      add(component.id, component.download_size_bytes);
    }
  }
  if (plan.verifier.required && !plan.verifier.available) add("cosign", plan.verifier.download_size_bytes);
  if (repair.refresh_trivy_db) add("trivy-db", TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE);
  for (const ecosystem of repair.osv_ecosystems) add(`osv:${ecosystem}`, OSV_DB_SIZE_ESTIMATES[ecosystem]);
  return { trivy_db: repair.refresh_trivy_db, osv_ecosystems: repair.osv_ecosystems, large };
}

const OVER_100_MB = " (over 100 MB)";

function largeNames(large: readonly LargeDownload[]): string {
  return large.map((item) => `${item.id} (~${item.approx_size})`).join(", ");
}

/** "X is over 100 MB and was not approved" / "X, Y are over 100 MB and were not approved". */
function notApproved(large: readonly LargeDownload[]): string {
  return `${largeNames(large)} ${large.length > 1 ? "are over 100 MB and were" : "is over 100 MB and was"} not approved`;
}

export async function buildInitPlan(
  parsed: Pick<ParsedArgs, "clients" | "skipEngines" | "path">,
  env: InitEnv,
  cwd: string,
  buildPlan: typeof buildSetupPlan,
  inspect: () => Promise<EngineSetupStatus> = () => inspectEngineSetup(),
): Promise<InitPlan> {
  const detected = await detectClients(env);
  const wanted = parsed.clients ? detected.filter((client) => parsed.clients!.includes(client.id)) : detected;
  const notFound = (parsed.clients ?? []).filter((id) => !detected.some((client) => client.id === id));
  // Attached in place, not copied: apply finds the text each file step planned on by the step object itself.
  const clients = await Promise.all(wanted.map(async (client) => Object.assign(await planRegistration(client), { detected_by: client.detected_by })));

  let engines: InitEngines | undefined;
  let target: string | undefined;
  if (!parsed.skipEngines) {
    target = parsed.path ? resolve(cwd, parsed.path) : projectTarget(cwd, env.home);
    engines = await planInitEngines(await inspect(), target, buildPlan);
  }
  const downloads = engines?.downloads ?? { trivy_db: false, osv_ecosystems: [], large: [] };
  const estimated = engines
    ? engines.plan.exact_download_bytes + engines.plan.estimated_osv_download_bytes + (downloads.trivy_db ? TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE : 0)
    : 0;
  return {
    clients,
    not_found: notFound,
    engines: engines?.plan ?? null,
    engine_selection: engines?.selection ?? [],
    ...(target ? { target } : {}),
    trivy_db_download: downloads.trivy_db,
    large_downloads: downloads.large,
    estimated_download_bytes: estimated,
    manual_json: MANUAL_JSON_BLOCK,
  };
}

interface InitEngines {
  plan: SetupPlan;
  selection: SetupComponentId[];
  downloads: EngineDownloads;
  /** With withoutLarge: each engine left out although its own binary is not the problem, and why. */
  skipped: Array<{ id: SetupComponentId; reason: SkipReason }>;
}

type SkipReason = "large" | "cosign" | "trivy-db" | "osv" | "other";

const SKIP_REASONS: Record<SkipReason, [one: string, several: string]> = {
  large: ["which is over 100 MB", "which are over 100 MB"],
  cosign: ["which needs the Cosign verifier", "which need the Cosign verifier"],
  "trivy-db": ["which needs the Trivy DB", "which need the Trivy DB"],
  osv: ["which has no other OSV database to download", "which have no other OSV database to download"],
  other: ["which needs a download over 100 MB", "which need a download over 100 MB"],
};

function andList(items: readonly string[]): string {
  return items.length > 1 ? `${items.slice(0, -1).join(", ")} and ${items.at(-1)}` : items.join("");
}

/** "Opengrep, Trivy and OSV-Scanner, which need the Cosign verifier; and …", or "" when no engine is skipped. */
function skippedEngines(plan: SetupPlan, skipped: InitEngines["skipped"]): string {
  const groups = (Object.keys(SKIP_REASONS) as SkipReason[]).flatMap((reason) => {
    const ids = SETUP_COMPONENTS.filter((id) => skipped.some((item) => item.id === id && item.reason === reason));
    if (!ids.length) return [];
    const names = ids.map((id) => plan.components.find((item) => item.id === id)?.name ?? id);
    return [`${andList(names)}, ${SKIP_REASONS[reason][names.length > 1 ? 1 : 0]}`];
  });
  return groups.join("; and ");
}

/**
 * The engine part of `init`: all four engines minus any that cannot run here. With `withoutLarge` (a no to the
 * second question) it also leaves out every single download over 100 MB and what needs it: an engine binary that
 * large, Trivy when its DB is, an OSV database (osv-scanner too when no other database is left), and the engines
 * verified with Cosign while the verifier itself is. The install then receives exactly this plan.
 */
async function planInitEngines(
  status: EngineSetupStatus,
  target: string | undefined,
  buildPlan: typeof buildSetupPlan,
  withoutLarge = false,
): Promise<InitEngines> {
  const planFor = (components: readonly SetupComponentId[], osvEcosystems?: OsvEcosystem[]) =>
    buildPlan({ status, selection: components, ...(target ? { target } : {}), ...(osvEcosystems ? { osvEcosystems } : {}) });
  const full = await planFor(SETUP_COMPONENTS);
  // A component that cannot run here (e.g. Opengrep on musl) is shown but not installed; the plan is rebuilt
  // for the rest so the install receives exactly the plan the user saw.
  const blockedComponents = full.components.filter((item) => item.action === "blocked");
  let selection = SETUP_COMPONENTS.filter((id) => !blockedComponents.some((item) => item.id === id));
  let osvEcosystems: OsvEcosystem[] | undefined;
  const rebuild = async (): Promise<SetupPlan> => {
    if (!selection.length || (selection.length === SETUP_COMPONENTS.length && !osvEcosystems)) return full;
    const rebuilt = await planFor(selection, osvEcosystems);
    return {
      ...rebuilt,
      components: rebuilt.components.map((item) => blockedComponents.find((other) => other.id === item.id) ?? item),
    };
  };
  let plan = await rebuild();
  let downloads = engineDownloads(plan, selection, status);
  const skipped: InitEngines["skipped"] = [];
  while (withoutLarge && downloads.large.length && selection.length) {
    const large = new Set(downloads.large.map((item) => item.id));
    const lockfile = large.has("cosign") ? await loadLockfile() : undefined;
    const before = `${selection.join(",")}|${osvEcosystems?.join(",") ?? ""}`;
    selection = selection.filter((id) => {
      const component = plan.components.find((item) => item.id === id);
      const fetchesBinary = component?.action === "download" || component?.action === "redownload";
      const reason: SkipReason | undefined = large.has(id)
        ? "large"
        : lockfile && fetchesBinary && engineNeedsCosign(lockfile, id)
          ? "cosign"
          : id === "trivy" && large.has("trivy-db") ? "trivy-db" : undefined;
      if (reason) skipped.push({ id, reason });
      return !reason;
    });
    if (selection.includes("osv-scanner") && [...large].some((id) => id.startsWith("osv:"))) {
      const kept = plan.osv_databases.filter((database) => database.selected && !large.has(`osv:${database.ecosystem}`));
      if (kept.length) osvEcosystems = kept.map((database) => database.ecosystem);
      else {
        selection = selection.filter((id) => id !== "osv-scanner");
        skipped.push({ id: "osv-scanner", reason: "osv" });
      }
    }
    // Nothing more could be left out: install nothing rather than a download that was not approved.
    if (`${selection.join(",")}|${osvEcosystems?.join(",") ?? ""}` === before) {
      for (const id of selection) skipped.push({ id, reason: "other" });
      selection = [];
    }
    plan = await rebuild();
    downloads = selection.length ? engineDownloads(plan, selection, status) : { trivy_db: false, osv_ecosystems: [], large: [] };
  }
  // An engine whose own download is one of the large items is already named in the list.
  return { plan, selection, downloads, skipped: skipped.filter((item) => item.reason !== "large") };
}

function componentLine(plan: SetupPlan, id: SetupComponentId, trivyDb: boolean, large: readonly LargeDownload[]): string {
  const component = plan.components.find((item) => item.id === id)!;
  const label = `${component.name} ${component.version}`;
  if (component.action === "blocked") return `  ${label}: not available here (${component.note ?? component.state})`;
  const isLarge = (key: string): string => (large.some((item) => item.id === key) ? OVER_100_MB : "");
  const size = component.download_size_bytes === undefined ? "size unavailable" : `${approxSize(component.download_size_bytes)}${isLarge(id)}`;
  const database = `the vulnerability DB (~${approxSize(TRIVY_DB_DOWNLOAD_BYTES_ESTIMATE)} download${isLarge("trivy-db")}, ` +
    `~${approxSize(component.estimated_database_disk_bytes ?? plan.estimated_database_disk_bytes)} on disk)`;
  let action: string;
  switch (component.action) {
    case "none": action = "already installed"; break;
    case "download": action = `download ${size}${trivyDb ? `, plus ${database}` : ""}`; break;
    case "redownload": action = `re-download ${size} (the installed copy does not match its pin)${trivyDb ? `, plus ${database}` : ""}`; break;
    case "refresh_database": action = id === "trivy" ? (trivyDb ? `refresh ${database}` : "no download") : "download the OSV databases below"; break;
    default: action = component.action;
  }
  return `  ${label}: ${action}; licence ${component.license}`;
}

export function formatInitPlan(plan: InitPlan): string {
  const lines = ["CodeInspectus init: everything below happens only after you say yes.", ""];
  lines.push("AI assistants (MCP server: npx -y codeinspectus)");
  if (!plan.clients.length && !plan.not_found.length) lines.push("  none found on this machine");
  for (const step of plan.clients) lines.push(`  ${step.name} (${step.detected_by}): ${step.detail}`);
  for (const id of plan.not_found) lines.push(`  ${CLIENT_NAMES[id]}: not found on this machine`);
  lines.push("  Any other assistant: add this to its MCP configuration by hand:");
  lines.push(...plan.manual_json.split("\n").map((line) => `    ${line}`));
  lines.push("");

  const engines = plan.engines;
  if (!engines) {
    lines.push("Engines: skipped (--skip-engines).");
  } else {
    lines.push("Engines (open source, verified against pinned hashes, installed under ~/.codeinspectus)");
    for (const id of SETUP_COMPONENTS) lines.push(componentLine(engines, id, plan.trivy_db_download, plan.large_downloads));
    lines.push(...verifierLines(engines, plan.large_downloads));
    if (engines.osv_databases.length) {
      lines.push(`OSV databases ${plan.target ? `for ${plan.target}` : "already installed"} (from osv-vulnerabilities.storage.googleapis.com)`);
      for (const database of engines.osv_databases) {
        const large = plan.large_downloads.some((item) => item.id === `osv:${database.ecosystem}`) ? OVER_100_MB : "";
        lines.push(`  ${database.ecosystem}: ${database.state}; ${database.state === "installed" || !database.selected
          ? "no download"
          : `~${approxSize(database.estimated_download_bytes)} download${large}`}`);
        if (database.note && database.state !== "installed") lines.push(`    ${database.note}`);
      }
    } else if (plan.target) {
      lines.push(`OSV databases: none needed for ${plan.target} (no supported lockfiles found).`);
    }
    if (!plan.target) {
      lines.push("No project folder here, so no new OSV database is offered. Run `npx codeinspectus init --path <repo>` to add the ones a project needs.");
    }
    for (const warning of engines.warnings) lines.push(`Warning: ${warning}`);
    lines.push(`Total download: about ${approxSize(plan.estimated_download_bytes)} (database sizes are estimates).`);
    if (plan.large_downloads.length) {
      lines.push(`Over 100 MB each: ${largeNames(plan.large_downloads)}. You are asked about them separately; with --yes, add --large.`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function verifierLines(plan: SetupPlan, large: readonly LargeDownload[]): string[] {
  if (!plan.verifier.required || plan.verifier.available) return [];
  const size = plan.verifier.download_size_bytes === undefined ? "size unavailable" : approxSize(plan.verifier.download_size_bytes);
  return [`  Cosign ${plan.verifier.version} verifier: download ${size}${large.some((item) => item.id === "cosign") ? OVER_100_MB : ""}; licence Apache-2.0`];
}

function hasWork(plan: InitPlan): boolean {
  return plan.clients.some((step) => step.status === "add") ||
    Boolean(plan.engines && engineWork(plan.engines, plan.engine_selection));
}

export function formatInitResult(result: InitResult): string {
  const lines = ["", "Summary"];
  for (const outcome of result.clients) {
    const label = outcome.outcome === "already" ? "already registered" : outcome.outcome;
    lines.push(`  ${outcome.name}: ${label} — ${outcome.detail}`);
  }
  if (result.engines) lines.push(`  Engines: ${result.engines.message}`);
  lines.push("", "Next: restart your assistant and ask it to run a security scan of your project.");
  return `${lines.join("\n")}\n`;
}

async function isDirectory(path: string): Promise<boolean> {
  return stat(path).then((info) => info.isDirectory(), () => false);
}

/** `codeinspectus init`. Exit 0 done, declined or nothing to do; 1 a client or the engine setup failed; 2 usage or not approved. */
export async function runInitCli(args: readonly string[], options: InitCliOptions = {}): Promise<number> {
  const io = options.io ?? defaultIo();
  try {
    const parsed = parseArgs(args);
    if (parsed.update) return await runInitUpdate(parsed, io, options);
    if (parsed.help) {
      io.stdout(initHelp());
      return 0;
    }
    // JSON mode never asks: stdout must hold exactly one JSON document, and a question would break that.
    if (parsed.json && !parsed.yes && !parsed.dryRun) {
      throw new UsageError("--json needs --yes (and --large for downloads over 100 MB), or --dry-run; run without --json to review the plan and be asked.");
    }
    const cwd = options.cwd ?? process.cwd();
    if (parsed.path && !(await isDirectory(resolve(cwd, parsed.path)))) throw new UsageError(`--path ${parsed.path} is not a directory.`);

    const env = options.env ?? defaultInitEnv();
    const plan = await buildInitPlan(parsed, env, cwd, options.buildPlan ?? buildSetupPlan, options.inspect);
    const print = (value: object, text: string): void => io.stdout(parsed.json ? `${JSON.stringify(value, null, 2)}\n` : text);

    if (parsed.dryRun) {
      print({ dry_run: true, plan }, `${formatInitPlan(plan)}\nDry run: nothing was changed.\n`);
      return 0;
    }
    if (!hasWork(plan)) {
      const manual = plan.clients.filter((step) => step.status === "unparseable" || step.status === "conflict").map((step) => step.name);
      print({ plan, result: { clients: [], engines: { outcome: "not_needed", message: "nothing to do" } } },
        `${formatInitPlan(plan)}\n${manual.length
          ? `Nothing to change or download automatically. ${manual.join(", ")}: see the step shown above.`
          : "Everything is already set up; nothing to change or download."}\n`);
      return 0;
    }
    if (!parsed.json) io.stdout(formatInitPlan(plan));
    // What the engine install receives: the plan shown, or that plan without the downloads over 100 MB.
    let engines = { plan: plan.engines, selection: plan.engine_selection };
    let leftOut: LargeDownload[] = [];
    let alsoSkipped = "";
    if (!parsed.yes) {
      if (!io.stdinIsTTY) {
        io.stderr("Re-run with --yes to set this up (or --dry-run to only look).\n");
        return 2;
      }
      io.stdout("\nTo narrow this, re-run with --clients claude,codex (any of claude,codex,cursor,vscode,windsurf,cline) or --skip-engines.\n");
      const answer = (await io.question("Set all of this up? [y/N] ")).trim().toLowerCase();
      if (answer !== "y" && answer !== "yes") {
        io.stdout("Nothing was changed.\n");
        return 0;
      }
      // The same rule as `update` and `init --update`: a download over 100 MB gets its own question.
      if (plan.large_downloads.length && !parsed.large) {
        // What a no installs (offline), so the question can name the engines a no also skips.
        const reduced = await planInitEngines(
          await (options.inspect ?? (() => inspectEngineSetup()))(),
          plan.target,
          options.buildPlan ?? buildSetupPlan,
          true,
        );
        alsoSkipped = skippedEngines(reduced.plan, reduced.skipped);
        const second = (await io.question(
          `These include downloads over 100 MB (${largeNames(plan.large_downloads)}). ` +
          `${alsoSkipped ? `A no also skips ${alsoSkipped}. ` : ""}Download them too? [y/N] `,
        )).trim().toLowerCase();
        if (second !== "y" && second !== "yes") {
          // A no installs everything else.
          engines = { plan: reduced.plan, selection: reduced.selection };
          leftOut = plan.large_downloads;
        }
      }
    } else if (plan.large_downloads.length && !parsed.large) {
      // The same rule as `update`: --yes alone never approves a single download over 100 MB.
      if (parsed.json) print({ plan }, "");
      io.stderr(`${notApproved(plan.large_downloads)}. Re-run with --yes --large to download ${plan.large_downloads.length > 1 ? "them" : "it"}. Nothing was changed.\n`);
      return 2;
    }

    // Progress goes to stderr under --json so stdout stays one JSON document.
    const progress: InstallIo = parsed.json
      ? { stdout: (text) => io.stderr(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) }
      : { stdout: (text) => io.stdout(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) };

    const clients: RegistrationOutcome[] = [];
    for (const step of plan.clients) clients.push(await applyRegistration(step, env));

    const result: InitResult = { clients };
    const leftOutNote = leftOut.length
      ? ` Left out (over 100 MB, not approved): ${largeNames(leftOut)}; run \`npx codeinspectus init\` again to add ${leftOut.length > 1 ? "them" : "it"}.` +
        (alsoSkipped ? ` Also skipped: ${alsoSkipped}.` : "")
      : "";
    if (!engines.plan) {
      result.engines = { outcome: "skipped", message: "skipped (--skip-engines)." };
    } else if (!engines.selection.length || !engineWork(engines.plan, engines.selection)) {
      result.engines = leftOut.length
        ? { outcome: "skipped", message: `nothing downloaded.${leftOutNote}` }
        : { outcome: "not_needed", message: "already installed; nothing downloaded." };
    } else {
      try {
        const installed = await (options.install ?? installSetupComponents)(engines.selection, true, {
          plan: engines.plan,
          io: progress,
          ...(plan.target ? { target: plan.target } : {}),
        });
        result.engines = { outcome: "installed", message: `${installed.message}${leftOutNote}` };
      } catch (error) {
        result.engines = { outcome: "failed", message: `Engine setup failed: ${errorMessage(error)}` };
        io.stderr(`${result.engines.message}\n`);
      }
    }
    print({ plan, result }, formatInitResult(result));
    const failed = clients.some((outcome) => outcome.outcome === "failed") || result.engines?.outcome === "failed";
    return failed ? 1 : 0;
  } catch (error) {
    io.stderr(`CodeInspectus init: ${errorMessage(error)}\n`);
    return 2;
  }
}

export interface InitUpdatePlan {
  /** Setup plan for the enabled components that need a new pin or a missing binary (null when none do). */
  engines: SetupPlan | null;
  engine_selection: SetupComponentId[];
  /** Components the user has enabled in setup (empty before any setup). */
  enabled: SetupComponentId[];
  /** Databases the engine repair itself downloads (Trivy DB, OSV ecosystems); the refresh then skips them. */
  engine_databases: { trivy_db: boolean; osv_ecosystems: OsvEcosystem[] };
  databases: DatabaseUpdatePlan;
  /** Every single download over 100 MB in this run (engine binaries, the verifier, and all databases). */
  large_downloads: LargeDownload[];
}

export function initUpdateHelp(): string {
  return [
    "Usage: codeinspectus init --update [--yes] [--large] [--dry-run] [--json]",
    "",
    "After a CodeInspectus release: downloads new engine pins or missing binaries for the engines you enabled in",
    "setup, then re-downloads your installed Trivy DB and OSV databases (the same refresh as `codeinspectus update`).",
    "One screen shows everything first; nothing is downloaded before you say yes.",
    "",
    "  --yes       Update without asking. Needed when stdin is not a terminal.",
    "  --large     Also approve downloads over 100 MB (the Trivy DB, about 140 MB; the OSV npm export, about 220 MB;",
    "              the Cosign verifier, about 140-200 MB depending on platform, when an engine repair needs it and",
    "              it is not installed yet).",
    "              --yes alone never does.",
    "  --dry-run   Print the screen and change nothing.",
    "  --json      Print the plan and result as one JSON document (needs --yes or --dry-run; never asks).",
    "",
    "npx may run a cached copy of CodeInspectus: run `npx codeinspectus@latest init --update` after a release.",
    "",
  ].join("\n");
}

/** What `init --update` would do. Offline. */
export async function buildInitUpdatePlan(
  buildPlan: typeof buildSetupPlan,
  inspect: () => Promise<EngineSetupStatus>,
): Promise<InitUpdatePlan> {
  // Without a setup preference file the user has enabled nothing yet: `init` (not --update) is the first step.
  const status = await inspect();
  const saved = await buildPlan({ status });
  const enabled = saved.preference_state === "configured"
    ? saved.components.filter((item) => item.selected && item.action !== "blocked").map((item) => item.id)
    : [];
  // Engines: only new pins and missing binaries. Databases are left to the M2 refresh below, so none is fetched twice.
  const selection = saved.components
    .filter((item) => enabled.includes(item.id) && (item.action === "download" || item.action === "redownload"))
    .map((item) => item.id);
  const engines = selection.length ? await buildPlan({ status, selection }) : null;
  // What the engine repair downloads itself (a missing or stale Trivy DB, OSV databases due a refresh) is shown
  // and gated for --large here; the database refresh afterwards skips whatever that repair refreshed.
  const downloads = engines ? engineDownloads(engines, selection, status) : { trivy_db: false, osv_ecosystems: [], large: [] };
  // A database whose engine this run repairs is refreshed too, so it is shown (and counted for --large) now.
  const repaired = new Set<string>(selection);
  const databases = planDatabaseUpdate({
    ...status,
    engines: status.engines.map((engine) => (repaired.has(engine.engine) ? { ...engine, state: "ready" as const } : engine)),
  });
  const large = [...downloads.large];
  for (const item of databases.large_downloads) if (!large.some((other) => other.id === item.id)) large.push(item);
  return {
    engines,
    engine_selection: selection,
    enabled,
    engine_databases: { trivy_db: downloads.trivy_db, osv_ecosystems: downloads.osv_ecosystems },
    databases,
    large_downloads: large,
  };
}

export function formatInitUpdatePlan(plan: InitUpdatePlan): string {
  const lines = ["CodeInspectus init --update: everything below happens only after you say yes.", "", "Engines"];
  if (!plan.enabled.length) {
    lines.push("  none enabled yet; run `npx codeinspectus init` to set them up.");
  } else if (!plan.engines) {
    lines.push(`  ${plan.enabled.join(", ")}: up to date; nothing to download.`);
  } else {
    for (const id of plan.engine_selection) lines.push(componentLine(plan.engines, id, plan.engine_databases.trivy_db, plan.large_downloads));
    for (const ecosystem of plan.engine_databases.osv_ecosystems) {
      const large = plan.large_downloads.some((item) => item.id === `osv:${ecosystem}`) ? OVER_100_MB : "";
      lines.push(`  OSV ${ecosystem} database: ~${approxSize(OSV_DB_SIZE_ESTIMATES[ecosystem])} download${large} (with the OSV-Scanner repair)`);
    }
    const current = plan.enabled.filter((id) => !plan.engine_selection.includes(id));
    if (current.length) lines.push(`  ${current.join(", ")}: up to date.`);
    lines.push(...verifierLines(plan.engines, plan.large_downloads));
  }
  lines.push("", "Databases", formatDatabaseUpdatePlan(plan.databases));
  if (plan.engine_databases.trivy_db || plan.engine_databases.osv_ecosystems.length) {
    lines.push("  A database the engine repair above refreshes is not downloaded a second time.");
  }
  if (plan.large_downloads.length) lines.push(`Over 100 MB each: ${largeNames(plan.large_downloads)}.`);
  return `${lines.join("\n")}\n`;
}

/** `init --update`: refresh engines (new pins) and databases behind one confirmation. Exit codes as `init`. */
async function runInitUpdate(parsed: ParsedArgs, io: InitCliIo, options: InitCliOptions): Promise<number> {
  for (const [flag, used] of [["--clients", parsed.clients], ["--skip-engines", parsed.skipEngines], ["--path", parsed.path]] as const) {
    if (used) throw new UsageError(`${flag} is not used with --update.`);
  }
  if (parsed.help) {
    io.stdout(initUpdateHelp());
    return 0;
  }
  if (parsed.json && !parsed.yes && !parsed.dryRun) {
    throw new UsageError("--json needs --yes (and --large for databases over 100 MB), or --dry-run; run without --json to review the plan and be asked.");
  }
  const plan = await buildInitUpdatePlan(options.buildPlan ?? buildSetupPlan, options.inspect ?? (() => inspectEngineSetup()));
  const print = (value: object, text: string): void => io.stdout(parsed.json ? `${JSON.stringify(value, null, 2)}\n` : text);
  if (parsed.dryRun) {
    print({ dry_run: true, plan }, `${formatInitUpdatePlan(plan)}\nDry run: nothing was changed.\n`);
    return 0;
  }
  if (!plan.engine_selection.length && !plan.databases.databases.length) {
    print({ plan }, `${formatInitUpdatePlan(plan)}\nNothing to update.\n`);
    return 0;
  }
  if (!parsed.json) io.stdout(formatInitUpdatePlan(plan));

  // The same consent rules as `codeinspectus update`: --yes, and --large (or a second yes) for downloads over 100 MB.
  let yes = parsed.yes;
  let large = yes && parsed.large;
  const names = largeNames(plan.large_downloads);
  if (!yes) {
    if (!io.stdinIsTTY) {
      io.stderr("Re-run with --yes to update (or --dry-run to only look).\n");
      return 2;
    }
    const answer = (await io.question("Update all of this? [y/N] ")).trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") {
      io.stdout("No update downloaded.\n");
      return 0;
    }
    yes = true;
    if (plan.large_downloads.length && !parsed.large) {
      const several = plan.large_downloads.length > 1;
      const second = (await io.question(`${names} ${several ? "are" : "is"} over 100 MB. Download ${several ? "them" : "it"} too? [y/N] `)).trim().toLowerCase();
      if (second !== "y" && second !== "yes") {
        io.stdout("No update downloaded.\n");
        return 0;
      }
    }
    large = true;
  }
  if (plan.large_downloads.length && !large) {
    if (parsed.json) print({ plan }, "");
    io.stderr(`${notApproved(plan.large_downloads)}. Re-run with --yes --large to download ${plan.large_downloads.length > 1 ? "them" : "it"}.\n`);
    return 2;
  }

  const progress: InstallIo = parsed.json
    ? { stdout: (text) => io.stderr(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) }
    : { stdout: (text) => io.stdout(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) };

  const inspect = options.inspect ?? (() => inspectEngineSetup());
  // (a) New pins and missing binaries for the enabled engines, through the setup install path.
  let engines: { outcome: "installed" | "failed" | "not_needed"; message: string } = { outcome: "not_needed", message: "up to date; nothing downloaded." };
  let refreshedByRepair: string[] = [];
  if (plan.engines && plan.engine_selection.length) {
    const before = await inspect();
    try {
      const installed = await (options.install ?? installSetupComponents)(plan.engine_selection, true, { plan: plan.engines, io: progress });
      engines = { outcome: "installed", message: installed.message };
    } catch (error) {
      engines = { outcome: "failed", message: `Engine update failed (${plan.engine_selection.join(", ")}): ${errorMessage(error)}` };
      io.stderr(`${engines.message}\n`);
    }
    // Whatever the repair re-downloaded (its download time changed) is not downloaded again below.
    const after = await inspect().catch(() => before);
    const beforeTimes = new Map(installedManagedDatabases(before).map((database) => [database.id, database.updated_at]));
    refreshedByRepair = installedManagedDatabases(after)
      .filter((database) => database.updated_at !== undefined && database.updated_at !== beforeTimes.get(database.id))
      .map((database) => database.id);
  }

  // (b) The installed databases, through the M2 refresh (it re-checks engine readiness itself).
  let databases: DatabaseUpdateResult | { outcome: "failed"; error: string } | undefined;
  let databasesNote: string | undefined;
  if (plan.databases.databases.length) {
    const remaining = plan.databases.databases.filter((database) => !refreshedByRepair.includes(database.id));
    if (!remaining.length) {
      databasesNote = `Databases: ${refreshedByRepair.join(", ")} refreshed with the engine update; nothing else to download.`;
    } else {
      try {
        databases = await (options.runUpdate ?? runDatabaseUpdate)({
          confirmDownloads: true,
          confirmLargeDownloads: large,
          io: progress,
          ...(refreshedByRepair.length ? { exclude: refreshedByRepair } : {}),
          ...(options.inspect ? { inspect: options.inspect } : {}),
        });
      } catch (error) {
        databases = { outcome: "failed", error: `Database update failed: ${errorMessage(error)}` };
        io.stderr(`${databases.error}\n`);
      }
    }
  }

  const lines = ["", `Engines: ${engines.message}`];
  if (databasesNote) lines.push(databasesNote);
  if (databases && "error" in databases) lines.push(databases.error);
  else if (databases) {
    lines.push(formatDatabaseUpdateResult(databases));
    if (databases.package.newer) {
      lines.push(`CodeInspectus ${databases.package.latest} is on npm. npx may run a cached copy, so run ` +
        "`npx codeinspectus@latest init --update` to use it.");
    }
  }
  print({ plan, result: { engines, ...(refreshedByRepair.length ? { refreshed_by_engine_update: refreshedByRepair } : {}), ...(databases ? { databases } : {}) } },
    `${lines.join("\n")}\n`);
  return engines.outcome === "failed" || (databases && databases.outcome !== "updated") ? 1 : 0;
}
