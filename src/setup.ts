/**
 * Consent-driven external-engine setup.
 *
 * Inspection is always offline. Downloads happen only after an explicit CLI
 * confirmation/flag or an MCP call with confirm_downloads=true. Preferences
 * suppress repeated first-run prompts; they never change scan results.
 */

import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin as processStdin, stdout as processStdout } from "node:process";

import { MANAGED_BIN, MANAGED_SETUP_PREFERENCES, type EngineName } from "./config.js";
import { inspectEngineSetup } from "./engine-health.js";
import { loadLockfile, platformKey, type Lockfile } from "./engines/lockfile.js";
import { hasManagedCosign } from "./engines/signature.js";
import { repairEngines, type InstallIo } from "./install.js";
import { nativePackInventory } from "./packs/registry.js";
import type { EngineSetupStatus } from "./types.js";
import { sha256Hex } from "./util/hash.js";

export const SETUP_COMPONENTS = ["opengrep", "gitleaks", "trivy"] as const;
export type SetupComponentId = (typeof SETUP_COMPONENTS)[number];
export type SetupAction = "none" | "download" | "redownload" | "refresh_database" | "blocked";

const TRIVY_DB_ESTIMATED_DISK_BYTES = 1_181_116_006;
const PREFERENCE_SCHEMA_VERSION = 1;

interface SetupPreferences {
  schema_version: 1;
  updated_at: string;
  choices: Record<SetupComponentId, "enabled" | "declined">;
}

export interface SetupComponentPlan {
  id: SetupComponentId;
  name: string;
  version: string;
  state: string;
  action: SetupAction;
  selected: boolean;
  download_size_bytes?: number;
  estimated_database_disk_bytes?: number;
  coverage: string[];
  license: string;
  note?: string;
}

export interface SetupPlan {
  schema_version: "1.0.0";
  platform: string;
  native: { rule_count: number; download_required: false; coverage: string };
  components: SetupComponentPlan[];
  verifier: {
    name: "Cosign";
    version: string;
    required: boolean;
    available: boolean;
    download_size_bytes?: number;
    license: "Apache-2.0";
    purpose: string;
  };
  preference_state: "unconfigured" | "configured" | "invalid";
  network_required: boolean;
  confirmation_required: boolean;
  exact_download_bytes: number;
  estimated_database_disk_bytes: number;
  warnings: string[];
}

export interface SetupResult {
  outcome: "planned" | "installed" | "declined";
  message: string;
  plan: SetupPlan;
}

interface PreferenceRead {
  state: SetupPlan["preference_state"];
  value?: SetupPreferences;
  warning?: string;
}

function validPreferences(value: unknown): value is SetupPreferences {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SetupPreferences>;
  return candidate.schema_version === PREFERENCE_SCHEMA_VERSION &&
    Boolean(candidate.choices) &&
    SETUP_COMPONENTS.every((id) => candidate.choices?.[id] === "enabled" || candidate.choices?.[id] === "declined");
}

async function readPreferences(path = MANAGED_SETUP_PREFERENCES): Promise<PreferenceRead> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!validPreferences(parsed)) {
      return { state: "invalid", warning: `Ignored invalid setup preferences at ${path}.` };
    }
    return { state: "configured", value: parsed };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "unconfigured" };
    return { state: "invalid", warning: `Could not read setup preferences at ${path}.` };
  }
}

async function writePreferences(
  choices: Record<SetupComponentId, "enabled" | "declined">,
  path = MANAGED_SETUP_PREFERENCES,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const value: SetupPreferences = {
    schema_version: PREFERENCE_SCHEMA_VERSION,
    updated_at: new Date().toISOString(),
    choices,
  };
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function componentAction(
  id: SetupComponentId,
  status: EngineSetupStatus,
): { action: SetupAction; state: string; note?: string } {
  const engine = status.engines.find((item) => item.engine === id);
  if (!engine) return { action: "blocked", state: "unknown", note: "Engine health was not reported." };
  if (["unsupported_platform", "unpinned", "lockfile_error"].includes(engine.state)) {
    return { action: "blocked", state: engine.state, note: engine.detail ?? "Packaged pin state cannot be repaired safely." };
  }
  if (engine.state === "missing") return { action: "download", state: engine.state };
  if (engine.state === "hash_mismatch") return { action: "redownload", state: engine.state };
  if (id === "trivy" && status.trivy_db.state !== "ready") {
    return { action: "refresh_database", state: `binary_ready;database_${status.trivy_db.state}` };
  }
  return { action: "none", state: "ready" };
}

const COMPONENT_METADATA: Record<SetupComponentId, Pick<SetupComponentPlan, "name" | "coverage" | "license">> = {
  opengrep: {
    name: "Opengrep",
    coverage: ["Curated SAST for SQL injection, XSS, SSRF, command injection, weak cryptography, and insecure deserialization."],
    license: "GNU LGPL 2.1",
  },
  gitleaks: {
    name: "Gitleaks",
    coverage: ["200+ upstream secret patterns plus 4 CodeInspectus rules for credentials, API keys, and private keys."],
    license: "MIT",
  },
  trivy: {
    name: "Trivy",
    coverage: ["Dependency CVEs, IaC misconfiguration, secrets, license inventory, and SBOM generation."],
    license: "Apache-2.0",
  },
};

export async function buildSetupPlan(options: {
  status?: EngineSetupStatus;
  lockfile?: Lockfile;
  preferencesPath?: string;
  cosignAvailable?: boolean;
  selection?: readonly SetupComponentId[];
} = {}): Promise<SetupPlan> {
  const [status, lockfile, preferences, cosignAvailable] = await Promise.all([
    options.status ?? inspectEngineSetup(),
    options.lockfile ?? loadLockfile(),
    readPreferences(options.preferencesPath),
    options.cosignAvailable ?? hasManagedCosign(),
  ]);
  const key = status.platform || platformKey();
  const warnings = preferences.warning ? [preferences.warning] : [];
  const components = SETUP_COMPONENTS.map((id): SetupComponentPlan => {
    const state = componentAction(id, status);
    const entry = lockfile.engines[id]?.platforms[key];
    const selected = options.selection
      ? options.selection.includes(id)
      : preferences.value
        ? preferences.value.choices[id] === "enabled"
        : true;
    return {
      id,
      ...COMPONENT_METADATA[id],
      version: lockfile.engines[id]?.version ?? "unknown",
      state: state.state,
      action: state.action,
      selected,
      ...(entry?.download_size_bytes !== undefined ? { download_size_bytes: entry.download_size_bytes } : {}),
      ...(id === "trivy" ? { estimated_database_disk_bytes: TRIVY_DB_ESTIMATED_DISK_BYTES } : {}),
      ...(state.note ? { note: state.note } : {}),
    };
  });
  const selectedActionable = components.filter((item) => item.selected && item.action !== "none" && item.action !== "blocked");
  const requiresCosign = selectedActionable.some((item) =>
    (item.id === "opengrep" || item.id === "trivy") && (item.action === "download" || item.action === "redownload"),
  );
  const verifierEntry = lockfile.verifiers?.cosign.platforms[key];
  const verifierDownload = requiresCosign && !cosignAvailable ? verifierEntry?.download_size_bytes ?? 0 : 0;
  const exactDownloadBytes = selectedActionable.reduce((total, item) =>
    total + ((item.action === "download" || item.action === "redownload") ? item.download_size_bytes ?? 0 : 0), verifierDownload);
  const estimatedDbBytes = selectedActionable.some((item) => item.id === "trivy" && item.action !== "none")
    ? TRIVY_DB_ESTIMATED_DISK_BYTES
    : 0;
  if (requiresCosign && !cosignAvailable && !verifierEntry) {
    warnings.push(`Cosign has no bootstrap pin for ${key}; Opengrep/Trivy installation is blocked.`);
  }
  return {
    schema_version: "1.0.0",
    platform: key,
    native: {
      rule_count: nativePackInventory().reduce((sum, pack) => sum + pack.rules.registered, 0),
      download_required: false,
      coverage: "First-party CodeInspectus rules are available immediately without external downloads.",
    },
    components,
    verifier: {
      name: "Cosign",
      version: lockfile.verifiers?.cosign.version ?? "unknown",
      required: requiresCosign,
      available: cosignAvailable,
      ...(verifierEntry?.download_size_bytes !== undefined ? { download_size_bytes: verifierEntry.download_size_bytes } : {}),
      license: "Apache-2.0",
      purpose: "Verifies publisher signatures for Opengrep and Trivy before installation; a managed copy is bootstrapped from a shipped immutable SHA pin when absent.",
    },
    preference_state: preferences.state,
    network_required: selectedActionable.length > 0,
    confirmation_required: selectedActionable.length > 0,
    exact_download_bytes: exactDownloadBytes,
    estimated_database_disk_bytes: estimatedDbBytes,
    warnings,
  };
}

function mib(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

export function formatSetupPlan(plan: SetupPlan): string {
  const lines = [
    `CodeInspectus engine setup (${plan.platform})`,
    `Native CodeInspectus: ${plan.native.rule_count} rules, ready immediately, no download.`,
    "",
  ];
  for (const component of plan.components) {
    const size = component.download_size_bytes === undefined
      ? "size unavailable"
      : component.action === "blocked"
        ? `${mib(component.download_size_bytes)} upstream asset (not usable on this runtime)`
      : component.action === "none"
        ? `${mib(component.download_size_bytes)} upstream asset if a future repair is needed`
        : `${mib(component.download_size_bytes)} engine download`;
    const db = component.id === "trivy" ? ` + vulnerability DB (~${mib(component.estimated_database_disk_bytes ?? 0)} disk; network transfer varies)` : "";
    lines.push(`${component.selected ? "[selected]" : "[declined]"} ${component.name} ${component.version}: ${component.action}; ${size}${db}`);
    lines.push(`  Checks: ${component.coverage.join(" ")}`);
    lines.push(`  License: ${component.license}`);
    if (component.note) lines.push(`  Note: ${component.note}`);
  }
  if (plan.verifier.required && !plan.verifier.available) {
    lines.push(`\nRequired verifier: Cosign ${plan.verifier.version}, ${plan.verifier.download_size_bytes ? mib(plan.verifier.download_size_bytes) : "size unavailable"}, Apache-2.0.`);
  }
  lines.push(`\nExact selected binary downloads: ${mib(plan.exact_download_bytes)}.`);
  if (plan.estimated_database_disk_bytes) {
    lines.push(`Additional Trivy DB disk estimate: ~${mib(plan.estimated_database_disk_bytes)} (database download size changes upstream).`);
  }
  lines.push("Downloads go only to ~/.codeinspectus. Scans remain offline and never modify the target repository.");
  for (const warning of plan.warnings) lines.push(`Warning: ${warning}`);
  return `${lines.join("\n")}\n`;
}

export async function bootstrapCosign(
  lockfile: Lockfile,
  key: string,
  io: InstallIo,
  options: { managedBin?: string; managedReady?: () => Promise<boolean> } = {},
): Promise<void> {
  if (await (options.managedReady ?? hasManagedCosign)()) return;
  const verifier = lockfile.verifiers?.cosign;
  const entry = verifier?.platforms[key];
  if (!verifier || !entry?.sha256) throw new Error(`Cosign bootstrap is not pinned for ${key}.`);
  io.stdout(
    `• Cosign ${verifier.version} verifier — downloading${entry.download_size_bytes === undefined ? "" : ` ${mib(entry.download_size_bytes)}`} (this can take several minutes).`,
  );
  const response = await fetch(`${verifier.release_base}/${entry.asset}`, { redirect: "follow" });
  if (!response.ok) throw new Error(`Cosign download failed (${response.status} ${response.statusText}).`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (entry.download_size_bytes !== undefined && bytes.byteLength !== entry.download_size_bytes) {
    throw new Error(`Cosign download length mismatch (expected ${entry.download_size_bytes}, got ${bytes.byteLength}).`);
  }
  const digest = sha256Hex(bytes);
  if (digest.toLowerCase() !== entry.sha256.toLowerCase()) {
    throw new Error(`Cosign SHA256 mismatch (expected ${entry.sha256}, got ${digest}).`);
  }
  const managedBin = options.managedBin ?? MANAGED_BIN;
  await mkdir(managedBin, { recursive: true });
  const destination = join(managedBin, process.platform === "win32" ? "cosign.exe" : "cosign");
  const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
  const backup = `${destination}.${process.pid}.${randomUUID()}.backup`;
  let preserveBackup = false;
  try {
    await writeFile(temporary, bytes, { flag: "wx", mode: 0o755 });
    await chmod(temporary, 0o755).catch(() => undefined);
    try {
      await rename(temporary, destination);
    } catch (first) {
      await rename(destination, backup);
      try {
        await rename(temporary, destination);
      } catch (second) {
        try {
          await rename(backup, destination);
        } catch (restore) {
          preserveBackup = true;
          throw new AggregateError(
            [first, second, restore],
            `Could not install Cosign or restore the prior managed binary. Backup preserved at ${backup}.`,
          );
        }
        throw new AggregateError([first, second], "Could not atomically install the verified Cosign binary.");
      }
      await rm(backup, { force: true });
    }
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
    if (!preserveBackup) await rm(backup, { force: true }).catch(() => undefined);
  }
  io.stdout(`✓ Installed SHA-pinned Cosign ${verifier.version} verifier in ${managedBin}.`);
}

function choicesFor(selection: readonly SetupComponentId[], mode: "enabled" | "declined"): Record<SetupComponentId, "enabled" | "declined"> {
  const selected = new Set(selection);
  return Object.fromEntries(SETUP_COMPONENTS.map((id) => [id, selected.has(id) ? mode : mode === "enabled" ? "declined" : "enabled"])) as Record<SetupComponentId, "enabled" | "declined">;
}

export async function installSetupComponents(
  selection: readonly SetupComponentId[],
  confirmDownloads: boolean,
  options: {
    preferencesPath?: string;
    io?: InstallIo;
    repair?: typeof repairEngines;
    plan?: SetupPlan;
    bootstrap?: typeof bootstrapCosign;
    loadLockfile?: typeof loadLockfile;
  } = {},
): Promise<SetupResult> {
  const unique = [...new Set(selection)];
  if (!unique.length) throw new Error("Select at least one component.");
  const invalid = unique.filter((item) => !SETUP_COMPONENTS.includes(item));
  if (invalid.length) throw new Error(`Unknown setup component(s): ${invalid.join(", ")}.`);
  const plan = options.plan ?? await buildSetupPlan({ preferencesPath: options.preferencesPath, selection: unique });
  const selectedPlan = plan.components.filter((item) => unique.includes(item.id));
  const networkRequired = selectedPlan.some((item) => item.action !== "none" && item.action !== "blocked");
  const blockers = selectedPlan.filter((item) => item.action === "blocked");
  if (blockers.length) throw new Error(blockers.map((item) => `${item.name}: ${item.note ?? item.state}`).join("; "));
  if (networkRequired && !confirmDownloads) {
    throw new Error("Download confirmation is required. Review the plan, then retry with explicit approval.");
  }
  const io = options.io ?? {
    stdout: (text: string) => process.stdout.write(`${text}\n`),
    stderr: (text: string) => process.stderr.write(`${text}\n`),
  };
  if (networkRequired) {
    const needsVerifier = selectedPlan.some((item) =>
      (item.id === "opengrep" || item.id === "trivy") && (item.action === "download" || item.action === "redownload"),
    );
    if (needsVerifier) await (options.bootstrap ?? bootstrapCosign)(await (options.loadLockfile ?? loadLockfile)(), plan.platform, io);
    await (options.repair ?? repairEngines)(unique as EngineName[], io);
  }
  await writePreferences(choicesFor(unique, "enabled"), options.preferencesPath);
  const finalPlan = await buildSetupPlan({ preferencesPath: options.preferencesPath });
  return {
    outcome: "installed",
    message: networkRequired ? "Selected components installed and verified." : "Selected components were already healthy; no download was needed.",
    plan: finalPlan,
  };
}

export async function declineSetupComponents(
  selection: readonly SetupComponentId[] = SETUP_COMPONENTS,
  preferencesPath?: string,
): Promise<SetupResult> {
  await writePreferences(choicesFor(selection, "declined"), preferencesPath);
  return {
    outcome: "declined",
    message: "Saved your choice. Native CodeInspectus coverage remains available; declined external coverage will be reported as partial or unavailable.",
    plan: await buildSetupPlan({ preferencesPath }),
  };
}

export interface SetupCliIo {
  stdinIsTTY: boolean;
  stdout(text: string): void;
  stderr(text: string): void;
  question(prompt: string): Promise<string>;
}

export function setupHelp(): string {
  return [
    "Usage: codeinspectus setup [option]",
    "",
    "  (no option)                       Show the plan and ask before downloading.",
    "  --status                          Inspect setup without downloading or writing.",
    "  --all                             Approve all recommended external components.",
    "  --select opengrep,gitleaks,trivy  Approve only named components.",
    "  --reset                           Forget saved component choices.",
    "",
    "No npm install hook or scan downloads engines. Setup writes only to ~/.codeinspectus.",
    "",
  ].join("\n");
}

function defaultSetupIo(): SetupCliIo {
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

function parseSelection(value: string): SetupComponentId[] {
  const values = [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
  const invalid = values.filter((item) => !SETUP_COMPONENTS.includes(item as SetupComponentId));
  if (invalid.length || !values.length) throw new Error(`Expected a comma-separated selection from: ${SETUP_COMPONENTS.join(", ")}.`);
  return values as SetupComponentId[];
}

export async function runSetupCli(
  args: readonly string[],
  options: {
    automatic?: boolean;
    io?: SetupCliIo;
    preferencesPath?: string;
    plan?: SetupPlan;
    install?: typeof installSetupComponents;
    decline?: typeof declineSetupComponents;
  } = {},
): Promise<number> {
  const io = options.io ?? defaultSetupIo();
  try {
    if (args.includes("--help") || args.includes("-h")) {
      io.stdout(setupHelp());
      return 0;
    }
    const status = args.includes("--status");
    const all = args.includes("--all");
    const reset = args.includes("--reset");
    const selectIndex = args.indexOf("--select");
    const known = new Set(["--status", "--all", "--reset", "--select"]);
    const unknown = args.filter((arg, index) => !known.has(arg) && index !== selectIndex + 1);
    if (unknown.length || (selectIndex >= 0 && !args[selectIndex + 1])) throw new Error(`Unknown or incomplete setup option: ${unknown[0] ?? "--select"}.`);
    if ([status, all, reset, selectIndex >= 0].filter(Boolean).length > 1) throw new Error("Use only one of --status, --all, --select, or --reset.");
    if (reset) {
      await rm(options.preferencesPath ?? MANAGED_SETUP_PREFERENCES, { force: true });
      io.stdout("Setup choices reset. Run `codeinspectus setup` to choose again.\n");
      return 0;
    }
    let selection: SetupComponentId[] | undefined;
    if (all) selection = [...SETUP_COMPONENTS];
    if (selectIndex >= 0) selection = parseSelection(args[selectIndex + 1]!);
    const plan = options.plan ?? await buildSetupPlan({ preferencesPath: options.preferencesPath, ...(selection ? { selection } : {}) });
    io.stdout(formatSetupPlan(plan));
    if (status) return plan.components.some((item) => item.selected && item.action === "blocked") ? 2 : 0;

    const actionable = plan.components.filter((item) => item.action !== "none" && item.action !== "blocked");
    const selectedBlockers = plan.components.filter((item) => item.selected && item.action === "blocked");
    if (!selection && selectedBlockers.length) {
      io.stderr(`${selectedBlockers.map((item) => `${item.name}: ${item.note ?? item.state}`).join("; ")}\n`);
      return 2;
    }
    if (!selection && options.automatic && plan.preference_state === "configured" && !actionable.some((item) => item.selected)) {
      io.stdout("Saved setup choices decline the currently missing components. Run `codeinspectus setup` to review or change them.\n");
      return 0;
    }
    if (!selection && !actionable.length) {
      io.stdout("✓ Selected engine setup is healthy; no download needed.\n");
      return 0;
    }
    if (!selection && !io.stdinIsTTY) {
      io.stderr("CodeInspectus setup needs explicit approval. Use `codeinspectus setup --all` or `--select opengrep,gitleaks,trivy`.\n");
      return 2;
    }
    if (!selection) {
      const answer = (await io.question("Install all recommended external components? [Y]es / [n]o / [s]elect: ")).trim().toLowerCase();
      if (answer === "n" || answer === "no") {
        const result = await (options.decline ?? declineSetupComponents)(actionable.map((item) => item.id), options.preferencesPath);
        io.stdout(`${result.message}\n`);
        return 0;
      }
      if (answer === "s" || answer === "select") {
        selection = parseSelection(await io.question(`Choose components (${SETUP_COMPONENTS.join(",")}): `));
      } else if (!answer || answer === "y" || answer === "yes") {
        selection = [...SETUP_COMPONENTS];
      } else {
        throw new Error("Setup cancelled: expected yes, no, or select.");
      }
    }
    const result = await (options.install ?? installSetupComponents)(selection, true, {
      preferencesPath: options.preferencesPath,
      io: { stdout: (text) => io.stdout(`${text}\n`), stderr: (text) => io.stderr(`${text}\n`) },
    });
    io.stdout(`${result.message}\n`);
    return 0;
  } catch (error) {
    io.stderr(`CodeInspectus setup: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
