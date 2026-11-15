/**
 * `codeinspectus init`: find the user's AI assistants and register the CodeInspectus MCP server in each.
 *
 * Safety rules (4.1 M3): a client CLI is preferred where one exists (Claude Code, VS Code's `code`); otherwise
 * the client's own config file is merged, never clobbered. A file that does not parse is never rewritten (the
 * manual instruction is returned instead); an existing `codeinspectus` entry that differs is left alone; the
 * first write to an existing file is preceded by a one-time `<file>.codeinspectus-backup`; every write is
 * atomic (temp file + rename, or an exclusive link for a new file) and keeps the original file mode and line
 * endings. Only a step planned as `add` is ever written, and only while the file still holds exactly what the
 * plan read. Every location is derived from the injected InitEnv, so tests never touch the real home directory
 * or run a real client CLI.
 *
 * Config files can hold tokens (an `env` block), so nothing read from a file ever reaches a step, an outcome or
 * an error message: only statuses, paths, error codes and line/column positions do.
 *
 * CLI-only module: it never writes to stdout, but nothing on the MCP server path imports it.
 */

import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, copyFile, link, lstat, mkdir, readFile, realpath, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parse as parseToml } from "smol-toml";

export const CLIENT_IDS = ["claude", "codex", "cursor", "vscode", "windsurf", "cline"] as const;
export type ClientId = (typeof CLIENT_IDS)[number];

export const CLIENT_NAMES: Record<ClientId, string> = {
  claude: "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  vscode: "VS Code",
  windsurf: "Windsurf",
  cline: "Cline",
};

const SERVER_NAME = "codeinspectus";
const SERVER_COMMAND = "npx";
const SERVER_ARGS = ["-y", "codeinspectus"] as const;
const STDIO_ENTRY = { command: SERVER_COMMAND, args: [...SERVER_ARGS] };
/** Claude Code on native Windows needs npx servers wrapped in `cmd /c` (its documented requirement). */
const WINDOWS_CMD_ENTRY = { command: "cmd", args: ["/c", SERVER_COMMAND, ...SERVER_ARGS] };

/** Config files larger than this are not read (their status is unknown, or the file is skipped). */
export const CONFIG_READ_LIMIT_BYTES = 50 * 1024 * 1024;

export const CLAUDE_CODE_ARGV: readonly string[] = [
  "claude", "mcp", "add-json", "--scope", "user", SERVER_NAME, JSON.stringify(STDIO_ENTRY),
];
export const CLAUDE_CODE_ARGV_WIN32: readonly string[] = [
  "claude", "mcp", "add-json", "--scope", "user", SERVER_NAME, JSON.stringify(WINDOWS_CMD_ENTRY),
];
export const VSCODE_ARGV: readonly string[] = [
  "code", "--add-mcp", JSON.stringify({ name: SERVER_NAME, ...STDIO_ENTRY }),
];
export const CODEX_TOML_BLOCK =
  `[mcp_servers.${SERVER_NAME}]\ncommand = "${SERVER_COMMAND}"\nargs = ["-y", "codeinspectus"]\ntool_timeout_sec = 600\n`;

/** The README's generic JSON block: the manual route for any client init does not know. */
export const MANUAL_JSON_BLOCK = `{\n  "mcpServers": {\n    "${SERVER_NAME}": ${JSON.stringify(STDIO_ENTRY)}\n  }\n}`;

export interface InitEnv {
  home: string;
  platform: NodeJS.Platform;
  /** %APPDATA% on Windows (default `<home>\AppData\Roaming`). */
  appData?: string;
  /** $CLAUDE_CONFIG_DIR: Claude Code keeps `.claude.json` there instead of the home directory. */
  claudeConfigDir?: string;
  which(command: string): Promise<string | undefined>;
  run(argv: readonly string[]): Promise<{ code: number; stderr: string; stdout?: string }>;
}

export type ConfigFormat = "json-mcpServers" | "json-servers" | "toml-append";

export type ClientRoute =
  | { kind: "command"; argv: readonly string[]; check: { path: string; format: ConfigFormat } }
  | { kind: "file"; path: string; format: ConfigFormat };

export interface DetectedClient {
  id: ClientId;
  name: string;
  detected_by: string;
  route: ClientRoute;
}

export type RegistrationStatus = "add" | "already" | "conflict" | "unparseable";

export type RegistrationStep =
  | {
      client: ClientId;
      name: string;
      kind: "command";
      argv: readonly string[];
      /** The read-only file consulted to tell whether the client already has the server. */
      check_path: string;
      check_format: ConfigFormat;
      status: Exclude<RegistrationStatus, "unparseable">;
      detail: string;
    }
  | {
      client: ClientId;
      name: string;
      kind: "file";
      path: string;
      format: ConfigFormat;
      status: RegistrationStatus;
      /** The file does not exist yet and would be created. */
      create: boolean;
      detail: string;
    };

export interface RegistrationOutcome {
  client: ClientId;
  name: string;
  outcome: "registered" | "already" | "conflict" | "skipped" | "failed";
  detail: string;
  /** Set when this registration made the one-time backup. */
  backup?: string;
}

/**
 * The exact text each file step read when it was planned (undefined: the file did not exist). Kept off the step
 * object so it never reaches `--json` output; apply writes only while the file still holds this text.
 */
const plannedText = new WeakMap<object, string | undefined>();

function vscodeUserDir(env: InitEnv): string {
  if (env.platform === "darwin") return join(env.home, "Library", "Application Support", "Code", "User");
  if (env.platform === "win32") return join(env.appData ?? join(env.home, "AppData", "Roaming"), "Code", "User");
  return join(env.home, ".config", "Code", "User");
}

async function isDirectory(path: string): Promise<boolean> {
  return stat(path).then((info) => info.isDirectory(), () => false);
}

/** Read-only: which supported assistants this machine has, and where each would be registered. */
export async function detectClients(env: InitEnv): Promise<DetectedClient[]> {
  const found: DetectedClient[] = [];
  const add = (id: ClientId, detected_by: string, route: ClientRoute): void => {
    found.push({ id, name: CLIENT_NAMES[id], detected_by, route });
  };
  const userDir = vscodeUserDir(env);
  const [claude, codex, code] = await Promise.all([env.which("claude"), env.which("codex"), env.which("code")]);

  if (claude) {
    add("claude", "`claude` on PATH", {
      kind: "command",
      argv: env.platform === "win32" ? CLAUDE_CODE_ARGV_WIN32 : CLAUDE_CODE_ARGV,
      check: { path: join(env.claudeConfigDir || env.home, ".claude.json"), format: "json-mcpServers" },
    });
  }
  const codexDir = join(env.home, ".codex");
  if (codex || await isDirectory(codexDir)) {
    add("codex", codex ? "`codex` on PATH" : `${codexDir} exists`, { kind: "file", path: join(codexDir, "config.toml"), format: "toml-append" });
  }
  const cursorDir = join(env.home, ".cursor");
  if (await isDirectory(cursorDir)) {
    add("cursor", `${cursorDir} exists`, { kind: "file", path: join(cursorDir, "mcp.json"), format: "json-mcpServers" });
  }
  const vscodeConfig = join(userDir, "mcp.json");
  if (code) {
    add("vscode", "`code` on PATH", { kind: "command", argv: VSCODE_ARGV, check: { path: vscodeConfig, format: "json-servers" } });
  } else if (await isDirectory(userDir)) {
    add("vscode", `${userDir} exists`, { kind: "file", path: vscodeConfig, format: "json-servers" });
  }
  const windsurfDir = join(env.home, ".codeium", "windsurf");
  if (await isDirectory(windsurfDir)) {
    add("windsurf", `${windsurfDir} exists`, { kind: "file", path: join(windsurfDir, "mcp_config.json"), format: "json-mcpServers" });
  }
  const clineDir = join(userDir, "globalStorage", "saoudrizwan.claude-dev");
  if (await isDirectory(clineDir)) {
    add("cline", `${clineDir} exists`, {
      kind: "file", path: join(clineDir, "settings", "cline_mcp_settings.json"), format: "json-mcpServers",
    });
  }
  return found;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** An fs error's code only: its message is safe today, but a code is all a user needs. */
function errorCode(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === "string" ? code : "unknown error";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sameArgs(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value) && value.length === expected.length && value.every((arg, index) => arg === expected[index]);
}

/** Same server: `npx -y codeinspectus`, or Windows' `cmd /c npx -y codeinspectus` (other keys do not matter). */
function sameEntry(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  return (value.command === SERVER_COMMAND && sameArgs(value.args, SERVER_ARGS)) ||
    (value.command === WINDOWS_CMD_ENTRY.command && sameArgs(value.args, WINDOWS_CMD_ENTRY.args));
}

function serversKey(format: ConfigFormat): "mcpServers" | "servers" {
  return format === "json-servers" ? "servers" : "mcpServers";
}

function entryFor(format: ConfigFormat): Record<string, unknown> {
  return format === "json-servers" ? { type: "stdio", ...STDIO_ENTRY } : { ...STDIO_ENTRY };
}

/** A shell-quoted command line for display (POSIX single quotes where needed). */
export function displayCommand(argv: readonly string[]): string {
  return argv.map((arg) => (/^[\w./:=@,+-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`)).join(" ");
}

/** What the user can do by hand for a file route. */
export function manualFileInstruction(path: string, format: ConfigFormat): string {
  if (format === "toml-append") return `Add this to ${path}:\n${CODEX_TOML_BLOCK}`;
  const key = serversKey(format);
  return `Add this entry under "${key}" in ${path}:\n"${SERVER_NAME}": ${JSON.stringify(entryFor(format))}`;
}

type Inspection =
  | { exists: false }
  | { exists: true; text: string; status: RegistrationStatus; reason?: string };

type ReadResult = { kind: "missing" } | { kind: "text"; text: string } | { kind: "unreadable"; reason: string };

async function readConfig(path: string): Promise<ReadResult> {
  let info;
  try {
    info = await stat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") return { kind: "unreadable", reason: `it could not be read (${errorCode(error)})` };
    // stat follows links: a link whose target is gone must not be replaced by a regular file.
    const link = await lstat(path).catch(() => undefined);
    return link?.isSymbolicLink() ? { kind: "unreadable", reason: "it is a symbolic link to a missing file" } : { kind: "missing" };
  }
  if (!info.isFile()) return { kind: "unreadable", reason: `it could not be read (${info.isDirectory() ? "EISDIR" : "not a regular file"})` };
  if (info.size > CONFIG_READ_LIMIT_BYTES) return { kind: "unreadable", reason: "it is larger than 50 MiB" };
  try {
    return { kind: "text", text: await readFile(path, "utf8") };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { kind: "missing" };
    return { kind: "unreadable", reason: `it could not be read (${errorCode(error)})` };
  }
}

/** Where a JSON.parse error happened, as `line N, column M`. The message itself quotes the file, so it is never used. */
function jsonErrorLocation(error: unknown, text: string): string | undefined {
  const message = errorMessage(error);
  const lineColumn = /line (\d+) column (\d+)/.exec(message);
  if (lineColumn) return `line ${lineColumn[1]}, column ${lineColumn[2]}`;
  const position = /position (\d+)/.exec(message);
  if (!position) return undefined;
  const before = text.slice(0, Number(position[1]));
  const line = before.split("\n").length;
  return `line ${line}, column ${before.length - before.lastIndexOf("\n")}`;
}

const JSON_TOKEN = /"(?:[^"\\]|\\.)*"|[{}[\]:,]|[^\s{}[\]:,"]+/g;

/**
 * For text JSON.parse accepted: a duplicate key anywhere, or a number literal that re-serialising would change
 * (an integer past 2^53, `1.0`, `1e3`). Either makes a merge lossy, so the file is skipped instead.
 */
function lossyJson(text: string): string | undefined {
  const stack: Array<{ object: boolean; keys: Set<string>; expectKey: boolean }> = [];
  for (const [token] of text.matchAll(JSON_TOKEN)) {
    const top = stack[stack.length - 1];
    if (token === "{") stack.push({ object: true, keys: new Set(), expectKey: true });
    else if (token === "[") stack.push({ object: false, keys: new Set(), expectKey: false });
    else if (token === "}" || token === "]") stack.pop();
    else if (token === ",") {
      if (top?.object) top.expectKey = true;
    } else if (token === ":") {
      // the key was consumed already
    } else if (token.startsWith('"')) {
      if (top?.object && top.expectKey) {
        const key = JSON.parse(token) as string;
        if (top.keys.has(key)) return "it has a duplicate key";
        top.keys.add(key);
        top.expectKey = false;
      }
    } else if (token !== "true" && token !== "false" && token !== "null" && JSON.stringify(JSON.parse(token)) !== token) {
      return "it holds a number that rewriting would change (precision or notation)";
    }
  }
  return undefined;
}

function parseJsonConfig(text: string, format: ConfigFormat): { status: RegistrationStatus; root?: Record<string, unknown>; reason?: string } {
  let root: unknown;
  if (!text.trim()) return { status: "add", root: {} };
  try {
    root = JSON.parse(text);
  } catch (error) {
    const location = jsonErrorLocation(error, text);
    return { status: "unparseable", reason: `it is not plain JSON (comments, trailing commas or other syntax)${location ? `, at ${location}` : ""}` };
  }
  if (!isPlainObject(root)) return { status: "unparseable", reason: "its top level is not a JSON object" };
  const lossy = lossyJson(text);
  if (lossy) return { status: "unparseable", reason: lossy };
  const key = serversKey(format);
  const servers = root[key];
  if (servers === undefined) return { status: "add", root };
  if (!isPlainObject(servers)) return { status: "unparseable", reason: `its "${key}" value is not an object` };
  if (!(SERVER_NAME in servers)) return { status: "add", root };
  return { status: sameEntry(servers[SERVER_NAME]) ? "already" : "conflict", root };
}

/** A TOML error as `line N, column M` only: smol-toml's message embeds a code block of the file. */
function tomlErrorLocation(error: unknown): string {
  const { line, column } = (error ?? {}) as { line?: unknown; column?: unknown };
  return typeof line === "number" && typeof column === "number" ? `, at line ${line}, column ${column}` : "";
}

function parseTomlConfig(text: string): { status: RegistrationStatus; reason?: string } {
  let root: unknown;
  try {
    root = parseToml(text);
  } catch (error) {
    return { status: "unparseable", reason: `it is not valid TOML${tomlErrorLocation(error)}` };
  }
  const servers = isPlainObject(root) ? root.mcp_servers : undefined;
  if (!isPlainObject(servers) || !(SERVER_NAME in servers)) {
    // The appended table must still parse (an inline `mcp_servers = { ... }` cannot be extended by a table header).
    try {
      parseToml(appendToml(text));
    } catch {
      return { status: "unparseable", reason: "the [mcp_servers.codeinspectus] table cannot be appended to it safely" };
    }
    return { status: "add" };
  }
  return { status: sameEntry(servers[SERVER_NAME]) ? "already" : "conflict" };
}

function lineEnding(text: string): "\r\n" | "\n" {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

function appendToml(text: string): string {
  if (!text.length) return CODEX_TOML_BLOCK;
  const eol = lineEnding(text);
  return `${text}${text.endsWith("\n") ? "" : eol}${eol}${CODEX_TOML_BLOCK.replace(/\n/g, eol)}`;
}

function inspectText(text: string, format: ConfigFormat): Inspection {
  const parsed = format === "toml-append" ? parseTomlConfig(text) : parseJsonConfig(text, format);
  return { exists: true, text, status: parsed.status, ...(parsed.reason ? { reason: parsed.reason } : {}) };
}

async function inspectFile(path: string, format: ConfigFormat): Promise<Inspection> {
  const read = await readConfig(path);
  if (read.kind === "missing") return { exists: false };
  if (read.kind === "unreadable") return { exists: true, text: "", status: "unparseable", reason: read.reason };
  return inspectText(read.text, format);
}

function stepDetail(status: RegistrationStatus, path: string, format: ConfigFormat, create: boolean, reason?: string): string {
  switch (status) {
    case "add":
      return format === "toml-append"
        ? `${create ? "create" : "append to"} ${path}: [mcp_servers.${SERVER_NAME}] with tool_timeout_sec = 600`
        : `${create ? "create" : "merge into"} ${path}: "${serversKey(format)}"."${SERVER_NAME}"`;
    case "already":
      return `already registered in ${path}`;
    case "conflict":
      return `${path} already has a different "${SERVER_NAME}" entry; it is left unchanged`;
    case "unparseable":
      return `${path} was not changed because ${reason ?? "it could not be read"}. ${manualFileInstruction(path, format)}`;
  }
}

/** Read-only: what registering one detected client would do. */
export async function planRegistration(client: DetectedClient): Promise<RegistrationStep> {
  const route = client.route;
  if (route.kind === "command") {
    // The client's own file is only read here, never edited, and only its status is kept: an unreadable,
    // oversized or unparseable file means "unknown", and the CLI decides.
    const inspection = await inspectFile(route.check.path, route.check.format).catch(() => ({ exists: false }) as const);
    const status = inspection.exists && (inspection.status === "already" || inspection.status === "conflict") ? inspection.status : "add";
    const command = displayCommand(route.argv);
    return {
      client: client.id,
      name: client.name,
      kind: "command",
      argv: route.argv,
      check_path: route.check.path,
      check_format: route.check.format,
      status,
      detail: status === "add"
        ? `run: ${command}`
        : status === "already"
          ? `already registered (${route.check.path})`
          : `${route.check.path} already has a different "${SERVER_NAME}" entry; it is left unchanged (to replace it yourself: ${command})`,
    };
  }
  let inspection: Inspection;
  try {
    inspection = await inspectFile(route.path, route.format);
  } catch (error) {
    inspection = { exists: true, text: "", status: "unparseable", reason: `it could not be read (${errorCode(error)})` };
  }
  const create = !inspection.exists;
  const status = inspection.exists ? inspection.status : "add";
  const step: RegistrationStep = {
    client: client.id,
    name: client.name,
    kind: "file",
    path: route.path,
    format: route.format,
    status,
    create,
    detail: stepDetail(status, route.path, route.format, create, inspection.exists ? inspection.reason : undefined),
  };
  if (status === "add") plannedText.set(step, inspection.exists ? inspection.text : undefined);
  return step;
}

async function backupOnce(path: string): Promise<string | undefined> {
  const backup = `${path}.codeinspectus-backup`;
  try {
    await copyFile(path, backup, fsConstants.COPYFILE_EXCL);
    return backup;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return undefined;
    throw error;
  }
}

class ChangedWhileRunning extends Error {}

/**
 * Write through a temp file in the same directory. An existing file (symlinks resolved) is replaced by rename,
 * keeping its mode, but only if it still holds `expected` just before the rename. A new file is linked into
 * place exclusively, so a file someone else created meanwhile is never replaced.
 */
async function atomicWrite(
  path: string,
  text: string,
  expected: string | undefined,
  beforeCommit?: () => Promise<void>,
): Promise<{ backup?: string }> {
  const existing = expected !== undefined;
  const target = existing ? await realpath(path) : path;
  const mode = existing ? (await stat(target)).mode & 0o777 : 0o600;
  if (!existing) await mkdir(dirname(target), { recursive: true });
  const temporary = `${target}.${process.pid}.${randomUUID()}.codeinspectus-tmp`;
  try {
    await writeFile(temporary, text, { encoding: "utf8", flag: "wx", mode });
    await chmod(temporary, mode).catch(() => undefined); // the umask may have narrowed it
    await beforeCommit?.();
    if (existing) {
      const now = await readConfig(target);
      if (now.kind !== "text" || now.text !== expected) throw new ChangedWhileRunning();
      // Backed up only once the compare passed, so a skipped file never gets a backup.
      const backup = await backupOnce(path);
      await rename(temporary, target);
      return backup ? { backup } : {};
    }
    try {
      await link(temporary, target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new ChangedWhileRunning();
      // A file system without hard links: fall back to a checked rename.
      if ((await readConfig(target)).kind !== "missing") throw new ChangedWhileRunning();
      await rename(temporary, target);
      return {};
    }
    await unlink(temporary).catch(() => undefined);
    return {};
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function detectIndent(text: string): string | number {
  const match = /^([ \t]+)"/m.exec(text);
  return match?.[1] ?? 2;
}

function mergedJson(text: string, format: ConfigFormat): string {
  const parsed = parseJsonConfig(text, format);
  const root = parsed.root ?? {};
  const key = serversKey(format);
  const servers = isPlainObject(root[key]) ? root[key] : {};
  // Assigning onto the parsed objects keeps every existing key in its original order; the new entry goes last.
  servers[SERVER_NAME] = entryFor(format);
  root[key] = servers;
  const eol = lineEnding(text);
  const body = JSON.stringify(root, null, detectIndent(text)).replace(/\n/g, eol);
  return `${body}${text.length === 0 || text.endsWith("\n") ? eol : ""}`;
}

const CHANGED = "the file changed while init was running; run init again";

export interface ApplyOptions {
  /** Test hook: runs after the new content is staged and before the final check and rename. */
  beforeCommit?: () => Promise<void>;
}

/** Register one client. Only a step planned as `add` is written, and only while the file still holds what the plan read. */
export async function applyRegistration(step: RegistrationStep, env: InitEnv, options: ApplyOptions = {}): Promise<RegistrationOutcome> {
  const base = { client: step.client, name: step.name };
  if (step.kind === "command") {
    if (step.status === "already") return { ...base, outcome: "already", detail: step.detail };
    if (step.status === "conflict") return { ...base, outcome: "conflict", detail: step.detail };
    try {
      const result = await env.run(step.argv);
      if (result.code !== 0) {
        // Only the read-only check can confirm an identical entry ("already", handled above); the CLI's word that
        // some entry by this name exists says nothing about what it runs.
        if (/already exists/i.test(`${result.stderr}\n${result.stdout ?? ""}`)) {
          return {
            ...base,
            outcome: "conflict",
            detail: `an entry named ${SERVER_NAME} already exists in ${step.name}; it was not changed (check it with \`${step.argv[0]} mcp get ${SERVER_NAME}\`)`,
          };
        }
        const stderr = result.stderr.trim().slice(0, 500);
        return {
          ...base,
          outcome: "failed",
          detail: `\`${step.argv[0]}\` exited with code ${result.code}${stderr ? `: ${stderr}` : ""}. To register by hand: ${displayCommand(step.argv)}`,
        };
      }
      return { ...base, outcome: "registered", detail: `ran: ${displayCommand(step.argv)}` };
    } catch (error) {
      return { ...base, outcome: "failed", detail: `could not run \`${step.argv[0]}\` (${errorMessage(error)}). To register by hand: ${displayCommand(step.argv)}` };
    }
  }

  // The planned status is final: a file shown as unparseable or conflicting is never written, even if fixed since.
  if (step.status !== "add") {
    return { ...base, outcome: step.status === "unparseable" ? "skipped" : step.status, detail: step.detail };
  }
  const changed = { ...base, outcome: "skipped" as const, detail: `${step.path} was not changed: ${CHANGED}. ${manualFileInstruction(step.path, step.format)}` };
  try {
    const read = await readConfig(step.path);
    if (read.kind === "unreadable") {
      return { ...base, outcome: "skipped", detail: stepDetail("unparseable", step.path, step.format, false, read.reason) };
    }
    const current = read.kind === "text" ? read.text : undefined;
    const planned = plannedText.has(step) ? plannedText.get(step) : current;
    if (current !== planned) return changed;
    // Re-check the content itself too (a step that was not planned in this process has no recorded text).
    const inspection = current === undefined ? undefined : inspectText(current, step.format);
    if (inspection?.exists && inspection.status !== "add") {
      return {
        ...base,
        outcome: inspection.status === "unparseable" ? "skipped" : inspection.status,
        detail: stepDetail(inspection.status, step.path, step.format, false, inspection.reason),
      };
    }
    const next = step.format === "toml-append" ? appendToml(current ?? "") : mergedJson(current ?? "", step.format);
    const { backup } = await atomicWrite(step.path, next, current, options.beforeCommit);
    return {
      ...base,
      outcome: "registered",
      detail: `${current !== undefined ? "updated" : "created"} ${step.path}${backup ? ` (backup: ${backup})` : ""}`,
      ...(backup ? { backup } : {}),
    };
  } catch (error) {
    if (error instanceof ChangedWhileRunning) return changed;
    return { ...base, outcome: "failed", detail: `could not update ${step.path} (${errorCode(error)}). ${manualFileInstruction(step.path, step.format)}` };
  }
}
