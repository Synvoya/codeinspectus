/**
 * Supabase Edge Function authentication and privileged-client authorization.
 *
 * The analyzer models repository-visible deployment units instead of treating an
 * arbitrary file-wide auth-looking token as protection:
 *
 *   deployment entrypoint -> actual served/exported handler -> request-bound
 *   authentication proof -> privileged Supabase operation -> dominating authz.
 *
 * Unsupported/dynamic shapes remain coverage notes. They never become proof.
 */

import { lstat, readFile, readdir } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";
import { posix } from "node:path";
import { parse as parseToml } from "smol-toml";
import type { Finding } from "../types.js";
import {
  arrayItems,
  expression,
  isConditionallyExecuted,
  jsCalls,
  lexicalScopeAt,
  nearestDefinition,
  objectProperty,
  parseJavaScriptSource,
  resolveImport,
  staticString,
  type JsCall,
  type JsDocument,
  type JsExpression,
  type JsToken,
} from "../packs/react-native/javascript.js";
import { makeAiFinding } from "./finding.js";
import { lineText } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"] as const;
const CODE_EXT_SET = new Set<string>(CODE_EXTS);
const DEFAULT_ENTRYPOINTS = CODE_EXTS.map((ext) => `index.${ext}`);
const IGNORE_DIRS = new Set([
  "node_modules", ".git", ".cache", "coverage", ".turbo", ".vercel",
  "dist", "build", ".next", "out", ".idea", ".vscode", ".pnpm-store",
]);
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_DIRECTORIES = 4_096;
const MAX_FILES = 4_096;
const MAX_MODULES_PER_FUNCTION = 64;
const MAX_HANDLER_ALIASES = 4;
const MAX_NOTES = 32;
const MAX_FINDINGS = 128;

const SUPABASE_SERVER_RE = /^(?:npm:)?@supabase\/server(?:@[^/]+)?(?:\/core)?$/;
const SUPABASE_JS_RE = /^(?:npm:)?@supabase\/supabase-js(?:@[^/]+)?$/;
const STRIPE_RE = /^(?:npm:)?stripe(?:@[^/]+)?$/;
const OCTOKIT_WEBHOOKS_RE = /^(?:npm:)?@octokit\/webhooks(?:@[^/]+)?$/;
const OCTOKIT_METHODS_RE = /^(?:npm:)?@octokit\/webhooks-methods(?:@[^/]+)?$/;
const JOSE_RE = /^(?:npm:)?jose(?:@[^/]+)?$/;
const DENO_SERVE_RE = /^(?:https:\/\/deno\.land\/std(?:@[^/]+)?\/http\/server\.ts|jsr:@std\/http(?:@[^/]+)?)$/;
const EXACT_SECRET_RE = /^sb_secret_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}$/;
const SECRET_KEY_NAME_RE = /^(?:SUPABASE_(?:SERVICE_ROLE|SECRET)_KEYS?|SERVICE_ROLE_KEY)$/i;
const QUERY_METHODS = new Set([
  "select", "insert", "update", "upsert", "delete", "remove", "upload",
  "download", "list", "move", "copy", "createSignedUrl", "createSignedUrls",
  "getPublicUrl", "invoke",
]);
const DIRECT_PRIVILEGED_METHODS = new Set([
  "rpc", "deleteUser", "inviteUserByEmail", "createUser", "updateUserById",
  "generateLink", "listUsers", "signOut", "mfa", "invoke",
]);

export interface SupabaseEdgeAuthAnalysis {
  findings: Finding[];
  notes: string[];
}

type ConfigState = "platform-user" | "disabled" | "ambiguous";
type AuthFactor = "user" | "secret" | "signed-webhook";
type WrapperMode = AuthFactor | "anonymous";

interface LoadedFile {
  abs: string;
  rel: string;
  content: string;
  ext: string;
}

interface LoadResult {
  root: string;
  files: Map<string, LoadedFile>;
  skipped: Set<string>;
  incomplete: boolean;
}

interface FunctionConfig {
  state: ConfigState;
  entrypoint?: string;
}

interface DeploymentUnit {
  slug: string;
  configRel: string;
  entryRel?: string;
  state: ConfigState;
}

interface BodyRange {
  start: number;
  end: number;
  scope: readonly number[];
  open?: number;
}

interface HandlerRoot {
  line: number;
  body: BodyRange;
  requestNames: Set<string>;
  contextNames: Set<string>;
  wrapperModes?: WrapperMode[];
}

interface DirectGuard {
  start: number;
  end: number;
  condition: readonly JsToken[];
}

interface AuthProof {
  factors: AuthFactor[];
  end: number;
  contextNames: Set<string>;
  userReferences: string[][];
}

interface PrivilegedSink {
  line: number;
  tokenIndex: number;
}

interface CallBinding {
  errorReferences: string[][];
  userReferences: string[][];
  contextNames: Set<string>;
  booleanReferences: string[][];
}

class BoundedNotes {
  private readonly values = new Set<string>();
  private omitted = 0;

  add(value: string): void {
    if (this.values.has(value)) return;
    if (this.values.size < MAX_NOTES) this.values.add(value);
    else this.omitted++;
  }

  finish(required: readonly string[] = []): string[] {
    const values = [...this.values];
    if (this.omitted > 0) {
      values.push(`Supabase Edge authentication coverage omitted ${this.omitted} additional bounded note(s).`);
    }
    for (const value of required) if (!values.includes(value)) values.push(value);
    return values;
  }
}

function relPath(root: string, value: string): string {
  return relative(root, value).replace(/\\/g, "/");
}

function relevantFile(rel: string): boolean {
  const ext = extname(rel).slice(1).toLowerCase();
  if (CODE_EXT_SET.has(ext)) return /(^|\/)supabase\//.test(rel);
  if (/(^|\/)supabase\/config\.toml$/.test(rel)) return true;
  if (/(^|\/)package\.json$/.test(rel)) return true;
  if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) return true;
  return /(^|\/)scripts?\/[^/]+\.(?:sh|bash|zsh)$/.test(rel);
}

async function loadProject(target: string, notes: BoundedNotes): Promise<LoadResult> {
  const root = resolve(target);
  const files = new Map<string, LoadedFile>();
  const skipped = new Set<string>();
  let incomplete = false;
  let directories = 0;
  let candidates = 0;
  let totalBytes = 0;

  const walk = async (directory: string): Promise<void> => {
    if (++directories > MAX_DIRECTORIES) {
      incomplete = true;
      notes.add(`Supabase Edge project walk stopped at the ${MAX_DIRECTORIES}-directory bound.`);
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => undefined);
    if (!entries) {
      incomplete = true;
      notes.add(`${relPath(root, directory) || "."}: unreadable directory; Edge deployment state was not inferred.`);
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const abs = join(directory, entry.name);
      const rel = relPath(root, abs);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) await walk(abs);
        continue;
      }
      if (entry.isSymbolicLink()) {
        if (/(^|\/)supabase\//.test(rel)) {
          skipped.add(rel);
          notes.add(`${rel}: symlink not followed; Edge deployment/authentication state was not inferred.`);
        }
        continue;
      }
      if (!entry.isFile() || !relevantFile(rel)) continue;
      if (++candidates > MAX_FILES) {
        incomplete = true;
        notes.add(`Supabase Edge project load stopped at the ${MAX_FILES}-file bound.`);
        continue;
      }
      const info = await lstat(abs).catch(() => undefined);
      if (!info || info.size > MAX_SOURCE_BYTES || totalBytes + info.size > MAX_TOTAL_BYTES) {
        skipped.add(rel);
        incomplete ||= totalBytes + (info?.size ?? 0) > MAX_TOTAL_BYTES;
        notes.add(`${rel}: unreadable or exceeded the bounded source loader; authentication state was not inferred.`);
        continue;
      }
      const content = await readFile(abs, "utf8").catch(() => undefined);
      if (content === undefined) {
        skipped.add(rel);
        notes.add(`${rel}: unreadable source; authentication state was not inferred.`);
        continue;
      }
      totalBytes += info.size;
      files.set(rel, { abs, rel, content, ext: extname(rel).slice(1).toLowerCase() });
    }
  };

  await walk(root);
  return { root, files, skipped, incomplete };
}

async function ensureLoaded(
  loaded: LoadResult,
  rel: string,
  notes: BoundedNotes,
): Promise<LoadedFile | undefined> {
  const existing = loaded.files.get(rel);
  if (existing) return existing;
  const normalized = posix.normalize(rel);
  if (normalized.startsWith("../") || posix.isAbsolute(normalized)) {
    notes.add(`${rel}: custom Edge entrypoint escapes the scan target; coverage is unknown.`);
    return undefined;
  }
  const abs = join(loaded.root, ...normalized.split("/"));
  const info = await lstat(abs).catch(() => undefined);
  if (!info?.isFile() || info.size > MAX_SOURCE_BYTES) {
    notes.add(`${rel}: configured Edge entrypoint is missing, unreadable, or oversized.`);
    loaded.skipped.add(rel);
    return undefined;
  }
  const content = await readFile(abs, "utf8").catch(() => undefined);
  if (content === undefined) {
    notes.add(`${rel}: configured Edge entrypoint is unreadable.`);
    loaded.skipped.add(rel);
    return undefined;
  }
  const file = { abs, rel: normalized, content, ext: extname(normalized).slice(1).toLowerCase() };
  loaded.files.set(normalized, file);
  return file;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function configsForProject(
  configRel: string,
  loaded: LoadResult,
  notes: BoundedNotes,
): Map<string, FunctionConfig> | undefined {
  const file = loaded.files.get(configRel);
  if (!file) return undefined;
  let root: Record<string, unknown>;
  try {
    root = asRecord(parseToml(file.content)) ?? {};
  } catch {
    notes.add(`${configRel}: invalid TOML; platform JWT state was not inferred.`);
    loaded.skipped.add(configRel);
    return undefined;
  }
  const functions = root.functions;
  if (functions === undefined) return new Map();
  const table = asRecord(functions);
  if (!table) {
    notes.add(`${configRel}: invalid functions table; platform JWT state was not inferred.`);
    loaded.skipped.add(configRel);
    return undefined;
  }
  const result = new Map<string, FunctionConfig>();
  for (const [slug, raw] of Object.entries(table)) {
    const entry = asRecord(raw);
    if (!entry) {
      notes.add(`${configRel}: invalid configuration for function '${slug}'.`);
      result.set(slug, { state: "ambiguous" });
      continue;
    }
    const verifyJwt = entry.verify_jwt;
    let state: ConfigState;
    if (verifyJwt === undefined || verifyJwt === true) state = "platform-user";
    else if (verifyJwt === false) state = "disabled";
    else {
      state = "ambiguous";
      notes.add(`${configRel}: verify_jwt for function '${slug}' is not a literal boolean.`);
    }
    const configuredEntrypoint = entry.entrypoint;
    if (configuredEntrypoint !== undefined && typeof configuredEntrypoint !== "string") {
      notes.add(`${configRel}: entrypoint for function '${slug}' is not a literal string.`);
      result.set(slug, { state: "ambiguous" });
      continue;
    }
    result.set(slug, {
      state,
      ...(typeof configuredEntrypoint === "string" ? { entrypoint: configuredEntrypoint } : {}),
    });
  }
  return result;
}

function ancestorConfigs(fileRel: string, configs: ReadonlySet<string>): string[] {
  const values: string[] = [];
  let directory = posix.dirname(fileRel);
  while (true) {
    const candidate = directory === "." ? "supabase/config.toml" : `${directory}/supabase/config.toml`;
    if (configs.has(candidate)) values.push(candidate);
    if (directory === ".") break;
    directory = posix.dirname(directory);
  }
  return values;
}

function deployNoVerifyJwt(
  files: Iterable<LoadedFile>,
  configPaths: ReadonlySet<string>,
  notes: BoundedNotes,
): Map<string, Set<string>> {
  const affected = new Map<string, Set<string>>();
  const command = /\bsupabase\s+functions\s+deploy(?:\s+([A-Za-z0-9_-]+))?[^\n"']*?--no-verify-jwt\b/g;
  for (const file of files) {
    if (!/(?:package\.json|\.ya?ml|\.(?:sh|bash|zsh))$/.test(file.rel)) continue;
    for (const match of file.content.matchAll(command)) {
      const candidate = match[1];
      const slug = candidate && !candidate.startsWith("-") ? candidate : "*";
      const line = file.content.slice(0, match.index ?? 0).split(/\r?\n/).length;
      const configs = ancestorConfigs(file.rel, configPaths);
      if (configs.length !== 1) {
        notes.add(`${file.rel}:${line}: repository deploy command uses --no-verify-jwt${slug === "*" ? "" : ` for '${slug}'`}, but its Supabase project is not unambiguously resolved; config state was not overridden.`);
        continue;
      }
      const configRel = configs[0]!;
      const slugs = affected.get(configRel) ?? new Set<string>();
      slugs.add(slug);
      affected.set(configRel, slugs);
      notes.add(`${file.rel}:${line}: repository deploy command unambiguously uses --no-verify-jwt${slug === "*" ? "" : ` for '${slug}'`} in '${configRel}'; config defaults are overridden.`);
    }
  }
  return affected;
}

function projectPrefixForConfig(configRel: string): string {
  return configRel.slice(0, -"supabase/config.toml".length);
}

function discoverUnits(loaded: LoadResult, notes: BoundedNotes): DeploymentUnit[] {
  const configPaths = new Set<string>();
  const discovered = new Map<string, Set<string>>();
  for (const rel of [...loaded.files.keys(), ...loaded.skipped]) {
    const configMatch = /^(.*)supabase\/config\.toml$/.exec(rel);
    if (configMatch) configPaths.add(rel);
    const functionMatch = /^(.*)supabase\/functions\/([^/]+)\//.exec(rel);
    if (functionMatch && !functionMatch[2]!.startsWith("_")) {
      const configRel = `${functionMatch[1]}supabase/config.toml`;
      configPaths.add(configRel);
      const values = discovered.get(configRel) ?? new Set<string>();
      values.add(functionMatch[2]!);
      discovered.set(configRel, values);
    }
  }
  const overrides = deployNoVerifyJwt(loaded.files.values(), configPaths, notes);
  const units: DeploymentUnit[] = [];
  for (const configRel of [...configPaths].sort()) {
    const parsed = configsForProject(configRel, loaded, notes);
    const slugs = new Set(discovered.get(configRel) ?? []);
    if (parsed) for (const slug of parsed.keys()) slugs.add(slug);
    const prefix = projectPrefixForConfig(configRel);
    for (const slug of [...slugs].sort()) {
      const entry = parsed?.get(slug);
      let state: ConfigState;
      const configOverrides = overrides.get(configRel);
      if (configOverrides?.has("*") || configOverrides?.has(slug)) state = "disabled";
      else if (entry) state = entry.state;
      else if (loaded.skipped.has(configRel) || loaded.incomplete) state = "ambiguous";
      else state = "platform-user";
      if (state === "ambiguous") {
        notes.add(`${configRel}: platform authentication for function '${slug}' is not repository-verifiable.`);
      }
      let entryRel: string | undefined;
      if (entry?.entrypoint) {
        entryRel = posix.normalize(posix.join(posix.dirname(configRel), entry.entrypoint));
      } else {
        const base = `${prefix}supabase/functions/${slug}`;
        const candidates = DEFAULT_ENTRYPOINTS.map((name) => `${base}/${name}`)
          .filter((candidate) => loaded.files.has(candidate) || loaded.skipped.has(candidate));
        if (candidates.length === 1) entryRel = candidates[0];
        else if (candidates.length > 1) {
          entryRel = candidates[0];
          notes.add(`${base}: multiple default Edge entrypoints found; '${entryRel}' was analyzed deterministically.`);
        } else {
          entryRel = `${base}/index.ts`;
          notes.add(`${entryRel}: default Edge entrypoint is missing or unreadable.`);
        }
      }
      units.push({ slug, configRel, entryRel, state });
    }
  }
  return units;
}

function importedSpecifiers(document: JsDocument): string[] {
  const values: string[] = [];
  const tokens = document.tokens;
  for (let index = 0; index < tokens.length; index++) {
    if (!['import', 'export'].includes(tokens[index]?.value ?? '')) continue;
    let cursor = index + 1;
    while (cursor < tokens.length && tokens[cursor]!.line <= tokens[index]!.line + 8) {
      if (tokens[cursor]?.kind === "string" && tokens[cursor]?.staticValue?.startsWith(".")) {
        values.push(tokens[cursor]!.staticValue!);
        break;
      }
      if ([";", "import", "export"].includes(tokens[cursor]?.value ?? "") && cursor > index + 1) break;
      cursor++;
    }
  }
  return [...new Set(values)];
}

function importCandidates(from: string, specifier: string): string[] {
  const base = posix.normalize(posix.join(posix.dirname(from), specifier));
  if (CODE_EXT_SET.has(posix.extname(base).slice(1))) return [base];
  return [
    ...CODE_EXTS.map((ext) => `${base}.${ext}`),
    ...CODE_EXTS.map((ext) => `${base}/index.${ext}`),
  ];
}

async function reachableModules(
  unit: DeploymentUnit,
  loaded: LoadResult,
  notes: BoundedNotes,
): Promise<Array<{ file: LoadedFile; document: JsDocument; isEntrypoint: boolean }>> {
  if (!unit.entryRel) return [];
  const entry = await ensureLoaded(loaded, unit.entryRel, notes);
  if (!entry || !CODE_EXT_SET.has(entry.ext)) return [];
  const queue = [entry.rel];
  const seen = new Set<string>();
  const result: Array<{ file: LoadedFile; document: JsDocument; isEntrypoint: boolean }> = [];
  while (queue.length && seen.size < MAX_MODULES_PER_FUNCTION) {
    const rel = queue.shift()!;
    if (seen.has(rel)) continue;
    seen.add(rel);
    const file = loaded.files.get(rel);
    if (!file) continue;
    const document = parseJavaScriptSource(file.rel, file.content);
    if (!document.balanced || document.lexicalIssues.length) {
      notes.add(`${file.rel}: unsupported, malformed, or parser-bounded source; Edge authentication was not inferred.`);
      continue;
    }
    result.push({ file, document, isEntrypoint: rel === entry.rel });
    for (const specifier of importedSpecifiers(document)) {
      const candidate = importCandidates(rel, specifier).find((value) => loaded.files.has(value));
      if (candidate && !seen.has(candidate)) queue.push(candidate);
      else if (!candidate) notes.add(`${file.rel}: local import '${specifier}' was not resolved by the bounded Edge module graph.`);
    }
  }
  if (queue.length) notes.add(`${unit.entryRel}: Edge module graph exceeded the ${MAX_MODULES_PER_FUNCTION}-module bound.`);
  return result;
}

function sameScope(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => right[index] === value);
}

function trimParens(document: JsDocument, input: JsExpression): JsExpression {
  let value = input;
  while (value.tokens[0]?.value === "(" && value.tokens.at(-1)?.value === ")") {
    if (document.pairs.get(value.start) !== value.end - 1) break;
    value = expression(document.tokens, value.start + 1, value.end - 1);
  }
  return value;
}

function simpleIdentifier(input: JsExpression): string | undefined {
  return input.tokens.length === 1 && input.tokens[0]?.kind === "identifier"
    ? input.tokens[0].value
    : undefined;
}

function parameterNames(tokens: readonly JsToken[]): string[] {
  const names: string[] = [];
  let start = 0;
  for (let index = 0; index <= tokens.length; index++) {
    if (index < tokens.length && tokens[index]?.value !== ",") continue;
    const part = tokens.slice(start, index).filter((token) => token.kind === "identifier");
    const name = part.find((token) => !["async", "readonly", "Request", "unknown"].includes(token.value));
    if (name) names.push(name.value);
    start = index + 1;
  }
  return names;
}

function functionBody(
  document: JsDocument,
  paramsOpen: number,
): { body: BodyRange; params: string[] } | undefined {
  const paramsClose = document.pairs.get(paramsOpen);
  if (paramsClose === undefined) return undefined;
  let bodyOpen = paramsClose + 1;
  if (document.tokens[bodyOpen]?.value === ":") {
    bodyOpen++;
    while (bodyOpen < document.tokens.length && !["{", "=>"].includes(document.tokens[bodyOpen]!.value)) bodyOpen++;
    if (document.tokens[bodyOpen]?.value === "=>") bodyOpen++;
  }
  if (document.tokens[bodyOpen]?.value === "=>") bodyOpen++;
  const params = parameterNames(document.tokens.slice(paramsOpen + 1, paramsClose));
  if (document.tokens[bodyOpen]?.value === "{") {
    const close = document.pairs.get(bodyOpen);
    if (close === undefined) return undefined;
    return {
      params,
      body: { start: bodyOpen + 1, end: close, scope: lexicalScopeAt(document, bodyOpen + 1), open: bodyOpen },
    };
  }
  let end = bodyOpen;
  while (end < document.tokens.length && ![",", ";", "}"].includes(document.tokens[end]!.value)) end++;
  return { params, body: { start: bodyOpen, end, scope: lexicalScopeAt(document, bodyOpen) } };
}

function directCallForExpression(document: JsDocument, input: JsExpression): JsCall | undefined {
  const value = trimParens(document, input);
  const start = value.start + (value.tokens[0]?.value === "await" ? 1 : 0);
  return jsCalls(document).find((call) => call.tokenIndex === start && call.closeIndex === value.end - 1);
}

function wrapperModes(
  document: JsDocument,
  call: JsCall,
): WrapperMode[] | undefined {
  const auth = objectProperty(document, call.arguments[0], "auth", call.tokenIndex);
  if (!auth) return undefined;
  const values = auth.tokens[0]?.value === "[" ? arrayItems(document, auth) : [auth];
  const modes: WrapperMode[] = [];
  for (const value of values) {
    const mode = staticString(document, value, call.tokenIndex);
    if (mode === "user") modes.push("user");
    else if (mode === "secret" || mode?.startsWith("secret:")) modes.push("secret");
    else if (mode === "none" || mode === "publishable" || mode?.startsWith("publishable:")) modes.push("anonymous");
    else return undefined;
  }
  return modes.length ? [...new Set(modes)] : undefined;
}

function resolveHandler(
  document: JsDocument,
  input: JsExpression,
  line: number,
  notes: BoundedNotes,
  depth = 0,
  seen = new Set<string>(),
): HandlerRoot | undefined {
  if (depth > MAX_HANDLER_ALIASES) {
    notes.add(`${document.path}:${line}: handler alias bound exceeded; authentication was not inferred.`);
    return undefined;
  }
  const value = trimParens(document, input);
  const identifier = simpleIdentifier(value);
  if (identifier) {
    const definition = nearestDefinition(document, identifier, value.start);
    if (!definition) return undefined;
    if (definition.origin?.source.startsWith(".")) {
      notes.add(`${document.path}:${line}: imported handler '${identifier}' crosses a module boundary; cross-module handler provenance is not inferred.`);
      return undefined;
    }
    const key = `${definition.tokenIndex}:${identifier}`;
    if (seen.has(key)) return undefined;
    seen.add(key);
    if (definition.expression) {
      return resolveHandler(document, definition.expression, line, notes, depth + 1, seen);
    }
    if (definition.kind === "function") {
      let paramsOpen = definition.tokenIndex + 1;
      while (paramsOpen < document.tokens.length && document.tokens[paramsOpen]?.value !== "(") paramsOpen++;
      const parsed = functionBody(document, paramsOpen);
      if (!parsed) return undefined;
      return {
        line,
        body: parsed.body,
        requestNames: new Set(parsed.params.slice(0, 1)),
        contextNames: new Set(parsed.params.slice(1, 2)),
      };
    }
    return undefined;
  }

  const rootCall = directCallForExpression(document, value);
  if (rootCall) {
    const origin = resolveImport(document, rootCall.reference, rootCall.tokenIndex);
    if (origin?.imported === "withSupabase" && SUPABASE_SERVER_RE.test(origin.source)) {
      const modes = wrapperModes(document, rootCall);
      if (!modes) {
        notes.add(`${document.path}:${line}: dynamic withSupabase auth mode; authentication was not inferred.`);
        return undefined;
      }
      const inner = rootCall.arguments.at(-1);
      if (!inner) return undefined;
      const handler = resolveHandler(document, inner, line, notes, depth + 1, seen);
      return handler ? { ...handler, wrapperModes: modes } : undefined;
    }
    notes.add(`${document.path}:${line}: custom handler wrapper is outside bounded authentication provenance.`);
    return undefined;
  }

  const tokens = document.tokens;
  let functionIndex = value.start;
  if (tokens[functionIndex]?.value === "async") functionIndex++;
  if (tokens[functionIndex]?.value === "function") {
    let paramsOpen = functionIndex + 1;
    if (tokens[paramsOpen]?.kind === "identifier") paramsOpen++;
    while (paramsOpen < value.end && tokens[paramsOpen]?.value !== "(") paramsOpen++;
    const parsed = functionBody(document, paramsOpen);
    if (!parsed) return undefined;
    return {
      line,
      body: parsed.body,
      requestNames: new Set(parsed.params.slice(0, 1)),
      contextNames: new Set(parsed.params.slice(1, 2)),
    };
  }
  let arrow = value.start;
  while (arrow < value.end && tokens[arrow]?.value !== "=>") {
    if (["{", "["].includes(tokens[arrow]?.value ?? "")) {
      const close = document.pairs.get(arrow);
      if (close !== undefined && close < value.end) arrow = close;
    }
    arrow++;
  }
  if (arrow < value.end) {
    let params: string[];
    if (tokens[arrow - 1]?.value === ")") {
      const open = document.pairs.get(arrow - 1);
      params = open === undefined ? [] : parameterNames(tokens.slice(open + 1, arrow - 1));
    } else params = tokens[arrow - 1]?.kind === "identifier" ? [tokens[arrow - 1]!.value] : [];
    const bodyOpen = arrow + 1;
    if (tokens[bodyOpen]?.value === "{") {
      const close = document.pairs.get(bodyOpen);
      if (close === undefined) return undefined;
      return {
        line,
        body: { start: bodyOpen + 1, end: close, scope: lexicalScopeAt(document, bodyOpen + 1), open: bodyOpen },
        requestNames: new Set(params.slice(0, 1)),
        contextNames: new Set(params.slice(1, 2)),
      };
    }
    return {
      line,
      body: { start: bodyOpen, end: value.end, scope: lexicalScopeAt(document, bodyOpen) },
      requestNames: new Set(params.slice(0, 1)),
      contextNames: new Set(params.slice(1, 2)),
    };
  }
  return undefined;
}

function directServeCall(document: JsDocument, call: JsCall): boolean {
  if (call.reference.join(".") === "Deno.serve" && !nearestDefinition(document, "Deno", call.tokenIndex)) return true;
  if (call.reference.length !== 1 || call.reference[0] !== "serve") return false;
  const origin = resolveImport(document, call.reference, call.tokenIndex);
  return origin?.imported === "serve" && DENO_SERVE_RE.test(origin.source);
}

function topLevelObjectParts(document: JsDocument, open: number, close: number): JsExpression[] {
  const parts: JsExpression[] = [];
  let start = open + 1;
  let cursor = start;
  while (cursor < close) {
    if (["(", "[", "{"].includes(document.tokens[cursor]?.value ?? "")) {
      const paired = document.pairs.get(cursor);
      if (paired !== undefined && paired < close) {
        cursor = paired + 1;
        continue;
      }
    }
    if (document.tokens[cursor]?.value === ",") {
      if (cursor > start) parts.push(expression(document.tokens, start, cursor));
      start = cursor + 1;
    }
    cursor++;
  }
  if (close > start) parts.push(expression(document.tokens, start, close));
  return parts.filter((part) => part.tokens.length > 0);
}

function exportDefaultHandlers(
  document: JsDocument,
  notes: BoundedNotes,
): HandlerRoot[] {
  const handlers: HandlerRoot[] = [];
  const tokens = document.tokens;
  for (let index = 0; index < tokens.length - 2; index++) {
    if (
      tokens[index]?.value !== "export" || tokens[index + 1]?.value !== "default" ||
      lexicalScopeAt(document, index).length > 0
    ) continue;
    let cursor = index + 2;
    if (tokens[cursor]?.value === "async") cursor++;
    if (tokens[cursor]?.value === "function") {
      const handler = resolveHandler(document, expression(tokens, index + 2, tokens.length), tokens[index]!.line, notes);
      if (handler) handlers.push(handler);
      continue;
    }
    if (tokens[cursor]?.value !== "{") {
      let end = cursor;
      while (end < tokens.length && tokens[end]?.value !== ";") end++;
      const handler = resolveHandler(document, expression(tokens, cursor, end), tokens[index]!.line, notes);
      if (handler) handlers.push(handler);
      continue;
    }
    const close = document.pairs.get(cursor);
    if (close === undefined) continue;
    for (const part of topLevelObjectParts(document, cursor, close)) {
      let member = part.start;
      if (tokens[member]?.value === "async") member++;
      const key = tokens[member]?.staticValue ?? tokens[member]?.value;
      if (key !== "fetch") continue;
      if (tokens[member + 1]?.value === ":") {
        const handler = resolveHandler(
          document,
          expression(tokens, member + 2, part.end),
          tokens[member]!.line,
          notes,
        );
        if (handler) handlers.push(handler);
      } else if (tokens[member + 1]?.value === "(") {
        const parsed = functionBody(document, member + 1);
        if (parsed) handlers.push({
          line: tokens[member]!.line,
          body: parsed.body,
          requestNames: new Set(parsed.params.slice(0, 1)),
          contextNames: new Set(parsed.params.slice(1, 2)),
        });
      }
    }
  }
  return handlers;
}

function handlerRoots(
  document: JsDocument,
  isEntrypoint: boolean,
  notes: BoundedNotes,
): HandlerRoot[] {
  const handlers: HandlerRoot[] = [];
  for (const call of jsCalls(document)) {
    if (!directServeCall(document, call)) continue;
    const input = call.arguments.at(-1);
    const handler = input ? resolveHandler(document, input, call.line, notes) : undefined;
    if (handler) handlers.push(handler);
    else notes.add(`${document.path}:${call.line}: served handler shape is unsupported; authentication was not inferred.`);
  }
  if (isEntrypoint) handlers.push(...exportDefaultHandlers(document, notes));
  return handlers.filter((handler, index, all) =>
    all.findIndex((candidate) => candidate.body.start === handler.body.start && candidate.body.end === handler.body.end) === index
  );
}

function nestedFunctionRanges(document: JsDocument, handler: HandlerRoot): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const tokens = document.tokens;
  for (let index = handler.body.start; index < handler.body.end; index++) {
    let open: number | undefined;
    if (tokens[index]?.value === "function") {
      let params = index + 1;
      if (tokens[params]?.kind === "identifier") params++;
      while (params < handler.body.end && tokens[params]?.value !== "(") params++;
      const close = document.pairs.get(params);
      open = close === undefined ? undefined : close + 1;
    } else if (tokens[index]?.value === "=>") open = index + 1;
    if (open !== undefined && tokens[open]?.value === "{" && open !== handler.body.open) {
      const close = document.pairs.get(open);
      if (close !== undefined) ranges.push([open, close]);
    } else if (open !== undefined && tokens[index]?.value === "=>") {
      let end = open;
      while (end < handler.body.end && ![";", ","].includes(tokens[end]?.value ?? "")) {
        if (["(", "[", "{"].includes(tokens[end]?.value ?? "")) {
          const close = document.pairs.get(end);
          if (close !== undefined) {
            end = close + 1;
            continue;
          }
        }
        end++;
      }
      ranges.push([index, end]);
    }
  }
  return ranges;
}

function inNestedFunction(index: number, ranges: readonly [number, number][]): boolean {
  return ranges.some(([start, end]) => index > start && index < end);
}

function directTermination(document: JsDocument, afterCondition: number, handler: HandlerRoot): number | undefined {
  const tokens = document.tokens;
  const start = afterCondition + 1;
  if (tokens[start]?.value === "{") {
    const close = document.pairs.get(start);
    if (close === undefined || close > handler.body.end) return undefined;
    const bodyScope = lexicalScopeAt(document, start + 1);
    for (let index = start + 1; index < close; index++) {
      if (!sameScope(lexicalScopeAt(document, index), bodyScope)) continue;
      if (
        ["return", "throw"].includes(tokens[index]?.value ?? "") &&
        !isConditionallyExecuted(document, index)
      ) return close;
    }
    return undefined;
  }
  return ["return", "throw"].includes(tokens[start]?.value ?? "") ? start + 1 : undefined;
}

function directGuards(document: JsDocument, handler: HandlerRoot): DirectGuard[] {
  const guards: DirectGuard[] = [];
  const tokens = document.tokens;
  for (let index = handler.body.start; index < handler.body.end; index++) {
    if (
      tokens[index]?.value !== "if" || tokens[index + 1]?.value !== "(" ||
      !sameScope(lexicalScopeAt(document, index), handler.body.scope)
    ) continue;
    const close = document.pairs.get(index + 1);
    if (close === undefined) continue;
    const end = directTermination(document, close, handler);
    if (end !== undefined) guards.push({
      start: index,
      end,
      condition: document.tokens.slice(index + 2, close),
    });
  }
  return guards;
}

function referenceValues(reference: readonly string[]): string[] {
  const values: string[] = [];
  for (const [index, value] of reference.entries()) {
    if (index > 0) values.push(".");
    values.push(value);
  }
  return values;
}

function normalizedCondition(tokens: readonly JsToken[]): string[] {
  let values = tokens.map((token) => token.staticValue ?? token.value);
  while (values[0] === "(" && values.at(-1) === ")") values = values.slice(1, -1);
  return values;
}

function splitOr(tokens: readonly JsToken[]): string[][] {
  const parts: string[][] = [];
  let current: string[] = [];
  let depth = 0;
  for (const token of tokens) {
    if (["(", "[", "{"].includes(token.value)) depth++;
    if ([")", "]", "}"].includes(token.value)) depth--;
    if (token.value === "||" && depth === 0) {
      parts.push(current);
      current = [];
    } else current.push(token.staticValue ?? token.value);
  }
  parts.push(current);
  return parts.map((part) => {
    while (part[0] === "(" && part.at(-1) === ")") part = part.slice(1, -1);
    return part;
  });
}

function equalValues(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function positiveReference(condition: readonly JsToken[], references: readonly string[][]): boolean {
  return splitOr(condition).some((part) => references.some((reference) =>
    equalValues(part, referenceValues(reference))
  ));
}

function negativeReference(condition: readonly JsToken[], references: readonly string[][]): boolean {
  return splitOr(condition).some((part) => references.some((reference) => {
    const values = referenceValues(reference);
    return equalValues(part, ["!", ...values]) ||
      equalValues(part, [...values, "==", "null"]) ||
      equalValues(part, [...values, "===", "null"]) ||
      equalValues(part, [...values, "==", "undefined"]) ||
      equalValues(part, [...values, "===", "undefined"]) ||
      equalValues(part, [...values, "===", "false"]);
  }));
}

function objectBindings(tokens: readonly JsToken[]): Map<string, string> {
  const result = new Map<string, string>();
  for (let index = 1; index < tokens.length - 1; index++) {
    if (tokens[index]?.kind !== "identifier") continue;
    const property = tokens[index]!.value;
    const local = tokens[index + 1]?.value === ":" && tokens[index + 2]?.kind === "identifier"
      ? tokens[index + 2]!.value
      : property;
    result.set(property, local);
    while (index < tokens.length && ![",", "}"].includes(tokens[index]?.value ?? "")) index++;
  }
  return result;
}

function callBinding(document: JsDocument, call: JsCall): CallBinding | undefined {
  const tokens = document.tokens;
  let equals = call.tokenIndex - 1;
  while (equals >= 0 && !["=", ";", "}"].includes(tokens[equals]?.value ?? "")) equals--;
  if (tokens[equals]?.value !== "=") return undefined;
  let declaration = equals - 1;
  while (declaration >= 0 && !["const", "let", "var", ";"].includes(tokens[declaration]?.value ?? "")) declaration--;
  if (!["const", "let", "var"].includes(tokens[declaration]?.value ?? "")) return undefined;
  const lhs = tokens.slice(declaration + 1, equals).filter((token) =>
    !["await", "as", "unknown"].includes(token.value)
  );
  if (lhs[0]?.value === "{") {
    const bindings = objectBindings(lhs);
    const data = bindings.get("data");
    const error = bindings.get("error");
    return {
      errorReferences: error ? [[error]] : [],
      userReferences: data ? [[data, "user"]] : [],
      contextNames: new Set(data ? [data] : []),
      booleanReferences: [],
    };
  }
  const name = lhs.find((token) => token.kind === "identifier")?.value;
  if (!name) return undefined;
  return {
    errorReferences: [[name, "error"]],
    userReferences: [[name, "data", "user"]],
    contextNames: new Set([name]),
    booleanReferences: [[name]],
  };
}

function expressionIsRequestValue(
  document: JsDocument,
  input: JsExpression | undefined,
  requestNames: ReadonlySet<string>,
  kind: "request" | "authorization" | "body" | "raw-body" | "stripe-signature" | "github-signature",
  useIndex: number,
  depth = 0,
  seen = new Set<string>(),
): boolean {
  if (!input || depth > 3) return false;
  let value = trimParens(document, input);
  if (value.tokens[0]?.value === "await") value = expression(document.tokens, value.start + 1, value.end);
  if (kind === "request" && value.tokens.length === 1 && requestNames.has(value.tokens[0]?.value ?? "")) return true;
  if (value.tokens.length === 1 && value.tokens[0]?.kind === "identifier") {
    const name = value.tokens[0].value;
    const definition = nearestDefinition(document, name, useIndex);
    if (!definition?.expression) return false;
    const key = `${definition.tokenIndex}:${name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return expressionIsRequestValue(document, definition.expression, requestNames, kind, definition.tokenIndex, depth + 1, seen);
  }
  const expectedMethod = kind === "authorization" || kind === "stripe-signature" || kind === "github-signature"
    ? "get"
    : kind === "raw-body" ? "text" : undefined;
  const calls = jsCalls(document).filter((call) => {
    if (call.tokenIndex < value.start || call.closeIndex >= value.end) return false;
    const root = call.reference[0];
    if (!root || !requestNames.has(root)) return false;
    if (kind === "authorization" || kind === "stripe-signature" || kind === "github-signature") {
      if (call.reference.length !== 3 || call.reference[1] !== "headers" || call.callee !== expectedMethod) return false;
      const header = staticString(document, call.arguments[0], call.tokenIndex);
      if (kind === "authorization") return /^authorization$/i.test(header ?? "");
      if (kind === "stripe-signature") return /^stripe-signature$/i.test(header ?? "");
      return /^x-hub-signature-256$/i.test(header ?? "");
    }
    if (kind === "raw-body") return call.reference.length === 2 && call.callee === expectedMethod;
    return call.reference.length === 2 && ["json", "text", "formData", "arrayBuffer"].includes(call.callee);
  });
  if (calls.length !== 1) return false;
  const call = calls[0]!;
  const referenceStart = call.tokenIndex - (call.reference.length * 2 - 2);
  if (referenceStart !== value.start) return false;
  const suffix = document.tokens.slice(call.closeIndex + 1, value.end);
  return suffix.length === 0 ||
    suffix.length === 1 && suffix[0]?.value === "!" ||
    suffix.length === 2 && suffix[0]?.value === "??" && suffix[1]?.staticValue !== undefined;
}

function expressionUsesEnvSecret(
  document: JsDocument,
  input: JsExpression | undefined,
  useIndex: number,
  expected = /SECRET|SERVICE_ROLE/i,
  depth = 0,
  seen = new Set<string>(),
): boolean {
  if (!input || depth > 3) return false;
  let value = trimParens(document, input);
  if (value.tokens[0]?.value === "await") value = expression(document.tokens, value.start + 1, value.end);
  if (value.tokens.length === 1 && value.tokens[0]?.kind === "identifier") {
    const name = value.tokens[0].value;
    const definition = nearestDefinition(document, name, useIndex);
    if (!definition?.expression) return false;
    const key = `${definition.tokenIndex}:${name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return expressionUsesEnvSecret(document, definition.expression, definition.tokenIndex, expected, depth + 1, seen);
  }
  const call = jsCalls(document).find((candidate) =>
    candidate.tokenIndex >= value.start && candidate.closeIndex < value.end &&
    candidate.reference.join(".") === "Deno.env.get" &&
    !nearestDefinition(document, "Deno", candidate.tokenIndex)
  );
  if (!call) return false;
  const referenceStart = call.tokenIndex - 4;
  if (referenceStart !== value.start) return false;
  const secretName = staticString(document, call.arguments[0], call.tokenIndex);
  if (!secretName || !expected.test(secretName)) return false;
  const suffix = document.tokens.slice(call.closeIndex + 1, value.end);
  return suffix.length === 0 || suffix.length === 1 && suffix[0]?.value === "!" ||
    suffix.length === 2 && suffix[0]?.value === "??" && suffix[1]?.staticValue !== undefined;
}

function directHandlerCall(document: JsDocument, call: JsCall, handler: HandlerRoot): boolean {
  return sameScope(lexicalScopeAt(document, call.tokenIndex), handler.body.scope);
}

function guardsAfter(
  guards: readonly DirectGuard[],
  after: number,
  before: number,
): DirectGuard[] {
  return guards.filter((guard) => guard.start > after && guard.end < before);
}

function createContextProof(
  document: JsDocument,
  call: JsCall,
  handler: HandlerRoot,
  guards: readonly DirectGuard[],
  before: number,
): AuthProof | undefined {
  const origin = resolveImport(document, call.reference, call.tokenIndex);
  if (
    origin?.imported !== "createSupabaseContext" || !SUPABASE_SERVER_RE.test(origin.source) ||
    !directHandlerCall(document, call, handler) ||
    !expressionIsRequestValue(document, call.arguments[0], handler.requestNames, "request", call.tokenIndex)
  ) return undefined;
  const auth = objectProperty(document, call.arguments[1], "auth", call.tokenIndex);
  const values = auth?.tokens[0]?.value === "[" ? arrayItems(document, auth) : auth ? [auth] : [];
  const factors: AuthFactor[] = [];
  for (const value of values) {
    const mode = staticString(document, value, call.tokenIndex);
    if (mode === "user") factors.push("user");
    else if (mode === "secret" || mode?.startsWith("secret:")) factors.push("secret");
    else return undefined;
  }
  const binding = callBinding(document, call);
  if (!binding || !factors.length) return undefined;
  const guard = guardsAfter(guards, call.closeIndex, before).find((candidate) =>
    positiveReference(candidate.condition, binding.errorReferences)
  );
  if (!guard) return undefined;
  return {
    factors: [...new Set(factors)],
    end: guard.end,
    contextNames: binding.contextNames,
    userReferences: binding.userReferences,
  };
}

function isSupabaseClient(document: JsDocument, root: string, useIndex: number): boolean {
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition?.expression) return false;
  return jsCalls(document).some((candidate) =>
    candidate.tokenIndex >= definition.expression!.start && candidate.closeIndex <= definition.expression!.end &&
    resolveImport(document, candidate.reference, candidate.tokenIndex)?.imported === "createClient" &&
    SUPABASE_JS_RE.test(resolveImport(document, candidate.reference, candidate.tokenIndex)?.source ?? "")
  );
}

function getUserProof(
  document: JsDocument,
  call: JsCall,
  handler: HandlerRoot,
  guards: readonly DirectGuard[],
  before: number,
): AuthProof | undefined {
  if (
    call.reference.length < 3 || call.reference.at(-2) !== "auth" || call.callee !== "getUser" ||
    !directHandlerCall(document, call, handler) ||
    !isSupabaseClient(document, call.reference[0]!, call.tokenIndex) ||
    !expressionIsRequestValue(document, call.arguments[0], handler.requestNames, "authorization", call.tokenIndex)
  ) return undefined;
  const binding = callBinding(document, call);
  if (!binding) return undefined;
  const candidates = guardsAfter(guards, call.closeIndex, before);
  const errorGuard = candidates.find((guard) => positiveReference(guard.condition, binding.errorReferences));
  const userGuard = candidates.find((guard) => negativeReference(guard.condition, binding.userReferences));
  if (!errorGuard || !userGuard) return undefined;
  return {
    factors: ["user"],
    end: Math.max(errorGuard.end, userGuard.end),
    contextNames: new Set(),
    userReferences: binding.userReferences,
  };
}

function enclosingTryCatchTermination(
  document: JsDocument,
  call: JsCall,
  handler: HandlerRoot,
): number | undefined {
  const tokens = document.tokens;
  for (let index = handler.body.start; index < call.tokenIndex; index++) {
    if (
      tokens[index]?.value !== "try" || tokens[index + 1]?.value !== "{" ||
      !sameScope(lexicalScopeAt(document, index), handler.body.scope)
    ) continue;
    const tryClose = document.pairs.get(index + 1);
    if (tryClose === undefined || call.tokenIndex > tryClose) continue;
    let cursor = tryClose + 1;
    if (tokens[cursor]?.value !== "catch") continue;
    cursor++;
    if (tokens[cursor]?.value === "(") cursor = (document.pairs.get(cursor) ?? cursor) + 1;
    if (tokens[cursor]?.value !== "{") continue;
    const catchClose = document.pairs.get(cursor);
    if (catchClose === undefined) continue;
    const catchScope = lexicalScopeAt(document, cursor + 1);
    const terminates = tokens.slice(cursor + 1, catchClose).some((token, offset) => {
      const tokenIndex = cursor + 1 + offset;
      return ["return", "throw"].includes(token.value) &&
        sameScope(lexicalScopeAt(document, tokenIndex), catchScope) &&
        !isConditionallyExecuted(document, tokenIndex);
    });
    const finallyIndex = catchClose + 1;
    if (!terminates || tokens[finallyIndex]?.value === "finally") continue;
    return catchClose;
  }
  return undefined;
}

function stripeInstance(document: JsDocument, root: string, useIndex: number): boolean {
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition?.expression) return false;
  return jsCalls(document).some((candidate) => {
    if (candidate.tokenIndex < definition.expression!.start || candidate.closeIndex > definition.expression!.end) return false;
    const origin = resolveImport(document, candidate.reference, candidate.tokenIndex);
    return origin?.imported === "default" && STRIPE_RE.test(origin.source) &&
      expressionUsesEnvSecret(document, candidate.arguments[0], candidate.tokenIndex, /STRIPE_SECRET_KEY/i);
  });
}

function stripeWebhookProof(
  document: JsDocument,
  call: JsCall,
  handler: HandlerRoot,
): AuthProof | undefined {
  if (
    call.reference.length !== 3 || call.reference[1] !== "webhooks" || call.callee !== "constructEvent" ||
    !stripeInstance(document, call.reference[0]!, call.tokenIndex) ||
    !expressionIsRequestValue(document, call.arguments[0], handler.requestNames, "raw-body", call.tokenIndex) ||
    !expressionIsRequestValue(document, call.arguments[1], handler.requestNames, "stripe-signature", call.tokenIndex) ||
    !expressionUsesEnvSecret(document, call.arguments[2], call.tokenIndex, /STRIPE_WEBHOOK_SECRET/i)
  ) return undefined;
  const end = enclosingTryCatchTermination(document, call, handler);
  return end === undefined ? undefined : {
    factors: ["signed-webhook"], end, contextNames: new Set(), userReferences: [],
  };
}

function githubInstance(document: JsDocument, root: string, useIndex: number): boolean {
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition?.expression) return false;
  return jsCalls(document).some((candidate) => {
    if (candidate.tokenIndex < definition.expression!.start || candidate.closeIndex > definition.expression!.end) return false;
    const origin = resolveImport(document, candidate.reference, candidate.tokenIndex);
    if (origin?.imported !== "Webhooks" || !OCTOKIT_WEBHOOKS_RE.test(origin.source)) return false;
    const secret = objectProperty(document, candidate.arguments[0], "secret", candidate.tokenIndex);
    return expressionUsesEnvSecret(document, secret, candidate.tokenIndex, /GITHUB_WEBHOOK_SECRET/i);
  });
}

function githubWebhookProof(
  document: JsDocument,
  call: JsCall,
  handler: HandlerRoot,
  guards: readonly DirectGuard[],
  before: number,
): AuthProof | undefined {
  let body: JsExpression | undefined;
  let signature: JsExpression | undefined;
  const instance = call.reference.length === 2 && call.callee === "verify" &&
    githubInstance(document, call.reference[0]!, call.tokenIndex);
  if (instance) {
    body = call.arguments[0];
    signature = call.arguments[1];
  } else {
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    if (
      origin?.imported !== "verify" || !OCTOKIT_METHODS_RE.test(origin.source) ||
      !expressionUsesEnvSecret(document, call.arguments[0], call.tokenIndex, /GITHUB_WEBHOOK_SECRET/i)
    ) {
      return undefined;
    }
    body = call.arguments[1];
    signature = call.arguments[2];
  }
  if (
    !directHandlerCall(document, call, handler) ||
    !expressionIsRequestValue(document, body, handler.requestNames, "raw-body", call.tokenIndex) ||
    !expressionIsRequestValue(document, signature, handler.requestNames, "github-signature", call.tokenIndex)
  ) return undefined;
  const binding = callBinding(document, call);
  if (!binding) return undefined;
  const guard = guardsAfter(guards, call.closeIndex, before).find((candidate) =>
    negativeReference(candidate.condition, binding.booleanReferences)
  );
  return guard ? {
    factors: ["signed-webhook"], end: guard.end, contextNames: new Set(), userReferences: [],
  } : undefined;
}

function bodyProofs(
  document: JsDocument,
  handler: HandlerRoot,
  before: number,
  notes: BoundedNotes,
): AuthProof[] {
  const proofs: AuthProof[] = [];
  const guards = directGuards(document, handler);
  const nested = nestedFunctionRanges(document, handler);
  for (const call of jsCalls(document)) {
    if (
      call.tokenIndex < handler.body.start || call.closeIndex > handler.body.end ||
      call.tokenIndex >= before || inNestedFunction(call.tokenIndex, nested)
    ) continue;
    const createContext = createContextProof(document, call, handler, guards, before);
    if (createContext) {
      proofs.push(createContext);
      continue;
    }
    const getUser = getUserProof(document, call, handler, guards, before);
    if (getUser) {
      proofs.push(getUser);
      continue;
    }
    const stripe = stripeWebhookProof(document, call, handler);
    if (stripe && stripe.end < before) {
      proofs.push(stripe);
      continue;
    }
    const github = githubWebhookProof(document, call, handler, guards, before);
    if (github) {
      proofs.push(github);
      continue;
    }
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    if (origin?.imported === "jwtVerify" && JOSE_RE.test(origin.source)) {
      notes.add(`${document.path}:${call.line}: manual jose.jwtVerify is not authentication proof; request, key, issuer, audience, and algorithm trust were not all proven.`);
    }
    if (origin?.imported === "withSupabase" && SUPABASE_SERVER_RE.test(origin.source)) {
      notes.add(`${document.path}:${call.line}: withSupabase inside a handler body is not proof because its returned wrapper is not the handler root.`);
    }
  }
  return proofs;
}

function contextNamesFromCalls(
  document: JsDocument,
  handler: HandlerRoot,
  before = handler.body.end,
): Set<string> {
  const names = new Set(handler.contextNames);
  const nested = nestedFunctionRanges(document, handler);
  for (const call of jsCalls(document)) {
    if (
      call.tokenIndex < handler.body.start || call.closeIndex >= before ||
      inNestedFunction(call.tokenIndex, nested)
    ) continue;
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    if (origin?.imported !== "createSupabaseContext" || !SUPABASE_SERVER_RE.test(origin.source)) continue;
    const binding = callBinding(document, call);
    if (binding) for (const name of binding.contextNames) names.add(name);
  }
  return names;
}

function noteCrossModuleCalls(
  document: JsDocument,
  handler: HandlerRoot,
  notes: BoundedNotes,
): void {
  const nested = nestedFunctionRanges(document, handler);
  for (const call of jsCalls(document)) {
    if (
      call.tokenIndex < handler.body.start || call.closeIndex > handler.body.end ||
      inNestedFunction(call.tokenIndex, nested)
    ) continue;
    const root = call.reference[0];
    if (!root) continue;
    const definition = nearestDefinition(document, root, call.tokenIndex);
    if (definition?.origin?.source.startsWith(".")) {
      notes.add(`${document.path}:${call.line}: call through imported '${root}' crosses a module boundary; privileged-client provenance is not inferred.`);
    }
  }
}

function privilegedKey(document: JsDocument, input: JsExpression | undefined, useIndex: number, depth = 0): boolean {
  if (!input || depth > 3) return false;
  const literal = staticString(document, input, useIndex);
  if (literal && EXACT_SECRET_RE.test(literal)) return true;
  if (expressionUsesEnvSecret(document, input, useIndex, SECRET_KEY_NAME_RE)) return true;
  if (input.tokens.length === 1 && input.tokens[0]?.kind === "identifier") {
    const name = input.tokens[0].value;
    if (SECRET_KEY_NAME_RE.test(name)) return true;
    const definition = nearestDefinition(document, name, useIndex);
    return Boolean(definition?.expression && privilegedKey(document, definition.expression, definition.tokenIndex, depth + 1));
  }
  return false;
}

function expressionReference(input: JsExpression | undefined): string[] | undefined {
  if (!input?.tokens.length || input.tokens[0]?.kind !== "identifier") return undefined;
  const result = [input.tokens[0].value];
  let cursor = 1;
  while (cursor < input.tokens.length && [".", "?."].includes(input.tokens[cursor]?.value ?? "") && input.tokens[cursor + 1]?.kind === "identifier") {
    result.push(input.tokens[cursor + 1]!.value);
    cursor += 2;
  }
  return cursor === input.tokens.length ? result : undefined;
}

function destructuredMember(
  document: JsDocument,
  localName: string,
  useIndex: number,
): { object: string; property: string } | undefined {
  const definition = nearestDefinition(document, localName, useIndex);
  if (!definition?.expression) return undefined;
  const object = expressionReference(definition.expression);
  if (object?.length !== 1) return undefined;
  const tokens = document.tokens;
  let declaration = definition.tokenIndex;
  while (declaration >= 0 && !["const", "let", "var", ";"].includes(tokens[declaration]?.value ?? "")) declaration--;
  if (!["const", "let", "var"].includes(tokens[declaration]?.value ?? "") || tokens[declaration + 1]?.value !== "{") return undefined;
  const close = document.pairs.get(declaration + 1);
  if (close === undefined || definition.tokenIndex > close) return undefined;
  let cursor = declaration + 2;
  while (cursor < close) {
    if (tokens[cursor]?.kind !== "identifier") {
      cursor++;
      continue;
    }
    const property = tokens[cursor]!.value;
    const local = tokens[cursor + 1]?.value === ":" && tokens[cursor + 2]?.kind === "identifier"
      ? tokens[cursor + 2]!.value
      : property;
    if (local === localName) return { object: object[0]!, property };
    while (cursor < close && ![",", "}"].includes(tokens[cursor]?.value ?? "")) cursor++;
    cursor++;
  }
  return undefined;
}

function privilegedClientRoot(
  document: JsDocument,
  root: string,
  useIndex: number,
  contexts: ReadonlySet<string>,
  depth = 0,
  seen = new Set<string>(),
): boolean {
  if (depth > 4) return false;
  const definition = nearestDefinition(document, root, useIndex);
  if (!definition?.expression) return false;
  const key = `${definition.tokenIndex}:${root}`;
  if (seen.has(key)) return false;
  seen.add(key);
  const ref = expressionReference(definition.expression);
  if (ref?.length === 2 && contexts.has(ref[0]!) && ref[1] === "supabaseAdmin") return true;
  const destructured = destructuredMember(document, root, useIndex);
  if (destructured?.property === "supabaseAdmin" && contexts.has(destructured.object)) return true;
  if (ref?.length === 1) return privilegedClientRoot(document, ref[0]!, definition.tokenIndex, contexts, depth + 1, seen);
  return jsCalls(document).some((call) => {
    if (call.tokenIndex < definition.expression!.start || call.closeIndex > definition.expression!.end) return false;
    const origin = resolveImport(document, call.reference, call.tokenIndex);
    if (
      origin?.imported === "createClient" && SUPABASE_JS_RE.test(origin.source) &&
      privilegedKey(document, call.arguments[1], call.tokenIndex)
    ) return true;
    if (call.reference.length >= 3 && contexts.has(call.reference[0]!) && call.reference[1] === "supabaseAdmin") return true;
    if (call.reference.length >= 2 && call.reference[0] !== root) {
      return privilegedClientRoot(document, call.reference[0]!, call.tokenIndex, contexts, depth + 1, new Set(seen));
    }
    return false;
  });
}

function chainMethodAfter(document: JsDocument, call: JsCall): { method: string; tokenIndex: number } | undefined {
  let cursor = call.closeIndex + 1;
  const end = Math.min(document.tokens.length, call.closeIndex + 96);
  while (cursor < end && ![";", "return", "throw"].includes(document.tokens[cursor]?.value ?? "")) {
    if (
      [".", "?."].includes(document.tokens[cursor]?.value ?? "") &&
      document.tokens[cursor + 1]?.kind === "identifier" &&
      document.tokens[cursor + 2]?.value === "("
    ) {
      const method = document.tokens[cursor + 1]!.value;
      if (QUERY_METHODS.has(method)) return { method, tokenIndex: cursor + 1 };
      const close = document.pairs.get(cursor + 2);
      if (close !== undefined) {
        cursor = close + 1;
        continue;
      }
    }
    cursor++;
  }
  return undefined;
}

function privilegedSinks(
  document: JsDocument,
  handler: HandlerRoot,
  contexts: ReadonlySet<string>,
): PrivilegedSink[] {
  const sinks: PrivilegedSink[] = [];
  const nested = nestedFunctionRanges(document, handler);
  for (const call of jsCalls(document)) {
    if (
      call.tokenIndex < handler.body.start || call.closeIndex > handler.body.end ||
      inNestedFunction(call.tokenIndex, nested)
    ) continue;
    const root = call.reference[0];
    if (!root) continue;
    let privileged = call.reference.length >= 2 && contexts.has(root) && call.reference[1] === "supabaseAdmin";
    if (!privileged) privileged = privilegedClientRoot(document, root, call.tokenIndex, contexts);
    if (!privileged) continue;
    const method = call.callee;
    const direct = DIRECT_PRIVILEGED_METHODS.has(method) || QUERY_METHODS.has(method) ||
      call.reference.includes("admin") && !["from", "schema"].includes(method);
    const chained = ["from", "schema"].includes(method) ? chainMethodAfter(document, call) : undefined;
    if (!direct && !chained) continue;
    const tokenIndex = chained?.tokenIndex ?? call.tokenIndex;
    sinks.push({ line: document.tokens[tokenIndex]?.line ?? call.line, tokenIndex });
  }
  return sinks.filter((sink, index, all) => all.findIndex((candidate) => candidate.tokenIndex === sink.tokenIndex) === index);
}

function requestDerivedName(document: JsDocument, name: string, handler: HandlerRoot, useIndex: number): boolean {
  const definition = nearestDefinition(document, name, useIndex);
  return Boolean(definition?.expression && (
    expressionIsRequestValue(document, definition.expression, handler.requestNames, "body", definition.tokenIndex) ||
    expressionIsRequestValue(document, definition.expression, handler.requestNames, "authorization", definition.tokenIndex)
  ));
}

function authModeSecretGuard(condition: readonly JsToken[], contexts: ReadonlySet<string>): boolean {
  const values = normalizedCondition(condition);
  for (const context of contexts) {
    const prefix = [context, ".", "authMode"];
    if (
      equalValues(values.slice(0, prefix.length), prefix) &&
      ["!=", "!=="].includes(values[prefix.length] ?? "") &&
      /^secret(?::|$)/.test(values[prefix.length + 1] ?? "") &&
      condition[prefix.length + 1]?.staticValue !== undefined &&
      values.length === prefix.length + 2
    ) return true;
  }
  return false;
}

function exactMetadataDenial(condition: readonly JsToken[], contexts: ReadonlySet<string>): boolean {
  const values = normalizedCondition(condition);
  for (const context of contexts) {
    for (const claims of ["userClaims", "jwtClaims"]) {
      for (const property of ["role", "permission", "permissions", "is_admin", "isAdmin"]) {
        const prefix = [context, ".", claims, ".", "app_metadata", ".", property];
        if (
          equalValues(values.slice(0, prefix.length), prefix) &&
          ["!=", "!=="].includes(values[prefix.length] ?? "") &&
          condition[prefix.length + 1]?.staticValue !== undefined && values.length === prefix.length + 2
        ) return true;
        if (["is_admin", "isAdmin"].includes(property) && equalValues(values, ["!", ...prefix])) return true;
      }
    }
  }
  return false;
}

function exactOwnershipDenial(
  document: JsDocument,
  condition: readonly JsToken[],
  handler: HandlerRoot,
  contexts: ReadonlySet<string>,
  userReferences: readonly string[][],
  useIndex: number,
): boolean {
  const values = normalizedCondition(condition);
  const operator = values.findIndex((value) => ["!=", "!=="].includes(value));
  if (operator <= 0 || operator >= values.length - 1) return false;
  const left = values.slice(0, operator);
  const right = values.slice(operator + 1);
  const identities = [
    ...[...contexts].flatMap((context) => [
      [context, ".", "userClaims", ".", "id"],
      [context, ".", "jwtClaims", ".", "sub"],
    ]),
    ...userReferences.map((reference) => [...referenceValues(reference), ".", "id"]),
  ];
  const identityLeft = identities.some((identity) => equalValues(left, identity));
  const identityRight = identities.some((identity) => equalValues(right, identity));
  if (identityLeft === identityRight) return false;
  const owner = identityLeft ? right : left;
  const ownerProperty = owner.at(-1) ?? "";
  if (!/^(?:user_id|owner_id|account_id|profile_id|owner)$/.test(ownerProperty)) return false;
  const ownerRoot = owner[0];
  return ownerRoot !== undefined && !handler.requestNames.has(ownerRoot) &&
    !requestDerivedName(document, ownerRoot, handler, useIndex);
}

function authorizationBefore(
  document: JsDocument,
  handler: HandlerRoot,
  sink: PrivilegedSink,
  contexts: ReadonlySet<string>,
  userReferences: readonly string[][],
): { authorized: boolean; secretOnly: boolean } {
  let authorized = false;
  let secretOnly = false;
  for (const guard of directGuards(document, handler)) {
    if (guard.end >= sink.tokenIndex) continue;
    if (authModeSecretGuard(guard.condition, contexts)) secretOnly = true;
    if (
      exactMetadataDenial(guard.condition, contexts) ||
      exactOwnershipDenial(document, guard.condition, handler, contexts, userReferences, guard.start)
    ) authorized = true;
  }
  return { authorized, secretOnly };
}

function accessPaths(
  state: ConfigState,
  handler: HandlerRoot,
  proofs: readonly AuthProof[],
): Array<Set<AuthFactor>> {
  let paths: Array<Set<AuthFactor>> = state === "platform-user"
    ? [new Set<AuthFactor>(["user"])]
    : [new Set<AuthFactor>()];
  if (handler.wrapperModes) {
    paths = paths.flatMap((path) => handler.wrapperModes!.map((mode) => {
      const value = new Set(path);
      if (mode !== "anonymous") value.add(mode);
      return value;
    }));
  }
  for (const proof of proofs) {
    paths = paths.flatMap((path) => proof.factors.map((factor) => new Set([...path, factor])));
  }
  const unique = new Map(paths.map((path) => [[...path].sort().join("|"), path] as const));
  return [...unique.values()];
}

function noAuthFinding(file: string, line: number, content: string): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-edge-fn-no-auth",
    title: "Supabase Edge Function reaches privileged data access without enforced authentication",
    severity: "high",
    cwe: ["CWE-862", "CWE-285"],
    owasp_web: ["A01:2021"],
    file,
    startLine: line,
    snippet: lineText(content, line),
    message:
      "A repository-visible path can reach an RLS-bypassing Supabase operation without platform JWT enforcement or a request-bound, fail-closed replacement authentication proof.",
    remediation: {
      summary: "Restore verify_jwt=true, or enforce request-bound user, secret-key, or signed-webhook authentication before privileged access.",
      steps: [
        "Prefer the Supabase gateway default for user-authenticated functions.",
        "For verify_jwt=false, validate the current request and terminate unconditionally on failure before the privileged operation.",
      ],
      references: ["CWE-862", "https://supabase.com/docs/guides/functions/auth"],
    },
    confidence: "high",
  });
}

function privilegedFinding(file: string, sink: PrivilegedSink, content: string): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-edge-fn-privileged-no-authz",
    title: "User-authenticated Edge Function performs an RLS-bypassing operation without enforced authorization",
    severity: "critical",
    cwe: ["CWE-863", "CWE-285"],
    owasp_web: ["A01:2021"],
    file,
    startLine: sink.line,
    snippet: lineText(content, sink.line),
    message:
      "A user-authenticated path reaches a service-role/secret Supabase operation, but no dominating server-controlled role, permission, ownership, or secret-mode denial was proven.",
    remediation: {
      summary: "Use the caller-scoped client, or enforce server-controlled authorization before the privileged operation.",
      steps: [
        "Prefer the user-scoped client so RLS enforces ownership.",
        "For admin access, deny callers using app_metadata/static permissions or verified resource ownership before the sink.",
        "For mixed user/secret modes, require ctx.authMode to be secret before admin access.",
        "Never authorize from user_metadata, which the user can edit.",
      ],
      references: ["CWE-863", "https://supabase.com/docs/guides/database/postgres/row-level-security"],
    },
    confidence: "high",
  });
}

export async function runSupabaseEdgeAuthAnalysis(target: string): Promise<SupabaseEdgeAuthAnalysis> {
  const notes = new BoundedNotes();
  const loaded = await loadProject(target, notes);
  const units = discoverUnits(loaded, notes);
  const findings: Finding[] = [];
  const findingKeys = new Set<string>();
  let omittedFindings = 0;
  const pushFinding = (finding: Finding): void => {
    const key = `${finding.rule_id}:${finding.location.file}:${finding.location.start_line}`;
    if (findingKeys.has(key)) return;
    findingKeys.add(key);
    if (findings.length < MAX_FINDINGS) findings.push(finding);
    else omittedFindings++;
  };

  for (const unit of units) {
    const modules = await reachableModules(unit, loaded, notes);
    let roots = 0;
    for (const module of modules) {
      const handlers = handlerRoots(module.document, module.isEntrypoint, notes);
      roots += handlers.length;
      for (const handler of handlers) {
        noteCrossModuleCalls(module.document, handler, notes);
        const preliminaryProofs = bodyProofs(module.document, handler, handler.body.end, notes);
        const initialContexts = new Set([
          ...contextNamesFromCalls(module.document, handler),
          ...preliminaryProofs.flatMap((proof) => [...proof.contextNames]),
        ]);
        const sinks = privilegedSinks(module.document, handler, initialContexts);
        if (!sinks.length) {
          const paths = accessPaths(unit.state, handler, preliminaryProofs);
          if (paths.some((path) => path.size === 0)) {
            notes.add(`${module.file.rel}:${handler.line}: public or unverifiable Edge handler has no repository-proven privileged Supabase operation; intent is not statically verifiable.`);
          }
          continue;
        }
        for (const sink of sinks) {
          const proofs = bodyProofs(module.document, handler, sink.tokenIndex, notes);
          const contexts = new Set([
            ...contextNamesFromCalls(module.document, handler, sink.tokenIndex),
            ...proofs.flatMap((proof) => [...proof.contextNames]),
          ]);
          const userReferences = proofs.flatMap((proof) => proof.userReferences);
          const paths = accessPaths(unit.state, handler, proofs);
          if (paths.some((path) => path.size === 0)) {
            pushFinding(noAuthFinding(module.file.rel, sink.line, module.file.content));
            continue;
          }
          const userOnly = paths.some((path) => path.has("user") && !path.has("secret") && !path.has("signed-webhook"));
          if (!userOnly) continue;
          const authz = authorizationBefore(module.document, handler, sink, contexts, userReferences);
          if (!authz.authorized && !authz.secretOnly) {
            pushFinding(privilegedFinding(module.file.rel, sink, module.file.content));
          }
        }
      }
    }
    if (modules.length > 0 && roots === 0) {
      notes.add(`${unit.entryRel}: no supported served/exported Edge handler root was found.`);
    }
  }
  const requiredNotes = omittedFindings > 0
    ? [`Supabase Edge authentication omitted ${omittedFindings} finding(s) after the ${MAX_FINDINGS}-finding bound.`]
    : [];
  return { findings, notes: notes.finish(requiredNotes) };
}

export async function runSupabaseEdgeAuthCheck(target: string): Promise<Finding[]> {
  return (await runSupabaseEdgeAuthAnalysis(target)).findings;
}
