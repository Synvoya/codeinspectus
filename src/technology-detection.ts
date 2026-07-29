/**
 * Deterministic, read-only repository technology detection.
 *
 * Detection uses only repository-visible paths and a small set of bounded
 * manifests. It never executes target code and never performs network I/O.
 */

import { lstat, open, opendir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { basename, dirname, extname, join, relative } from "node:path";
import type { DetectedTechnology } from "./types.js";
import {
  isPythonDependencyManifest,
  parsePythonDependencyManifest,
} from "./packs/python/dependencies.js";

export type { DetectedTechnology } from "./types.js";
export type TechnologyKind = DetectedTechnology["kind"];
export type TechnologyConfidence = DetectedTechnology["confidence"];

export type TechnologyInspectionLimitationReason =
  | "target_unreadable"
  | "unsupported_target"
  | "directory_unreadable"
  | "file_unreadable"
  | "file_too_large"
  | "manifest_invalid"
  | "manifest_inconclusive"
  | "symlink_skipped"
  | "discovery_entry_limit_reached"
  | "directory_depth_limit_reached"
  | "manifest_count_limit_reached"
  | "manifest_bytes_limit_reached"
  | "additional_failures_omitted";

export interface TechnologyInspectionLimitation {
  path: string;
  reason: TechnologyInspectionLimitationReason;
}

export interface TechnologyDetectionResult {
  detected_technologies: DetectedTechnology[];
  limitations: TechnologyInspectionLimitation[];
}

export interface TechnologyDetectionLimits {
  maxEntries: number;
  maxDepth: number;
  maxManifestFiles: number;
  maxManifestBytes: number;
}

type TechnologyId =
  | "javascript"
  | "typescript"
  | "sql"
  | "dart"
  | "python"
  | "go"
  | "java"
  | "csharp"
  | "php"
  | "rust"
  | "ruby"
  | "react"
  | "react-native"
  | "expo"
  | "nextjs"
  | "vue"
  | "svelte"
  | "astro"
  | "supabase"
  | "firebase"
  | "github-actions"
  | "flutter"
  | "android"
  | "ios"
  | "fastapi"
  | "starlette"
  | "flask"
  | "django"
  | "jinja2"
  | "openai"
  | "anthropic"
  | "langchain";

interface TechnologyDefinition {
  id: TechnologyId;
  kind: TechnologyKind;
}

interface DetectionState {
  evidence: Map<TechnologyId, Set<string>>;
  confidence: Map<TechnologyId, TechnologyConfidence>;
  limitations: Map<string, TechnologyInspectionLimitation>;
  limits: TechnologyDetectionLimits;
  entriesInspected: number;
  manifestsRead: number;
  manifestBytesRead: number;
  discoveryStopped: boolean;
  manifestReadsStopped: boolean;
}

const TECHNOLOGIES: readonly TechnologyDefinition[] = [
  { id: "javascript", kind: "language" },
  { id: "typescript", kind: "language" },
  { id: "sql", kind: "language" },
  { id: "dart", kind: "language" },
  { id: "python", kind: "language" },
  { id: "go", kind: "language" },
  { id: "java", kind: "language" },
  { id: "csharp", kind: "language" },
  { id: "php", kind: "language" },
  { id: "rust", kind: "language" },
  { id: "ruby", kind: "language" },
  { id: "react", kind: "framework" },
  { id: "react-native", kind: "framework" },
  { id: "expo", kind: "framework" },
  { id: "fastapi", kind: "framework" },
  { id: "starlette", kind: "framework" },
  { id: "flask", kind: "framework" },
  { id: "django", kind: "framework" },
  { id: "jinja2", kind: "framework" },
  { id: "openai", kind: "framework" },
  { id: "anthropic", kind: "framework" },
  { id: "langchain", kind: "framework" },
  { id: "nextjs", kind: "framework" },
  { id: "vue", kind: "framework" },
  { id: "svelte", kind: "framework" },
  { id: "astro", kind: "framework" },
  { id: "supabase", kind: "framework" },
  { id: "firebase", kind: "platform" },
  { id: "github-actions", kind: "platform" },
  { id: "flutter", kind: "framework" },
  { id: "android", kind: "platform" },
  { id: "ios", kind: "platform" },
];

const MAX_EVIDENCE_PER_TECHNOLOGY = 5;
const MAX_LIMITATIONS = 20;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_XCODE_PROJECT_BYTES = 4 * 1024 * 1024;
const DEFAULT_DETECTION_LIMITS: TechnologyDetectionLimits = {
  maxEntries: 100_000,
  maxDepth: 64,
  maxManifestFiles: 4_096,
  maxManifestBytes: 64 * 1024 * 1024,
};
const EXPO_STATIC_CONFIG_FILES = new Set(["app.json", "app.config.json"]);
const EXPO_DYNAMIC_CONFIG_FILES = new Set([
  "app.config.js",
  "app.config.mjs",
  "app.config.cjs",
  "app.config.ts",
  "app.config.mts",
  "app.config.cts",
]);

/** Generated output, dependency, cache, and VCS trees never contribute signals. */
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".cache",
  ".dart_tool",
  ".gradle",
  ".next",
  ".nuxt",
  ".output",
  ".pub-cache",
  ".mypy_cache",
  ".nox",
  ".pytest_cache",
  ".ruff_cache",
  ".svelte-kit",
  ".tox",
  ".venv",
  "__pycache__",
  "build",
  "cache",
  "caches",
  "coverage",
  "deriveddata",
  "dist",
  "node_modules",
  "out",
  "pods",
  "target",
  "venv",
  "vendor",
]);

const JAVASCRIPT_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs"]);
const TYPESCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts"]);
const PLATFORM_CORPUS_DIRECTORIES = new Set([
  "androidtest",
  "debug",
  "demo",
  "demos",
  "example",
  "examples",
  "integration_test",
  "profile",
  "sample",
  "samples",
  "test",
  "tests",
]);

function forwardSlash(path: string): string {
  return path.replace(/\\/g, "/");
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function relativeEvidence(root: string, path: string): string {
  const rel = forwardSlash(relative(root, path));
  return rel && rel !== "." ? rel : basename(path);
}

function confidenceRank(confidence: TechnologyConfidence): number {
  return confidence === "high" ? 2 : 1;
}

function addDetection(
  state: DetectionState,
  id: TechnologyId,
  evidence: string,
  confidence: TechnologyConfidence = "high",
): void {
  const normalized = forwardSlash(evidence);
  const entries = state.evidence.get(id) ?? new Set<string>();
  entries.add(normalized);
  state.evidence.set(id, entries);

  const current = state.confidence.get(id);
  if (!current || confidenceRank(confidence) > confidenceRank(current)) {
    state.confidence.set(id, confidence);
  }
}

function addLimitation(
  state: DetectionState,
  path: string,
  reason: TechnologyInspectionLimitationReason,
): void {
  const normalized = forwardSlash(path || ".");
  state.limitations.set(`${normalized}\0${reason}`, { path: normalized, reason });
}

function stripYamlComment(line: string): string {
  let singleQuoted = false;
  let doubleQuoted = false;
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (char === "'" && !doubleQuoted) singleQuoted = !singleQuoted;
    else if (char === '"' && !singleQuoted && line[index - 1] !== "\\") doubleQuoted = !doubleQuoted;
    else if (char === "#" && !singleQuoted && !doubleQuoted) return line.slice(0, index);
  }
  return line;
}

/** Recognizes the Flutter SDK dependency and Flutter's top-level pubspec section. */
function pubspecHasFlutterSignal(content: string): boolean {
  let section: string | undefined;
  let flutterDependencyIndent: number | undefined;

  for (const rawLine of content.split(/\r?\n/)) {
    const line = stripYamlComment(rawLine).replace(/\s+$/, "");
    if (!line.trim()) continue;

    const indent = line.match(/^[ \t]*/)?.[0].replace(/\t/g, "  ").length ?? 0;
    const trimmed = line.trim();

    if (indent === 0) {
      const topLevel = trimmed.match(/^([A-Za-z_][\w-]*)\s*:/)?.[1]?.toLowerCase();
      section = topLevel;
      flutterDependencyIndent = undefined;
      // A top-level Flutter configuration section is emitted only for Flutter packages.
      if (topLevel === "flutter") return true;
      continue;
    }

    if (section !== "dependencies" && section !== "dev_dependencies") continue;

    if (flutterDependencyIndent !== undefined && indent <= flutterDependencyIndent) {
      flutterDependencyIndent = undefined;
    }

    const dependency = trimmed.match(/^flutter\s*:\s*(.*)$/i);
    if (dependency) {
      flutterDependencyIndent = indent;
      if (/\bsdk\s*:\s*flutter\b/i.test(dependency[1] ?? "")) return true;
      continue;
    }

    if (
      flutterDependencyIndent !== undefined &&
      indent > flutterDependencyIndent &&
      /^sdk\s*:\s*flutter\b/i.test(trimmed)
    ) {
      return true;
    }
  }

  return false;
}

function flutterMetadataSignal(content: string): boolean {
  return (
    /This file tracks properties of this Flutter project/i.test(content) &&
    /^project_type\s*:\s*[A-Za-z_-]+\s*$/m.test(content)
  );
}

function dependencyNames(manifest: unknown): Set<string> {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return new Set();
  const record = manifest as Record<string, unknown>;
  const names = new Set<string>();
  for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    const dependencies = record[field];
    if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) continue;
    for (const name of Object.keys(dependencies)) names.add(name.toLowerCase());
  }
  return names;
}

const PYTHON_FRAMEWORK_DEPENDENCIES: Readonly<Record<string, TechnologyId>> = {
  fastapi: "fastapi",
  starlette: "starlette",
  flask: "flask",
  django: "django",
  jinja2: "jinja2",
  openai: "openai",
  anthropic: "anthropic",
  langchain: "langchain",
  "langchain-community": "langchain",
};

function addPythonDependencyDetections(
  state: DetectionState,
  dependencies: ReadonlySet<string>,
  evidence: string,
): void {
  for (const dependency of dependencies) {
    const technology = PYTHON_FRAMEWORK_DEPENDENCIES[dependency];
    if (technology) addDetection(state, technology, evidence);
    if (dependency === "flask-cors") addDetection(state, "flask", evidence, "medium");
    if (dependency === "django-cors-headers") addDetection(state, "django", evidence, "medium");
  }
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

/** Remove JSONC comments without interpreting comment markers inside strings. */
function stripJsonComments(content: string): string | undefined {
  let output = "";
  let inString = false;
  let escaped = false;

  for (let index = 0; index < content.length; index++) {
    const char = content[index] ?? "";
    const next = content[index + 1] ?? "";

    if (inString) {
      output += char;
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }

    if (char === '"') {
      inString = true;
      output += char;
      continue;
    }

    if (char === "/" && next === "/") {
      output += "  ";
      index += 2;
      while (index < content.length && content[index] !== "\n" && content[index] !== "\r") {
        output += " ";
        index++;
      }
      if (index < content.length) output += content[index];
      continue;
    }

    if (char === "/" && next === "*") {
      output += "  ";
      index += 2;
      let closed = false;
      while (index < content.length) {
        const current = content[index] ?? "";
        if (current === "*" && content[index + 1] === "/") {
          output += "  ";
          index++;
          closed = true;
          break;
        }
        output += current === "\n" || current === "\r" ? current : " ";
        index++;
      }
      if (!closed) return undefined;
      continue;
    }

    output += char;
  }

  return output;
}

/** Remove JSONC trailing commas without changing string contents. */
function stripJsonTrailingCommas(content: string): string {
  const characters = [...content];
  let inString = false;
  let escaped = false;

  for (let index = 0; index < characters.length; index++) {
    const char = characters[index] ?? "";
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      continue;
    }
    if (char !== ",") continue;

    let next = index + 1;
    while (next < characters.length && /\s/.test(characters[next] ?? "")) next++;
    if (characters[next] === "}" || characters[next] === "]") characters[index] = " ";
  }

  return characters.join("");
}

function parseJsonConfig(content: string): unknown | undefined {
  const withoutComments = stripJsonComments(content);
  if (withoutComments === undefined) return undefined;
  try {
    return JSON.parse(stripJsonTrailingCommas(withoutComments));
  } catch {
    return undefined;
  }
}

/**
 * Without exact package evidence, only an explicit top-level `expo` object is
 * framework-specific enough to activate Expo and React Native packs. Root
 * `name` + `slug` fields are valid Expo config but also common in other tools.
 */
function hasStaticExpoObject(value: unknown): boolean {
  const config = objectRecord(value);
  if (!config) return false;
  return Object.hasOwn(config, "expo") && objectRecord(config.expo) !== undefined;
}

type JavaScriptTokenKind = "identifier" | "string" | "punctuation" | "other";

interface JavaScriptToken {
  kind: JavaScriptTokenKind;
  value: string;
}

interface JavaScriptTokens {
  tokens: JavaScriptToken[];
  valid: boolean;
  conclusive: boolean;
}

function javascriptPunctuation(token: JavaScriptToken | undefined, value: string): boolean {
  return token?.kind === "punctuation" && token.value === value;
}

function javascriptIdentifier(token: JavaScriptToken | undefined, value: string): boolean {
  return token?.kind === "identifier" && token.value === value;
}

/** A deliberately small lexer: it proves literal object shape without executing config code. */
function tokenizeJavaScript(content: string): JavaScriptTokens {
  const tokens: JavaScriptToken[] = [];
  for (let index = 0; index < content.length;) {
    const char = content[index] ?? "";
    const next = content[index + 1] ?? "";

    if (/\s/.test(char)) {
      index++;
      continue;
    }
    if (content.startsWith("<!--", index) || content.startsWith("-->", index)) {
      return { tokens, valid: true, conclusive: false };
    }
    if (char === "/" && next === "/") {
      index += 2;
      while (index < content.length && content[index] !== "\n" && content[index] !== "\r") index++;
      continue;
    }
    if (char === "/" && next === "*") {
      const end = content.indexOf("*/", index + 2);
      if (end < 0) return { tokens, valid: false, conclusive: false };
      index = end + 2;
      continue;
    }
    if (char === "/") {
      // Distinguishing division from a regular-expression literal requires a
      // full JavaScript parser. Keep technology detection fail-closed instead
      // of interpreting regexp contents as structural config tokens.
      return { tokens, valid: true, conclusive: false };
    }
    if (char === '"' || char === "'") {
      const quote = char;
      let value = "";
      let closed = false;
      index++;
      while (index < content.length) {
        const current = content[index] ?? "";
        if (current === "\\") {
          const escaped = content[index + 1];
          if (escaped !== undefined) value += escaped;
          index += 2;
          continue;
        }
        if (current === quote) {
          index++;
          closed = true;
          break;
        }
        if (current === "\n" || current === "\r") break;
        value += current;
        index++;
      }
      if (!closed) return { tokens, valid: false, conclusive: false };
      tokens.push({ kind: "string", value });
      continue;
    }
    if (char === "`") {
      let closed = false;
      index++;
      while (index < content.length) {
        const current = content[index] ?? "";
        if (current === "\\") {
          index += 2;
          continue;
        }
        if (current === "`") {
          index++;
          closed = true;
          break;
        }
        index++;
      }
      if (!closed) return { tokens, valid: false, conclusive: false };
      tokens.push({ kind: "other", value: "template" });
      continue;
    }
    if (/[A-Za-z_$]/.test(char)) {
      let end = index + 1;
      while (end < content.length && /[A-Za-z0-9_$]/.test(content[end] ?? "")) end++;
      tokens.push({ kind: "identifier", value: content.slice(index, end) });
      index = end;
      continue;
    }
    if (char === "=" && next === ">") {
      tokens.push({ kind: "punctuation", value: "=>" });
      index += 2;
      continue;
    }
    if ("{}[]():,;.=".includes(char)) {
      tokens.push({ kind: "punctuation", value: char });
      index++;
      continue;
    }
    tokens.push({ kind: "other", value: char });
    index++;
  }
  return { tokens, valid: true, conclusive: true };
}

function matchingToken(
  tokens: readonly JavaScriptToken[],
  start: number,
  open: string,
  close: string,
): number | undefined {
  if (!javascriptPunctuation(tokens[start], open)) return undefined;
  let depth = 0;
  for (let index = start; index < tokens.length; index++) {
    if (javascriptPunctuation(tokens[index], open)) depth++;
    else if (javascriptPunctuation(tokens[index], close) && --depth === 0) return index;
  }
  return undefined;
}

function staticExpoObjectAt(tokens: readonly JavaScriptToken[], start: number): boolean {
  const end = matchingToken(tokens, start, "{", "}");
  if (end === undefined) return false;
  let propertyStart = true;

  for (let index = start + 1; index < end; index++) {
    const token = tokens[index];
    if (!token) continue;

    if (
      propertyStart &&
      (token.kind === "identifier" || token.kind === "string") &&
      javascriptPunctuation(tokens[index + 1], ":")
    ) {
      const value = tokens[index + 2];
      if (token.value === "expo" && javascriptPunctuation(value, "{")) return true;
      propertyStart = false;
      index++;
      continue;
    }

    if (javascriptPunctuation(token, ",")) {
      propertyStart = true;
      continue;
    }
    const structural = token?.kind === "punctuation" && ["{", "[", "("].includes(token.value)
      ? token.value
      : undefined;
    if (structural) {
      const closing = structural === "{" ? "}" : structural === "[" ? "]" : ")";
      const nestedEnd = matchingToken(tokens, index, structural, closing);
      if (nestedEnd === undefined) return false;
      index = nestedEnd;
      continue;
    }
    propertyStart = false;
  }

  return false;
}

function returnedStaticExpoObject(
  tokens: readonly JavaScriptToken[],
  blockStart: number,
): boolean {
  const blockEnd = matchingToken(tokens, blockStart, "{", "}");
  if (blockEnd === undefined) return false;
  for (let index = blockStart + 1; index < blockEnd; index++) {
    const token = tokens[index];
    if (javascriptIdentifier(token, "return")) {
      let candidate = index + 1;
      if (javascriptPunctuation(tokens[candidate], "(")) candidate++;
      if (javascriptPunctuation(tokens[candidate], "{") && staticExpoObjectAt(tokens, candidate)) return true;
    }
    const structural = token?.kind === "punctuation" && ["{", "[", "("].includes(token.value)
      ? token.value
      : undefined;
    if (structural) {
      const closing = structural === "{" ? "}" : structural === "[" ? "]" : ")";
      const nestedEnd = matchingToken(tokens, index, structural, closing);
      if (nestedEnd === undefined) return false;
      index = nestedEnd;
    }
  }
  return false;
}

function exportedExpressionHasStaticExpoObject(
  tokens: readonly JavaScriptToken[],
  expressionStart: number,
  resolveIdentifier = true,
): boolean {
  const first = tokens[expressionStart];
  if (!first) return false;
  if (javascriptPunctuation(first, "{")) return staticExpoObjectAt(tokens, expressionStart);
  if (javascriptIdentifier(first, "function")) {
    let parameters = expressionStart + 1;
    if (tokens[parameters]?.kind === "identifier") parameters++;
    if (!javascriptPunctuation(tokens[parameters], "(")) return false;
    const parametersEnd = matchingToken(tokens, parameters, "(", ")");
    if (parametersEnd === undefined) return false;
    const body = tokens.findIndex((token, index) =>
      index > parametersEnd && javascriptPunctuation(token, "{")
    );
    return body >= 0 && returnedStaticExpoObject(tokens, body);
  }
  if (javascriptPunctuation(first, "(")) {
    const closing = matchingToken(tokens, expressionStart, "(", ")");
    if (closing === undefined) return false;
    if (javascriptPunctuation(tokens[closing + 1], "=>")) {
      const body = closing + 2;
      if (javascriptPunctuation(tokens[body], "(")) {
        return javascriptPunctuation(tokens[body + 1], "{") && staticExpoObjectAt(tokens, body + 1);
      }
      return javascriptPunctuation(tokens[body], "{") && returnedStaticExpoObject(tokens, body);
    }
    return javascriptPunctuation(tokens[expressionStart + 1], "{") &&
      staticExpoObjectAt(tokens, expressionStart + 1);
  }
  if (javascriptPunctuation(tokens[expressionStart + 1], "=>")) {
    const body = expressionStart + 2;
    if (javascriptPunctuation(tokens[body], "(")) {
      return javascriptPunctuation(tokens[body + 1], "{") && staticExpoObjectAt(tokens, body + 1);
    }
    return javascriptPunctuation(tokens[body], "{") && returnedStaticExpoObject(tokens, body);
  }
  if (first.kind === "identifier" && resolveIdentifier) {
    for (let index = expressionStart - 1; index >= 0; index--) {
      if (
        !javascriptIdentifier(tokens[index], "const") ||
        tokens[index + 1]?.kind !== "identifier" ||
        tokens[index + 1]?.value !== first.value
      ) continue;
      let initializer = index + 2;
      while (
        initializer < expressionStart &&
        !javascriptPunctuation(tokens[initializer], "=") &&
        !javascriptPunctuation(tokens[initializer], ";")
      ) initializer++;
      if (!javascriptPunctuation(tokens[initializer], "=")) return false;
      return exportedExpressionHasStaticExpoObject(tokens, initializer + 1, false);
    }
  }
  return false;
}

function dynamicConfigHasStaticExpoObject(content: string): {
  detected: boolean;
  valid: boolean;
  conclusive: boolean;
} {
  const lexed = tokenizeJavaScript(content);
  if (!lexed.valid) return { detected: false, valid: false, conclusive: false };
  if (!lexed.conclusive) return { detected: false, valid: true, conclusive: false };
  const { tokens } = lexed;

  for (let index = 0; index < tokens.length; index++) {
    let expressionStart: number | undefined;
    if (javascriptIdentifier(tokens[index], "export") && javascriptIdentifier(tokens[index + 1], "default")) {
      expressionStart = index + 2;
    } else if (
      javascriptIdentifier(tokens[index], "module") &&
      javascriptPunctuation(tokens[index + 1], ".") &&
      javascriptIdentifier(tokens[index + 2], "exports") &&
      javascriptPunctuation(tokens[index + 3], "=")
    ) {
      expressionStart = index + 4;
    } else if (
      javascriptIdentifier(tokens[index], "exports") &&
      javascriptPunctuation(tokens[index + 1], ".") &&
      javascriptIdentifier(tokens[index + 2], "default") &&
      javascriptPunctuation(tokens[index + 3], "=")
    ) {
      expressionStart = index + 4;
    }
    if (
      expressionStart !== undefined &&
      exportedExpressionHasStaticExpoObject(tokens, expressionStart)
    ) {
      return { detected: true, valid: true, conclusive: true };
    }
  }
  return { detected: false, valid: true, conclusive: true };
}

function addExpoDetection(state: DetectionState, evidence: string): void {
  addDetection(state, "expo", evidence);
  addDetection(state, "react-native", evidence, "medium");
}

async function isExpoProjectRoot(absolutePath: string, relativePath: string): Promise<boolean> {
  const normalized = forwardSlash(relativePath);
  const segments = normalized.toLowerCase().split("/");
  const directorySegments = segments.slice(0, -1);
  if (directorySegments.some((segment) => PLATFORM_CORPUS_DIRECTORIES.has(segment))) return false;
  if (directorySegments.length === 0) return true;

  try {
    const packageInfo = await lstat(join(dirname(absolutePath), "package.json"));
    return packageInfo.isFile();
  } catch {
    return false;
  }
}

async function readBoundedManifest(
  absolutePath: string,
  evidencePath: string,
  state: DetectionState,
  maxBytes = MAX_MANIFEST_BYTES,
): Promise<string | undefined> {
  if (state.manifestReadsStopped) return undefined;
  if (state.manifestsRead >= state.limits.maxManifestFiles) {
    addLimitation(state, evidencePath, "manifest_count_limit_reached");
    state.manifestReadsStopped = true;
    return undefined;
  }

  try {
    const info = await lstat(absolutePath);
    if (info.isSymbolicLink()) {
      addLimitation(state, evidencePath, "symlink_skipped");
      return undefined;
    }
    if (!info.isFile()) {
      addLimitation(state, evidencePath, "file_unreadable");
      return undefined;
    }
    if (info.size > maxBytes) {
      addLimitation(state, evidencePath, "file_too_large");
      return undefined;
    }

    const remainingBytes = state.limits.maxManifestBytes - state.manifestBytesRead;
    if (remainingBytes <= 0 || info.size > remainingBytes) {
      addLimitation(state, evidencePath, "manifest_bytes_limit_reached");
      state.manifestReadsStopped = true;
      return undefined;
    }

    state.manifestsRead++;
    const handle = await open(absolutePath, "r");
    try {
      const openedInfo = await handle.stat();
      if (openedInfo.dev !== info.dev || openedInfo.ino !== info.ino || !openedInfo.isFile()) {
        addLimitation(state, evidencePath, "file_unreadable");
        return undefined;
      }
      if (openedInfo.size > maxBytes) {
        addLimitation(state, evidencePath, "file_too_large");
        return undefined;
      }
      if (openedInfo.size > remainingBytes) {
        addLimitation(state, evidencePath, "manifest_bytes_limit_reached");
        state.manifestReadsStopped = true;
        return undefined;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      const readCap = Math.min(maxBytes, remainingBytes);
      while (total <= readCap) {
        const capacity = Math.min(64 * 1024, readCap + 1 - total);
        if (capacity <= 0) break;
        const buffer = Buffer.allocUnsafe(capacity);
        const { bytesRead } = await handle.read(buffer, 0, capacity, null);
        if (bytesRead === 0) break;
        chunks.push(buffer.subarray(0, bytesRead));
        total += bytesRead;
        state.manifestBytesRead += Math.min(
          bytesRead,
          Math.max(0, state.limits.maxManifestBytes - state.manifestBytesRead),
        );
        if (state.manifestBytesRead >= state.limits.maxManifestBytes) {
          state.manifestReadsStopped = true;
        }
      }
      if (total > readCap && readCap === remainingBytes) {
        addLimitation(state, evidencePath, "manifest_bytes_limit_reached");
        state.manifestReadsStopped = true;
        return undefined;
      }
      if (total > readCap) {
        addLimitation(state, evidencePath, "file_too_large");
        if (state.manifestBytesRead >= state.limits.maxManifestBytes) {
          state.manifestReadsStopped = true;
        }
        return undefined;
      }
      return Buffer.concat(chunks, total).toString("utf8");
    } finally {
      await handle.close();
    }
  } catch {
    addLimitation(state, evidencePath, "file_unreadable");
    return undefined;
  }
}

function detectFromPath(relativePath: string, state: DetectionState): void {
  const lower = relativePath.toLowerCase();
  const base = lower.split("/").at(-1) ?? lower;
  const extension = extname(base);

  if (JAVASCRIPT_EXTENSIONS.has(extension)) addDetection(state, "javascript", relativePath);
  if (TYPESCRIPT_EXTENSIONS.has(extension)) addDetection(state, "typescript", relativePath);
  if (extension === ".sql") addDetection(state, "sql", relativePath);
  if (extension === ".dart") addDetection(state, "dart", relativePath);
  if ([".py", ".pyi", ".pyw"].includes(extension)) addDetection(state, "python", relativePath);
  if (extension === ".go") addDetection(state, "go", relativePath);
  if (extension === ".java") addDetection(state, "java", relativePath);
  if (extension === ".cs") addDetection(state, "csharp", relativePath);
  if (extension === ".php") addDetection(state, "php", relativePath);
  if (extension === ".rs") addDetection(state, "rust", relativePath);
  if (extension === ".rb") addDetection(state, "ruby", relativePath);

  if (extension === ".vue") addDetection(state, "vue", relativePath);
  if (extension === ".svelte") addDetection(state, "svelte", relativePath);
  if (extension === ".astro") addDetection(state, "astro", relativePath);

  if (/^tsconfig(?:\.[^/]+)?\.json$/.test(base)) addDetection(state, "typescript", relativePath);
  if (isPythonDependencyManifest(base) || base === "setup.py") {
    addDetection(state, "python", relativePath);
  }
  if (base === "go.mod") addDetection(state, "go", relativePath);
  if (base === "pom.xml" || base === "build.gradle" || base === "build.gradle.kts") {
    addDetection(state, "java", relativePath, "medium");
  }
  if (extension === ".csproj" || extension === ".sln" || extension === ".slnx") {
    addDetection(state, "csharp", relativePath, "medium");
  }
  if (base === "composer.json" || base === "composer.lock") {
    addDetection(state, "php", relativePath, "medium");
  }
  if (base === "cargo.toml" || base === "cargo.lock") {
    addDetection(state, "rust", relativePath, "medium");
  }
  if (base === "gemfile" || base === "gemfile.lock" || extension === ".gemspec") {
    addDetection(state, "ruby", relativePath, "medium");
  }
  if (/^next\.config\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$/.test(base)) {
    addDetection(state, "nextjs", relativePath);
    addDetection(state, "react", relativePath, "medium");
  }
  if (/^vue\.config\.(?:js|mjs|cjs|ts|mts|cts)$/.test(base)) addDetection(state, "vue", relativePath);
  if (/^svelte\.config\.(?:js|mjs|cjs|ts|mts|cts)$/.test(base)) addDetection(state, "svelte", relativePath);
  if (/^astro\.config\.(?:js|mjs|cjs|ts|mts|cts)$/.test(base)) addDetection(state, "astro", relativePath);

  const segments = lower.split("/");
  const excludedPlatformCorpus = segments.some((segment) =>
    PLATFORM_CORPUS_DIRECTORIES.has(segment)
  );
  if (/(^|\/)supabase\/(?:config\.toml$|migrations\/|functions\/)/.test(lower)) {
    addDetection(state, "supabase", relativePath);
  }

  if (
    !excludedPlatformCorpus &&
    (base === "firebase.json" || base === ".firebaserc" || base === "firestore.rules" ||
      base === "storage.rules" || base === "database.rules.json")
  ) {
    addDetection(state, "firebase", relativePath);
  }

  const excludedWorkflowCorpus = excludedPlatformCorpus ||
    segments.some((segment) => segment === "fixture" || segment === "fixtures" || segment === "spec");
  if (
    !excludedWorkflowCorpus &&
    /^\.github\/workflows\/[^/]+\.ya?ml$/.test(lower)
  ) {
    addDetection(state, "github-actions", relativePath);
  }

  if (
    !excludedPlatformCorpus &&
    base === "androidmanifest.xml" &&
    ((segments.includes("src") && segments.includes("main")) || segments.length === 1)
  ) {
    addDetection(state, "android", relativePath);
  }

  if (
    !excludedPlatformCorpus && (
      (segments.includes("ios") && (
        base === "info.plist" ||
        base === "podfile" ||
        base.endsWith(".entitlements")
      )) ||
    (segments.includes("ios") && base === "project.pbxproj" &&
      segments.some((segment) => segment.endsWith(".xcodeproj")))
    )
  ) {
    addDetection(state, "ios", relativePath);
  }

  if (base === "pubspec.yaml" || base === "pubspec.yml" || base === "pubspec.lock") {
    addDetection(state, "dart", relativePath);
  }
}

async function detectFromManifest(
  absolutePath: string,
  relativePath: string,
  state: DetectionState,
): Promise<void> {
  const base = basename(relativePath).toLowerCase();

  if (isPythonDependencyManifest(base)) {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    const parsed = parsePythonDependencyManifest(base, content);
    if (!parsed.valid) {
      addLimitation(state, relativePath, "manifest_invalid");
      return;
    }
    addPythonDependencyDetections(state, parsed.names, relativePath);
    return;
  }

  if (base === "go.mod") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    const withoutComments = content.replace(/\/\/[^\n\r]*/g, " ");
    if (/(?:^|\s)github\.com\/openai\/openai-go(?:\/v\d+)?(?:\s|$)/m.test(withoutComments)) {
      addDetection(state, "openai", relativePath);
    }
    return;
  }

  if (base === "pom.xml") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    const withoutComments = content.replace(/<!--[\s\S]*?-->/g, " ");
    for (const dependency of withoutComments.matchAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency\s*>/gi)) {
      const body = dependency[1] ?? "";
      const group = body.match(/<groupId\s*>\s*([^<\s]+)\s*<\/groupId\s*>/i)?.[1];
      const artifact = body.match(/<artifactId\s*>\s*([^<\s]+)\s*<\/artifactId\s*>/i)?.[1];
      if (group === "com.openai" && (artifact === "openai-java" || artifact === "openai-java-core")) {
        addDetection(state, "openai", relativePath);
        break;
      }
    }
    return;
  }

  if (base === "build.gradle" || base === "build.gradle.kts") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    const withoutComments = content.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ");
    if (/['"]com\.openai:openai-java(?:-core)?:[^'"]+['"]/.test(withoutComments)) {
      addDetection(state, "openai", relativePath);
    }
    return;
  }

  if (extname(base) === ".csproj") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    const withoutComments = content.replace(/<!--[\s\S]*?-->/g, " ");
    if (/<PackageReference\b[^>]*\bInclude\s*=\s*["']OpenAI["'][^>]*\/?\s*>/i.test(withoutComments)) {
      addDetection(state, "openai", relativePath);
    }
    return;
  }

  if (base === "composer.json") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    let manifest: unknown;
    try {
      manifest = JSON.parse(content);
    } catch {
      addLimitation(state, relativePath, "manifest_invalid");
      return;
    }
    const record = objectRecord(manifest);
    const dependencies = new Set<string>();
    for (const field of ["require", "require-dev"]) {
      const entries = objectRecord(record?.[field]);
      for (const dependency of Object.keys(entries ?? {})) dependencies.add(dependency.toLowerCase());
    }
    if (dependencies.has("openai-php/client") || dependencies.has("openai-php/laravel")) {
      addDetection(state, "openai", relativePath);
    }
    return;
  }

  if (base === "cargo.toml") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    let section = "";
    for (const rawLine of content.split(/\r?\n/)) {
      const line = stripYamlComment(rawLine).trim();
      if (!line) continue;
      const heading = /^\[([^\]]+)\]$/.exec(line)?.[1]?.toLowerCase();
      if (heading !== undefined) {
        section = heading;
        continue;
      }
      const dependencySection = section === "dependencies" ||
        section === "workspace.dependencies" ||
        /^target\..+\.dependencies$/.test(section);
      if (dependencySection && /^(?:"async-openai"|async-openai)\s*=/.test(line)) {
        addDetection(state, "openai", relativePath);
        break;
      }
    }
    return;
  }

  if (base === "gemfile" || base === "gemfile.lock" || extname(base) === ".gemspec") {
    // Gemfile.lock does not preserve dependency groups. Treat it as Ruby-language evidence only;
    // activating from a lockfile alone would turn a development-only gem into production evidence.
    if (base === "gemfile.lock") return;
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    const withoutBlockComments = content.replace(/^=begin\b[\s\S]*?^=end\b[^\n\r]*/gm, " ");
    const lines = withoutBlockComments.split(/\r?\n/).map((rawLine) => {
      let singleQuoted = false;
      let doubleQuoted = false;
      let escaped = false;
      for (let index = 0; index < rawLine.length; index++) {
        const char = rawLine[index];
        if (escaped) {
          escaped = false;
          continue;
        }
        if (char === "\\" && doubleQuoted) {
          escaped = true;
          continue;
        }
        if (char === "'" && !doubleQuoted) singleQuoted = !singleQuoted;
        else if (char === '"' && !singleQuoted) doubleQuoted = !doubleQuoted;
        else if (char === "#" && !singleQuoted && !doubleQuoted) return rawLine.slice(0, index);
      }
      return rawLine;
    });
    let excludedGroupDepth = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (/^group\b[^\n]*(?::development|:test)[^\n]*\bdo\s*$/.test(trimmed)) {
        excludedGroupDepth++;
        continue;
      }
      if (excludedGroupDepth > 0) {
        if (/\bdo\s*$/.test(trimmed) || /^(?:def|class|module|if|unless|case|begin|while|until|for)\b/.test(trimmed)) excludedGroupDepth++;
        if (/^end\b/.test(trimmed)) excludedGroupDepth--;
        continue;
      }
      const productionDependency = base === "gemfile"
        ? /^gem\s*(?:\(\s*)?['"]openai['"](?:\s*[,)]|\s*$)/.test(trimmed) &&
          !/\bgroup\s*:\s*(?::development|:test)|\bgroups\s*:\s*\[[^\]]*(?::development|:test)/.test(trimmed)
        : /\badd_(?:runtime_)?dependency\s*(?:\(\s*)?['"]openai['"](?:\s*[,)]|\s*$)/.test(trimmed) &&
          !/\badd_development_dependency\b/.test(trimmed);
      if (productionDependency) {
        addDetection(state, "openai", relativePath);
        break;
      }
    }
    return;
  }

  if (base === "project.pbxproj") {
    const segments = forwardSlash(relativePath).toLowerCase().split("/");
    if (segments.some((segment) => PLATFORM_CORPUS_DIRECTORIES.has(segment))) return;
    if (segments.includes("ios")) return; // Strong path evidence was already recorded.
    const content = await readBoundedManifest(
      absolutePath,
      relativePath,
      state,
      MAX_XCODE_PROJECT_BYTES,
    );
    if (content === undefined) return;
    const withoutComments = content
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .replace(/\/\/[^\n\r]*/g, " ");
    if (
      /\bSDKROOT\s*=\s*"?iphoneos"?\s*;/i.test(withoutComments) ||
      /\bSUPPORTED_PLATFORMS\s*=\s*(?:"[^"]*\biphoneos\b[^"]*"|\([^)]*\biphoneos\b[^)]*\)|[^;\r\n]*\biphoneos\b[^;\r\n]*)\s*;/i.test(withoutComments)
    ) {
      addDetection(state, "ios", relativePath);
    }
    return;
  }

  if (base === "package.json") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;
    let manifest: unknown;
    try {
      manifest = JSON.parse(content);
    } catch {
      addLimitation(state, relativePath, "manifest_invalid");
      return;
    }
    const dependencies = dependencyNames(manifest);
    if (dependencies.has("typescript")) addDetection(state, "typescript", relativePath, "medium");
    if (dependencies.has("react") || dependencies.has("react-dom") || dependencies.has("@vitejs/plugin-react")) {
      addDetection(state, "react", relativePath);
    }
    if (dependencies.has("react-native")) {
      addDetection(state, "react-native", relativePath);
    }
    if (dependencies.has("expo")) {
      addExpoDetection(state, relativePath);
    }
    if (dependencies.has("next")) {
      addDetection(state, "nextjs", relativePath);
      addDetection(state, "react", relativePath);
    }
    if (dependencies.has("vue") || dependencies.has("nuxt")) addDetection(state, "vue", relativePath);
    if (dependencies.has("svelte") || dependencies.has("@sveltejs/kit")) addDetection(state, "svelte", relativePath);
    if (dependencies.has("astro") || [...dependencies].some((name) => name.startsWith("@astrojs/"))) {
      addDetection(state, "astro", relativePath);
    }
    if ([...dependencies].some((name) => name.startsWith("@supabase/"))) {
      addDetection(state, "supabase", relativePath);
    }
    if (
      dependencies.has("firebase") || dependencies.has("firebase-admin") ||
      [...dependencies].some((name) => name.startsWith("@firebase/"))
    ) {
      addDetection(state, "firebase", relativePath);
    }
    return;
  }

  if (EXPO_STATIC_CONFIG_FILES.has(base) || EXPO_DYNAMIC_CONFIG_FILES.has(base)) {
    if (!(await isExpoProjectRoot(absolutePath, relativePath))) return;
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content === undefined) return;

    if (EXPO_STATIC_CONFIG_FILES.has(base)) {
      const config = parseJsonConfig(content);
      if (config === undefined) {
        addLimitation(state, relativePath, "manifest_invalid");
      } else if (hasStaticExpoObject(config)) {
        addExpoDetection(state, relativePath);
      }
      return;
    }

    const dynamicConfig = dynamicConfigHasStaticExpoObject(content);
    if (!dynamicConfig.valid) addLimitation(state, relativePath, "manifest_invalid");
    else if (!dynamicConfig.conclusive) {
      addLimitation(state, relativePath, "manifest_inconclusive");
    }
    else if (dynamicConfig.detected) addExpoDetection(state, relativePath);
    return;
  }

  if (base === "pubspec.yaml" || base === "pubspec.yml") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content !== undefined && pubspecHasFlutterSignal(content)) {
      addDetection(state, "flutter", relativePath);
      addDetection(state, "dart", relativePath);
    }
    return;
  }

  if (base === ".metadata") {
    const content = await readBoundedManifest(absolutePath, relativePath, state);
    if (content !== undefined && flutterMetadataSignal(content)) {
      addDetection(state, "flutter", relativePath);
      addDetection(state, "dart", relativePath);
    }
  }
}

async function inspectFile(
  absolutePath: string,
  root: string,
  state: DetectionState,
): Promise<void> {
  const evidencePath = relativeEvidence(root, absolutePath);
  detectFromPath(evidencePath, state);
  await detectFromManifest(absolutePath, evidencePath, state);
}

async function readBoundedDirectory(
  directory: string,
  root: string,
  state: DetectionState,
): Promise<Dirent[] | undefined> {
  const evidencePath = forwardSlash(relative(root, directory)) || ".";
  const remainingEntries = state.limits.maxEntries - state.entriesInspected;
  if (remainingEntries <= 0) {
    addLimitation(state, evidencePath, "discovery_entry_limit_reached");
    state.discoveryStopped = true;
    return undefined;
  }

  const entries: Dirent[] = [];
  try {
    const expected = await lstat(directory);
    if (expected.isSymbolicLink()) {
      addLimitation(state, evidencePath, "symlink_skipped");
      return undefined;
    }
    if (!expected.isDirectory()) {
      addLimitation(state, evidencePath, "directory_unreadable");
      return undefined;
    }
    const handle = await opendir(directory);
    try {
      const openedPath = await lstat(directory);
      if (
        openedPath.isSymbolicLink() || !openedPath.isDirectory() ||
        openedPath.dev !== expected.dev || openedPath.ino !== expected.ino
      ) {
        addLimitation(
          state,
          evidencePath,
          openedPath.isSymbolicLink() ? "symlink_skipped" : "directory_unreadable",
        );
        return undefined;
      }
      while (true) {
        const entry = await handle.read();
        if (!entry) break;
        entries.push(entry);
        if (entries.length > remainingEntries) {
          addLimitation(state, evidencePath, "discovery_entry_limit_reached");
          state.entriesInspected = state.limits.maxEntries;
          state.discoveryStopped = true;
          return undefined;
        }
      }
      const finalPath = await lstat(directory);
      if (
        finalPath.isSymbolicLink() || !finalPath.isDirectory() ||
        finalPath.dev !== expected.dev || finalPath.ino !== expected.ino
      ) {
        addLimitation(
          state,
          evidencePath,
          finalPath.isSymbolicLink() ? "symlink_skipped" : "directory_unreadable",
        );
        return undefined;
      }
    } finally {
      await handle.close().catch(() => undefined);
    }
  } catch {
    addLimitation(state, evidencePath, "directory_unreadable");
    return undefined;
  }

  state.entriesInspected += entries.length;
  entries.sort((left, right) => compareText(left.name, right.name));
  return entries;
}

async function walkDirectory(
  directory: string,
  root: string,
  state: DetectionState,
  depth = 0,
): Promise<void> {
  if (state.discoveryStopped) return;
  if (depth > state.limits.maxDepth) {
    addLimitation(
      state,
      forwardSlash(relative(root, directory)) || ".",
      "directory_depth_limit_reached",
    );
    return;
  }

  const entries = await readBoundedDirectory(directory, root, state);
  if (!entries) return;
  for (const entry of entries) {
    if (state.discoveryStopped) break;
    const absolutePath = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
      await walkDirectory(absolutePath, root, state, depth + 1);
    } else if (entry.isFile()) {
      await inspectFile(absolutePath, root, state);
    } else if (entry.isSymbolicLink()) {
      // Do not follow or read the link. The bounded filename signal lets the Pub loader report
      // the skipped lockfile as partial coverage instead of incorrectly saying it was inapplicable.
      const evidencePath = relativeEvidence(root, absolutePath);
      if (IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
      addLimitation(state, evidencePath, "symlink_skipped");
      if (entry.name.toLowerCase() === "pubspec.lock") addDetection(state, "dart", evidencePath);
    }
    // Other symlinks and special files are intentionally skipped: never leave the target tree.
  }
}

function finalizeLimitations(state: DetectionState): TechnologyInspectionLimitation[] {
  const limitations = [...state.limitations.values()].sort((left, right) => {
    const pathOrder = compareText(left.path, right.path);
    return pathOrder || compareText(left.reason, right.reason);
  });
  if (limitations.length <= MAX_LIMITATIONS) return limitations;
  return [
    ...limitations.slice(0, MAX_LIMITATIONS - 1),
    { path: ".", reason: "additional_failures_omitted" },
  ];
}

function finalizeTechnologies(state: DetectionState): DetectedTechnology[] {
  const output: DetectedTechnology[] = [];
  for (const definition of TECHNOLOGIES) {
    const evidence = state.evidence.get(definition.id);
    if (!evidence?.size) continue;
    output.push({
      id: definition.id,
      kind: definition.kind,
      confidence: state.confidence.get(definition.id) ?? "medium",
      evidence: [...evidence].sort(compareText).slice(0, MAX_EVIDENCE_PER_TECHNOLOGY),
    });
  }
  return output;
}

function clampDetectionLimit(
  requested: number | undefined,
  fallback: number,
  minimum: number,
): number {
  if (requested === undefined || !Number.isFinite(requested)) return fallback;
  return Math.max(minimum, Math.min(fallback, Math.floor(requested)));
}

function detectionLimits(
  requested: Partial<TechnologyDetectionLimits> | undefined,
): TechnologyDetectionLimits {
  return {
    maxEntries: clampDetectionLimit(
      requested?.maxEntries,
      DEFAULT_DETECTION_LIMITS.maxEntries,
      1,
    ),
    maxDepth: clampDetectionLimit(
      requested?.maxDepth,
      DEFAULT_DETECTION_LIMITS.maxDepth,
      0,
    ),
    maxManifestFiles: clampDetectionLimit(
      requested?.maxManifestFiles,
      DEFAULT_DETECTION_LIMITS.maxManifestFiles,
      1,
    ),
    maxManifestBytes: clampDetectionLimit(
      requested?.maxManifestBytes,
      DEFAULT_DETECTION_LIMITS.maxManifestBytes,
      1,
    ),
  };
}

/** Detect repository technologies without executing target code or using the network. */
export async function detectTechnologies(
  target: string,
  requestedLimits?: Partial<TechnologyDetectionLimits>,
): Promise<TechnologyDetectionResult> {
  const state: DetectionState = {
    evidence: new Map(),
    confidence: new Map(),
    limitations: new Map(),
    limits: detectionLimits(requestedLimits),
    entriesInspected: 0,
    manifestsRead: 0,
    manifestBytesRead: 0,
    discoveryStopped: false,
    manifestReadsStopped: false,
  };

  let targetInfo;
  try {
    targetInfo = await lstat(target);
  } catch {
    addLimitation(state, ".", "target_unreadable");
    return { detected_technologies: [], limitations: finalizeLimitations(state) };
  }

  if (targetInfo.isSymbolicLink()) {
    if (basename(target).toLowerCase() === "pubspec.lock") {
      addDetection(state, "dart", basename(target));
    }
    addLimitation(state, ".", "symlink_skipped");
  } else if (targetInfo.isDirectory()) {
    await walkDirectory(target, target, state);
  } else if (targetInfo.isFile()) {
    const targetBase = basename(target).toLowerCase();
    if (
      [".yml", ".yaml"].includes(extname(targetBase)) &&
      basename(dirname(target)).toLowerCase() === "workflows" &&
      basename(dirname(dirname(target))).toLowerCase() === ".github"
    ) {
      addDetection(state, "github-actions", basename(target));
    }
    if (targetBase === "androidmanifest.xml" || targetBase === "network_security_config.xml") {
      addDetection(state, "android", basename(target));
    }
    if (targetBase === "info.plist" || targetBase.endsWith(".entitlements")) {
      // These file formats are shared with other Apple platforms. An explicit
      // file target is still useful, but is weaker evidence than an iOS path or
      // an Xcode project with iphoneos/iphonesimulator settings.
      addDetection(state, "ios", basename(target), "medium");
    }
    await inspectFile(target, dirname(target), state);
  } else {
    addLimitation(state, ".", "unsupported_target");
  }

  return {
    detected_technologies: finalizeTechnologies(state),
    limitations: finalizeLimitations(state),
  };
}
