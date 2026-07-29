/**
 * Bounded, read-only Firebase Security Rules analysis.
 *
 * The parser deliberately recognizes only literal unconditional write grants in
 * checked-in Firestore, Cloud Storage, and Realtime Database rule files. It does
 * not execute Firebase tooling or target code and never follows symbolic links.
 */

import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readdir, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, join, parse, relative, resolve } from "node:path";

import { makeAiFinding } from "../../ai-checks/finding.js";
import type { Finding } from "../../types.js";
import type { NativeAnalyzerResult } from "../types.js";

export const FIREBASE_FIRESTORE_PUBLIC_WRITE_RULE_ID = "ci-firebase-firestore-public-write";
export const FIREBASE_STORAGE_PUBLIC_WRITE_RULE_ID = "ci-firebase-storage-public-write";
export const FIREBASE_DATABASE_PUBLIC_WRITE_RULE_ID = "ci-firebase-realtime-database-public-write";

export const FIREBASE_CONFIG_RULE_IDS = [
  FIREBASE_FIRESTORE_PUBLIC_WRITE_RULE_ID,
  FIREBASE_STORAGE_PUBLIC_WRITE_RULE_ID,
  FIREBASE_DATABASE_PUBLIC_WRITE_RULE_ID,
] as const;

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 1_000;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_ENTRIES = 50_000;
const MAX_NOTES = 24;

const IGNORED_DIRECTORIES = new Set([
  ".cache", ".dart_tool", ".git", ".gradle", ".idea", ".next", ".nuxt",
  ".output", ".pytest_cache", ".svelte-kit", ".vscode", "build", "cache",
  "coverage", "dist", "generated", "node_modules", "out", "target", "tmp", "vendor",
]);
const NON_PRODUCTION_DIRECTORIES = new Set([
  "demo", "demos", "example", "examples", "fixture", "fixtures", "integration-test",
  "integration-tests", "sample", "samples", "spec", "test", "testdata", "tests",
]);

interface FirebaseDocument {
  path: string;
  content: string;
  kind: "rules" | "database";
}

interface FirebaseProject {
  files: FirebaseDocument[];
  limitations: string[];
}

interface MaskedRules {
  source: string;
  valid: boolean;
}

interface ServiceBlock {
  kind: "firestore" | "storage";
  start: number;
  end: number;
}

function normalized(path: string): string {
  return path.replace(/\\/g, "/");
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(left: BigIntStats, right: BigIntStats): boolean {
  return sameIdentity(left, right) && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function candidateKind(path: string): FirebaseDocument["kind"] | undefined {
  const lower = basename(path).toLowerCase();
  if (lower === "database.rules.json") return "database";
  if (extname(lower) === ".rules") return "rules";
  return undefined;
}

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index++) {
    if (source.charCodeAt(index) === 10) line++;
  }
  return line;
}

function snippet(source: string, start: number, end: number): string {
  return source.slice(start, end).trim().replace(/\s+/g, " ").slice(0, 240);
}

function noteCollector(): { add: (note: string) => void; finish: () => string[] } {
  const notes = new Set<string>();
  let omitted = 0;
  return {
    add(note) {
      if (notes.size < MAX_NOTES - 1) notes.add(note);
      else omitted++;
    },
    finish() {
      return [...notes, ...(omitted ? [`${omitted} additional Firebase configuration limitations omitted.`] : [])]
        .sort();
    },
  };
}

async function hasSymbolicLinkAncestor(absoluteTarget: string): Promise<boolean> {
  const filesystemRoot = parse(absoluteTarget).root;
  const ancestors: string[] = [];
  let current = dirname(absoluteTarget);
  while (current !== filesystemRoot) {
    ancestors.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  for (const ancestor of ancestors.reverse()) {
    const metadata = await lstat(ancestor).catch(() => undefined);
    if (!metadata) break;
    if (metadata.isSymbolicLink()) return true;
  }
  return false;
}

async function readFirebaseFile(
  absolute: string,
  displayPath: string,
  kind: FirebaseDocument["kind"],
  remainingBytes: number,
): Promise<{ document?: FirebaseDocument; bytes?: number; limitation?: string; totalExceeded?: boolean }> {
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(absolute, { bigint: true });
    if (before.isSymbolicLink()) {
      return { limitation: `Skipped symbolic-link Firebase rule file ${displayPath}.` };
    }
    if (!before.isFile()) return {};
    if (before.size > BigInt(MAX_FILE_BYTES)) {
      return { limitation: `Skipped oversized Firebase rule file ${displayPath} (limit: ${MAX_FILE_BYTES} bytes).` };
    }
    if (before.size > BigInt(remainingBytes)) return { bytes: Number(before.size), totalExceeded: true };

    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened)) {
      return { limitation: `Skipped changed Firebase rule file ${displayPath}.` };
    }
    const size = Number(opened.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const result = await handle.read(bytes, offset, size - offset, offset);
      if (result.bytesRead === 0) {
        return { bytes: size, limitation: `Skipped changed Firebase rule file ${displayPath}.` };
      }
      offset += result.bytesRead;
    }
    if (!unchangedFile(opened, await handle.stat({ bigint: true }))) {
      return { bytes: size, limitation: `Skipped changed Firebase rule file ${displayPath}.` };
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return { bytes: size, limitation: `Skipped non-UTF-8 Firebase rule file ${displayPath}.` };
    }
    return { document: { path: normalized(displayPath), content, kind }, bytes: size };
  } catch {
    return { limitation: `Skipped unreadable Firebase rule file ${displayPath}.` };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function loadFirebaseProject(target: string): Promise<FirebaseProject> {
  const absoluteTarget = resolve(target);
  const notes = noteCollector();
  if (await hasSymbolicLinkAncestor(absoluteTarget)) {
    return {
      files: [],
      limitations: [
        "Skipped Firebase configuration target because a symbolic-link ancestor would be followed; symbolic-link ancestors are never allowed.",
      ],
    };
  }
  const targetMetadata = await lstat(absoluteTarget).catch(() => undefined);
  if (!targetMetadata) return { files: [], limitations: ["Firebase configuration target was unreadable."] };
  if (targetMetadata.isSymbolicLink()) {
    return { files: [], limitations: ["Skipped symbolic-link Firebase configuration target; symbolic links are never followed."] };
  }
  if (targetMetadata.isFile()) {
    const kind = candidateKind(absoluteTarget);
    if (!kind) return { files: [], limitations: [] };
    const loaded = await readFirebaseFile(absoluteTarget, basename(absoluteTarget), kind, MAX_TOTAL_BYTES);
    if (loaded.limitation) notes.add(loaded.limitation);
    return { files: loaded.document ? [loaded.document] : [], limitations: notes.finish() };
  }
  if (!targetMetadata.isDirectory()) return { files: [], limitations: [] };

  const files: FirebaseDocument[] = [];
  let entriesInspected = 0;
  let totalBytes = 0;
  let stopped = false;

  async function walk(directory: string, depth: number): Promise<void> {
    if (stopped) return;
    if (depth > MAX_DEPTH) {
      notes.add(`Skipped Firebase rule files below ${normalized(relative(absoluteTarget, directory)) || "."} beyond the ${MAX_DEPTH}-level depth bound.`);
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => undefined);
    if (!entries) {
      notes.add(`Skipped unreadable Firebase configuration directory ${normalized(relative(absoluteTarget, directory)) || "."}.`);
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (stopped) break;
      if (++entriesInspected > MAX_ENTRIES) {
        notes.add(`Stopped Firebase rule discovery at the ${MAX_ENTRIES}-entry bound.`);
        stopped = true;
        break;
      }
      const absolute = join(directory, entry.name);
      const displayPath = normalized(relative(absoluteTarget, absolute));
      if (entry.isSymbolicLink()) {
        if (candidateKind(entry.name)) notes.add(`Skipped symbolic-link Firebase rule file ${displayPath}.`);
        continue;
      }
      if (entry.isDirectory()) {
        const lower = entry.name.toLowerCase();
        if (!IGNORED_DIRECTORIES.has(lower) && !NON_PRODUCTION_DIRECTORIES.has(lower)) {
          await walk(absolute, depth + 1);
        }
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = candidateKind(entry.name);
      if (!kind) continue;
      if (files.length >= MAX_FILES) {
        notes.add(`Stopped Firebase rule discovery at the ${MAX_FILES}-file bound.`);
        stopped = true;
        break;
      }
      const loaded = await readFirebaseFile(absolute, displayPath, kind, MAX_TOTAL_BYTES - totalBytes);
      if (loaded.limitation) notes.add(loaded.limitation);
      if (loaded.totalExceeded) {
        notes.add(`Stopped Firebase rule discovery at the ${MAX_TOTAL_BYTES}-byte project bound.`);
        stopped = true;
        break;
      }
      totalBytes += loaded.bytes ?? 0;
      if (loaded.document) files.push(loaded.document);
    }
  }

  await walk(absoluteTarget, 0);
  return { files, limitations: notes.finish() };
}

/** Offset-preserving masker for Firebase Rules comments and quoted strings. */
function maskRules(source: string): MaskedRules {
  const output = source.split("");
  let state: "code" | "line-comment" | "block-comment" | "single" | "double" = "code";
  let escaped = false;
  for (let index = 0; index < source.length; index++) {
    const character = source[index]!;
    const next = source[index + 1];
    if (state === "code") {
      if (character === "/" && next === "/") {
        output[index] = output[index + 1] = " ";
        state = "line-comment";
        index++;
      } else if (character === "/" && next === "*") {
        output[index] = output[index + 1] = " ";
        state = "block-comment";
        index++;
      } else if (character === "'") {
        output[index] = " ";
        state = "single";
        escaped = false;
      } else if (character === '"') {
        output[index] = " ";
        state = "double";
        escaped = false;
      }
      continue;
    }
    if (state === "line-comment") {
      if (character === "\n" || character === "\r") state = "code";
      else output[index] = " ";
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        output[index] = output[index + 1] = " ";
        state = "code";
        index++;
      } else if (character !== "\n" && character !== "\r") output[index] = " ";
      continue;
    }
    if (character === "\n" || character === "\r") {
      output[index] = character;
      escaped = false;
      continue;
    }
    output[index] = " ";
    if (escaped) {
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if ((state === "single" && character === "'") || (state === "double" && character === '"')) {
      state = "code";
    }
  }
  let depth = 0;
  let bracesValid = true;
  for (const character of output) {
    if (character === "{") depth++;
    else if (character === "}" && --depth < 0) bracesValid = false;
  }
  return {
    source: output.join(""),
    valid: (state === "code" || state === "line-comment") && depth === 0 && bracesValid,
  };
}

function closingBrace(masked: string, opening: number): number | undefined {
  let depth = 0;
  for (let index = opening; index < masked.length; index++) {
    if (masked[index] === "{") depth++;
    else if (masked[index] === "}" && --depth === 0) return index;
  }
  return undefined;
}

function serviceBlocks(masked: string): ServiceBlock[] {
  const blocks: ServiceBlock[] = [];
  const patterns = [
    { kind: "firestore" as const, pattern: /\bservice\s+cloud\s*\.\s*firestore\s*\{/g },
    { kind: "storage" as const, pattern: /\bservice\s+firebase\s*\.\s*storage\s*\{/g },
  ];
  for (const { kind, pattern } of patterns) {
    for (const match of masked.matchAll(pattern)) {
      const opening = (match.index ?? 0) + match[0].lastIndexOf("{");
      const end = closingBrace(masked, opening);
      if (end !== undefined) blocks.push({ kind, start: opening + 1, end });
    }
  }
  return blocks.sort((left, right) => left.start - right.start);
}

function unwrapParentheses(value: string): string {
  let current = value.trim();
  while (current.startsWith("(") && current.endsWith(")")) {
    let depth = 0;
    let closesAtEnd = false;
    for (let index = 0; index < current.length; index++) {
      if (current[index] === "(") depth++;
      else if (current[index] === ")" && --depth === 0) {
        closesAtEnd = index === current.length - 1;
        break;
      }
    }
    if (!closesAtEnd) break;
    current = current.slice(1, -1).trim();
  }
  return current;
}

function publicWriteFinding(
  kind: ServiceBlock["kind"] | "database",
  file: string,
  line: number,
  statement: string,
): Finding {
  const ruleId = kind === "firestore"
    ? FIREBASE_FIRESTORE_PUBLIC_WRITE_RULE_ID
    : kind === "storage"
      ? FIREBASE_STORAGE_PUBLIC_WRITE_RULE_ID
      : FIREBASE_DATABASE_PUBLIC_WRITE_RULE_ID;
  const product = kind === "firestore"
    ? "Cloud Firestore"
    : kind === "storage"
      ? "Cloud Storage"
      : "Realtime Database";
  const reference = kind === "firestore"
    ? "https://firebase.google.com/docs/firestore/security/rules-conditions"
    : kind === "storage"
      ? "https://firebase.google.com/docs/storage/security/core-syntax"
      : "https://firebase.google.com/docs/database/security/core-syntax";
  return makeAiFinding({
    ruleId,
    title: `${product} rule allows public writes`,
    severity: "critical",
    cwe: ["CWE-862", "CWE-285"],
    owasp_web: ["A01:2021"],
    file,
    startLine: line,
    snippet: statement,
    message: `${product} grants write access without an authentication or authorization condition. Any unauthenticated client that can reach this Firebase resource can modify its data.`,
    remediation: {
      summary: `Require explicit authentication and resource-level authorization before ${product} writes.`,
      steps: [
        "Replace the unconditional write grant with a condition that checks request.auth or auth.",
        "Bind the authenticated identity to the specific resource, owner, tenant, or permitted role; authentication alone is not sufficient authorization.",
        "Exercise allowed and denied cases with the Firebase Emulator Suite before deployment.",
      ],
      references: [
        "CWE-862",
        "https://cwe.mitre.org/data/definitions/862.html",
        reference,
      ],
    },
    confidence: "high",
  });
}

function analyzeRulesFile(document: FirebaseDocument): { findings: Finding[]; malformed: boolean } {
  const masked = maskRules(document.content);
  if (!masked.valid) return { findings: [], malformed: true };
  const findings: Finding[] = [];
  const writeMethods = new Set(["write", "create", "update", "delete"]);
  for (const block of serviceBlocks(masked.source)) {
    const body = masked.source.slice(block.start, block.end);
    const allowPattern = /\ballow\s+([^:;{}]+?)(?:\s*:\s*if\s*([^;{}]+?))?\s*;/g;
    for (const match of body.matchAll(allowPattern)) {
      const methods = (match[1] ?? "").split(",").map((method) => method.trim().toLowerCase());
      if (!methods.some((method) => writeMethods.has(method))) continue;
      const condition = match[2];
      if (condition !== undefined && unwrapParentheses(condition).replace(/\s+/g, "") !== "true") continue;
      const start = block.start + (match.index ?? 0);
      const end = start + match[0].length;
      findings.push(publicWriteFinding(
        block.kind,
        document.path,
        lineAt(document.content, start),
        snippet(document.content, start, end),
      ));
    }
  }
  return { findings, malformed: false };
}

function jsonStringAt(source: string, start: number): { value: string; end: number } | undefined {
  if (source[start] !== '"') return undefined;
  let escaped = false;
  for (let index = start + 1; index < source.length; index++) {
    const character = source[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      try {
        return { value: JSON.parse(source.slice(start, index + 1)) as string, end: index + 1 };
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

function analyzeDatabaseFile(document: FirebaseDocument): { findings: Finding[]; malformed: boolean } {
  try {
    JSON.parse(document.content);
  } catch {
    return { findings: [], malformed: true };
  }
  const findings: Finding[] = [];
  let cursor = 0;
  while (cursor < document.content.length) {
    if (document.content[cursor] !== '"') {
      cursor++;
      continue;
    }
    const key = jsonStringAt(document.content, cursor);
    if (!key) return { findings: [], malformed: true };
    const keyStart = cursor;
    cursor = key.end;
    let separator = cursor;
    while (/\s/.test(document.content[separator] ?? "")) separator++;
    if (document.content[separator] !== ":") continue;
    let valueStart = separator + 1;
    while (/\s/.test(document.content[valueStart] ?? "")) valueStart++;
    let publicWrite = false;
    let valueEnd = valueStart;
    if (document.content.startsWith("true", valueStart)) {
      const boundary = document.content[valueStart + 4];
      publicWrite = boundary === undefined || /[\s,}\]]/.test(boundary);
      valueEnd = valueStart + 4;
    } else if (document.content[valueStart] === '"') {
      const value = jsonStringAt(document.content, valueStart);
      if (value) {
        publicWrite = value.value === "true";
        valueEnd = value.end;
      }
    }
    if (key.value === ".write" && publicWrite) {
      findings.push(publicWriteFinding(
        "database",
        document.path,
        lineAt(document.content, keyStart),
        snippet(document.content, keyStart, valueEnd),
      ));
    }
  }
  return { findings, malformed: false };
}

export async function runFirebaseConfig(target: string): Promise<NativeAnalyzerResult> {
  const project = await loadFirebaseProject(target);
  const findings: Finding[] = [];
  const notes = noteCollector();
  for (const limitation of project.limitations) notes.add(limitation);
  for (const document of project.files) {
    const result = document.kind === "rules" ? analyzeRulesFile(document) : analyzeDatabaseFile(document);
    findings.push(...result.findings);
    if (result.malformed) notes.add(`Skipped malformed Firebase rule file ${document.path}.`);
  }
  findings.sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    left.location.start_line - right.location.start_line ||
    left.rule_id.localeCompare(right.rule_id)
  );
  const limitations = notes.finish();
  return { findings, ...(limitations.length ? { notes: limitations } : {}) };
}
