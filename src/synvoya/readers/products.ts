/**
 * Declared product versions: Adobe Commerce / Magento Open Source from `composer.lock`, and WordPress
 * core from `composer.lock` or `wp-includes/version.php`. Read-only and bounded (see walk.ts); a file
 * that cannot be parsed is reported in `skipped`, never thrown.
 *
 * `spec` is the version string as the lock or file states it (a Magento `-pN` patch level is kept);
 * `resolved` repeats it for `exact`. This is what a repository declares, not what is deployed.
 */

import type { Declaration, ReaderOptions, ReaderResult } from "../types.js";

import { readCandidate, walkCandidates, type WalkMatcher } from "./walk.js";

type Product = "adobe-commerce" | "magento-open-source" | "wordpress";

/** composer.lock is the one input that legitimately exceeds the shared 1 MiB cap. */
const LOCK_MAX_BYTES = 16 * 1024 * 1024;
const PHP_MAX_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_DECLARATIONS_PER_FILE = 64;
const MAX_DECLARATIONS_PER_SCAN = 2000;
const MAX_NOTES_PER_FILE = 64;
const MAX_NOTES_PER_SCAN = 2000;
const MAX_PACKAGES_PER_LOCK = 100_000;
/** Real locks hold a few thousand containers; JSON.parse of 16 MiB of `{}` costs ~0.5 GB, so refuse before parsing. */
const MAX_JSON_CONTAINERS = 400_000;
const MAX_SCAN_BYTES = 64 * 1024 * 1024;
const MAX_RAW_CHARS = 128;
/** vendor/<org>/<package>/wp-includes/version.php is four directories below vendor. */
const VENDOR_WALK = { maxDepth: 5, maxEntries: 20_000 } as const;

const LOCK_MATCHERS: readonly WalkMatcher[] = [{ basename: "composer.lock" }];
const PHP_MATCHERS: readonly WalkMatcher[] = [{ basename: "version.php", suffix: "wp-includes/version.php" }];

const ENTERPRISE = "magento/product-enterprise-edition";
const COMMUNITY = ["magento/product-community-edition", "magento/magento2-base"] as const;
const WORDPRESS = ["roots/wordpress", "roots/wordpress-no-content", "johnpbloch/wordpress-core"] as const;
const INTERESTING: ReadonlySet<string> = new Set([ENTERPRISE, ...COMMUNITY, ...WORDPRESS]);

class Malformed extends Error {}
/** Valid but too large to parse safely (memory), as opposed to Malformed. */
class Oversized extends Error {}

interface Ctx {
  file: string;
  out: Declaration[];
  notes: string[];
  /** Some of the file was not read (a per-file cap or bound): it is reported as skipped "capped", never parsed. */
  capped?: boolean;
}

function note(ctx: Ctx, text: string): void {
  if (ctx.notes.length < MAX_NOTES_PER_FILE) ctx.notes.push(text);
}

function clip(text: string): string {
  return text.length > MAX_RAW_CHARS ? `${text.slice(0, MAX_RAW_CHARS)}…` : text;
}

// ---- version classification ----

function classify(product: Product, raw: string): { spec: string; exact: boolean } {
  const spec = raw.trim().replace(/^v(?=\d)/, "");
  // WordPress names its x.y.0 releases "x.y"; Magento and Adobe Commerce always carry three parts.
  const pattern = product === "wordpress"
    ? /^\d+\.\d+(?:\.\d+)?(?:[-+._A-Za-z][0-9A-Za-z.+_-]*)?$/
    : /^\d+\.\d+\.\d+(?:[-+._A-Za-z][0-9A-Za-z.+_-]*)?$/;
  return { spec, exact: pattern.test(spec) && spec.length <= MAX_RAW_CHARS };
}

function emit(ctx: Ctx, product: Product, raw: string, line: number, source: string): void {
  if (ctx.out.length >= MAX_DECLARATIONS_PER_FILE) {
    ctx.capped = true;
    return;
  }
  const { spec, exact } = classify(product, raw);
  if (!exact) {
    note(ctx, `${ctx.file}:${line}: ${source} "${clip(spec)}" does not name a resolvable version; no ${product} finding is possible for it.`);
  }
  ctx.out.push({
    subject: { type: "product", product },
    spec: clip(spec),
    ...(exact ? { resolved: spec } : {}),
    precision: exact ? "exact" : "unresolved",
    file: ctx.file,
    line,
    source,
  });
}

// ---- composer.lock ----

/**
 * One pass over a composer.lock: rejects nesting past MAX_JSON_DEPTH (Malformed) and records the
 * 1-based line of the first `"name"` key of each `packages` / `packages-dev` entry whose value is one
 * of INTERESTING (keyed `section\0name`). Also refuses more than MAX_JSON_CONTAINERS `{`/`[` (Oversized)
 * before anything is parsed. Linear time; memory bounded by the six names looked up.
 */
function scanLock(text: string): Map<string, number> {
  const lines = new Map<string, number>();
  interface Frame { object: boolean; key?: string }
  const frames: Frame[] = [];
  let line = 1;
  let containers = 0;
  for (let at = 0; at < text.length; at++) {
    const ch = text.charCodeAt(at);
    if (ch === 10) line++;
    else if (ch === 123 || ch === 91) {
      if (frames.length >= MAX_JSON_DEPTH) throw new Malformed();
      if (++containers > MAX_JSON_CONTAINERS) throw new Oversized();
      frames.push({ object: ch === 123 });
    } else if (ch === 125 || ch === 93) frames.pop();
    else if (ch === 34) {
      let end = at + 1;
      while (end < text.length && text.charCodeAt(end) !== 34) end += text.charCodeAt(end) === 92 ? 2 : 1;
      const top = frames[frames.length - 1];
      if (top?.object) {
        let after = end + 1;
        while (after < text.length && /\s/.test(text[after]!)) after++;
        if (text[after] === ":") {
          top.key = text.slice(at + 1, end);
          // frames: root object, section array, package object.
          const section = frames[0]?.key;
          if (frames.length === 3 && top.key === "name" && (section === "packages" || section === "packages-dev")) {
            let value = after + 1;
            while (value < text.length && /\s/.test(text[value]!)) value++;
            if (text[value] === '"') {
              let close = value + 1;
              while (close < text.length && text.charCodeAt(close) !== 34) close += text.charCodeAt(close) === 92 ? 2 : 1;
              const name = text.slice(value + 1, close);
              const id = `${section}\0${name}`;
              if (INTERESTING.has(name) && !lines.has(id)) lines.set(id, line);
            }
          }
        }
      }
      at = end;
    }
  }
  return lines;
}

interface LockPackage { name: string; version: string; line: number }

function lockPackages(ctx: Ctx, text: string): LockPackage[] {
  const lines = scanLock(text);
  let root: unknown;
  try {
    root = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Malformed();
  }
  if (root === null || typeof root !== "object" || Array.isArray(root)) throw new Malformed();
  const found: LockPackage[] = [];
  let seen = 0;
  for (const section of ["packages", "packages-dev"] as const) {
    const list = (root as Record<string, unknown>)[section];
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      if (++seen > MAX_PACKAGES_PER_LOCK) {
        ctx.capped = true;
        note(ctx, `${ctx.file}: more than ${MAX_PACKAGES_PER_LOCK} packages; the rest is ignored`);
        return found;
      }
      if (entry === null || typeof entry !== "object") continue;
      const { name, version } = entry as Record<string, unknown>;
      if (typeof name !== "string" || typeof version !== "string" || !INTERESTING.has(name)) continue;
      found.push({ name, version, line: lines.get(`${section}\0${name}`) ?? 1 });
    }
  }
  return found;
}

function readLock(ctx: Ctx, text: string): void {
  const packages = lockPackages(ctx, text);
  const first = (names: readonly string[]): LockPackage | undefined => {
    for (const name of names) {
      const hit = packages.find((entry) => entry.name === name);
      if (hit !== undefined) return hit;
    }
    return undefined;
  };

  // Enterprise ships on top of the community base, so it wins: one Magento-family declaration per lock.
  const enterprise = first([ENTERPRISE]);
  const community = enterprise === undefined ? first(COMMUNITY) : undefined;
  if (enterprise !== undefined) emit(ctx, "adobe-commerce", enterprise.version, enterprise.line, `composer.lock ${enterprise.name}`);
  else if (community !== undefined) emit(ctx, "magento-open-source", community.version, community.line, `composer.lock ${community.name}`);

  // roots/wordpress is a metapackage of roots/wordpress-no-content: report each distinct version once.
  const versions = new Set<string>();
  for (const name of WORDPRESS) {
    for (const entry of packages) {
      if (entry.name !== name || versions.has(entry.version)) continue;
      versions.add(entry.version);
      emit(ctx, "wordpress", entry.version, entry.line, `composer.lock ${entry.name}`);
    }
  }
}

// ---- wp-includes/version.php ----

/**
 * `text` with PHP comments (`//`, `#` not starting a `#[` attribute, and block comments) replaced by
 * spaces, newlines kept so offsets and line numbers still match the original. One linear pass that
 * respects quoted strings, so a comment marker inside a string is left alone.
 */
function blankComments(text: string): string {
  const parts: string[] = [];
  let from = 0;
  let at = 0;
  const blank = (start: number, end: number): void => {
    parts.push(text.slice(from, start), text.slice(start, end).replace(/[^\r\n]/g, " "));
    from = end;
  };
  while (at < text.length) {
    const ch = text[at]!;
    if (ch === "'" || ch === '"') {
      at++;
      while (at < text.length && text[at] !== ch) at += text[at] === "\\" ? 2 : 1;
      at++;
    } else if (ch === "#" && text[at + 1] !== "[" || ch === "/" && text[at + 1] === "/") {
      let end = at;
      while (end < text.length && text[end] !== "\n" && text[end] !== "\r") end++;
      blank(at, end);
      at = end;
    } else if (ch === "/" && text[at + 1] === "*") {
      const close = text.indexOf("*/", at + 2);
      const end = close === -1 ? text.length : close + 2;
      blank(at, end);
      at = end;
    } else at++;
  }
  parts.push(text.slice(from));
  return parts.join("");
}

/** The first `$wp_version = …;` that starts a line or follows `<?php` / `;` (so comments never match). */
const WP_VERSION = /(?:^|<\?php|;)[ \t]*(\$wp_version)[ \t]*=[ \t]*([^;\r\n]{0,256});/m;

function readVersionPhp(ctx: Ctx, text: string): void {
  const body = blankComments(text.replace(/^﻿/, ""));
  const match = WP_VERSION.exec(body);
  if (match === null) return;
  const offset = match.index + match[0].indexOf(match[1]!);
  let line = 1;
  for (let at = body.indexOf("\n"); at !== -1 && at < offset; at = body.indexOf("\n", at + 1)) line++;
  const value = match[2]!.trim();
  const quoted = /^(["'])([^"'\\]*)\1$/.exec(value);
  if (quoted === null || (quoted[1] === '"' && quoted[2]!.includes("$"))) {
    note(ctx, `${ctx.file}:${line}: wp-includes/version.php $wp_version is not a literal string ("${clip(value)}"); no wordpress finding is possible for it.`);
    ctx.out.push({
      subject: { type: "product", product: "wordpress" },
      spec: clip(value),
      precision: "unresolved",
      file: ctx.file,
      line,
      source: "wp-includes/version.php $wp_version",
    });
    return;
  }
  emit(ctx, "wordpress", quoted[2]!, line, "wp-includes/version.php $wp_version");
}

// ---- entry point ----

export async function readProducts(target: string, options: ReaderOptions = {}): Promise<ReaderResult> {
  const result: ReaderResult = { declarations: [], parsed: [], skipped: [], notes: [] };
  try {
    const locks = await walkCandidates(target, LOCK_MATCHERS, { maxFileBytes: LOCK_MAX_BYTES }, { signal: options.signal, only: options.only });
    const php = await walkCandidates(target, PHP_MATCHERS, { maxFileBytes: PHP_MAX_BYTES }, { vendor: VENDOR_WALK, signal: options.signal, only: options.only });
    for (const entry of locks.skipped) result.skipped.push(entry);
    for (const entry of php.skipped) result.skipped.push(entry);

    const queue: Array<{ file: string; lock: boolean }> = [];
    for (const file of locks.files) queue.push({ file, lock: true });
    for (const file of php.files) {
      if (file === "wp-includes/version.php" || file.endsWith("/wp-includes/version.php")) queue.push({ file, lock: false });
    }

    let consumed = 0;
    for (const { file, lock } of queue) {
      if (options.signal?.aborted) {
        result.skipped.push({ file, reason: "deadline" });
        continue;
      }
      if (consumed >= MAX_SCAN_BYTES) {
        if (!result.skipped.some((entry) => entry.reason === "budget")) {
          result.notes.push(`${file}: more than ${MAX_SCAN_BYTES / (1024 * 1024)} MiB read in this scan (scan budget); the remaining files are skipped`);
        }
        result.skipped.push({ file, reason: "budget" });
        continue;
      }
      const text = await readCandidate(target, file, lock ? LOCK_MAX_BYTES : PHP_MAX_BYTES);
      if (text === undefined) {
        result.skipped.push({ file, reason: "unreadable" });
        continue;
      }
      consumed += text.length;
      const ctx: Ctx = { file, out: [], notes: [] };
      let scanFull = false;
      try {
        if (lock) readLock(ctx, text);
        else readVersionPhp(ctx, text);
        // Appended in loops, never spread: the arrays are bounded, but a spread's argument limit is not ours to rely on.
        for (const declaration of ctx.out) {
          if (result.declarations.length >= MAX_DECLARATIONS_PER_SCAN) {
            scanFull = true;
            const capNote = `${file}: more than ${MAX_DECLARATIONS_PER_SCAN} product declarations; extra ignored`;
            ctx.notes.push(capNote);
            (result.priorityNotes ??= []).push(capNote);
            break;
          }
          result.declarations.push(declaration);
        }
        for (const message of ctx.notes) if (result.notes.length < MAX_NOTES_PER_SCAN) result.notes.push(message);
        // A file read only in part is not a re-check of everything it declares.
        if (ctx.capped || scanFull) result.skipped.push({ file, reason: "capped" });
        else result.parsed.push(file);
      } catch (error) {
        if (error instanceof Oversized) {
          if (result.notes.length < MAX_NOTES_PER_SCAN) result.notes.push(`${file}: more than ${MAX_JSON_CONTAINERS} JSON containers; not parsed`);
          result.skipped.push({ file, reason: "oversized" });
          continue;
        }
        // Malformed content (including a RangeError from hostile input) is reported, never thrown.
        result.skipped.push({ file, reason: "malformed" });
      }
      if (scanFull) break;
    }
  } catch {
    result.notes.push("product readers stopped early: unexpected failure while reading the target");
  }
  return result;
}
