/**
 * Vendored and CDN front-end libraries: the npm packages a repository ships as copied scripts or loads
 * from a public CDN. Read-only and bounded (see walk.ts); a file that cannot be read is reported in
 * `skipped`, never thrown.
 *
 * Only three kinds of evidence create a declaration, each against the reviewed library table
 * (detection-db/synvoya/libraries.json), never against free text:
 *  - `banner`: a comment that starts a line within the first 4 KiB of a `.js` / `.mjs` file and matches
 *    one of the table's anchored banner regexes (`/*! jQuery v3.1.1`, `/** @license React v17.0.2`);
 *  - `file-name`: `<stem>-<version>(.min).js` or `<stem>.<version>.js` with a table stem;
 *  - `cdn-url`: a URL on one of the listed CDN hosts that names a table library with an explicit version.
 * A name inside a string literal, a banner after byte 4096 or mid-line, and a URL without a version never
 * make an exact declaration.
 *
 * Versions: x.y.z is exact, x or x.y floats, anything else (`latest`, a range, no version) is unresolved
 * and noted. `spec` is the version as written with a leading `v` removed.
 */

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";

import type { Declaration, LibraryTable, ReaderOptions, ReaderResult } from "../types.js";

import { walkCandidates, type WalkMatcher } from "./walk.js";

type Source = "banner" | "file-name" | "cdn-url";

/** Banner comments are looked for here only. */
const HEAD_BYTES = 4096;
const MAX_BANNER_COMMENTS = 8;
const MAX_COMMENT_LINES = 64;
const MAX_COMMENT_CHARS = 1024;
/** Text read per file; a larger file is read to here and reported as capped. */
const MAX_READ_BYTES = 1024 * 1024;
/** The walk lists a file up to here (a bundle may be large; only its first MAX_READ_BYTES are read). */
const WALK_MAX_BYTES = 64 * 1024 * 1024;
const MAX_DECLARATIONS_PER_FILE = 64;
const MAX_DECLARATIONS_PER_SCAN = 2000;
const MAX_NOTES_PER_FILE = 64;
const MAX_NOTES_PER_SCAN = 2000;
const MAX_SCAN_BYTES = 128 * 1024 * 1024;
const MAX_RAW_CHARS = 128;
const MAX_NAME_CHARS = 200;
/** assets/vendor/<lib>/dist/<lib>.js is a few directories below vendor. */
const VENDOR_WALK = { maxDepth: 6, maxEntries: 20_000 } as const;

const SUFFIXES = [".js", ".mjs", ".html", ".htm", ".php", ".twig", ".erb", ".vue", ".svelte", ".jsx", ".tsx", ".ejs", ".hbs"] as const;
const MATCHERS: readonly WalkMatcher[] = SUFFIXES.map((suffix) => ({ suffix }));

/**
 * `vendor/` and `vendors/` are entered by the walk wherever they are (never `node_modules/`), but only one
 * under a web asset root (or Rails' own `vendor/assets/`) holds copied front-end libraries; the rest is a
 * dependency manager's tree (Composer, Bundler) that other engines own.
 */
const ASSET_ROOTS: ReadonlySet<string> = new Set(["public", "static", "assets", "web", "wp-content"]);

/** Hosts whose URLs are read; the path after the host is bounded so one match is bounded work. */
const URL_PATTERN =
  "(?:https?:)?\\/\\/(cdnjs\\.cloudflare\\.com|cdn\\.jsdelivr\\.net|unpkg\\.com|code\\.jquery\\.com|stackpath\\.bootstrapcdn\\.com|ajax\\.googleapis\\.com)\\/([^\\s\"'<>()`\\\\,;|{}\\[\\]]{1,300})";
const URL_RE = new RegExp(URL_PATTERN, "gi");

interface Compiled {
  banners: Array<{ npm: string; re: RegExp }>;
  stems: Map<string, string>;
  cdn: Map<string, string>;
}

const compiled = new WeakMap<LibraryTable, Compiled>();

function compile(table: LibraryTable): Compiled {
  const cached = compiled.get(table);
  if (cached) return cached;
  const result: Compiled = { banners: [], stems: new Map(), cdn: new Map() };
  for (const library of table.libraries) {
    for (const source of library.banners) result.banners.push({ npm: library.npm, re: new RegExp(source) });
    for (const stem of library.fileStems) result.stems.set(stem.toLowerCase(), library.npm);
    for (const path of library.cdnPaths) result.cdn.set(path.toLowerCase(), library.npm);
  }
  compiled.set(table, result);
  return result;
}

interface Ctx {
  file: string;
  out: Declaration[];
  notes: string[];
  seen: Set<string>;
  /** The per-file declaration cap was reached: nothing more is read from this file. */
  stop: boolean;
  /** Some of the file was not read (a cap or a bound): it is reported as skipped "capped", never parsed. */
  capped: boolean;
  unjudged: boolean;
}

function note(ctx: Ctx, text: string): void {
  if (ctx.notes.length < MAX_NOTES_PER_FILE) ctx.notes.push(text);
}

function clip(text: string): string {
  return text.length > MAX_RAW_CHARS ? `${text.slice(0, MAX_RAW_CHARS)}…` : text;
}

// ---- versions ----

function classify(raw: string | undefined): { spec: string; precision: "exact" | "floating" | "unresolved" } {
  const spec = clip((raw ?? "").trim().replace(/^v(?=\d)/i, ""));
  // Only a known pre-release marker keeps a version exact: `3.7.1-custom` or `3.7.1+build` is not a release the advisory ranges can order.
  if (spec.length < MAX_RAW_CHARS && /^\d+\.\d+\.\d+(?:-(?:alpha|beta|rc|pre|next)(?:[.-]?\d+){0,4})?$/.test(spec)) return { spec, precision: "exact" };
  if (/^\d+(?:\.\d+)?(?:\.[xX*])*$/.test(spec)) return { spec, precision: "floating" };
  return { spec, precision: "unresolved" };
}

function emit(ctx: Ctx, npm: string, raw: string | undefined, line: number, source: Source): void {
  if (ctx.stop) return;
  const { spec, precision } = classify(raw);
  const key = `${npm}\0${spec}`;
  if (ctx.seen.has(key)) return;
  if (ctx.out.length >= MAX_DECLARATIONS_PER_FILE) {
    ctx.stop = true;
    ctx.capped = true;
    note(ctx, `${ctx.file}: more than ${MAX_DECLARATIONS_PER_FILE} library declarations; extra ignored`);
    return;
  }
  ctx.seen.add(key);
  if (precision === "unresolved") {
    ctx.unjudged = true;
    note(ctx, `${ctx.file}:${line}: ${source} names ${npm} without a resolvable version ("${spec === "" ? "none" : spec}"); no finding is possible for it.`);
  }
  ctx.out.push({
    subject: { type: "package", ecosystem: "npm", name: npm },
    spec,
    ...(precision === "exact" ? { resolved: spec } : {}),
    precision,
    file: ctx.file,
    line,
    source,
    ...(precision === "unresolved" ? { noted: true as const } : {}),
  });
}

// ---- banners ----

interface Comment {
  text: string;
  line: number;
}

/** A block comment's inner text without a leading `!` or `*` and the ` * ` gutter of each line. */
function blockText(inner: string): string {
  return inner
    .replace(/\r/g, "")
    .replace(/^[!*]+/, "")
    .split("\n")
    .map((line) => line.replace(/^[ \t]*\*+[ \t]?/, ""))
    .join("\n")
    .trim()
    .slice(0, MAX_COMMENT_CHARS);
}

/**
 * The comments within `head` that start a line (after blanks): block comments and runs of `//` lines.
 * One pass: a block comment is skipped as a whole, so the work is linear in `head` however many openers
 * it holds, and a comment marker inside code or a string that does not start a line is never one.
 * When `truncated` (the file goes on past the head), a block comment with no end inside the head and a
 * final `//` line cut at the head's edge are dropped: their version may be cut short (3.7.1 for 3.7.10).
 */
function lineStartComments(head: string, truncated: boolean): Comment[] {
  const comments: Comment[] = [];
  let pos = 0;
  let line = 1;
  while (pos < head.length && comments.length < MAX_BANNER_COMMENTS) {
    let eol = head.indexOf("\n", pos);
    if (eol === -1) eol = head.length;
    let at = pos;
    while (at < eol && (head.charCodeAt(at) === 32 || head.charCodeAt(at) === 9)) at++;
    if (head.startsWith("/*", at)) {
      const close = head.indexOf("*/", at + 2);
      if (close === -1 && truncated) break;
      const end = close === -1 ? head.length : close + 2;
      comments.push({ text: blockText(head.slice(at + 2, close === -1 ? end : close)), line });
      let newlines = 0;
      for (let nl = head.indexOf("\n", pos); nl !== -1 && nl < end; nl = head.indexOf("\n", nl + 1)) newlines++;
      const next = head.indexOf("\n", end);
      pos = next === -1 ? head.length : next + 1;
      line += newlines + 1;
    } else if (head.startsWith("//", at)) {
      const start = line;
      const lines: string[] = [];
      let cut = false;
      while (pos < head.length && lines.length < MAX_COMMENT_LINES) {
        let lineEnd = head.indexOf("\n", pos);
        if (lineEnd === -1) {
          if (truncated) {
            cut = true;
            break;
          }
          lineEnd = head.length;
        }
        let from = pos;
        while (from < lineEnd && (head.charCodeAt(from) === 32 || head.charCodeAt(from) === 9)) from++;
        if (!head.startsWith("//", from)) break;
        lines.push(head.slice(from, lineEnd).replace(/^\/\/[!/]?[ \t]*/, "").replace(/\r$/, ""));
        pos = lineEnd + 1;
        line++;
      }
      if (lines.length > 0) comments.push({ text: lines.join("\n").trim().slice(0, MAX_COMMENT_CHARS), line: start });
      if (cut) break;
    } else {
      pos = eol + 1;
      line++;
    }
  }
  return comments;
}

function readBanners(ctx: Ctx, head: string, headTruncated: boolean, table: Compiled): void {
  if (table.banners.length === 0) return;
  for (const comment of lineStartComments(head, headTruncated)) {
    if (comment.text === "") continue;
    for (const banner of table.banners) {
      const match = banner.re.exec(comment.text);
      if (match !== null) {
        emit(ctx, banner.npm, match[1], comment.line, "banner");
        break;
      }
    }
  }
}

// ---- file names ----

const FILE_NAME = /^(.+?)[-.](\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)((?:\.(?:min|slim|bundle))*)\.m?js$/;

function readFileName(ctx: Ctx, base: string, table: Compiled): void {
  if (base.length > MAX_NAME_CHARS) return;
  const match = FILE_NAME.exec(base);
  if (match === null) return;
  const npm = table.stems.get(match[1]!.toLowerCase());
  if (npm === undefined) return;
  // A pre-release part may have swallowed a variant suffix (1.0.0-rc.1.min).
  emit(ctx, npm, match[2]!.replace(/(?:\.(?:min|slim|bundle))+$/, ""), 1, "file-name");
}

// ---- CDN URLs ----

/** A path segment that is a version (or a word such as `latest`); a file name or anything else is no version. */
function versionToken(segment: string | undefined): string | undefined {
  if (segment === undefined || segment === "") return undefined;
  if (/^v?\d/i.test(segment)) return segment;
  return /^[A-Za-z-]{1,32}$/.test(segment) ? segment : undefined;
}

/** `name@version`, or `@scope/name@version`, starting at segment `at`. */
function npmSpecifier(segments: string[], at: number): { key: string; version: string | undefined } | undefined {
  const first = segments[at];
  if (first === undefined || first === "") return undefined;
  let name = first;
  let rest = first;
  let prefix = "";
  if (first.startsWith("@")) {
    const second = segments[at + 1];
    if (second === undefined || second === "") return undefined;
    prefix = `${first}/`;
    name = second;
    rest = second;
  }
  const split = rest.indexOf("@");
  return { key: (prefix + (split < 0 ? name : name.slice(0, split))).toLowerCase(), version: split < 0 ? undefined : rest.slice(split + 1) };
}

function resolveUrl(host: string, path: string, table: Compiled): { npm: string; version: string | undefined } | undefined {
  const cut = path.search(/[?#]/);
  const clean = cut < 0 ? path : path.slice(0, cut);
  // A dot segment or an encoded separator makes the URL name some other resource than the library it starts with.
  if (/%2e|%2f|%5c/i.test(clean)) return undefined;
  const segments = clean.split("/");
  if (segments.some((segment) => segment === "." || segment === "..")) return undefined;
  switch (host) {
    case "cdnjs.cloudflare.com":
    case "ajax.googleapis.com": {
      if (segments[0] !== "ajax" || segments[1] !== "libs" || !segments[2]) return undefined;
      const npm = table.cdn.get(`ajax/libs/${segments[2].toLowerCase()}`);
      return npm === undefined ? undefined : { npm, version: versionToken(segments[3]) };
    }
    case "cdn.jsdelivr.net": {
      if (segments[0] !== "npm") return undefined;
      const specifier = npmSpecifier(segments, 1);
      const npm = specifier && table.cdn.get(`npm/${specifier.key}`);
      return specifier && npm ? { npm, version: specifier.version } : undefined;
    }
    case "unpkg.com": {
      const specifier = npmSpecifier(segments, 0);
      const npm = specifier && table.cdn.get(specifier.key);
      return specifier && npm ? { npm, version: specifier.version } : undefined;
    }
    case "stackpath.bootstrapcdn.com": {
      // This host serves bootstrap (and font-awesome); no other table library is hosted there.
      const npm = segments[0] ? table.cdn.get(segments[0].toLowerCase()) : undefined;
      return npm !== "bootstrap" ? undefined : { npm, version: versionToken(segments[1]) };
    }
    case "code.jquery.com": {
      if (segments[0] === "ui") {
        const npm = table.cdn.get("jquery-ui");
        return npm === undefined ? undefined : { npm, version: versionToken(segments[1]) };
      }
      const base = (segments[0] ?? "").replace(/(?:\.(?:min|slim|pack))*\.js$/i, "");
      const match = /^(jquery)(?:-(latest|git|\d[0-9A-Za-z.+-]{0,63}))?$/i.exec(base);
      const npm = match ? table.stems.get(match[1]!.toLowerCase()) : undefined;
      return match && npm ? { npm, version: match[2] } : undefined;
    }
    default:
      return undefined;
  }
}

const URL_DELIMITERS = new Set([32, 9, 10, 13, 34, 39, 96, 60, 62, 40, 41, 91, 93, 123, 125, 44, 59, 124, 92]);
const MAX_LOOKBEHIND = 300;

/**
 * Whether the URL starting at `index` is only the tail of something else (`https://x/?u=https://cdn...`,
 * `https://x/https://cdn...`, `foo/https://cdn...`): a name character or `/` right before it, or `//`
 * earlier in the same delimiter-free run. Bounded look-behind, so a long run costs a constant per match.
 */
function embedded(text: string, index: number): boolean {
  if (index === 0) return false;
  const before = text.charCodeAt(index - 1);
  const nameLike = (before >= 48 && before <= 57) || (before >= 65 && before <= 90) || (before >= 97 && before <= 122);
  if (nameLike || before === 46 || before === 95 || before === 126 || before === 47 || before === 37 || before === 45) return true;
  const floor = Math.max(0, index - MAX_LOOKBEHIND);
  for (let at = index - 1; at >= floor; at--) {
    const code = text.charCodeAt(at);
    if (URL_DELIMITERS.has(code)) return false;
    if (code === 47 && at > 0 && text.charCodeAt(at - 1) === 47) return true;
  }
  return false;
}

/**
 * Every CDN URL in `text`, one linear pass: the regex consumes a bounded path per match, and the line
 * number advances past each newline once, so no line length can make the work quadratic.
 */
function readUrls(ctx: Ctx, text: string, table: Compiled): void {
  URL_RE.lastIndex = 0;
  let line = 1;
  let newline = text.indexOf("\n");
  for (let match = URL_RE.exec(text); match !== null && !ctx.stop; match = URL_RE.exec(text)) {
    while (newline !== -1 && newline < match.index) {
      line++;
      newline = text.indexOf("\n", newline + 1);
    }
    if (embedded(text, match.index)) continue;
    const found = resolveUrl(match[1]!.toLowerCase(), match[2]!, table);
    if (found !== undefined) emit(ctx, found.npm, found.version, line, "cdn-url");
  }
}

// ---- reading ----

interface Bounded {
  text: string;
  /** The first HEAD_BYTES bytes, decoded. */
  head: string;
  /** The file goes on past the head. */
  headTruncated: boolean;
  bytes: number;
  truncated: boolean;
}

/** At most `max` bytes of a regular file, never following a link; undefined when it vanished or is unreadable. */
async function readBounded(target: string, rel: string, max: number): Promise<Bounded | undefined> {
  const path = join(target, ...rel.split("/"));
  let handle;
  try {
    if (!(await lstat(path)).isFile()) return undefined;
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const info = await handle.stat();
    if (!info.isFile()) return undefined;
    const length = Math.min(info.size, max);
    const buffer = Buffer.allocUnsafe(length);
    let filled = 0;
    while (filled < length) {
      const { bytesRead } = await handle.read(buffer, filled, length - filled, filled);
      if (bytesRead === 0) break;
      filled += bytesRead;
    }
    const text = buffer.toString("utf8", 0, filled);
    return {
      text,
      head: buffer.toString("utf8", 0, Math.min(filled, HEAD_BYTES)).replace(/^\uFEFF/, ""),
      headTruncated: filled > HEAD_BYTES,
      bytes: filled,
      truncated: info.size > max,
    };
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Whether `rel` is read: its innermost vendor-style folder, if any, must sit below a web asset root. */
function wanted(rel: string): boolean {
  const segments = rel.split("/");
  let assetRoot = false;
  let vendorHasRoot = true;
  for (let at = 0; at < segments.length - 1; at++) {
    const segment = segments[at]!;
    // Rails keeps copied front-end libraries in `vendor/assets/`: that vendor folder is an asset root itself.
    if (segment === "vendor" || segment === "vendors") vendorHasRoot = assetRoot || (segment === "vendor" && segments[at + 1] === "assets" && at + 1 < segments.length - 1);
    if (ASSET_ROOTS.has(segment)) assetRoot = true;
  }
  return vendorHasRoot;
}

export async function readLibraries(target: string, table: LibraryTable, options: ReaderOptions = {}): Promise<ReaderResult> {
  const result: ReaderResult = { declarations: [], parsed: [], skipped: [], notes: [] };
  try {
    const walked = await walkCandidates(target, MATCHERS, { maxFileBytes: WALK_MAX_BYTES }, { vendor: VENDOR_WALK, vendorNames: ["vendor", "vendors"], signal: options.signal, only: options.only });
    for (const entry of walked.skipped) result.skipped.push(entry);
    const tables = compile(table);

    let consumed = 0;
    let scanFull = false;
    for (const file of walked.files) {
      if (!wanted(file)) continue;
      if (scanFull) {
        // Past the per-scan declaration cap: not read, and never reported as checked.
        result.skipped.push({ file, reason: "capped" });
        continue;
      }
      if (options.signal?.aborted) {
        result.skipped.push({ file, reason: "deadline" });
        continue;
      }
      if (consumed >= MAX_SCAN_BYTES) {
        if (!result.skipped.some((entry) => entry.reason === "budget")) {
          const budgetNote = `${file}: more than ${MAX_SCAN_BYTES / (1024 * 1024)} MiB read in this scan (scan budget); the remaining files are skipped`;
          result.notes.push(budgetNote);
          (result.priorityNotes ??= []).push(budgetNote);
        }
        result.skipped.push({ file, reason: "budget" });
        continue;
      }
      const read = await readBounded(target, file, MAX_READ_BYTES);
      if (read === undefined) {
        result.skipped.push({ file, reason: "unreadable" });
        continue;
      }
      consumed += read.bytes;
      const ctx: Ctx = { file, out: [], notes: [], seen: new Set(), stop: false, capped: read.truncated, unjudged: false };
      try {
        const base = file.slice(file.lastIndexOf("/") + 1);
        if (/\.m?js$/i.test(base)) {
          readBanners(ctx, read.head, read.headTruncated, tables);
          readFileName(ctx, base, tables);
        }
        readUrls(ctx, read.text, tables);
        if (read.truncated) note(ctx, `${file}: larger than ${MAX_READ_BYTES / (1024 * 1024)} MiB; only the first ${MAX_READ_BYTES / (1024 * 1024)} MiB was read`);
        // Appended in loops, never spread: the arrays are bounded, but a spread's argument limit is not ours to rely on.
        for (const declaration of ctx.out) {
          if (result.declarations.length >= MAX_DECLARATIONS_PER_SCAN) {
            scanFull = true;
            const capNote = `${file}: more than ${MAX_DECLARATIONS_PER_SCAN} library declarations; extra ignored`;
            ctx.notes.push(capNote);
            (result.priorityNotes ??= []).push(capNote);
            break;
          }
          result.declarations.push(declaration);
        }
        for (const message of ctx.notes) if (result.notes.length < MAX_NOTES_PER_SCAN) result.notes.push(message);
        if (ctx.unjudged) (result.unjudged ??= []).push(file);
        // A file read only in part is not a re-check of everything it declares.
        if (ctx.capped || scanFull) result.skipped.push({ file, reason: "capped" });
        else result.parsed.push(file);
      } catch {
        // Malformed content (including a RangeError from hostile input) is reported, never thrown.
        result.skipped.push({ file, reason: "malformed" });
      }
    }
  } catch {
    result.notes.push("library reader stopped early: unexpected failure while reading the target");
  }
  return result;
}
