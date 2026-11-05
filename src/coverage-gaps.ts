/**
 * Declared coverage gaps (field re-test G1/G4): inputs CodeInspectus can see but no bundled engine
 * analyzes. Each gap has a stable, documented id (docs/CLI-REFERENCE.md). A gap makes aggregate
 * coverage `partial`; a user may accept named gap ids so CI passes, and accepted gaps stay listed.
 *
 * Read-only and bounded: no symlink is followed, manifests over 1 MiB are not parsed, and discovery
 * stops at a fixed entry bound with a coverage warning.
 */

import { lstat, opendir, readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import { basename, dirname, join, posix, relative } from "node:path";

import { BUILD_DIRS } from "./config.js";
import { isDisplayablePath } from "./display-path.js";
import { OPENGREP_BUNDLE_SKIPPING_RULES_LABEL } from "./provenance.js";
import type { ScanResult } from "./types.js";

export const COVERAGE_GAP_IDS = [
  "php-sast", "ruby-sast", "java-sast", "kotlin-sast", "go-sast", "csharp-sast", "rust-sast", "swift-sast",
  "c-sast", "cpp-sast", "scala-sast", "dart-sast",
  // Review I-2 / Ruling 15: component files whose script no engine reads, and further languages.
  "vue-sast", "svelte-sast", "astro-sast", "objc-sast", "elixir-sast", "erlang-sast", "lua-sast", "perl-sast",
  "groovy-sast", "clojure-sast", "haskell-sast", "ocaml-sast", "r-sast", "julia-sast", "zig-sast", "solidity-sast",
  "vb-sast",
  // Reported by the Opengrep run, not by discovery: files whose only errors were parser limits, and
  // vendored or minified bundles the bundle-skipping Opengrep pass skipped (M4 Task 4; taint baseline rules since the M4 perf fix).
  "sast-parse-errors", "third-party-bundles",
  // Reported by the native packs and technology detection (native-gaps.ts): deterministic limits.
  "native-parse-errors", "oversized-files", "native-token-budget", "express-routes-unresolved", "nextjs-routes-unresolved",
  "symlinked-paths",
  // Inputs with no advisory data in any bundled engine (online recheck 2026-11-01).
  "wordpress-plugins", "actions-unchecked",
  // Review I-1 / re-review N-2: Maven dependencies Trivy drops even with --include-dev-deps.
  "dev-deps-unscanned",
  "deno-lock", "bun-lockb", "no-lockfile-npm", "no-lockfile-composer", "npm-shrinkwrap-unread",
  // Reported by the Synvoya layer: exact vendored or CDN libraries osv-scanner could not check (no engine or npm DB).
  "vendored-js",
] as const;
export type CoverageGapId = (typeof COVERAGE_GAP_IDS)[number];

/** Languages with source files but no bundled code-pattern (Opengrep) rules: `<language>-sast`. */
const SAST_GAP_EXTENSIONS: Readonly<Partial<Record<CoverageGapId, readonly string[]>>> = {
  // Server templates with embedded code count toward their language (fix round 3). The Synvoya PHP pack
  // (detection-db/opengrep-rules/synvoya-php) covers .php, .phtml and .blade.php, which Opengrep parses
  // as PHP; Twig templates (Symfony, Drupal) are not PHP to Opengrep and stay a php-sast gap.
  "php-sast": [".twig"],
  "ruby-sast": [".rb", ".erb"],
  "java-sast": [".java", ".jsp", ".jspx"],
  "kotlin-sast": [".kt", ".kts"],
  "go-sast": [".go"],
  "csharp-sast": [".cs", ".cshtml", ".razor"],
  "rust-sast": [".rs"],
  "swift-sast": [".swift"],
  "c-sast": [".c", ".h"],
  "cpp-sast": [".cc", ".cpp", ".cxx", ".hpp", ".hh"],
  "scala-sast": [".scala"],
  "dart-sast": [".dart"],
  // Opengrep 1.33.1 neither scans nor lists these, and the native JavaScript packs do not read them.
  "vue-sast": [".vue"],
  "svelte-sast": [".svelte"],
  "astro-sast": [".astro"],
  // `.m` is counted as Objective-C; MATLAB files share the extension and cannot be told apart.
  "objc-sast": [".m", ".mm"],
  "elixir-sast": [".ex", ".exs"],
  "erlang-sast": [".erl", ".hrl"],
  "lua-sast": [".lua"],
  "perl-sast": [".pl", ".pm"],
  "groovy-sast": [".groovy"],
  "clojure-sast": [".clj", ".cljs", ".cljc"],
  "haskell-sast": [".hs"],
  "ocaml-sast": [".ml", ".mli"],
  "r-sast": [".r"],
  "julia-sast": [".jl"],
  "zig-sast": [".zig"],
  "solidity-sast": [".sol"],
  "vb-sast": [".vb"],
};
/** Component files: a gap names their script code, not a language. */
const COMPONENT_GAPS: Readonly<Partial<Record<CoverageGapId, string>>> = {
  "vue-sast": ".vue", "svelte-sast": ".svelte", "astro-sast": ".astro",
};
/**
 * Scripts no bundled SAST rule reads. Ruling 15: an informational note, not a gap, because nearly
 * every repository has some and they are build or tooling glue rather than application code.
 */
const SCRIPT_KINDS: ReadonlyArray<readonly [string, (name: string, extension: string) => boolean]> = [
  ["shell", (_name, extension) => [".sh", ".bash", ".zsh", ".ksh"].includes(extension)],
  ["PowerShell", (_name, extension) => [".ps1", ".psm1", ".psd1"].includes(extension)],
  ["Makefile", (name, extension) => ["Makefile", "makefile", "GNUmakefile"].includes(name) || extension === ".mk"],
];
/**
 * Bundled Opengrep rules declare these languages; tests keep this in step with detection-db. Rules in
 * `generic` (configuration files and Blade templates) cover no source language and are not listed.
 */
export const SAST_COVERED_LANGUAGES = ["javascript", "typescript", "python", "php"] as const;

export interface CoverageGap {
  id: CoverageGapId;
  /** Matching files (source files, lockfiles or manifests). */
  files: number;
  /** Up to five target-relative example paths. */
  examples: string[];
}

/** An informational scope disclosure (export evidence `state: "informational"`); never a gap. */
export interface CoverageNote {
  /** Export evidence component, e.g. `engine:opengrep` or `scope:scripts`. */
  component: string;
  detail: string;
}

/**
 * Default scope that applies to every repository: Opengrep's managed ignore list and the native
 * JavaScript packs' Yarn-tooling skip. Review M1: carried as coverage notes so the MCP result and the
 * text summary show them, not only the export.
 */
export function defaultScopeNotes(scan: Pick<ScanResult, "engine_details" | "pack_coverage">): CoverageNote[] {
  const notes: CoverageNote[] = [];
  if (scan.engine_details.some((engine) => engine.engine === "opengrep" && engine.ran)) {
    notes.push({
      component: "engine:opengrep",
      detail: "Opengrep skips its default ignore list in every repository (detection-db/opengrep-ignore/default.semgrepignore): " +
        "node_modules/, vendor/, build/, dist/, test/, tests/, testsuite/, .yarn/, .venv/, *.min.js, *_test.go and similar, " +
        `and the build-output folders where file routing drops its findings: ${[...BUILD_DIRS].map((folder) => `${folder}/`).join(", ")}.`,
    });
  }
  if ((scan.pack_coverage ?? []).some((pack) => pack.pack_id === "javascript-baseline" && (pack.state === "ran" || pack.state === "partial"))) {
    notes.push({
      component: "pack:javascript-baseline",
      detail: "The native JavaScript packs skip node_modules/ and, beside a package.json, Yarn's .yarn/releases, " +
        ".yarn/plugins, .yarn/sdks, .yarn/cache and .yarn/unplugged folders and its .pnp.cjs/.pnp.loader.mjs loaders.",
    });
  }
  return notes;
}

export interface CoverageGapDiscovery {
  gaps: CoverageGap[];
  /** Set when discovery stopped early; the caller reports it as partial coverage. */
  limitation?: string;
  /** Informational: shell, PowerShell and Makefile files no SAST rule reads (not a gap). */
  scriptNote?: string;
  /**
   * Every distinct third-party `uses:` reference and workflow file pair (capped), in discovery order: once the
   * Synvoya Actions matcher has run, actionsUncheckedGap rebuilds `actions-unchecked` from it.
   */
  actionReferences?: Array<{ reference: string; file: string }>;
}

// Directories the managed Opengrep ignore list skips (detection-db/opengrep-ignore): third-party,
// generated and test trees are not counted as the project's own unanalyzed source or manifests.
// Case-sensitive, as Opengrep matches them (review M3: Tests/, Vendor/ and Build/ are scanned).
const SKIPPED_DIRS = new Set([
  ".git", ".svn", ".hg", "_darcs", "CVS", "build", "vendor", "dist", ".env", ".tox", "node_modules", ".npm",
  ".yarn", ".venv", "_opam", "_build", "_cargo", "test", "tests", "testsuite",
  ...BUILD_DIRS,
]);
const MAX_ENTRIES = 200_000;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_EXAMPLES = 5;
const NPM_LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"];
/** Lockfiles Trivy 0.76.1 reads; it does not read npm-shrinkwrap.json (review I-3). */
const TRIVY_NPM_LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"];
const NPM_DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];
/** Bound on WordPress entries per lockfile and on GitHub Actions references read. */
const MAX_MATCHES_PER_FILE = 10_000;
/** composer.lock files are often over 1 MiB; WordPress packages are found by name in the text. */
const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const WPACKAGIST_PACKAGE = /"name"\s*:\s*"(wpackagist-(?:plugin|theme)\/[^"\\]{1,200})"/g;
/** A WordPress plugin's main file declares `Plugin Name:` in its header comment. */
const WORDPRESS_PLUGIN_HEADER = /^[ \t/*#@]*Plugin Name[ \t]*:/im;
/** A step's or job's `uses:` reference in a workflow (local `./` actions are the repository's own). */
const WORKFLOW_USES = /^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*["']?([^"'\s#]{1,300})/gm;
// One bounded run between the tags, trimmed afterwards: optional whitespace around a lazy capture
// backtracked cubically (re-review N-1: 48.5 s for a 1 MiB pom.xml).
const MAVEN_COORDINATE = (tag: string) => new RegExp(`<${tag}>([^<]{1,200})</${tag}>`);
/** Scopes Trivy 0.76.1 drops even with --include-dev-deps (review I-1, re-review N-2). */
const MAVEN_DROPPED_SCOPES = new Set(["test", "provided", "system"]);

/**
 * Why Trivy would drop one Maven `<dependency>` block, or undefined: a test, provided or system scope,
 * `<optional>true</optional>`, or a scope or optional flag set through a property it cannot resolve.
 */
function mavenDropReason(block: string): string | undefined {
  const scope = MAVEN_COORDINATE("scope").exec(block)?.[1]?.trim();
  if (scope?.includes("${")) return `scope ${scope}`;
  if (scope && MAVEN_DROPPED_SCOPES.has(scope.toLowerCase())) return scope.toLowerCase();
  const optional = MAVEN_COORDINATE("optional").exec(block)?.[1]?.trim();
  if (optional?.includes("${")) return `optional ${optional}`;
  return optional?.toLowerCase() === "true" ? "optional" : undefined;
}

/** Dependencies of one pom.xml that Trivy drops, deduplicated and capped (linear scan). */
function mavenDevDependencies(text: string): string[] {
  const found = new Set<string>();
  for (let at = 0; found.size < MAX_MATCHES_PER_FILE;) {
    const start = text.indexOf("<dependency>", at);
    const end = start < 0 ? -1 : text.indexOf("</dependency>", start);
    if (end < 0) break;
    at = end + "</dependency>".length;
    const block = text.slice(start, end);
    const reason = mavenDropReason(block);
    if (!reason) continue;
    const group = MAVEN_COORDINATE("groupId").exec(block)?.[1]?.trim() || "?";
    const artifact = MAVEN_COORDINATE("artifactId").exec(block)?.[1]?.trim() || "?";
    found.add(`${group}:${artifact} (${reason})`);
  }
  return [...found];
}

/** Composer platform requirements, not installable packages. */
const COMPOSER_PLATFORM = /^(?:php(?:-64bit|-ipv6|-zts|-debug)?|hhvm|ext-.+|lib-.+|composer(?:-plugin|-runtime)?-api)$/i;

/** A bounded regular file's text, or undefined (missing, symlink, over 1 MiB, unreadable). */
async function boundedText(path: string, maxBytes = MAX_MANIFEST_BYTES): Promise<string | undefined> {
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.size > maxBytes) return undefined;
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

function jsonObject(text: string | undefined): Record<string, unknown> | undefined {
  try {
    const value = text === undefined ? undefined : JSON.parse(text) as unknown;
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function hasEntries(value: unknown, keep: (name: string) => boolean = () => true): boolean {
  return value !== null && typeof value === "object" && Object.keys(value).some(keep);
}

const MAX_WORKSPACE_PATTERNS = 64;
const MAX_WORKSPACE_PATTERN_LENGTH = 256;

/** A compiled workspace glob: path segments, `**` as a whole segment matching zero or more. */
type WorkspaceGlob = readonly string[];
/** Include and exclude globs, or undefined when the declaration is over a bound (undeclared). */
type WorkspaceDeclaration = { include: WorkspaceGlob[]; exclude: WorkspaceGlob[] } | undefined;

/**
 * Linear two-pointer wildcard match of one path segment (`*` any run, `?` one character). Workspace
 * globs come from the scanned repository, so no RegExp is ever built from them (security review: a
 * glob such as `*a*a*a…b` compiled to a backtracking RegExp is a ReDoS).
 */
function segmentMatches(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] === "*") {
      star = p++;
      mark = t;
    } else if (star !== -1) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }
  while (pattern[p] === "*") p++;
  return p === pattern.length;
}

/** Iterative DP over segments: `reachable[j]` means the glob prefix matches the first j path segments. */
function globMatches(glob: WorkspaceGlob, path: readonly string[]): boolean {
  let reachable = path.map(() => false).concat(false);
  reachable[0] = true;
  for (const segment of glob) {
    const next = path.map(() => false).concat(false);
    if (segment === "**") {
      let any = false;
      for (let index = 0; index <= path.length; index++) next[index] = any = any || reachable[index]!;
    } else {
      for (let index = 1; index <= path.length; index++) next[index] = reachable[index - 1]! && segmentMatches(segment, path[index - 1]!);
    }
    reachable = next;
  }
  return reachable[path.length]!;
}

/** `{a,b}` alternatives expanded (no nesting), or undefined past the pattern bound. */
function expandBraces(pattern: string, budget: { left: number }): string[] | undefined {
  const open = pattern.indexOf("{");
  const close = open < 0 ? -1 : pattern.indexOf("}", open);
  if (close < 0) return --budget.left < 0 ? undefined : [pattern];
  const expanded: string[] = [];
  for (const alternative of pattern.slice(open + 1, close).split(",")) {
    const rest = expandBraces(pattern.slice(0, open) + alternative + pattern.slice(close + 1), budget);
    if (!rest) return undefined;
    expanded.push(...rest);
  }
  return expanded;
}

function compileWorkspaceGlobs(patterns: readonly string[]): WorkspaceGlob[] | undefined {
  const budget = { left: MAX_WORKSPACE_PATTERNS };
  const globs: WorkspaceGlob[] = [];
  for (const pattern of patterns) {
    if (pattern.length > MAX_WORKSPACE_PATTERN_LENGTH) return undefined;
    const expanded = expandBraces(pattern.trim().replace(/^(?:\.\/)+/, "").replace(/\/+$/, ""), budget);
    if (!expanded) return undefined;
    for (const glob of expanded) {
      if (!glob) continue;
      // `**` is globstar only as a whole segment; elsewhere a run of `*` is one `*`.
      globs.push(glob.split("/").map((segment) => (segment === "**" ? segment : segment.replace(/\*+/g, "*"))));
    }
  }
  return globs;
}

/**
 * Workspace folders a project root declares: `workspaces` in its package.json (npm, Yarn and Bun; an
 * array or `{ packages: [...] }`) and `packages` in pnpm-workspace.yaml. `!` patterns exclude. More
 * than 64 patterns or one over 256 characters makes the root undeclared (fail closed).
 */
async function workspaceDeclaration(
  root: string,
  present: ReadonlySet<string>,
  readText: (rel: string) => Promise<string | undefined>,
): Promise<WorkspaceDeclaration> {
  const patterns: string[] = [];
  const manifestPath = posix.join(root, "package.json");
  if (present.has(manifestPath)) {
    const workspaces = jsonObject(await readText(manifestPath))?.workspaces;
    patterns.push(...strings(workspaces), ...strings((workspaces as Record<string, unknown> | undefined)?.packages));
  }
  const pnpmPath = posix.join(root, "pnpm-workspace.yaml");
  if (present.has(pnpmPath)) {
    try {
      const text = await readText(pnpmPath);
      const parsed = text === undefined ? undefined : parseYaml(text) as unknown;
      if (parsed !== null && typeof parsed === "object") patterns.push(...strings((parsed as Record<string, unknown>).packages));
    } catch {
      // Unparsable: declares nothing, so the nested manifest stays a gap (fail closed).
    }
  }
  if (patterns.length > MAX_WORKSPACE_PATTERNS) return undefined;
  const include = compileWorkspaceGlobs(patterns.filter((pattern) => !pattern.startsWith("!")));
  const exclude = compileWorkspaceGlobs(patterns.filter((pattern) => pattern.startsWith("!")).map((pattern) => pattern.slice(1)));
  return include && exclude ? { include, exclude } : undefined;
}

/**
 * Review M4 ruling: an npm lockfile covers a package.json beside it, or in a folder that an ancestor
 * holding a lockfile declares as a workspace. A lockfile further up that does not declare the folder
 * (examples/, docs/, website/) covers nothing there. Paths are target-relative POSIX on every
 * platform (review I-5: win32 joins never matched them). Declarations are read and compiled once per
 * root (`declarations`).
 */
async function npmLocked(
  rel: string,
  lockFolders: ReadonlySet<string>,
  present: ReadonlySet<string>,
  readText: (rel: string) => Promise<string | undefined>,
  declarations: Map<string, Promise<WorkspaceDeclaration>>,
): Promise<boolean> {
  const folder = posix.dirname(rel);
  if (lockFolders.has(folder)) return true;
  // Only folders that hold a lockfile can cover; checked by prefix, so deep paths cost O(length).
  for (const root of lockFolders) {
    if (root !== "." && !folder.startsWith(`${root}/`)) continue;
    if (!declarations.has(root)) declarations.set(root, workspaceDeclaration(root, present, readText));
    const declaration = await declarations.get(root)!;
    const path = (root === "." ? folder : folder.slice(root.length + 1)).split("/");
    if (declaration && declaration.include.some((glob) => globMatches(glob, path)) &&
      !declaration.exclude.some((glob) => globMatches(glob, path))) return true;
  }
  return false;
}

export async function discoverCoverageGaps(target: string): Promise<CoverageGapDiscovery> {
  const files: string[] = [];
  let entries = 0;
  let limitation: string | undefined;

  const root = await lstat(target).catch(() => undefined);
  if (root?.isFile()) files.push(basename(target));
  async function walk(directory: string): Promise<void> {
    if (limitation) return;
    let handle;
    try {
      handle = await opendir(directory);
      const children = [];
      for await (const entry of handle) children.push(entry);
      // Review M6: code-point order, so examples do not depend on the host's ICU locale.
      children.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
      for (const entry of children) {
        if (++entries > MAX_ENTRIES) {
          limitation = `Coverage-gap discovery partial: stopped at the ${MAX_ENTRIES}-entry bound, so undeclared gaps may exist.`;
          return;
        }
        const absolute = join(directory, entry.name);
        if (entry.isDirectory() && !SKIPPED_DIRS.has(entry.name)) await walk(absolute);
        else if (entry.isFile()) files.push(relative(target, absolute).replace(/\\/g, "/"));
      }
    } catch {
      const folder = relative(target, directory).replace(/\\/g, "/") || ".";
      limitation ??= `Coverage-gap discovery partial: ${isDisplayablePath(folder) ? folder : "a folder"} was unreadable, so undeclared gaps may exist.`;
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  if (root?.isDirectory()) await walk(target);

  const base = root?.isFile() ? dirname(target) : target;
  const classified = await gapsFromFiles(files, (rel, maxBytes) => boundedText(join(base, rel), maxBytes));
  return { ...classified, ...(limitation ? { limitation } : {}) };
}

/**
 * Classifies target-relative POSIX paths (pure apart from `readText`). Exported for the win32
 * path-semantics test; every path operation here is `posix`.
 */
export async function gapsFromFiles(
  files: readonly string[],
  readText: (rel: string, maxBytes?: number) => Promise<string | undefined>,
): Promise<Omit<CoverageGapDiscovery, "limitation">> {
  // O(1) per call: a count plus the first displayable examples (security review: no list copying).
  const found = new Map<CoverageGapId, { count: number; examples: string[] }>();
  const add = (id: CoverageGapId, rel: string) => {
    const entry = found.get(id) ?? { count: 0, examples: [] };
    entry.count++;
    // Unsafe (control, bidi) names are counted but never shown.
    if (entry.examples.length < MAX_EXAMPLES && isDisplayablePath(rel)) entry.examples.push(rel);
    found.set(id, entry);
  };
  const present = new Set(files);
  const declarations = new Map<string, Promise<WorkspaceDeclaration>>();
  const wordpressUnits = new Set<string>();
  const actionReferences = new Set<string>();
  const actionPairs = new Map<string, { reference: string; file: string }>();
  const lockFolders = new Set(files.filter((rel) => NPM_LOCKFILES.includes(posix.basename(rel))).map((rel) => posix.dirname(rel)));
  const scripts = new Map<string, number>();
  const scriptExamples: string[] = [];
  for (const rel of files) {
    const name = posix.basename(rel);
    const extension = posix.extname(name).toLowerCase();
    for (const [id, extensions] of Object.entries(SAST_GAP_EXTENSIONS)) {
      if (extensions?.includes(extension)) add(id as CoverageGapId, rel);
    }
    const script = SCRIPT_KINDS.find(([, matches]) => matches(name, extension))?.[0];
    if (script) {
      scripts.set(script, (scripts.get(script) ?? 0) + 1);
      if (scriptExamples.length < MAX_EXAMPLES && isDisplayablePath(rel)) scriptExamples.push(rel);
    }
    if (name === "deno.lock") add("deno-lock", rel);
    if (name === "bun.lockb" && !present.has(posix.join(posix.dirname(rel), "bun.lock"))) add("bun-lockb", rel);
    if (name === "npm-shrinkwrap.json" && !TRIVY_NPM_LOCKFILES.some((lock) => present.has(posix.join(posix.dirname(rel), lock)))) {
      add("npm-shrinkwrap-unread", rel);
    }
    if (name === "package.json" && !await npmLocked(rel, lockFolders, present, readText, declarations)) {
      const json = jsonObject(await readText(rel));
      // An unreadable or unparsable manifest cannot be shown to declare nothing.
      if (!json || NPM_DEPENDENCY_FIELDS.some((field) => hasEntries(json[field]))) add("no-lockfile-npm", rel);
    }
    // Recheck item 7: WordPress plugins and themes have no advisory data in any bundled engine.
    if (name === "composer.lock") {
      // Deduplicated and capped per file: a crafted lockfile cannot make the count or the work grow.
      const seen = new Set<string>();
      for (const match of (await readText(rel, MAX_LOCKFILE_BYTES))?.matchAll(WPACKAGIST_PACKAGE) ?? []) {
        if (seen.size >= MAX_MATCHES_PER_FILE) break;
        if (seen.has(match[1]!)) continue;
        seen.add(match[1]!);
        add("wordpress-plugins", `${rel}: ${match[1]}`);
      }
    }
    const plugin = /(?:^|\/)wp-content\/plugins\/([^/]+)(?:\/([^/]+))?$/.exec(rel);
    if (plugin && extension === ".php") {
      const unit = plugin[2] === undefined ? rel : rel.slice(0, rel.length - plugin[2].length - 1);
      if (!wordpressUnits.has(unit) && WORDPRESS_PLUGIN_HEADER.test((await readText(rel))?.slice(0, 8192) ?? "")) {
        wordpressUnits.add(unit);
        add("wordpress-plugins", unit);
      }
    }
    // Recheck item 8: third-party GitHub Actions. The Synvoya Actions matcher, when its database is installed,
    // narrows this to the references it could not evaluate (actionsUncheckedGap).
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(rel)) {
      let matches = 0;
      for (const match of (await readText(rel))?.matchAll(WORKFLOW_USES) ?? []) {
        if (++matches > MAX_MATCHES_PER_FILE || actionReferences.size >= MAX_MATCHES_PER_FILE) break;
        const reference = match[1]!;
        if (reference.startsWith("./")) continue;
        if (actionPairs.size < MAX_MATCHES_PER_FILE && !actionPairs.has(`${rel}\0${reference}`)) actionPairs.set(`${rel}\0${reference}`, { reference, file: rel });
        if (actionReferences.has(reference)) continue;
        actionReferences.add(reference);
        add("actions-unchecked", `${reference} (${rel})`);
      }
    }
    // Review I-1 / re-review N-2: Trivy 0.76.1 drops Maven test, provided, system and optional
    // dependencies even with --include-dev-deps.
    // An unreadable pom.xml cannot be shown to declare none.
    if (name === "pom.xml") {
      const text = await readText(rel);
      if (text === undefined) add("dev-deps-unscanned", `${rel} (unreadable)`);
      for (const dependency of text === undefined ? [] : mavenDevDependencies(text)) add("dev-deps-unscanned", `${rel}: ${dependency}`);
    }
    // Review M4 ruling: composer.lock covers only the composer.json beside it.
    if (name === "composer.json" && !present.has(posix.join(posix.dirname(rel), "composer.lock"))) {
      const json = jsonObject(await readText(rel));
      if (!json || hasEntries(json.require, (name) => !COMPOSER_PLATFORM.test(name))) add("no-lockfile-composer", rel);
    }
  }
  const gaps = COVERAGE_GAP_IDS.flatMap((id) => {
    const entry = found.get(id);
    return entry ? [{ id, files: entry.count, examples: entry.examples }] : [];
  });
  const scriptCount = [...scripts.values()].reduce((sum, count) => sum + count, 0);
  const scriptNote = scriptCount
    ? `No bundled SAST rules read ${SCRIPT_KINDS.flatMap(([kind]) => scripts.has(kind) ? [`${scripts.get(kind)} ${kind}`] : []).join(", ")} ` +
      `file(s) (informational, not a coverage gap)` +
      `${scriptExamples.length ? `: ${scriptExamples.join(", ")}${scriptCount > scriptExamples.length ? ", …" : ""}` : ""}.`
    : undefined;
  return { gaps, ...(scriptNote ? { scriptNote } : {}), ...(actionPairs.size ? { actionReferences: [...actionPairs.values()] } : {}) };
}

/**
 * `actions-unchecked` once the Synvoya Actions matcher ran: each distinct reference (in first-seen order) with
 * at least one occurrence the matcher did not evaluate (`evaluated` holds `${file}\0${reference}`), named with
 * that occurrence's file; undefined when every reference was evaluated.
 */
export function actionsUncheckedGap(
  references: ReadonlyArray<{ reference: string; file: string }>,
  evaluated: ReadonlySet<string>,
): CoverageGap | undefined {
  const firstUnchecked = new Map<string, string | undefined>();
  for (const { reference, file } of references) {
    if (!firstUnchecked.has(reference)) firstUnchecked.set(reference, undefined);
    if (firstUnchecked.get(reference) === undefined && !evaluated.has(`${file}\0${reference}`)) firstUnchecked.set(reference, file);
  }
  const unchecked = [...firstUnchecked].filter((entry): entry is [string, string] => entry[1] !== undefined);
  if (unchecked.length === 0) return undefined;
  const examples = unchecked.map(([reference, file]) => `${reference} (${file})`).filter(isDisplayablePath).slice(0, MAX_EXAMPLES);
  return { id: "actions-unchecked", files: unchecked.length, examples };
}

/** Human description used in coverage evidence and summaries. */
export function describeCoverageGap(gap: CoverageGap, accepted: boolean): string {
  const n = gap.files;
  const other: Record<Exclude<CoverageGapId, `${string}-sast`>, string> = {
    "sast-parse-errors": `${n} file(s) have code Opengrep's parsers could not read, so SAST rules did not see that code`,
    "third-party-bundles": `${n} vendored or minified bundle file(s) were skipped by the Opengrep taint rules, which cannot finish on them ` +
      `(the Synvoya PHP and Node packs and the taint-mode baseline rules: ${OPENGREP_BUNDLE_SKIPPING_RULES_LABEL}); ` +
      "the other baseline Opengrep rules still scanned them",
    "native-parse-errors": `${n} file(s) the native packs' bounded parsers could not read, so native AI and SAST checks skipped them`,
    "oversized-files": `${n} file(s) exceed a native per-file size or call-count bound (often vendored or minified bundles), so native checks skipped them`,
    "native-token-budget": `${n} file(s) come after the native JavaScript/TypeScript project token budget was spent, so native checks skipped them`,
    "express-routes-unresolved": `${n} file(s) have Express admin-route candidates whose middleware or handler could not be proven either way`,
    "nextjs-routes-unresolved": `${n} file(s) have Next.js admin API route handlers whose wrapper, guard or privileged operation could not be proven either way`,
    "symlinked-paths": `${n} symbolic link(s) resolve inside the repository to content the native packs or technology detection read under its own path; path-sensitive checks did not read it under the link's path`,
    "deno-lock": `${n} deno.lock file(s) are not read by any dependency engine`,
    "bun-lockb": `${n} binary bun.lockb file(s) without a text bun.lock are not read by any dependency engine`,
    "no-lockfile-npm": `${n} package.json file(s) declare dependencies without a lockfile, so no versions are checked`,
    "no-lockfile-composer": `${n} composer.json file(s) require packages without a composer.lock, so no versions are checked`,
    "npm-shrinkwrap-unread": `${n} npm-shrinkwrap.json file(s) have no lockfile beside them that Trivy reads, so no versions are checked`,
    "dev-deps-unscanned": `${n} Maven pom.xml entr(ies) (test, provided, system, optional or property-scoped dependencies, or an unreadable pom.xml) are dropped by Trivy even with development dependencies included, so their versions are not checked`,
    "wordpress-plugins": `${n} WordPress plugin(s) or theme(s) have no advisory data in any bundled engine, so their versions are not checked`,
    "actions-unchecked": `${n} third-party GitHub Actions reference(s) in workflows are not checked against advisories: the OSV GitHub Actions database ` +
      "is not installed (`codeinspectus setup` offers it), or the Synvoya Actions matcher could not evaluate the reference " +
      "(a branch or commit the advisory data does not list, a docker:// step, or a file it could not read)",
    "vendored-js": `${n} file(s) ship vendored or CDN-loaded JavaScript libraries at exact versions, but osv-scanner or its OSV npm database is not installed, so they were not checked. ` +
      "Known limits even when it is installed: only exact versions are checked (floating or unversioned ones are notes); vendor folders outside a web asset root " +
      "(other than Rails vendor/assets) and dist/ or other build output are not read, while WordPress plugin and theme vendor folders under wp-content are",
  };
  const component = COMPONENT_GAPS[gap.id];
  const what = component
    ? `${n} ${component} component file(s) have script code no bundled SAST rule or native pack reads`
    : gap.id === "php-sast"
      ? `${n} Twig template file(s) have no bundled SAST rules (the Synvoya PHP pack reads .php, .phtml and .blade.php only)`
      : gap.id.endsWith("-sast")
      ? `${n} ${gap.id.slice(0, -"-sast".length)} source file(s) have no bundled SAST rules`
      : other[gap.id as keyof typeof other];
  const examples = gap.examples.length ? `: ${gap.examples.join(", ")}${n > gap.examples.length ? ", …" : ""}` : "";
  return `${what} (${gap.id})${examples}.` + (accepted ? " Accepted with accept_gaps; still not covered." : "");
}
