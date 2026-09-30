import { chmod, lstat, mkdir, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import type { ScanInput } from "./schemas.js";
import { executeScan, projectScanForDisplay } from "./scan.js";
import { saveScan } from "./store.js";
import type { Finding, GitScanScope, GitScopeEntry, ScanResult } from "./types.js";
import { IGNORE_SUBMODULE_WORKTREES, repositoryFilterDrivers, runGitReadBuffer } from "./util/git.js";
import { releaseTemporaryDirectory, trackTemporaryDirectory } from "./util/temporary.js";
import { requireSafeScanTarget } from "./path-safety.js";
import { detectGitSafety } from "./git-safety.js";
import { findingsMatch } from "./scan-history.js";
import { isDocumentationName } from "./path-safety.js";
import { pairMovedFindings } from "./dedup.js";

const MAX_REVISION_LENGTH = 256;
const MAX_SCOPE_ENTRIES = 50_000;
const MAX_TREE_ENTRIES = 50_000;
const MAX_TREE_BYTES = 128 * 1024 * 1024;
const MAX_BLOB_BYTES = 8 * 1024 * 1024;

export interface GitScopeRequest {
  mode: "commit_diff" | "working_tree";
  base: string;
  head?: string;
}

function validateRevision(revision: string, option: string): void {
  if (!revision || revision.length > MAX_REVISION_LENGTH || revision.startsWith("-") || /[\0\r\n\x00-\x1f\x7f]/.test(revision)) {
    throw new Error(`${option} must be a non-option Git revision without control characters (maximum ${MAX_REVISION_LENGTH} characters).`);
  }
}

export async function resolveGitCommit(repository: string, revision: string, option: string): Promise<string> {
  validateRevision(revision, option);
  const result = await runGitReadBuffer(repository, ["rev-parse", "--verify", "--end-of-options", `${revision}^{commit}`], { maxBytes: 1024 });
  const commit = result.stdout.toString("utf8").trim();
  if (result.code !== 0 || !/^[0-9a-f]{40,64}$/.test(commit)) {
    throw new Error(`${option} '${revision}' does not resolve to a commit${result.stderr ? `: ${result.stderr}` : "."}`);
  }
  return commit;
}

export async function findGitRepositoryRoot(target: string): Promise<string> {
  const result = await runGitReadBuffer(target, ["rev-parse", "--show-toplevel"], { maxBytes: 16 * 1024 });
  if (result.code !== 0) throw new Error("Git-scoped scans require a target inside a Git working tree.");
  const root = result.stdout.toString("utf8").trim();
  if (!root) throw new Error("Git did not return a working-tree root for the target.");
  return (await requireSafeScanTarget(root)).canonical_path;
}

function splitNul(buffer: Buffer): string[] {
  const values = buffer.toString("utf8").split("\0");
  if (values.at(-1) === "") values.pop();
  return values;
}

function generatedPath(path: string): boolean {
  return /(?:^|\/)(?:dist|build|coverage|generated|vendor|node_modules|target|\.dart_tool)(?:\/|$)/i.test(path) ||
    /(?:\.generated\.|\.g\.dart$|\.freezed\.dart$|_generated\.|_pb2\.py$|\.g\.cs$)/i.test(path);
}

function safeRepoPath(path: string): boolean {
  if (!path || path.includes("\0") || path.includes("\\") || path.startsWith("/") || path.split("/").some((part) => part === "" || part === "." || part === "..")) return false;
  return Buffer.byteLength(path) <= 4096;
}

function targetPrefix(repository: string, target: string): string {
  const rel = relative(repository, target).split(sep).join("/");
  return rel === "." ? "" : rel;
}

function inTarget(path: string, prefix: string): boolean {
  return !prefix || path === prefix || path.startsWith(`${prefix}/`);
}

async function binaryPaths(repository: string, base: string, head?: string): Promise<Set<string>> {
  const args = head
    ? ["diff", "--numstat", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", IGNORE_SUBMODULE_WORKTREES, base, head]
    : ["diff", "--numstat", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", IGNORE_SUBMODULE_WORKTREES, base];
  const result = await runGitReadBuffer(repository, args);
  if (result.code !== 0) throw new Error(`Git could not enumerate binary changes${result.stderr ? `: ${result.stderr}` : "."}`);
  const binary = new Set<string>();
  for (const record of splitNul(result.stdout)) {
    const fields = record.split("\t");
    if (fields[0] === "-" && fields[1] === "-" && fields[2]) binary.add(fields[2]);
  }
  return binary;
}

async function changedEntries(repository: string, base: string, head: string | undefined, prefix: string): Promise<GitScopeEntry[]> {
  const args = head
    ? ["diff", "--name-status", "-z", "--find-renames", "--no-ext-diff", "--no-textconv", IGNORE_SUBMODULE_WORKTREES, base, head]
    : ["diff", "--name-status", "-z", "--find-renames", "--no-ext-diff", "--no-textconv", IGNORE_SUBMODULE_WORKTREES, base];
  const result = await runGitReadBuffer(repository, args);
  if (result.code !== 0) throw new Error(`Git could not enumerate changed paths${result.stderr ? `: ${result.stderr}` : "."}`);
  const values = splitNul(result.stdout);
  const binaries = await binaryPaths(repository, base, head);
  const entries: GitScopeEntry[] = [];
  for (let index = 0; index < values.length;) {
    const code = values[index++]!;
    const status = code[0];
    const oldPath = status === "R" || status === "C" ? values[index++] : undefined;
    const path = values[index++];
    if (!path || !safeRepoPath(path) || (oldPath && !safeRepoPath(oldPath))) throw new Error("Git returned an unsafe or malformed changed path.");
    if (!inTarget(path, prefix) && !(oldPath && inTarget(oldPath, prefix))) continue;
    const mapped = status === "A" || status === "C" ? "added" : status === "D" ? "deleted" : status === "R" ? "renamed" : "modified";
    entries.push({
      status: mapped,
      path,
      ...(oldPath ? { old_path: oldPath } : {}),
      binary: binaries.has(path),
      generated: generatedPath(path),
      submodule: false,
      inspected: mapped !== "deleted" && !binaries.has(path) && !generatedPath(path),
      ...(mapped === "deleted" ? { note: "Deleted path inspected through the resulting repository context; no deleted content was scanned." }
        : binaries.has(path) ? { note: "Binary content was not inspected by source analyzers." }
          : generatedPath(path) ? { note: "Generated/build artifact is recorded but excluded by source analyzers." } : {}),
    });
    if (entries.length > MAX_SCOPE_ENTRIES) throw new Error(`Git scope exceeds the ${MAX_SCOPE_ENTRIES}-entry safety limit.`);
  }
  return entries;
}

function boundedOutputError(error: unknown): boolean {
  return error instanceof Error && /Git output exceeded the \d+-byte safety limit/.test(error.message);
}

async function appendWorkingTreeOnlyEntries(repository: string, prefix: string, entries: GitScopeEntry[]): Promise<string[]> {
  const limitations: string[] = [];
  const trackedPaths = new Set(entries.map((entry) => entry.path));
  let untracked;
  try {
    untracked = await runGitReadBuffer(repository, ["ls-files", "--others", "--exclude-standard", "-z"]);
  } catch (error) {
    if (!boundedOutputError(error)) throw error;
    limitations.push("Non-ignored untracked path enumeration exceeded its bounded output limit; untracked coverage is incomplete.");
  }
  if (untracked && untracked.code !== 0) throw new Error(`Git could not enumerate untracked paths${untracked.stderr ? `: ${untracked.stderr}` : "."}`);
  for (const path of untracked ? splitNul(untracked.stdout) : []) {
    if (!safeRepoPath(path)) throw new Error("Git returned an unsafe untracked path.");
    if (!inTarget(path, prefix) || trackedPaths.has(path)) continue;
    const inspection = await inspectUntrackedFile(join(repository, path));
    const binary = inspection.binary;
    entries.push({ status: "untracked", path, binary, generated: generatedPath(path), submodule: false, inspected: inspection.readable && !generatedPath(path) && !binary,
      ...(!inspection.readable ? { note: inspection.note }
        : binary ? { note: "Binary content was not inspected by source analyzers." }
        : generatedPath(path) ? { note: "Generated/build artifact is recorded but excluded by source analyzers." } : {}) });
    if (entries.length > MAX_SCOPE_ENTRIES) throw new Error(`Git scope exceeds the ${MAX_SCOPE_ENTRIES}-entry safety limit.`);
  }
  let ignored;
  try {
    ignored = await runGitReadBuffer(repository, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], { maxBytes: 4 * 1024 * 1024 });
  } catch (error) {
    if (!boundedOutputError(error)) throw error;
    limitations.push("Ignored path enumeration exceeded its bounded output limit; ignored-path metadata is incomplete.");
  }
  if (!ignored) return limitations;
  if (ignored.code !== 0) throw new Error(`Git could not enumerate ignored paths${ignored.stderr ? `: ${ignored.stderr}` : "."}`);
  for (const path of splitNul(ignored.stdout)) {
    if (!safeRepoPath(path)) throw new Error("Git returned an unsafe ignored path.");
    if (!inTarget(path, prefix)) continue;
    entries.push({ status: "ignored", path, binary: false, generated: generatedPath(path), submodule: false, inspected: false, note: "Ignored path is outside the declared working-tree scan scope." });
    if (entries.length > MAX_SCOPE_ENTRIES) throw new Error(`Git scope exceeds the ${MAX_SCOPE_ENTRIES}-entry safety limit.`);
  }
  return limitations;
}

async function inspectUntrackedFile(path: string): Promise<{ binary: boolean; readable: boolean; note?: string }> {
  let handle;
  try {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) return { binary: false, readable: false, note: "Symbolic-link content was not inspected." };
    if (!metadata.isFile()) return { binary: false, readable: false, note: "Non-regular content was not inspected." };
    handle = await open(path, "r");
    const buffer = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return { binary: buffer.subarray(0, bytesRead).includes(0), readable: true };
  } catch {
    return { binary: false, readable: false, note: "Unreadable content was not inspected." };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function classifyWorkingTreeLinks(repository: string, entries: GitScopeEntry[]): Promise<void> {
  for (const entry of entries) {
    if (["deleted", "ignored", "untracked"].includes(entry.status)) continue;
    try {
      const metadata = await lstat(join(repository, entry.path));
      if (metadata.isSymbolicLink()) {
        entry.inspected = false;
        entry.note = "Symbolic-link content was not inspected.";
      }
    } catch {
      entry.inspected = false;
      entry.note = "Changed path was unreadable during scope inspection.";
    }
  }
}

async function markSubmodules(
  repository: string,
  entries: GitScopeEntry[],
  commits: string[],
  includeIndex: boolean,
): Promise<string[]> {
  const gitlinks = new Set<string>();
  const requests = [
    ...commits.map((commit) => ["ls-tree", "-r", "-z", "--full-tree", commit]),
    ...(includeIndex ? [["ls-files", "--stage", "-z"]] : []),
  ];
  for (const args of requests) {
    let result;
    try {
      result = await runGitReadBuffer(repository, args, { maxBytes: 32 * 1024 * 1024 });
    } catch (error) {
      if (!boundedOutputError(error)) throw error;
      return ["Gitlink enumeration exceeded its bounded output limit; submodule classification is incomplete."];
    }
    if (result.code !== 0) throw new Error(`Git could not enumerate gitlinks${result.stderr ? `: ${result.stderr}` : "."}`);
    for (const record of splitNul(result.stdout)) {
      const tab = record.indexOf("\t");
      if (tab > 0 && record.startsWith("160000 ")) gitlinks.add(record.slice(tab + 1));
    }
  }
  for (const entry of entries) {
    if (gitlinks.has(entry.path)) {
      entry.submodule = true;
      entry.inspected = false;
      entry.note = "Gitlink recorded; submodule contents were not inspected.";
    }
  }
  return [];
}

export async function materializeGitCommit(repository: string, commit: string): Promise<{
  directory: string;
  limitations: string[];
  skipped: Array<{ path: string; kind: "symlink" | "submodule" }>;
}> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-git-"));
  trackTemporaryDirectory(directory);
  const limitations: string[] = [];
  const skipped: Array<{ path: string; kind: "symlink" | "submodule" }> = [];
  try {
    const tree = await runGitReadBuffer(repository, ["ls-tree", "-r", "-z", "--full-tree", commit], { maxBytes: 32 * 1024 * 1024 });
    if (tree.code !== 0) throw new Error(`Git could not enumerate commit tree${tree.stderr ? `: ${tree.stderr}` : "."}`);
    const records = splitNul(tree.stdout);
    if (records.length > MAX_TREE_ENTRIES) throw new Error(`Commit tree exceeds the ${MAX_TREE_ENTRIES}-entry safety limit.`);
    let totalBytes = 0;
    for (const record of records) {
      const tab = record.indexOf("\t");
      const header = record.slice(0, tab).split(" ");
      const path = record.slice(tab + 1);
      if (tab < 0 || header.length !== 3 || !safeRepoPath(path)) throw new Error("Git returned an unsafe or malformed tree entry.");
      const [mode, type, object] = header;
      if (type === "commit" || mode === "160000") {
        limitations.push(`Submodule gitlink ${path} was not materialized.`);
        skipped.push({ path, kind: "submodule" });
        continue;
      }
      if (type !== "blob" || !/^[0-9a-f]{40,64}$/.test(object!)) throw new Error(`Unsupported Git tree entry at ${path}.`);
      if (mode === "120000") {
        limitations.push(`Symbolic link ${path} was not materialized.`);
        skipped.push({ path, kind: "symlink" });
        continue;
      }
      const blob = await runGitReadBuffer(repository, ["cat-file", "blob", object!], { maxBytes: MAX_BLOB_BYTES });
      if (blob.code !== 0) throw new Error(`Git could not read blob for ${path}.`);
      totalBytes += blob.stdout.length;
      if (totalBytes > MAX_TREE_BYTES) throw new Error(`Commit content exceeds the ${MAX_TREE_BYTES}-byte materialization limit.`);
      const destination = resolve(directory, path);
      if (!destination.startsWith(`${directory}${sep}`)) throw new Error("Commit tree path escaped the isolated snapshot.");
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, blob.stdout, { flag: "wx" });
      if (mode === "100755") await chmod(destination, 0o755);
    }
    return { directory, limitations, skipped };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    releaseTemporaryDirectory(directory);
    throw error;
  }
}

function primaryPaths(entries: GitScopeEntry[]): string[] {
  return [...new Set(entries.filter((entry) => !["deleted", "ignored"].includes(entry.status)).map((entry) => entry.path))].sort();
}

function scopeRole(path: string, primary: Set<string>): Finding["scope_role"] {
  const normalized = path.replace(/\\/g, "/").replace(/^\.\//, "");
  return primary.has(normalized) ? "primary" : "supporting_context";
}

function scopeLimitations(entries: GitScopeEntry[], materialization: string[]): string[] {
  const limitations = [...materialization];
  if (entries.some((entry) => entry.binary)) limitations.push("Binary changed content was enumerated but not inspected by source analyzers.");
  if (entries.some((entry) => entry.submodule)) limitations.push("Submodule gitlinks were enumerated but submodule contents were not inspected.");
  if (entries.some((entry) => entry.generated && entry.status !== "ignored")) limitations.push("Generated/build changed paths were enumerated but excluded by source analyzers.");
  if (entries.some((entry) => /symbolic-link/i.test(entry.note ?? ""))) limitations.push("Changed symbolic-link content was enumerated but not inspected.");
  if (entries.some((entry) => /unreadable/i.test(entry.note ?? ""))) limitations.push("One or more changed paths were unreadable and not inspected.");
  return [...new Set(limitations)].sort();
}

/** Execute a read-only Git-scoped scan and persist only the final original-repository record. */
/** The merge-base of `base` and `head`, so changes made only on the base branch are not attributed to the change. */
async function mergeBase(repository: string, base: string, head: string): Promise<string | undefined> {
  const result = await runGitReadBuffer(repository, ["merge-base", "--end-of-options", base, head], { maxBytes: 1024 });
  const commit = result.stdout.toString("utf8").trim();
  return result.code === 0 && /^[0-9a-f]{40,64}$/.test(commit) ? commit : undefined;
}

/**
 * Git hides working-tree edits to index entries flagged skip-worktree or assume-unchanged, and a
 * path removed from the index with `git rm --cached` shows as deleted even though an edited copy is
 * still on disk. Both are changes in the working tree, so they are brought into scope.
 */
async function appendHiddenWorkingTreeChanges(repository: string, prefix: string, entries: GitScopeEntry[]): Promise<void> {
  for (const entry of entries) {
    if (entry.status !== "deleted") continue;
    const present = await lstat(join(repository, entry.path)).then((metadata) => metadata.isFile(), () => false);
    if (!present) continue;
    const inspection = await inspectUntrackedFile(join(repository, entry.path));
    entry.status = "modified";
    entry.binary = inspection.binary;
    entry.inspected = inspection.readable && !entry.generated && !inspection.binary;
    entry.note = "Removed from the index but still present in the working tree; scanned as a working-tree change.";
  }
  const deletedPresent = new Set(entries.filter((entry) => entry.status === "modified").map((entry) => entry.path));
  for (let index = entries.length - 1; index >= 0; index--) {
    if (entries[index]!.status === "ignored" && deletedPresent.has(entries[index]!.path)) entries.splice(index, 1);
  }
  const listed = await runGitReadBuffer(repository, ["ls-files", "-v", "-z"], { maxBytes: 32 * 1024 * 1024 });
  if (listed.code !== 0) throw new Error(`Git could not enumerate index flags${listed.stderr ? `: ${listed.stderr}` : "."}`);
  const known = new Set(entries.map((entry) => entry.path));
  for (const record of splitNul(listed.stdout)) {
    const tag = record.slice(0, 1);
    const path = record.slice(2);
    if (!(tag === "S" || /^[a-z]$/.test(tag)) || !safeRepoPath(path) || !inTarget(path, prefix) || known.has(path)) continue;
    const absolute = join(repository, path);
    if (!(await lstat(absolute).then((metadata) => metadata.isFile(), () => false))) continue;
    const indexed = await runGitReadBuffer(repository, ["ls-files", "-s", "-z", "--", path], { maxBytes: 64 * 1024 });
    const blob = indexed.stdout.toString("utf8").split(" ")[1];
    const current = await runGitReadBuffer(repository, ["hash-object", "--no-filters", "--", absolute], { maxBytes: 1024 });
    if (blob && current.code === 0 && current.stdout.toString("utf8").trim() === blob) continue;
    const inspection = await inspectUntrackedFile(absolute);
    entries.push({
      status: "modified", path, binary: inspection.binary, generated: generatedPath(path), submodule: false,
      inspected: inspection.readable && !generatedPath(path) && !inspection.binary,
      note: "Index entry is flagged skip-worktree or assume-unchanged, which hides its changes from git; scanned as a working-tree change.",
    });
    if (entries.length > MAX_SCOPE_ENTRIES) throw new Error(`Git scope exceeds the ${MAX_SCOPE_ENTRIES}-entry safety limit.`);
  }
}

/**
 * A change can introduce a finding outside the changed paths, for example deleting a migration that
 * enabled row-level security. Scan the base commit with the same configuration and promote every
 * supporting-context finding that is not present there (by identity or as moved content).
 */
async function findingsIntroducedOutsideChanges(
  repository: string,
  base: string,
  input: ScanInput,
  findings: Finding[],
  primary: Set<string>,
  prefix: string,
  ignored: ReadonlySet<string>,
): Promise<{ introduced: Set<Finding>; limitation?: string }> {
  // Only findings inside the declared target and outside git-ignored paths can be promoted: a
  // per-package job must not fail on another package, and ignored files are outside the scope.
  const supporting = findings.filter((finding) =>
    scopeRole(finding.location.file, primary) === "supporting_context" &&
    inTarget(finding.location.file.replace(/\\/g, "/"), prefix) &&
    !ignored.has(finding.location.file.replace(/\\/g, "/")));
  if (!supporting.length) return { introduced: new Set() };
  let snapshot: Awaited<ReturnType<typeof materializeGitCommit>>;
  try {
    snapshot = await materializeGitCommit(repository, base);
  } catch (error) {
    return { introduced: new Set(), limitation: `The base commit could not be scanned to find findings introduced outside the changed paths: ${error instanceof Error ? error.message : String(error)}` };
  }
  try {
    const baseFindings = (await executeScan({ ...input, path: snapshot.directory }, { persist: false })).canonical.findings;
    const unmatched = supporting.filter((finding) => !baseFindings.some((candidate) => findingsMatch(candidate, finding)));
    const moved = pairMovedFindings(
      baseFindings.filter((candidate) => !findings.some((finding) => findingsMatch(candidate, finding))),
      unmatched,
    );
    // Submodule contents are not in the base snapshot, so findings inside a submodule are not
    // comparable and are never promoted. A base symlink that a scanner could interpret (anything
    // but documentation) might carry context that changes base findings, so it fails closed.
    const submodules = snapshot.skipped.filter((item) => item.kind === "submodule").map((item) => item.path);
    const interpretableLinks = snapshot.skipped.filter((item) => item.kind === "symlink" && !isDocumentationName(basename(item.path)));
    const inSubmodule = (file: string) => submodules.some((path) => file === path || file.startsWith(`${path}/`));
    return {
      introduced: new Set(unmatched.filter((finding) => !moved.has(finding) && !inSubmodule(finding.location.file.replace(/\\/g, "/")))),
      ...(interpretableLinks.length ? {
        limitation: `Base-commit symbolic link(s) ${interpretableLinks.map((item) => item.path).join(", ")} could not be materialized, so findings introduced outside the changed paths may be incomplete.`,
      } : {}),
    };
  } finally {
    await rm(snapshot.directory, { recursive: true, force: true }).catch(() => undefined);
    releaseTemporaryDirectory(snapshot.directory);
  }
}

export async function runGitScopedScan(input: ScanInput, request: GitScopeRequest): Promise<ScanResult> {
  const targetInspection = await requireSafeScanTarget(input.path);
  if (targetInspection.type !== "directory") throw new Error("Git-scoped scans require a directory target.");
  const repository = await findGitRepositoryRoot(targetInspection.canonical_path);
  const prefix = targetPrefix(repository, targetInspection.canonical_path);
  const requestedBase = await resolveGitCommit(repository, request.base, "--diff/--base");
  if (request.mode === "commit_diff" && !request.head) throw new Error("A commit-diff scan requires an exact head revision.");
  const head = request.mode === "commit_diff" ? await resolveGitCommit(repository, request.head!, "--head") : undefined;
  const base = await mergeBase(repository, requestedBase, head ?? "HEAD") ?? requestedBase;
  if (!head) {
    // Comparing the working tree makes git run the repository's own filter drivers.
    const drivers = await repositoryFilterDrivers(repository);
    if (drivers.length) {
      throw new Error(`Working-tree Git scope refused: the repository config defines filter driver(s) ${drivers.join(", ")} that git would execute. Use --head with an exact commit, or remove the drivers.`);
    }
  }
  const entries = await changedEntries(repository, base, head, prefix);
  const enumerationLimitations = request.mode === "working_tree"
    ? await appendWorkingTreeOnlyEntries(repository, prefix, entries)
    : [];
  if (request.mode === "working_tree") await appendHiddenWorkingTreeChanges(repository, prefix, entries);
  if (request.mode === "working_tree") await classifyWorkingTreeLinks(repository, entries);
  const gitlinkLimitations = await markSubmodules(repository, entries, [base, ...(head ? [head] : [])], request.mode === "working_tree");

  // Supporting context is the exact repository tree, even when the declared target is a
  // subdirectory. This lets framework/config/auth/lockfile and workflow-chain evidence inform
  // changed-path findings without pretending those supporting files are primary changes.
  let scanTarget = repository;
  let cleanup: string | undefined;
  let materializationLimitations: string[] = [];
  if (request.mode === "commit_diff") {
    const snapshot = await materializeGitCommit(repository, head!);
    cleanup = snapshot.directory;
    materializationLimitations = snapshot.limitations;
    scanTarget = snapshot.directory;
    for (const entry of entries) {
      if (materializationLimitations.some((limitation) => limitation.includes(entry.path))) {
        entry.inspected = false;
        entry.note = materializationLimitations.find((limitation) => limitation.includes(entry.path));
      }
    }
  }
  try {
    const execution = await executeScan({ ...input, path: scanTarget }, { persist: false });
    const primary = new Set(primaryPaths(entries));
    const ignoredPaths = new Set(entries.filter((entry) => entry.status === "ignored").map((entry) => entry.path));
    const introducedCheck = await findingsIntroducedOutsideChanges(repository, base, input, execution.canonical.findings, primary, prefix, ignoredPaths);
    const limitations = scopeLimitations(entries, [
      ...materializationLimitations, ...enumerationLimitations, ...gitlinkLimitations,
      ...(introducedCheck.limitation ? [introducedCheck.limitation] : []),
    ]);
    const scopedFindings = execution.canonical.findings.map((finding) => ({
      ...finding,
      scope_role: introducedCheck.introduced.has(finding) ? "primary" as const : scopeRole(finding.location.file, primary),
    }));
    const introducedNote = introducedCheck.introduced.size
      ? [`${introducedCheck.introduced.size} finding(s) outside the changed paths are new relative to the base commit and are treated as primary.`]
      : [];
    const scope: GitScanScope = {
      schema_version: "1.0.0",
      mode: request.mode,
      repository,
      base: { requested: request.base, commit: base },
      ...(head ? { head: { requested: request.head!, commit: head } } : {}),
      entries: entries.sort((left, right) => left.path.localeCompare(right.path)),
      primary_paths: [...primary],
      primary_finding_count: scopedFindings.filter((finding) => finding.scope_role === "primary").length,
      supporting_context_finding_count: scopedFindings.filter((finding) => finding.scope_role === "supporting_context").length,
      supporting_context_scanned: true,
      completeness: limitations.length ? "partial" : "complete",
      limitations,
    };
    const canonical: ScanResult = {
      ...execution.canonical,
      target: targetInspection.canonical_path,
      repository_root: repository,
      findings: scopedFindings,
      git_scope: scope,
      git_safety: request.mode === "commit_diff" ? await detectGitSafety(repository) : execution.canonical.git_safety,
      warnings: [...execution.canonical.warnings, ...introducedNote, ...limitations.map((limitation) => `Git scope partial: ${limitation}`)],
    };
    await saveScan(canonical, { canonicalFindings: true });
    return projectScanForDisplay(canonical, input);
  } finally {
    if (cleanup) {
      await rm(cleanup, { recursive: true, force: true }).catch(() => undefined);
      releaseTemporaryDirectory(cleanup);
    }
  }
}
