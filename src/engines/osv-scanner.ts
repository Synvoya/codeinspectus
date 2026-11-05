/**
 * osv-scanner wrapper — offline dependency vulnerability and malicious-package matching.
 *
 * ZERO-EGRESS GUARDRAIL (PRD §7): every invocation passes --offline and reads only the per-ecosystem
 * OSV databases that `setup` downloaded under MANAGED_OSV_DB. The scan never touches the network.
 * `--config` always points at a managed, comment-only file, so a repository's own osv-scanner.toml
 * (IgnoredVulns, PackageOverrides) cannot silence or rewrite results; `--no-ignore` keeps a lockfile
 * listed in .gitignore in scope. `--no-call-analysis=all` is required: by default 2.7.0 runs Go call
 * analysis (govulncheck) on go.mod projects, which invokes the Go toolchain and may download modules.
 * Never added: --call-analysis, --licenses, --download-offline-databases, --offline-vulnerabilities,
 * --data-source, --serve.
 *
 * osv-scanner fails the WHOLE scan when the archive for an ecosystem it saw is missing (PyPI, SwiftURL
 * and others do; npm is silent), so each run reads a per-scan overlay directory instead of the managed
 * one: a symlink to every installed archive (a hard link where the platform refuses symlinks, never a
 * copy) and a valid empty zip for every other ecosystem OSV publishes or its schema names, allow-listed or
 * not. Coverage is still derived from the allow-list, managed archive and provenance record, never from
 * the overlay.
 *
 * Output is native findings (the Pub engine shape), not SARIF: one finding per (package, advisory
 * group), carrying the structured `package` so dedup can merge across scanners without collapsing
 * different packages that share an advisory.
 */

import { randomUUID } from "node:crypto";
import { link, lstat, mkdir, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

import { MANAGED_OSV_CONFIG, MANAGED_OSV_DB } from "../config.js";
import { log } from "../logger.js";
import { osvDbZipPath, readOsvDbRecord, type OsvDbRecord } from "../osv/database.js";
import { packageEntryLine, readLockfileLines as readLines, type LockfileLines } from "../osv/package-line.js";
import {
  isOsvEcosystem,
  isOverlaySegment,
  normalizePackageName,
  OSV_ECOSYSTEMS,
  OSV_OVERLAY_ECOSYSTEMS,
  type OsvEcosystem,
} from "../osv/ecosystems.js";
import {
  invocationSignature,
  osvDatabaseComponent,
  osvSbomFindingComponents,
  osvScannerFindingComponents,
  signature,
} from "../provenance.js";
import type { DependencyCoverage, EngineRunInfo, Finding, Severity } from "../types.js";
import { SEVERITY_RANK } from "../types.js";
import { fingerprint as makeFingerprint } from "../util/hash.js";
import { execBinary, type ExecResult } from "./exec.js";
import { EngineUnavailableError, resolveEngine } from "./resolve.js";
import { engineWorkingDirectory } from "./target.js";

export interface OsvScanResult {
  info: EngineRunInfo;
  /**
   * False only when osv-scanner is not installed: add nothing to the scan. A completed run that found no
   * package sources is applicable (an engine run with no findings), so rescan can prove that removing
   * the last lockfile resolved its findings.
   */
  applicable: boolean;
  findings: Finding[];
  /** One entry per ecosystem osv-scanner listed, in allow-list order. */
  coverage: DependencyCoverage[];
  /** Files osv-scanner's JSON listed packages from, relative to the target and `/`-separated, sorted. */
  lockfiles: string[];
  /**
   * Every package osv-scanner listed (`--all-packages`), vulnerable or not, in output order, with the
   * target-relative file it came from: the package inventory the Synvoya gap layer evaluates.
   */
  packages?: Array<{
    ecosystem: string;
    name: string;
    version: string;
    file: string;
    /** The source was outside the target: `file` is only its name, so no line may be looked up from it. */
    outside?: true;
  }>;
  componentSignatures: Record<string, string>;
  /** Everything the user should be told; the caller forwards these and need not warn from `info.note` as well. */
  warnings: string[];
}

const MANAGED_CONFIG_CONTENT =
  "# CodeInspectus managed osv-scanner configuration.\n" +
  "# Intentionally empty: passing this file with --config stops a repository's own osv-scanner.toml\n" +
  "# (IgnoredVulns, PackageOverrides, ...) from silencing or rewriting results. Do not add rules here.\n";

const MAX_OUTPUT_BYTES = 128 * 1024 * 1024;
const MAX_FIXED_VERSIONS = 6;
const MAX_TEXT = 240;
const MAX_NAME = 214; // the npm package-name limit, the longest of the ecosystems
const MAX_VERSION = 128;
/** OSV identifiers (CVE-, GHSA-, PYSEC-, MAL-, openSUSE-SU-2020:1234-1, ...). */
const ADVISORY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function buildOsvScannerArgs(target: string, outputPath: string, configPath: string): string[] {
  // Defence in depth: the scan boundary canonicalises the target, and a relative one would resolve against cwd.
  if (!isAbsolute(target)) throw new Error("osv-scanner needs an absolute scan target.");
  return [...scanFlags(outputPath, configPath), "-r", target];
}

/** The flags every osv-scanner run takes, whatever it reads. */
function scanFlags(outputPath: string, configPath: string): string[] {
  return [
    "scan",
    "source",
    "--offline",
    "--no-resolve",
    "--no-ignore",
    "--allow-no-lockfiles",
    "--all-packages",
    "--no-call-analysis=all",
    "--format",
    "json",
    "--output-file",
    outputPath,
    "--config",
    configPath,
  ];
}

/**
 * The per-scan SBOM's file name. osv-scanner 2.7.0 reads a CycloneDX SBOM through `scan source -L <file>`
 * (`--lockfile`), and picks its CycloneDX extractor from the file name: `<name>.cdx.json` is read, while
 * `sbom.json` exits 127 with "could not determine extractor suitable to this file" and the parser-prefixed
 * `-L cyclonedx:<file>` is refused ("could not determine extractor"); `--sbom` is deprecated. The name is
 * passed relative to the run's working directory (the SBOM's folder), so no drive letter or other `:` in an
 * absolute path can be read as a `-L <parser>:<path>` prefix. Its JSON result keys each package by the
 * component's `name` and `version` (not the purl), lists identical name@version components once, and carries
 * no bom-ref, so callers map packages back by ecosystem, name and version. Verified against the real 2.7.0
 * binary (2026-11-04); the engine eval E87 runs it.
 */
export const OSV_SBOM_FILE_NAME = "inventory.cdx.json";

/** The main run's flags with `-L <SBOM>` in place of `-r <target>`: offline, managed config, no resolution. */
export function buildOsvScannerSbomArgs(sbomName: string, outputPath: string, configPath: string): string[] {
  if (sbomName !== OSV_SBOM_FILE_NAME) throw new Error(`osv-scanner reads the managed SBOM only as ${OSV_SBOM_FILE_NAME}.`);
  return [...scanFlags(outputPath, configPath), "-L", sbomName];
}

/** The SBOM run's invocation signature: its arguments with the managed paths as placeholders, so it is constant. */
export function osvSbomInvocationSignature(): string {
  return invocationSignature("osv-scanner", buildOsvScannerSbomArgs(OSV_SBOM_FILE_NAME, "<managed-temp>", "<managed-config>"));
}

// ── osv-scanner JSON ────────────────────────────────────────────────────────

interface ParsedAdvisory {
  id: string;
  summary?: string;
  /** Raw `database_specific.severity` ("CRITICAL", "MODERATE", ...). */
  databaseSeverity?: string;
  cwes: string[];
  affected: Array<{ ecosystem: string; name: string; fixed: string[] }>;
}

interface ParsedGroup {
  ids: string[];
  aliases: string[];
  /** CVSS score osv-scanner computed for the group; undefined when it reported none. */
  score?: number;
}

interface ParsedPackage {
  ecosystem: string;
  name: string;
  version: string;
  groups: ParsedGroup[];
  advisories: Map<string, ParsedAdvisory>;
}

interface ParsedSource {
  path: string;
  packages: ParsedPackage[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

/** Advisory ids end up in rule ids and URLs, so anything that is not an identifier is dropped. */
function advisoryIds(value: unknown): string[] {
  return strings(value).filter((id) => ADVISORY_ID.test(id));
}

/** Package names and versions come from the scanned repository's lockfile: strip control characters, bound the length. */
function identifier(value: unknown, max: number): string | undefined {
  const cleaned = typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]+/g, "").slice(0, max) : "";
  return cleaned.length > 0 ? cleaned : undefined;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Advisory text is third-party data: flatten it to one printable line of bounded length. */
function oneLine(value: string): string {
  const flat = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return flat.length > MAX_TEXT ? `${flat.slice(0, MAX_TEXT - 1)}…` : flat;
}

function parseAdvisory(raw: unknown): ParsedAdvisory | undefined {
  if (!isRecord(raw)) return undefined;
  const id = advisoryIds([raw.id])[0];
  if (!id) return undefined;
  const databaseSpecific = isRecord(raw.database_specific) ? raw.database_specific : {};
  const affected = (Array.isArray(raw.affected) ? raw.affected : []).flatMap((entry) => {
    if (!isRecord(entry) || !isRecord(entry.package)) return [];
    const ecosystem = text(entry.package.ecosystem);
    const name = text(entry.package.name);
    if (!ecosystem || !name) return [];
    // Only ECOSYSTEM and SEMVER ranges carry installable versions; GIT ranges carry commit hashes.
    const fixed = (Array.isArray(entry.ranges) ? entry.ranges : []).flatMap((range) =>
      isRecord(range) && (range.type === "ECOSYSTEM" || range.type === "SEMVER") && Array.isArray(range.events)
        ? range.events.flatMap((event) => (isRecord(event) && text(event.fixed) ? [event.fixed as string] : []))
        : []);
    return [{ ecosystem, name, fixed }];
  });
  return {
    id,
    summary: text(raw.summary),
    databaseSeverity: text(databaseSpecific.severity),
    cwes: strings(databaseSpecific.cwe_ids).filter((cwe) => /^CWE-\d{1,5}$/.test(cwe)),
    affected,
  };
}

function parseGroup(raw: unknown): ParsedGroup | undefined {
  if (!isRecord(raw)) return undefined;
  const ids = advisoryIds(raw.ids);
  const aliases = advisoryIds(raw.aliases);
  if (!ids.length && !aliases.length) return undefined;
  const score = Number.parseFloat(typeof raw.max_severity === "string" ? raw.max_severity : "");
  return { ids, aliases, ...(Number.isFinite(score) ? { score } : {}) };
}

function parsePackage(raw: unknown): ParsedPackage | undefined {
  if (!isRecord(raw) || !isRecord(raw.package)) return undefined;
  const name = identifier(raw.package.name, MAX_NAME);
  if (!name) return undefined;
  const advisories = new Map<string, ParsedAdvisory>();
  const ungrouped: ParsedGroup[] = [];
  for (const entry of Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : []) {
    const advisory = parseAdvisory(entry);
    if (!advisory) continue;
    advisories.set(advisory.id, advisory);
    ungrouped.push({ ids: [advisory.id], aliases: isRecord(entry) ? advisoryIds(entry.aliases) : [] });
  }
  const groups = (Array.isArray(raw.groups) ? raw.groups : []).flatMap((group) => parseGroup(group) ?? []);
  return {
    ecosystem: identifier(raw.package.ecosystem, MAX_VERSION) ?? "",
    name,
    version: identifier(raw.package.version, MAX_VERSION) ?? "",
    // Advisories without groups would otherwise vanish: report each on its own rather than lose it.
    groups: groups.length ? groups : ungrouped,
    advisories,
  };
}

/** Advisory groups osv-scanner reported for one package entry (each vulnerability when it gave no groups). */
function reportedGroups(entry: unknown): number {
  if (!isRecord(entry)) return 0;
  const groups = Array.isArray(entry.groups) ? entry.groups.length : 0;
  return groups || (Array.isArray(entry.vulnerabilities) ? entry.vulnerabilities.length : 0);
}

/**
 * Undefined when the document is not osv-scanner's result shape: never read as "no findings". `dropped`
 * counts the advisory groups lost to an unreadable package name or advisory id.
 */
function parseOutput(raw: string): { sources: ParsedSource[]; dropped: number } | undefined {
  let document: unknown;
  try {
    document = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!isRecord(document) || !Array.isArray(document.results)) return undefined;
  const sources: ParsedSource[] = [];
  let dropped = 0;
  for (const result of document.results) {
    if (!isRecord(result) || !isRecord(result.source)) return undefined;
    const path = text(result.source.path);
    if (!path) return undefined;
    const packages: ParsedPackage[] = [];
    for (const entry of Array.isArray(result.packages) ? result.packages : []) {
      const pkg = parsePackage(entry);
      dropped += Math.max(0, reportedGroups(entry) - (pkg?.groups.length ?? 0));
      if (pkg) packages.push(pkg);
    }
    if (packages.length) sources.push({ path, packages });
  }
  return { sources, dropped };
}

// ── location ────────────────────────────────────────────────────────────────

interface TargetInfo {
  path: string;
  isFile: boolean;
}

/** Path relative to the scan target (like Trivy), plus the absolute path only when it is inside the target. */
function locate(target: TargetInfo, sourcePath: string): { file: string; absolute?: string } {
  if (target.isFile) return { file: basename(target.path), absolute: target.path };
  const absolute = isAbsolute(sourcePath) ? sourcePath : resolve(target.path, sourcePath);
  const inside = relative(target.path, absolute);
  if (!inside || inside.startsWith("..") || isAbsolute(inside)) {
    log.debug(`osv-scanner reported a source outside the scan target; reporting its file name only: ${basename(absolute)}`);
    return { file: basename(absolute) };
  }
  return { file: inside.split("\\").join("/"), absolute };
}

// ── findings ────────────────────────────────────────────────────────────────

const SEVERITY_BY_LABEL: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  medium: "medium",
  low: "low",
};

function severityFor(group: ParsedGroup, records: ParsedAdvisory[], malicious: boolean): Severity {
  if (malicious) return "critical";
  const score = group.score;
  if (score !== undefined && score > 0) {
    return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  }
  const labelled = records
    .map((record) => SEVERITY_BY_LABEL[record.databaseSeverity?.toLowerCase() ?? ""])
    .filter((severity): severity is Severity => severity !== undefined);
  if (!labelled.length) return "medium";
  return labelled.reduce((highest, severity) => (SEVERITY_RANK[severity] > SEVERITY_RANK[highest] ? severity : highest));
}

function unique<T>(items: Iterable<T>): T[] {
  return [...new Set(items)];
}

/** CVE first (it is what Trivy reports), then GHSA, then whatever osv-scanner lists first. */
function chooseRuleId(group: ParsedGroup): string | undefined {
  const all = unique([...group.ids, ...group.aliases]).sort();
  return all.find((id) => /^CVE-\d{4}-\d+$/i.test(id)) ?? all.find((id) => /^GHSA-/i.test(id)) ?? group.ids[0] ?? group.aliases[0];
}

/**
 * OSV keys Drupal contrib packages as `https://packages.drupal.org/8:drupal/<module>`. Packagist values
 * lose a leading repository URL ending in `:` before comparing; comparison only, never a fingerprint input.
 */
function packagistValue(ecosystem: string, value: string): string {
  return ecosystem === "Packagist" ? value.replace(/^https?:\/\/[^\s/]+(?:\/[^\s:]*)?:/, "") : value;
}

function fixedVersions(records: ParsedAdvisory[], pkg: ParsedPackage): string[] {
  const name = normalizePackageName(packagistValue(pkg.ecosystem, pkg.name));
  return unique(
    records.flatMap((record) => record.affected
      .filter((entry) => entry.ecosystem === pkg.ecosystem && normalizePackageName(packagistValue(entry.ecosystem, entry.name)) === name)
      .flatMap((entry) => entry.fixed.map((version) => packagistValue(entry.ecosystem, version)))),
  ).slice(0, MAX_FIXED_VERSIONS);
}

interface FindingContext {
  file: string;
  line: number;
  producerComponents: string[];
  database?: OsvDbRecord;
  /** Replaces the opening "<file> resolves <ecosystem> package <name@version>." sentence. */
  lead?: string;
  /**
   * The name the repository declares when osv-scanner matched the package under another (advisory) name: the
   * finding's title, remediation, package and fingerprint use it; the fixed releases still come from the
   * advisory's own package entry.
   */
  declaredName?: string;
  /** A vendored root: replaces `file` as the fingerprint's location input (see `OsvSbomLocation`). */
  fingerprintScope?: string;
}

function findingFor(pkg: ParsedPackage, group: ParsedGroup, context: FindingContext): Finding | undefined {
  const ruleId = chooseRuleId(group);
  if (!ruleId) return undefined;
  const records = group.ids
    .map((id) => pkg.advisories.get(id))
    .filter((record): record is ParsedAdvisory => record !== undefined)
    .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const malicious = [...group.ids, ...group.aliases].some((id) => /^MAL-/i.test(id));
  const summaryText = records.map((record) => record.summary).find((summary) => summary !== undefined);
  const summary = summaryText ? oneLine(summaryText) : ruleId;
  const aliases = unique([...group.ids, ...group.aliases]).filter((id) => id !== ruleId).sort();
  const cwe = unique([
    ...(malicious ? ["CWE-506"] : ["CWE-1395"]),
    ...records.flatMap((record) => record.cwes).sort(),
  ]);
  // The rule id leads when OSV has a record under that id (a CVE alias may not be one).
  const osvIds = unique([...(group.ids.includes(ruleId) ? [ruleId] : []), ...group.ids]);
  const references = [
    ...osvIds.map((id) => `https://osv.dev/vulnerability/${id}`),
    ...cwe.map((id) => `https://cwe.mitre.org/data/definitions/${id.slice(4)}.html`),
  ];
  const name = context.declaredName ?? pkg.name;
  const label = `${name}@${pkg.version}`;
  const fixed = fixedVersions(records, pkg);

  let remediationSummary: string;
  let steps: string[];
  if (malicious) {
    remediationSummary = `Remove ${label} and treat every environment that installed or ran it as compromised.`;
    steps = [
      `Remove ${label} from the dependency manifest and lockfile, then install a known-good release or an alternative package from the official registry.`,
      "Rotate every credential, token and API key that was reachable from any machine, CI runner or container that installed or imported this package, and revoke the old ones at the provider.",
      `Rebuild affected environments from a clean base and review logs for the activity described in the OSV record (${references[0] ?? "https://osv.dev"}).`,
      "Re-run CodeInspectus and confirm the malicious-package record no longer matches.",
    ];
  } else {
    remediationSummary = fixed.length === 1
      ? `Upgrade ${name} to ${fixed[0]}, the fixed release listed upstream, or remove the package.`
      : fixed.length
        ? `Upgrade ${name} to a fixed release listed upstream (${fixed.join(", ")}; choose the one on your release line), or remove the package.`
        : `Upgrade ${name} to a version not listed as affected, or remove the package.`;
    steps = [
      remediationSummary,
      "Regenerate the lockfile using your normal trusted package-manager workflow.",
      "Re-run CodeInspectus and confirm the advisory no longer matches the resolved version.",
      "If an immediate upgrade is impossible, assess whether the vulnerable code path is reachable in your application and consider an alternative package.",
    ];
  }

  const snapshot = context.database ? ` (database recorded ${context.database.recorded_at})` : "";
  const fingerprint = makeFingerprint([
    "osv-scanner",
    ...(context.fingerprintScope !== undefined ? ["vendored-root", context.fingerprintScope] : [context.file]),
    normalizePackageName(name),
    pkg.version,
    ruleId,
  ]);
  return {
    id: fingerprint,
    fingerprint,
    title: `${summary} (${label})`,
    severity: severityFor(group, records, malicious),
    engine: "osv-scanner",
    engines: ["osv-scanner"],
    rule_id: ruleId,
    ...(aliases.length ? { vulnerability_aliases: aliases } : {}),
    cwe,
    owasp_web: ["A06:2021"],
    location: { file: context.file, start_line: context.line, end_line: context.line },
    message:
      `${context.lead ?? `${context.file} resolves ${pkg.ecosystem} package ${label}.`} ` +
      `${ruleId} is reported against that exact version by osv-scanner using the offline OSV ${pkg.ecosystem} database${snapshot}. ` +
      (malicious
        ? "OSV classifies it as a malicious package: treat any environment that installed or ran it as potentially compromised. "
        : "") +
      "This proves dependency presence, not vulnerable-code reachability.",
    remediation: { summary: remediationSummary, steps, references },
    frameworks: [],
    confidence: "high",
    producer_components: context.producerComponents,
    finding_kind: "vulnerability",
    package: { ecosystem: pkg.ecosystem, name, version: pkg.version },
  };
}

// ── databases and coverage ──────────────────────────────────────────────────

interface DatabaseState {
  record?: OsvDbRecord;
  archive: boolean;
}

async function readDatabaseStates(): Promise<Map<OsvEcosystem, DatabaseState>> {
  const entries = await Promise.all(OSV_ECOSYSTEMS.map(async (ecosystem): Promise<[OsvEcosystem, DatabaseState]> => {
    const [record, metadata] = await Promise.all([
      readOsvDbRecord(ecosystem),
      stat(osvDbZipPath(ecosystem)).catch(() => undefined),
    ]);
    const archive = metadata?.isFile() === true;
    // As in health (inspectOsvDatabases): a record that does not describe the archive on disk proves
    // nothing about the bytes osv-scanner reads, so that database is `partial`, with no signature.
    return [ecosystem, { record: archive && record?.bytes === metadata?.size ? record : undefined, archive }];
  }));
  return new Map(entries);
}

/**
 * (Re)write the managed config before every run, atomically (temporary file, then rename), so its content
 * is always the managed constant: an edited copy (IgnoredVulns, PackageOverrides) is never honoured.
 * If the rename is refused (Windows, while a concurrent scan's osv-scanner has the file open), the run
 * proceeds only when the file on disk already holds exactly the managed content.
 */
async function writeManagedConfig(): Promise<string> {
  await mkdir(dirname(MANAGED_OSV_CONFIG), { recursive: true });
  const temporary = `${MANAGED_OSV_CONFIG}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, MANAGED_CONFIG_CONTENT, { encoding: "utf8", flag: "wx" });
    await rename(temporary, MANAGED_OSV_CONFIG);
  } catch (error) {
    const current = await readFile(MANAGED_OSV_CONFIG, "utf8").catch(() => undefined);
    if (current !== MANAGED_CONFIG_CONTENT) throw error;
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
  return MANAGED_CONFIG_CONTENT;
}

/** End-of-central-directory record only: a valid zip with no entries, which osv-scanner reads as an empty database. */
const EMPTY_ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(18)]);

/** The overlay could not be built; the message names the ecosystem and the errno code. */
class OverlayLinkError extends Error {}

/**
 * Windows without Developer Mode or elevation refuses file symlinks with one of these; some Linux file
 * systems (exFAT, FUSE, network shares) report EOPNOTSUPP.
 */
const SYMLINK_REFUSED = new Set(["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"]);

function errorCode(error: unknown): string {
  return (error as NodeJS.ErrnoException | undefined)?.code ?? "";
}

/** Link the managed archive into the overlay: a symlink, else a hard link. Never a copy (npm's is ~220 MB). */
async function linkArchive(ecosystem: OsvEcosystem, entry: string): Promise<void> {
  const source = osvDbZipPath(ecosystem);
  const failed = (error: unknown) =>
    new OverlayLinkError(`could not link the OSV ${ecosystem} database into the scan overlay: ${errorCode(error) || "unknown error"}`);
  try {
    await symlink(source, entry, "file");
    return;
  } catch (error) {
    // Any other failure (ENOSPC, EIO, ...) is reported by its code alone: its message holds absolute paths.
    if (!SYMLINK_REFUSED.has(errorCode(error))) throw failed(error);
  }
  try {
    await link(source, entry);
  } catch (error) {
    throw failed(error);
  }
}

/** The overlay directory for one ecosystem; the name is checked even though every caller passes a vetted one. */
function overlayEntry(overlay: string, ecosystem: string): string {
  if (!isOverlaySegment(ecosystem)) throw new OverlayLinkError("refused an OSV ecosystem name that is not one plain path segment");
  return join(overlay, "osv-scalibr", ecosystem, "all.zip");
}

/**
 * Per-scan database directory laid out as osv-scanner expects (`osv-scalibr/<Ecosystem>/all.zip`).
 * Installed allow-listed archives are linked, never copied (npm's is over 200 MB); every other
 * ecosystem OSV publishes or its schema names gets an empty zip, so neither a missing database nor a
 * lockfile from an ecosystem CodeInspectus does not support (SwiftURL, ConanCenter, ...) can fail the
 * scan for the ecosystems that are installed.
 */
async function buildDatabaseOverlay(
  overlay: string,
  databases: ReadonlyMap<OsvEcosystem, DatabaseState>,
): Promise<void> {
  // rm does not follow symlinks, so a reused directory loses only its links, never the managed archives.
  await rm(overlay, { recursive: true, force: true });
  // Settle every entry before reporting a failure, so no write is still running when the caller removes tmpDir.
  const results = await Promise.allSettled(OSV_OVERLAY_ECOSYSTEMS.map(async (ecosystem) => {
    const entry = overlayEntry(overlay, ecosystem);
    await mkdir(dirname(entry), { recursive: true });
    if (isOsvEcosystem(ecosystem) && databases.get(ecosystem)?.archive) await linkArchive(ecosystem, entry);
    else await writeFile(entry, EMPTY_ZIP, { flag: "wx" });
  }));
  const failure = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
  if (failure) throw failure.reason;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

interface EcosystemTally {
  packages: number;
  lockfiles: Set<string>;
}

function coverageFor(
  ecosystem: string,
  tally: EcosystemTally,
  database: DatabaseState | undefined,
): { coverage: DependencyCoverage; warning?: string } {
  const supported = isOsvEcosystem(ecosystem);
  const state: DependencyCoverage["state"] = !supported || !database?.archive
    ? "unavailable"
    : database.record ? "ran" : "partial";
  const checked = state === "ran" || state === "partial";
  const shown = ecosystem === "unknown" ? "unrecognised" : `"${ecosystem}"`;
  const warning = !supported
    ? `The ${shown} ecosystem is not supported by CodeInspectus (no OSV database is offered for it), so ${plural(tally.packages, "package")} found by osv-scanner were not checked.`
    : state === "unavailable"
      ? `osv-scanner found ${plural(tally.packages, `${ecosystem} package`)}, but the OSV ${ecosystem} database is not installed, so they were not checked. Run \`codeinspectus setup\` to review and download it.`
      : state === "partial"
        ? `The OSV ${ecosystem} database has no install record that matches it (an interrupted, manual or modified install), so its results cannot be proven reproducible on rescan. Run \`codeinspectus setup\` to reinstall it.`
        : undefined;
  const record = checked ? database?.record : undefined;
  return {
    warning,
    coverage: {
      ecosystem,
      engine: "osv-scanner",
      state,
      lockfiles: { discovered: tally.lockfiles.size, analyzed: checked ? tally.lockfiles.size : 0 },
      packages: {
        resolved: tally.packages,
        eligible: checked ? tally.packages : 0,
        skipped: checked ? 0 : tally.packages,
      },
      // The upstream snapshot date when the server sent one; the archive's hash is in the component signatures.
      ...(record?.last_modified ? { database_version: record.last_modified } : {}),
      ...(record ? { database_checked_at: record.recorded_at } : {}),
      matching: "osv-scanner-offline",
      limitations: checked
        ? [
          `Versions pinned in lockfiles and manifests are matched against the offline OSV ${ecosystem} database; manifests are read with --no-resolve, so unpinned or transitive dependencies are not expanded.`,
          "A match proves dependency presence, not vulnerable-code reachability.",
          ...(warning ? [warning] : []),
        ]
        : [warning!],
      ...(warning ? { note: warning } : {}),
    },
  };
}

// ── run ─────────────────────────────────────────────────────────────────────

const CAUSE_LINE = /error|could not|failed|unable/i;
/** 2.7.0's progress lines. They embed repository paths, so a keyword inside a path must not make one the cause. */
const PROGRESS_LINE = /^(Scanning dir |Starting filesystem walk|Scanned .* file and found \d+ packages?$|End status: |Loaded .* local db from )/;
const MAX_CAUSE = 500;

type Redactions = ReadonlyArray<readonly [path: string, label: string]>;

/**
 * Replace each local path with its placeholder, longest first so a path inside another one is never
 * half-replaced (an ancestor target would otherwise leave `<target>/<user>/...`), and only where the path
 * ends at a separator or a non-name character, so `/repo` never matches the start of `/repo2`.
 */
function redactPaths(text: string, redactions: Redactions): string {
  let cleaned = text;
  for (const [path, label] of [...redactions].sort((left, right) => right[0].length - left[0].length)) {
    if (path.length <= 1) continue;
    const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // A following name character, or a dot that starts one (`/repo.bak`), means a different path; a dot
    // that ends a sentence (`... /repo.`) does not.
    cleaned = cleaned.replace(new RegExp(`${escaped}(?![\\w-]|\\.[\\w.-])`, "g"), label);
  }
  return cleaned;
}

/**
 * Why osv-scanner failed, from its stderr. 2.7.0 prints progress lines first and the cause last, so a
 * prefix would cut the cause off: keep the lines that name an error (else the tail). Local paths are
 * replaced by placeholders before anything is kept.
 */
function stderrCause(stderr: string, redactions: Redactions): string {
  const lines = redactPaths(stderr, redactions).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const messages = lines.filter((line) => !PROGRESS_LINE.test(line));
  const causes = messages.filter((line) => CAUSE_LINE.test(line));
  const kept = (causes.length ? causes : messages.length ? messages : lines).slice(-4).join(" | ");
  return kept.length > MAX_CAUSE ? `${kept.slice(0, MAX_CAUSE)}…` : kept;
}

const MISSING_DB = /could not load db for (.+?) ecosystem/gi;
const MISSING_DB_LINE = /could not load db for .+? ecosystem/i;

/**
 * Ruling 35: a completed run that may have stopped at a database it could not load. Its findings are real, but
 * packages matched after that point may be missing, so coverage is lowered: never raised, nothing removed.
 */
const STOPPED_EARLY =
  "osv-scanner stopped at an OSV database it could not load, so packages it would have matched after that point " +
  "may be missing from its results; they are partial and cannot prove a fix on rescan.";

/**
 * Whether the final run may be partial: stderr still names a database osv-scanner could not load (any name; it is
 * never used as a path), or the structured output lists a package whose ecosystem has no overlay entry. stderr can
 * only lower coverage here, so a forged line costs a repository its own OSV coverage, never a false clean.
 */
function stoppedEarly(stderr: string, sources: readonly ParsedSource[], seeded: ReadonlySet<string>): boolean {
  if (MISSING_DB_LINE.test(stderr)) return true;
  return sources.some((source) => source.packages.some((pkg) => {
    const base = pkg.ecosystem.split(":")[0]!.toLowerCase();
    return base !== "" && !seeded.has(base);
  }));
}

/** Lower a possibly partial run: checked coverage becomes partial, and no database signature vouches for it. */
function lowerToPartial(coverage: DependencyCoverage[], componentSignatures: Record<string, string>, warnings: string[]): void {
  for (const entry of coverage) {
    if (entry.state !== "ran" && entry.state !== "partial") continue;
    entry.state = "partial";
    entry.limitations.push(STOPPED_EARLY);
    entry.note = entry.note ? `${entry.note} ${STOPPED_EARLY}` : STOPPED_EARLY;
  }
  // Without the database signature, rescan reports these findings' absence as not re-checked, never resolved.
  const databasePrefix = osvDatabaseComponent("");
  for (const component of Object.keys(componentSignatures)) {
    if (component.startsWith(databasePrefix)) delete componentSignatures[component];
  }
  warnings.push(STOPPED_EARLY);
}

/**
 * The ecosystem named by the LAST "could not load db for <Name> ecosystem" line, when it is one plain path
 * segment the overlay does not seed (newer than both snapshots). osv-scanner stops at the first database it
 * cannot load and prints that cause after every progress line, so a real run names exactly one, last; an
 * earlier match can be forged through a repository path in a progress line. Compared case-insensitively so
 * the entry can never alias an installed archive's link. stderr only steers the retry: coverage for that
 * ecosystem still comes from the allow-list.
 */
function unseededMissingDatabase(stderr: string): string | undefined {
  const name = [...stderr.matchAll(MISSING_DB)].at(-1)?.[1];
  if (name === undefined || !isOverlaySegment(name)) return undefined;
  const key = name.toLowerCase();
  return OSV_OVERLAY_ECOSYSTEMS.some((seeded) => seeded.toLowerCase() === key) ? undefined : name;
}

/** The empty database for the retry. `wx` never writes through an existing entry or link. */
async function addEmptyDatabase(overlay: string, ecosystem: string): Promise<void> {
  const entry = overlayEntry(overlay, ecosystem);
  await mkdir(dirname(entry), { recursive: true });
  await writeFile(entry, EMPTY_ZIP, { flag: "wx" });
}

/**
 * What to tell the user about a "could not load db for <X> ecosystem" failure. `codeinspectus setup` can
 * only (re)install allow-listed databases, so it is suggested only when one of those could not be read;
 * an ecosystem outside the allow-list (one OSV added after both overlay snapshots and still missing after
 * the retry) is named as unsupported instead. The ecosystem name itself is already in the cause.
 */
function missingDatabaseHint(stderr: string): string {
  if (!/could not load db/i.test(stderr)) return "";
  const named = [...stderr.matchAll(MISSING_DB)].map((match) => match[1]);
  return named.length && !named.some((ecosystem) => isOsvEcosystem(ecosystem))
    ? " The database osv-scanner needed is for an ecosystem CodeInspectus's OSV setup does not support, so `codeinspectus setup` cannot install it."
    : " An OSV database could not be read: run `codeinspectus setup` to reinstall it.";
}

/**
 * Run osv-scanner offline against the overlay. It stops at the first database it cannot load: exit 127, or
 * exit 1 with the packages after it left unmatched once it had found vulnerabilities. For an ecosystem newer
 * than both overlay snapshots, an empty database is added and the run retried once. A forged stderr line can
 * at most cost this one extra run and lower the run's coverage to partial (Ruling 35); never raise it.
 */
async function execWithOverlay(
  binary: string,
  args: string[],
  outputPath: string,
  overlay: string,
  cwd: string,
): Promise<{ res: ExecResult; unseeded?: string }> {
  const run = async () => {
    // A stale file from an earlier run must never be read as this run's result.
    await rm(outputPath, { force: true });
    return execBinary(binary, args, { cwd, offline: true, env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: overlay } });
  };
  let res = await run();
  const unseeded = !res.timedOut && (res.code === 1 || res.code === 127) ? unseededMissingDatabase(res.stderr) : undefined;
  if (unseeded !== undefined) {
    // If the empty database cannot be written, keep the first result; the caller lowers it to partial.
    const added = await addEmptyDatabase(overlay, unseeded).then(() => true, (error: unknown) => {
      log.debug(`osv-scanner retry skipped: could not add an empty ${unseeded} database (${errorCode(error) || "unknown error"})`);
      return false;
    });
    if (added) {
      log.debug(`osv-scanner could not load a database for ${unseeded}; retrying once with an empty one`);
      res = await run();
    }
  }
  return { res, ...(unseeded !== undefined ? { unseeded } : {}) };
}

/** Why a completed-looking run cannot be read; undefined when its output file is there and in bounds. */
async function unreadableRun(res: ExecResult, outputPath: string, cause: (stderr: string) => string): Promise<string | undefined> {
  if (res.timedOut) return "osv-scanner timed out before producing results.";
  if (res.code !== 0 && res.code !== 1) return `osv-scanner exited with code ${res.code ?? "unknown"} and no usable result.${cause(res.stderr)}`;
  const output = await lstat(outputPath).then((metadata) => metadata, () => undefined);
  if (!output?.isFile()) return `osv-scanner produced no output file (exit ${res.code}).${cause(res.stderr)}`;
  if (output.size > MAX_OUTPUT_BYTES) return `osv-scanner output exceeds the ${MAX_OUTPUT_BYTES / (1024 * 1024)} MiB bound and was not read.`;
  return undefined;
}

function outcome(
  version: string,
  started: number,
  info: Pick<EngineRunInfo, "available" | "ran"> & Partial<EngineRunInfo>,
  rest: { applicable: boolean } & Partial<Omit<OsvScanResult, "info">>,
): OsvScanResult {
  return {
    findings: [],
    coverage: [],
    lockfiles: [],
    componentSignatures: {},
    // A run that did not complete is reported once, through the warnings the caller forwards.
    warnings: info.note && !info.ran ? [info.note] : [],
    ...rest,
    info: { engine: "osv-scanner", version, finding_count: 0, duration_ms: Date.now() - started, ...info },
  };
}

export async function runOsvScanner(target: string, tmpDir: string): Promise<OsvScanResult> {
  const started = Date.now();
  let version = "unknown";
  const redactions: Redactions = [
    [target, "<target>"],
    [tmpDir, "<managed-temp>"],
    [MANAGED_OSV_DB, "<managed-osv-db>"],
    [homedir(), "~"],
  ];
  try {
    const bin = await resolveEngine("osv-scanner");
    version = bin.version;
    const failed = (note: string): OsvScanResult =>
      outcome(version, started, { available: true, ran: false, note }, { applicable: true });

    const outputPath = join(tmpDir, "osv-scanner.json");
    const args = buildOsvScannerArgs(target, outputPath, MANAGED_OSV_CONFIG);
    const cause = (stderr: string): string => {
      const text = stderrCause(stderr, redactions);
      const hint = missingDatabaseHint(stderr);
      return text ? ` Cause: ${/[.!?…]$/.test(text) ? text : `${text}.`}${hint}` : hint;
    };
    const configContent = await writeManagedConfig();
    const databases = await readDatabaseStates();
    const componentSignatures: Record<string, string> = {
      "osv-scanner:binary": `sha256:${bin.sha256}`,
      "osv-scanner:invocation": invocationSignature("osv-scanner", args.map((arg) =>
        arg === outputPath ? "<managed-temp>"
          : arg === MANAGED_OSV_CONFIG ? "<managed-config>"
            : arg === target ? "<target>"
              : arg)),
      "osv-scanner:config": signature(configContent),
    };
    for (const [ecosystem, { record, archive }] of databases) {
      if (record && archive) componentSignatures[osvDatabaseComponent(ecosystem)] = record.signature;
    }

    const overlay = join(tmpDir, "osv-db-overlay");
    try {
      await buildDatabaseOverlay(overlay, databases);
    } catch (error) {
      // No link means osv-scanner could not read an installed database: a failed run, never a clean one.
      if (error instanceof OverlayLinkError) return failed(error.message);
      throw error;
    }
    const cwd = await engineWorkingDirectory(target);
    const { res, unseeded } = await execWithOverlay(bin.path, args, outputPath, overlay, cwd);

    // Exit 0 (no vulnerabilities) and 1 (vulnerabilities found) are both a completed scan.
    const unreadable = await unreadableRun(res, outputPath, cause);
    // A completed run's stderr is never read as a result (Ruling 31), but it helps diagnose one.
    if (!unreadable && res.stderr.trim()) log.debug(`osv-scanner stderr (exit ${res.code}): ${stderrCause(res.stderr, redactions)}`);
    if (unreadable) return failed(unreadable);
    const parsed = parseOutput(await readFile(outputPath, "utf8"));
    if (!parsed) return failed(`osv-scanner output was not the expected JSON result (exit ${res.code}).`);
    const { sources, dropped } = parsed;
    const seeded = new Set([...OSV_OVERLAY_ECOSYSTEMS, ...(unseeded === undefined ? [] : [unseeded])].map((name) => name.toLowerCase()));
    const partialRun = stoppedEarly(res.stderr, sources, seeded);
    // Exit 1 means osv-scanner found vulnerabilities. Producing none of them (an unreadable package,
    // an unexpected id, schema drift) must read as a failed run, not as a clean one.
    const unmapped = "osv-scanner reported vulnerabilities that could not be mapped.";
    if (!sources.length) {
      if (res.code === 1) return failed(unmapped);
      // No package sources, from a run that completed (exit 0, output parsed): still a run, with nothing found.
      const warnings: string[] = [];
      if (partialRun) lowerToPartial([], componentSignatures, warnings);
      return outcome(version, started, { available: true, ran: true }, { applicable: true, componentSignatures, warnings });
    }

    const targetMetadata = await lstat(target);
    const targetInfo: TargetInfo = { path: target, isFile: !targetMetadata.isDirectory() };
    const findings: Finding[] = [];
    const tallies = new Map<string, EcosystemTally>();
    const lineCache = new Map<string, Promise<LockfileLines | undefined>>();
    const extracted = new Set<string>();
    const packages: NonNullable<OsvScanResult["packages"]> = [];
    for (const source of sources) {
      const { file, absolute } = locate(targetInfo, source.path);
      extracted.add(file);
      for (const pkg of source.packages) {
        const ecosystem = pkg.ecosystem || "unknown";
        if (pkg.ecosystem && pkg.version) {
          packages.push({ ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version, file, ...(absolute ? {} : { outside: true as const }) });
        }
        const tally = tallies.get(ecosystem) ?? { packages: 0, lockfiles: new Set<string>() };
        tally.packages += 1;
        tally.lockfiles.add(file);
        tallies.set(ecosystem, tally);
        if (!pkg.groups.length) continue;

        let lines = absolute ? lineCache.get(absolute) : undefined;
        if (!lines && absolute) {
          lines = readLines(absolute);
          lineCache.set(absolute, lines);
        }
        const line = packageEntryLine(await lines, file, pkg.name, pkg.version);
        const database = isOsvEcosystem(ecosystem) ? databases.get(ecosystem) : undefined;
        for (const group of pkg.groups) {
          const finding = findingFor(pkg, group, {
            file,
            line,
            producerComponents: osvScannerFindingComponents(ecosystem),
            database: database?.archive ? database.record : undefined,
          });
          if (finding) findings.push(finding);
        }
      }
    }

    if (res.code === 1 && findings.length === 0) return failed(unmapped);

    const order = (ecosystem: string): number => {
      const index = (OSV_ECOSYSTEMS as readonly string[]).indexOf(ecosystem);
      return index < 0 ? OSV_ECOSYSTEMS.length : index;
    };
    const coverage: DependencyCoverage[] = [];
    const warnings: string[] = [];
    for (const ecosystem of [...tallies.keys()].sort((a, b) => order(a) - order(b) || (a < b ? -1 : a > b ? 1 : 0))) {
      const built = coverageFor(ecosystem, tallies.get(ecosystem)!, isOsvEcosystem(ecosystem) ? databases.get(ecosystem) : undefined);
      coverage.push(built.coverage);
      if (built.warning) warnings.push(built.warning);
    }
    if (dropped) {
      warnings.push(
        `osv-scanner reported ${plural(dropped, "advisory group")} that could not be mapped (an unreadable package name or ` +
        `advisory id); ${dropped === 1 ? "it is" : "they are"} not in the findings.`,
      );
    }
    if (partialRun) lowerToPartial(coverage, componentSignatures, warnings);
    const checkedAny = coverage.some((entry) => entry.state === "ran" || entry.state === "partial");
    return outcome(
      version,
      started,
      {
        available: true,
        ran: checkedAny,
        finding_count: findings.length,
        ...(checkedAny ? {} : { note: warnings.join(" ") }),
      },
      { applicable: true, findings, coverage, lockfiles: [...extracted].sort(), packages, componentSignatures, warnings },
    );
  } catch (err) {
    if (err instanceof EngineUnavailableError) {
      return outcome(version, started, { available: false, ran: false, note: err.message }, { applicable: false });
    }
    log.warn("osv-scanner wrapper error", err);
    return outcome(
      version,
      started,
      // An errno message (ENOENT, ENOSPC, ...) carries absolute paths.
      { available: true, ran: false, note: `osv-scanner failed: ${redactPaths(err instanceof Error ? err.message : String(err), redactions)}` },
      { applicable: true },
    );
  }
}

// ── per-scan SBOM run (Synvoya vendored libraries) ──────────────────────────

/** Where a package from the SBOM was declared in the repository. */
export interface OsvSbomLocation {
  file: string;
  line: number;
  /** The finding message's opening sentence, naming the declaration (never the SBOM). */
  lead: string;
  /** The package name the repository declares, when the SBOM names the package by its advisory name. */
  declaredName?: string;
  /**
   * The vendored root a location stands for (one finding per install): the fingerprint is keyed on it instead
   * of `file`, so it stays stable when the file the finding is shown at changes.
   */
  fingerprintScope?: string;
}

export interface OsvSbomOptions {
  /**
   * Ecosystems whose installed database the SBOM needs. When none is installed nothing runs (`unavailable`);
   * otherwise the run goes ahead and names the missing ones in `missingDatabases`: their packages were checked
   * against nothing, so the caller must treat them as not checked.
   */
  ecosystems: readonly OsvEcosystem[];
  /** The declarations behind one package osv-scanner listed; none when the SBOM never named it. */
  locate: (pkg: { ecosystem: string; name: string; version: string }) => OsvSbomLocation[];
  /**
   * Every package the SBOM names. `--all-packages` lists clean ones too, so a run that does not list one of
   * them (an extractor change, a skipped component) is incomplete: absence of a finding proves nothing there.
   */
  expected: ReadonlyArray<{ ecosystem: string; name: string; version: string }>;
}

export interface OsvSbomResult {
  /** `unavailable`: osv-scanner or a needed database is not installed, so it never ran. */
  state: "ran" | "failed" | "unavailable";
  version: string;
  /** Why it did not run (local paths replaced by placeholders). */
  reason?: string;
  /** The needed databases that are not installed: every one when `unavailable`; their packages were not checked. */
  missingDatabases: OsvEcosystem[];
  /**
   * The run proves absence for the installed ecosystems: it completed, every installed needed database has a
   * matching install record, it did not stop at a database it could not load, every advisory group was mapped
   * to a declaration, and it listed every expected package of an installed ecosystem.
   */
  complete: boolean;
  findings: Finding[];
  /** Reasons the run is not complete, for the user. */
  warnings: string[];
}

/**
 * Check a per-scan CycloneDX SBOM (OSV_SBOM_FILE_NAME in its own folder under the scan's temp dir) with the
 * main run's offline flags, managed config and database overlay construction. `workDir` holds this run's own
 * overlay and output, so it never shares files with the main run. Findings are located only through
 * `locate`: never at the SBOM.
 */
export async function runOsvScannerOnSbom(sbomPath: string, workDir: string, options: OsvSbomOptions): Promise<OsvSbomResult> {
  let version = "unknown";
  const redactions: Redactions = [
    [workDir, "<managed-temp>"],
    [dirname(sbomPath), "<managed-temp>"],
    [MANAGED_OSV_DB, "<managed-osv-db>"],
    [homedir(), "~"],
  ];
  const result = (state: OsvSbomResult["state"], rest: Partial<OsvSbomResult> = {}): OsvSbomResult => ({
    state, version, missingDatabases: [], complete: false, findings: [], warnings: [], ...rest,
  });
  try {
    if (basename(sbomPath) !== OSV_SBOM_FILE_NAME) throw new Error(`the SBOM must be named ${OSV_SBOM_FILE_NAME}`);
    const bin = await resolveEngine("osv-scanner");
    version = bin.version;
    await writeManagedConfig();
    const databases = await readDatabaseStates();
    const missingDatabases = options.ecosystems.filter((ecosystem) => !databases.get(ecosystem)?.archive);
    const installed = options.ecosystems.filter((ecosystem) => !missingDatabases.includes(ecosystem));
    if (installed.length === 0) {
      return result("unavailable", { missingDatabases, reason: `the OSV ${missingDatabases.join(", ")} database is not installed` });
    }

    const outputPath = join(workDir, "osv-scanner-sbom.json");
    const args = buildOsvScannerSbomArgs(OSV_SBOM_FILE_NAME, outputPath, MANAGED_OSV_CONFIG);
    const failed = (reason: string) => result("failed", { reason });
    const overlay = join(workDir, "osv-db-overlay");
    try {
      await buildDatabaseOverlay(overlay, databases);
    } catch (error) {
      if (error instanceof OverlayLinkError) return failed(error.message);
      throw error;
    }
    const { res, unseeded } = await execWithOverlay(bin.path, args, outputPath, overlay, dirname(sbomPath));
    const cause = (stderr: string): string => {
      const text = stderrCause(stderr, redactions);
      return text ? ` Cause: ${/[.!?…]$/.test(text) ? text : `${text}.`}` : "";
    };
    const unreadable = await unreadableRun(res, outputPath, cause);
    if (unreadable) return failed(unreadable);
    const parsed = parseOutput(await readFile(outputPath, "utf8"));
    if (!parsed) return failed(`osv-scanner output was not the expected JSON result (exit ${res.code}).`);
    const seeded = new Set([...OSV_OVERLAY_ECOSYSTEMS, ...(unseeded === undefined ? [] : [unseeded])].map((name) => name.toLowerCase()));
    const partialRun = stoppedEarly(res.stderr, parsed.sources, seeded);

    const findings: Finding[] = [];
    let unlocated = 0;
    for (const source of parsed.sources) {
      for (const pkg of source.packages) {
        if (!pkg.groups.length) continue;
        const locations = options.locate({ ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version });
        if (!locations.length) {
          unlocated += pkg.groups.length;
          continue;
        }
        const database = isOsvEcosystem(pkg.ecosystem) ? databases.get(pkg.ecosystem) : undefined;
        for (const location of locations) {
          for (const group of pkg.groups) {
            const finding = findingFor(pkg, group, {
              file: location.file,
              line: location.line,
              lead: location.lead,
              ...(location.declaredName !== undefined ? { declaredName: location.declaredName } : {}),
              ...(location.fingerprintScope !== undefined ? { fingerprintScope: location.fingerprintScope } : {}),
              producerComponents: osvSbomFindingComponents(pkg.ecosystem),
              database: database?.archive ? database.record : undefined,
            });
            if (finding) findings.push(finding);
          }
        }
      }
    }
    if (res.code === 1 && findings.length === 0) return failed("osv-scanner reported vulnerabilities that could not be mapped.");

    const warnings: string[] = [];
    const listed = new Set(parsed.sources.flatMap((source) => source.packages.map((pkg) => `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`)));
    const unlisted = (options.expected ?? []).filter((pkg) =>
      !(missingDatabases as readonly string[]).includes(pkg.ecosystem) && !listed.has(`${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`)).length;
    if (unlisted) warnings.push(`osv-scanner did not list ${plural(unlisted, "package")} the SBOM names, so ${unlisted === 1 ? "it was" : "they were"} not checked.`);
    if (parsed.dropped) warnings.push(`osv-scanner reported ${plural(parsed.dropped, "advisory group")} for vendored libraries that could not be mapped; they are not in the findings.`);
    if (unlocated) warnings.push(`osv-scanner reported ${plural(unlocated, "advisory group")} for a package the SBOM did not name; they are not in the findings.`);
    if (partialRun) warnings.push(STOPPED_EARLY);
    const unrecorded = installed.filter((ecosystem) => !databases.get(ecosystem)?.record);
    if (unrecorded.length) {
      warnings.push(`The OSV ${unrecorded.join(", ")} database has no install record that matches it, so vendored-library results cannot be proven reproducible on rescan.`);
    }
    return result("ran", { findings, warnings, missingDatabases, complete: warnings.length === 0 });
  } catch (err) {
    if (err instanceof EngineUnavailableError) return result("unavailable", { reason: "osv-scanner is not installed" });
    log.warn("osv-scanner SBOM run error", err);
    return result("failed", { reason: `osv-scanner failed: ${redactPaths(err instanceof Error ? err.message : String(err), redactions)}` });
  }
}
