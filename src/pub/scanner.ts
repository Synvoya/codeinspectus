/** First-party, offline Pub dependency vulnerability scanner. */

import { resolve as resolvePath } from "node:path";

import { CODEINSPECTUS_PUB_VERSION, OSV_PUB_SNAPSHOT } from "../config.js";
import { pubFindingComponents, pubStaticComponentSignatures } from "../provenance.js";
import type { DependencyCoverage, EngineRunInfo, Finding } from "../types.js";
import { fingerprint as makeFingerprint } from "../util/hash.js";
import { inspectPubDatabase } from "./database.js";
import { loadPubLockfiles, type PubLockfileLoadResult, type PubResolvedPackage } from "./lockfile.js";
import { matchPubPackage } from "./matcher.js";
import { fixedVersions } from "./snapshot.js";

export interface PubScanResult {
  findings: Finding[];
  info: EngineRunInfo;
  coverage: DependencyCoverage;
  componentSignatures: Record<string, string>;
  applicability: "applicable" | "ambiguous" | "not_applicable";
}

interface PubScanOptions {
  snapshotPath?: string;
}

function joinedNote(notes: readonly string[]): string | undefined {
  const unique = [...new Set(notes.filter(Boolean))];
  return unique.length ? unique.join(" ") : undefined;
}

function discoveredCount(load: PubLockfileLoadResult): number {
  return load.lockfiles.length
    + load.skipped.symlinked_lockfiles
    + load.skipped.lockfiles_beyond_limit;
}

function pubApplicability(load: PubLockfileLoadResult): PubScanResult["applicability"] {
  if (discoveredCount(load) > 0) return "applicable";
  const skipped = load.skipped;
  return skipped.symlinked_paths > 0
    || skipped.unreadable_directories > 0
    || skipped.directories_beyond_depth > 0
    || skipped.traversal_limit_reached > 0
    ? "ambiguous"
    : "not_applicable";
}

function hasIncompleteLockfileCoverage(load: PubLockfileLoadResult): boolean {
  const skipped = load.skipped;
  return skipped.symlinked_lockfiles > 0
    || skipped.symlinked_paths > 0
    || skipped.oversized_lockfiles > 0
    || skipped.unreadable_lockfiles > 0
    || skipped.malformed_lockfiles > 0
    || skipped.lockfiles_beyond_limit > 0
    || skipped.lockfiles_beyond_total_bytes > 0
    || skipped.unreadable_directories > 0
    || skipped.directories_beyond_depth > 0
    || skipped.traversal_limit_reached > 0
    || skipped.unsupported_targets > 0;
}

function isEligible(pkg: PubResolvedPackage): boolean {
  return pkg.source === "hosted" && pkg.registry === "official";
}

function findingFor(
  pkg: PubResolvedPackage,
  match: ReturnType<typeof matchPubPackage>[number],
  databaseVersion: string,
  checkedAt: string,
): Finding {
  const { advisory, affected } = match;
  const fixed = fixedVersions(affected);
  const cwe = [...new Set(["CWE-1395", ...advisory.cwe])];
  const aliases = [...new Set(advisory.aliases)].sort();
  const references = [...new Set([
    `https://osv.dev/vulnerability/${advisory.id}`,
    `https://github.com/advisories/${advisory.id}`,
    ...advisory.references,
    "https://cwe.mitre.org/data/definitions/1395.html",
  ])];
  const fixText = fixed.length
    ? `Upgrade ${pkg.name} to the published fixed version ${fixed.join(" or ")}, or remove the package.`
    : `Upgrade ${pkg.name} to a version not listed as affected, or remove the package.`;
  const fingerprint = makeFingerprint([
    "codeinspectus-pub",
    pkg.lockfile_path,
    pkg.name,
    pkg.version,
    advisory.id,
  ]);
  return {
    id: fingerprint,
    fingerprint,
    title: `${advisory.summary} (${pkg.name}@${pkg.version})`,
    severity: advisory.severity,
    engine: "codeinspectus-pub",
    engines: ["codeinspectus-pub"],
    rule_id: advisory.id,
    ...(aliases.length ? { vulnerability_aliases: aliases } : {}),
    cwe,
    owasp_web: ["A06:2021"],
    location: {
      file: pkg.lockfile_path,
      start_line: pkg.version_line,
      end_line: pkg.version_line,
      snippet: `version: "${pkg.version}"`,
    },
    message:
      `${pkg.lockfile_path} resolves official Pub package ${pkg.name}@${pkg.version}. ` +
      `${advisory.id} lists that exact version as affected in bundled snapshot ${databaseVersion} ` +
      `(checked ${checkedAt}). This proves dependency presence, not vulnerable-code reachability.`,
    remediation: {
      summary: fixText,
      steps: [
        fixText,
        "Regenerate pubspec.lock using the normal trusted Dart/Flutter dependency workflow.",
        "Re-run CodeInspectus and confirm the advisory no longer matches the resolved version.",
        "If an immediate upgrade is impossible, assess whether the affected code path is reachable and consider an alternative package.",
      ],
      references,
    },
    frameworks: [],
    confidence: "high",
    producer_components: pubFindingComponents(),
    finding_kind: "vulnerability",
  };
}

export async function runPubScan(target: string, options: PubScanOptions = {}): Promise<PubScanResult> {
  const started = Date.now();
  const resolvedTarget = resolvePath(target);
  const [load, database] = await Promise.all([
    loadPubLockfiles(resolvedTarget),
    inspectPubDatabase(options.snapshotPath ?? OSV_PUB_SNAPSHOT),
  ]);
  const parsedLockfiles = load.lockfiles.filter((lockfile) => lockfile.status === "parsed").length;
  const applicability = pubApplicability(load);
  const eligible = load.packages.filter(isEligible);
  const packageSkipped = load.packages.length - eligible.length;
  const notes = [...load.notes];
  const databaseAvailable = database.loaded !== undefined;

  if (database.info.note) notes.push(database.info.note);
  if (!databaseAvailable) {
    const note = joinedNote(notes) ?? "The bundled Pub advisory database is unavailable.";
    return {
      findings: [],
      info: {
        engine: "codeinspectus-pub",
        version: CODEINSPECTUS_PUB_VERSION,
        available: false,
        ran: false,
        finding_count: 0,
        duration_ms: Date.now() - started,
        note,
      },
      coverage: {
        ecosystem: "Pub",
        engine: "codeinspectus-pub",
        state: "unavailable",
        lockfiles: { discovered: discoveredCount(load), analyzed: parsedLockfiles },
        packages: { resolved: load.packages.length, eligible: eligible.length, skipped: packageSkipped },
        matching: "exact-enumerated-versions",
        limitations: [...new Set(notes)],
        note,
      },
      componentSignatures: {},
      applicability,
    };
  }
  const loadedDatabase = database.loaded!;

  const findings = eligible.flatMap((pkg) =>
    matchPubPackage(loadedDatabase.data, pkg).map((match) =>
      findingFor(
        pkg,
        match,
        database.info.version,
        database.info.checked_at ?? "unknown",
      ),
    ),
  );
  const noLockfile = discoveredCount(load) === 0;
  const incomplete = noLockfile
    || hasIncompleteLockfileCoverage(load)
    || packageSkipped > 0
    || database.info.state === "stale";
  if (!findings.length && parsedLockfiles > 0) {
    notes.push(
      `No eligible locked Pub version matched the ${database.info.active_advisories} active advisories in bundled snapshot ${database.info.version}; this is not a claim of complete vulnerability absence.`,
    );
  }
  const ran = parsedLockfiles > 0;
  const state: DependencyCoverage["state"] = incomplete ? "partial" : "ran";
  const note = joinedNote(notes);
  return {
    findings,
    info: {
      engine: "codeinspectus-pub",
      version: CODEINSPECTUS_PUB_VERSION,
      available: true,
      ran,
      finding_count: findings.length,
      duration_ms: Date.now() - started,
      ...(note ? { note } : {}),
    },
    coverage: {
      ecosystem: "Pub",
      engine: "codeinspectus-pub",
      state,
      lockfiles: { discovered: discoveredCount(load), analyzed: parsedLockfiles },
      packages: { resolved: load.packages.length, eligible: eligible.length, skipped: packageSkipped },
      database_version: database.info.version,
      ...(database.info.checked_at ? { database_checked_at: database.info.checked_at } : {}),
      matching: "exact-enumerated-versions",
      limitations: [...new Set(notes)],
      ...(note ? { note } : {}),
    },
    componentSignatures: pubStaticComponentSignatures(loadedDatabase.content_signature),
    applicability,
  };
}
