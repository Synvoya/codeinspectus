/**
 * Repository paths are attacker-controlled text. Before one is shown in a warning, a coverage note, a
 * gap example or suppression metadata it must carry no control character (terminal escapes, newlines,
 * U+0085), no Unicode format character (bidi overrides such as U+202E, isolates, zero-width
 * characters, U+FEFF) and no line or paragraph separator (U+2028 and U+2029, classes Zl and Zp).
 * Callers count such a path but never show it, or show it escaped when the list must keep every entry.
 */

import type { ScanResult } from "./types.js";

const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const UNSAFE_GLOBAL = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export function isDisplayablePath(path: string): boolean {
  return !UNSAFE.test(path);
}

/** The path with each unsafe character written as a visible `\u{…}` escape. */
export function escapePathForDisplay(path: string): string {
  return path.replace(UNSAFE_GLOBAL, (character) => `\\u{${character.codePointAt(0)!.toString(16)}}`);
}

/**
 * Fix round 3: every composed warning or note that can embed a repository path (native-pack and
 * dependency limitations, technology evidence and detection warnings, engine notes, repository-trust,
 * Git-scope and history limitations, coverage notes) with unsafe characters escaped. Findings are
 * data, not notes, and are left alone. Idempotent: an escaped text has no unsafe character left.
 */
export function escapeScanDisplayText<T extends ScanResult>(result: T): T {
  const text = escapePathForDisplay;
  const list = (items: readonly string[]) => items.map(text);
  const trust = result.repository_trust;
  return {
    ...result,
    warnings: list(result.warnings),
    engine_details: result.engine_details.map((engine) => (engine.note === undefined ? engine : { ...engine, note: text(engine.note) })),
    detected_technologies: result.detected_technologies.map((technology) => ({ ...technology, evidence: list(technology.evidence) })),
    pack_coverage: result.pack_coverage.map((pack) => ({
      ...pack, limitations: list(pack.limitations), ...(pack.note === undefined ? {} : { note: text(pack.note) }),
    })),
    ...(result.dependency_coverage
      ? {
        dependency_coverage: result.dependency_coverage.map((dependency) => ({
          ...dependency, limitations: list(dependency.limitations), ...(dependency.note === undefined ? {} : { note: text(dependency.note) }),
        })),
      }
      : {}),
    repository_trust: {
      ...trust,
      coverage: {
        ...trust.coverage,
        limitations: list(trust.coverage.limitations),
        capabilities: trust.coverage.capabilities.map((capability) => ({ ...capability, limitations: list(capability.limitations) })),
      },
      artifacts: trust.artifacts.map((artifact) => ({ ...artifact, limitations: list(artifact.limitations) })),
    },
    ...(result.coverage_notes ? { coverage_notes: result.coverage_notes.map((note) => ({ ...note, detail: text(note.detail) })) } : {}),
    ...(result.git_scope
      ? {
        git_scope: {
          ...result.git_scope,
          limitations: list(result.git_scope.limitations),
          entries: result.git_scope.entries.map((entry) => (entry.note === undefined ? entry : { ...entry, note: text(entry.note) })),
        },
      }
      : {}),
    ...(result.history_revision
      ? { history_revision: { ...result.history_revision, limitations: list(result.history_revision.limitations) } }
      : {}),
  };
}
