/**
 * Native-pack limits that are genuine, deterministic analysis limits rather than failures (pre-release
 * field validation item 3). Each is a declared coverage gap with a stable id, a file count and up to
 * five examples, so `accept_gaps` can accept it by name; every other native limitation (an analyzer
 * failure, a project-wide bound other than the JavaScript/TypeScript token budget, a reconciliation
 * mismatch) stays partial coverage no id accepts.
 *
 * Gaps come only from structured records the analyzers emit where the limit is hit; a free-text note
 * is never a gap.
 */

import type { CoverageGap, CoverageGapId } from "./coverage-gaps.js";
import { isDisplayablePath } from "./display-path.js";

const MAX_EXAMPLES = 5;

/**
 * A declared gap emitted at the exact code site that hit the limit (security review: free-text notes
 * embed repository paths, so they are never classified; only these records are acceptable).
 */
export interface NativeGapRecord {
  id: CoverageGapId;
  path: string;
}

/** Gaps from structured records, one entry per id, files counted once. */
export function nativeGaps(entries: Iterable<NativeGapRecord>): CoverageGap[] {
  const byId = new Map<CoverageGapId, Set<string>>();
  for (const { id, path } of entries) byId.set(id, (byId.get(id) ?? new Set()).add(path));
  return [...byId].map(([id, paths]) => {
    const sorted = [...paths].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    return { id, files: sorted.length, examples: sorted.filter(isDisplayablePath).slice(0, MAX_EXAMPLES) };
  });
}
