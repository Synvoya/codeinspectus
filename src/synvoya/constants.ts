/**
 * Synvoya gap-advisory dataset constants.
 *
 * Kept out of src/config.ts on purpose. The directory resolves exactly like
 * OSV_PUB_SNAPSHOT: relative to the package root via DETECTION_DB_DIR, so it is
 * identical in the source tree, the built dist/ and the installed npm package.
 */

import { join } from "node:path";

import { DETECTION_DB_DIR } from "../config.js";

export const SYNVOYA_DATASET_DIR = join(DETECTION_DB_DIR, "synvoya");

/** Every file in the dataset directory that the manifest must digest. */
export const SYNVOYA_DATASET_FILES = ["advisories.json", "aliases.json", "eol.json", "libraries.json"] as const;

/** Hard per-file size cap (applies to the manifest and every dataset file). */
export const SYNVOYA_MAX_FILE_BYTES = 8 * 1024 * 1024;

const DEFAULT_READER_DEADLINE_MS = 30_000;

/** Verification-only switch (like the scan-persistence one): replaces the reader deadline; `0` is already expired. */
export const INTERNAL_SYNVOYA_DEADLINE_ENV = "CODEINSPECTUS_INTERNAL_SYNVOYA_DEADLINE_MS";

/** The reader deadline for an environment: the internal override when it is a whole number of milliseconds, else 30 s. */
export function synvoyaReaderDeadlineMs(environment: Record<string, string | undefined> = process.env): number {
  const raw = environment[INTERNAL_SYNVOYA_DEADLINE_ENV];
  return raw !== undefined && /^\d{1,9}$/.test(raw) ? Number(raw) : DEFAULT_READER_DEADLINE_MS;
}

/** Wall-clock budget shared by every Synvoya reader in one scan; past it no new file is started. */
export const SYNVOYA_READER_DEADLINE_MS = synvoyaReaderDeadlineMs();

/** Synvoya notes carried into one scan's coverage notes; priority notes are always kept beyond it. */
export const SYNVOYA_MAX_COVERAGE_NOTES = 50;

/** Entries kept per checked-file set in a stored scan; a larger set is omitted (rescan then confirms nothing it held). */
export const SYNVOYA_MAX_CHECKED_FILES = 10_000;
