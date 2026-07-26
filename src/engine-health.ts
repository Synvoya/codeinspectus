/**
 * Offline machine-level engine and Trivy-DB health inspection.
 *
 * This module never downloads or repairs anything. It converts verified binary
 * probes plus small DB metadata/provenance reads into a stable setup state that
 * agents can act on only after user approval.
 */

import { access } from "node:fs/promises";

import {
  MANAGED_TRIVY_DB,
  TRIVY_DB_STALE_AFTER_MS,
  type EngineName,
} from "./config.js";
import { platformKey } from "./engines/lockfile.js";
import { probeEngine, type EngineAvailabilityIssue } from "./engines/resolve.js";
import { readTrivyDbDate } from "./engines/trivy.js";
import { readTrivyDbContentDigest } from "./provenance.js";
import type {
  EngineArtifactHealth,
  EngineArtifactState,
  EngineSetupStatus,
  TrivyDbHealthState,
} from "./types.js";

export const ENGINE_REPAIR_COMMAND = "npx codeinspectus repair-engines";
const ENGINE_ORDER: EngineName[] = ["opengrep", "gitleaks", "trivy"];

export interface EngineHealthProbe {
  engine: EngineName;
  version: string;
  available: boolean;
  issue?: EngineAvailabilityIssue;
  note?: string;
}

export interface TrivyDbProbe {
  exists: boolean;
  downloadedAt?: string;
  provenanceRecorded: boolean;
}

function artifactState(probe: EngineHealthProbe): EngineArtifactState {
  if (probe.available) return "ready";
  return probe.issue ?? "lockfile_error";
}

export function trivyDbState(db: TrivyDbProbe, nowMs = Date.now()): TrivyDbHealthState {
  if (!db.exists || !db.downloadedAt) return "missing";
  if (!db.provenanceRecorded) return "provenance_missing";
  const downloaded = Date.parse(db.downloadedAt);
  if (!Number.isFinite(downloaded) || nowMs - downloaded > TRIVY_DB_STALE_AFTER_MS) return "stale";
  return "ready";
}

export function deriveEngineSetupStatus(
  platform: string,
  probes: EngineHealthProbe[],
  db: TrivyDbProbe,
  nowMs = Date.now(),
): EngineSetupStatus {
  const engines: EngineArtifactHealth[] = probes.map((probe) => ({
    engine: probe.engine,
    version: probe.version,
    state: artifactState(probe),
    ...(probe.note && !probe.available ? { detail: probe.note } : {}),
  }));
  const dbState = trivyDbState(db, nowMs);
  const unsupported = engines.some((engine) => engine.state === "unsupported_platform");
  const packagedStateBroken = engines.some(
    (engine) => engine.state === "unpinned" || engine.state === "lockfile_error",
  );
  const broken = engines.some((engine) => engine.state !== "ready");
  const state: EngineSetupStatus["state"] = unsupported
    ? "unsupported_platform"
    : broken || dbState === "missing"
      ? "repair_required"
      : dbState === "provenance_missing" || dbState === "stale"
        ? "db_refresh_recommended"
        : "ready";

  return {
    state,
    platform,
    engines,
    trivy_db: {
      state: dbState,
      ...(db.downloadedAt ? { downloaded_at: db.downloadedAt } : {}),
    },
    ...(state !== "ready" && state !== "unsupported_platform" && !packagedStateBroken
      ? { repair_command: ENGINE_REPAIR_COMMAND }
      : {}),
    network_required: state !== "ready" && state !== "unsupported_platform" && !packagedStateBroken,
  };
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function inspectEngineSetup(nowMs = Date.now()): Promise<EngineSetupStatus> {
  const [rawProbes, dbExists, downloadedAt, dbDigest] = await Promise.all([
    Promise.all(ENGINE_ORDER.map(async (engine) => ({ engine, ...(await probeEngine(engine)) }))),
    fileExists(MANAGED_TRIVY_DB),
    readTrivyDbDate(),
    readTrivyDbContentDigest(),
  ]);
  return deriveEngineSetupStatus(
    platformKey(),
    rawProbes,
    { exists: dbExists, downloadedAt, provenanceRecorded: Boolean(dbDigest) },
    nowMs,
  );
}

export function engineSetupMessage(status: EngineSetupStatus): string {
  if (status.state === "ready") return "Engine setup ready.";
  if (status.state === "unsupported_platform") {
    return `Engine setup unsupported on ${status.platform}; inspect engine_setup details before scanning.`;
  }
  if (!status.repair_command) {
    return "The packaged engine lockfile is unreadable or unpinned. Reinstall CodeInspectus before scanning.";
  }
  const issue = status.engines
    .filter((engine) => engine.state !== "ready")
    .map((engine) => `${engine.engine}:${engine.state}`)
    .join(", ");
  const parts = [
    `Engine setup ${status.state}`,
    issue ? `engines ${issue}` : undefined,
    status.trivy_db.state !== "ready" ? `Trivy DB ${status.trivy_db.state}` : undefined,
  ].filter(Boolean);
  return `${parts.join("; ")}. Run \`${status.repair_command}\` after user approval.`;
}
