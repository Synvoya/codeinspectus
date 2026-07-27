import { OSV_PUB_SNAPSHOT } from "../config.js";
import { loadPubSnapshot, type LoadedPubSnapshot } from "./snapshot.js";

export const PUB_SNAPSHOT_STALE_AFTER_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface PubAdvisoryDatabaseInfo {
  engine: "codeinspectus-pub";
  ecosystem: "Pub";
  state: "current" | "stale" | "missing" | "invalid";
  version: string;
  checked_at?: string;
  latest_record_modified?: string;
  age_days?: number;
  stale_after_days: number;
  content_digest?: string;
  active_advisories: number;
  withdrawn_records: number;
  affected_packages: number;
  matching: "exact-enumerated-versions";
  source_url: string;
  source_database: "GitHub Advisory Database";
  license: "CC-BY-4.0";
  attribution: string;
  note?: string;
}

export interface PubDatabaseInspection {
  info: PubAdvisoryDatabaseInfo;
  loaded?: LoadedPubSnapshot;
}

function unavailableInfo(state: "missing" | "invalid", note: string): PubAdvisoryDatabaseInfo {
  return {
    engine: "codeinspectus-pub",
    ecosystem: "Pub",
    state,
    version: "unknown",
    stale_after_days: PUB_SNAPSHOT_STALE_AFTER_DAYS,
    active_advisories: 0,
    withdrawn_records: 0,
    affected_packages: 0,
    matching: "exact-enumerated-versions",
    source_url: "https://storage.googleapis.com/osv-vulnerabilities/Pub/modified_id.csv",
    source_database: "GitHub Advisory Database",
    license: "CC-BY-4.0",
    attribution: "OSV.dev and GitHub Advisory Database contributors",
    note,
  };
}

export async function inspectPubDatabase(
  path = OSV_PUB_SNAPSHOT,
  options: { nowMs?: number } = {},
): Promise<PubDatabaseInspection> {
  try {
    const loaded = await loadPubSnapshot(path);
    const snapshot = loaded.data.snapshot;
    const checkedMs = Date.parse(snapshot.checked_at);
    if (!Number.isFinite(checkedMs)) {
      return { info: unavailableInfo("invalid", "The bundled Pub snapshot has an invalid checked_at timestamp.") };
    }
    const ageMs = Math.max(0, (options.nowMs ?? Date.now()) - checkedMs);
    const ageDays = Math.floor(ageMs / DAY_MS);
    const state = ageMs >= PUB_SNAPSHOT_STALE_AFTER_DAYS * DAY_MS ? "stale" : "current";
    return {
      loaded,
      info: {
        engine: "codeinspectus-pub",
        ecosystem: "Pub",
        state,
        version: snapshot.snapshot_version,
        checked_at: snapshot.checked_at,
        latest_record_modified: snapshot.latest_record_modified,
        age_days: ageDays,
        stale_after_days: PUB_SNAPSHOT_STALE_AFTER_DAYS,
        content_digest: loaded.content_signature,
        active_advisories: snapshot.advisory_count,
        withdrawn_records: snapshot.withdrawn_record_count,
        affected_packages: snapshot.affected_package_count,
        matching: snapshot.matching,
        source_url: snapshot.source_index_url,
        source_database: "GitHub Advisory Database",
        license: snapshot.license,
        attribution: snapshot.attribution,
        ...(state === "stale"
          ? { note: `Bundled Pub advisory snapshot is ${ageDays} days old; refresh it before the next release.` }
          : {}),
      },
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    const state = code === "ENOENT" ? "missing" : "invalid";
    const detail = error instanceof Error ? error.message : String(error);
    return {
      info: unavailableInfo(
        state,
        state === "missing"
          ? "The bundled Pub advisory snapshot is missing. Reinstall CodeInspectus."
          : `The bundled Pub advisory snapshot failed validation: ${detail}`,
      ),
    };
  }
}
