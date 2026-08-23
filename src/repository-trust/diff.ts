import {
  repositoryTrustChangesSchema,
  type RepositoryArtifact,
  type RepositoryTrustCapability,
  type RepositoryTrustChanges,
  type RepositoryTrustDocument,
} from "./schemas.js";

function validatorsFor(document: RepositoryTrustDocument, capability: RepositoryTrustCapability): string[] {
  return document.coverage.capabilities.find((entry) => entry.capability === capability)?.validators ?? [];
}

function coverageFor(document: RepositoryTrustDocument, capability: RepositoryTrustCapability) {
  return document.coverage.capabilities.find((entry) => entry.capability === capability)?.state ?? "not_run";
}

function sameValidators(left: string[], right: string[]): boolean {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function sorted(artifacts: RepositoryArtifact[]): RepositoryArtifact[] {
  return [...artifacts].sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    (left.location.start_line ?? 0) - (right.location.start_line ?? 0) ||
    (left.location.start_column ?? 0) - (right.location.start_column ?? 0) ||
    left.marker_class.localeCompare(right.marker_class)
  );
}

/**
 * Compare versioned non-CWE artifacts without converting incomplete detector coverage into a
 * false resolution claim. Absence is resolution only when the matching capability ran completely
 * with the same validator set.
 */
export function diffRepositoryTrust(
  prior: RepositoryTrustDocument,
  fresh: RepositoryTrustDocument,
): RepositoryTrustChanges {
  const priorByFingerprint = new Map(prior.artifacts.map((artifact) => [artifact.fingerprint, artifact]));
  const freshByFingerprint = new Map(fresh.artifacts.map((artifact) => [artifact.fingerprint, artifact]));
  const remaining = fresh.artifacts.filter((artifact) => priorByFingerprint.has(artifact.fingerprint));
  const introduced = fresh.artifacts.filter((artifact) => !priorByFingerprint.has(artifact.fingerprint));
  const resolved: RepositoryArtifact[] = [];
  const notRechecked: RepositoryArtifact[] = [];
  const limitations = new Set<string>();

  for (const artifact of prior.artifacts) {
    if (freshByFingerprint.has(artifact.fingerprint)) continue;
    const capability = artifact.kind;
    const freshCoverage = coverageFor(fresh, capability);
    const priorValidators = validatorsFor(prior, capability);
    const freshValidators = validatorsFor(fresh, capability);
    if (freshCoverage !== "ran") {
      notRechecked.push(artifact);
      limitations.add(`${capability} coverage was ${freshCoverage}, so absent artifacts are not confirmed resolved.`);
      continue;
    }
    if (!priorValidators.length || !freshValidators.length || !sameValidators(priorValidators, freshValidators)) {
      notRechecked.push(artifact);
      limitations.add(`${capability} validator identity changed or was not recorded, so absent artifacts are not confirmed resolved.`);
      continue;
    }
    resolved.push(artifact);
  }

  const result: RepositoryTrustChanges = {
    schema_version: "1.0.0",
    resolved: sorted(resolved),
    remaining: sorted(remaining),
    introduced: sorted(introduced),
    not_rechecked: sorted(notRechecked),
    summary: {
      resolved: resolved.length,
      remaining: remaining.length,
      introduced: introduced.length,
      not_rechecked: notRechecked.length,
    },
    partial: notRechecked.length > 0 || limitations.size > 0,
    limitations: [...limitations],
  };
  return repositoryTrustChangesSchema.parse(result);
}

export function createEmptyRepositoryTrustChanges(): RepositoryTrustChanges {
  return repositoryTrustChangesSchema.parse({
    schema_version: "1.0.0",
    resolved: [],
    remaining: [],
    introduced: [],
    not_rechecked: [],
    summary: { resolved: 0, remaining: 0, introduced: 0, not_rechecked: 0 },
    partial: false,
    limitations: [],
  });
}
