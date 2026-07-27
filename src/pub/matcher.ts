/** Exact-version Pub vulnerability matcher. No generic SemVer range inference. */

import type { PubAdvisory, PubAdvisorySnapshot, PubAffectedPackage } from "./snapshot.js";

export interface PubPackageIdentity {
  name: string;
  version: string;
}

export interface PubVulnerabilityMatch {
  advisory: PubAdvisory;
  affected: PubAffectedPackage;
}

export function matchPubPackage(
  snapshot: PubAdvisorySnapshot,
  pkg: PubPackageIdentity,
): PubVulnerabilityMatch[] {
  const matches: PubVulnerabilityMatch[] = [];
  for (const advisory of snapshot.advisories) {
    for (const affected of advisory.affected) {
      if (affected.package === pkg.name && affected.versions.includes(pkg.version)) {
        matches.push({ advisory, affected });
      }
    }
  }
  return matches.sort((left, right) => left.advisory.id.localeCompare(right.advisory.id));
}
