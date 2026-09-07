import { scanAiProvenance, type AiProvenanceOptions } from "./ai-provenance.js";
import {
  repositoryTrustDocumentSchema,
  type RepositoryArtifactState,
  type RepositoryTrustDocument,
} from "./schemas.js";
import { scanSourceIntegrity } from "./source-integrity.js";

export async function scanRepositoryTrust(
  target: string,
  options: { aiProvenance?: AiProvenanceOptions } = {},
): Promise<RepositoryTrustDocument> {
  const [source, provenance] = await Promise.all([
    scanSourceIntegrity(target),
    scanAiProvenance(target, options.aiProvenance),
  ]);
  const sourceCoverage = source.coverage.capabilities.find((item) => item.capability === "source_integrity")!;
  const artifacts = [...source.artifacts, ...provenance.artifacts].sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    (left.location.start_line ?? 0) - (right.location.start_line ?? 0) ||
    (left.location.field ?? "").localeCompare(right.location.field ?? "") ||
    left.marker_class.localeCompare(right.marker_class)
  );
  const capabilities = [
    sourceCoverage,
    { capability: "explicit_ai_attribution" as const, ...provenance.explicitAttribution },
    { capability: "content_provenance" as const, ...provenance.contentProvenance },
    {
      capability: "statistical_watermark" as const,
      state: "unavailable" as const,
      validators: [],
      limitations: [
        "Statistical watermark verification is not available without an authoritative, independently verifiable detector and calibrated operating thresholds.",
      ],
    },
  ];
  const implementedStates = capabilities
    .filter((item) => item.capability !== "statistical_watermark")
    .map((item) => item.state);
  const count = (state: RepositoryArtifactState): number => artifacts.filter((artifact) => artifact.state === state).length;
  return repositoryTrustDocumentSchema.parse({
    schema_version: "1.0.0",
    coverage: {
      state: "partial",
      capabilities,
      limitations: [
        ...(implementedStates.includes("partial")
          ? ["One or more implemented repository-trust capabilities reported partial coverage; inspect capability limitations."]
          : []),
        "Statistical watermark verification remains unavailable; V3.2 does not rewrite text or remove provenance records.",
      ],
    },
    summary: {
      verified: count("verified"),
      probable: count("probable"),
      informational: count("informational"),
      not_verifiable: count("not_verifiable"),
      total: artifacts.length,
    },
    artifacts,
  });
}
