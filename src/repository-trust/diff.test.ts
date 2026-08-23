import { describe, expect, test } from "vitest";
import { diffRepositoryTrust } from "./diff.js";
import { createUnavailableRepositoryTrust, type RepositoryArtifact, type RepositoryTrustDocument } from "./schemas.js";

function artifact(fingerprint: string, line: number): RepositoryArtifact {
  return {
    artifact_id: `artifact-si-${fingerprint.slice(-8)}`,
    fingerprint: `sha256:${fingerprint.padStart(64, "a")}`,
    kind: "source_integrity",
    state: "verified",
    marker_class: "unicode_bidi_override",
    location: { file: "src/app.ts", start_line: line, end_line: line, start_column: 1, end_column: 1 },
    evidence: { summary: "Observed", attributes: [] },
    validator: { id: "codeinspectus-source-integrity", version: "1.0.0", method: "deterministic", authoritative: true, independently_verifiable: true, egress: "none" },
    confidence: "high",
    limitations: [],
    remediation: { eligible: true, requires_approval: true, reversible: true, protected_record: false, reason: "approved edit" },
  };
}

function document(artifacts: RepositoryArtifact[], state: "ran" | "partial" = "ran", validator = "codeinspectus-source-integrity@1.0.0"): RepositoryTrustDocument {
  return {
    schema_version: "1.0.0",
    coverage: {
      state: "partial",
      capabilities: [
        { capability: "source_integrity", state, validators: [validator], limitations: state === "partial" ? ["bounded"] : [] },
        { capability: "explicit_ai_attribution", state: "unavailable", validators: [], limitations: ["unavailable"] },
        { capability: "content_provenance", state: "unavailable", validators: [], limitations: ["unavailable"] },
        { capability: "statistical_watermark", state: "unavailable", validators: [], limitations: ["unavailable"] },
      ],
      limitations: ["other capabilities unavailable"],
    },
    summary: {
      verified: artifacts.filter((item) => item.state === "verified").length,
      probable: artifacts.filter((item) => item.state === "probable").length,
      informational: artifacts.filter((item) => item.state === "informational").length,
      not_verifiable: artifacts.filter((item) => item.state === "not_verifiable").length,
      total: artifacts.length,
    },
    artifacts,
  };
}

describe("repository-trust rescan diff", () => {
  test("classifies resolved, remaining, and introduced artifacts with complete matching validators", () => {
    const remaining = artifact("1", 1);
    const resolved = artifact("2", 2);
    const introduced = artifact("3", 3);
    const result = diffRepositoryTrust(document([remaining, resolved]), document([remaining, introduced]));
    expect(result.summary).toEqual({ resolved: 1, remaining: 1, introduced: 1, not_rechecked: 0 });
    expect(result.resolved).toEqual([resolved]);
    expect(result.remaining).toEqual([remaining]);
    expect(result.introduced).toEqual([introduced]);
    expect(result.partial).toBe(false);
  });

  test("does not claim resolution when fresh coverage is partial or validator identity changed", () => {
    const priorArtifact = artifact("4", 4);
    const partial = diffRepositoryTrust(document([priorArtifact]), document([], "partial"));
    expect(partial.not_rechecked).toEqual([priorArtifact]);
    expect(partial.resolved).toEqual([]);
    expect(partial.partial).toBe(true);

    const changed = diffRepositoryTrust(document([priorArtifact]), document([], "ran", "codeinspectus-source-integrity@2.0.0"));
    expect(changed.not_rechecked).toEqual([priorArtifact]);
    expect(changed.limitations.join(" ")).toMatch(/validator identity changed/i);
  });

  test("treats a legacy unavailable document as having no prior artifacts", () => {
    const introduced = artifact("5", 5);
    const result = diffRepositoryTrust(createUnavailableRepositoryTrust(), document([introduced]));
    expect(result.summary).toEqual({ resolved: 0, remaining: 0, introduced: 1, not_rechecked: 0 });
  });
});
