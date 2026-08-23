import { readFile } from "node:fs/promises";
import { Ajv } from "ajv";
import { describe, expect, test } from "vitest";
import {
  createUnavailableRepositoryTrust,
  repositoryTrustDocumentSchema,
  type RepositoryTrustDocument,
} from "./schemas.js";

function verifiedArtifactDocument(): RepositoryTrustDocument {
  return {
    schema_version: "1.0.0",
    coverage: {
      state: "ran",
      capabilities: [
        {
          capability: "source_integrity",
          state: "ran",
          validators: ["codeinspectus-unicode@1.0.0"],
          limitations: [],
        },
      ],
      limitations: [],
    },
    summary: {
      verified: 1,
      probable: 0,
      informational: 0,
      not_verifiable: 0,
      total: 1,
    },
    artifacts: [
      {
        artifact_id: "artifact-source-integrity-1",
        fingerprint: `sha256:${"a".repeat(64)}`,
        kind: "source_integrity",
        state: "verified",
        marker_class: "unicode_bidi_control",
        location: {
          file: "src/index.ts",
          start_line: 3,
          end_line: 3,
          start_column: 8,
          end_column: 8,
        },
        evidence: {
          summary: "Unexpected RIGHT-TO-LEFT OVERRIDE at an executable source location.",
          attributes: [{ name: "code_point", value: "U+202E" }],
        },
        validator: {
          id: "codeinspectus-unicode",
          version: "1.0.0",
          method: "deterministic",
          authoritative: true,
          independently_verifiable: true,
          egress: "none",
        },
        confidence: "high",
        limitations: [],
        remediation: {
          eligible: true,
          requires_approval: true,
          reversible: true,
          protected_record: false,
          reason: "The exact source character can be removed after file-scoped approval.",
        },
      },
    ],
  };
}

describe("repository trust contract", () => {
  test("accepts a deterministic non-CWE artifact and the packaged JSON Schema agrees", async () => {
    const document = verifiedArtifactDocument();
    expect(repositoryTrustDocumentSchema.parse(document)).toEqual(document);

    const schema = JSON.parse(
      await readFile("schemas/codeinspectus-repository-trust-1.0.0.schema.json", "utf8"),
    ) as object;
    const validate = new Ajv({ strict: false, validateSchema: false }).compile(schema);
    expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
  });

  test("represents unimplemented capabilities explicitly instead of treating zero artifacts as clean", () => {
    const document = createUnavailableRepositoryTrust();
    expect(document.artifacts).toEqual([]);
    expect(document.summary.total).toBe(0);
    expect(document.coverage.state).toBe("unavailable");
    expect(document.coverage.capabilities).toHaveLength(4);
    expect(document.coverage.capabilities.every((entry) => entry.state === "unavailable")).toBe(true);
    expect(document.coverage.limitations.join(" ")).toContain("No repository-trust detectors ran");
    expect(repositoryTrustDocumentSchema.parse(document)).toEqual(document);
  });

  test("rejects inconsistent summary counts and unverifiable artifacts that claim remediation eligibility", () => {
    const badSummary = verifiedArtifactDocument();
    badSummary.summary.total = 2;
    expect(repositoryTrustDocumentSchema.safeParse(badSummary).success).toBe(false);

    const unverifiable = verifiedArtifactDocument();
    unverifiable.artifacts[0] = {
      ...unverifiable.artifacts[0]!,
      state: "not_verifiable",
      confidence: "none",
      remediation: {
        ...unverifiable.artifacts[0]!.remediation,
        eligible: true,
      },
    };
    unverifiable.summary = {
      verified: 0,
      probable: 0,
      informational: 0,
      not_verifiable: 1,
      total: 1,
    };
    expect(repositoryTrustDocumentSchema.safeParse(unverifiable).success).toBe(false);
  });

  test("rejects verified statistical claims without authoritative independently verifiable validation", () => {
    const document = verifiedArtifactDocument();
    document.artifacts[0] = {
      ...document.artifacts[0]!,
      kind: "statistical_watermark",
      marker_class: "vendor_text_watermark",
      validator: {
        ...document.artifacts[0]!.validator,
        method: "statistical",
        authoritative: false,
        independently_verifiable: false,
      },
    };
    expect(repositoryTrustDocumentSchema.safeParse(document).success).toBe(false);
  });

  test("does not accept vulnerability severity or CWE fields in artifact records", () => {
    const document = verifiedArtifactDocument() as RepositoryTrustDocument & {
      artifacts: Array<RepositoryTrustDocument["artifacts"][number] & {
        severity?: string;
        cwe?: string[];
      }>;
    };
    document.artifacts[0]!.severity = "high";
    document.artifacts[0]!.cwe = ["CWE-79"];
    expect(repositoryTrustDocumentSchema.safeParse(document).success).toBe(false);
  });
});
