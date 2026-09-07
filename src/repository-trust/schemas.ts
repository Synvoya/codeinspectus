import { z } from "zod";

export const REPOSITORY_TRUST_SCHEMA_VERSION = "1.0.0" as const;
export const REPOSITORY_TRUST_SCHEMA_URI =
  "https://codeinspectus.com/schemas/v1.0.0/repository-trust.schema.json" as const;

export const repositoryTrustCapabilitySchema = z.enum([
  "source_integrity",
  "explicit_ai_attribution",
  "content_provenance",
  "statistical_watermark",
]);

export const repositoryArtifactStateSchema = z.enum([
  "verified",
  "probable",
  "informational",
  "not_verifiable",
]);

export const repositoryArtifactConfidenceSchema = z.enum([
  "high",
  "medium",
  "low",
  "none",
]);

export const repositoryTrustCoverageStateSchema = z.enum([
  "ran",
  "partial",
  "not_run",
  "not_applicable",
  "unavailable",
]);

const repositoryArtifactLocationSchema = z
  .object({
    file: z.string().min(1),
    start_line: z.number().int().positive().optional(),
    end_line: z.number().int().positive().optional(),
    start_column: z.number().int().positive().optional(),
    end_column: z.number().int().positive().optional(),
    field: z.string().min(1).optional(),
  })
  .strict()
  .superRefine((location, context) => {
    if ((location.start_line === undefined) !== (location.end_line === undefined)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [location.start_line === undefined ? "start_line" : "end_line"],
        message: "start_line and end_line must be provided together",
      });
    }
    if (
      location.start_line !== undefined &&
      location.end_line !== undefined &&
      location.end_line < location.start_line
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["end_line"],
        message: "end_line must not precede start_line",
      });
    }
    if ((location.start_column === undefined) !== (location.end_column === undefined)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [location.start_column === undefined ? "start_column" : "end_column"],
        message: "start_column and end_column must be provided together",
      });
    }
    if (location.start_column !== undefined && location.start_line === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["start_column"],
        message: "column locations require line locations",
      });
    }
    if (
      location.start_line === undefined &&
      location.field === undefined
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["field"],
        message: "a repository artifact location requires a line range or metadata field",
      });
    }
  });

const repositoryArtifactEvidenceSchema = z
  .object({
    summary: z.string().min(1),
    attributes: z
      .array(
        z
          .object({
            name: z.string().min(1),
            value: z.union([z.string(), z.number().finite(), z.boolean()]),
            redacted: z.boolean().optional(),
          })
          .strict(),
      )
      .max(128),
  })
  .strict();

const repositoryArtifactValidatorSchema = z
  .object({
    id: z.string().min(1),
    version: z.string().min(1).optional(),
    method: z.enum(["deterministic", "declarative", "statistical"]),
    authoritative: z.boolean(),
    independently_verifiable: z.boolean(),
    egress: z.enum(["none", "optional", "required"]),
  })
  .strict();

const repositoryArtifactRemediationSchema = z
  .object({
    eligible: z.boolean(),
    requires_approval: z.literal(true),
    reversible: z.boolean(),
    protected_record: z.boolean(),
    reason: z.string().min(1),
  })
  .strict();

export const repositoryArtifactSchema = z
  .object({
    artifact_id: z.string().regex(/^artifact-[a-z0-9][a-z0-9._:-]{0,127}$/),
    fingerprint: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    kind: repositoryTrustCapabilitySchema,
    state: repositoryArtifactStateSchema,
    marker_class: z.string().regex(/^[a-z][a-z0-9_]{0,127}$/),
    location: repositoryArtifactLocationSchema,
    evidence: repositoryArtifactEvidenceSchema,
    validator: repositoryArtifactValidatorSchema,
    confidence: repositoryArtifactConfidenceSchema,
    limitations: z.array(z.string().min(1)),
    remediation: repositoryArtifactRemediationSchema,
  })
  .strict()
  .superRefine((artifact, context) => {
    if (
      artifact.state === "verified" &&
      (artifact.confidence !== "high" || !artifact.validator.independently_verifiable)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["state"],
        message: "verified artifacts require high confidence and independently verifiable validation",
      });
    }
    if (
      artifact.kind === "statistical_watermark" &&
      artifact.state === "verified" &&
      (!artifact.validator.authoritative || !artifact.validator.independently_verifiable)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["validator"],
        message: "verified statistical watermarks require authoritative, independently verifiable validation",
      });
    }
    if (artifact.state === "not_verifiable" && artifact.confidence !== "none") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["confidence"],
        message: "not_verifiable artifacts must use confidence none",
      });
    }
    if (artifact.remediation.eligible && artifact.state !== "verified") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["remediation", "eligible"],
        message: "only verified artifacts may be eligible for remediation",
      });
    }
    if (artifact.remediation.eligible && !artifact.remediation.reversible) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["remediation", "reversible"],
        message: "eligible remediation must be reversible",
      });
    }
    if (artifact.remediation.protected_record && artifact.remediation.eligible) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["remediation", "eligible"],
        message: "protected records cannot be remediation eligible",
      });
    }
  });

const repositoryTrustCapabilityCoverageSchema = z
  .object({
    capability: repositoryTrustCapabilitySchema,
    state: repositoryTrustCoverageStateSchema,
    validators: z.array(z.string().min(1)),
    limitations: z.array(z.string().min(1)),
  })
  .strict();

const repositoryTrustSummarySchema = z
  .object({
    verified: z.number().int().nonnegative(),
    probable: z.number().int().nonnegative(),
    informational: z.number().int().nonnegative(),
    not_verifiable: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
  })
  .strict();

export const repositoryTrustDocumentSchema = z
  .object({
    schema_version: z.literal(REPOSITORY_TRUST_SCHEMA_VERSION),
    coverage: z
      .object({
        state: repositoryTrustCoverageStateSchema,
        capabilities: z.array(repositoryTrustCapabilityCoverageSchema),
        limitations: z.array(z.string().min(1)),
      })
      .strict(),
    summary: repositoryTrustSummarySchema,
    artifacts: z.array(repositoryArtifactSchema),
  })
  .strict()
  .superRefine((document, context) => {
    const counts = {
      verified: document.artifacts.filter((artifact) => artifact.state === "verified").length,
      probable: document.artifacts.filter((artifact) => artifact.state === "probable").length,
      informational: document.artifacts.filter((artifact) => artifact.state === "informational").length,
      not_verifiable: document.artifacts.filter((artifact) => artifact.state === "not_verifiable").length,
    };
    const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
    for (const [state, count] of Object.entries(counts)) {
      if (document.summary[state as keyof typeof counts] !== count) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["summary", state],
          message: `${state} count must equal the artifacts array`,
        });
      }
    }
    if (document.summary.total !== total) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["summary", "total"],
        message: "total must equal the artifacts array length",
      });
    }
    const capabilities = new Set<string>();
    for (const [index, capability] of document.coverage.capabilities.entries()) {
      if (capabilities.has(capability.capability)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["coverage", "capabilities", index, "capability"],
          message: "capability coverage entries must be unique",
        });
      }
      capabilities.add(capability.capability);
    }
    if (
      document.artifacts.length > 0 &&
      ["not_run", "not_applicable", "unavailable"].includes(document.coverage.state)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["coverage", "state"],
        message: "documents with artifacts require ran or partial coverage",
      });
    }
  });

export type RepositoryArtifact = z.infer<typeof repositoryArtifactSchema>;
export type RepositoryArtifactState = z.infer<typeof repositoryArtifactStateSchema>;
export type RepositoryArtifactConfidence = z.infer<typeof repositoryArtifactConfidenceSchema>;
export type RepositoryTrustCapability = z.infer<typeof repositoryTrustCapabilitySchema>;
export type RepositoryTrustDocument = z.infer<typeof repositoryTrustDocumentSchema>;

const repositoryTrustChangeSummarySchema = z
  .object({
    resolved: z.number().int().nonnegative(),
    remaining: z.number().int().nonnegative(),
    introduced: z.number().int().nonnegative(),
    not_rechecked: z.number().int().nonnegative(),
  })
  .strict();

export const repositoryTrustChangesSchema = z
  .object({
    schema_version: z.literal("1.0.0"),
    resolved: z.array(repositoryArtifactSchema),
    remaining: z.array(repositoryArtifactSchema),
    introduced: z.array(repositoryArtifactSchema),
    not_rechecked: z.array(repositoryArtifactSchema),
    summary: repositoryTrustChangeSummarySchema,
    partial: z.boolean(),
    limitations: z.array(z.string().min(1)),
  })
  .strict()
  .superRefine((changes, context) => {
    for (const key of ["resolved", "remaining", "introduced", "not_rechecked"] as const) {
      if (changes.summary[key] !== changes[key].length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["summary", key],
          message: `${key} count must equal its artifact array`,
        });
      }
    }
    if (changes.partial !== (changes.not_rechecked.length > 0 || changes.limitations.length > 0)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["partial"],
        message: "partial must reflect not-rechecked artifacts or stated limitations",
      });
    }
  });

export type RepositoryTrustChanges = z.infer<typeof repositoryTrustChangesSchema>;

const UNAVAILABLE_CAPABILITIES: ReadonlyArray<{
  capability: RepositoryTrustCapability;
  limitation: string;
}> = [
  {
    capability: "source_integrity",
    limitation: "Source-integrity evidence was not recorded for this scan; rerun with V3.2 or later to evaluate it.",
  },
  {
    capability: "explicit_ai_attribution",
    limitation: "Explicit AI-attribution evidence was not recorded for this scan; rerun with V3.2 or later to evaluate it.",
  },
  {
    capability: "content_provenance",
    limitation: "Content-provenance evidence was not recorded for this scan; rerun with V3.2 or later to evaluate it.",
  },
  {
    capability: "statistical_watermark",
    limitation: "Statistical watermark verification remains unavailable until an authoritative or independently validated detector exists.",
  },
];

export function createUnavailableRepositoryTrust(): RepositoryTrustDocument {
  return repositoryTrustDocumentSchema.parse({
    schema_version: REPOSITORY_TRUST_SCHEMA_VERSION,
    coverage: {
      state: "unavailable",
      capabilities: UNAVAILABLE_CAPABILITIES.map(({ capability, limitation }) => ({
        capability,
        state: "unavailable",
        validators: [],
        limitations: [limitation],
      })),
      limitations: [
        "No repository-trust detectors ran. Zero artifacts does not mean that the repository was audited or found clean.",
      ],
    },
    summary: {
      verified: 0,
      probable: 0,
      informational: 0,
      not_verifiable: 0,
      total: 0,
    },
    artifacts: [],
  });
}
