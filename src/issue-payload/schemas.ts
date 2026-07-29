import { z } from "zod";
import { scanIdSchema } from "../schemas.js";
import { aggregateCoverageSchema } from "../export/schemas.js";

export const ISSUE_PAYLOAD_SCHEMA_VERSION = "1.0.0" as const;
export const ISSUE_PAYLOAD_SCHEMA_URI = "https://codeinspectus.com/schemas/issue-payload/1.0.0/payload.schema.json" as const;

const destinationSchema = z.object({
  visibility: z.enum(["private", "public"]),
  warnings: z.array(z.string()).min(2),
  review_required: z.literal(true),
  submission: z.literal("not_performed"),
  required_destination_fields: z.array(z.string()),
});

const sourceSchema = z.object({
  scan_id: scanIdSchema,
  finding_id: z.string().min(1),
  fingerprint: z.string().min(1),
  aggregate_coverage: aggregateCoverageSchema,
});

const githubPayloadSchema = z.object({ title: z.string().min(1).max(240), body: z.string().min(1).max(20_000), labels: z.array(z.string()).max(20) });
const jiraPayloadSchema = z.object({ fields: z.object({
  summary: z.string().min(1).max(240),
  description: z.object({ type: z.literal("doc"), version: z.literal(1), content: z.array(z.object({
    type: z.literal("paragraph"), content: z.array(z.object({ type: z.literal("text"), text: z.string().max(20_000) })).length(1),
  })).length(1) }),
  labels: z.array(z.string()).max(20),
}) });
const linearPayloadSchema = z.object({ title: z.string().min(1).max(240), description: z.string().min(1).max(20_000) });

export const issuePayloadSchema = z.discriminatedUnion("adapter", [
  z.object({ $schema: z.literal(ISSUE_PAYLOAD_SCHEMA_URI), schema_version: z.literal(ISSUE_PAYLOAD_SCHEMA_VERSION), adapter: z.literal("github"), generated_by: z.object({ name: z.literal("codeinspectus"), version: z.string() }), source: sourceSchema, destination: destinationSchema, payload: githubPayloadSchema }),
  z.object({ $schema: z.literal(ISSUE_PAYLOAD_SCHEMA_URI), schema_version: z.literal(ISSUE_PAYLOAD_SCHEMA_VERSION), adapter: z.literal("jira"), generated_by: z.object({ name: z.literal("codeinspectus"), version: z.string() }), source: sourceSchema, destination: destinationSchema, payload: jiraPayloadSchema }),
  z.object({ $schema: z.literal(ISSUE_PAYLOAD_SCHEMA_URI), schema_version: z.literal(ISSUE_PAYLOAD_SCHEMA_VERSION), adapter: z.literal("linear"), generated_by: z.object({ name: z.literal("codeinspectus"), version: z.string() }), source: sourceSchema, destination: destinationSchema, payload: linearPayloadSchema }),
]);

export type IssuePayload = z.infer<typeof issuePayloadSchema>;
export type IssueAdapter = IssuePayload["adapter"];
export type DestinationVisibility = IssuePayload["destination"]["visibility"];
