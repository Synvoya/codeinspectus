import { readFile } from "node:fs/promises";
import { Ajv } from "ajv";
import { describe, expect, test } from "vitest";
import { createIssuePayload } from "./index.js";
import { issuePayloadSchema, type IssueAdapter } from "./schemas.js";
import { ISSUE_TEST_SECRET, issueTestScan } from "./test-fixture.js";

function body(document: ReturnType<typeof createIssuePayload>): string {
  return document.adapter === "github" ? document.payload.body : document.adapter === "jira" ? document.payload.fields.description.content[0]!.content[0]!.text : document.payload.description;
}

describe("safe issue-payload generation", () => {
  test.each(["github", "jira", "linear"] as IssueAdapter[])("generates deterministic redacted %s JSON with no submission path", async (adapter) => {
    const first = createIssuePayload(issueTestScan(), "CI-0001", adapter, "public");
    const second = createIssuePayload(issueTestScan(), "CI-0001", adapter, "public");
    expect(first).toEqual(second);
    expect(first).toMatchObject({ schema_version: "1.0.0", adapter, source: { finding_id: "CI-0001", aggregate_coverage: "partial" }, destination: { visibility: "public", review_required: true, submission: "not_performed" } });
    expect(first.destination.warnings.join(" ")).toMatch(/PUBLIC DESTINATION.*coordinated-disclosure/i);
    expect(JSON.stringify(first)).not.toContain(ISSUE_TEST_SECRET);
    expect(JSON.stringify(first)).not.toContain('"snippet":');
    expect(body(first)).toContain("No source snippet or matched secret value is included");
    expect(body(first)).not.toContain("@owner");
    expect(JSON.stringify(first)).toContain("@​owner");
    expect(first.destination.required_destination_fields.length).toBeGreaterThan(0);
    expect(issuePayloadSchema.parse(first)).toEqual(first);

    const schema = JSON.parse(await readFile("schemas/codeinspectus-issue-payload-1.0.0.schema.json", "utf8"));
    const validate = new Ajv({ strict: false, validateSchema: false }).compile(schema);
    expect(validate(first), JSON.stringify(validate.errors)).toBe(true);
  });

  // Repository-controlled text (file names, messages) reaches tracker Markdown. Raw `<`/`&` could open
  // HTML such as a phishing link, and bidi controls could make a file name render as something else.
  test("neutralizes HTML, entities and invisible or bidirectional characters from repository text", () => {
    const scan = issueTestScan();
    scan.findings[0]!.location.file = "src/<a href=\"https://evil.example\">login</a>&amp;\u202etxt.exe\u200b.ts";
    scan.findings[0]!.message = "Message <img src=x onerror=alert(1)> \u2066hidden\u2069";
    const text = body(createIssuePayload(scan, "CI-0001", "github", "public"));
    expect(text).not.toMatch(/<a |<img /);
    expect(text).toContain("&lt;a href");
    expect(text).toContain("&amp;amp;");
    expect(text).not.toMatch(/[\u202a-\u202e\u2066-\u2069]/);
    expect(text).toContain("\\\\u202e");
    expect(text.replace(/@\u200b/g, "")).not.toContain("\u200b");
  });

  test("retains a private visibility warning and rejects unknown findings or adapter/payload mismatches", () => {
    const privatePayload = createIssuePayload(issueTestScan(), "CI-0001", "github", "private");
    expect(privatePayload.destination.warnings.join(" ")).toMatch(/PRIVATE DESTINATION.*access controls/i);
    expect(() => createIssuePayload(issueTestScan(), "CI-9999", "github", "private")).toThrow(/does not exist/i);
    expect(issuePayloadSchema.safeParse({ ...privatePayload, adapter: "linear" }).success).toBe(false);
  });
});
