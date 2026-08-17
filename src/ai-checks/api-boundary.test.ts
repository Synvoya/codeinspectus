/**
 * Project CI Enhancement 1 — API-boundary detector contract lock.
 *
 * The corpus is frozen before the analyzer. Every planted TP must fire exactly once;
 * realistic validation/projection/redaction near misses must remain silent.
 */

import { afterEach, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Finding } from "../types.js";
import { runApiBoundaryChecks } from "./api-boundary.js";

const CORPUS = join(process.cwd(), "fixtures", "api-boundary-corpus");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })
  ));
});

const RULES = {
  error: "ci-ai-client-error-leak",
  response: "ci-ai-sensitive-api-response",
  write: "ci-ai-unvalidated-request-write",
  log: "ci-ai-sensitive-log",
} as const;

const TP: Array<{ file: string; rule: string; cwe: string; owaspWeb: string; owaspApi: string }> = [
  { file: "tp/01-error-message-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/02-raw-error-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/03-internal-detail-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/09-error-stack-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/10-provider-error-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/11-mongoose-mass-assignment.ts", rule: RULES.write, cwe: "CWE-915", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/12-raw-error-after-public-branch.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/13-request-spread-write.ts", rule: RULES.write, cwe: "CWE-915", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/14-raw-custom-error-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/15-fastify-error-response.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/16-prisma-transaction-write.ts", rule: RULES.write, cwe: "CWE-915", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/17-lowercase-mongoose-model.ts", rule: RULES.write, cwe: "CWE-915", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/18-fastify-sensitive-log.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/04-sensitive-response.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/05-prisma-mass-assignment.ts", rule: RULES.write, cwe: "CWE-915", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/06-supabase-mass-assignment.ts", rule: RULES.write, cwe: "CWE-915", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/07-sensitive-log.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/auth/08-login-body-log.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
];

const FP = [
  "fp/01-generic-errors.ts",
  "fp/02-safe-response.ts",
  "fp/03-zod-validated-write.ts",
  "fp/04-joi-validated-write.ts",
  "fp/05-explicit-field-projection.ts",
  "fp/06-safe-logging.ts",
  "fp/07-generic-body-log.ts",
  "fp/08-mongoose-explicit-projection.ts",
  "fp/09-commented-sinks.ts",
  "fp/10-vendored-library.min.js",
  "fp/11-public-user-error.ts",
  "fp/12-boolean-sensitive-presence.ts",
];

const atFile = (findings: Finding[], suffix: string) =>
  findings.filter((finding) => finding.location.file.endsWith(suffix));

describe("API-boundary analyzers — frozen corpus", () => {
  let findings: Finding[];

  beforeAll(async () => {
    findings = await runApiBoundaryChecks(CORPUS);
  });

  test.each(TP)("TP $file emits $rule once with canonical mappings", (tp) => {
    const hits = atFile(findings, tp.file).filter((finding) => finding.rule_id === tp.rule);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.cwe).toContain(tp.cwe);
    expect(hits[0]!.owasp_web).toContain(tp.owaspWeb);
    expect(hits[0]!.owasp_api).toContain(tp.owaspApi);
    expect(hits[0]!.confidence).toBe("medium");
    expect(hits[0]!.producer_components).toBeUndefined(); // assigned by runAiChecks, not the analyzer alone
  });

  test.each(FP)("FP %s remains silent for every Enhancement 1 API rule", (file) => {
    expect(atFile(findings, file)).toHaveLength(0);
  });

  test("emits exactly the planted findings with no duplicates", () => {
    expect(findings).toHaveLength(TP.length);
    expect(new Set(findings.map((finding) => `${finding.rule_id}:${finding.location.file}:${finding.location.start_line}`)).size)
      .toBe(TP.length);
  });

  test("sensitive snippets never echo planted field values", () => {
    const surfaced = JSON.stringify(findings);
    expect(surfaced).not.toContain("provider failure");
    expect(surfaced).not.toContain("database unavailable");
    expect(surfaced).not.toContain("session.accessToken");
    expect(surfaced).not.toContain("request.headers.get");
  });

  test("project-root scans exclude deliberate Express test/example error responses", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-api-boundary-production-"));
    temporaryDirectories.push(directory);
    await mkdir(join(directory, "src"));
    await mkdir(join(directory, "test"));
    await mkdir(join(directory, "examples"));
    await writeFile(join(directory, "src", "server.js"), `
      app.use(function (err, req, res, next) {
        res.status(500).send({ error: err.message });
      });
    `);
    const deliberateHarness = `
      app.use(function (err, req, res, next) {
        res.status(500).send([count, called, err.message].join(" "));
      });
    `;
    await writeFile(join(directory, "test", "res.render.js"), deliberateHarness);
    await writeFile(join(directory, "examples", "web-service.js"), deliberateHarness);

    const result = await runApiBoundaryChecks(directory);

    expect(result.map((finding) => finding.location.file)).toEqual(["src/server.js"]);
    expect(result[0]?.rule_id).toBe(RULES.error);
  });
});
