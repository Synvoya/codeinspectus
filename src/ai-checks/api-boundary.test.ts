/**
 * Project CI Enhancement 1 — API-boundary detector contract lock.
 *
 * The corpus is frozen before the analyzer. Every planted TP must fire exactly once;
 * realistic validation/projection/redaction near misses must remain silent.
 */

import { afterEach, beforeAll, describe, expect, test } from "vitest";
import { readdirSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Finding } from "../types.js";
import { hasHandlerSignature, runApiBoundaryChecks } from "./api-boundary.js";
import { routeFindings } from "../file-routing.js";

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
  // 4.1 M9 Task 3: real variants that must keep firing next to each precision fix.
  { file: "tp/19-express-bare-res-error.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/20-fastify-reply-stack.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/21-hono-context-error.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/22-password-hash-response.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/23-authorization-echo.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/24-reassigned-token.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/25-token-from-other-scope.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/26-log-member-value.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/27-log-authorization-header.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/28-log-whole-headers.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/29-log-template-token.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  // 4.1 M9 addendum A1 (mailflare shapes, original code): real variants next to each parsing fix.
  { file: "tp/30-braceless-typed-stack.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/31-braceless-branch-then-leak.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/32-destructured-token-returned.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/33-nested-object-token.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/34-object-assign-token.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/35-session-from-store.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/36-conditional-stored-secret.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // 4.1 M9 addendum A4: an app-defined error class whose message is not fixed, or a name imported from a package.
  { file: "tp/37-app-error-upstream-message/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/38-app-error-param-passthrough/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/39-app-error-name-from-package/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // 4.1 M9 fix round 1 (review item 1): a wrapper call that is the whole response keeps its fields.
  { file: "tp/41-wrapped-response-helper.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/42-success-wrapper-password.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 1 (review item 4): a generated value is issued only when created in the responding function and not rewritten.
  { file: "tp/43-issued-in-outer-scope.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/44-issued-then-destructured.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/45-issued-then-nullish-assign.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/46-issued-then-shadowed-param.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 1 (review item 5): Next.js pages API handlers and typed Fastify handlers are server handlers.
  { file: "tp/47-next-pages-api-handler.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/48-fastify-generic-request-type.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // Fix round 1 (review item 6): sensitive headers by name, and member reads that still log the secret.
  { file: "tp/49-log-api-key-header.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/50-log-auth-token-header.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/51-log-secret-access-key.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/52-log-token-value.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  { file: "tp/53-log-password-slice.ts", rule: RULES.log, cwe: "CWE-532", owaspWeb: "A09:2021", owaspApi: "API8:2023" },
  // Fix round 3 (item 5): nested call arguments are blanked only under id/receipt-shaped keys.
  { file: "tp/71-profile-wrapper-call.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 5 (item 2): a later top-level computed key can override the issued field.
  { file: "tp/80-issued-then-computed-key.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 5 (item 1): `this.message` written in the class body by `+=` or in bracket form, or outside any class body
  // through a prototype method assigned in another file.
  { file: "tp/77-app-error-method-compound/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/78-app-error-method-bracket/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/79-app-error-prototype-method/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // Fix round 4 (item 3): a `*Url` key is not a receipt; the URL can carry the credential its call is built from.
  { file: "tp/76-reset-url-wrapper-call.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 4 (item 2): a top-level spread after the issued field overrides it.
  { file: "tp/74-issued-then-later-spread.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/75-issued-self-spread-then-later-spread.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 4 (item 1): a compound message write, and a cross-file helper that never names the class.
  { file: "tp/72-app-error-compound-message/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/73-app-error-cross-file-helper/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // Fix round 3 (item 3): only `Error`/`globalThis.Error` is a root; a library's `lib.Error` is not.
  { file: "tp/70-app-error-library-base/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // Fix round 3 (item 2): a message mutated after construction keeps the class non-public.
  { file: "tp/67-app-error-caught-mutated/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/68-app-error-assign-variable/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/69-app-error-define-property/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // Fix round 3 (item 1): the issued name used anywhere but as a top-level response field, or rebound by a bare
  // for-of or a destructured catch, is not the issued credential.
  { file: "tp/62-issued-then-callback-declaration.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/63-issued-then-callback-destructure.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/64-issued-then-default-with-call.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/65-issued-then-destructured-catch.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/66-issued-then-bare-for-of.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 2 (item 5): a call under a data-carrying property returns its arguments.
  { file: "tp/61-data-wrapper-call.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 2 (item 3): a namespace-imported parent, and a message overwritten after construction.
  { file: "tp/58-app-error-namespace-subclass/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/59-app-error-object-assign-message/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/60-app-error-message-write/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  // Fix round 2 (item 2): the same name rebound in the response expression or a loop header is not the issued value.
  { file: "tp/56-issued-then-map-destructure.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  { file: "tp/57-issued-then-loop-binding.ts", rule: RULES.response, cwe: "CWE-201", owaspWeb: "A01:2021", owaspApi: "API3:2023" },
  // Fix round 1 (review item 7): a `message` parameter property, and a subclass built from upstream text.
  { file: "tp/54-app-error-message-param-property/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
  { file: "tp/55-app-error-dynamic-subclass/route.ts", rule: RULES.error, cwe: "CWE-209", owaspWeb: "A05:2021", owaspApi: "API8:2023" },
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
  // 4.1 M9 Task 3: not a server response, an issued credential, or a non-sensitive logged value.
  "fp/13-browser-xhr-send.ts",
  "fp/14-websocket-sdk-send.ts",
  "fp/15-issued-jwt-response.ts",
  "fp/16-fastify-constant-message.ts",
  "fp/17-issued-api-key.ts",
  "fp/billing/18-log-member-and-headers.ts",
  // 4.1 M9 addendum A1: brace-less typed branch, destructured rest, nested call argument, issued session/secret.
  "fp/19-braceless-typed-error.ts",
  "fp/20-destructured-rest.ts",
  "fp/21-nested-call-credential.ts",
  "fp/22-issued-session-and-secret.ts",
  // 4.1 M9 addendum A4: fp/23 (error classes whose every message is a literal) moved to
  // fixtures/api-boundary-public-errors/ in fix round 4: a message write anywhere in a repository makes every class
  // non-public, and this corpus holds the message-write TPs, so it is scanned as its own repository below.
  // Fix round 3 (item 5): an id-shaped key consumes its call's arguments.
  "fp/25-id-wrapper-call.ts",
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
    // 4.1 M9 fresh-set gate: client-error-leak is low severity and low confidence; the others stay medium.
    expect(hits[0]!.confidence).toBe(tp.rule === RULES.error ? "low" : "medium");
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

  test("M9: Cypress specs are skipped; e2e/ and playwright/ are reported and lowered by routing (fix round 1)", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-api-boundary-e2e-"));
    temporaryDirectories.push(directory);
    const leaky = `
      app.use(function (err, req, res, next) {
        console.log("token", token);
        res.status(500).send({ error: err.message });
      });
    `;
    for (const rel of ["cypress/e2e/login.ts", "e2e/api.ts", "playwright/auth.ts", "web/login.cy.ts", "src/server.js"]) {
      await mkdir(join(directory, rel, ".."), { recursive: true });
      await writeFile(join(directory, rel), leaky);
    }
    const result = await runApiBoundaryChecks(directory);
    expect([...new Set(result.map((finding) => finding.location.file))].sort()).toEqual(["e2e/api.ts", "playwright/auth.ts", "src/server.js"]);
    // runAiChecks classifies these as `ai` findings before routing.
    const routed = routeFindings(result.map((finding) => ({ ...finding, finding_kind: "ai" as const })), () => "tracked").findings;
    expect(routed.filter((finding) => finding.location.file !== "src/server.js").every((finding) => finding.severity === "low")).toBe(true);
    // Production code keeps the analyzer's severity (client-error-leak is low by the 4.1 fresh-set gate; the log stays high).
    expect(routed.filter((finding) => finding.location.file === "src/server.js").map((finding) => finding.severity))
      .toEqual(result.filter((finding) => finding.location.file === "src/server.js").map((finding) => finding.severity));
    expect(routed.some((finding) => finding.location.file === "src/server.js" && finding.severity === "high")).toBe(true);
  });

  // Security review (fix round 1): the handler-signature search stays linear on adversarial input.
  test("handler-signature detection is fast on long generic-looking lines", () => {
    const long = "(err: a<b<c,".repeat(Math.ceil(50_000 / 12));
    const near = "(err: a<b<c,".repeat(160);
    const started = performance.now();
    expect(hasHandlerSignature(long)).toBe(false);
    expect(hasHandlerSignature(near)).toBe(false);
    expect(hasHandlerSignature(`${"(req: x<y<z,".repeat(150)}\n`)).toBe(false);
    expect(performance.now() - started).toBeLessThan(100);
    expect(hasHandlerSignature("export function h(_req: NextApiRequest, res: NextApiResponse) {}")).toBe(true);
    expect(hasHandlerSignature("function h(\n  request: FastifyRequest<{ Params: { id: string }; Body: B }, unknown>,\n  reply: FastifyReply,\n) {}")).toBe(true);
  });
});

// Fix round 4 (item 1): a message write anywhere in a repository makes every error class in it non-public, so each
// project-error-class case is scanned as its own repository (in the whole corpus the message-write TPs cover all).
describe("API-boundary project error classes — each case scanned as its own repository", () => {
  const PUBLIC_ERRORS = join(process.cwd(), "fixtures", "api-boundary-public-errors", "23-app-error-literal-message");
  const APP_ERROR_TPS = readdirSync(join(CORPUS, "tp")).filter((name) => name.includes("app-error")).sort();

  /** The public-error repository plus one more file. */
  const withExtraFile = async (source: string): Promise<Finding[]> => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-api-boundary-public-"));
    temporaryDirectories.push(directory);
    await cp(PUBLIC_ERRORS, directory, { recursive: true });
    await mkdir(join(directory, "lib"));
    await writeFile(join(directory, "lib", "unrelated.ts"), source);
    return runApiBoundaryChecks(directory);
  };

  test("literal-message classes stay public in a repository with no message write", async () => {
    expect(await runApiBoundaryChecks(PUBLIC_ERRORS)).toEqual([]);
    expect(await withExtraFile("export const note = 1;\n")).toEqual([]);
  });

  test.each(APP_ERROR_TPS)("tp/%s alone emits one client-error leak", async (name) => {
    const findings = await runApiBoundaryChecks(join(CORPUS, "tp", name));
    expect(findings.map((finding) => finding.rule_id)).toEqual([RULES.error]);
  });

  test.each([
    ["an assignment", "e.message = s;"],
    ["a compound assignment", "e.message += s;"],
    ["a nullish assignment", "e.message ??= s;"],
    ["a bracket compound assignment", "e[\"message\"] += s;"],
    ["an Object.defineProperties call", "Object.defineProperties(e, { message: { value: s } });"],
    ["a destructuring target", "({ message: e.message } = body);"],
    ["a write through a member of this", "this.cause.message = s;"],
    // Fix round 5: a `this` write outside any class body (a free function, a prototype method) counts.
    ["a this.message write outside a class body", "this.message = s;"],
    ["a this.message compound write outside a class body", "this.message += s;"],
  ])("%s in a file that never names a class makes every class non-public", async (_label, statement) => {
    const findings = await withExtraFile(
      `export function touch(this: { cause: { message: string } }, e: { message: string }, s: string, body: { message: string }) {\n  ${statement}\n}\n`,
    );
    expect(findings.filter((finding) => finding.rule_id === RULES.error)).toHaveLength(3);
  });

  test.each([
    ["a read into an object", "return { message: e.message };"],
    ["comparisons", "return e.message === s || e.message !== s || e.message >= s || e.message <= s;"],
    ["an arrow body", "return [e].map((x) => x.message);"],
  ])("%s is not a message write", async (_label, statement) => {
    const findings = await withExtraFile(
      `export function touch(this: { message: string }, e: { message: string }, s: string) {\n  ${statement}\n}\n`,
    );
    expect(findings).toEqual([]);
  });

  // Fix round 5: a `this` write inside a class body is that class's own business (checked by its own body).
  test("a this.message write inside another class body is not a repository-wide write", async () => {
    const findings = await withExtraFile(
      "export class Toast {\n  message = \"\";\n  show(s: string) {\n    this.message = s;\n    this[\"message\"] += s;\n  }\n}\n",
    );
    expect(findings).toEqual([]);
  });
});
