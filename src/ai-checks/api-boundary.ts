/**
 * Project CI Enhancement 1 — conservative JavaScript/TypeScript API-boundary checks.
 *
 * Four narrow, intrafile contracts:
 *   - client-visible internal error details (CWE-209)
 *   - explicit sensitive fields in API responses (CWE-201)
 *   - request objects written directly through common ORM/Supabase sinks (CWE-915)
 *   - sensitive values written to application logs (CWE-532)
 *
 * These checks deliberately prefer silence when intent or middleware is ambiguous. They
 * never claim generic response minimization, complete input validation, or runtime policy.
 */

import type { Finding } from "../types.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineOf } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const NON_PRODUCTION_DIRS = new Set([
  "__fixtures__", "__mocks__", "__tests__", "demo", "demos", "example", "examples",
  "fixture", "fixtures", "integration_test", "integration_tests", "sample", "samples",
  "test", "tests",
]);

const RESPONSE_CALL_RE =
  /\b(?:NextResponse|Response)\.json\s*\(|\b[A-Za-z_$][\w$]*(?:\.(?:status|code)\s*\([^)]*\))?\.(?:json|send)\s*\(|\bnew\s+Response\s*\(/g;
const WRITE_CALL_RE =
  /\b(?:prisma|prismaClient|db|database|tx)\.[A-Za-z_$][\w$]*\.(?:create|createMany|update|updateMany|upsert)\s*\(|\b[A-Za-z_$][\w$]*\.from\s*\([^)]*\)\s*\.(?:insert|update|upsert)\s*\(|\b(?:[A-Z][A-Za-z0-9_$]*(?:Model)?|[A-Za-z_$][\w$]*Model)\.(?:create|bulkCreate|insertMany|update|updateOne|updateMany|replaceOne|findByIdAndUpdate|findOneAndUpdate)\s*\(/g;
const LOG_CALL_RE =
  /\b(?:console|logger|log|pino|winston)(?:\.[A-Za-z_$][\w$]*)?\.(?:trace|debug|info|warn|error|log)\s*\(/g;

const WHOLE_REQUEST_SOURCE_RE =
  /\b(?:req|request)\.(?:body|query|params)\b(?!\s*(?:\.|\[))|\b(?:req|request)\.(?:json|text|formData)\s*\(|\b(?:ctx|context|c)\.req\.(?:json|text|parseBody)\s*\(/;
const VALIDATOR_RE =
  /\b(?:sanitize|validate|validator|allowlist|whitelist|pick|parseBody|cleanInput)\b|\.(?:safeParse(?:Async)?|parse(?:Async)?|validate(?:Async)?)\s*\(/i;
const PUBLIC_ERROR_MAPPER_RE =
  /\b(?:toPublicError|publicError|sanitizeError|safeError|mapPublicError|formatPublicError)\s*\(/i;
const AUTH_PAYMENT_PATH_RE =
  /(^|\/)(?:auth|login|signin|sign-in|signup|sign-up|password|reset|payment|payments|checkout|billing|webhook)(\/|[-_.])/i;

const SENSITIVE_FIELD_RE =
  /^(?:password|passwordhash|password_hash|passwd|token|access_?token|refresh_?token|session_?token|api_?key|private_?key|service_?role|client_?secret|authorization|cookie|credentials?|secret)$/i;
const SENSITIVE_IDENTIFIER_RE =
  /\b(?:password|passwordHash|password_hash|passwd|token|accessToken|access_token|refreshToken|refresh_token|sessionToken|session_token|apiKey|api_key|privateKey|private_key|serviceRole|service_role|clientSecret|client_secret|authorization|cookie|credentials|secret)\b/g;

interface CallMatch {
  args: string;
  index: number;
}

/** Project-root scans report deployable API behavior, not deliberately unsafe test/example code. */
function nonProductionProjectPath(rel: string): boolean {
  const segments = rel.split("/");
  if (segments.slice(0, -1).some((segment) => NON_PRODUCTION_DIRS.has(segment.toLowerCase()))) {
    return true;
  }
  const base = segments.at(-1)?.toLowerCase() ?? "";
  return /(?:^|[._-])(?:test|spec)(?:[._-]|$)/.test(base);
}

/** Replace comments with spaces while preserving offsets and line numbers. */
function maskComments(value: string): string {
  const chars = [...value];
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    const next = chars[index + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      else chars[index] = " ";
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        chars[index] = " ";
        chars[index + 1] = " ";
        blockComment = false;
        index++;
      } else if (char !== "\n") {
        chars[index] = " ";
      }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
    } else if (char === "/" && next === "/") {
      chars[index] = " ";
      chars[index + 1] = " ";
      lineComment = true;
      index++;
    } else if (char === "/" && next === "*") {
      chars[index] = " ";
      chars[index + 1] = " ";
      blockComment = true;
      index++;
    }
  }
  return chars.join("");
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Extract a balanced call argument list, ignoring brackets inside strings/comments. */
function extractCall(content: string, openParenIndex: number, maxChars = 12_000): string {
  let depth = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  const end = Math.min(content.length, openParenIndex + maxChars);

  for (let index = openParenIndex; index < end; index++) {
    const char = content[index]!;
    const next = content[index + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index++;
      }
      continue;
    }
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = undefined;
      }
      continue;
    }
    if (char === "/" && next === "/") {
      lineComment = true;
      index++;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index++;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(") depth++;
    if (char === ")" && --depth === 0) return content.slice(openParenIndex + 1, index);
  }
  return content.slice(openParenIndex + 1, end);
}

function callsFor(content: string, pattern: RegExp): CallMatch[] {
  const calls: CallMatch[] = [];
  const uncommented = maskComments(content);
  const searchable = maskStrings(uncommented);
  pattern.lastIndex = 0;
  for (const match of searchable.matchAll(pattern)) {
    const text = match[0] ?? "";
    const start = match.index ?? 0;
    const relativeOpen = text.lastIndexOf("(");
    if (relativeOpen < 0) continue;
    const open = start + relativeOpen;
    calls.push({ args: extractCall(uncommented, open), index: start });
  }
  return calls;
}

function firstTopLevelArg(args: string): string {
  let round = 0;
  let square = 0;
  let curly = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < args.length; index++) {
    const char = args[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(") round++;
    else if (char === ")") round--;
    else if (char === "[") square++;
    else if (char === "]") square--;
    else if (char === "{") curly++;
    else if (char === "}") curly--;
    else if (char === "," && round === 0 && square === 0 && curly === 0) return args.slice(0, index);
  }
  return args;
}

function catchVariables(content: string): Set<string> {
  const variables = new Set(["error", "err", "exception"]);
  for (const match of content.matchAll(/\bcatch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    if (match[1]) variables.add(match[1]);
  }
  let changed = true;
  let pass = 0;
  while (changed && pass++ < 4) {
    changed = false;
    for (const match of content.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g)) {
      const name = match[1];
      const rhs = match[2] ?? "";
      if (!name || variables.has(name)) continue;
      for (const variable of variables) {
        const escaped = escapeRe(variable);
        if (
          new RegExp(`\\b${escaped}\\s*\\.(?:message|stack|cause|details|query|sql|path)\\b`).test(rhs) ||
          new RegExp(`\\b(?:String|JSON\\.stringify)\\s*\\(\\s*${escaped}\\b`).test(rhs)
        ) {
          variables.add(name);
          changed = true;
          break;
        }
      }
    }
  }
  return variables;
}

function isMappedCustomPublicError(
  content: string,
  index: number,
  expression: string,
  errorVars: Set<string>,
): boolean {
  const windowStart = Math.max(0, index - 1_200);
  const preceding = content.slice(windowStart, index);
  for (const variable of errorVars) {
    const escaped = escapeRe(variable);
    const branch = new RegExp(
      `if\\s*\\(\\s*${escaped}\\s+instanceof\\s+((?!Error\\b)[A-Za-z_$][\\w$]*Error)\\s*\\)\\s*\\{`,
      "g",
    );
    for (const match of preceding.matchAll(branch)) {
      const errorClass = match[1] ?? "";
      const localOpen = (match.index ?? 0) + (match[0]?.lastIndexOf("{") ?? 0);
      const open = windowStart + localOpen;
      let depth = 0;
      let quote: "'" | '"' | "`" | undefined;
      let escapedChar = false;
      let lineComment = false;
      let blockComment = false;
      for (let cursor = open; cursor < index; cursor++) {
        const char = content[cursor]!;
        const next = content[cursor + 1];
        if (lineComment) {
          if (char === "\n") lineComment = false;
          continue;
        }
        if (blockComment) {
          if (char === "*" && next === "/") {
            blockComment = false;
            cursor++;
          }
          continue;
        }
        if (quote) {
          if (escapedChar) escapedChar = false;
          else if (char === "\\") escapedChar = true;
          else if (char === quote) quote = undefined;
          continue;
        }
        if (char === "/" && next === "/") {
          lineComment = true;
          cursor++;
        } else if (char === "/" && next === "*") {
          blockComment = true;
          cursor++;
        } else if (char === "'" || char === '"' || char === "`") {
          quote = char;
        } else if (char === "{") {
          depth++;
        } else if (char === "}") {
          depth--;
        }
      }
      if (depth > 0) {
        const rawObject = new RegExp(
          `(?:^|[{,])\\s*${escaped}\\s*(?=[,}])|\\b(?:error|details|debug)\\s*:\\s*${escaped}\\b(?=\\s*[,}])`,
          "i",
        ).test(maskStrings(expression));
        const internalDetail = new RegExp(
          `\\b${escaped}\\s*\\.(?:stack|cause|details|query|sql|path)\\b`,
        ).test(expression);
        const publicCodeAndMessage =
          new RegExp(`\\b${escaped}\\s*\\.code\\b`).test(expression) &&
          new RegExp(`\\b${escaped}\\s*\\.message\\b`).test(expression);
        const explicitlyPublicClass = /^(?:User|Public|Client|Validation|BadRequest)Error$/.test(errorClass);
        const publicClassMessage =
          explicitlyPublicClass && new RegExp(`\\b${escaped}\\s*\\.message\\b`).test(expression);
        if (!rawObject && !internalDetail && (publicCodeAndMessage || publicClassMessage)) return true;
      }
    }
  }
  return false;
}

function errorDetailsInResponse(expression: string, errorVars: Set<string>): boolean {
  if (PUBLIC_ERROR_MAPPER_RE.test(expression)) return false;
  const trimmed = expression.trim();
  for (const variable of errorVars) {
    const escaped = escapeRe(variable);
    if (new RegExp(`^${escaped}$`).test(trimmed)) return true;
    if (new RegExp(`\\b(?:String|JSON\\.stringify)\\s*\\(\\s*${escaped}\\b`).test(expression)) return true;
    if (new RegExp(`\\b${escaped}\\s*\\.(?:message|stack|cause|details|query|sql)\\b`).test(expression)) return true;
    if (new RegExp(`\\b(?:error|message|stack|details|debug|query|sql|path)\\s*:\\s*${escaped}\\b(?=\\s*[,}])`, "i").test(expression)) return true;
    if (new RegExp(`(?:^|[{,])\\s*${escaped}\\s*(?=[,}])`).test(maskStrings(expression))) return true;
    if (new RegExp(`\\$\\{\\s*${escaped}\\s*\\}|(?:\\+\\s*${escaped}\\b|\\b${escaped}\\s*\\+)`).test(expression)) return true;
  }
  return /\b(?:error|message|details|debug|query|sql|path)\s*:\s*["'`][^"'`]*(?:\b(?:select|insert|update|delete)\b[^"'`]*\b(?:from|into|set)\b|\/(?:Users|home|srv|var|app)\/|[A-Za-z]:\\\\|\b(?:SQLSTATE|ECONN\w*|PrismaClient\w*Error|Stripe\w*Error)\b|\bP\d{4}\b)[^"'`]*["'`]/i.test(expression);
}

function sensitiveResponseFields(expression: string): string[] {
  const fields = new Set<string>();
  const pairRe = /(?:^|[{,])\s*["']?([A-Za-z_$][\w$-]*)["']?\s*:\s*([^,}\n]+)/g;
  for (const match of expression.matchAll(pairRe)) {
    const key = match[1] ?? "";
    const value = (match[2] ?? "").trim();
    if (!SENSITIVE_FIELD_RE.test(key)) continue;
    if (/^(?:undefined|null|false|true|["'](?:\[?redacted\]?|masked|hidden)["'])$/i.test(value)) continue;
    if (/\b(?:Boolean|redact|mask|hash|fingerprint|scrub)\s*\(/i.test(value) || /^!!/.test(value)) continue;
    fields.add(key);
  }
  const shorthandRe = /(?:^|[{,])\s*([A-Za-z_$][\w$]*)\s*(?=[,}])/g;
  for (const match of maskStrings(expression).matchAll(shorthandRe)) {
    const key = match[1] ?? "";
    if (SENSITIVE_FIELD_RE.test(key)) fields.add(key);
  }
  return [...fields].sort();
}

function maskStrings(value: string): string {
  // Keep this linear. The prior backreference/lookahead regex could take tens of
  // seconds over a large TS/TSX repository after comment masking changed the
  // surrounding lexical shape. Mask code units in place so every later regex
  // retains the original offsets. An unterminated literal is masked to EOF:
  // malformed source must fail closed instead of exposing string text as code.
  const chars = value.split("");
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;

  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    if (!quote) {
      if (char === "'" || char === '"' || char === "`") {
        quote = char;
        chars[index] = " ";
      }
      continue;
    }

    chars[index] = " ";
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === quote) {
      quote = undefined;
    }
  }

  return chars.join("");
}

function isExplicitProjection(rhs: string, tainted: Set<string>): boolean {
  const trimmed = rhs.trim().replace(/^\(+|\)+$/g, "");
  if (!trimmed.startsWith("{") || !trimmed.includes("}")) return false;
  if (WHOLE_REQUEST_SOURCE_RE.test(trimmed)) return false;
  for (const variable of tainted) {
    const escaped = escapeRe(variable);
    if (new RegExp(`\\.\\.\\.\\s*${escaped}\\b`).test(trimmed)) return false;
    if (new RegExp(`(?:^|[{,])\\s*${escaped}\\s*(?:[,}])`).test(trimmed)) return false;
    if (new RegExp(`:\\s*${escaped}\\s*(?:[,}])`).test(trimmed)) return false;
  }
  return true;
}

function refsTainted(value: string, tainted: Set<string>, requireWholeObject = false): boolean {
  const unquoted = maskStrings(value);
  for (const variable of tainted) {
    const escaped = escapeRe(variable);
    const pattern = requireWholeObject
      ? new RegExp(`(?:\\.\\.\\.\\s*|:\\s*|[(,]\\s*|^)${escaped}\\b(?!\\s*\\.)`)
      : new RegExp(`\\b${escaped}\\b`);
    if (pattern.test(unquoted)) return true;
  }
  return false;
}

function requestTaint(content: string): Set<string> {
  const tainted = new Set<string>();
  const assignRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g;
  let changed = true;
  let pass = 0;
  while (changed && pass++ < 6) {
    changed = false;
    for (const match of content.matchAll(assignRe)) {
      const name = match[1];
      const rhs = match[2] ?? "";
      if (!name || VALIDATOR_RE.test(rhs) || isExplicitProjection(rhs, tainted)) continue;
      if (!WHOLE_REQUEST_SOURCE_RE.test(rhs) && !refsTainted(rhs, tainted, true)) continue;
      if (!tainted.has(name)) {
        tainted.add(name);
        changed = true;
      }
    }
  }
  return tainted;
}

function unvalidatedWrite(args: string, tainted: Set<string>): boolean {
  if (VALIDATOR_RE.test(args)) return false;
  if (WHOLE_REQUEST_SOURCE_RE.test(args)) return true;
  return refsTainted(args, tainted, true);
}

function sensitiveLogLabels(args: string, rel: string, tainted: Set<string>): string[] {
  const visibleArgs = args.replace(
    /\b(?:redact|mask|hash|fingerprint|scrub|omitSecrets)\s*\([^()]*\)/gi,
    (match) => " ".repeat(match.length),
  );
  const exposedArgs = visibleArgs
    .replace(/\bBoolean\s*\([^)]*\)/gi, (match) => " ".repeat(match.length))
    .replace(/!!\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/g, (match) => " ".repeat(match.length));
  const labels = new Set<string>();
  if (/\b(?:req|request)\.headers(?:\.get\s*\(\s*["']authorization["']\s*\)|\.authorization)\b/i.test(exposedArgs)) {
    labels.add("authorization");
  }
  if (/\b(?:req|request)\.headers\b/i.test(exposedArgs)) labels.add("request headers");
  if (/\b(?:req|request)\.cookies?\b/i.test(exposedArgs)) labels.add("cookies");

  let analyzable = maskStrings(exposedArgs)
    .replace(/\b[A-Za-z_$][\w$-]*\s*:/g, "");
  for (const match of analyzable.matchAll(SENSITIVE_IDENTIFIER_RE)) labels.add(match[0]);

  if (AUTH_PAYMENT_PATH_RE.test(rel)) {
    if (/\b(?:req|request)\.body\b|\b(?:req|request)\.(?:json|formData)\s*\(/.test(exposedArgs)) {
      labels.add("whole request body");
    } else if (refsTainted(analyzable, tainted, true)) {
      labels.add("whole request body");
    }
  }
  return [...labels].sort();
}

function errorFinding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-client-error-leak",
    title: "Internal error details returned to the client",
    severity: "high",
    cwe: ["CWE-209"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file,
    startLine: line,
    snippet: "Client response exposes internal error details [DETAILS REDACTED]",
    message:
      "A client-visible response includes a raw exception, stack trace, provider/database message, query detail, or internal path. Attackers can use these implementation details to refine further attacks.",
    remediation: {
      summary: "Return a stable generic error code/message to the client and keep diagnostic detail in protected server logs.",
      steps: [
        "Replace the response body with a generic public error code and message.",
        "Record the full exception only in protected server-side logs, with sensitive values redacted.",
        "Correlate the public response and private log with a non-sensitive request/error identifier.",
      ],
      references: ["CWE-209", "https://cwe.mitre.org/data/definitions/209.html"],
    },
    confidence: "medium",
  });
}

function responseFinding(file: string, line: number, fields: string[]): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-sensitive-api-response",
    title: "Sensitive field explicitly returned in an API response",
    severity: "high",
    cwe: ["CWE-201"],
    owasp_web: ["A01:2021"],
    owasp_api: ["API3:2023"],
    file,
    startLine: line,
    snippet: `API response includes sensitive field(s): ${fields.join(", ")} [VALUES REDACTED]`,
    message:
      "The API response explicitly includes password material, tokens, API keys, private credentials, or another sensitive field. Client-side filtering cannot protect data already sent over the API.",
    remediation: {
      summary: "Return an explicit response DTO containing only fields the caller is authorized to receive.",
      steps: [
        "Remove the sensitive fields from the response object.",
        "Project database/provider objects into an explicit public response schema.",
        "Add a response-schema test that fails if credential or password fields reappear.",
      ],
      references: ["CWE-201", "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
    },
    confidence: "medium",
  });
}

function writeFinding(file: string, line: number): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-unvalidated-request-write",
    title: "Unvalidated request object passed directly to a database write",
    severity: "high",
    cwe: ["CWE-915"],
    owasp_web: ["A01:2021"],
    owasp_api: ["API3:2023"],
    file,
    startLine: line,
    snippet: "Database write receives an unvalidated request object [REQUEST DATA REDACTED]",
    message:
      "A request-derived object reaches a common ORM/Supabase write sink without visible schema validation or explicit field projection. Attackers may submit privileged or internal fields the UI never exposes.",
    remediation: {
      summary: "Validate the request on the server and construct an allow-listed write object before calling the database.",
      steps: [
        "Parse the request with a server-side schema such as Zod or Joi.",
        "Construct the database write object from explicitly allowed fields.",
        "Enforce authorization separately for privileged fields such as role, owner, plan, or status.",
      ],
      references: ["CWE-915", "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
    },
    confidence: "medium",
  });
}

function logFinding(file: string, line: number, labels: string[]): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-sensitive-log",
    title: "Sensitive request data written to application logs",
    severity: labels.includes("whole request body") ? "medium" : "high",
    cwe: ["CWE-532"],
    owasp_web: ["A09:2021"],
    owasp_api: ["API8:2023"],
    file,
    startLine: line,
    snippet: `Logging call receives sensitive data: ${labels.join(", ")} [VALUES REDACTED]`,
    message:
      "A logging call receives credentials, tokens, cookies, authorization data, or a whole auth/payment request body. Logs commonly have broader access and longer retention than the source request.",
    remediation: {
      summary: "Remove sensitive values from logs; record only allow-listed operational metadata and non-reversible identifiers.",
      steps: [
        "Delete the sensitive argument or replace it with a boolean/presence signal.",
        "Use a structured logger redaction policy for headers, cookies, tokens, and password fields.",
        "Review existing retained logs and rotate credentials if a real secret may have been recorded.",
      ],
      references: ["CWE-532", "https://cwe.mitre.org/data/definitions/532.html"],
    },
    confidence: "medium",
  });
}

export async function runApiBoundaryChecks(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false });

  for (const file of files) {
    if (nonProductionProjectPath(file.rel)) continue;
    // Minified bundles/vendor artifacts are not auditable source and make regex
    // matches context-free. Build output is already excluded; cover the common
    // vendored `*.min.js` case explicitly as well.
    if (/\.min\.(?:js|mjs|cjs)$/i.test(file.rel)) continue;

    const content = maskComments(file.content);
    const errorVars = catchVariables(content);
    const tainted = requestTaint(content);

    for (const call of callsFor(content, RESPONSE_CALL_RE)) {
      const expression = firstTopLevelArg(call.args);
      const line = lineOf(content, call.index);
      if (!isMappedCustomPublicError(content, call.index, expression, errorVars) && errorDetailsInResponse(expression, errorVars)) {
        findings.push(errorFinding(file.rel, line));
      }
      const fields = sensitiveResponseFields(expression);
      if (fields.length) findings.push(responseFinding(file.rel, line, fields));
    }

    for (const call of callsFor(content, WRITE_CALL_RE)) {
      if (unvalidatedWrite(call.args, tainted)) {
        findings.push(writeFinding(file.rel, lineOf(content, call.index)));
      }
    }

    for (const call of callsFor(content, LOG_CALL_RE)) {
      const labels = sensitiveLogLabels(call.args, file.rel, tainted);
      if (labels.length) findings.push(logFinding(file.rel, lineOf(content, call.index), labels));
    }
  }

  return findings;
}
