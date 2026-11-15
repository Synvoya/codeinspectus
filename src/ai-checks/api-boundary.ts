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

import { maskCommentsFromParser } from "../packs/react-native/javascript-parse.js";
import type { Finding } from "../types.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineOf } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const NON_PRODUCTION_DIRS = new Set([
  "__fixtures__", "__mocks__", "__tests__", "demo", "demos", "example", "examples",
  "fixture", "fixtures", "integration_test", "integration_tests", "sample", "samples",
  "test", "tests",
  // 4.1 M9: Cypress suites. `e2e/` and `playwright/` stay analyzed (fix round 1): routing's contextFor reports
  // their findings at low severity instead of dropping them.
  "cypress",
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
  /** The matched call head, e.g. `res.status(500).json(`. */
  head: string;
}

/**
 * 4.1 M9: a server-handler file by path (`app/**\/route.*`, `pages/api/**`, a `server/` or `api/` folder), by
 * an import or require of a server framework, or by a handler signature (`(req, res)`, `(request, reply)`,
 * `(err, req, res, next)`, Hono's `(c)`).
 */
const SERVER_PATH_RE = /(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$|(?:^|\/)pages\/api\/|(?:^|\/)(?:server|api)\//;
const SERVER_IMPORT_RE =
  /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)["'](?:express|fastify|koa|@koa\/router|koa-router|hono|hono\/[\w/-]+|@nestjs\/[\w-]+|next|next\/server|h3|elysia)["']/;
// Every run is bounded and the runs do not overlap (security review: no catastrophic backtracking).
const HANDLER_SIGNATURE_RE = new RegExp([
  // (req, res), (_req, res), (request, reply), (err, req, res, next); a type may carry generic commas.
  String.raw`\(\s*(?:err\w{0,40}\s*(?::[^,()]{0,200})?,\s*)?_?req\w{0,40}\s*(?::\s*[^,()<]{0,200}(?:<[^()<>]{0,400}>[^,()<>]{0,200})?)?,\s*(?:res|resp|response|reply)\b`,
  // (err, res) error callbacks and middleware.
  String.raw`\(\s*err\w{0,40}\s*(?::[^,()]{0,200})?,\s*(?:res|resp|response|reply)\b`,
  // A parameter typed as a server response.
  String.raw`[(,]\s*_?\w{1,60}\s*:\s*(?:NextApiResponse|FastifyReply|Reply|Response)\b(?:<[^()<>]{0,200}>)?\s*[,)]`,
  // Hono's (c) / (c: Context).
  String.raw`\(\s*(?:c|ctx|context)\s*(?::\s*Context\b[^()]{0,200})?\)\s*=>`,
].join("|"));
/** Lines longer than this (minified or generated code) are not searched for a handler signature. */
const HANDLER_SIGNATURE_MAX_LINE = 2_000;

/** Whether the file declares a server handler signature; very long lines are skipped. */
export function hasHandlerSignature(content: string): boolean {
  const searchable = content.split("\n").map((line) => (line.length > HANDLER_SIGNATURE_MAX_LINE ? "" : line)).join("\n");
  return HANDLER_SIGNATURE_RE.test(searchable);
}
/** Receivers whose `.send(`/`.json(` never answers an HTTP request: sockets, channels, XHR, message ports. */
const NON_HTTP_RECEIVER_RE =
  /^(?:ws|wss|socket|websocket|webSocket|xhr|request|channel|connection|conn|postMessage|port|worker|peer|io|emitter|stream|transport|client)$/i;
const RESPONSE_RECEIVERS = new Set(["res", "resp", "response", "reply"]);
const CONTEXT_RECEIVERS = new Set(["c", "ctx", "context"]);

function serverHandlerFile(rel: string, content: string): boolean {
  return SERVER_PATH_RE.test(rel) || SERVER_IMPORT_RE.test(content) || hasHandlerSignature(content);
}

/**
 * 4.1 M9: whether a matched response call answers an HTTP request. Web/Next `Response` constructors always do;
 * a `.status(…)`/`.code(…)` chain does unless its receiver is a socket-like object; a bare `res`/`reply`/
 * `response` receiver, or Hono's `c.json`, only in a server-handler file. Any other receiver never does.
 */
function isServerResponse(head: string, serverFile: boolean): boolean {
  if (/^(?:NextResponse|Response)\.json\b|^new\s+Response\b/.test(head)) return true;
  const match = /^([A-Za-z_$][\w$]*)(\.(?:status|code)\s*\()?/.exec(head);
  const receiver = match?.[1] ?? "";
  if (!receiver || NON_HTTP_RECEIVER_RE.test(receiver)) return false;
  if (match?.[2]) return true;
  if (RESPONSE_RECEIVERS.has(receiver)) return serverFile;
  if (CONTEXT_RECEIVERS.has(receiver)) return serverFile && /\.json\s*\($/.test(head);
  return false;
}

/** Project-root scans report deployable API behavior, not deliberately unsafe test/example code. */
function nonProductionProjectPath(rel: string): boolean {
  const segments = rel.split("/");
  if (segments.slice(0, -1).some((segment) => NON_PRODUCTION_DIRS.has(segment.toLowerCase()))) {
    return true;
  }
  const base = segments.at(-1)?.toLowerCase() ?? "";
  return /(?:^|[._-])(?:test|spec)(?:[._-]|$)/.test(base) || /\.cy\.(?:[cm]?[jt]s|[jt]sx)$/.test(base);
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

/** `uncommented` is a file whose comments the caller already masked (parser ranges, else maskComments). */
function callsFor(uncommented: string, pattern: RegExp): CallMatch[] {
  const calls: CallMatch[] = [];
  const searchable = maskStrings(uncommented);
  pattern.lastIndex = 0;
  for (const match of searchable.matchAll(pattern)) {
    const text = match[0] ?? "";
    const start = match.index ?? 0;
    const relativeOpen = text.lastIndexOf("(");
    if (relativeOpen < 0) continue;
    const open = start + relativeOpen;
    calls.push({ args: extractCall(uncommented, open), index: start, head: text });
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

/** The branch body returns only a public projection of a typed error: `.message` with `.code`, or an explicitly public class. */
function publicTypedErrorProjection(
  expression: string,
  escaped: string,
  errorClass: string,
  publicClasses: ReadonlySet<string>,
): boolean {
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
  // 4.1 M9 (A4): or a class of this repository whose message is always a literal.
  const explicitlyPublicClass = /^(?:User|Public|Client|Validation|BadRequest)Error$/.test(errorClass) ||
    publicClasses.has(errorClass);
  const publicClassMessage =
    explicitlyPublicClass && new RegExp(`\\b${escaped}\\s*\\.message\\b`).test(expression);
  return !rawObject && !internalDetail && (publicCodeAndMessage || publicClassMessage);
}

function isMappedCustomPublicError(
  content: string,
  index: number,
  expression: string,
  errorVars: Set<string>,
  publicClasses: ReadonlySet<string> = new Set(),
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
      if (depth > 0 && publicTypedErrorProjection(expression, escaped, errorClass, publicClasses)) return true;
    }
    // 4.1 M9 (A1): the brace-less form `if (err instanceof XError) return <response>;` with the same checks.
    // The response must be the branch's own statement: only `return` (and `await`) between the condition
    // and the call, so a branch that does something else does not cover a later response.
    const braceless = new RegExp(
      `if\\s*\\(\\s*${escaped}\\s+instanceof\\s+((?!Error\\b)[A-Za-z_$][\\w$]*Error)\\s*\\)(\\s*(?:return\\s+(?:await\\s+)?)?)$`,
    );
    const tail = braceless.exec(preceding);
    if (tail && publicTypedErrorProjection(expression, escaped, tail[1] ?? "", publicClasses)) return true;
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

/**
 * 4.1 M9: a credential the handler itself just issued to the caller (a new session or API token, a signing
 * secret shown once). Password material, private keys, client secrets, service-role keys, authorization
 * headers and cookies are never "issued" and always count.
 */
const ISSUABLE_FIELD_RE =
  /^(?:token|access_?token|refresh_?token|session_?token|api_?key|credentials?|secret)$/i;
/** Generator calls: `jwt.sign`, `sign*`, `randomBytes`, `randomUUID`, `nanoid`, `generate*Token`, `create*Token`, `generateKey`. */
const GENERATOR_CALL = String.raw`(?:[A-Za-z_$][\w$]*\.)*(?:sign(?:[A-Z][\w$]*)?|randomBytes|randomUUID|nanoid|generate[A-Z][\w$]*Token|create[A-Z][\w$]*Token|generateKey)\s*\(`;
// 4.1 M9 (A1): session and id creators (`createSession`, `create*Session`, `newId`, `new*Id`).
const SESSION_GENERATOR_CALL = String.raw`(?:[A-Za-z_$][\w$]*\.)*(?:create(?:[A-Z][\w$]*)?Session|newId|new[A-Z][\w$]*Id)\s*\(`;
const GENERATOR_VALUE = String.raw`(?:await\s+)?(?:${GENERATOR_CALL}|${SESSION_GENERATOR_CALL}|new\s+SignJWT\b[^;]*\.sign\s*\(|\`[^\`]*\$\{\s*(?:${GENERATOR_CALL}|${SESSION_GENERATOR_CALL}))`;
const GENERATOR_VALUE_RE = new RegExp(`^${GENERATOR_VALUE}`);
/** `cond ? <generator>(…) : null` or `cond ? null : <generator>(…)`: issued or nothing. */
const CONDITIONAL_GENERATOR_RE = new RegExp(
  String.raw`^[^?;\n]+\?\s*(?:${GENERATOR_VALUE}[^;:?\n]*:\s*(?:null|undefined)|(?:null|undefined)\s*:\s*${GENERATOR_VALUE}[^;:?\n]*)\s*(?:;|\n|$)`,
);

/**
 * Whether `name`, read at `index`, holds a credential generated in the same scope: its last assignment before
 * `index` is a generator call, and that assignment's block still encloses `index` (a reassignment, or an
 * assignment in a block that has closed, does not count).
 */
/** Keywords whose `(…) {` block is a statement, not a function body. */
const BLOCK_STATEMENT_RE = /(?:^|[^\w$.])(?:if|for|while|switch|catch|with)\s*$/;

/**
 * The `{` that opens the innermost function body enclosing `index` in string-masked text, or -1 at module scope.
 * A function body is a `{` after `=>`, or after a parameter list `)` (optionally with a return type) that does not
 * belong to `if`/`for`/`while`/`switch`/`catch`.
 */
function enclosingFunctionOpen(masked: string, index: number): number {
  let depth = 0;
  for (let cursor = index - 1; cursor >= 0; cursor--) {
    const char = masked[cursor];
    if (char === "}") depth++;
    else if (char === "{") {
      if (depth > 0) {
        depth--;
        continue;
      }
      const before = masked.slice(Math.max(0, cursor - 400), cursor).replace(/\s+$/, "");
      if (/=>$/.test(before)) return cursor;
      // `) {` or `): Type {` — find the matching `(` and look at the word before it.
      const typed = /\)\s*:\s*[^(){};=]*$/.exec(before);
      const closeAt = typed ? typed.index : before.endsWith(")") ? before.length - 1 : -1;
      if (closeAt >= 0) {
        let parens = 0;
        let openAt = -1;
        for (let scan = closeAt; scan >= 0; scan--) {
          if (before[scan] === ")") parens++;
          else if (before[scan] === "(" && --parens === 0) {
            openAt = scan;
            break;
          }
        }
        if (openAt >= 0 && !BLOCK_STATEMENT_RE.test(before.slice(0, openAt))) return cursor;
      }
    }
  }
  return -1;
}

/**
 * Fix round 3: whether every occurrence of `name` in the response expression is a top-level field of the response
 * object literal: a shorthand `{ name }`, a key `name:` or a value `key: name`. An expression that is not an
 * object literal, any other occurrence, or a top-level spread (fix round 4) or computed key (fix round 5) after the
 * field, fails closed.
 */
function onlyTopLevelField(expression: string, name: string): boolean {
  const masked = maskStrings(expression);
  const start = masked.search(/\S/);
  if (start < 0 || masked[start] !== "{") return false;
  const depthAt: number[] = new Array(masked.length).fill(0);
  let depth = 0;
  for (let index = 0; index < masked.length; index++) {
    const char = masked[index]!;
    if (char === "{" || char === "(" || char === "[") depthAt[index] = ++depth;
    else if (char === "}" || char === ")" || char === "]") depthAt[index] = depth--;
    else depthAt[index] = depth;
  }
  // A top-level conditional spread of the field itself, `...(name ? { name } : {})`, adds it as a top-level field.
  const allowed = new Set<number>();
  const selfSpreads = new Set<number>();
  const escaped = escapeRe(name);
  for (const spread of masked.matchAll(new RegExp(String.raw`\.\.\.\s*\(\s*${escaped}\s*\?\s*\{\s*${escaped}\s*\}\s*:\s*\{\s*\}\s*\)`, "g"))) {
    const at = spread.index ?? 0;
    if (depthAt[at] !== 1) continue;
    selfSpreads.add(at);
    for (const inner of spread[0].matchAll(new RegExp(String.raw`(?<![\w$.])${escaped}(?![\w$])`, "g"))) allowed.add(at + (inner.index ?? 0));
  }
  const occurrences = [...masked.matchAll(new RegExp(String.raw`(?<![\w$.])${escaped}(?![\w$])`, "g"))];
  if (!occurrences.length) return false;
  // Fix round 4: a later top-level spread wins over the field (`{ token, ...user }` returns `user.token`); only the
  // self-spread above may follow it.
  const first = occurrences[0]!.index ?? 0;
  for (const spread of masked.matchAll(/\.\.\./g)) {
    const at = spread.index ?? 0;
    if (at > first && depthAt[at] === 1 && !selfSpreads.has(at)) return false;
  }
  // Fix round 5: so does a later top-level computed key (`{ token, ["token"]: user.token }`).
  for (const bracket of masked.matchAll(/[{,]\s*\[/g)) {
    const at = (bracket.index ?? 0) + bracket[0].length - 1;
    if (at > first && depthAt[at] === 2 && depthAt[bracket.index ?? 0]! <= 1) return false;
  }
  return occurrences.every((match) => {
    const at = match.index ?? 0;
    if (allowed.has(at)) return true;
    if (depthAt[at] !== 1 || at < start) return false;
    const before = masked.slice(0, at).replace(/\s+$/, "").at(-1);
    const after = masked.slice(at + name.length).replace(/^\s+/, "")[0];
    if ((before === "{" || before === ",") && (after === "," || after === "}" || after === ":")) return true;
    return before === ":" && (after === "," || after === "}");
  });
}

/**
 * Whether `name`, read at `index`, holds a credential generated for this response: its last assignment before
 * `index` is a generator call made in the same function as the response, in a block that still encloses it, and
 * nothing rewrites or shadows the name in between (a destructuring write, `??=`/`||=`/`&&=` or other compound
 * assignment, or a parameter of the same name).
 */
function issuedInScope(content: string, index: number, name: string, responseExpression = ""): boolean {
  const masked = maskStrings(content.slice(0, index));
  const escaped = escapeRe(name);
  const assignRe = new RegExp(String.raw`(?:\b(?:const|let|var)\s+)?(?<![\w$.])${escaped}\s*=(?![=>])`, "g");
  let last: RegExpExecArray | undefined;
  for (const match of masked.matchAll(assignRe)) last = match as RegExpExecArray;
  if (!last) return false;
  const rhsStart = (last.index ?? 0) + last[0].length;
  const rhs = content.slice(rhsStart, Math.min(index, rhsStart + 600)).trimStart();
  if (!GENERATOR_VALUE_RE.test(rhs) && !CONDITIONAL_GENERATOR_RE.test(rhs)) return false;
  let depth = 0;
  for (let cursor = rhsStart; cursor < masked.length; cursor++) {
    const char = masked[cursor];
    if (char === "{") depth++;
    else if (char === "}" && --depth < 0) return false;
  }
  // Fix round 1: the same function, and no rewrite or shadowing in between.
  const fn = enclosingFunctionOpen(masked, index);
  if (fn < 0 || enclosingFunctionOpen(masked, last.index ?? 0) !== fn) return false;
  const between = masked.slice(rhsStart, index);
  const rewrite = new RegExp(String.raw`(?<![\w$.])${escaped}\s*(?:\?\?|\|\||&&|\*\*|<<|>>>?|[-+*/%&|^])=`);
  const destructure = new RegExp(String.raw`[{\[][^;{}\[\]]*(?<![\w$.])${escaped}\b[^;{}\[\]]*[}\]]\s*=(?![=>])`);
  // A same-name binding: a parameter (plain or destructured), a catch binding or a loop variable.
  const parameter = new RegExp(
    String.raw`\([^()]*(?<![\w$.])${escaped}\b[^()]*\)\s*(?::[^=;{]*)?=>|(?<![\w$.])${escaped}\s*=>|\bfunction\b[^(]*\([^)]*(?<![\w$.])${escaped}\b[^)]*\)|\bcatch\s*\(\s*${escaped}\s*\)` +
    // Fix round 3: a bare `for (token of …)` reassignment and a destructured `catch ({ token })` also rebind it.
    String.raw`|\bfor\s*\(\s*(?:(?:const|let|var)\s+)?(?:\{[^{}]*(?<![\w$.])${escaped}\b[^{}]*\}|\[[^\[\]]*(?<![\w$.])${escaped}\b[^\[\]]*\]|${escaped})\s+(?:of|in)\b` +
    String.raw`|\bcatch\s*\(\s*[{\[][^)]*(?<![\w$.])${escaped}\b[^)]*\)`,
  );
  // Fix round 3: the issued name may appear in the response only as a top-level field of the response object
  // (`{ token }`, `{ token: token }`); any other use (a callback, a nested object, a default, an argument) is not it.
  if (!onlyTopLevelField(responseExpression, name)) return false;
  return !rewrite.test(between) && !destructure.test(between) && !parameter.test(between);
}

/**
 * Response properties that hold an identifier or receipt, not the record a nested call builds. Fix round 4: not
 * `url`/`*Url`, which can carry the credential its call is built from (`resetUrl: buildUrl({ token })`).
 */
const RECEIPT_PROPERTY_RE = /^(?:id|count|status)$|(?:Id|ID|_id|Count|Status)$/;

/** Calls whose arguments become the response: serialisers and object merges. */
const TRANSPARENT_CALL_RE = /(?:^|[^\w$.])(?:JSON\.stringify|Object\.assign|structuredClone)\s*$/;

/**
 * 4.1 M9 (A1): the response's own fields. Blank the argument lists of nested calls (a credential passed into
 * `grant({ sessionToken })` is consumed, not returned), except serialisers and object merges, and callbacks
 * (an argument with `=>` builds the returned value). Blank a destructuring pattern `{ token, ...rest }` whose
 * rest is spread elsewhere in the expression (the named keys are removed, not returned). Offsets are kept.
 */
function responseFieldView(expression: string): string {
  const masked = maskStrings(expression);
  const out = expression.split("");
  const pairs = new Map<number, number>();
  const stack: number[] = [];
  for (let index = 0; index < masked.length; index++) {
    if (masked[index] === "(") stack.push(index);
    else if (masked[index] === ")" && stack.length) pairs.set(stack.pop()!, index);
  }
  for (let index = 0; index < masked.length; index++) {
    const close = pairs.get(index);
    if (close === undefined) continue;
    const before = masked.slice(Math.max(0, index - 200), index);
    const isCall = /[\w$)\]]\s*$/.test(before) && !/(?:^|[^\w$])(?:if|for|while|switch|catch|return|typeof|await|in|of)\s*$/.test(before);
    if (!isCall || TRANSPARENT_CALL_RE.test(before) || masked.slice(index, close).includes("=>")) continue;
    // Fix round 1: only a call that is the value of a non-sensitive property (`grantId: await grant({...})`) consumes
    // its arguments. A call that is the whole response, an array element or a spread returns them.
    const windowStart = Math.max(0, index - 200);
    const property = new RegExp(String.raw`${windowStart === 0 ? "(?:^|[{,])" : "[{,]"}\s*["']?([A-Za-z_$][\w$-]*)["']?\s*:\s*(?:await\s+)?[A-Za-z_$][\w$.]*\s*$`)
      .exec(expression.slice(windowStart, index));
    // Fix round 3: only an id/receipt-shaped property (`elevationId: await grant({ … })`) consumes its call's
    // arguments; any other property (`data`, `profile`, …) returns what the call wraps.
    if (!property || !RECEIPT_PROPERTY_RE.test(property[1] ?? "")) continue;
    for (let cursor = index + 1; cursor < close; cursor++) if (out[cursor] !== "\n") out[cursor] = " ";
    index = close;
  }
  const view = out.join("");
  const viewMasked = maskStrings(view);
  return view.replace(/\{([^{}]*)\.\.\.\s*([A-Za-z_$][\w$]*)\s*\}(?=\s*(?::[^)=]*)?\)\s*=>|\s*=(?![=>]))/g, (match, _keys, rest: string, offset: number) => {
    const spread = new RegExp(`\\.\\.\\.\\s*${escapeRe(rest)}\\b`, "g");
    const elsewhere = [...viewMasked.matchAll(spread)].some((m) => (m.index ?? 0) < offset || (m.index ?? 0) >= offset + match.length);
    return elsewhere ? match.replace(/[^\n]/g, " ") : match;
  });
}

function sensitiveResponseFields(rawExpression: string, issued: (name: string) => boolean = () => false): string[] {
  const fields = new Set<string>();
  const expression = responseFieldView(rawExpression);
  const pairRe = /(?:^|[{,])\s*["']?([A-Za-z_$][\w$-]*)["']?\s*:\s*([^,}\n]+)/g;
  for (const match of expression.matchAll(pairRe)) {
    const key = match[1] ?? "";
    const value = (match[2] ?? "").trim();
    if (!SENSITIVE_FIELD_RE.test(key)) continue;
    if (/^(?:undefined|null|false|true|["'](?:\[?redacted\]?|masked|hidden)["'])$/i.test(value)) continue;
    if (/\b(?:Boolean|redact|mask|hash|fingerprint|scrub)\s*\(/i.test(value) || /^!!/.test(value)) continue;
    if (ISSUABLE_FIELD_RE.test(key) && (GENERATOR_VALUE_RE.test(value) || (/^[A-Za-z_$][\w$]*$/.test(value) && issued(value)))) continue;
    fields.add(key);
  }
  const shorthandRe = /(?:^|[{,])\s*([A-Za-z_$][\w$]*)\s*(?=[,}])/g;
  for (const match of maskStrings(expression).matchAll(shorthandRe)) {
    const key = match[1] ?? "";
    if (!SENSITIVE_FIELD_RE.test(key)) continue;
    if (ISSUABLE_FIELD_RE.test(key) && issued(key)) continue;
    fields.add(key);
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

/**
 * Mask string text but keep template substitutions (`${value}`) visible: a substituted value is logged.
 * Offsets are preserved; an unterminated literal is masked to EOF.
 */
function maskStringsKeepSubstitutions(value: string): string {
  const chars = value.split("");
  // Stack of open contexts: a quote character, or "${" for a substitution inside a template.
  const stack: string[] = [];
  let escaped = false;
  const depth: number[] = [];
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    const top = stack.at(-1);
    if (top === undefined || top === "${") {
      if (top === "${") {
        if (char === "{") depth[depth.length - 1]!++;
        else if (char === "}" && --depth[depth.length - 1]! < 0) {
          stack.pop();
          depth.pop();
          chars[index] = " ";
          continue;
        }
      }
      if (char === "'" || char === '"' || char === "`") {
        stack.push(char);
        chars[index] = " ";
      }
      continue;
    }
    chars[index] = " ";
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (top === "`" && char === "$" && chars[index + 1] !== undefined && value[index + 1] === "{") {
      chars[index + 1] = " ";
      index++;
      stack.push("${");
      depth.push(0);
    } else if (char === top) {
      stack.pop();
    }
  }
  return chars.join("");
}

/**
 * 4.1 M9 (fix round 1): a member read on a sensitive name logs metadata only for this allow-list (`token.length`,
 * `token.expiresAt`); any other member (`token.value`, `password.slice(0)`, `credentials.secretAccessKey`) counts.
 */
const METADATA_MEMBER_RE = /^\s*(?:\?\.|\.)\s*(?:length|expiresAt|exp|type|id|size|count)\b(?!\s*\()/;


function sensitiveLogLabels(args: string, rel: string, tainted: Set<string>): string[] {
  const visibleArgs = args.replace(
    /\b(?:redact|mask|hash|fingerprint|scrub|omitSecrets)\s*\([^()]*\)/gi,
    (match) => " ".repeat(match.length),
  );
  const exposedArgs = visibleArgs
    .replace(/\bBoolean\s*\([^)]*\)/gi, (match) => " ".repeat(match.length))
    .replace(/!!\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/g, (match) => " ".repeat(match.length));
  const labels = new Set<string>();
  if (/\b(?:req|request)\.headers(?:\.get\s*\(\s*["']authorization["']\s*\)|\.authorization\b|\[\s*["']authorization["']\s*\])/i.test(exposedArgs)) {
    labels.add("authorization");
  }
  if (/\b(?:req|request)\.headers(?:\.get\s*\(\s*["']cookie["']\s*\)|\.cookie\b|\[\s*["']cookie["']\s*\])/i.test(exposedArgs)) {
    labels.add("cookies");
  }
  // Fix round 1: any other header whose name says it carries a credential (x-api-key, x-auth-token, x-session-id).
  for (const match of exposedArgs.matchAll(/\b(?:req|request)\.headers(?:\.get\s*\(\s*["']([^"']+)["']\s*\)|\[\s*["']([^"']+)["']\s*\]|\.([A-Za-z_$][\w$]*))/gi)) {
    const header = (match[1] ?? match[2] ?? match[3] ?? "").toLowerCase();
    if (header === "authorization" || header === "cookie" || header === "get") continue;
    if (/auth|token|key|secret|session|cookie|password|signature/.test(header)) labels.add("sensitive header");
  }
  // 4.1 M9: the whole headers object, not one named header such as content-type or origin.
  if (/\b(?:req|request)\.headers\b(?!\s*(?:\??\.|\[))/i.test(exposedArgs)) labels.add("request headers");
  if (/\b(?:req|request)\.cookies?\b/i.test(exposedArgs)) labels.add("cookies");

  let analyzable = maskStringsKeepSubstitutions(exposedArgs)
    .replace(/\b[A-Za-z_$][\w$-]*\s*:/g, (match) => " ".repeat(match.length));
  for (const match of analyzable.matchAll(SENSITIVE_IDENTIFIER_RE)) {
    const start = match.index ?? 0;
    const after = analyzable.slice(start + match[0].length);
    // 4.1 M9: only a logged value counts: not `typeof token`, not a member read such as `token.length`.
    if (/\btypeof\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)*$/.test(analyzable.slice(0, start))) continue;
    if (METADATA_MEMBER_RE.test(after)) continue;
    labels.add(match[0]);
  }

  if (AUTH_PAYMENT_PATH_RE.test(rel)) {
    // 4.1 M9: the whole request body, not one field of it such as `req.body.amount`.
    if (/\b(?:req|request)\.body\b(?!\s*(?:\??\.|\[))|\b(?:req|request)\.(?:json|formData)\s*\(/.test(exposedArgs)) {
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
    severity: "low", // 4.1 M9 fresh-set gate: P_cap 0.67 (Ruling 3)
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
    confidence: "low",
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

/** A string literal or a template literal without substitutions: a fixed message. */
const LITERAL_MESSAGE_RE = /^\s*(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`)\s*$/;

/** Split a call's argument text at top-level commas. */
function topLevelArgs(args: string): string[] {
  const parts: string[] = [];
  let rest = args;
  while (rest.trim()) {
    const first = firstTopLevelArg(rest);
    parts.push(first);
    if (first.length >= rest.length) break;
    rest = rest.slice(first.length + 1);
  }
  return parts;
}

/**
 * 4.1 M9 (A4): error classes declared in the scanned repository (`class XError extends Error`) whose message
 * is always a literal: the class body's `super(...)` passes a literal (or nothing), or passes a constructor
 * parameter (or there is no constructor) and every `new XError(...)` site in the repository passes a literal
 * at that position. A class declared twice, or assigning `this.message` from anything else, is never public.
 */
/**
 * Fix round 4: a write to an error's `message` after construction, on any receiver but `this` (the class body is
 * checked by `ownMessageFixed`): a plain or compound assignment (`err.message = …`, `err.message += …`, `??=`,
 * `||=` …) in dot or bracket form (`err["message"] = …`), `Object.assign(…)` or `Object.defineProperties(…)` whose
 * arguments mention `message`, `Object.defineProperty`/`Reflect.set`/`Reflect.defineProperty` on `"message"`, and
 * a `.message` used as a destructuring assignment target (`({ message: e.message } = body)`).
 * Known limits: a computed key held in a variable (`err[key] = …` with `key = "message"`), a `.message` target
 * inside a nested or array destructuring pattern, and writes in files this pass does not collect (for example
 * `.vue` single-file components) are not detected.
 */
const MESSAGE_ASSIGN_OP = String.raw`(?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|\|\||&&)?=(?![=>])`;
const MESSAGE_WRITE_RE = new RegExp(String.raw`\.\s*message\s*${MESSAGE_ASSIGN_OP}`, "g");
const MESSAGE_INDEX_WRITE_RE = new RegExp(String.raw`\[\s*["'\`]message["'\`]\s*\]\s*${MESSAGE_ASSIGN_OP}`, "g");
/** The receiver before a `.message`/`["message"]` write is `this` (or `this?`). */
const THIS_RECEIVER_RE = /(?<![\w$.])this\s*(?:\?\s*)?$/;
/** Fix round 5: a write to `this.message` or `this["message"]` with any assignment operator (class-body check). */
const THIS_MESSAGE_WRITE_RE = new RegExp(String.raw`\bthis\s*(?:\?\s*)?\.\s*message\s*${MESSAGE_ASSIGN_OP}`);
const THIS_MESSAGE_INDEX_WRITE_RE = new RegExp(String.raw`\bthis\s*(?:\?\.\s*)?\[\s*["'\`]message["'\`]\s*\]\s*${MESSAGE_ASSIGN_OP}`);
/** `Object.defineProperty(…, "message", …)` or `Reflect.set(…, "message", …)`, quotes of any kind. */
const MESSAGE_PROPERTY_CALL_RE = /\b(?:Object\.defineProperty|Reflect\.set|Reflect\.defineProperty)\s*\([^;]*?,\s*["'`]message["'`]/;
/** A flat object pattern with a `.message` target, followed by an assignment: `({ message: e.message } = body)`. */
const MESSAGE_DESTRUCTURE_RE = /\{[^;{}()]*:\s*[\w$.]+\.message\s*(?:,[^;{}()]*)?\}\s*=(?![=>])/;

/**
 * Fix round 5: the `{ … }` body ranges of every `class` in a masked view. A head the pattern does not read
 * (`class A extends mixin(B) {`) yields no range, so its `this` writes count (fail closed).
 */
function classBodies(view: string): Array<[number, number]> {
  const bodies: Array<[number, number]> = [];
  for (const match of view.matchAll(/(?<![\w$.])class\b[^{};=()]*\{/g)) {
    const open = (match.index ?? 0) + match[0].length - 1;
    let depth = 0;
    for (let index = open; index < view.length; index++) {
      if (view[index] === "{") depth++;
      else if (view[index] === "}" && --depth === 0) {
        bodies.push([open, index]);
        break;
      }
    }
  }
  return bodies;
}

/**
 * Whether this file writes any error's `message` after construction (see `MESSAGE_WRITE_RE`). Fix round 5: a
 * `this` receiver is exempt only inside a class body, which `ownMessageFixed` checks for that class; a `this` write
 * anywhere else (a prototype method, a free function, an object method) counts.
 */
function writesMessage(content: string): boolean {
  if (!content.includes("message")) return false;
  const uncommented = maskComments(content);
  // Fail closed: test the comment-masked view (an apostrophe in a comment cannot hide code) and the plain view (so
  // a mis-lexed comment cannot hide code either; a commented-out write counts). Each view keeps its text's offsets.
  const pairs: Array<[string, string]> = [[maskStringsKeepSubstitutions(uncommented), uncommented], [maskStrings(content), content]];
  for (const [view, text] of pairs) {
    const bodies = classBodies(view);
    const exempt = (match: RegExpMatchArray): boolean => {
      const at = match.index ?? 0;
      return THIS_RECEIVER_RE.test(view.slice(Math.max(0, at - 40), at)) && bodies.some(([open, close]) => at > open && at < close);
    };
    if ([...view.matchAll(MESSAGE_WRITE_RE)].some((match) => !exempt(match))) return true;
    if (MESSAGE_DESTRUCTURE_RE.test(view)) return true;
    if ([...text.matchAll(MESSAGE_INDEX_WRITE_RE)].some((match) => !exempt(match))) return true;
    if (MESSAGE_PROPERTY_CALL_RE.test(text)) return true;
  }
  const masked = maskStrings(uncommented);
  for (const match of masked.matchAll(/\bObject\.(?:assign|defineProperties)\s*\(/g)) {
    const args = extractCall(uncommented, (match.index ?? 0) + match[0].length - 1);
    if (/\bmessage\b/.test(args)) return true;
  }
  return false;
}

function literalMessageErrorClasses(files: ReadonlyArray<{ content: string }>): Set<string> {
  // Every `class X extends Y` in the repository (body and parent), and every `new X(...)` site's arguments.
  const declarations = new Map<string, Array<{ parent: string; rawParent: string; body: string }>>();
  const sites = new Map<string, string[][]>();
  for (const { content } of files) {
    // Fix round 4: a message write in any file of the repository, whether or not it names a class (a helper such
    // as `withContext(e, ctx)` cannot be tied to one), makes every error class in the repository non-public.
    if (writesMessage(content)) return new Set();
    if (!content.includes("Error")) continue;
    const masked = maskStrings(content);
    for (const match of masked.matchAll(/\bclass\s+([A-Za-z_$][\w$]*)\s+extends\s+([A-Za-z_$][\w$.]*)\s*(?:<[^{]*>)?\s*\{/g)) {
      const open = (match.index ?? 0) + match[0].length - 1;
      let depth = 0;
      let close = -1;
      for (let index = open; index < masked.length; index++) {
        if (masked[index] === "{") depth++;
        else if (masked[index] === "}" && --depth === 0) {
          close = index;
          break;
        }
      }
      if (close < 0) continue;
      const list = declarations.get(match[1]!) ?? [];
      // Fix round 2: a parent named through a namespace import (`errors.QuotaError`) is keyed by its last segment.
      list.push({ parent: match[2]!.split(".").at(-1)!, rawParent: match[2]!, body: content.slice(open + 1, close) });
      declarations.set(match[1]!, list);
    }
    for (const site of masked.matchAll(/\bnew\s+([A-Za-z_$][\w$]*)\s*\(/g)) {
      if (!declarations.has(site[1]!) && !/Error$/.test(site[1]!)) continue;
      const list = sites.get(site[1]!) ?? [];
      list.push(topLevelArgs(extractCall(content, (site.index ?? 0) + site[0].length - 1)));
      sites.set(site[1]!, list);
    }
  }

  /** The class's own message is always a literal (its constructor, field and construction sites). */
  const ownMessageFixed = (name: string): boolean => {
    const list = declarations.get(name);
    if (!list || list.length !== 1) return false;
    const body = list[0]!.body;
    const maskedBody = maskStrings(body);
    const ctor = /\bconstructor\s*\(/.exec(maskedBody);
    const ctorParams = ctor ? extractCall(maskedBody, ctor.index + ctor[0].length - 1) : "";
    // Fix round 1: a TypeScript parameter property named `message` overrides it with the argument.
    if (/(?:^|,)\s*(?:(?:public|private|protected|readonly|override)\s+)+message\b/.test(ctorParams)) return false;
    // The message is overridden: assigned, declared as a field, or a getter (constructor parameters aside).
    const fieldsView = ctor
      ? maskedBody.slice(0, ctor.index + ctor[0].length) + " ".repeat(ctorParams.length) + maskedBody.slice(ctor.index + ctor[0].length + ctorParams.length)
      : maskedBody;
    if (/\bget\s+message\s*\(|^\s*(?:(?:override|readonly|public|declare)\s+)*message\s*[:=](?!=)/m.test(fieldsView)) return false;
    // Fix round 5: any write to `this.message` in the body (`=`, `+=`, `??=` …, or `this["message"]`).
    if (THIS_MESSAGE_WRITE_RE.test(fieldsView) || THIS_MESSAGE_INDEX_WRITE_RE.test(body)) return false;
    // Which constructor argument becomes the message (-1: none, it is fixed).
    let messageArg = 0;
    if (ctor) {
      const params = topLevelArgs(extractCall(body, ctor.index + ctor[0].length - 1))
        .map((param) => /^\s*(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)/.exec(param)?.[1] ?? "");
      const superCall = /\bsuper\s*\(/.exec(maskedBody);
      if (!superCall) return false;
      const first = topLevelArgs(extractCall(body, superCall.index + superCall[0].length - 1))[0]?.trim() ?? "";
      if (first === "" || LITERAL_MESSAGE_RE.test(first)) messageArg = -1;
      else if (params.includes(first)) messageArg = params.indexOf(first);
      else return false;
    }
    return messageArg < 0 || (sites.get(name) ?? []).every((args) => {
      const value = args[messageArg];
      return value === undefined || LITERAL_MESSAGE_RE.test(value);
    });
  };

  // Fix round 1: `instanceof X` also catches every subclass, so X is public only when every repository class
  // descending from it also has a literal message.
  const children = new Map<string, string[]>();
  for (const [name, list] of declarations) {
    for (const { parent } of list) children.set(parent, [...(children.get(parent) ?? []), name]);
  }
  const publicClasses = new Set<string>();
  for (const [name, list] of declarations) {
    // Fix round 3: only the built-in `Error` (or `globalThis.Error`) is a root; `lib.Error` is a library class.
    if (!/Error$/.test(name) || list.length !== 1 || !["Error", "globalThis.Error"].includes(list[0]!.rawParent)) continue;
    const seen = new Set<string>();
    const queue = [name];
    let fixed = true;
    while (queue.length && fixed) {
      const current = queue.shift()!;
      if (seen.has(current)) continue;
      seen.add(current);
      fixed = ownMessageFixed(current);
      queue.push(...(children.get(current) ?? []));
    }
    if (fixed) publicClasses.add(name);
  }
  return publicClasses;
}

/** A class name this file imports from a package (not a relative or aliased project path) is not the project's own. */
function importedFromPackage(content: string, name: string): boolean {
  const re = new RegExp(String.raw`\bimport\s*\{[^}]*\b${escapeRe(name)}\b[^}]*\}\s*from\s*["']([^"']+)["']`, "g");
  for (const match of content.matchAll(re)) {
    const source = match[1] ?? "";
    if (!/^(?:\.{1,2}\/|\/|@\/|~\/|#)/.test(source)) return true;
  }
  return false;
}

export async function runApiBoundaryChecks(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false });
  const literalMessageClasses = literalMessageErrorClasses(files);

  for (const file of files) {
    if (nonProductionProjectPath(file.rel)) continue;
    // Minified bundles/vendor artifacts are not auditable source and make regex
    // matches context-free. Build output is already excluded; cover the common
    // vendored `*.min.js` case explicitly as well.
    if (/\.min\.(?:js|mjs|cjs)$/i.test(file.rel)) continue;

    const content = maskCommentsFromParser(file.content, file.rel) ?? maskComments(file.content);
    const errorVars = catchVariables(content);
    const tainted = requestTaint(content);
    const serverFile = serverHandlerFile(file.rel, content);

    for (const call of callsFor(content, RESPONSE_CALL_RE)) {
      if (!isServerResponse(call.head, serverFile)) continue;
      const expression = firstTopLevelArg(call.args);
      const line = lineOf(content, call.index);
      const publicClasses = new Set([...literalMessageClasses].filter((name) => !importedFromPackage(content, name)));
      if (!isMappedCustomPublicError(content, call.index, expression, errorVars, publicClasses) && errorDetailsInResponse(expression, errorVars)) {
        findings.push(errorFinding(file.rel, line));
      }
      const fields = sensitiveResponseFields(expression, (name) => issuedInScope(content, call.index, name, expression));
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
