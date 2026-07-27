import type { Finding } from "../../types.js";
import { makeAiFinding } from "../../ai-checks/finding.js";
import { hashSecret } from "../../redact.js";

import {
  analyzePythonDocument,
  argument,
  directArgumentReference,
  directCallExpression,
  functionAt,
  hasSpreadArgument,
  memberTargetParts,
  originEquals,
  resolveCallOrigin,
  resolveReferenceOrigin,
  staticString,
  statementAt,
  targetSubscriptString,
  topLevelAssignment,
  unwrapPythonExpression,
  uniqueFindingsByLocation,
  type PythonAnalysisContext,
  type PythonLocalAssignment,
} from "./analysis.js";
import { pythonStaticString } from "../python/analysis.js";
import { splitPythonTopLevel, type PythonExpression } from "../python/python.js";
import { resolvePythonProject, type PythonProjectInput } from "../python/project.js";

export const PYTHON_HARDCODED_SIGNING_SECRET_RULE_ID = "ci-python-hardcoded-signing-secret";

interface HardcodedSecret {
  value: string;
  line: number;
  setting: string;
}

function nonempty(value: string | undefined): value is string {
  return value !== undefined && value.length > 0;
}

function topLevelOrIndex(tokens: readonly { value: string }[]): number {
  let depth = 0;
  for (let index = 0; index < tokens.length; index++) {
    const value = tokens[index]!.value;
    if (["(", "[", "{"].includes(value)) depth++;
    else if ([")", "]", "}"].includes(value)) depth--;
    else if (depth === 0 && value === "or") return index;
  }
  return -1;
}

function literalFallback(
  context: PythonAnalysisContext,
  value: PythonExpression,
): string | undefined {
  const unwrapped = unwrapPythonExpression(value);
  const direct = pythonStaticString(unwrapped);
  if (nonempty(direct)) return direct;

  const call = directCallExpression(context, unwrapped);
  if (call && !hasSpreadArgument(call)) {
    const origin = resolveCallOrigin(context, call)?.join(".");
    if (["os.getenv", "os.environ.get"].includes(origin ?? "")) {
      const fallback = staticString(argument(call, 1, "default"));
      if (nonempty(fallback)) return fallback;
    }
  }

  const orIndex = topLevelOrIndex(unwrapped.tokens);
  if (orIndex > 0) {
    const candidates = splitPythonTopLevel(unwrapped.tokens.slice(orIndex + 1));
    const fallback = pythonStaticString(candidates[0]);
    if (nonempty(fallback)) return fallback;
  }
  return undefined;
}

function assignmentSecrets(
  context: PythonAnalysisContext,
  assignment: PythonLocalAssignment,
  setting: string,
): HardcodedSecret[] {
  const fallback = literalFallback(context, assignment.expression);
  if (fallback) return [{ value: fallback, line: assignment.line, setting }];
  const list = literalList(context, assignment.expression);
  return list.length ? [{ value: list.join("\u0000"), line: assignment.line, setting }] : [];
}

function literalList(context: PythonAnalysisContext, value: PythonExpression): string[] {
  const unwrapped = unwrapPythonExpression(value);
  const opening = unwrapped.tokens[0]?.value;
  const closing = opening === "[" ? "]" : opening === "(" ? ")" : undefined;
  if (!closing || unwrapped.tokens.at(-1)?.value !== closing || unwrapped.tokens[0]?.pairIndex !== unwrapped.tokens.at(-1)?.index) {
    return [];
  }
  return splitPythonTopLevel(unwrapped.tokens.slice(1, -1))
    .map((item) => literalFallback(context, item))
    .filter(nonempty);
}

function dictionaryValue(
  value: PythonExpression | undefined,
  key: string,
): PythonExpression | undefined {
  const unwrapped = unwrapPythonExpression(value);
  if (unwrapped.tokens[0]?.value !== "{" || unwrapped.tokens.at(-1)?.value !== "}") return undefined;
  for (const item of splitPythonTopLevel(unwrapped.tokens.slice(1, -1))) {
    let depth = 0;
    let colon = -1;
    for (let index = 0; index < item.tokens.length; index++) {
      const token = item.tokens[index]!;
      if (["(", "[", "{"].includes(token.value)) depth++;
      else if ([")", "]", "}"].includes(token.value)) depth--;
      else if (depth === 0 && token.value === ":") colon = index;
    }
    if (colon <= 0 || pythonStaticString({
      tokens: item.tokens.slice(0, colon),
      start: item.tokens[0]?.index ?? -1,
      end: item.tokens[colon - 1]?.index ?? -1,
    }) !== key) continue;
    return {
      tokens: item.tokens.slice(colon + 1),
      start: item.tokens[colon + 1]?.index ?? -1,
      end: item.tokens.at(-1)?.index ?? -1,
    };
  }
  return undefined;
}

function secretValue(
  context: PythonAnalysisContext,
  value: PythonExpression,
): string | undefined {
  const list = literalList(context, value);
  return literalFallback(context, value) ?? (list.length ? list.join("\u0000") : undefined);
}

function djangoSecrets(context: PythonAnalysisContext): HardcodedSecret[] {
  // Django settings modules conventionally assign these exact top-level names;
  // no target code is imported or executed to prove settings ownership.
  if (!/(?:^|\/)settings(?:\.pyw?$|\/)/.test(context.document.path)) return [];
  const output: HardcodedSecret[] = [];
  for (const name of ["SECRET_KEY", "SECRET_KEY_FALLBACKS"] as const) {
    const assignment = topLevelAssignment(context, name);
    if (assignment) output.push(...assignmentSecrets(context, assignment, name));
  }
  return output;
}

interface FlaskSecretWrite {
  identity: string;
  line: number;
  setting: string;
  tokenIndex: number;
  blockPath: readonly number[];
  secret: string | undefined;
}

function sameBlockPath(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((block, index) => right[index] === block);
}

function flaskSecrets(context: PythonAnalysisContext): HardcodedSecret[] {
  const writes: FlaskSecretWrite[] = [];
  const addWrite = (
    root: string,
    key: "SECRET_KEY" | "SECRET_KEY_FALLBACKS",
    value: PythonExpression,
    tokenIndex: number,
    line: number,
    blockPath: readonly number[],
  ) => {
    const scope = functionAt(context, tokenIndex);
    writes.push({
      identity: `${scope?.id ?? "module"}:${root}:${key}`,
      line,
      setting: key === "SECRET_KEY" ? "Flask SECRET_KEY" : "Flask SECRET_KEY_FALLBACKS",
      tokenIndex,
      blockPath,
      secret: secretValue(context, value),
    });
  };

  for (const assignment of context.assignments) {
    const member = memberTargetParts(assignment.target);
    if (member?.length === 2 && member[1] === "secret_key") {
      const owner = resolveReferenceOrigin(context, [member[0]!], assignment.tokenIndex);
      if (originEquals(owner, "flask.Flask") || originEquals(owner, "flask.app.Flask")) {
        addWrite(
          member[0]!,
          "SECRET_KEY",
          assignment.expression,
          assignment.tokenIndex,
          assignment.line,
          assignment.blockPath,
        );
      }
      continue;
    }
    const subscript = targetSubscriptString(assignment.target);
    if (
      subscript?.attributes.join(".") === "config" &&
      ["SECRET_KEY", "SECRET_KEY_FALLBACKS"].includes(subscript.key)
    ) {
      const owner = resolveReferenceOrigin(context, [subscript.root], assignment.tokenIndex);
      if (originEquals(owner, "flask.Flask") || originEquals(owner, "flask.app.Flask")) {
        addWrite(
          subscript.root,
          subscript.key as "SECRET_KEY" | "SECRET_KEY_FALLBACKS",
          assignment.expression,
          assignment.tokenIndex,
          assignment.line,
          assignment.blockPath,
        );
      }
    }
  }

  for (const call of context.calls) {
    if (hasSpreadArgument(call)) continue;
    const origin = resolveCallOrigin(context, call)?.join(".") ?? "";
    if (
      !origin.startsWith("flask.Flask.config.") && !origin.startsWith("flask.app.Flask.config.") ||
      !["update", "from_mapping"].includes(origin.split(".").at(-1) ?? "")
    ) {
      continue;
    }
    const statement = statementAt(context, call.startIndex);
    if (!statement) continue;
    const root = call.reference.slice(0, -2).join(".");
    if (!root) continue;
    for (const name of ["SECRET_KEY", "SECRET_KEY_FALLBACKS"] as const) {
      const keyword = call.arguments.find((candidate) => candidate.name === name)?.expression;
      const mapping = dictionaryValue(argument(call, 0)?.expression, name);
      const value = keyword ?? mapping;
      if (value) addWrite(root, name, value, call.startIndex, call.line, statement.blockPath);
    }
  }

  const output: HardcodedSecret[] = [];
  for (const identity of new Set(writes.map((write) => write.identity))) {
    const candidates = writes
      .filter((write) => write.identity === identity)
      .sort((left, right) => left.tokenIndex - right.tokenIndex);
    const first = candidates[0];
    if (!first || candidates.some((candidate) => !sameBlockPath(first.blockPath, candidate.blockPath))) {
      // Conditional writes make the final runtime value ambiguous. Do not
      // claim a hardcoded active secret unless the write order is straight-line.
      continue;
    }
    const latest = candidates.at(-1)!;
    if (latest.secret) output.push({
      value: latest.secret,
      line: latest.line,
      setting: latest.setting,
    });
  }
  return output;
}

function sessionMiddlewareSecrets(context: PythonAnalysisContext): HardcodedSecret[] {
  const output: HardcodedSecret[] = [];
  for (const call of context.calls) {
    if (hasSpreadArgument(call)) continue;
    const origin = resolveCallOrigin(context, call);
    let proven = originEquals(origin, "starlette.middleware.sessions.SessionMiddleware");
    if (!proven && (
      originEquals(origin, "fastapi.FastAPI.add_middleware") ||
      originEquals(origin, "fastapi.applications.FastAPI.add_middleware") ||
      originEquals(origin, "starlette.applications.Starlette.add_middleware") ||
      originEquals(origin, "starlette.middleware.Middleware")
    )) {
      const middleware = directArgumentReference(argument(call, 0));
      proven = Boolean(
        middleware && originEquals(
          resolveReferenceOrigin(context, middleware, call.startIndex),
          "starlette.middleware.sessions.SessionMiddleware",
        ),
      );
    }
    if (!proven) continue;
    const secretArgument = argument(call, 1, "secret_key");
    const secret = secretArgument ? literalFallback(context, secretArgument.expression) : undefined;
    if (secret) output.push({ value: secret, line: call.line, setting: "Starlette SessionMiddleware secret_key" });
  }
  return output;
}

function finding(file: string, secret: HardcodedSecret): Finding {
  return makeAiFinding({
    ruleId: PYTHON_HARDCODED_SIGNING_SECRET_RULE_ID,
    title: "Hardcoded Python signing secret",
    severity: "high",
    cwe: ["CWE-798", "CWE-321"],
    owasp_web: ["A02:2021"],
    file,
    startLine: secret.line,
    snippet: `${secret.setting} = [VALUE REDACTED]`,
    message: `${secret.setting} uses a non-empty source-code literal as a signing secret.`,
    remediation: {
      summary: "Load signing secrets from a runtime secret store and rotate the exposed value.",
      steps: [
        "Remove the literal from source and version history, then rotate it in every environment.",
        "Inject a high-entropy value through the deployment secret manager without a literal fallback.",
        "Use framework-supported key rotation where old signed sessions or tokens must remain valid temporarily.",
      ],
      references: [
        "CWE-798",
        "CWE-321",
        "https://docs.djangoproject.com/en/5.2/ref/settings/#secret-key",
        "https://flask.palletsprojects.com/en/stable/quickstart/#sessions",
        "https://www.starlette.io/middleware/",
      ],
    },
    confidence: "high",
    isSecret: true,
    secretValueHash: hashSecret(secret.value),
  });
}

export async function runPythonHardcodedSigningSecret(
  input: PythonProjectInput,
): Promise<Finding[]> {
  const project = await resolvePythonProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const context = analyzePythonDocument(document);
    for (const secret of [
      ...djangoSecrets(context),
      ...flaskSecrets(context),
      ...sessionMiddlewareSecrets(context),
    ]) findings.push(finding(document.path, secret));
  }
  return uniqueFindingsByLocation(findings);
}
