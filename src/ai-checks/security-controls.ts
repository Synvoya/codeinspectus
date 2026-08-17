/**
 * Project CI Enhancement 2 — repository-visible runtime security-control evidence.
 *
 * This analyzer intentionally distinguishes:
 *   - verified_in_repository
 *   - insecure_configuration_found
 *   - not_verifiable_from_repository
 *
 * Missing headers/CAPTCHA never become findings. Conflicting repository layers are
 * conservative unknowns. Only explicit unsafe literal configuration produces findings.
 */

import type {
  Finding,
  SecurityControlEvidence,
  SecurityControlEvidenceLocation,
} from "../types.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineOf } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const CONFIG_EXTS = [...CODE_EXTS, "json", "conf", "toml", ""];
const HEADER_NAME_PATTERN =
  "Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|Referrer-Policy|Permissions-Policy";

const CONTROLS = {
  hsts: "http.header.strict-transport-security",
  contentType: "http.header.x-content-type-options",
  frame: "http.header.x-frame-options",
  csp: "http.header.content-security-policy",
  referrer: "http.header.referrer-policy",
  permissions: "http.header.permissions-policy",
  cookie: "http.cookie.session-security",
  captcha: "supabase.auth.captcha-token",
} as const;

type ControlId = (typeof CONTROLS)[keyof typeof CONTROLS];
type Verdict = "safe" | "unsafe" | "unknown";
type IssueKind =
  | "header-disabled"
  | "unsafe-csp"
  | "unsafe-referrer-policy"
  | "overbroad-permissions-policy"
  | "insecure-cookie"
  | "captcha-missing";

interface Observation {
  controlId: ControlId;
  verdict: Verdict;
  provider: string;
  file: string;
  line: number;
  label: string;
  issue?: IssueKind;
  /** A conflict/dynamic value means even another safe/unsafe observation cannot resolve final state. */
  ambiguous?: boolean;
  /** Known route scope/order, currently used for Next.js's documented last-match override. */
  scope?: string;
  order?: number;
}

export interface SecurityControlAnalysis {
  findings: Finding[];
  evidence: SecurityControlEvidence[];
}

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

function extractBalanced(
  content: string,
  openIndex: number,
  openChar: "(" | "{",
  closeChar: ")" | "}",
  maxChars = 20_000,
): string {
  let depth = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  const end = Math.min(content.length, openIndex + maxChars);

  for (let index = openIndex; index < end; index++) {
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
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
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
    if (char === openChar) depth++;
    if (char === closeChar && --depth === 0) return content.slice(openIndex + 1, index);
  }
  return content.slice(openIndex + 1, end);
}

function optionObject(args: string, property: string): string | undefined {
  const match = new RegExp(`\\b${property}\\s*:\\s*\\{`, "g").exec(args);
  if (!match) return undefined;
  const open = (match.index ?? 0) + match[0].lastIndexOf("{");
  return extractBalanced(args, open, "{", "}");
}

function providerFor(rel: string): string {
  if (/(^|\/)next\.config\.(?:js|ts|mjs|cjs)$/i.test(rel)) return "nextjs";
  if (/(^|\/)vercel\.json$/i.test(rel)) return "vercel";
  if (/(^|\/)_headers$/i.test(rel)) return "cloudflare-pages";
  if (/(^|\/)nginx(?:\.[^/]*)?\.conf$|(^|\/)nginx\.conf$/i.test(rel)) return "nginx";
  if (/(^|\/)supabase\/config\.toml$/i.test(rel)) return "supabase";
  return "express-node";
}

function isNonProductionPath(rel: string): boolean {
  const normalized = rel.toLowerCase();
  return (
    /(^|\/)(?:tests?|__tests__|fixtures?|examples?|samples?|mocks?|__mocks__)(?:\/|$)/.test(
      normalized,
    ) ||
    /(?:^|\/)[^/]+\.(?:test|spec)\.[cm]?[jt]sx?$/.test(normalized) ||
    /(?:^|\/)nginx\.(?:dev|development|local|test)\.conf$/.test(normalized)
  );
}

function nearestHeaderScope(content: string, index: number): string | undefined {
  const before = content.slice(Math.max(0, index - 4_000), index);
  const scopes = [
    ...before.matchAll(/["']?source["']?\s*:\s*(["'])([^"']+)\1/g),
  ];
  return scopes.at(-1)?.[2];
}

function isConfiguredHeaderObject(content: string, index: number): boolean {
  const before = content.slice(Math.max(0, index - 4_000), index);
  const sourceMatches = [...before.matchAll(/["']?source["']?\s*:\s*(["'])([^"']+)\1/g)];
  const source = sourceMatches.at(-1);
  if (!source || source.index === undefined) return false;
  return /["']?headers["']?\s*:\s*\[/.test(before.slice(source.index));
}

function isDevelopmentOnly(content: string, index: number): boolean {
  const lineStart = content.lastIndexOf("\n", index) + 1;
  const lineEnd = content.indexOf("\n", index);
  const line = content.slice(lineStart, lineEnd < 0 ? content.length : lineEnd);
  if (
    /(?:NODE_ENV\s*={2,3}\s*["']development["']|import\.meta\.env\.DEV\b)/.test(line)
  ) {
    return true;
  }

  const before = content.slice(Math.max(0, index - 700), index);
  const ifIndex = before.lastIndexOf("if");
  if (ifIndex < 0) return false;
  const candidate = before.slice(ifIndex);
  if (
    !/(?:NODE_ENV\s*={2,3}\s*["']development["']|import\.meta\.env\.DEV\b)/.test(candidate)
  ) {
    return false;
  }
  let braces = 0;
  for (const char of candidate) {
    if (char === "{") braces++;
    else if (char === "}") braces--;
  }
  return braces > 0;
}

function headerControl(name: string): ControlId | undefined {
  const normalized = name.toLowerCase();
  if (normalized === "strict-transport-security") return CONTROLS.hsts;
  if (normalized === "x-content-type-options") return CONTROLS.contentType;
  if (normalized === "x-frame-options") return CONTROLS.frame;
  if (normalized === "content-security-policy") return CONTROLS.csp;
  if (normalized === "referrer-policy") return CONTROLS.referrer;
  if (normalized === "permissions-policy") return CONTROLS.permissions;
  return undefined;
}

function referrerPolicyVerdict(value: string): Verdict {
  const recognized = new Set([
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
  ]);
  const effective = value
    .split(",")
    .map((token) => token.trim().toLowerCase())
    .filter((token) => recognized.has(token))
    .at(-1);
  if (effective === "unsafe-url") return "unsafe";
  if (
    effective === "no-referrer" || effective === "same-origin" ||
    effective === "strict-origin" || effective === "strict-origin-when-cross-origin"
  ) {
    return "safe";
  }
  return "unknown";
}

function permissionsPolicyVerdict(value: string): Verdict {
  const target = new Map<string, string>();
  for (const rawDirective of value.split(",")) {
    const match = /^\s*([a-z][a-z0-9-]*)\s*=\s*([\s\S]+?)\s*$/i.exec(rawDirective);
    if (!match) return "unknown";
    const feature = match[1]!.toLowerCase();
    if (["camera", "microphone", "geolocation"].includes(feature)) {
      target.set(feature, match[2]!.trim().toLowerCase());
    }
  }
  if ([...target.values()].some((allowlist) => allowlist === "*" || allowlist === "(*)")) {
    return "unsafe";
  }
  if (!["camera", "microphone", "geolocation"].every((feature) => target.has(feature))) {
    return "unknown";
  }
  return [...target.values()].every(
    (allowlist) => allowlist === "()" || allowlist === "self" || allowlist === "(self)",
  )
    ? "safe"
    : "unknown";
}

function literalHeaderVerdict(name: string, value: string): Verdict {
  const control = headerControl(name);
  if (control === CONTROLS.csp) return cspScriptVerdict(value);
  if (control === CONTROLS.referrer) return referrerPolicyVerdict(value);
  if (control === CONTROLS.permissions) return permissionsPolicyVerdict(value);
  return headerVerdict(name, value);
}

function headerIssue(controlId: ControlId): IssueKind {
  if (controlId === CONTROLS.csp) return "unsafe-csp";
  if (controlId === CONTROLS.referrer) return "unsafe-referrer-policy";
  if (controlId === CONTROLS.permissions) return "overbroad-permissions-policy";
  return "header-disabled";
}

function hasImportProvenResponseFramework(content: string): boolean {
  return /\b(?:from\s+|require\s*\(\s*)["'](?:express|fastify|node:https?|https?)["']/i.test(
    content,
  );
}

function responseReceiverIsHandlerParameter(
  content: string,
  index: number,
  receiver: string,
): boolean {
  const start = Math.max(0, index - 16_000);
  const before = content.slice(start, index);
  const candidates = [
    ...before.matchAll(/\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*\(([^()]*)\)\s*(?::[^{}]+)?\s*\{/g),
    ...before.matchAll(/\(([^()]*)\)\s*(?::[^={}>]+)?=>\s*\{/g),
  ].sort((left, right) => (right.index ?? 0) - (left.index ?? 0));
  const parameterName = (raw: string): string | undefined =>
    /^\s*(?:\.\.\.)?([A-Za-z_$][\w$]*)/.exec(raw)?.[1];
  for (const candidate of candidates) {
    const absoluteMatch = start + (candidate.index ?? 0);
    const openBrace = content.indexOf("{", absoluteMatch + candidate[0].length - 1);
    if (openBrace < 0 || openBrace >= index) continue;
    let depth = 0;
    for (let cursor = openBrace; cursor < index; cursor += 1) {
      if (content[cursor] === "{") depth += 1;
      else if (content[cursor] === "}") depth -= 1;
    }
    if (depth <= 0) continue;
    const parameters = candidate[1]!.split(",").map(parameterName);
    return parameters[1]?.toLowerCase() === receiver;
  }

  const lineStart = content.lastIndexOf("\n", index) + 1;
  const linePrefix = content.slice(lineStart, index);
  const expressionArrow = /\(([^()]*)\)\s*(?::[^={}>]+)?=>[^;]*$/g.exec(linePrefix);
  if (!expressionArrow) return false;
  const parameters = expressionArrow[1]!.split(",").map(parameterName);
  return parameters[1]?.toLowerCase() === receiver;
}

function headerVerdict(name: string, value: string): Verdict {
  const normalizedName = name.toLowerCase();
  const normalizedValue = value.trim().toLowerCase();
  if (normalizedName === "strict-transport-security") {
    const maxAge = /\bmax-age\s*=\s*(\d+)\b/i.exec(normalizedValue);
    if (!maxAge) return "unknown";
    return Number(maxAge[1]) > 0 ? "safe" : "unsafe";
  }
  if (normalizedName === "x-content-type-options") {
    return normalizedValue === "nosniff" ? "safe" : "unsafe";
  }
  if (normalizedName === "x-frame-options") {
    return /^(?:deny|sameorigin)$/i.test(normalizedValue) ? "safe" : "unsafe";
  }
  return "unknown";
}

function cspScriptVerdict(policy: string): Verdict {
  const directives = new Map<string, string[]>();
  for (const raw of policy.split(";")) {
    const tokens = raw.trim().split(/\s+/).filter(Boolean);
    const name = tokens.shift()?.toLowerCase();
    if (name) directives.set(name, tokens.map((token) => token.toLowerCase()));
  }
  const sources = directives.get("script-src") ?? directives.get("default-src");
  if (!sources) return "unknown";
  const unsafe = sources.some((source) => {
    const unquoted = source.replace(/^['"]|['"]$/g, "");
    return unquoted === "*" || unquoted === "unsafe-eval";
  });
  return unsafe ? "unsafe" : "safe";
}

function cspObjectVerdict(block: string): Verdict {
  const directive = (name: string): string | undefined => {
    const match = new RegExp(
      `(?:\\b${name}\\b|["']${name.replace(/[A-Z]/g, (char) => `-${char.toLowerCase()}`)}["'])\\s*:\\s*\\[([\\s\\S]*?)\\]`,
      "i",
    ).exec(block);
    return match?.[1];
  };
  const sources = directive("scriptSrc") ?? directive("defaultSrc");
  if (!sources) return /\buseDefaults\s*:\s*false\b/.test(block) ? "unknown" : "safe";
  const literalSources = [...sources.matchAll(/["'`]([^"'`]+)["'`]/g)].map((match) =>
    (match[1] ?? "").toLowerCase().replace(/^['"]|['"]$/g, ""),
  );
  return literalSources.some((source) => source === "*" || source === "unsafe-eval")
    ? "unsafe"
    : "safe";
}

function addLiteralHeaderObservations(
  observations: Observation[],
  file: { rel: string; content: string },
): void {
  const provider = providerFor(file.rel);
  // `_headers` begins wildcard routes with `/*`; treating that as a JS block comment
  // would erase the entire Cloudflare configuration.
  const content = provider === "cloudflare-pages" ? file.content : maskComments(file.content);

  // Next.js/Vercel key-value header objects.
  const objectHeader = new RegExp(
    `["']?key["']?\\s*:\\s*(["'])(${HEADER_NAME_PATTERN})\\1\\s*,\\s*["']?value["']?\\s*:\\s*(["'\\x60])([\\s\\S]*?)\\3`,
    "g",
  );
  for (const match of provider === "nextjs" || provider === "vercel" ? content.matchAll(objectHeader) : []) {
    const name = match[2]!;
    const value = match[4] ?? "";
    const index = match.index ?? 0;
    if (!isConfiguredHeaderObject(content, index)) continue;
    if (isDevelopmentOnly(content, index)) continue;
    const controlId = headerControl(name)!;
    const verdict = literalHeaderVerdict(name, value);
    observations.push({
      controlId,
      verdict,
      provider,
      file: file.rel,
      line: lineOf(content, index),
      label: name,
      ...(verdict === "unsafe" ? { issue: headerIssue(controlId) } : {}),
      ...(verdict === "unknown" ? { ambiguous: true } : {}),
      ...(provider === "nextjs"
        ? { scope: nearestHeaderScope(content, index), order: index }
        : {}),
    });
  }

  // Express/Node literal response headers.
  const responseHeader = new RegExp(
    `\\b([A-Za-z_$][\\w$]*)\\.(?:setHeader|header|set)\\s*\\(\\s*(["'])(${HEADER_NAME_PATTERN})\\2\\s*,\\s*(["'\\x60])([^"'\\x60]+)\\4`,
    "g",
  );
  for (const match of content.matchAll(responseHeader)) {
    if (!hasImportProvenResponseFramework(content)) continue;
    const receiver = match[1]!.toLowerCase();
    if (!["res", "response", "reply"].includes(receiver)) continue;
    if (!responseReceiverIsHandlerParameter(content, match.index ?? 0, receiver)) continue;
    const name = match[3]!;
    const value = match[5] ?? "";
    const index = match.index ?? 0;
    if (isDevelopmentOnly(content, index)) continue;
    const controlId = headerControl(name)!;
    const verdict = literalHeaderVerdict(name, value);
    observations.push({
      controlId,
      verdict,
      provider,
      file: file.rel,
      line: lineOf(content, index),
      label: name,
      ...(verdict === "unsafe" ? { issue: headerIssue(controlId) } : {}),
      ...(verdict === "unknown" ? { ambiguous: true } : {}),
    });
  }

  const removed = new RegExp(
    `\\b([A-Za-z_$][\\w$]*)\\.removeHeader\\s*\\(\\s*(["'])(${HEADER_NAME_PATTERN})\\2\\s*\\)`,
    "g",
  );
  for (const match of content.matchAll(removed)) {
    if (!hasImportProvenResponseFramework(content)) continue;
    const receiver = match[1]!.toLowerCase();
    if (!["res", "response", "reply"].includes(receiver)) continue;
    if (!responseReceiverIsHandlerParameter(content, match.index ?? 0, receiver)) continue;
    const name = match[3]!;
    const index = match.index ?? 0;
    if (isDevelopmentOnly(content, index)) continue;
    const controlId = headerControl(name)!;
    const unknownRemoval = controlId === CONTROLS.referrer || controlId === CONTROLS.permissions;
    observations.push({
      controlId,
      verdict: unknownRemoval ? "unknown" : "unsafe",
      provider,
      file: file.rel,
      line: lineOf(content, index),
      label: name,
      ...(!unknownRemoval ? { issue: "header-disabled" as const } : { ambiguous: true }),
    });
  }

  // nginx final response-header configuration.
  if (provider === "nginx") {
    const nginxHeader = new RegExp(
      `^\\s*add_header\\s+(${HEADER_NAME_PATTERN})\\s+(?:"([^"]*)"|'([^']*)'|([^;\\s][^;]*?))(?:\\s+always)?\\s*;`,
      "gim",
    );
    for (const match of content.matchAll(nginxHeader)) {
      const name = match[1]!;
      const value = (match[2] ?? match[3] ?? match[4] ?? "").trim();
      const controlId = headerControl(name)!;
      const verdict = literalHeaderVerdict(name, value);
      observations.push({
        controlId,
        verdict,
        provider,
        file: file.rel,
        line: lineOf(content, match.index ?? 0),
        label: name,
        ...(verdict === "unsafe" ? { issue: headerIssue(controlId) } : {}),
        ...(verdict === "unknown" ? { ambiguous: true } : {}),
      });
    }
  }

  // Cloudflare Pages `_headers`: a leading `!` explicitly detaches a header.
  if (provider === "cloudflare-pages") {
    const detached = new RegExp(`^\\s*!\\s+(${HEADER_NAME_PATTERN})\\s*$`, "gim");
    for (const match of content.matchAll(detached)) {
      const name = match[1]!;
      const controlId = headerControl(name)!;
      const unknownRemoval = controlId === CONTROLS.referrer || controlId === CONTROLS.permissions;
      observations.push({
        controlId,
        verdict: unknownRemoval ? "unknown" : "unsafe",
        provider,
        file: file.rel,
        line: lineOf(content, match.index ?? 0),
        label: name,
        ...(!unknownRemoval ? { issue: "header-disabled" as const } : { ambiguous: true }),
      });
    }

    const attached = new RegExp(`^\\s*(${HEADER_NAME_PATTERN}):\\s*(.+)$`, "gim");
    for (const match of content.matchAll(attached)) {
      const name = match[1]!;
      const value = match[2] ?? "";
      const controlId = headerControl(name)!;
      const verdict = literalHeaderVerdict(name, value);
      observations.push({
        controlId,
        verdict,
        provider,
        file: file.rel,
        line: lineOf(content, match.index ?? 0),
        label: name,
        ...(verdict === "unsafe" ? { issue: headerIssue(controlId) } : {}),
        ...(verdict === "unknown" ? { ambiguous: true } : {}),
      });
    }
  }
}

/**
 * Next.js documents that when matching header entries set the same key, the last
 * matching value wins. Resolve only when file + literal source + control are known;
 * every other cross-layer/scope conflict stays conservative unknown.
 */
function resolveKnownOrdering(observations: Observation[]): Observation[] {
  const effective = new Map<string, Observation>();
  const passthrough: Observation[] = [];
  for (const observation of observations) {
    if (
      observation.provider === "nextjs" &&
      observation.scope &&
      observation.order !== undefined
    ) {
      const key = [
        observation.provider,
        observation.file,
        observation.scope,
        observation.controlId,
      ].join("\0");
      const prior = effective.get(key);
      if (!prior || (prior.order ?? -1) < observation.order) effective.set(key, observation);
    } else {
      passthrough.push(observation);
    }
  }
  return [...passthrough, ...effective.values()];
}

function importProvenHelmetBindings(content: string): string[] {
  const bindings = new Set<string>();
  for (const match of content.matchAll(
    /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])helmet\2/g,
  )) {
    bindings.add(match[1]!);
  }
  for (const match of content.matchAll(
    /\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(["'])helmet\2\s*\)/g,
  )) {
    bindings.add(match[1]!);
  }
  return [...bindings];
}

function addHelmetObservations(
  observations: Observation[],
  file: { rel: string; content: string },
): void {
  if (!CODE_EXTS.some((ext) => file.rel.toLowerCase().endsWith(`.${ext}`))) return;
  const content = maskComments(file.content);
  const bindings = importProvenHelmetBindings(content);
  if (!bindings.length) return;
  const callStart = new RegExp(
    `\\b(?:${bindings.map((binding) => binding.replace(/[$]/g, "\\$")).join("|")})\\s*\\(`,
    "g",
  );

  for (const match of content.matchAll(callStart)) {
    const index = match.index ?? 0;
    if (isDevelopmentOnly(content, index)) continue;
    const open = index + (match[0]?.lastIndexOf("(") ?? 0);
    const args = extractBalanced(content, open, "(", ")");
    const line = lineOf(content, index);
    const falseOption = (name: string): boolean =>
      new RegExp(`\\b${name}\\s*:\\s*false\\b`).test(args);

    const referrerDisabled = falseOption("referrerPolicy");
    const referrerBlock = optionObject(args, "referrerPolicy");
    const referrerPolicy = referrerBlock
      ? /\bpolicy\s*:\s*(["'])([^"']+)\1/i.exec(referrerBlock)?.[2]
      : undefined;
    const referrerVerdict = referrerDisabled
      ? "unknown"
      : referrerPolicy
        ? referrerPolicyVerdict(referrerPolicy)
        : referrerBlock
          ? "unknown"
          : "safe";
    observations.push({
      controlId: CONTROLS.referrer,
      verdict: referrerVerdict,
      provider: "helmet",
      file: file.rel,
      line,
      label: "Referrer-Policy",
      ...(referrerVerdict === "unsafe" ? { issue: "unsafe-referrer-policy" as const } : {}),
      ...(referrerVerdict === "unknown" ? { ambiguous: true } : {}),
    });

    if (/\bpermissionsPolicy\s*:/.test(args)) {
      observations.push({
        controlId: CONTROLS.permissions,
        verdict: "unknown",
        provider: "helmet",
        file: file.rel,
        line,
        label: "Permissions-Policy",
        ambiguous: true,
      });
    }

    const cspDisabled = falseOption("contentSecurityPolicy");
    const cspBlock = optionObject(args, "contentSecurityPolicy");
    const reportOnly = !!cspBlock && /\breportOnly\s*:\s*true\b/.test(cspBlock);
    if (cspDisabled) {
      observations.push({
        controlId: CONTROLS.csp,
        verdict: "unsafe",
        provider: "helmet",
        file: file.rel,
        line,
        label: "Content-Security-Policy",
        issue: "header-disabled",
      });
    } else if (reportOnly) {
      observations.push({
        controlId: CONTROLS.csp,
        verdict: "unknown",
        provider: "helmet",
        file: file.rel,
        line,
        label: "Content-Security-Policy",
        ambiguous: true,
      });
    } else {
      const verdict = cspBlock ? cspObjectVerdict(cspBlock) : "safe";
      observations.push({
        controlId: CONTROLS.csp,
        verdict,
        provider: "helmet",
        file: file.rel,
        line,
        label: "Content-Security-Policy",
        ...(verdict === "unsafe" ? { issue: "unsafe-csp" as const } : {}),
        ...(verdict === "unknown" ? { ambiguous: true } : {}),
      });
    }

    const hstsBlock =
      optionObject(args, "strictTransportSecurity") ?? optionObject(args, "hsts");
    const hstsFalse =
      falseOption("strictTransportSecurity") || falseOption("hsts");
    const hstsZero = !!hstsBlock && /\bmaxAge\s*:\s*0\b/.test(hstsBlock);
    observations.push({
      controlId: CONTROLS.hsts,
      verdict: hstsFalse || hstsZero ? "unsafe" : "safe",
      provider: "helmet",
      file: file.rel,
      line,
      label: "Strict-Transport-Security",
      ...(hstsFalse || hstsZero ? { issue: "header-disabled" as const } : {}),
    });

    const contentTypeFalse = falseOption("xContentTypeOptions");
    observations.push({
      controlId: CONTROLS.contentType,
      verdict: contentTypeFalse ? "unsafe" : "safe",
      provider: "helmet",
      file: file.rel,
      line,
      label: "X-Content-Type-Options",
      ...(contentTypeFalse ? { issue: "header-disabled" as const } : {}),
    });

    const frameFalse = falseOption("xFrameOptions") || falseOption("frameguard");
    const frameCompensatedByCsp = frameFalse && !cspDisabled && !reportOnly;
    observations.push({
      controlId: CONTROLS.frame,
      verdict: frameFalse ? (frameCompensatedByCsp ? "unknown" : "unsafe") : "safe",
      provider: "helmet",
      file: file.rel,
      line,
      label: "X-Frame-Options",
      ...(frameFalse && !frameCompensatedByCsp ? { issue: "header-disabled" as const } : {}),
      ...(frameCompensatedByCsp ? { ambiguous: true } : {}),
    });
  }
}

function firstStringArg(args: string): string | undefined {
  return /^\s*(["'`])([^"'`]+)\1/.exec(args)?.[2];
}

function addCookieObservations(
  observations: Observation[],
  file: { rel: string; content: string },
): void {
  if (!CODE_EXTS.some((ext) => file.rel.toLowerCase().endsWith(`.${ext}`))) return;
  const content = maskComments(file.content);
  const cookieCall =
    /\b(?:[A-Za-z_$][\w$]*\.cookie|[A-Za-z_$][\w$]*\.cookies\.set|cookies\s*\(\s*\)\.set|setCookie|serialize)\s*\(/g;

  for (const match of content.matchAll(cookieCall)) {
    const index = match.index ?? 0;
    if (isDevelopmentOnly(content, index)) continue;
    const open = index + (match[0]?.lastIndexOf("(") ?? 0);
    const args = extractBalanced(content, open, "(", ")");
    const name = firstStringArg(args);
    if (!name || !/(?:^|[_-])(?:session|auth|access|refresh|token|jwt|sid)(?:$|[_-])/i.test(name)) {
      continue;
    }

    const httpOnlyFalse = /\bhttpOnly\s*:\s*false\b/.test(args);
    const secureFalse = /\bsecure\s*:\s*false\b/.test(args);
    const sameSiteNone = /\bsameSite\s*:\s*["']none["']/i.test(args);
    const secureTrue = /\bsecure\s*:\s*true\b/.test(args);
    const unsafe = httpOnlyFalse || secureFalse || (sameSiteNone && !secureTrue);
    const safe =
      /\bhttpOnly\s*:\s*true\b/.test(args) &&
      secureTrue &&
      (!sameSiteNone || secureTrue);
    observations.push({
      controlId: CONTROLS.cookie,
      verdict: unsafe ? "unsafe" : safe ? "safe" : "unknown",
      provider: "application-cookie-api",
      file: file.rel,
      line: lineOf(content, index),
      label: "auth/session cookie attributes",
      ...(unsafe ? { issue: "insecure-cookie" as const } : {}),
      ...(!unsafe && !safe ? { ambiguous: true } : {}),
    });
  }
}

interface CaptchaConfig {
  file: string;
  line: number;
  enabled: boolean | undefined;
  prefix: string;
}

function captchaConfigs(files: Array<{ rel: string; content: string }>): CaptchaConfig[] {
  const configs: CaptchaConfig[] = [];
  for (const file of files) {
    if (!/(^|\/)supabase\/config\.toml$/i.test(file.rel)) continue;
    const section = /^\s*\[auth\.captcha\]\s*$/gim.exec(file.content);
    if (!section) continue;
    const start = section.index + section[0].length;
    const nextSection = /^\s*\[[^\]]+\]\s*$/gm;
    nextSection.lastIndex = start;
    const next = nextSection.exec(file.content);
    const block = file.content.slice(start, next?.index ?? file.content.length);
    const enabled = /^\s*enabled\s*=\s*(true|false)\s*$/im.exec(block)?.[1];
    configs.push({
      file: file.rel,
      line: lineOf(file.content, section.index),
      enabled: enabled === "true" ? true : enabled === "false" ? false : undefined,
      prefix: file.rel.slice(0, file.rel.length - "supabase/config.toml".length),
    });
  }
  return configs;
}

function addCaptchaObservations(
  observations: Observation[],
  files: Array<{ rel: string; content: string }>,
): void {
  const configs = captchaConfigs(files);
  if (!configs.length) return;
  const states = new Set(configs.map((config) => config.enabled));
  if (states.size > 1 || states.has(undefined)) {
    for (const config of configs) {
      observations.push({
        controlId: CONTROLS.captcha,
        verdict: "unknown",
        provider: "supabase",
        file: config.file,
        line: config.line,
        label: "Supabase CAPTCHA configuration",
        ambiguous: true,
      });
    }
    return;
  }

  if (states.has(false)) {
    for (const config of configs) {
      observations.push({
        controlId: CONTROLS.captcha,
        verdict: "unknown",
        provider: "supabase",
        file: config.file,
        line: config.line,
        label: "Supabase CAPTCHA explicitly disabled",
        ambiguous: true,
      });
    }
    return;
  }

  let recognizedCalls = 0;
  const authCall =
    /\.auth\.(signUp|signInWithPassword|signInWithOtp|signInWithSSO|signInWithWeb3|resetPasswordForEmail)\s*\(/g;
  for (const config of configs) {
    for (const file of files) {
      if (!file.rel.startsWith(config.prefix)) continue;
      if (!CODE_EXTS.some((ext) => file.rel.toLowerCase().endsWith(`.${ext}`))) continue;
      const content = maskComments(file.content);
      for (const match of content.matchAll(authCall)) {
        const index = match.index ?? 0;
        const open = index + (match[0]?.lastIndexOf("(") ?? 0);
        const args = extractBalanced(content, open, "(", ")");
        recognizedCalls++;
        const supplied = /\bcaptchaToken\s*(?::|,|})/.test(args);
        observations.push({
          controlId: CONTROLS.captcha,
          verdict: supplied ? "safe" : "unsafe",
          provider: "supabase",
          file: file.rel,
          line: lineOf(content, index),
          label: `${match[1]} captchaToken`,
          ...(!supplied ? { issue: "captcha-missing" as const } : {}),
        });
      }
    }
  }

  if (!recognizedCalls) {
    for (const config of configs) {
      observations.push({
        controlId: CONTROLS.captcha,
        verdict: "unknown",
        provider: "supabase",
        file: config.file,
        line: config.line,
        label: "CAPTCHA enabled but no supported auth call was found",
        ambiguous: true,
      });
    }
  }
}

function uniqueLocations(observations: Observation[]): SecurityControlEvidenceLocation[] {
  const seen = new Set<string>();
  const locations: SecurityControlEvidenceLocation[] = [];
  for (const observation of observations) {
    const key = `${observation.file}:${observation.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    locations.push({
      file: observation.file,
      start_line: observation.line,
      end_line: observation.line,
    });
  }
  return locations.sort((a, b) =>
    a.file === b.file ? a.start_line - b.start_line : a.file.localeCompare(b.file),
  );
}

function resolveEvidence(observations: Observation[]): SecurityControlEvidence[] {
  return Object.values(CONTROLS).map((controlId) => {
    const relevant = observations.filter((observation) => observation.controlId === controlId);
    const hasSafe = relevant.some((observation) => observation.verdict === "safe");
    const hasUnsafe = relevant.some((observation) => observation.verdict === "unsafe");
    const hasAmbiguous = relevant.some((observation) => observation.ambiguous);
    const providers = new Set(relevant.map((observation) => observation.provider));
    const unresolvedCrossLayerConflict =
      hasSafe &&
      hasUnsafe &&
      providers.size > 1 &&
      controlId !== CONTROLS.cookie &&
      controlId !== CONTROLS.captcha;

    let state: SecurityControlEvidence["state"];
    let limitation: string;
    if (unresolvedCrossLayerConflict || hasAmbiguous) {
      state = "not_verifiable_from_repository";
      limitation =
        "Repository evidence is conflicting, scoped, dynamic, disabled, or report-only; the effective deployed control cannot be resolved safely.";
    } else if (hasUnsafe) {
      state = "insecure_configuration_found";
      limitation =
        "An explicit insecure repository configuration was found. Unmodeled gateways or deployment overrides may still change runtime behavior.";
    } else if (hasSafe) {
      state = "verified_in_repository";
      limitation =
        "Recognized repository configuration passed this rule's narrow literal check; deployed overrides, uncovered routes, broader policy quality, and runtime behavior were not tested.";
    } else {
      state = "not_verifiable_from_repository";
      limitation =
        "No authoritative repository evidence was found. A hosting provider, gateway, dashboard, or runtime layer may configure this control.";
    }

    return {
      control_id: controlId,
      state,
      providers: [...new Set(relevant.map((observation) => observation.provider))].sort(),
      evidence_locations: uniqueLocations(relevant),
      limitation,
    };
  });
}

function headerFinding(observation: Observation): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-security-header-disabled",
    title: "Security response header explicitly disabled or ineffective",
    severity: "medium",
    cwe: ["CWE-693"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file: observation.file,
    startLine: observation.line,
    snippet: `${observation.label} is explicitly disabled, removed, or configured with an ineffective literal value`,
    message:
      "A repository-controlled response layer explicitly disables, removes, or neutralizes a security header. This finding does not claim that an unmodeled gateway cannot override the response.",
    remediation: {
      summary: "Configure an effective production value at the final repository-controlled response layer.",
      steps: [
        "Remove the explicit disablement/removal or replace the ineffective literal with a valid secure value.",
        "Resolve duplicate route/layer definitions so the effective value is deterministic.",
        "Verify the deployed response with an integration test or an HTTP header probe.",
      ],
      references: [
        "CWE-693",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      ],
    },
    confidence: "high",
  });
}

function cspFinding(observation: Observation): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-unsafe-production-csp",
    title: "Production CSP explicitly allows unsafe script execution",
    severity: "medium",
    cwe: ["CWE-693"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file: observation.file,
    startLine: observation.line,
    snippet: "Enforced CSP script policy contains bare * or 'unsafe-eval'",
    message:
      "An enforced repository-visible CSP gives script-src (or its default-src fallback) a bare wildcard source or 'unsafe-eval', weakening CSP protection against injected script execution.",
    remediation: {
      summary: "Remove the unsafe script source and allow only required origins, nonces, or hashes.",
      steps: [
        "Remove the bare wildcard and 'unsafe-eval' from the enforced production script policy.",
        "Use explicit trusted origins plus nonces or hashes for scripts that must execute.",
        "Keep development-only exceptions behind an explicit development branch and test the production header.",
      ],
      references: [
        "CWE-693",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
      ],
    },
    confidence: "high",
  });
}

function referrerPolicyFinding(observation: Observation): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-unsafe-referrer-policy",
    title: "Referrer-Policy explicitly sends full URLs across origins",
    severity: "medium",
    cwe: ["CWE-200", "CWE-693"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file: observation.file,
    startLine: observation.line,
    snippet: "The effective literal Referrer-Policy value is unsafe-url",
    message:
      "The effective recognized Referrer-Policy token is unsafe-url, which sends the full referrer URL on same-origin and cross-origin requests, including HTTPS-to-HTTP navigations. Missing, dynamic, invalid, or merely weaker policies are not reported by this rule.",
    remediation: {
      summary: "Replace unsafe-url with a policy that limits cross-origin referrer disclosure.",
      steps: [
        "Use strict-origin-when-cross-origin for a balanced default, or no-referrer for maximum privacy.",
        "Keep fallback tokens ordered from older to newer because the last recognized token is effective.",
        "Verify the final deployed response header on representative routes.",
      ],
      references: ["CWE-200", "https://www.w3.org/TR/referrer-policy/"],
    },
    confidence: "high",
  });
}

function permissionsPolicyFinding(observation: Observation): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-overbroad-permissions-policy",
    title: "Permissions-Policy delegates a sensitive feature to every origin",
    severity: "medium",
    cwe: ["CWE-942", "CWE-693"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file: observation.file,
    startLine: observation.line,
    snippet: "Permissions-Policy uses the universal * allowlist for camera, microphone, or geolocation",
    message:
      "A literal Permissions-Policy universally delegates camera, microphone, or geolocation. The browser still applies user permission prompts, but any embedded origin can become eligible to request the delegated feature.",
    remediation: {
      summary: "Restrict sensitive browser features to no origins or only the application origin.",
      steps: [
        "Use camera=(), microphone=(), and geolocation=() when the application does not need them.",
        "Use (self) only for features required by the top-level application.",
        "List specific third-party origins only after reviewing why each embedded origin needs access.",
      ],
      references: ["CWE-942", "https://www.w3.org/TR/permissions-policy/"],
    },
    confidence: "high",
  });
}

function cookieFinding(observation: Observation): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-insecure-session-cookie",
    title: "Auth/session cookie explicitly uses insecure attributes",
    severity: "medium",
    cwe: ["CWE-1004", "CWE-614"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file: observation.file,
    startLine: observation.line,
    snippet:
      "Auth/session cookie explicitly disables HttpOnly/Secure or uses SameSite=None without Secure",
    message:
      "A recognized auth/session cookie explicitly disables HttpOnly or Secure, or requests SameSite=None without Secure. This can expose session material to script access or insecure transport, or cause the browser to reject the cookie.",
    remediation: {
      summary: "Set secure attributes explicitly for auth/session cookies.",
      steps: [
        "Set httpOnly: true so browser scripts cannot read the session cookie.",
        "Set secure: true in production so the cookie is sent only over HTTPS.",
        "When SameSite=None is required, always pair it with Secure.",
      ],
      references: [
        "CWE-1004",
        "CWE-614",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
      ],
    },
    confidence: "high",
  });
}

function captchaFinding(observation: Observation): Finding {
  return makeAiFinding({
    ruleId: "ci-ai-supabase-captcha-token-missing",
    title: "CAPTCHA-enabled Supabase auth call omits captchaToken",
    severity: "medium",
    cwe: ["CWE-693"],
    owasp_web: ["A05:2021"],
    owasp_api: ["API8:2023"],
    file: observation.file,
    startLine: observation.line,
    snippet: `${observation.label} is missing required captchaToken`,
    message:
      "Checked-in Supabase configuration explicitly enables CAPTCHA, but this recognized auth call omits captchaToken. Supabase should reject the request rather than bypass CAPTCHA, so this is an integration failure that can break the auth flow—not proof that bot protection is bypassed.",
    remediation: {
      summary: "Pass the completed CAPTCHA token in the supported Supabase auth-call options.",
      steps: [
        "Render hCaptcha or Cloudflare Turnstile and retain the completed challenge token.",
        "Pass captchaToken in the supported options object for the affected Supabase auth method.",
        "Reset the challenge after the request and verify each affected auth flow independently.",
      ],
      references: [
        "CWE-693",
        "https://supabase.com/docs/guides/auth/auth-captcha",
      ],
    },
    confidence: "high",
  });
}

export async function runSecurityControlChecks(
  target: string,
): Promise<SecurityControlAnalysis> {
  const files = await collectFiles(target, {
    exts: CONFIG_EXTS,
    includeBuilt: false,
    maxBytes: 2 * 1024 * 1024,
  });
  const productionFiles = files.filter((file) => !isNonProductionPath(file.rel));
  const observations: Observation[] = [];

  for (const file of productionFiles) {
    addLiteralHeaderObservations(observations, file);
    addHelmetObservations(observations, file);
    addCookieObservations(observations, file);
  }
  addCaptchaObservations(observations, productionFiles);

  const effectiveObservations = resolveKnownOrdering(observations);
  const evidence = resolveEvidence(effectiveObservations);
  const insecureControls = new Set(
    evidence
      .filter((record) => record.state === "insecure_configuration_found")
      .map((record) => record.control_id),
  );
  const findings: Finding[] = [];
  for (const observation of effectiveObservations) {
    if (
      observation.verdict !== "unsafe" ||
      !observation.issue ||
      !insecureControls.has(observation.controlId)
    ) {
      continue;
    }
    if (observation.issue === "header-disabled") findings.push(headerFinding(observation));
    else if (observation.issue === "unsafe-csp") findings.push(cspFinding(observation));
    else if (observation.issue === "unsafe-referrer-policy") findings.push(referrerPolicyFinding(observation));
    else if (observation.issue === "overbroad-permissions-policy") findings.push(permissionsPolicyFinding(observation));
    else if (observation.issue === "insecure-cookie") findings.push(cookieFinding(observation));
    else findings.push(captchaFinding(observation));
  }

  return { findings, evidence };
}
