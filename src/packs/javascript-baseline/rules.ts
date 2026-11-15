import type { NativeGapRecord } from "../../native-gaps.js";
import type { Finding } from "../../types.js";
import { remediationForCwe } from "../../remediation.js";
import { fingerprint } from "../../util/hash.js";
import {
  jsCalls,
  staticString,
  type JsCall,
  type JsDocument,
  type JsExpression,
  type JsToken,
} from "../react-native/javascript.js";
import {
  resolveJavaScriptBaselineProject,
  type JavaScriptBaselineProjectInput,
} from "./project.js";

export const JAVASCRIPT_WEAK_HASH_RULE_ID = "ci-baseline-weak-hash";
export const JAVASCRIPT_WEAK_CIPHER_RULE_ID = "ci-baseline-weak-cipher";
export const JAVASCRIPT_BASELINE_RULE_IDS = [
  JAVASCRIPT_WEAK_HASH_RULE_ID,
  JAVASCRIPT_WEAK_CIPHER_RULE_ID,
] as const;

// Design 10.6 precision pass: MD5/SHA1 is mostly used for cache keys, checksums and ids (0 of 13 field
// hits hashed a credential), so weak-hash is low/low. Kept in exact parity with the Opengrep rule (E34).
// 4.1 M7 (Ruling 10): both implementations report MD5/SHA-1 only in a credential context.
const RULE_METADATA = {
  [JAVASCRIPT_WEAK_HASH_RULE_ID]: {
    title: "Weak hashing algorithm (MD5/SHA1) used.",
    message: "Weak hashing algorithm (MD5/SHA1) used. Use SHA-256+ or a password KDF (bcrypt/scrypt/argon2) for credentials.\n",
    severity: "low",
    confidence: "low",
  },
  [JAVASCRIPT_WEAK_CIPHER_RULE_ID]: {
    title: "Deprecated password-based createCipher or weak cipher (DES/RC4/3DES) used.",
    message: "Deprecated password-based createCipher or weak cipher (DES/RC4/3DES) used. Use createCipheriv with a modern AEAD cipher, an independent random key, and a unique nonce.\n",
    severity: "medium",
    confidence: "medium",
  },
} as const;

/**
 * 4.1 M7 (Ruling 10): the credential words, matched as a word after camelCase / snake / kebab splitting,
 * never as a substring (footprint, spinner, tokenizer and bypass do not match). The Opengrep rule in
 * security-baseline/crypto.yaml carries the same regex sources (a unit test compares them).
 */
export const CREDENTIAL_WORDS = [
  "password", "passwd", "passphrase", "pwd", "pass", "secret", "token", "apikey",
  "credential", "credentials", "signature", "sig", "hmac", "salt",
] as const;

const wordForms = (word: string): string[] => {
  const capitalized = word[0]!.toUpperCase() + word.slice(1);
  return [`${word}(?![a-z])`, `${capitalized}(?![a-z])`, `${word.toUpperCase()}(?:(?![A-Za-z])|(?=[A-Z][a-z]))`];
};
const WORD_START = "(?:^|(?<=[^A-Za-z])|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z]))";
const API_KEY = "(?:api|Api|API)[_-]?(?:key(?![a-z])|Key(?![a-z])|KEY(?:(?![A-Za-z])|(?=[A-Z][a-z])))";
/** One credential word anywhere in a name, at word boundaries (api + key also as two words). */
export const CREDENTIAL_WORD_SOURCE = `${WORD_START}(?:${[API_KEY, ...CREDENTIAL_WORDS.flatMap(wordForms)].join("|")})`;
/** An identifier or member chain whose last name holds a credential word. */
const CREDENTIAL_CHAIN = `(?:[A-Za-z_$][\\w$]*\\.)*[\\w$]*?${CREDENTIAL_WORD_SOURCE}[\\w$]*`;
/** The whole text is such a chain (an update() argument, a template interpolation, a + operand). */
export const CREDENTIAL_CHAIN_SOURCE = `^\\s*${CREDENTIAL_CHAIN}\\s*$`;
/** An assignment / initialiser target or a property key (optionally quoted) named with a credential word. */
export const CREDENTIAL_TARGET_SOURCE = `^["']?${CREDENTIAL_CHAIN}["']?$`;
const CREDENTIAL_WORD = new RegExp(CREDENTIAL_WORD_SOURCE);
const CREDENTIAL_CHAIN_TEXT = new RegExp(CREDENTIAL_CHAIN_SOURCE);
const CREDENTIAL_TARGET = new RegExp(CREDENTIAL_TARGET_SOURCE);

export function hasCredentialWord(name: string): boolean {
  return CREDENTIAL_WORD.test(name);
}

const text = (document: JsDocument, first: JsToken, last: JsToken): string => document.content.slice(first.start, last.end);

// Tokens that may follow the right operand of `+` / precede its left operand without changing what that
// operand is (`a + b * c` makes b * c the operand; `a - b + c` makes a - b the left one).
const OPERAND_AFTER = new Set(["+", "-", ")", ",", "]", "}", ";", "?", ":", "===", "!==", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "??"]);
const OPERAND_BEFORE = new Set(["(", ",", "+", "[", "{", "?", ":", "=", "===", "!==", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "??"]);

/** (a) An update() argument that is, or holds as a template interpolation or a + operand, a credential chain. */
function credentialArgument(document: JsDocument, argument: JsExpression | undefined): boolean {
  if (!argument || argument.tokens.length === 0) return false;
  const tokens = argument.tokens;
  if (CREDENTIAL_CHAIN_TEXT.test(text(document, tokens[0]!, tokens[tokens.length - 1]!))) return true;
  const templates = tokens.filter((token) => token.kind === "template");
  // A template literal interpolating a plain name (`${password}`). Opengrep 1.33.1 does not match a member
  // expression there (`${user.password}`, probed), so for exact parity neither implementation does.
  for (const template of templates) {
    for (const match of template.raw.matchAll(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g)) if (CREDENTIAL_CHAIN_TEXT.test(match[1]!)) return true;
  }
  // Interpolated expressions are tokenized after their template token: leave them out of the operand scan.
  const plain = tokens.filter((token) => !templates.some((template) => token.start > template.start && token.end <= template.end));
  const isChainToken = (index: number, expectIdentifier: boolean): boolean =>
    expectIdentifier ? plain[index]?.kind === "identifier" : plain[index]?.value === ".";
  for (let index = 0; index < plain.length; index++) {
    if (plain[index]!.value !== "+") continue;
    let end = index + 1;
    if (isChainToken(end, true)) {
      while (isChainToken(end + 1, false) && isChainToken(end + 2, true)) end += 2;
      const next = plain[end + 1];
      if ((!next || OPERAND_AFTER.has(next.value)) && CREDENTIAL_CHAIN_TEXT.test(text(document, plain[index + 1]!, plain[end]!))) return true;
    }
    let start = index - 1;
    if (isChainToken(start, true)) {
      while (isChainToken(start - 1, false) && isChainToken(start - 2, true)) start -= 2;
      const before = plain[start - 1];
      if ((!before || OPERAND_BEFORE.has(before.value)) && CREDENTIAL_CHAIN_TEXT.test(text(document, plain[start]!, plain[index - 1]!))) return true;
    }
  }
  return false;
}

// After the whole createHash(...) chain: the expression must end there for (b).
const EXPRESSION_END = new Set([";", ",", ")", "}", "]"]);
const CONTINUES = new Set([".", "?.", "+", "-", "*", "/", "%", "**", "(", "[", "?", ":", "&&", "||", "??", "`", "=",
  "==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in", "|", "&", "^"]);

/** The credential contexts of ci-baseline-weak-hash (both implementations, nothing else). */
function credentialContext(document: JsDocument, call: JsCall, callAt: ReadonlyMap<number, JsCall>): boolean {
  const tokens = document.tokens;
  // (a) createHash(...).update(X, ...), chained.
  if (tokens[call.closeIndex + 1]?.value === "." && tokens[call.closeIndex + 2]?.value === "update") {
    const update = callAt.get(call.closeIndex + 2);
    if (update && credentialArgument(document, update.arguments[0])) return true;
  }
  // (b) the whole chain createHash(...)[.m(...)]{0,4} is assigned, initialised or a property value.
  let end = call.closeIndex;
  for (let chained = 0; chained < 4; chained++) {
    if (tokens[end + 1]?.value !== "." || tokens[end + 2]?.kind !== "identifier") break;
    const next = callAt.get(end + 2);
    if (!next) break;
    end = next.closeIndex;
  }
  const after = tokens[end + 1];
  const ends = !after || EXPRESSION_END.has(after.value) || (after.line > tokens[end]!.line && !CONTINUES.has(after.value));
  if (!ends) return false;
  let start = call.tokenIndex;
  while (tokens[start - 1]?.value === "." && tokens[start - 2]?.kind === "identifier") start -= 2;
  const before = tokens[start - 1];
  if (before?.value === "=") {
    let last = start - 2;
    // `const name: Type = ...`: skip a one-name type annotation.
    if (tokens[last]?.kind === "identifier" && tokens[last - 1]?.value === ":" && tokens[last - 2]?.kind === "identifier") last -= 2;
    if (tokens[last]?.kind !== "identifier") return false;
    let first = last;
    while (tokens[first - 1]?.value === "." && tokens[first - 2]?.kind === "identifier") first -= 2;
    return CREDENTIAL_TARGET.test(text(document, tokens[first]!, tokens[last]!));
  }
  if (before?.value === ":") {
    const key = tokens[start - 2];
    const opener = tokens[start - 3]?.value;
    if (!key || (key.kind !== "identifier" && key.kind !== "string") || (opener !== "{" && opener !== ",")) return false;
    return CREDENTIAL_TARGET.test(key.raw);
  }
  return false;
}

function fullLineSnippet(document: JsDocument, startLine: number, endLine: number): string {
  return document.content.split(/\r?\n/).slice(startLine - 1, endLine).join("\n");
}

function matchingRule(
  document: JsDocument,
  call: JsCall,
  callAt: ReadonlyMap<number, JsCall>,
): keyof typeof RULE_METADATA | undefined {
  if (call.callee === "createHash") {
    const algorithm = staticString(document, call.arguments[0], call.tokenIndex);
    if (["md5", "sha1"].includes(algorithm ?? "") && credentialContext(document, call, callAt)) return JAVASCRIPT_WEAK_HASH_RULE_ID;
  }
  if (call.callee === "createCipheriv") {
    const algorithm = staticString(document, call.arguments[0], call.tokenIndex);
    if (["des", "des-ede3", "rc4"].includes(algorithm ?? "")) return JAVASCRIPT_WEAK_CIPHER_RULE_ID;
  }
  if (call.callee === "createCipher") return JAVASCRIPT_WEAK_CIPHER_RULE_ID;
  return undefined;
}

function candidateFinding(
  document: JsDocument,
  call: JsCall,
  ruleId: keyof typeof RULE_METADATA,
): Finding {
  const endLine = document.tokens[call.closeIndex]?.line ?? call.line;
  const metadata = RULE_METADATA[ruleId];
  const findingFingerprint = fingerprint([
    "javascript-baseline-shadow",
    document.path,
    call.line,
    endLine,
    "CWE-327",
    ruleId,
  ]);
  return {
    id: findingFingerprint,
    fingerprint: findingFingerprint,
    title: metadata.title,
    severity: metadata.severity,
    engine: "codeinspectus-ai",
    engines: ["codeinspectus-ai"],
    rule_id: ruleId,
    cwe: ["CWE-327"],
    owasp_web: ["A02:2021"],
    location: {
      file: document.path,
      start_line: call.line,
      end_line: endLine,
      snippet: fullLineSnippet(document, call.line, endLine),
    },
    message: metadata.message,
    remediation: remediationForCwe(["CWE-327"]),
    frameworks: [],
    confidence: metadata.confidence,
    finding_kind: "sast",
    producer_components: ["shadow:javascript-baseline"],
  };
}

export interface JavaScriptBaselineCandidateResult {
  findings: Finding[];
  limitations: string[];
  gaps: NativeGapRecord[];
}

/** Candidate execution primitive; the registered pack and reconciler control normal-scan surfacing. */
export async function runJavaScriptBaselineCandidates(
  input: JavaScriptBaselineProjectInput,
): Promise<JavaScriptBaselineCandidateResult> {
  const project = await resolveJavaScriptBaselineProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    const calls = jsCalls(document);
    const callAt = new Map(calls.map((call) => [call.tokenIndex, call]));
    for (const call of calls) {
      const ruleId = matchingRule(document, call, callAt);
      if (ruleId) findings.push(candidateFinding(document, call, ruleId));
    }
  }
  return {
    findings: findings.sort((left, right) =>
      left.location.file.localeCompare(right.location.file) ||
      left.location.start_line - right.location.start_line ||
      left.location.end_line - right.location.end_line ||
      left.rule_id.localeCompare(right.rule_id)
    ),
    limitations: [...(project.limitations ?? [])],
    gaps: [...(project.gaps ?? [])],
  };
}
