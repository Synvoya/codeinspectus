import type { Finding } from "../../types.js";
import { remediationForCwe } from "../../remediation.js";
import { fingerprint } from "../../util/hash.js";
import {
  jsCalls,
  staticString,
  type JsCall,
  type JsDocument,
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

const RULE_METADATA = {
  [JAVASCRIPT_WEAK_HASH_RULE_ID]: {
    title: "Weak hashing algorithm (MD5/SHA1) used.",
    message: "Weak hashing algorithm (MD5/SHA1) used. Use SHA-256+ or a password KDF (bcrypt/scrypt/argon2) for credentials.\n",
  },
  [JAVASCRIPT_WEAK_CIPHER_RULE_ID]: {
    title: "Deprecated password-based createCipher or weak cipher (DES/RC4/3DES) used.",
    message: "Deprecated password-based createCipher or weak cipher (DES/RC4/3DES) used. Use createCipheriv with a modern AEAD cipher, an independent random key, and a unique nonce.\n",
  },
} as const;

function fullLineSnippet(document: JsDocument, startLine: number, endLine: number): string {
  return document.content.split(/\r?\n/).slice(startLine - 1, endLine).join("\n");
}

function matchingRule(document: JsDocument, call: JsCall): keyof typeof RULE_METADATA | undefined {
  if (call.callee === "createHash") {
    const algorithm = staticString(document, call.arguments[0], call.tokenIndex);
    if (["md5", "sha1"].includes(algorithm ?? "")) return JAVASCRIPT_WEAK_HASH_RULE_ID;
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
    severity: "medium",
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
    confidence: "medium",
    finding_kind: "sast",
    producer_components: ["shadow:javascript-baseline"],
  };
}

export interface JavaScriptBaselineCandidateResult {
  findings: Finding[];
  limitations: string[];
}

/** Candidate execution primitive; the registered pack and reconciler control normal-scan surfacing. */
export async function runJavaScriptBaselineCandidates(
  input: JavaScriptBaselineProjectInput,
): Promise<JavaScriptBaselineCandidateResult> {
  const project = await resolveJavaScriptBaselineProject(input);
  const findings: Finding[] = [];
  for (const document of project.files) {
    for (const call of jsCalls(document)) {
      const ruleId = matchingRule(document, call);
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
  };
}
