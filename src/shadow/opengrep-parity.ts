import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { runOpengrep } from "../engines/opengrep.js";
import { runJavaScriptBaselineCandidates } from "../packs/javascript-baseline/index.js";
import { signature } from "../provenance.js";
import { normalizeEngineOutput } from "../sarif/normalize.js";
import type { Finding } from "../types.js";

const SELECTED_RULES = new Set([
  "ci-baseline-weak-hash",
  "ci-baseline-weak-cipher",
]);

export const JAVASCRIPT_BASELINE_CANDIDATE_SIGNATURE = signature(
  "javascript-baseline-shadow\0v2\0medium-confidence\0weak-hash(md5,sha1)\0weak-cipher(des,des-ede3,rc4,deprecated-createCipher)\0bounded-js-ts-structural-parser",
);

export interface ShadowIdentity {
  rule_id: string;
  file: string;
  start_line: number;
  end_line: number;
}

interface ShadowProjection extends ShadowIdentity {
  severity: Finding["severity"];
  cwe: string[];
  confidence: Finding["confidence"];
  finding_kind: Finding["finding_kind"];
  owasp_web: string[];
  owasp_api: string[];
  owasp_llm: string[];
  snippet: string;
  title: string;
  message: string;
  remediation: Finding["remediation"];
}

export interface ShadowMetadataMismatch {
  identity: ShadowIdentity;
  fields: string[];
}

export interface ShadowComparison {
  exact: boolean;
  reference_count: number;
  candidate_count: number;
  matched_count: number;
  reference_only: ShadowIdentity[];
  candidate_only: ShadowIdentity[];
  metadata_mismatches: ShadowMetadataMismatch[];
}

export interface OpengrepShadowReport {
  target: string;
  passed: boolean;
  opengrep: {
    version: string;
    available: boolean;
    ran: boolean;
    binary_signature?: string;
    ruleset_signature?: string;
    invocation_signature?: string;
    note?: string;
  };
  candidate_signature: string;
  candidate_limitations: string[];
  comparison: ShadowComparison;
}

function identity(finding: Finding): ShadowIdentity {
  return {
    rule_id: finding.rule_id,
    file: finding.location.file.replace(/\\/g, "/"),
    start_line: finding.location.start_line,
    end_line: finding.location.end_line,
  };
}

function projection(finding: Finding): ShadowProjection {
  return {
    ...identity(finding),
    severity: finding.severity,
    cwe: [...finding.cwe].sort(),
    confidence: finding.confidence,
    finding_kind: finding.finding_kind,
    owasp_web: [...(finding.owasp_web ?? [])].sort(),
    owasp_api: [...(finding.owasp_api ?? [])].sort(),
    owasp_llm: [...(finding.owasp_llm ?? [])].sort(),
    snippet: finding.location.snippet ?? "",
    title: finding.title,
    message: finding.message,
    remediation: finding.remediation,
  };
}

function identityKey(value: ShadowIdentity): string {
  return JSON.stringify([value.rule_id, value.file, value.start_line, value.end_line]);
}

function projectedIdentity(item: ShadowProjection): ShadowIdentity {
  return {
    rule_id: item.rule_id,
    file: item.file,
    start_line: item.start_line,
    end_line: item.end_line,
  };
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function changedFields(left: ShadowProjection, right: ShadowProjection): string[] {
  return Object.keys(left)
    .filter((key) => !["rule_id", "file", "start_line", "end_line"].includes(key))
    .filter((key) => stable(left[key as keyof ShadowProjection]) !== stable(right[key as keyof ShadowProjection]))
    .sort();
}

export function compareShadowFindings(
  referenceFindings: readonly Finding[],
  candidateFindings: readonly Finding[],
): ShadowComparison {
  const reference = referenceFindings.map(projection);
  const candidate = candidateFindings.map(projection);
  const keys = [...new Set([...reference, ...candidate].map(identityKey))].sort();
  const referenceOnly: ShadowIdentity[] = [];
  const candidateOnly: ShadowIdentity[] = [];
  const metadataMismatches: ShadowMetadataMismatch[] = [];
  let matchedCount = 0;

  for (const key of keys) {
    const left = reference.filter((item) => identityKey(item) === key).sort((a, b) => stable(a).localeCompare(stable(b)));
    const right = candidate.filter((item) => identityKey(item) === key).sort((a, b) => stable(a).localeCompare(stable(b)));
    const unmatchedRight = [...right];
    const unmatchedLeft: ShadowProjection[] = [];
    for (const item of left) {
      const exactIndex = unmatchedRight.findIndex((candidateItem) => stable(candidateItem) === stable(item));
      if (exactIndex >= 0) {
        unmatchedRight.splice(exactIndex, 1);
        matchedCount++;
      } else unmatchedLeft.push(item);
    }
    const pairs = Math.min(unmatchedLeft.length, unmatchedRight.length);
    for (let index = 0; index < pairs; index++) {
      metadataMismatches.push({
        identity: projectedIdentity(unmatchedLeft[index]!),
        fields: changedFields(unmatchedLeft[index]!, unmatchedRight[index]!),
      });
    }
    referenceOnly.push(...unmatchedLeft.slice(pairs).map(projectedIdentity));
    candidateOnly.push(...unmatchedRight.slice(pairs).map(projectedIdentity));
  }

  const exact = referenceOnly.length === 0 && candidateOnly.length === 0 &&
    metadataMismatches.length === 0 && reference.length === candidate.length;
  return {
    exact,
    reference_count: reference.length,
    candidate_count: candidate.length,
    matched_count: matchedCount,
    reference_only: referenceOnly,
    candidate_only: candidateOnly,
    metadata_mismatches: metadataMismatches,
  };
}

export async function runOpengrepShadowParity(target: string): Promise<OpengrepShadowReport> {
  const absoluteTarget = resolve(target);
  const canonicalTmp = await realpath(tmpdir());
  const managedTmp = await mkdtemp(join(canonicalTmp, "codeinspectus-opengrep-shadow-"));
  try {
    const [output, candidate] = await Promise.all([
      runOpengrep(absoluteTarget, managedTmp),
      runJavaScriptBaselineCandidates(absoluteTarget),
    ]);
    const reference = normalizeEngineOutput(output, absoluteTarget).filter((finding) => SELECTED_RULES.has(finding.rule_id));
    const comparison = compareShadowFindings(reference, candidate.findings);
    return {
      target: absoluteTarget,
      passed: output.available && output.ran && candidate.limitations.length === 0 && comparison.exact,
      opengrep: {
        version: output.version,
        available: output.available,
        ran: output.ran,
        binary_signature: output.componentSignatures?.["opengrep:binary"],
        ruleset_signature: output.componentSignatures?.["opengrep:ruleset"],
        invocation_signature: output.componentSignatures?.["opengrep:invocation"],
        ...(output.note ? { note: output.note } : {}),
      },
      candidate_signature: JAVASCRIPT_BASELINE_CANDIDATE_SIGNATURE,
      candidate_limitations: candidate.limitations,
      comparison,
    };
  } finally {
    await rm(managedTmp, { recursive: true, force: true });
  }
}
