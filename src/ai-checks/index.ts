/**
 * CodeInspectus AI-code checks runner (§6). Runs the analyzers and returns
 * their findings plus a run-info record (engine: "codeinspectus-ai"). These are
 * pure TypeScript and require no external binary — they always run.
 */

import type {
  DetectedTechnology,
  DetectorPackCoverage,
  Finding,
  EngineRunInfo,
  SecurityControlEvidence,
} from "../types.js";
import { CODEINSPECTUS_AI_VERSION } from "../config.js";
import { log } from "../logger.js";
import { executeNativePacks } from "../packs/registry.js";
import type { NativeDetectorPack } from "../packs/types.js";
import { detectTechnologies } from "../technology-detection.js";
import {
  AI_INVOCATION_COMPONENT,
  PIPELINE_COMPONENT,
  aiFindingComponents,
  aiSignaturesForComponents,
} from "../provenance.js";

export interface RunAiChecksOptions {
  detectedTechnologies?: readonly DetectedTechnology[];
  packs?: readonly NativeDetectorPack[];
  scannerKinds?: readonly ("ai" | "sast")[];
}

export async function runAiChecks(
  target: string,
  options: RunAiChecksOptions = {},
): Promise<{
  findings: Finding[];
  info: EngineRunInfo;
  componentSignatures: Record<string, string>;
  securityControlEvidence: SecurityControlEvidence[];
  packCoverage: DetectorPackCoverage[];
}> {
  const t0 = Date.now();
  const detectedTechnologies = options.detectedTechnologies ??
    (await detectTechnologies(target)).detected_technologies;
  const { analyzers, results, packCoverage } = await executeNativePacks(target, {
    detectedTechnologies,
    packs: options.packs,
    scannerKinds: options.scannerKinds,
  });

  const findings: Finding[] = [];
  const securityControlEvidence: SecurityControlEvidence[] = [];
  const componentIds = new Set<string>([PIPELINE_COMPONENT, AI_INVOCATION_COMPONENT]);
  let analyzersRan = 0;
  for (const [index, r] of results.entries()) {
    if (r.status === "fulfilled") {
      analyzersRan++;
      analyzers[index]?.components.forEach((component) => componentIds.add(component));
      securityControlEvidence.push(...(r.value.evidence ?? []));
      for (const finding of r.value.findings) {
        const scannerKind = analyzers[index]?.packScannerKind ?? "ai";
        const components = aiFindingComponents(finding.rule_id, scannerKind);
        finding.producer_components = components;
        finding.finding_kind = finding.is_secret ? "secret" : scannerKind;
        components.forEach((component) => componentIds.add(component));
        findings.push(finding);
      }
    } else log.warn("AI check failed:", r.reason);
  }
  const failedAnalyzers = analyzers.length - analyzersRan;
  const failureNote = failedAnalyzers > 0
    ? `${failedAnalyzers} of ${analyzers.length} native analyzers failed.`
    : undefined;

  return {
    findings,
    info: {
      engine: "codeinspectus-ai",
      version: CODEINSPECTUS_AI_VERSION,
      available: true,
      ran: analyzersRan > 0,
      finding_count: findings.length,
      duration_ms: Date.now() - t0,
      ...(failureNote ? { note: failureNote } : {}),
    },
    componentSignatures: aiSignaturesForComponents([...componentIds]),
    securityControlEvidence,
    packCoverage,
  };
}
