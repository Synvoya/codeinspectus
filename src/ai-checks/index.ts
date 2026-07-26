/**
 * CodeInspectus AI-code checks runner (§6). Runs the analyzers and returns
 * their findings plus a run-info record (engine: "codeinspectus-ai"). These are
 * pure TypeScript and require no external binary — they always run.
 */

import type { Finding, EngineRunInfo, SecurityControlEvidence } from "../types.js";
import { CODEINSPECTUS_AI_VERSION } from "../config.js";
import { log } from "../logger.js";
import { runClientSecretsCheck } from "./client-secrets.js";
import { runSupabaseRlsCheck } from "./supabase-rls.js";
import { runPromptInjectionCheck } from "./prompt-injection.js";
import { runClientMetadataAuthzCheck } from "./metadata-authz.js";
import { runLlmDangerousHtmlCheck } from "./llm-dangerous-html.js";
import { runApiBoundaryChecks } from "./api-boundary.js";
import { runSecurityControlChecks } from "./security-controls.js";
import {
  AI_INVOCATION_COMPONENT,
  PIPELINE_COMPONENT,
  aiFindingComponents,
  aiSignaturesForComponents,
} from "../provenance.js";

export async function runAiChecks(
  target: string,
): Promise<{
  findings: Finding[];
  info: EngineRunInfo;
  componentSignatures: Record<string, string>;
  securityControlEvidence: SecurityControlEvidence[];
}> {
  const t0 = Date.now();
  interface AnalyzerResult {
    findings: Finding[];
    evidence?: SecurityControlEvidence[];
  }
  const findingsOnly = async (run: () => Promise<Finding[]>): Promise<AnalyzerResult> => ({
    findings: await run(),
  });
  const analyzers = [
    {
      components: ["ai:client-secrets"],
      run: () => findingsOnly(() => runClientSecretsCheck(target)),
    },
    {
      components: ["ai:supabase-rls-policy-state", "ai:supabase-edge-auth"],
      run: () => findingsOnly(() => runSupabaseRlsCheck(target)),
    },
    {
      components: ["ai:prompt-injection"],
      run: () => findingsOnly(() => runPromptInjectionCheck(target)),
    },
    {
      components: ["ai:client-metadata-authz"],
      run: () => findingsOnly(() => runClientMetadataAuthzCheck(target)),
    },
    {
      components: ["ai:llm-dangerous-html"],
      run: () => findingsOnly(() => runLlmDangerousHtmlCheck(target)),
    },
    {
      components: [
        "ai:client-error-leak",
        "ai:sensitive-api-response",
        "ai:unvalidated-request-write",
        "ai:sensitive-log",
      ],
      run: () => findingsOnly(() => runApiBoundaryChecks(target)),
    },
    {
      components: [
        "ai:security-header-config",
        "ai:csp-config",
        "ai:session-cookie-config",
        "ai:supabase-captcha-integration",
      ],
      run: async (): Promise<AnalyzerResult> => {
        const result = await runSecurityControlChecks(target);
        return { findings: result.findings, evidence: result.evidence };
      },
    },
  ];
  const results = await Promise.allSettled(analyzers.map((analyzer) => analyzer.run()));

  const findings: Finding[] = [];
  const securityControlEvidence: SecurityControlEvidence[] = [];
  const componentIds = new Set<string>([PIPELINE_COMPONENT, AI_INVOCATION_COMPONENT]);
  for (const [index, r] of results.entries()) {
    if (r.status === "fulfilled") {
      analyzers[index]?.components.forEach((component) => componentIds.add(component));
      securityControlEvidence.push(...(r.value.evidence ?? []));
      for (const finding of r.value.findings) {
        const components = aiFindingComponents(finding.rule_id);
        finding.producer_components = components;
        finding.finding_kind = finding.is_secret ? "secret" : "ai";
        components.forEach((component) => componentIds.add(component));
        findings.push(finding);
      }
    } else log.warn("AI check failed:", r.reason);
  }

  return {
    findings,
    info: {
      engine: "codeinspectus-ai",
      version: CODEINSPECTUS_AI_VERSION,
      available: true,
      ran: true,
      finding_count: findings.length,
      duration_ms: Date.now() - t0,
    },
    componentSignatures: aiSignaturesForComponents([...componentIds]),
    securityControlEvidence,
  };
}
