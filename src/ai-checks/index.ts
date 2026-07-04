/**
 * CodeInspectus AI-code checks runner (§6). Runs the three analyzers and returns
 * their findings plus a run-info record (engine: "codeinspectus-ai"). These are
 * pure TypeScript and require no external binary — they always run.
 */

import type { Finding, EngineRunInfo } from "../types.js";
import { CODEINSPECTUS_AI_VERSION } from "../config.js";
import { log } from "../logger.js";
import { runClientSecretsCheck } from "./client-secrets.js";
import { runSupabaseRlsCheck } from "./supabase-rls.js";
import { runPromptInjectionCheck } from "./prompt-injection.js";
import { runClientMetadataAuthzCheck } from "./metadata-authz.js";
import { runLlmDangerousHtmlCheck } from "./llm-dangerous-html.js";

export async function runAiChecks(
  target: string,
): Promise<{ findings: Finding[]; info: EngineRunInfo }> {
  const t0 = Date.now();
  const results = await Promise.allSettled([
    runClientSecretsCheck(target),
    runSupabaseRlsCheck(target),
    runPromptInjectionCheck(target),
    runClientMetadataAuthzCheck(target),
    runLlmDangerousHtmlCheck(target),
  ]);

  const findings: Finding[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") findings.push(...r.value);
    else log.warn("AI check failed:", r.reason);
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
  };
}
