import { runApiBoundaryChecks } from "../ai-checks/api-boundary.js";
import { runClientSecretsCheck } from "../ai-checks/client-secrets.js";
import { runLlmDangerousHtmlCheck } from "../ai-checks/llm-dangerous-html.js";
import { runClientMetadataAuthzCheck } from "../ai-checks/metadata-authz.js";
import { runPromptInjectionCheck } from "../ai-checks/prompt-injection.js";
import { runSecurityControlChecks } from "../ai-checks/security-controls.js";
import { runSupabaseRlsCheck } from "../ai-checks/supabase-rls.js";
import { runUnsafeToolExecutionCheck } from "../ai-checks/unsafe-tool-execution.js";
import type {
  NativeAnalyzer,
  NativeAnalyzerResult,
  NativeDetectorPack,
} from "./types.js";

async function findingsOnly(
  run: () => Promise<NativeAnalyzerResult["findings"]>,
): Promise<NativeAnalyzerResult> {
  return { findings: await run() };
}

function createJavaScriptAnalyzers(target: string): readonly NativeAnalyzer[] {
  return [
    {
      id: "client-secrets",
      components: ["ai:client-secrets"],
      ruleIds: [
        "ci-ai-client-hardcoded-secret",
        "ci-ai-secret-in-bundle",
        "ci-ai-public-env-secret",
        "ci-ai-supabase-service-role-client",
        "ci-ai-llm-key-browser-exposed",
      ],
      run: () => findingsOnly(() => runClientSecretsCheck(target)),
    },
    {
      id: "supabase-rls",
      components: ["ai:supabase-rls-policy-state", "ai:supabase-edge-auth"],
      ruleIds: [
        "ci-ai-rls-using-true",
        "ci-ai-rls-missing",
        "ci-ai-rls-inverted-auth",
        "ci-ai-edge-fn-no-auth",
        "ci-ai-storage-rls-public",
      ],
      run: () => findingsOnly(() => runSupabaseRlsCheck(target)),
    },
    {
      id: "prompt-injection",
      components: ["ai:prompt-injection"],
      ruleIds: ["ci-ai-prompt-injection-sink"],
      run: () => findingsOnly(() => runPromptInjectionCheck(target)),
    },
    {
      id: "unsafe-tool-execution",
      components: ["ai:unsafe-tool-execution"],
      ruleIds: ["ci-ai-llm-tool-argument-command-execution"],
      run: () => findingsOnly(() => runUnsafeToolExecutionCheck(target)),
    },
    {
      id: "client-metadata-authz",
      components: ["ai:client-metadata-authz"],
      ruleIds: ["ci-ai-client-metadata-authz"],
      run: () => findingsOnly(() => runClientMetadataAuthzCheck(target)),
    },
    {
      id: "llm-dangerous-html",
      components: ["ai:llm-dangerous-html"],
      ruleIds: ["ci-ai-llm-output-dangerous-html"],
      run: () => findingsOnly(() => runLlmDangerousHtmlCheck(target)),
    },
    {
      id: "api-boundary",
      components: [
        "ai:client-error-leak",
        "ai:sensitive-api-response",
        "ai:unvalidated-request-write",
        "ai:sensitive-log",
      ],
      ruleIds: [
        "ci-ai-client-error-leak",
        "ci-ai-sensitive-api-response",
        "ci-ai-unvalidated-request-write",
        "ci-ai-sensitive-log",
      ],
      run: () => findingsOnly(() => runApiBoundaryChecks(target)),
    },
    {
      id: "security-controls",
      components: [
        "ai:security-header-config",
        "ai:csp-config",
        "ai:session-cookie-config",
        "ai:supabase-captcha-integration",
      ],
      ruleIds: [
        "ci-ai-security-header-disabled",
        "ci-ai-unsafe-production-csp",
        "ci-ai-insecure-session-cookie",
        "ci-ai-supabase-captcha-token-missing",
      ],
      run: async (): Promise<NativeAnalyzerResult> => {
        const result = await runSecurityControlChecks(target);
        return { findings: result.findings, evidence: result.evidence };
      },
    },
  ];
}

/**
 * Existing V1 analyzers, grouped behind the native-pack contract without changing
 * their invocation order, component identities, or output behavior.
 */
export const javascriptPack: NativeDetectorPack = {
  id: "javascript-typescript",
  // Pack semantics are unchanged when the aggregate native engine gains other packs.
  version: "1.3.0",
  scannerKind: "ai",
  languages: ["javascript", "typescript", "sql"],
  frameworks: ["react", "nextjs", "vue", "svelte", "astro", "supabase"],
  platforms: [],
  limitations: [
    "Rule-specific static analysis only; listed languages and frameworks are not complete coverage claims.",
    "Client-secret checks also inspect selected HTML and framework component files; runtime-control checks inspect selected repository configuration shapes.",
    "Model-tool command execution analysis is intrafile, import-proven, and bounded to direct flow or one named local wrapper; cross-module dispatch and runtime sandbox/approval state are not resolved.",
  ],
  createAnalyzers: createJavaScriptAnalyzers,
};
