import { runApiBoundaryChecks } from "../ai-checks/api-boundary.js";
import { runClientSecretsAnalysis } from "../ai-checks/client-secrets.js";
import { runLlmDangerousHtmlCheck } from "../ai-checks/llm-dangerous-html.js";
import { runLlmDynamicExecutionCheck } from "../ai-checks/llm-dynamic-execution.js";
import { runNextjsAdminRouteAnalysis } from "../ai-checks/nextjs-admin-route.js";
import { runExpressAdminRouteAnalysis } from "../ai-checks/express-admin-route.js";
import { runClientMetadataAuthzCheck } from "../ai-checks/metadata-authz.js";
import { runPromptInjectionCheck } from "../ai-checks/prompt-injection.js";
import { runSecurityControlChecks } from "../ai-checks/security-controls.js";
import { runSupabaseRlsAnalysis } from "../ai-checks/supabase-rls.js";
import { runSupabaseEdgeAuthAnalysis } from "../ai-checks/supabase-edge-auth.js";
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
        "ci-ai-supabase-secret-key-client",
        "ci-ai-llm-key-browser-exposed",
      ],
      run: async (): Promise<NativeAnalyzerResult> => {
        const result = await runClientSecretsAnalysis(target);
        return {
          findings: result.findings,
          ...(result.notes.length ? { notes: result.notes } : {}),
        };
      },
    },
    {
      id: "supabase-rls",
      components: ["ai:supabase-rls-policy-state"],
      ruleIds: [
        "ci-ai-rls-using-true",
        "ci-ai-rls-missing",
        "ci-ai-rls-inverted-auth",
        "ci-ai-storage-rls-public",
      ],
      run: async (): Promise<NativeAnalyzerResult> => {
        const result = await runSupabaseRlsAnalysis(target);
        return {
          findings: result.findings,
          ...(result.notes.length ? { notes: result.notes } : {}),
        };
      },
    },
    {
      id: "supabase-edge-auth",
      components: [
        "pack:javascript-typescript:dispatch",
        "javascript:bounded-structural-parser",
        "ai:supabase-edge-auth",
      ],
      ruleIds: [
        "ci-ai-edge-fn-no-auth",
        "ci-ai-edge-fn-privileged-no-authz",
      ],
      run: async (): Promise<NativeAnalyzerResult> => {
        const result = await runSupabaseEdgeAuthAnalysis(target);
        return {
          findings: result.findings,
          ...(result.notes.length ? { notes: result.notes } : {}),
        };
      },
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
      id: "llm-dynamic-execution",
      components: ["ai:llm-dynamic-execution"],
      ruleIds: ["ci-ai-llm-output-dynamic-execution"],
      run: () => findingsOnly(() => runLlmDynamicExecutionCheck(target)),
    },
    {
      id: "nextjs-admin-route",
      components: [
        "pack:javascript-typescript:dispatch",
        "javascript:bounded-structural-parser",
        "ai:nextjs-admin-route",
      ],
      ruleIds: ["ci-ai-nextjs-admin-route-no-authz"],
      run: async (): Promise<NativeAnalyzerResult> => {
        const result = await runNextjsAdminRouteAnalysis(target);
        return {
          findings: result.findings,
          ...(result.notes.length ? { notes: result.notes } : {}),
        };
      },
    },
    {
      id: "express-admin-route",
      components: [
        "pack:javascript-typescript:dispatch",
        "javascript:bounded-structural-parser",
        "ai:express-admin-route",
      ],
      ruleIds: ["ci-ai-express-admin-route-no-authz"],
      run: async (): Promise<NativeAnalyzerResult> => {
        const result = await runExpressAdminRouteAnalysis(target);
        return {
          findings: result.findings,
          ...(result.notes.length ? { notes: result.notes } : {}),
        };
      },
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
        "ai:referrer-policy-config",
        "ai:permissions-policy-config",
        "ai:session-cookie-config",
        "ai:supabase-captcha-integration",
      ],
      ruleIds: [
        "ci-ai-security-header-disabled",
        "ci-ai-unsafe-production-csp",
        "ci-ai-unsafe-referrer-policy",
        "ci-ai-overbroad-permissions-policy",
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
  version: "1.9.0",
  scannerKind: "ai",
  languages: ["javascript", "typescript", "sql"],
  frameworks: ["react", "nextjs", "express", "vue", "svelte", "astro", "supabase"],
  platforms: [],
  limitations: [
    "Rule-specific static analysis only; listed languages and frameworks are not complete coverage claims.",
    "Client-secret checks also inspect selected HTML and framework component files; runtime-control checks inspect selected repository configuration shapes.",
    "Model-tool command execution analysis is intrafile, import-proven, and bounded to direct flow or one named local wrapper; cross-module dispatch and runtime sandbox/approval state are not resolved.",
    "General model-output execution analysis is intrafile and bounded to recognized SDK output plus global eval/Function or import-proven shell-string APIs; custom wrappers, streams, indirect aliases, and runtime controls are not resolved.",
    "Next.js admin-route analysis recognizes conventional Pages/App Router paths and handler-scoped terminating authentication plus server-role/permission denials; cross-file middleware and custom guard semantics are reported as coverage limits rather than guessed.",
    "Express admin-route analysis requires an import-proven Express receiver, an immediate literal admin path, and a direct naked handler; ambiguous middleware, mounted routers, dynamic paths, imported handlers, and generated/minified/vendor assets stay silent.",
    "Supabase Edge authentication analysis resolves literal per-function verify_jwt state and supported in-handler user, service, or signed-webhook checks; CLI deployment flags, dashboard overrides, custom wrappers, and deployed state are not resolved.",
  ],
  createAnalyzers: createJavaScriptAnalyzers,
};
