/**
 * Conservative Next.js admin API route guard check.
 *
 * Path evidence limits this to conventional Pages/App Router admin endpoints. The file must expose
 * a recognized handler and contain visible evidence of both authentication and a server-side
 * role/permission decision. Cross-file middleware and custom guard semantics remain unknown.
 */
import type { Finding } from "../types.js";
import { makeAiFinding } from "./finding.js";
import { collectFiles, lineOf, lineText } from "./walk.js";

const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
const RULE_ID = "ci-ai-nextjs-admin-route-no-authz";
const PAGES_ADMIN_RE = /(?:^|\/)(?:src\/)?pages\/api\/admin(?:\/[^/]+|\.[^/]+)$/;
const APP_ADMIN_RE = /(?:^|\/)(?:src\/)?app\/api\/admin(?:\/[^/]+)*\/route\.(?:[cm]?[jt]sx?)$/;
const PAGES_HANDLER_RE = /\bexport\s+default\s+(?:async\s+)?(?:function\b|[A-Za-z_$][\w$]*)/;
const APP_HANDLER_RE = /\bexport\s+(?:async\s+function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)\b/;

const AUTHENTICATION_RE =
  /\b(?:getServerSession|getSession|getToken|currentUser|verifyIdToken|verifySessionCookie|authenticate|requireAuth)\s*\(|\b(?:auth|withAuth)\s*\(|\b[A-Za-z_$][\w$]*\.auth\.getUser\s*\(|\b(?:req|request)\.auth\b/;
const AUTHENTICATION_DEFINITION_RE =
  /\bfunction\s+(?:getServerSession|getSession|getToken|currentUser|verifyIdToken|verifySessionCookie|authenticate|requireAuth|auth|withAuth)\s*\(/;
const AUTHZ_HELPER_RE =
  /\b(?:requireRole|requirePermission|authorize|assertAuthorized|assertPermission|hasPermission|withRole|withPermission)\s*\(/i;
const AUTHZ_HELPER_DEFINITION_RE =
  /\bfunction\s+(?:requireRole|requirePermission|authorize|assertAuthorized|assertPermission|hasPermission|withRole|withPermission)\s*\(/i;
const PRIVILEGED_LITERAL_RE = /["'](?:admin|administrator|superadmin|super_admin|superuser|owner|root|staff|moderator|sysadmin)["']/i;
const SERVER_ROLE_RE =
  /\b(?:session(?:\?\.)?\.user|user|account|principal|claims|token)(?:\?\.)?\.(?:app_metadata\.)?(?:role|roles|permissions?|is_?admin)\b|\b(?:app_metadata|raw_app_meta_data)(?:\?\.)?\.(?:role|roles|permissions?|is_?admin)\b/i;
const PERMISSION_DECISION_RE = /\b(?:permissions?|roles)(?:\?\.)?\.(?:includes|has|some|indexOf)\s*\(/i;

function isAdminRoute(path: string): "pages" | "app" | undefined {
  if (APP_ADMIN_RE.test(path)) return "app";
  if (PAGES_ADMIN_RE.test(path)) return "pages";
  return undefined;
}

function handlerIndex(content: string, kind: "pages" | "app"): number | undefined {
  const match = (kind === "pages" ? PAGES_HANDLER_RE : APP_HANDLER_RE).exec(content);
  return match?.index;
}

function hasAuthorization(content: string): boolean {
  for (const line of content.split(/\r?\n/)) {
    if (AUTHZ_HELPER_RE.test(line) && !AUTHZ_HELPER_DEFINITION_RE.test(line)) return true;
    if (/\b(?:user_metadata|raw_user_meta_data)\b/.test(line)) continue;
    const decision = /\b(?:if|switch)\s*\(|\?(?![?.])/.test(line);
    if (!decision) continue;
    if (SERVER_ROLE_RE.test(line) && (PRIVILEGED_LITERAL_RE.test(line) || PERMISSION_DECISION_RE.test(line))) {
      return true;
    }
    if (PERMISSION_DECISION_RE.test(line)) return true;
  }
  return false;
}

function hasAuthentication(content: string): boolean {
  return content.split(/\r?\n/).some(
    (line) => AUTHENTICATION_RE.test(line) && !AUTHENTICATION_DEFINITION_RE.test(line),
  );
}

export async function runNextjsAdminRouteCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false })) {
    const kind = isAdminRoute(file.rel);
    if (!kind) continue;
    const index = handlerIndex(file.content, kind);
    if (index === undefined) continue;

    const authenticated = hasAuthentication(file.content);
    const authorized = hasAuthorization(file.content);
    if (authenticated && authorized) continue;

    const missing = !authenticated && !authorized
      ? "authentication and authorization"
      : !authenticated
        ? "authentication"
        : "authorization";
    const line = lineOf(file.content, index);
    findings.push(
      makeAiFinding({
        ruleId: RULE_ID,
        title: "Next.js admin API route lacks a visible authentication/authorization boundary",
        severity: "high",
        confidence: "medium",
        cwe: ["CWE-862", "CWE-863", "CWE-306"],
        owasp_web: ["A01:2021"],
        owasp_api: ["API5:2023"],
        file: file.rel,
        startLine: line,
        snippet: lineText(file.content, line),
        message:
          `This conventional Next.js admin API handler has no recognized in-file ${missing} check. ` +
          "Client-writable Supabase user_metadata is not authorization evidence. Cross-file middleware or custom guards may exist, so verify the deployed route boundary manually.",
        remediation: {
          summary:
            "Authenticate the caller and enforce a server-controlled role or permission decision before any privileged operation.",
          steps: [
            "Resolve the authenticated user from a server-side session or verified token and reject missing/invalid identity.",
            "Check a server-controlled role or permission (for Supabase, use app_metadata rather than user_metadata) and reject unauthorized callers.",
            "Keep the guard adjacent to the handler or use a reviewed shared wrapper, then test both unauthenticated and insufficient-role requests.",
          ],
          references: [
            "CWE-862",
            "CWE-863",
            "CWE-306",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
          ],
        },
      }),
    );
  }
  return findings;
}
