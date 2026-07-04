/**
 * V1.5 — client-writable `user_metadata` used for authorization (CodeInspectus AI-code check).
 * CWE-639 (Authorization Bypass Through User-Controlled Key), + CWE-284 / CWE-863; OWASP A01:2021.
 * The first community-intake detection (docs/good-first-issues/user-metadata-authz-rule.md).
 *
 * The footgun: `if (user.user_metadata.role === 'admin')`. Supabase `user_metadata`
 * (a.k.a. `raw_user_meta_data`) is CLIENT-WRITABLE — any signed-in user can set it via
 * `PUT /auth/v1/user` / `supabase.auth.updateUser({ data })`, so they can self-assign
 * `role = 'admin'`. The correct, server-only field is `app_metadata` (`raw_app_meta_data`).
 *
 * Detection contract — fixtures/metadata-authz-corpus/CONTRACT.md (frozen before this analyzer):
 *   FIRES when a `user_metadata` / `raw_user_meta_data` value reaches an authorization guard via
 *     (A) a ROLE-ISH field (role|roles|is_admin|isAdmin|admin|permission|permissions|claims|
 *         is_staff|is_superuser) used in a comparison / `.includes()` / `if()` condition; OR
 *     (B) ANY field compared to a PRIVILEGED literal (admin|superadmin|owner|root|staff|...).
 *   Inline (single expression) and split-variable / destructured (intrafile taint) both fire.
 *   STAYS SILENT for `app_metadata` (server-only), entitlement feature gates (`plan === 'pro'`),
 *   plain display reads (a role badge/name), and non-authz fields. Ambiguity prefers silence.
 *
 * Honest framing: confidence is `medium` — static analysis cannot prove the gated branch is a
 * real security boundary. The hedge lives in the wording, not a dropped severity (it stays high).
 * Scope: intrafile only. Cross-file taint and whole-object metadata aliases are documented FNs.
 */

import type { Finding } from "../types.js";
import { collectFiles, lineText } from "./walk.js";
import { makeAiFinding } from "./finding.js";

// JS/TS app code, client AND server: an authz check keyed off client-writable metadata is wrong
// wherever it runs (unlike the client-only secret checks). node_modules is skipped by the walker.
const CODE_EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

// Client-writable metadata source spellings. app_metadata / raw_app_meta_data are deliberately
// ABSENT — they are the server-only correct field and must stay silent (the clean discriminator).
const META = "(?:user_metadata|raw_user_meta_data)";
const META_RE = new RegExp("\\b" + META + "\\b");

// Role/permission-ish field names — authz-semantic (arm A). Matched case-insensitively so
// is_admin / isAdmin / IsSuperuser all count. `plan` / `tier` are intentionally NOT here — they
// are entitlement fields (feature gates); they only fire against a privileged literal (arm B).
const ROLE_FIELD_RE =
  /^(?:role|roles|is_?admin|admin|permission|permissions|claims|is_?staff|is_?superuser)$/i;

// Privileged-role literal values (arm B). Anchored to the surrounding quotes at each call site so
// "administrator" is not shadowed by the "admin" alternative. Case-insensitive.
const PRIV_SRC = "admin|administrator|superadmin|super_admin|superuser|owner|root|staff|moderator|sysadmin";
const PRIV_CMP_RE = new RegExp("(?:===|!==|==|!=)\\s*['\"`](?:" + PRIV_SRC + ")['\"`]", "i");
const PRIV_CMP_REV_RE = new RegExp("['\"`](?:" + PRIV_SRC + ")['\"`]\\s*(?:===|!==|==|!=)", "i");
const PRIV_INCLUDES_RE = new RegExp("\\.(?:includes|some|indexOf)\\s*\\(\\s*['\"`](?:" + PRIV_SRC + ")['\"`]", "i");

// A metadata field access: `.field`, `?.field`, or `["field"]` off a user_metadata source.
const META_FIELD_ACCESS = new RegExp(
  META + "\\s*(?:\\?\\.\\s*|\\.\\s*)([A-Za-z0-9_$]+)|" + META + "\\s*\\[\\s*['\"]([A-Za-z0-9_$]+)['\"]\\s*\\]",
  "g",
);

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Line has a privileged-literal comparison (`x === 'admin'` / `'admin' === x` / `.includes('admin')`). */
function hasPrivilegedComparison(line: string): boolean {
  return PRIV_CMP_RE.test(line) || PRIV_CMP_REV_RE.test(line) || PRIV_INCLUDES_RE.test(line);
}

/** Does this line compare `token` to a privileged-role literal (arm B, taint path)? */
function comparedToPrivileged(line: string, token: string): boolean {
  const t = escapeRe(token);
  const lit = "['\"`](?:" + PRIV_SRC + ")['\"`]";
  return (
    new RegExp(t + "\\s*(?:===|!==|==|!=)\\s*" + lit, "i").test(line) ||
    new RegExp(lit + "\\s*(?:===|!==|==|!=)\\s*" + t + "\\b", "i").test(line) ||
    new RegExp(t + "(?:\\?\\.)?\\.(?:includes|startsWith|indexOf)\\s*\\(\\s*" + lit, "i").test(line)
  );
}

/** Is `token` used as a boolean/comparison GUARD on this line (arm A, taint path)? The token's own
 * declaration line is filtered out by the caller; `?.` and `??` do not count as a ternary. */
function usedAsGuard(line: string, token: string): boolean {
  const t = escapeRe(token);
  return (
    new RegExp(t + "\\s*(?:===|!==|==|!=)").test(line) ||
    new RegExp("(?:===|!==|==|!=)\\s*" + t + "\\b").test(line) ||
    new RegExp(t + "(?:\\?\\.)?\\.(?:includes|has|some|every|indexOf)\\s*\\(").test(line) ||
    new RegExp("\\b(?:if|while|else\\s+if)\\s*\\([^)]*\\b" + t + "\\b").test(line) ||
    new RegExp("\\b" + t + "\\s*\\?(?![?.:])").test(line) || // ternary test — NOT ?. / ?? / TS `?:`
    new RegExp("!\\s*" + t + "\\b").test(line)
  );
}

/** Line declares `token` (so an occurrence there is the assignment, not a guard use). */
function declaresVar(line: string, token: string): boolean {
  const t = escapeRe(token);
  return new RegExp("(?:const|let|var)\\s+(?:\\{[^}]*\\b" + t + "\\b[^}]*\\}|" + t + "\\b)\\s*=").test(line);
}

/** Vars assigned a `user_metadata`/`raw_user_meta_data` field (or destructured from it), mapped to
 * their originating field name (for the role-ish check). app_metadata never taints. Intrafile. */
function collectTaintedMetaVars(content: string): Map<string, string> {
  const tainted = new Map<string, string>();
  const dot = new RegExp(
    "(?:const|let|var)\\s+([A-Za-z0-9_$]+)\\s*=\\s*[^;\\n]*?" + META + "\\s*(?:\\?\\.\\s*|\\.\\s*)([A-Za-z0-9_$]+)",
    "g",
  );
  for (const m of content.matchAll(dot)) if (m[1] && m[2]) tainted.set(m[1], m[2]);
  const bracket = new RegExp(
    "(?:const|let|var)\\s+([A-Za-z0-9_$]+)\\s*=\\s*[^;\\n]*?" + META + "\\s*\\[\\s*['\"]([A-Za-z0-9_$]+)['\"]\\s*\\]",
    "g",
  );
  for (const m of content.matchAll(bracket)) if (m[1] && m[2]) tainted.set(m[1], m[2]);
  // const { role, plan: p } = <...>.user_metadata  — each binding tainted; field = property name.
  const destr = new RegExp("(?:const|let|var)\\s+\\{\\s*([^}]+?)\\s*\\}\\s*=\\s*[^;\\n]*?" + META + "\\b", "g");
  for (const m of content.matchAll(destr)) {
    for (const part of (m[1] ?? "").split(",")) {
      const [field, alias] = part.split(":").map((s) => s.trim());
      const varName = (alias || field || "").replace(/\s.*$/, "");
      const fieldName = (field || "").replace(/\s.*$/, "");
      if (varName && fieldName) tainted.set(varName, fieldName);
    }
  }
  return tainted;
}

export async function runClientMetadataAuthzCheck(target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(target, { exts: CODE_EXTS, includeBuilt: false });

  for (const f of files) {
    const content = f.content;
    if (!META_RE.test(content)) continue; // cheap pre-filter (also excludes app_metadata-only files)

    const tainted = collectTaintedMetaVars(content);
    const lines = content.split(/\r?\n/);
    const firedLines = new Set<number>(); // dedup: one finding per authz site (line)

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const lineNo = i + 1;
      let fire = false;

      // ── Inline: direct user_metadata field access(es) used in a guard on this line ──
      const fields: string[] = [];
      for (const am of line.matchAll(META_FIELD_ACCESS)) {
        const field = am[1] ?? am[2] ?? "";
        if (field) fields.push(field);
      }
      if (fields.length) {
        const hasCmp = /(?:===|!==|==|!=)/.test(line);
        const hasIncludes = /\.(?:includes|some|every|has|indexOf)\s*\(/.test(line);
        const inIfCond = /\b(?:if|while|else\s+if)\s*\(/.test(line);
        const hasTernary = /(?<!\?)\?(?![?.:])/.test(line); // real ternary, not ?. / ?? / TS `?:`
        const guardOnLine = hasCmp || hasIncludes || inIfCond || hasTernary;
        if (fields.some((fld) => ROLE_FIELD_RE.test(fld)) && guardOnLine) fire = true; // arm A
        if (hasPrivilegedComparison(line)) fire = true; // arm B (field vs privileged literal)
      }

      // ── Split-variable / destructured: a tainted metadata var used in a guard on this line ──
      if (!fire) {
        for (const [v, field] of tainted) {
          if (!new RegExp("\\b" + escapeRe(v) + "\\b").test(line)) continue;
          if (declaresVar(line, v)) continue; // the assignment line is not a guard use
          if (ROLE_FIELD_RE.test(field) && usedAsGuard(line, v)) fire = true; // arm A via taint
          if (comparedToPrivileged(line, v)) fire = true; // arm B via taint
          if (fire) break;
        }
      }

      if (fire) firedLines.add(lineNo);
    }

    for (const lineNo of firedLines) {
      findings.push(
        makeAiFinding({
          ruleId: "ci-ai-client-metadata-authz",
          title: "Authorization decision trusts client-writable user_metadata",
          severity: "high",
          cwe: ["CWE-639", "CWE-284", "CWE-863"],
          owasp_web: ["A01:2021"],
          file: f.rel,
          startLine: lineNo,
          snippet: lineText(content, lineNo),
          message:
            "This authorization decision reads `user_metadata`, which is client-writable — any " +
            "authenticated user can self-assign this value via the Supabase auth API " +
            "(`PUT /auth/v1/user` / `supabase.auth.updateUser`). If this gates a real security " +
            "action (not just UI display), it's a privilege-escalation bypass. Use the server-only " +
            "`app_metadata` for authorization. Verify whether this check protects a real boundary.",
          remediation: {
            summary:
              "Move the authorization check to the server-controlled `app_metadata` (set only via the " +
              "service role / admin API); never trust client-writable `user_metadata` for access control.",
            steps: [
              "Set the role/permission on `app_metadata` server-side (e.g. supabase.auth.admin.updateUserById with app_metadata).",
              "Change the check to read `app_metadata` (or `raw_app_meta_data`) instead of `user_metadata`.",
              "Enforce the decision server-side (RLS policy / API route), not only in client code.",
            ],
            references: [
              "CWE-639",
              "https://supabase.com/docs/guides/auth/managing-user-data#user-metadata",
            ],
          },
          confidence: "medium",
        }),
      );
    }
  }

  return findings;
}
