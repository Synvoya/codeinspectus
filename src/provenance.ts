/**
 * Detection-component provenance for conservative rescan classification.
 * Signatures identify detector inputs, not user findings or secret contents.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";

import { MANAGED_PROVENANCE, MANAGED_TRIVY_DB, MANAGED_TRIVY_DB_PROVENANCE } from "./config.js";
import type { Engine, FindingKind } from "./types.js";

export const PIPELINE_COMPONENT = "codeinspectus:pipeline";
export const AI_INVOCATION_COMPONENT = "codeinspectus-ai:invocation";

const COMPONENT_REVISIONS: Record<string, string> = {
  [PIPELINE_COMPONENT]: "2:normalize-dedup-routing-envelope",
  [AI_INVOCATION_COMPONENT]: "1:all-analyzers-no-target-flags",
  "ai:client-secrets": "3:source-built-and-oversized-bundle-secret-state",
  "ai:supabase-rls-policy-state": "2:effective-migration-state",
  "ai:supabase-edge-auth": "1:request-serving-auth-check",
  "ai:prompt-injection": "1:prompt-sink-analysis",
  "ai:client-metadata-authz": "1:client-metadata-authz",
  "ai:llm-dangerous-html": "1:dangerous-html-flow",
};

const AI_RULE_COMPONENT: Record<string, string> = {
  "ci-ai-client-hardcoded-secret": "ai:client-secrets",
  "ci-ai-secret-in-bundle": "ai:client-secrets",
  "ci-ai-public-env-secret": "ai:client-secrets",
  "ci-ai-llm-key-browser-exposed": "ai:client-secrets",
  "ci-ai-supabase-service-role-client": "ai:client-secrets",
  "ci-ai-rls-missing": "ai:supabase-rls-policy-state",
  "ci-ai-rls-using-true": "ai:supabase-rls-policy-state",
  "ci-ai-storage-rls-public": "ai:supabase-rls-policy-state",
  "ci-ai-rls-inverted-auth": "ai:supabase-rls-policy-state",
  "ci-ai-edge-fn-no-auth": "ai:supabase-edge-auth",
  "ci-ai-prompt-injection-sink": "ai:prompt-injection",
  "ci-ai-client-metadata-authz": "ai:client-metadata-authz",
  "ci-ai-llm-output-dangerous-html": "ai:llm-dangerous-html",
};

export function signature(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export async function fileSignature(path: string): Promise<string> {
  return signature(await readFile(path));
}

/** Stable digest of detector-rule files: normalized relative path + content digest. */
export async function rulesetSignature(root: string): Promise<string> {
  const entries: string[] = [];
  async function walk(dir: string): Promise<void> {
    const children = await readdir(dir, { withFileTypes: true });
    for (const child of children.sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = join(dir, child.name);
      if (child.isDirectory()) await walk(abs);
      else if (child.isFile() && [".yaml", ".yml", ".json"].includes(extname(child.name).toLowerCase())) {
        const rel = relative(root, abs).replace(/\\/g, "/");
        entries.push(`${rel}\0${await fileSignature(abs)}`);
      }
    }
  }
  await walk(root);
  return signature(entries.join("\n"));
}

export function invocationSignature(producer: string, semanticArgs: readonly string[]): string {
  return signature(JSON.stringify({ producer, args: semanticArgs }));
}

export function staticComponentSignatures(componentIds: readonly string[]): Record<string, string> {
  return Object.fromEntries(componentIds.map((id) => {
    const revision = COMPONENT_REVISIONS[id];
    if (!revision) throw new Error(`No semantic revision registered for detector component '${id}'.`);
    return [id, signature(`${id}\0${revision}`)];
  }));
}

export function aiComponentForRule(ruleId: string): string {
  return AI_RULE_COMPONENT[ruleId] ?? "ai:unmapped-rule";
}

export function aiFindingComponents(ruleId: string): string[] {
  return [PIPELINE_COMPONENT, AI_INVOCATION_COMPONENT, aiComponentForRule(ruleId)];
}

export function aiSignaturesForComponents(componentIds: readonly string[]): Record<string, string> {
  return staticComponentSignatures([...new Set(componentIds)]);
}

export function externalFindingComponents(engine: Engine, kind: FindingKind): string[] {
  const base = [PIPELINE_COMPONENT, `${engine}:binary`, `${engine}:invocation`];
  if (engine === "opengrep") return [...base, "opengrep:ruleset"];
  if (engine === "gitleaks") return [...base, "gitleaks:config", "gitleaks:effective-ignore"];
  if (engine === "trivy") {
    const components = [...base, "trivy:checks"];
    if (kind === "vulnerability") components.push("trivy:vulnerability-db");
    return components;
  }
  return base;
}

export async function sha256FileStreaming(path: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return `sha256:${hash.digest("hex")}`;
}

/** Called only after install-engines downloads the DB; never hashes the 1.1GB DB during scans. */
export async function recordTrivyDbContentDigest(): Promise<string> {
  const digest = await sha256FileStreaming(MANAGED_TRIVY_DB);
  await mkdir(join(MANAGED_PROVENANCE, "trivy"), { recursive: true });
  await writeFile(
    MANAGED_TRIVY_DB_PROVENANCE,
    JSON.stringify({ component: "trivy:vulnerability-db", signature: digest, recorded_at: new Date().toISOString() }),
    "utf8",
  );
  return digest;
}

/** Small metadata read at scan time. Missing metadata means DB equivalence cannot be proven. */
export async function readTrivyDbContentDigest(): Promise<string | undefined> {
  try {
    const parsed = JSON.parse(await readFile(MANAGED_TRIVY_DB_PROVENANCE, "utf8")) as { signature?: unknown };
    return typeof parsed.signature === "string" && /^sha256:[a-f0-9]{64}$/.test(parsed.signature)
      ? parsed.signature
      : undefined;
  } catch {
    return undefined;
  }
}
