import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import {
  aiFindingComponents,
  invocationSignature,
  rulesetSignature,
  sha256FileStreaming,
} from "./provenance.js";
import { runAiChecks } from "./ai-checks/index.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("component signatures", () => {
  test("four RLS reducer rules share one component while edge auth remains separate", () => {
    for (const rule of [
      "ci-ai-rls-missing",
      "ci-ai-rls-using-true",
      "ci-ai-storage-rls-public",
      "ci-ai-rls-inverted-auth",
    ]) {
      expect(aiFindingComponents(rule)).toContain("ai:supabase-rls-policy-state");
      expect(aiFindingComponents(rule)).not.toContain("ai:supabase-edge-auth");
    }
    expect(aiFindingComponents("ci-ai-edge-fn-no-auth")).toContain("ai:supabase-edge-auth");
    expect(aiFindingComponents("ci-ai-edge-fn-no-auth")).not.toContain("ai:supabase-rls-policy-state");
  });

  test("ruleset signature changes with detector content but ignores non-rule documentation", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-provenance-rules-"));
    dirs.push(dir);
    await writeFile(join(dir, "rules.yaml"), "rules: []\n", "utf8");
    await writeFile(join(dir, "README.md"), "first\n", "utf8");
    const first = await rulesetSignature(dir);
    await writeFile(join(dir, "README.md"), "second\n", "utf8");
    expect(await rulesetSignature(dir)).toBe(first);
    await writeFile(join(dir, "rules.yaml"), "rules:\n  - id: changed\n", "utf8");
    expect(await rulesetSignature(dir)).not.toBe(first);
  });

  test("Trivy DB helper computes a content digest and invocation signatures include flags", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-provenance-db-"));
    dirs.push(dir);
    const db = join(dir, "trivy.db");
    await writeFile(db, "db-content", "utf8");
    expect(await sha256FileStreaming(db)).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(invocationSignature("trivy", ["--offline-scan"]))
      .not.toBe(invocationSignature("trivy", ["--offline-scan", "--skip-check-update"]));
  });

  test("a successful zero-finding AI pass still records every analyzer component", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-provenance-ai-"));
    dirs.push(dir);
    const result = await runAiChecks(dir);
    expect(result.findings).toEqual([]);
    expect(Object.keys(result.componentSignatures)).toEqual(expect.arrayContaining([
      "codeinspectus:pipeline",
      "codeinspectus-ai:invocation",
      "ai:client-secrets",
      "ai:supabase-rls-policy-state",
      "ai:supabase-edge-auth",
      "ai:prompt-injection",
      "ai:client-metadata-authz",
      "ai:llm-dangerous-html",
      "ai:client-error-leak",
      "ai:sensitive-api-response",
      "ai:unvalidated-request-write",
      "ai:sensitive-log",
      "ai:security-header-config",
      "ai:csp-config",
      "ai:session-cookie-config",
      "ai:supabase-captcha-integration",
    ]));
  });

  test("each API-boundary rule has a dedicated rescan component", () => {
    expect(aiFindingComponents("ci-ai-client-error-leak")).toContain("ai:client-error-leak");
    expect(aiFindingComponents("ci-ai-sensitive-api-response")).toContain("ai:sensitive-api-response");
    expect(aiFindingComponents("ci-ai-unvalidated-request-write")).toContain("ai:unvalidated-request-write");
    expect(aiFindingComponents("ci-ai-sensitive-log")).toContain("ai:sensitive-log");
  });

  test("each Enhancement 2 rule has a dedicated rescan component", () => {
    expect(aiFindingComponents("ci-ai-security-header-disabled")).toContain("ai:security-header-config");
    expect(aiFindingComponents("ci-ai-unsafe-production-csp")).toContain("ai:csp-config");
    expect(aiFindingComponents("ci-ai-insecure-session-cookie")).toContain("ai:session-cookie-config");
    expect(aiFindingComponents("ci-ai-supabase-captcha-token-missing")).toContain(
      "ai:supabase-captcha-integration",
    );
  });
});
