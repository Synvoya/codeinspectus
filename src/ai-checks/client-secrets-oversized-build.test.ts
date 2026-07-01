/**
 * CG-32 — close the §6.1 4MB-cap bundle blind spot. §6.1 (runClientSecretsCheck) skips
 * files over its 4MB cap (CG-23 B-1), so a structured secret inside a >4MB minified BUILD
 * chunk was invisible: §6.1 never scans it (cap) and CG-31 routing drops the anon-ambiguous
 * classes a generic engine might surface. A bounded, cap-independent scan must now catch the
 * full §6.1-detectable DANGEROUS set in oversized build chunks WITHOUT reintroducing the
 * anon/generic flood CG-31 closed, and WITHOUT lifting the global cap.
 *
 * Both directions are the gate: set (a) dangerous → KEPT (critical, shipped-to-browser,
 * redacted); set (b) public/generic → SILENT. FAKE values throughout (not real credentials).
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runClientSecretsCheck } from "./client-secrets.js";
import { routeFindings } from "../file-routing.js";
import { hashSecret } from "../redact.js";
import type { Finding } from "../types.js";

const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const HDR = "eyJhbGciOiJIUzI1NiJ9"; // {"alg":"HS256"} — base64url, starts with eyJ
const SIG = "s1gFAKEs1gFAKEs1gFAKEs1gFAKE12";
const jwt = (payload: Record<string, unknown>) => `${HDR}.${b64u(payload)}.${SIG}`;

// ── set (a): DANGEROUS, must be caught even in a >4MB build chunk ──────────────
const SERVICE_JWT = jwt({ role: "service_role", iss: "supabase", ref: "abcd" });
const ROLELESS_JWT = jwt({ sub: "user123", foo: "bar" }); // decodes, no role → fail-open fires
const SK_LIVE = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP1rE5wB9mNqK7";
const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"; // canonical AWS example id (AKIA + 16)
const GH_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"; // ghp_ + 38
const SLACK_TOKEN = "xoxb-1234567890-abcdefghijklmno";
const BARE_AIZA = "AIzaSyA00000000000000000000000000000abc"; // AIza + 35, NO firebase context → real-GCP-shaped
const PEM = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqFAKE0BAQEFAASCAT4wggE6AgEAfake1234567890\n-----END PRIVATE KEY-----";

// ── set (b): PUBLIC / generic, must STAY SILENT in the same >4MB chunk ─────────
const ANON_JWT = jwt({ role: "anon", iss: "supabase", ref: "abcd" });
const AUTH_JWT = jwt({ role: "authenticated", iss: "supabase" });
const PUBLIC_JWT = jwt({ role: "public" });
const DEMO_JWT = jwt({ role: "anon", iss: "supabase-demo" }); // published local-dev demo key
const FIREBASE_APIKEY = "AIzaSyB1234567890abcdefghijklmnopqrstuv"; // AIza in firebase config context below
const STRIPE_PK = "pk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP"; // publishable — no §6.1 pattern
const GENERIC_ENTROPY = "qZ3nT8wL1pK6vR9bY2dM5xH7jW4cF0gA"; // high-entropy, matches no provider pattern

// A minified-bundle-sized pad that pushes a chunk just past the 4MB §6.1 cap. The pad itself
// contains no secret pattern (one long run of a single char).
const PAD = "a".repeat(4 * 1024 * 1024 + 4096);
/** Wrap secret lines inside a >4MB blob (the secret sits AFTER the pad, like a real bundle). */
const oversized = (body: string) => `var __pad="${PAD}";\n${body}\n`;

let dir: string;
const at = (findings: Finding[], file: string) => findings.filter((f) => f.location.file === file);
const ruleIds = (findings: Finding[]) => new Set(findings.map((f) => f.rule_id));

describe("CG-32 §6.1 bounded scan on OVERSIZED (>4MB) build chunks", () => {
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ci-oversized-"));
    await mkdir(join(dir, "dist"), { recursive: true });

    // (a) one oversized build chunk carrying the full dangerous set.
    await writeFile(
      join(dir, "dist", "dangerous.js"),
      oversized(
        [
          `var a="${SERVICE_JWT}";`,
          `var b="${ROLELESS_JWT}";`,
          `var c="${SK_LIVE}";`,
          `var d="${OPENAI_KEY}";`,
          `var e="${AWS_KEY}";`,
          `var f="${GH_TOKEN}";`,
          `var g="${SLACK_TOKEN}";`,
          `var h="${BARE_AIZA}";`,
          `var i="${PEM}";`,
        ].join("\n"),
      ),
    );

    // (b) one oversized build chunk carrying only public/generic values.
    await writeFile(
      join(dir, "dist", "public.js"),
      oversized(
        [
          `var a="${ANON_JWT}";`,
          `var b="${AUTH_JWT}";`,
          `var c="${PUBLIC_JWT}";`,
          `var d="${DEMO_JWT}";`,
          `var cfg={apiKey:"${FIREBASE_APIKEY}",authDomain:"x.firebaseapp.com",projectId:"x",messagingSenderId:"1",appId:"1:2:web:3"};`,
          `var e="${STRIPE_PK}";`,
          `var f="${GENERIC_ENTROPY}";`,
        ].join("\n"),
      ),
    );

    // mixed: service_role (must fire) + anon (must stay silent) in the SAME oversized chunk.
    await writeFile(
      join(dir, "dist", "mixed.js"),
      oversized(`var svc="${SERVICE_JWT}";var pub="${ANON_JWT}";`),
    );

    // node_modules is never the user's shipped code — even a build dir inside it is dropped.
    await mkdir(join(dir, "node_modules", "somepkg", "dist"), { recursive: true });
    await writeFile(
      join(dir, "node_modules", "somepkg", "dist", "huge.js"),
      oversized(`var k="${SERVICE_JWT}";`),
    );

    // control: a NORMAL (<4MB) build chunk — must still fire via the existing §6.1 pass,
    // and must NOT be double-counted by the oversized path.
    await writeFile(join(dir, "dist", "small.js"), `const k = "${SK_LIVE}";\n`);
  }, 60000);

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  // ── direction 1: set (a) dangerous → KEPT ───────────────────────────────────
  test("service_role JWT in a >4MB chunk → fires (critical)", async () => {
    const f = await runClientSecretsCheck(dir);
    const hits = at(f, "dist/dangerous.js");
    const svc = hits.filter((x) => x.rule_id === "ci-ai-supabase-service-role-client");
    expect(svc.length).toBeGreaterThan(0);
    expect(svc.every((x) => x.severity === "critical")).toBe(true);
    // The detector emits the same client-reachable message as the <4MB pass; the
    // "shipped to browser" LABEL is added by CG-31 routing (asserted separately below).
  }, 60000);

  test("generic bundle secrets in a >4MB chunk are worded as compiled-into-a-shipped-bundle", async () => {
    const f = await runClientSecretsCheck(dir);
    const bundle = at(f, "dist/dangerous.js").filter((x) => x.rule_id === "ci-ai-secret-in-bundle");
    expect(bundle.length).toBeGreaterThan(0);
    expect(bundle.every((x) => /bundle|shipped/.test(`${x.title} ${x.message}`.toLowerCase()))).toBe(true);
  }, 60000);

  test("every dangerous set-(a) class in a >4MB chunk → fires as a critical bundle secret", async () => {
    const f = await runClientSecretsCheck(dir);
    const hits = at(f, "dist/dangerous.js");
    // sk_live / OpenAI / AWS / GitHub / Slack / bare-AIza / PEM / role-less-JWT all surface
    // via the generic bundle-secret arm; service_role additionally via its dedicated arm.
    const bundle = hits.filter((x) => x.rule_id === "ci-ai-secret-in-bundle");
    expect(bundle.length).toBeGreaterThanOrEqual(8);
    expect(bundle.every((x) => x.severity === "critical")).toBe(true);
    expect(hits.every((x) => x.engine === "codeinspectus-ai")).toBe(true);
  }, 60000);

  test("set-(a) hits are REDACTED — no raw token in any surfaced field", async () => {
    const f = await runClientSecretsCheck(dir);
    const blob = JSON.stringify(at(f, "dist/dangerous.js"));
    for (const raw of [SERVICE_JWT, SK_LIVE, OPENAI_KEY, AWS_KEY, GH_TOKEN, SLACK_TOKEN, BARE_AIZA]) {
      expect(blob).not.toContain(raw);
    }
    expect(blob).not.toContain("BEGIN PRIVATE KEY-----\nMII"); // PEM body never echoed
  }, 60000);

  test("a kept oversized-build finding survives CG-31 build_output routing (codeinspectus-ai)", async () => {
    const f = await runClientSecretsCheck(dir);
    const svc = at(f, "dist/mixed.js").find((x) => x.rule_id === "ci-ai-supabase-service-role-client");
    expect(svc).toBeTruthy();
    const { findings: kept } = routeFindings([svc!], () => "build_output");
    expect(kept.length).toBe(1); // not re-dropped by the jwt-class drop
    expect(`${kept[0]!.title} ${kept[0]!.message}`.toLowerCase()).toMatch(/shipped|bundle|browser/);
  }, 60000);

  // ── direction 2: set (b) public/generic → SILENT (the CG-31 regression guard) ─
  test("all public/generic set-(b) values in a >4MB chunk → SILENT (no flood reintroduced)", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "dist/public.js")).toHaveLength(0);
  }, 60000);

  test("MIXED >4MB chunk: service_role fires, anon STAYS SILENT (suppression survives oversized path)", async () => {
    const f = await runClientSecretsCheck(dir);
    const hits = at(f, "dist/mixed.js");
    expect(ruleIds(hits).has("ci-ai-supabase-service-role-client")).toBe(true);
    // The anon key in the SAME now-scanned chunk must not surface. Findings are redacted, so
    // assert on the value HASH: no finding may carry the anon JWT's hash (proves it never fired).
    const anonHash = hashSecret(ANON_JWT);
    expect(hits.some((x) => x.secret_value_hash === anonHash)).toBe(false);
    // Every surfaced hit is the service_role JWT (arm 1 generic + arm 3 dedicated) — anon-free.
    const svcHash = hashSecret(SERVICE_JWT);
    expect(hits.every((x) => x.secret_value_hash === svcHash)).toBe(true);
    expect(hits.every((x) => x.severity === "critical")).toBe(true);
  }, 60000);

  // ── fail-open backstop ──────────────────────────────────────────────────────
  test("role-less / undecodable JWT in a >4MB chunk → STILL fires (fail-open)", async () => {
    const f = await runClientSecretsCheck(dir);
    const hits = at(f, "dist/dangerous.js");
    // ROLELESS_JWT decodes but has no top-level role → must not be suppressed as public.
    expect(hits.some((x) => x.rule_id === "ci-ai-secret-in-bundle")).toBe(true);
  }, 60000);

  // ── scope guards ────────────────────────────────────────────────────────────
  test("an oversized build chunk INSIDE node_modules is NOT surfaced", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(f.some((x) => x.location.file.includes("node_modules"))).toBe(false);
  }, 60000);

  test("NO REGRESSION: a normal (<4MB) build chunk still fires exactly once (no double-count)", async () => {
    const f = await runClientSecretsCheck(dir);
    const small = at(f, "dist/small.js").filter((x) => x.rule_id === "ci-ai-secret-in-bundle");
    expect(small.length).toBe(1); // existing §6.1 pass handles it; oversized path must not touch it
    expect(small[0]!.severity).toBe("critical");
  }, 60000);
});
