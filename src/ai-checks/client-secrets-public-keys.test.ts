/**
 * CG-31 — §6.1 public-key allowlist stays authoritative in build output. Public-by-design
 * values that gitleaks/§6.1 can otherwise flag must STAY SILENT; real secrets still fire.
 * Temp-dir, per-file isolation so each class is asserted cleanly. (FAKE values, not real.)
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runClientSecretsCheck } from "./client-secrets.js";
import type { Finding } from "../types.js";

const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const ANON_JWT = `eyJhbGciOiJIUzI1NiJ9.${b64u({ role: "anon", iss: "supabase", ref: "abcd" })}.s1gFAKEs1gFAKEs1gFAKEs1gFAKE12`;
const SERVICE_JWT = `eyJhbGciOiJIUzI1NiJ9.${b64u({ role: "service_role", iss: "supabase", ref: "abcd" })}.s1gFAKEs1gFAKEs1gFAKEs1gFAKE12`;
// Top-level role anon but a NESTED app_metadata.role=service_role — the old substring check FP'd here.
const NESTED_ANON_JWT = `eyJhbGciOiJIUzI1NiJ9.${b64u({ app_metadata: { role: "service_role" }, role: "anon" })}.s1gFAKEs1gFAKEs1gFAKEs1gFAKE12`;
// A real service_role key whose payload is truncated (won't JSON.parse) — must STILL fire (fail-open).
const CORRUPT_SERVICE_JWT = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from('{"role":"service_role"', "utf8").toString("base64url")}.s1gFAKEs1gFAKEs1gFAKEs1gFAKE12`;
const FIREBASE_APIKEY = "AIzaSyB1234567890abcdefghijklmnopqrstuv"; // AIza + 35 (public Firebase web key shape)
const STRIPE_PK = "pk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP";
const STRIPE_SK = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP";

let dir: string;
const at = (findings: Finding[], file: string) => findings.filter((f) => f.location.file === `dist/${file}`);

describe("CG-31 §6.1 public-key allowlist in build output (FP class stays silent)", () => {
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ci-pubkeys-"));
    await mkdir(join(dir, "dist"), { recursive: true });
    await writeFile(join(dir, "dist", "anon.js"), `const k = "${ANON_JWT}";\n`);
    await writeFile(join(dir, "dist", "service.js"), `const k = "${SERVICE_JWT}";\n`);
    await writeFile(join(dir, "dist", "nested-anon.js"), `const k = "${NESTED_ANON_JWT}";\n`);
    await writeFile(join(dir, "dist", "corrupt-service.js"), `const k = "${CORRUPT_SERVICE_JWT}";\n`);
    await writeFile(
      join(dir, "dist", "firebase.js"),
      `const cfg = {apiKey:"${FIREBASE_APIKEY}",authDomain:"x.firebaseapp.com",projectId:"x",messagingSenderId:"1"};\n`,
    );
    await writeFile(join(dir, "dist", "bare-aiza.js"), `const k = "${FIREBASE_APIKEY}";\n`);
    await writeFile(join(dir, "dist", "pk.js"), `const k = "${STRIPE_PK}";\n`);
    await writeFile(join(dir, "dist", "sk.js"), `const k = "${STRIPE_SK}";\n`);
  }, 60000);
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("Supabase ANON key (public) → SILENT", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "anon.js")).toHaveLength(0);
  });

  test("Supabase SERVICE_ROLE key → fires (TP, critical)", async () => {
    const f = await runClientSecretsCheck(dir);
    const svc = at(f, "service.js");
    expect(svc.some((x) => x.rule_id === "ci-ai-supabase-service-role-client")).toBe(true);
    expect(svc.every((x) => x.severity === "critical")).toBe(true);
  });

  test("Firebase config apiKey (public web key in config context) → SILENT", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "firebase.js")).toHaveLength(0);
  });

  test("Stripe publishable pk_live → SILENT", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "pk.js")).toHaveLength(0);
  });

  test("Stripe sk_live (real secret) → fires (TP control), value stays redacted", async () => {
    const f = await runClientSecretsCheck(dir);
    const sk = at(f, "sk.js");
    expect(sk.some((x) => x.rule_id === "ci-ai-secret-in-bundle")).toBe(true);
    // Guardrail: the raw secret value must never appear in any surfaced field.
    expect(JSON.stringify(sk)).not.toContain(STRIPE_SK);
  });

  test("a BARE AIza with no firebase context still fires (could be a real GCP key — don't over-suppress)", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "bare-aiza.js").length).toBeGreaterThan(0);
  });

  test("nested app_metadata.role=service_role with top-level role=anon → SILENT (no substring FP)", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "nested-anon.js")).toHaveLength(0);
  });

  test("FAIL-OPEN: a service_role key with an undecodable payload STILL fires (never suppress on ambiguity)", async () => {
    const f = await runClientSecretsCheck(dir);
    expect(at(f, "corrupt-service.js").length).toBeGreaterThan(0);
  });
});
