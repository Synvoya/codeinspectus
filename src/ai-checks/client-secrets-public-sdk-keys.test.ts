/**
 * 4.1 M9 Task 4 — public SDK keys behind a client prefix, server-only config files, and PEM markers.
 *
 * Each precision fix sits next to a real variant that must keep firing: a public-key name that also says
 * SECRET/ADMIN/AUTH_TOKEN, an LLM key, and a complete private key (generated per run, never committed).
 */

import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runClientSecretsCheck } from "./client-secrets.js";
import type { Finding } from "../types.js";

let dir: string;
let findings: Finding[];

const at = (file: string, rule?: string) =>
  findings.filter((f) => f.location.file === file && (!rule || f.rule_id === rule));

// A freshly generated test key: complete PEM key material, created at test time only.
const TEST_PEM = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  .privateKey.export({ type: "pkcs8", format: "pem" }).toString();

const PEM_LINES = TEST_PEM.trim().split("\n");

const FILES: Record<string, string> = {
  // Public by the provider's own documentation: silent.
  "src/maps.tsx": "export const mapsKey = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY ?? '';\n",
  "src/analytics.ts": "export const mixpanel = import.meta.env.VITE_MIXPANEL_TOKEN;\n",
  "app/lib/purchases.ts": "export const keys = { ios: process.env.EXPO_PUBLIC_REVENUECAT_IOS_API_KEY };\n",
  "src/search.ts": "export const algolia = process.env.NEXT_PUBLIC_ALGOLIA_SEARCH_API_KEY;\n",
  "src/map-box.ts": "export const mapbox = import.meta.env.VITE_MAPBOX_PUBLIC_TOKEN;\n",
  "src/map-box-web.ts": "export const mapbox = import.meta.env.VITE_MAPBOX_WEB_ACCESS_TOKEN;\n",
  "src/posthog.ts": "export const ph = process.env.NEXT_PUBLIC_POSTHOG_API_KEY;\n",
  "src/amplitude.ts": "export const amp = process.env.REACT_APP_AMPLITUDE_API_KEY;\n",
  // Server-only configuration: PM2 process env and Nuxt private runtimeConfig.
  "ecosystem.config.cjs": [
    "module.exports = { apps: [{ name: 'web', env: {",
    "  NUXT_GITHUB_TOKEN: process.env.NUXT_PUBLIC_GITHUB_TOKEN || process.env.GITHUB_TOKEN,",
    "} }] };",
    "",
  ].join("\n"),
  "nuxt.config.ts": [
    "export default defineNuxtConfig({",
    "  runtimeConfig: {",
    "    apiSecret: process.env.NUXT_PUBLIC_API_SECRET,",
    "    githubToken: process.env.NUXT_PUBLIC_GITHUB_TOKEN || process.env.GITHUB_TOKEN,",
    "    public: {",
    "      uploadToken: process.env.NUXT_PUBLIC_UPLOAD_TOKEN,",
    "    },",
    "  },",
    "});",
    "",
  ].join("\n"),
  // PEM markers without key material: silent.
  "src/pem.ts": [
    "export function pemToDer(pem: string): string {",
    "  return pem",
    "    .replace(/-----BEGIN PRIVATE KEY-----/g, \"\")",
    "    .replace(/-----END PRIVATE KEY-----/g, \"\")",
    "    .replace(/\\s/g, \"\");",
    "}",
    "export function derToPem(b64: string): string {",
    "  const lines = [\"-----BEGIN PRIVATE KEY-----\"];",
    "  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));",
    "  lines.push(\"-----END PRIVATE KEY-----\");",
    "  return lines.join(\"\\n\");",
    "}",
    "",
  ].join("\n"),
  // Real variants that must keep firing.
  "src/stripe.ts": "export const s = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n",
  "src/maps-admin.ts": "export const m = import.meta.env.VITE_MAPS_ADMIN_API_KEY;\n",
  "src/maps-secret.ts": "export const m = process.env.NEXT_PUBLIC_GOOGLE_MAPS_SECRET_API_KEY;\n",
  "src/openai.ts": "export const o = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n",
  "src/sentry.ts": "export const t = import.meta.env.VITE_SENTRY_AUTH_TOKEN;\n",
  "src/algolia-admin.ts": "export const a = process.env.NEXT_PUBLIC_ALGOLIA_ADMIN_API_KEY;\n",
  "src/posthog-personal.ts": "export const p = process.env.NEXT_PUBLIC_POSTHOG_PERSONAL_API_KEY;\n",
  "src/nuxt-client.ts": "export const g = process.env.NUXT_PUBLIC_GITHUB_TOKEN;\n",
  // Fix round 1 (review item 11): Mapbox and RevenueCat need PUBLIC or a platform qualifier; SERVER, MASTER and
  // PERSONAL names are never public.
  "src/mapbox-any.ts": "export const m = import.meta.env.VITE_MAPBOX_ACCESS_TOKEN;\n",
  "src/revenuecat-any.ts": "export const r = process.env.EXPO_PUBLIC_REVENUECAT_API_KEY;\n",
  "src/maps-server.ts": "export const m = process.env.NEXT_PUBLIC_GOOGLE_MAPS_SERVER_API_KEY;\n",
  "src/algolia-master.ts": "export const a = process.env.NEXT_PUBLIC_ALGOLIA_SEARCH_MASTER_API_KEY;\n",
  "src/amplitude-personal.ts": "export const a = process.env.REACT_APP_AMPLITUDE_PERSONAL_API_KEY;\n",
  "src/key.ts": `export const signingKey = \`${TEST_PEM}\`;\n`,
  // Security review (M9): a header-only decoy before a real key, and a key split across concatenated strings.
  "src/key-decoy.ts": [
    "export const strip = (pem: string) => pem.replace(\"-----BEGIN PRIVATE KEY-----\", \"\");",
    `export const signingKey = \`${TEST_PEM}\`;`,
    "",
  ].join("\n"),
  "src/key-concat.ts": `export const signingKey =\n  ${PEM_LINES.map((line) => JSON.stringify(`${line}\n`)).join(" +\n  ")};\n`,
  // Fix round 1 (review item 9): a service-account JSON embedded in a JS string, so `\\n` and `\/` are double-escaped.
  "src/key-service-account.ts": `export const serviceAccount = "{\\"type\\":\\"service_account\\",\\"private_key\\":\\"${PEM_LINES.map((line) => line.replace(/\//g, "\\\\/")).join("\\\\n")}\\\\n\\"}";\n`,
  "src/key-array.ts": `export const signingKey = [\n  ${PEM_LINES.map((line) => JSON.stringify(line)).join(",\n  ")},\n].join("\\n");\n`,
  // Security review (M9): Nuxt runtimeConfig.app and a quoted "public" key are client-exposed; a `public`
  // object nested deeper than runtimeConfig's direct child is private.
  "nuxt-app/nuxt.config.ts": [
    "export default defineNuxtConfig({",
    "  runtimeConfig: {",
    "    stripe: { public: { hookSecret: process.env.NUXT_PUBLIC_HOOK_SECRET } },",
    "    app: {",
    "      cdnToken: process.env.NUXT_PUBLIC_CDN_TOKEN,",
    "    },",
    "    'public': {",
    "      mapsSecret: process.env.NUXT_PUBLIC_MAPS_SECRET,",
    "    },",
    "  },",
    "});",
    "",
  ].join("\n"),
  "nuxt-app/package.json": "{}\n",
  // Security review (M9): the PM2 exemption needs a root or package-root file with PM2 shape.
  "web/ecosystem.config.js": "module.exports = { apps: [{ env: { T: process.env.NEXT_PUBLIC_GITHUB_TOKEN } }] };\n",
  "pkg/package.json": "{}\n",
  "pkg/ecosystem.config.js": "module.exports = { apps: [{ env: { T: process.env.NEXT_PUBLIC_GITHUB_TOKEN } }] };\n",
  "tools/package.json": "{}\n",
  "tools/ecosystem.config.cjs": "module.exports = { env: { T: process.env.NEXT_PUBLIC_GITHUB_TOKEN } };\n",
};

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ci-public-sdk-keys-"));
  for (const [rel, content] of Object.entries(FILES)) {
    await mkdir(dirname(join(dir, rel)), { recursive: true });
    await writeFile(join(dir, rel), content);
  }
  findings = await runClientSecretsCheck(dir);
}, 60_000);

afterAll(async () => {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
});

describe("public-env-secret: documented public SDK keys (closed table)", () => {
  test.each([
    "src/maps.tsx", "src/analytics.ts", "app/lib/purchases.ts", "src/search.ts", "src/map-box.ts", "src/map-box-web.ts",
    "src/posthog.ts", "src/amplitude.ts",
  ])("%s is silent", (file) => {
    expect(at(file)).toEqual([]);
  });

  test.each([
    "src/stripe.ts", "src/maps-admin.ts", "src/maps-secret.ts", "src/openai.ts", "src/sentry.ts",
    "src/algolia-admin.ts", "src/posthog-personal.ts", "src/nuxt-client.ts", "src/mapbox-any.ts", "src/revenuecat-any.ts",
    "src/maps-server.ts", "src/algolia-master.ts", "src/amplitude-personal.ts",
  ])("%s still fires", (file) => {
    expect(at(file, "ci-ai-public-env-secret")).toHaveLength(1);
  });
});

describe("public-env-secret: server-only configuration", () => {
  test("a PM2 ecosystem file is server process env", () => {
    expect(at("ecosystem.config.cjs")).toEqual([]);
    expect(at("pkg/ecosystem.config.js")).toEqual([]);
  });

  test("an ecosystem file outside a package root, or without PM2 shape, is scanned normally", () => {
    expect(at("web/ecosystem.config.js", "ci-ai-public-env-secret")).toHaveLength(1);
    expect(at("tools/ecosystem.config.cjs", "ci-ai-public-env-secret")).toHaveLength(1);
  });

  test("Nuxt runtimeConfig.app and a quoted 'public' block fire; a deeper nested public is private", () => {
    const nuxt = at("nuxt-app/nuxt.config.ts", "ci-ai-public-env-secret");
    expect(nuxt.map((f) => f.location.start_line)).toEqual([5, 8]);
  });

  test("Nuxt analysis stays linear on large or unbalanced input", async () => {
    const big = await mkdtemp(join(tmpdir(), "ci-nuxt-perf-"));
    try {
      await writeFile(join(big, "nuxt.config.ts"), "runtimeConfig: {\n" + "key: {".repeat(Math.ceil((1 << 20) / 6)));
      await mkdir(join(big, "small"));
      await writeFile(join(big, "small", "nuxt.config.ts"), "runtimeConfig: {\n" + "key: {".repeat(Math.ceil((250 << 10) / 6)));
      const started = performance.now();
      await runClientSecretsCheck(big);
      expect(performance.now() - started).toBeLessThan(1_000);
    } finally {
      await rm(big, { recursive: true, force: true });
    }
  });

  test("Nuxt private runtimeConfig keys are silent; the public block still fires", () => {
    const nuxt = at("nuxt.config.ts", "ci-ai-public-env-secret");
    expect(nuxt.map((f) => f.location.start_line)).toEqual([6]);
  });
});

describe("client-hardcoded-secret: PEM headers need key material", () => {
  test("markers in replace() calls and a PEM builder are silent", () => {
    expect(at("src/pem.ts")).toEqual([]);
  });

  test.each(["src/key-decoy.ts", "src/key-concat.ts", "src/key-array.ts", "src/key-service-account.ts"])(
    "%s (decoy header first, or split across strings) still fires",
    (file) => {
      expect(at(file, "ci-ai-client-hardcoded-secret")).toHaveLength(1);
    },
  );

  test("a complete private key in client source still fires", () => {
    const key = at("src/key.ts", "ci-ai-client-hardcoded-secret");
    expect(key).toHaveLength(1);
    expect(JSON.stringify(key)).not.toContain(TEST_PEM.split("\n")[1]!);
  });
});
