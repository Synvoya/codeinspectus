import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { parse as parseToml } from "smol-toml";

interface GitleaksRule {
  id: string;
  regex: string;
  secretGroup?: number;
  keywords?: string[];
  path?: string;
}

interface GitleaksAllowlist {
  description?: string;
  regexTarget?: string;
  regexes?: string[];
}

describe("CodeInspectus Gitleaks extension", () => {
  test("owns an exact modern Supabase secret rule without matching publishable keys or placeholders", async () => {
    const config = parseToml(
      await readFile("detection-db/gitleaks/codeinspectus.toml", "utf8"),
    ) as {
      extend?: { useDefault?: boolean };
      rules?: GitleaksRule[];
      allowlists?: GitleaksAllowlist[];
    };
    const rules = config.rules ?? [];
    const ids = rules.map((rule) => rule.id);
    const supabase = rules.find(
      (rule) => rule.id === "codeinspectus-supabase-secret-key",
    );

    expect(config.extend?.useDefault).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
    expect(rules).toHaveLength(5);
    expect(supabase).toMatchObject({
      secretGroup: 1,
      keywords: ["sb_secret_"],
    });

    const expression = new RegExp(supabase!.regex);
    expect(expression.test("sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS")).toBe(true);
    expect(expression.test("sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS")).toBe(false);
    expect(expression.test("sb_secret_...")).toBe(false);
    expect(expression.test("sb_secret_testvalue123")).toBe(false);
    expect(expression.test("sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS4")).toBe(false);

    const publishableAllowlist = (config.allowlists ?? []).find((allowlist) =>
      allowlist.description?.includes("publishable API key"),
    );
    expect(publishableAllowlist?.regexTarget).toBe("match");
    const publishableExpression = new RegExp(publishableAllowlist!.regexes![0]!);
    expect(
      publishableExpression.test(
        'const supabaseKey = "sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";',
      ),
    ).toBe(true);
    expect(
      publishableExpression.test(
        'const supabaseKey = "sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";',
      ),
    ).toBe(false);
  });

  // Synvoya PHP pack (design 4.5): a committed Laravel APP_KEY is a secret, so Gitleaks (which redacts
  // it) reports it, and only in deployable env files -- never .env.example or test env files.
  test("reports a Laravel APP_KEY only in deployable .env files", async () => {
    const config = parseToml(await readFile("detection-db/gitleaks/codeinspectus.toml", "utf8")) as { rules?: GitleaksRule[] };
    const rule = (config.rules ?? []).find((entry) => entry.id === "codeinspectus-laravel-app-key");
    expect(rule).toMatchObject({ secretGroup: 1, keywords: ["app_key"] });
    // Go RE2 inline flags are JavaScript flags here.
    const value = new RegExp(rule!.regex.replace(/^\(\?m\)/, ""), "m");
    const path = new RegExp(rule!.path!);
    const key = `base64:${"QUJD".repeat(11)}`;
    expect(value.exec(`APP_NAME=Shop\nAPP_KEY=${key}\n`)?.[1]).toBe(key);
    expect(value.test(`export APP_KEY="${key}"`)).toBe(true);
    expect(value.test("APP_KEY=")).toBe(false);
    expect(value.test("APP_KEY=base64:short")).toBe(false);
    for (const file of [".env", "app/.env", ".env.production", ".env.prod", ".env.staging", "app\\.env"]) expect(path.test(file)).toBe(true);
    for (const file of [".env.example", ".env.testing", ".env.ci", ".env.local", ".env.dist", "env", "x.env.bak"]) expect(path.test(file)).toBe(false);
  });
});

// Design §10.6 field precision pass: each allowlist names one identifier or public-by-design class
// from the 2026-11-04 field triage. Samples are assembled at run time so this file holds no
// secret-shaped literal; the engine-backed counterpart is eval E121.
describe("CodeInspectus Gitleaks precision allowlists", () => {
  type Allowlist = GitleaksAllowlist & { targetRules?: string[]; paths?: string[]; condition?: string };
  const j = (...parts: string[]) => parts.join("");
  const js = (source: string) => source.startsWith("(?i)") ? new RegExp(source.slice(4), "i") : new RegExp(source);

  async function allowlists(): Promise<Allowlist[]> {
    const config = parseToml(await readFile("detection-db/gitleaks/codeinspectus.toml", "utf8")) as { allowlists?: Allowlist[] };
    return config.allowlists ?? [];
  }
  async function byDescription(fragment: string): Promise<Allowlist> {
    const found = (await allowlists()).find((allowlist) => allowlist.description?.includes(fragment));
    expect(found, fragment).toBeDefined();
    return found!;
  }
  const matches = (allowlist: Allowlist, value: string) => (allowlist.regexes ?? []).some((re) => js(re).test(value));

  test("generated schema identifiers are silenced, other values are not", async () => {
    const list = await byDescription("Generated database index");
    expect(list.targetRules).toEqual(["generic-api-key"]);
    expect(list.regexTarget).toBe("secret");
    expect(matches(list, j("IDX_368A4209", "A76ED395"))).toBe(true);
    expect(matches(list, j("uniq_20c9fb24", "5f37a13b"))).toBe(true);
    expect(matches(list, j("4395a1c7e2b94f0d", "8a6c3e1f5b7d9a20"))).toBe(false);
    expect(matches(list, j("IDX_368A4209", "A76ED395", "FF"))).toBe(false);
    // Review: pk_<hex> is a live-key prefix, so PK_ is not an index-name class.
    expect(matches(list, j("pk_368a4209", "a76ed395"))).toBe(false);
  });

  test("conda pins are silenced by line shape only", async () => {
    const list = await byDescription("Conda environment pins");
    expect(list.regexTarget).toBe("line");
    expect(matches(list, `  - aws-c-auth=0.7.3=${j("h28f75", "89_1")}`)).toBe(true);
    expect(matches(list, `  - API_KEY=${j("4395a1c7e2b94f0d", "8a6c3e1f5b7d9a20")}`)).toBe(false);
    // Review: only in conda environment files (a compose list item can share the line shape).
    expect(list.condition).toBe("AND");
    const paths = (list.paths ?? []).map(js);
    for (const file of ["environment.yml", "ml/ann/export/env.yaml", "conda-lock.yml"]) expect(paths.some((re) => re.test(file)), file).toBe(true);
    for (const file of ["docker-compose.yml", "deploy/values.yaml", "src/environment.ts"]) expect(paths.some((re) => re.test(file)), file).toBe(false);
  });

  test("OAuth client and tenant UUIDs are silenced; a client secret is not", async () => {
    const list = await byDescription("OAuth client id or tenant id");
    expect(matches(list, `OAUTH_CLIENT_ID: "${j("f508c1d2-0b1e-4a6f-9c3d-", "7e2a1b9c4d5e")}"`)).toBe(true);
    expect(matches(list, `'tenantId' => '${j("c687a1b2-3c4d-4e5f-8a9b-", "0c1d2e3f4a5b")}'`)).toBe(true);
    expect(matches(list, `OAUTH_CLIENT_SECRET: "${j("Xy7Qa1b2c3d4e5f6g7h8i9j0", "kLmNoPqRsTuV")}"`)).toBe(false);
  });

  test("reCAPTCHA site keys named as such are silenced; a secret key is not", async () => {
    const list = await byDescription("reCAPTCHA site key");
    expect(matches(list, `emailOctopusSiteKey: ${j("6LdYxAcTAAAAAJ", "cZVRqyHh71UMIEGNQ_MXjiZKh0")}`)).toBe(true);
    expect(matches(list, `'website_key' => env('RECAPTCHA_WEBSITE_KEY', '${j("6LcJq8Zt2Vb7Nx4Rk1Pm", "9Wd3Hy6Lc0Ts5Gf8Ja2x")}'`)).toBe(true);
    expect(matches(list, `'secret_key' => env('RECAPTCHA_SECRET_KEY', '${j("6LcJq8Zt2Vb7Nx4Rk1Pm", "9Wd3Hy6Lc0Ts5Gf8Ja2x")}'`)).toBe(false);
    // The key name must be the one assigned: a site key mentioned earlier on the line does not count.
    expect(matches(list, `site_key_note = 1; secret = '${j("6LcJq8Zt2Vb7Nx4Rk1Pm", "9Wd3Hy6Lc0Ts5Gf8Ja2x")}'`)).toBe(false);
    expect(matches(list, `site_key_secret: ${j("6LcJq8Zt2Vb7Nx4Rk1Pm", "9Wd3Hy6Lc0Ts5Gf8Ja2x")}`)).toBe(false);
  });

  test("exact published test and dev-server values only", async () => {
    const google = await byDescription("reCAPTCHA test site and secret keys");
    expect(matches(google, j("6LeIxAcTAAAAAJcZVRqyHh71", "UMIEGNQ_MXjiZKhI"))).toBe(true);
    expect(matches(google, j("6LeIxAcTAAAAAJcZVRqyHh71", "UMIEGNQ_MXjiZKhJ"))).toBe(false);
    const qstash = await byDescription("QStash local development server");
    expect(Buffer.from(qstash.regexes![0]!, "base64").toString("utf8")).toBe('{"UserID":"defaultUser","Password":"defaultPassword"}');
    expect(matches(qstash, j("sig_7kYjw48mhY7k", "AjqNGcy6cr29RJ6r"))).toBe(true);
    expect(matches(qstash, j("sig_7kYjw48mhY7k", "AjqNGcy6cr29RJ6s"))).toBe(false);
  });

  test("Stripe publishable keys are silenced, secret and restricted keys are not", async () => {
    const list = await byDescription("Stripe publishable key");
    expect(matches(list, j("pk_test_51H8xYzAbCdEfGh", "IjKlMnOpQr"))).toBe(true);
    expect(matches(list, j("sk_", "test_51H8xYzAbCdEfGh", "IjKlMnOpQr"))).toBe(false);
    expect(matches(list, j("rk_", "live_51H8xYzAbCdEfGh", "IjKlMnOpQr"))).toBe(false);
  });

  test("Firebase config files only, for the Google key rules", async () => {
    const list = await byDescription("Firebase app config file");
    // Review: only the Google key rule; a generic secret in google-services.json is still reported.
    expect(list.targetRules).toEqual(["gcp-api-key"]);
    const paths = (list.paths ?? []).map(js);
    expect(paths.some((re) => re.test("/repo/android/app/google-services.json"))).toBe(true);
    expect(paths.some((re) => re.test("ios/Runner/GoogleService-Info.plist"))).toBe(true);
    expect(paths.some((re) => re.test("src/config/google-services.json.ts"))).toBe(false);
    expect(paths.some((re) => re.test("ios/AppConfig.json"))).toBe(false);
  });

  test("the generic rule is silenced in Firebase config files only for the AIza browser key", async () => {
    const list = await byDescription("seen by the generic rule");
    expect(list.targetRules).toEqual(["generic-api-key"]);
    expect(list.condition).toBe("AND");
    expect(list.regexTarget).toBe("secret");
    expect(matches(list, j("AIzaSyA1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6Q"))).toBe(true);
    expect(matches(list, j("4c1e9a7b2d8f6e0a", "3b5c7d9e1f2a4b6c"))).toBe(false);
  });

  test("an allowlist without targetRules lists exact values only", async () => {
    for (const list of await allowlists()) {
      if (list.targetRules || list.description?.includes("Supabase")) continue;
      for (const re of list.regexes ?? []) expect(re, list.description).toMatch(/^[A-Za-z0-9_=+/-]+$/);
    }
  });
});
