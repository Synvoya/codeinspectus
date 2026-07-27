import { afterEach, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ANDROID_CLEARTEXT_RULE_ID,
  ANDROID_CONFIG_RULE_IDS,
  ANDROID_DEBUGGABLE_RULE_ID,
  ANDROID_EXPORTED_FILE_PROVIDER_RULE_ID,
  ANDROID_USER_CA_RULE_ID,
  runAndroidConfig,
} from "./android-config.js";

const temporaryDirectories: string[] = [];
const CORPUS = join(process.cwd(), "fixtures", "mobile-config-corpus", "android");

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })
  ));
});

async function temporaryProject(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-android-config-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function put(root: string, relativePath: string, content: string): Promise<string> {
  const path = join(root, ...relativePath.split("/"));
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, content, "utf8");
  return path;
}

const MANIFEST_OPEN = '<manifest xmlns:android="http://schemas.android.com/apk/res/android">';

describe("Android configuration frozen corpus", () => {
  test("emits one high-confidence finding for each TP rule and keeps FP/fixed silent", async () => {
    const tp = await runAndroidConfig(join(CORPUS, "tp"));
    const fp = await runAndroidConfig(join(CORPUS, "fp"));
    const fixed = await runAndroidConfig(join(CORPUS, "fixed"));

    expect(tp.findings).toHaveLength(4);
    expect(new Set(tp.findings.map((finding) => finding.rule_id))).toEqual(new Set(ANDROID_CONFIG_RULE_IDS));
    expect(tp.findings.filter((finding) => finding.severity === "high")).toHaveLength(1);
    expect(tp.findings.filter((finding) => finding.severity === "medium")).toHaveLength(3);
    expect(tp.findings.every((finding) => finding.confidence === "high")).toBe(true);
    expect(tp.findings.find((finding) => finding.rule_id === ANDROID_DEBUGGABLE_RULE_ID)?.location.file)
      .toBe("app/src/release/AndroidManifest.xml");
    expect(tp.findings.find((finding) => finding.rule_id === ANDROID_CLEARTEXT_RULE_ID)?.location.file)
      .toBe("app/src/main/res/xml/network_security_config.xml");
    expect(tp.findings.find((finding) => finding.rule_id === ANDROID_USER_CA_RULE_ID)?.cwe)
      .toEqual(["CWE-295"]);
    expect(tp.findings.find((finding) => finding.rule_id === ANDROID_EXPORTED_FILE_PROVIDER_RULE_ID))
      .toMatchObject({ severity: "high", cwe: ["CWE-926"] });
    expect(tp.notes).toBeUndefined();

    expect(fp).toEqual({ findings: [] });
    expect(fixed).toEqual({ findings: [] });
  });

  test("does not mutate any corpus configuration while scanning", async () => {
    const path = join(CORPUS, "tp", "app", "src", "main", "AndroidManifest.xml");
    const before = await readFile(path, "utf8");
    await runAndroidConfig(join(CORPUS, "tp"));
    await expect(readFile(path, "utf8")).resolves.toBe(before);
  });
});

describe("Android manifest effective production configuration", () => {
  test("requires explicit src/release evidence for debuggable release builds", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:debuggable="true" />
    </manifest>`);

    await expect(runAndroidConfig(project)).resolves.toEqual({ findings: [] });

    await put(project, "app/src/release/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:debuggable="true" />
    </manifest>`);
    const release = await runAndroidConfig(project);
    expect(release.findings.map((finding) => finding.rule_id)).toEqual([ANDROID_DEBUGGABLE_RULE_ID]);
  });

  test("uses release-over-main application and FileProvider attributes", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:usesCleartextTraffic="true">
        <provider android:name="androidx.core.content.FileProvider" android:exported="true" />
      </application>
    </manifest>`);
    await put(project, "app/src/release/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:usesCleartextTraffic="false">
        <provider android:name="androidx.core.content.FileProvider" android:exported="false" />
      </application>
    </manifest>`);

    await expect(runAndroidConfig(project)).resolves.toEqual({ findings: [] });
  });

  test("honors release tools:remove for supported application and provider attributes", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:networkSecurityConfig="@xml/network_security_config">
        <provider android:name="androidx.core.content.FileProvider" android:exported="true" />
      </application>
    </manifest>`);
    await put(project, "app/src/release/AndroidManifest.xml", `
      <manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools">
        <application tools:remove="android:networkSecurityConfig">
          <provider
              android:name="androidx.core.content.FileProvider"
              tools:remove="android:exported" />
        </application>
      </manifest>
    `);
    await put(project, "app/src/main/res/xml/network_security_config.xml", `
      <network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>
    `);

    await expect(runAndroidConfig(project)).resolves.toEqual({ findings: [] });
  });

  test("evaluates a referenced Network Security Config instead of a conflicting manifest flag", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application
          android:usesCleartextTraffic="true"
          android:networkSecurityConfig="@xml/network_security_config" />
    </manifest>`);
    await put(project, "app/src/main/res/xml/network_security_config.xml", `
      <network-security-config>
        <base-config cleartextTrafficPermitted="false" />
      </network-security-config>
    `);

    await expect(runAndroidConfig(project)).resolves.toEqual({ findings: [] });
  });

  test("prefers a release resource overlay over an insecure main resource", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:networkSecurityConfig="@xml/network_security_config" />
    </manifest>`);
    await put(project, "app/src/main/res/xml/network_security_config.xml", `
      <network-security-config>
        <base-config cleartextTrafficPermitted="true">
          <trust-anchors><certificates src="user" /></trust-anchors>
        </base-config>
      </network-security-config>
    `);
    await put(project, "app/src/release/res/xml/network_security_config.xml", `
      <network-security-config>
        <base-config cleartextTrafficPermitted="false">
          <trust-anchors><certificates src="system" /></trust-anchors>
        </base-config>
      </network-security-config>
    `);

    await expect(runAndroidConfig(project)).resolves.toEqual({ findings: [] });
  });

  test("flags a standalone manifest cleartext opt-in only when no network config is present", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:usesCleartextTraffic="true" />
    </manifest>`);

    const result = await runAndroidConfig(project);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([ANDROID_CLEARTEXT_RULE_ID]);
  });

  test("understands Android namespace aliases, single quotes, and the legacy support FileProvider", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `
      <manifest xmlns:a='http://schemas.android.com/apk/res/android'>
        <application>
          <provider a:name='android.support.v4.content.FileProvider' a:exported='true' />
        </application>
      </manifest>
    `);

    const result = await runAndroidConfig(project);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      ANDROID_EXPORTED_FILE_PROVIDER_RULE_ID,
    ]);
  });

  test("does not treat a scan target's ancestor directory name as an in-project exclusion", async () => {
    const container = await temporaryProject();
    const project = join(container, "tests", "real-app");
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:usesCleartextTraffic="true" />
    </manifest>`);

    const result = await runAndroidConfig(project);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([ANDROID_CLEARTEXT_RULE_ID]);
  });

  test("does not treat a directly scanned debug or demo source-set manifest as production", async () => {
    const project = await temporaryProject();
    const debug = await put(project, "app/src/debug/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:usesCleartextTraffic="true" />
    </manifest>`);
    const demo = await put(project, "app/src/demo/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:usesCleartextTraffic="true" />
    </manifest>`);

    await expect(runAndroidConfig(debug)).resolves.toEqual({ findings: [] });
    await expect(runAndroidConfig(demo)).resolves.toEqual({ findings: [] });
  });

  test("reports dynamic security attributes and unresolved resource references without guessing", async () => {
    const project = await temporaryProject();
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application
          android:usesCleartextTraffic="true"
          android:networkSecurityConfig="\${networkSecurityConfig}">
        <provider
            android:name="androidx.core.content.FileProvider"
            android:exported="\${fileProviderExported}" />
      </application>
    </manifest>`);

    const result = await runAndroidConfig(project);
    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/dynamic Android Network Security Config/i);
    expect(result.notes?.join(" ")).toMatch(/dynamic android:exported FileProvider/i);
  });
});

describe("Android Network Security Config precision", () => {
  test("flags production-domain cleartext but excludes local and reserved documentation domains", async () => {
    const project = await temporaryProject();
    const path = await put(project, "network_security_config.xml", `
      <network-security-config>
        <base-config cleartextTrafficPermitted="false" />
        <domain-config cleartextTrafficPermitted="true"><domain>localhost</domain></domain-config>
        <domain-config cleartextTrafficPermitted="true"><domain>api.example.com</domain></domain-config>
        <domain-config cleartextTrafficPermitted="true"><domain>api.real-service.tld</domain></domain-config>
      </network-security-config>
    `);

    const result = await runAndroidConfig(path);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([ANDROID_CLEARTEXT_RULE_ID]);
    expect(result.findings[0]?.location.snippet).not.toContain("real-service");
  });

  test("trusts user CAs only as a finding outside debug-overrides", async () => {
    const project = await temporaryProject();
    const path = await put(project, "network_security_config.xml", `
      <network-security-config>
        <base-config><trust-anchors><certificates src="user" /></trust-anchors></base-config>
        <debug-overrides><trust-anchors><certificates src="user" /></trust-anchors></debug-overrides>
      </network-security-config>
    `);

    const result = await runAndroidConfig(path);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([ANDROID_USER_CA_RULE_ID]);
  });

  test("requires a production domain for domain-scoped user CA trust", async () => {
    const project = await temporaryProject();
    const path = await put(project, "network_security_config.xml", `
      <network-security-config>
        <domain-config><domain>localhost</domain><trust-anchors><certificates src="user" /></trust-anchors></domain-config>
        <domain-config><domain>api.example.com</domain><trust-anchors><certificates src="user" /></trust-anchors></domain-config>
        <domain-config><domain>api.real-service.tld</domain><trust-anchors><certificates src="user" /></trust-anchors></domain-config>
      </network-security-config>
    `);

    const result = await runAndroidConfig(path);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([ANDROID_USER_CA_RULE_ID]);
  });

  test("does not inspect unreferenced Network Security Config files during a directory scan", async () => {
    const unreferenced = join(
      CORPUS,
      "fp",
      "app",
      "src",
      "main",
      "res",
      "xml",
      "unreferenced_insecure_config.xml",
    );
    const directory = await runAndroidConfig(join(CORPUS, "fp"));
    const direct = await runAndroidConfig(unreferenced);

    expect(directory.findings).toEqual([]);
    expect(new Set(direct.findings.map((finding) => finding.rule_id))).toEqual(new Set([
      ANDROID_CLEARTEXT_RULE_ID,
      ANDROID_USER_CA_RULE_ID,
    ]));
  });

  test("does not expand target-defined XML entities", async () => {
    const project = await temporaryProject();
    const path = await put(project, "network_security_config.xml", `
      <!DOCTYPE network-security-config [<!ENTITY enabled "true">]>
      <network-security-config>
        <base-config cleartextTrafficPermitted="&enabled;" />
      </network-security-config>
    `);

    await expect(runAndroidConfig(path)).resolves.toEqual({ findings: [] });
  });

  test("rejects multiple roots and duplicate expanded attribute names as malformed XML", async () => {
    const project = await temporaryProject();
    const multiple = await put(project, "multiple.xml", `
      <network-security-config />
      <network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>
    `);
    const duplicate = await put(project, "duplicate.xml", `
      <network-security-config>
        <base-config cleartextTrafficPermitted="false" cleartextTrafficPermitted="true" />
      </network-security-config>
    `);

    for (const path of [multiple, duplicate]) {
      const result = await runAndroidConfig(path);
      expect(result.findings).toEqual([]);
      expect(result.notes?.join(" ")).toMatch(/malformed Android XML/i);
    }
  });

  test("ignores security-looking values in Android-schema-invalid element nesting", async () => {
    const project = await temporaryProject();
    const config = await put(project, "invalid-structure.xml", `
      <network-security-config>
        <wrapper>
          <base-config cleartextTrafficPermitted="true">
            <trust-anchors><certificates src="user" /></trust-anchors>
          </base-config>
        </wrapper>
      </network-security-config>
    `);
    await expect(runAndroidConfig(config)).resolves.toEqual({ findings: [] });

    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application>
        <wrapper>
          <provider android:name="androidx.core.content.FileProvider" android:exported="true" />
        </wrapper>
      </application>
    </manifest>`);
    const manifest = await runAndroidConfig(project);
    expect(manifest.findings).toEqual([]);
  });

  test("does not follow a referenced Network Security Config symlink", async () => {
    const container = await temporaryProject();
    const project = join(container, "project");
    const outside = await put(container, "outside.xml", `
      <network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>
    `);
    await put(project, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:networkSecurityConfig="@xml/network_security_config" />
    </manifest>`);
    const linked = join(project, "app", "src", "main", "res", "xml", "network_security_config.xml");
    await mkdir(join(linked, ".."), { recursive: true });
    try {
      await symlink(outside, linked, "file");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }

    const result = await runAndroidConfig(project);
    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/symlinked Android XML/i);
  });
});

describe("Android configuration bounds and failure honesty", () => {
  test("reports missing, malformed, and oversized referenced XML instead of implying coverage", async () => {
    const missingProject = await temporaryProject();
    await put(missingProject, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:networkSecurityConfig="@xml/missing_config" />
    </manifest>`);
    const missing = await runAndroidConfig(missingProject);
    expect(missing.findings).toEqual([]);
    expect(missing.notes?.join(" ")).toMatch(/could not resolve referenced/i);

    const malformedProject = await temporaryProject();
    await put(malformedProject, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:networkSecurityConfig="@xml/network_security_config" />
    </manifest>`);
    await put(
      malformedProject,
      "app/src/main/res/xml/network_security_config.xml",
      "<network-security-config><base-config></network-security-config>",
    );
    const malformed = await runAndroidConfig(malformedProject);
    expect(malformed.findings).toEqual([]);
    expect(malformed.notes?.join(" ")).toMatch(/malformed Android XML/i);

    const oversizedProject = await temporaryProject();
    await put(oversizedProject, "app/src/main/AndroidManifest.xml", `${MANIFEST_OPEN}
      <application android:networkSecurityConfig="@xml/network_security_config" />
    </manifest>`);
    await put(
      oversizedProject,
      "app/src/main/res/xml/network_security_config.xml",
      `<network-security-config>${" ".repeat(1024 * 1024)}</network-security-config>`,
    );
    const oversized = await runAndroidConfig(oversizedProject);
    expect(oversized.findings).toEqual([]);
    expect(oversized.notes?.join(" ")).toMatch(/oversized Android XML/i);
  });
});
