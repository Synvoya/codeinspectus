import { afterEach, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Finding } from "../../types.js";
import { detectTechnologies } from "../../technology-detection.js";
import { createIosAnalyzers } from "./index.js";
import {
  IOS_CONFIG_RULE_IDS,
  runIosConfig,
} from "./ios-config.js";
import { parseXmlPlist, plistDictionary, plistEntry, plistString } from "./plist.js";
import { releaseConfigurationReferences } from "./pbx.js";
import { loadIosConfigurationProject } from "./project.js";

const CORPUS = join(process.cwd(), "fixtures", "mobile-config-corpus", "ios");
const REDACTION_SENTINEL = "CI_IOS_REDACTION_SENTINEL";
const temporaryDirectories: string[] = [];

const EXPECTED = [
  {
    ruleId: "ci-ios-ats-global-arbitrary-loads",
    file: "Runner/Info.plist",
    severity: "medium",
    cwe: ["CWE-319"],
  },
  {
    ruleId: "ci-ios-ats-insecure-domain-exception",
    file: "Runner/Info.plist",
    severity: "medium",
    cwe: ["CWE-319"],
  },
  {
    ruleId: "ci-ios-ats-weak-tls",
    file: "Runner/Info.plist",
    severity: "medium",
    cwe: ["CWE-327"],
  },
  {
    ruleId: "ci-ios-data-protection-disabled",
    file: "Runner/Runner.entitlements",
    severity: "medium",
    cwe: ["CWE-311"],
  },
] as const;

interface Scenario {
  findings: Finding[];
  notes: readonly string[];
}

let tp: Scenario;
let fp: Scenario;
let fixed: Scenario;

async function analyze(name: "tp" | "fp" | "fixed"): Promise<Scenario> {
  const result = await runIosConfig(join(CORPUS, name));
  return { findings: result.findings, notes: result.notes ?? [] };
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })
  ));
});

beforeAll(async () => {
  [tp, fp, fixed] = await Promise.all([analyze("tp"), analyze("fp"), analyze("fixed")]);
});

describe("iOS frozen configuration corpus", () => {
  test("emits exactly the four approved high-confidence TP rules", () => {
    expect(tp.notes).toEqual([]);
    expect(tp.findings).toHaveLength(4);
    expect(tp.findings.map((finding) => finding.rule_id).sort()).toEqual(
      [...IOS_CONFIG_RULE_IDS].sort(),
    );
    for (const expected of EXPECTED) {
      const finding = tp.findings.find((candidate) => candidate.rule_id === expected.ruleId);
      expect(finding, `missing ${expected.ruleId}`).toMatchObject({
        engine: "codeinspectus-ai",
        engines: ["codeinspectus-ai"],
        severity: expected.severity,
        confidence: "high",
        cwe: [...expected.cwe],
        location: { file: expected.file },
      });
      expect(finding?.remediation.summary.length).toBeGreaterThan(0);
      expect(finding?.remediation.steps.length).toBeGreaterThan(0);
      expect(finding?.remediation.references.length).toBeGreaterThan(0);
    }
    expect(JSON.stringify(tp)).not.toContain(REDACTION_SENTINEL);
  });

  test.each([
    ["FP", () => fp],
    ["fixed", () => fixed],
  ] as const)("keeps the %s repository silent", (_label, scenario) => {
    expect(scenario()).toEqual({ findings: [], notes: [] });
  });

  test("deduplicates repeated Release/AppStore references to the same selected files", async () => {
    const project = await loadIosConfigurationProject(join(CORPUS, "tp"));
    expect(project.documents.map((document) => document.path)).toEqual([
      "Runner/Info.plist",
      "Runner/Runner.entitlements",
    ]);
    expect(tp.findings).toHaveLength(4);
  });

  test("propagates iPhone-only project Release evidence to split target Release references", async () => {
    // Mirrors the official Flutter template shape: project-level Release owns
    // SDKROOT while target-level Release owns INFOPLIST_FILE/entitlements.
    const project = await loadIosConfigurationProject(join(CORPUS, "tp"));
    expect(project.limitations).toEqual([]);
    expect(project.documents.map((document) => document.path)).toEqual([
      "Runner/Info.plist",
      "Runner/Runner.entitlements",
    ]);
    expect(tp.findings.map((finding) => finding.rule_id).sort()).toEqual(
      [...IOS_CONFIG_RULE_IDS].sort(),
    );
  });

  test("selects only statically referenced release files when an Xcode project exists", async () => {
    const project = await loadIosConfigurationProject(join(CORPUS, "fp"));
    expect(project.documents.map((document) => document.path)).toEqual([
      "Runner/Info.plist",
      "Runner/Runner.entitlements",
    ]);
    expect(project.documents.map((document) => document.path)).not.toEqual(
      expect.arrayContaining([
        "Runner/Debug-Info.plist",
        "Runner/Debug.entitlements",
        "Runner/GoogleService-Info.plist",
        "Runner/Unused.entitlements",
      ]),
    );
  });

  test("is applicable to a non-Flutter Xcode repository signal", async () => {
    const detected = await detectTechnologies(join(CORPUS, "tp"));
    expect(detected.detected_technologies).toContainEqual(expect.objectContaining({
      id: "ios",
      kind: "platform",
      confidence: "high",
    }));
    expect(detected.detected_technologies.map((technology) => technology.id)).not.toContain("flutter");
  });
});

describe("iOS configuration selection and bounds", () => {
  test("allows an explicitly targeted nonstandard plist without inferring sibling configs", async () => {
    const result = await runIosConfig(join(CORPUS, "tp", "Runner", "Info.plist"));
    expect(result.findings.map((finding) => finding.rule_id).sort()).toEqual([
      "ci-ios-ats-global-arbitrary-loads",
      "ci-ios-ats-insecure-domain-exception",
      "ci-ios-ats-weak-tls",
    ]);
    expect(result.notes ?? []).toEqual([]);
  });

  test("does not guess a dynamic release configuration path", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-dynamic-"));
    temporaryDirectories.push(directory);
    await mkdir(join(directory, "App.xcodeproj"), { recursive: true });
    await writeFile(join(directory, "App.xcodeproj", "project.pbxproj"), `{
      objects = {
        RELEASE = {
          isa = XCBuildConfiguration;
          buildSettings = { INFOPLIST_FILE = "$(CONFIGURATION)/Info.plist"; SDKROOT = iphoneos; };
          name = Release;
        };
      };
    }`, "utf8");
    await writeFile(join(directory, "Info.plist"), `
      <plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><true/>
      </dict></dict></plist>
    `, "utf8");

    const result = await runIosConfig(directory);
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual([
      "Skipped 1 dynamic or out-of-target Xcode configuration reference(s).",
    ]);
  });

  test("excludes non-production named fallback files when no Xcode release selection exists", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-fallback-"));
    temporaryDirectories.push(directory);
    await writeFile(join(directory, "Info.plist"), `
      <plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><false/>
      </dict></dict></plist>
    `, "utf8");
    await writeFile(join(directory, "Runner.entitlements"), `
      <plist version="1.0"><dict><key>com.apple.developer.default-data-protection</key>
      <string>NSFileProtectionComplete</string></dict></plist>
    `, "utf8");
    const unsafe = `<plist version="1.0"><dict>
      <key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>
      </dict></plist>`;
    await writeFile(join(directory, "RunnerDebug.entitlements"), unsafe, "utf8");
    await writeFile(join(directory, "Runner-Profile.entitlements"), unsafe, "utf8");
    await writeFile(join(directory, "RunnerDevelopment.entitlements"), unsafe, "utf8");

    const result = await runIosConfig(directory);
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual([
      "Excluded 3 non-production-named iOS configuration file(s) without static release build selection.",
    ]);
  });

  test("still analyzes a non-production-named file when it is the explicit target", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-explicit-debug-"));
    temporaryDirectories.push(directory);
    const target = join(directory, "RunnerDebug.entitlements");
    await writeFile(target, `<plist version="1.0"><dict>
      <key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>
      </dict></plist>`, "utf8");
    const result = await runIosConfig(target);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      "ci-ios-data-protection-disabled",
    ]);
    expect(result.notes ?? []).toEqual([]);
  });

  test("surfaces binary, invalid, and oversized selected property lists as limitations", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-bounds-"));
    temporaryDirectories.push(directory);
    for (const name of ["Binary", "Invalid", "Oversized"]) {
      await mkdir(join(directory, name), { recursive: true });
    }
    await writeFile(join(directory, "Binary", "Info.plist"), "bplist00fixture", "utf8");
    await writeFile(join(directory, "Invalid", "Info.plist"), "<plist><dict><key>broken", "utf8");
    await writeFile(
      join(directory, "Oversized", "Info.plist"),
      `<plist><dict><key>padding</key><string>${"x".repeat(512 * 1024)}</string></dict></plist>`,
      "utf8",
    );

    const project = await loadIosConfigurationProject(directory);
    expect(project.documents).toEqual([]);
    expect(project.limitations).toEqual([
      "Skipped binary iOS property list Binary/Info.plist.",
      "Skipped invalid or unsupported iOS property list Invalid/Info.plist.",
      "Skipped oversized iOS property list Oversized/Info.plist (limit: 512 KiB).",
    ]);
  });

  test("does not treat a macOS-only Xcode Release configuration as iOS evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-macos-only-"));
    temporaryDirectories.push(directory);
    await mkdir(join(directory, "Desktop.xcodeproj"), { recursive: true });
    await writeFile(join(directory, "Desktop.xcodeproj", "project.pbxproj"), `{
      objects = {
        RELEASE = {
          isa = XCBuildConfiguration;
          buildSettings = { INFOPLIST_FILE = Runner/Info.plist; SDKROOT = macosx; };
          name = Release;
        };
      };
    }`, "utf8");
    await mkdir(join(directory, "Runner"), { recursive: true });
    await writeFile(join(directory, "Runner", "Info.plist"), `
      <plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><true/>
      </dict></dict></plist>
    `, "utf8");
    const result = await runIosConfig(directory);
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual([
      "Release/AppStore Xcode configurations lacked explicit iphoneos/iphonesimulator platform evidence; iOS property lists were not inferred.",
    ]);
  });

  test("requires same-configuration iPhone evidence for references in a mixed-platform project", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-mixed-platform-"));
    temporaryDirectories.push(directory);
    await mkdir(join(directory, "Mixed.xcodeproj"), { recursive: true });
    await mkdir(join(directory, "Phone"), { recursive: true });
    await mkdir(join(directory, "Desktop"), { recursive: true });
    await writeFile(join(directory, "Mixed.xcodeproj", "project.pbxproj"), `{
      objects = {
        PHONE = { isa = XCBuildConfiguration; buildSettings = {
          INFOPLIST_FILE = Phone/Info.plist; SDKROOT = iphoneos;
        }; name = Release; };
        MAC = { isa = XCBuildConfiguration; buildSettings = {
          INFOPLIST_FILE = Desktop/Info.plist; SDKROOT = macosx;
        }; name = Release; };
        UNSCOPED = { isa = XCBuildConfiguration; buildSettings = {
          CODE_SIGN_ENTITLEMENTS = Desktop/Unsafe.entitlements;
        }; name = Release; };
      };
    }`, "utf8");
    const unsafeInfo = `<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>`;
    await writeFile(join(directory, "Phone", "Info.plist"), unsafeInfo, "utf8");
    await writeFile(join(directory, "Desktop", "Info.plist"), unsafeInfo, "utf8");
    await writeFile(join(directory, "Desktop", "Unsafe.entitlements"), `<plist version="1.0"><dict>
      <key>com.apple.developer.default-data-protection</key><string>NSFileProtectionNone</string>
      </dict></plist>`, "utf8");

    const result = await runIosConfig(directory);
    expect(result.findings.map((finding) => [finding.rule_id, finding.location.file])).toEqual([
      ["ci-ios-ats-global-arbitrary-loads", "Phone/Info.plist"],
    ]);
    expect(result.notes).toEqual([
      "Skipped 2 release configuration reference(s) without same-configuration iPhone evidence in a mixed-platform Xcode project.",
    ]);
  });

  test("uses XCConfigurationList references and ignores an orphan unsafe Release configuration", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-orphan-config-"));
    temporaryDirectories.push(directory);
    await mkdir(join(directory, "App.xcodeproj"), { recursive: true });
    await mkdir(join(directory, "Safe"), { recursive: true });
    await mkdir(join(directory, "Orphan"), { recursive: true });
    await writeFile(join(directory, "App.xcodeproj", "project.pbxproj"), `{
      objects = {
        SAFE = { isa = XCBuildConfiguration; buildSettings = {
          INFOPLIST_FILE = Safe/Info.plist; SDKROOT = iphoneos;
        }; name = Release; };
        ORPHAN = { isa = XCBuildConfiguration; buildSettings = {
          INFOPLIST_FILE = Orphan/Info.plist; SDKROOT = iphoneos;
        }; name = Release; };
        ACTIVE_LIST = { isa = XCConfigurationList; buildConfigurations = (SAFE,); };
      };
    }`, "utf8");
    await writeFile(join(directory, "Safe", "Info.plist"), `
      <plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><false/>
      </dict></dict></plist>
    `, "utf8");
    await writeFile(join(directory, "Orphan", "Info.plist"), `
      <plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><true/>
      </dict></dict></plist>
    `, "utf8");

    const project = await loadIosConfigurationProject(directory);
    expect(project.documents.map((document) => document.path)).toEqual(["Safe/Info.plist"]);
    await expect(runIosConfig(directory)).resolves.toEqual({ findings: [] });
  });

  test("rejects duplicate OpenStep build-setting keys instead of applying last-wins", () => {
    expect(() => releaseConfigurationReferences(`{
      objects = {
        RELEASE = { isa = XCBuildConfiguration; buildSettings = {
          INFOPLIST_FILE = Safe/Info.plist;
          INFOPLIST_FILE = Unsafe/Info.plist;
          SDKROOT = iphoneos;
        }; name = Release; };
      };
    }`)).toThrow(/Duplicate Xcode project dictionary key 'INFOPLIST_FILE'/);
  });

  test("does not fall back to orphan configurations when a real configuration list is empty", () => {
    expect(releaseConfigurationReferences(`{
      objects = {
        ORPHAN = { isa = XCBuildConfiguration; buildSettings = {
          INFOPLIST_FILE = Unsafe/Info.plist; SDKROOT = iphoneos;
        }; name = Release; };
        ACTIVE_LIST = { isa = XCConfigurationList; buildConfigurations = (); };
      };
    }`)).toEqual({
      releaseCandidates: 0,
      configurations: 0,
      references: [],
      skippedMixedPlatformReferences: 0,
    });
  });

  test("parses bounded Xcode projects larger than the plist-specific 512 KiB cap", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-ios-large-pbx-"));
    temporaryDirectories.push(directory);
    await mkdir(join(directory, "App.xcodeproj"), { recursive: true });
    await mkdir(join(directory, "Runner"), { recursive: true });
    await writeFile(join(directory, "App.xcodeproj", "project.pbxproj"), `
      /* ${"x".repeat(600 * 1024)} */
      { objects = { RELEASE = { isa = XCBuildConfiguration; buildSettings = {
        INFOPLIST_FILE = Runner/Info.plist; SDKROOT = iphoneos;
      }; name = Release; }; }; }
    `, "utf8");
    await writeFile(join(directory, "Runner", "Info.plist"), `
      <plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
      <key>NSAllowsArbitraryLoads</key><true/>
      </dict></dict></plist>
    `, "utf8");
    const result = await runIosConfig(directory);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      "ci-ios-ats-global-arbitrary-loads",
    ]);
    expect(result.notes ?? []).toEqual([]);
  });

  test("exposes a single analyzer with exact static component and rule ownership", async () => {
    const [analyzer] = createIosAnalyzers(join(CORPUS, "tp"));
    expect(analyzer).toMatchObject({
      id: "ios-configuration",
      components: [
        "pack:ios:dispatch",
        "ios:xml-plist-parser",
        "ai:ios-ats-global-arbitrary-loads",
        "ai:ios-ats-insecure-domain-exception",
        "ai:ios-ats-weak-tls",
        "ai:ios-data-protection",
      ],
      ruleIds: [...IOS_CONFIG_RULE_IDS],
    });
    await expect(analyzer?.run()).resolves.toMatchObject({ findings: expect.any(Array) });
  });
});

describe("XML plist parser", () => {
  test("parses nested dictionaries, booleans, entities, and line metadata", () => {
    const root = parseXmlPlist(`<?xml version="1.0"?>
      <!-- unsafe-looking comments are not values: <true/> -->
      <plist version="1.0"><dict>
        <key>NSExceptionDomains</key><dict>
          <key>api&#46;codeinspectus&#46;com</key><dict>
            <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string>
            <key>AllowedPins</key><array/>
          </dict>
        </dict>
      </dict></plist>`);
    const domains = plistDictionary(plistEntry(root, "NSExceptionDomains")?.value);
    const domain = domains && plistDictionary(plistEntry(domains, "api.codeinspectus.com")?.value);
    expect(plistString(domain && plistEntry(domain, "NSExceptionMinimumTLSVersion")?.value))
      .toBe("TLSv1.2");
    expect(plistEntry(root, "NSExceptionDomains")?.key.line).toBe(4);
  });

  test.each([
    "",
    "bplist00fixture",
    "<plist><array/></plist>",
    "<plist><dict><key>broken</dict></plist>",
    "<plist><dict><key>x</key><unknown/></dict></plist>",
    "<plist><dict><key>x</key><true/><key>x</key><false/></dict></plist>",
  ])("rejects unsupported or malformed input", (content) => {
    expect(() => parseXmlPlist(content)).toThrow();
  });
});
