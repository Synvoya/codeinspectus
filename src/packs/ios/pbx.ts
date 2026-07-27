/** Minimal OpenStep project parser for release-configuration file selection. */

export type PbxValue = string | PbxDictionary | PbxValue[];
export type PbxDictionary = Map<string, PbxValue>;

export interface PbxConfigurationReference {
  setting: "INFOPLIST_FILE" | "CODE_SIGN_ENTITLEMENTS";
  value: string;
}

export interface PbxReleaseReferences {
  releaseCandidates: number;
  configurations: number;
  references: PbxConfigurationReference[];
  skippedMixedPlatformReferences: number;
}

export class PbxParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PbxParseError";
  }
}

type Token = { kind: "word" | "punctuation"; value: string };

function tokenize(content: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < content.length) {
    const char = content[index]!;
    if (/\s/.test(char)) {
      index++;
      continue;
    }
    if (char === "/" && content[index + 1] === "/") {
      index += 2;
      while (index < content.length && content[index] !== "\n") index++;
      continue;
    }
    if (char === "/" && content[index + 1] === "*") {
      const close = content.indexOf("*/", index + 2);
      if (close < 0) throw new PbxParseError("Unclosed Xcode project comment.");
      index = close + 2;
      continue;
    }
    if (char === '"') {
      index++;
      let value = "";
      let closed = false;
      while (index < content.length) {
        const current = content[index++]!;
        if (current === '"') {
          closed = true;
          break;
        }
        if (current === "\\" && index < content.length) {
          value += content[index++]!;
        } else {
          value += current;
        }
      }
      if (!closed) throw new PbxParseError("Unclosed Xcode project string.");
      tokens.push({ kind: "word", value });
      continue;
    }
    if ("{}()=;,".includes(char)) {
      tokens.push({ kind: "punctuation", value: char });
      index++;
      continue;
    }
    const start = index;
    while (
      index < content.length &&
      !/\s/.test(content[index]!) &&
      !"{}()=;,\"".includes(content[index]!) &&
      !(content[index] === "/" && ["/", "*"].includes(content[index + 1] ?? ""))
    ) index++;
    if (index === start) throw new PbxParseError("Unsupported Xcode project syntax.");
    tokens.push({ kind: "word", value: content.slice(start, index) });
  }
  return tokens;
}

class Parser {
  private index = 0;

  constructor(private readonly tokens: readonly Token[]) {}

  private punctuation(value: string): boolean {
    const token = this.tokens[this.index];
    return token?.kind === "punctuation" && token.value === value;
  }

  private consumePunctuation(value: string): void {
    if (!this.punctuation(value)) throw new PbxParseError(`Expected '${value}'.`);
    this.index++;
  }

  private word(): string {
    const token = this.tokens[this.index++];
    if (token?.kind !== "word") throw new PbxParseError("Expected Xcode project value.");
    return token.value;
  }

  private dictionary(): PbxDictionary {
    this.consumePunctuation("{");
    const dictionary: PbxDictionary = new Map();
    while (!this.punctuation("}")) {
      const key = this.word();
      this.consumePunctuation("=");
      if (dictionary.has(key)) {
        throw new PbxParseError(`Duplicate Xcode project dictionary key '${key}'.`);
      }
      dictionary.set(key, this.value());
      this.consumePunctuation(";");
    }
    this.consumePunctuation("}");
    return dictionary;
  }

  private array(): PbxValue[] {
    this.consumePunctuation("(");
    const values: PbxValue[] = [];
    while (!this.punctuation(")")) {
      values.push(this.value());
      if (this.punctuation(",")) this.index++;
    }
    this.consumePunctuation(")");
    return values;
  }

  private value(): PbxValue {
    if (this.punctuation("{")) return this.dictionary();
    if (this.punctuation("(")) return this.array();
    return this.word();
  }

  parse(): PbxDictionary {
    const root = this.dictionary();
    if (this.index !== this.tokens.length) throw new PbxParseError("Trailing Xcode project syntax.");
    return root;
  }
}

function isDictionary(value: PbxValue | undefined): value is PbxDictionary {
  return value instanceof Map;
}

function releaseConfigurationName(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    /(?:^|[-_ .])release(?:$|[-_ .])/.test(normalized) ||
    /(?:^|[-_ .])production(?:$|[-_ .])/.test(normalized) ||
    /(?:^|[-_ .])prod(?:$|[-_ .])/.test(normalized) ||
    /(?:^|[-_ .])appstore(?:$|[-_ .])/.test(normalized) ||
    /(?:^|[-_ .])app-store(?:$|[-_ .])/.test(normalized) ||
    /(?:^|[-_ .])distribution(?:$|[-_ .])/.test(normalized)
  );
}

function platformValues(value: PbxValue | undefined): string[] {
  if (typeof value === "string") return value.toLowerCase().split(/\s+/).filter(Boolean);
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => typeof entry === "string" ? [entry.toLowerCase()] : []);
}

function configurationPlatforms(buildSettings: PbxDictionary): {
  iphone: boolean;
  otherApple: boolean;
} {
  const sdkRoots = platformValues(buildSettings.get("SDKROOT"));
  const supported = platformValues(buildSettings.get("SUPPORTED_PLATFORMS"));
  const platforms = [...sdkRoots, ...supported];
  const iphone = platforms.some(
    (platform) => platform === "iphoneos" || platform === "iphonesimulator",
  );
  const otherApple = platforms.some((platform) => [
    "appletvos",
    "appletvsimulator",
    "macosx",
    "watchos",
    "watchsimulator",
    "xros",
    "xrsimulator",
  ].includes(platform));
  return { iphone, otherApple };
}

function visitDictionaries(value: PbxValue, visit: (dictionary: PbxDictionary) => void): void {
  if (isDictionary(value)) {
    visit(value);
    for (const child of value.values()) visitDictionaries(child, visit);
  } else if (Array.isArray(value)) {
    for (const child of value) visitDictionaries(child, visit);
  }
}

function selectedBuildConfigurations(root: PbxDictionary): PbxDictionary[] {
  const objects = root.get("objects");
  if (isDictionary(objects)) {
    const referencedIds = new Set<string>();
    let sawConfigurationList = false;
    for (const value of objects.values()) {
      if (!isDictionary(value) || value.get("isa") !== "XCConfigurationList") continue;
      sawConfigurationList = true;
      const configurations = value.get("buildConfigurations");
      if (!Array.isArray(configurations)) continue;
      for (const id of configurations) {
        if (typeof id === "string") referencedIds.add(id);
      }
    }

    // A real project declares active configurations through XCConfigurationList.
    // Once at least one list reference exists, orphaned/stale configuration objects
    // are excluded rather than treated as effective repository configuration.
    if (sawConfigurationList) {
      return [...referencedIds]
        .map((id) => objects.get(id))
        .filter((value): value is PbxDictionary =>
          isDictionary(value) && value.get("isa") === "XCBuildConfiguration"
        );
    }
  }

  // Conservative compatibility fallback for bounded list-less synthetic/minimal
  // projects. Production Xcode projects with configuration lists never use it.
  const configurations: PbxDictionary[] = [];
  visitDictionaries(root, (dictionary) => {
    if (dictionary.get("isa") === "XCBuildConfiguration") configurations.push(dictionary);
  });
  return configurations;
}

/** Extract only statically declared production/release build-setting paths. */
export function releaseConfigurationReferences(content: string): PbxReleaseReferences {
  const root = new Parser(tokenize(content)).parse();
  const candidates: Array<{
    buildSettings: PbxDictionary;
    references: PbxConfigurationReference[];
  }> = [];
  const references: PbxConfigurationReference[] = [];
  for (const dictionary of selectedBuildConfigurations(root)) {
    const name = dictionary.get("name");
    const buildSettings = dictionary.get("buildSettings");
    if (typeof name !== "string" || !releaseConfigurationName(name) || !isDictionary(buildSettings)) {
      continue;
    }
    const configurationReferences: PbxConfigurationReference[] = [];
    for (const setting of ["INFOPLIST_FILE", "CODE_SIGN_ENTITLEMENTS"] as const) {
      const value = buildSettings.get(setting);
      if (typeof value === "string" && value.trim()) {
        configurationReferences.push({ setting, value: value.trim() });
      }
    }
    candidates.push({ buildSettings, references: configurationReferences });
  }

  const platformEvidence = candidates.map(({ buildSettings }) =>
    configurationPlatforms(buildSettings)
  );
  const hasIphone = platformEvidence.some((platform) => platform.iphone);
  const hasOtherApple = platformEvidence.some((platform) => platform.otherApple);
  const projectWideIphoneOnly = hasIphone && !hasOtherApple;
  let configurations = 0;
  let skippedMixedPlatformReferences = 0;
  for (const [index, candidate] of candidates.entries()) {
    const platform = platformEvidence[index]!;
    // Xcode commonly puts SDKROOT on the project Release configuration and
    // INFOPLIST_FILE/CODE_SIGN_ENTITLEMENTS on separate target Release
    // configurations. Project-wide propagation is safe only when all explicit
    // Release platform evidence is iPhone-family. Mixed-platform projects must
    // prove iPhone applicability in the same configuration as each reference.
    if (projectWideIphoneOnly || platform.iphone) {
      configurations++;
      references.push(...candidate.references);
    } else if (hasIphone && hasOtherApple) {
      skippedMixedPlatformReferences += candidate.references.length;
    }
  }
  return {
    releaseCandidates: candidates.length,
    configurations,
    references,
    skippedMixedPlatformReferences,
  };
}
