/**
 * Bounded, read-only Android manifest and Network Security Config analysis.
 *
 * This module deliberately parses only repository XML. It never invokes Gradle,
 * follows target-provided code, resolves external/DTD-defined XML entities, or infers merge
 * behavior beyond the literal supported main/release overlays.
 */

import { lstat, readFile, readdir } from "node:fs/promises";
import { isIP } from "node:net";
import { basename, dirname, join, relative, resolve } from "node:path";

import { makeAiFinding } from "../../ai-checks/finding.js";
import type { Finding, Severity } from "../../types.js";
import type { NativeAnalyzerResult } from "../types.js";

export const ANDROID_DEBUGGABLE_RULE_ID = "ci-android-debuggable-release";
export const ANDROID_CLEARTEXT_RULE_ID = "ci-android-cleartext-traffic";
export const ANDROID_USER_CA_RULE_ID = "ci-android-user-ca-trust";
export const ANDROID_EXPORTED_FILE_PROVIDER_RULE_ID = "ci-android-exported-file-provider";

export const ANDROID_CONFIG_RULE_IDS = [
  ANDROID_DEBUGGABLE_RULE_ID,
  ANDROID_CLEARTEXT_RULE_ID,
  ANDROID_USER_CA_RULE_ID,
  ANDROID_EXPORTED_FILE_PROVIDER_RULE_ID,
] as const;

const ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android";
const TOOLS_NAMESPACE = "http://schemas.android.com/tools";
const MAX_XML_BYTES = 1024 * 1024;
const MAX_DIRECTORY_ENTRIES = 20_000;
const MAX_MANIFESTS = 500;
const MAX_WALK_DEPTH = 24;
const MAX_NOTES = 20;

const IGNORED_DIRECTORIES = new Set([
  ".dart_tool",
  ".git",
  ".gradle",
  ".idea",
  ".pub-cache",
  ".vscode",
  "build",
  "coverage",
  "debug",
  "demo",
  "demos",
  "dist",
  "example",
  "examples",
  "integration_test",
  "node_modules",
  "out",
  "pods",
  "profile",
  "sample",
  "samples",
  "androidtest",
  "test",
  "tests",
  "vendor",
]);

const FILE_PROVIDER_CLASSES = new Set([
  "androidx.core.content.FileProvider",
  "android.support.v4.content.FileProvider",
]);

interface XmlAttribute {
  name: string;
  prefix?: string;
  localName: string;
  value: string;
  line: number;
}

interface XmlElement {
  name: string;
  localName: string;
  line: number;
  attributes: XmlAttribute[];
  namespaces: ReadonlyMap<string, string>;
  parent?: XmlElement;
  children: XmlElement[];
  text: string;
}

interface ParsedXml {
  elements: XmlElement[];
  roots: XmlElement[];
  valid: boolean;
}

interface LoadedXml {
  path: string;
  relativePath: string;
  document: ParsedXml;
}

function qualifiedName(name: string): { prefix?: string; localName: string } {
  const colon = name.indexOf(":");
  if (colon < 0) return { localName: name };
  return { prefix: name.slice(0, colon), localName: name.slice(colon + 1) };
}

function decodeXmlText(value: string): string {
  return value.replace(
    /&(?:quot|apos|lt|gt|amp|#\d+|#x[\da-f]+);/gi,
    (entity) => {
      switch (entity.toLowerCase()) {
        case "&quot;": return "\"";
        case "&apos;": return "'";
        case "&lt;": return "<";
        case "&gt;": return ">";
        case "&amp;": return "&";
        default: {
          const hexadecimal = entity.toLowerCase().startsWith("&#x");
          const numeric = entity.slice(hexadecimal ? 3 : 2, -1);
          const codePoint = Number.parseInt(numeric, hexadecimal ? 16 : 10);
          return Number.isSafeInteger(codePoint) && codePoint >= 0 && codePoint <= 0x10ffff
            ? String.fromCodePoint(codePoint)
            : entity;
        }
      }
    },
  );
}

function lineStarts(source: string): number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index++) {
    if (source.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function lineAt(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    if (starts[middle]! <= offset) low = middle + 1;
    else high = middle - 1;
  }
  return high + 1;
}

function markupEnd(source: string, start: number): number {
  let quote: "\"" | "'" | undefined;
  let bracketDepth = 0;
  for (let index = start; index < source.length; index++) {
    const character = source[index]!;
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === "[") bracketDepth++;
    else if (character === "]" && bracketDepth > 0) bracketDepth--;
    else if (character === ">" && bracketDepth === 0) return index;
  }
  return -1;
}

interface ParsedTag {
  name: string;
  attributes: XmlAttribute[];
  selfClosing: boolean;
  valid: boolean;
}

function parseOpeningTag(body: string, bodyOffset: number, starts: readonly number[]): ParsedTag {
  let cursor = 0;
  while (/\s/.test(body[cursor] ?? "")) cursor++;
  const nameStart = cursor;
  while (cursor < body.length && !/[\s/>]/.test(body[cursor]!)) cursor++;
  const name = body.slice(nameStart, cursor);
  if (!name) return { name: "", attributes: [], selfClosing: false, valid: false };

  const attributes: XmlAttribute[] = [];
  const attributeNames = new Set<string>();
  let valid = true;
  let selfClosing = false;
  while (cursor < body.length) {
    while (/\s/.test(body[cursor] ?? "")) cursor++;
    if (body[cursor] === "/") {
      selfClosing = true;
      cursor++;
      while (/\s/.test(body[cursor] ?? "")) cursor++;
      if (cursor !== body.length) valid = false;
      break;
    }
    if (cursor >= body.length) break;

    const attributeStart = cursor;
    while (cursor < body.length && !/[\s=/>]/.test(body[cursor]!)) cursor++;
    const attributeName = body.slice(attributeStart, cursor);
    while (/\s/.test(body[cursor] ?? "")) cursor++;
    if (!attributeName || body[cursor] !== "=") {
      valid = false;
      break;
    }
    cursor++;
    while (/\s/.test(body[cursor] ?? "")) cursor++;
    const quote = body[cursor];
    if (quote !== "\"" && quote !== "'") {
      valid = false;
      break;
    }
    cursor++;
    const valueStart = cursor;
    while (cursor < body.length && body[cursor] !== quote) cursor++;
    if (cursor >= body.length) {
      valid = false;
      break;
    }
    const parsedName = qualifiedName(attributeName);
    if (attributeNames.has(attributeName)) valid = false;
    attributeNames.add(attributeName);
    attributes.push({
      name: attributeName,
      ...parsedName,
      value: decodeXmlText(body.slice(valueStart, cursor)),
      line: lineAt(starts, bodyOffset + attributeStart),
    });
    cursor++;
  }
  return { name, attributes, selfClosing, valid };
}

/** Small non-validating XML parser: no external/DTD-defined entity expansion or executable hooks. */
function parseXml(source: string): ParsedXml {
  const starts = lineStarts(source);
  const elements: XmlElement[] = [];
  const roots: XmlElement[] = [];
  const stack: XmlElement[] = [];
  let valid = true;
  let cursor = 0;

  while (cursor < source.length) {
    const open = source.indexOf("<", cursor);
    if (open < 0) {
      if (stack.length) stack.at(-1)!.text += decodeXmlText(source.slice(cursor));
      break;
    }
    if (stack.length && open > cursor) {
      stack.at(-1)!.text += decodeXmlText(source.slice(cursor, open));
    }
    if (source.startsWith("<!--", open)) {
      const close = source.indexOf("-->", open + 4);
      if (close < 0) {
        valid = false;
        break;
      }
      cursor = close + 3;
      continue;
    }
    if (source.startsWith("<![CDATA[", open)) {
      const close = source.indexOf("]]>", open + 9);
      if (close < 0) {
        valid = false;
        break;
      }
      if (stack.length) stack.at(-1)!.text += source.slice(open + 9, close);
      cursor = close + 3;
      continue;
    }
    if (source.startsWith("<?", open)) {
      const close = source.indexOf("?>", open + 2);
      if (close < 0) {
        valid = false;
        break;
      }
      cursor = close + 2;
      continue;
    }
    if (source.startsWith("<!", open)) {
      const close = markupEnd(source, open + 2);
      if (close < 0) {
        valid = false;
        break;
      }
      cursor = close + 1;
      continue;
    }

    const close = markupEnd(source, open + 1);
    if (close < 0) {
      valid = false;
      break;
    }
    const body = source.slice(open + 1, close);
    if (body.trimStart().startsWith("/")) {
      const closingName = body.trim().slice(1).trim();
      const current = stack.pop();
      if (!current || current.name !== closingName) valid = false;
      cursor = close + 1;
      continue;
    }

    const parsed = parseOpeningTag(body, open + 1, starts);
    if (!parsed.valid) valid = false;
    if (!parsed.name) {
      cursor = close + 1;
      continue;
    }
    const parent = stack.at(-1);
    const namespaces = new Map(parent?.namespaces ?? []);
    for (const attribute of parsed.attributes) {
      if (attribute.name === "xmlns") namespaces.set("", attribute.value);
      else if (attribute.prefix === "xmlns") namespaces.set(attribute.localName, attribute.value);
    }
    const expandedAttributeNames = new Set<string>();
    for (const attribute of parsed.attributes) {
      const namespace = attribute.prefix && attribute.prefix !== "xmlns"
        ? namespaces.get(attribute.prefix) ?? `unbound:${attribute.prefix}`
        : attribute.prefix === "xmlns" || attribute.name === "xmlns"
          ? "http://www.w3.org/2000/xmlns/"
          : "";
      const key = `${namespace}\0${attribute.localName}`;
      if (expandedAttributeNames.has(key)) valid = false;
      expandedAttributeNames.add(key);
    }
    const element: XmlElement = {
      name: parsed.name,
      localName: qualifiedName(parsed.name).localName,
      line: lineAt(starts, open),
      attributes: parsed.attributes,
      namespaces,
      ...(parent ? { parent } : {}),
      children: [],
      text: "",
    };
    elements.push(element);
    if (parent) parent.children.push(element);
    else roots.push(element);
    if (!parsed.selfClosing) stack.push(element);
    cursor = close + 1;
  }

  if (stack.length || roots.length !== 1) valid = false;
  return { elements, roots, valid };
}

function namespacedAttribute(
  element: XmlElement,
  namespace: string,
  localName: string,
): XmlAttribute | undefined {
  return element.attributes.find((attribute) =>
    attribute.localName === localName &&
    attribute.prefix !== undefined &&
    element.namespaces.get(attribute.prefix) === namespace
  );
}

function androidAttribute(element: XmlElement, localName: string): XmlAttribute | undefined {
  return namespacedAttribute(element, ANDROID_NAMESPACE, localName);
}

function plainAttribute(element: XmlElement, name: string): XmlAttribute | undefined {
  return element.attributes.find((attribute) => attribute.name === name);
}

function isTrue(attribute: XmlAttribute | undefined): boolean {
  return attribute?.value.trim().toLowerCase() === "true";
}

function relativeXmlPath(root: string, path: string): string {
  const value = relative(root, path).replace(/\\/g, "/");
  return value && !value.startsWith("../") ? value : basename(path);
}

function finding(spec: {
  ruleId: string;
  title: string;
  severity: Severity;
  cwe: string[];
  file: string;
  line: number;
  snippet: string;
  message: string;
  summary: string;
  steps: string[];
  references: string[];
}): Finding {
  return makeAiFinding({
    ruleId: spec.ruleId,
    title: spec.title,
    severity: spec.severity,
    cwe: spec.cwe,
    file: spec.file,
    startLine: spec.line,
    snippet: spec.snippet,
    message: spec.message,
    remediation: {
      summary: spec.summary,
      steps: spec.steps,
      references: spec.references,
    },
    confidence: "high",
  });
}

function debuggableFinding(file: string, line: number): Finding {
  return finding({
    ruleId: ANDROID_DEBUGGABLE_RULE_ID,
    title: "Android production manifest explicitly enables debugging",
    severity: "medium",
    cwe: ["CWE-489"],
    file,
    line,
    snippet: '<application android:debuggable="true">',
    message:
      "A main or release Android manifest explicitly marks the application as debuggable. A shipped debuggable build gives an attacker additional inspection and runtime-control capabilities.",
    summary: "Disable debugging in every production manifest and release build type.",
    steps: [
      "Remove android:debuggable=\"true\" from main and release manifests, or set it to false.",
      "Keep debug-only behavior in the debug source set instead of the production manifest.",
      "Inspect the merged release manifest or built APK to confirm the final debuggable value is false.",
    ],
    references: [
      "CWE-489",
      "https://cwe.mitre.org/data/definitions/489.html",
      "https://developer.android.com/privacy-and-security/risks/android-debuggable",
    ],
  });
}

function cleartextFinding(file: string, line: number, scope: "application" | "base" | "domain"): Finding {
  const scopeMessage = scope === "application"
    ? "The production application manifest explicitly permits cleartext traffic."
    : scope === "base"
      ? "The referenced Network Security Config explicitly permits cleartext traffic globally."
      : "The referenced Network Security Config explicitly permits cleartext traffic to a non-local domain.";
  return finding({
    ruleId: ANDROID_CLEARTEXT_RULE_ID,
    title: "Android production configuration explicitly permits cleartext traffic",
    severity: "medium",
    cwe: ["CWE-319"],
    file,
    line,
    snippet: scope === "application"
      ? '<application android:usesCleartextTraffic="true">'
      : scope === "base"
        ? '<base-config cleartextTrafficPermitted="true">'
        : '<domain-config cleartextTrafficPermitted="true"> [DOMAIN REDACTED]',
    message: `${scopeMessage} Any HTTP request allowed by this setting lacks transport confidentiality and integrity.`,
    summary: "Disallow cleartext transport in production Android configuration.",
    steps: [
      "Set usesCleartextTraffic and cleartextTrafficPermitted to false for production.",
      "Move any local-development exception into a debug-only source set and restrict it to loopback or emulator hosts.",
      "Verify production endpoints use HTTPS with platform certificate validation.",
    ],
    references: [
      "CWE-319",
      "https://cwe.mitre.org/data/definitions/319.html",
      "https://developer.android.com/privacy-and-security/security-config",
    ],
  });
}

function userCaFinding(file: string, line: number): Finding {
  return finding({
    ruleId: ANDROID_USER_CA_RULE_ID,
    title: "Android production network configuration trusts user-added CAs",
    severity: "medium",
    cwe: ["CWE-295"],
    file,
    line,
    snippet: '<certificates src="user">',
    message:
      "A production base/domain trust configuration includes the device user certificate store. A user-installed CA can therefore authenticate connections that the platform system trust store alone would reject.",
    summary: "Limit user-added CA trust to Android debug overrides.",
    steps: [
      "Remove certificates src=\"user\" from base-config and domain-config trust anchors.",
      "If a development proxy is required, place the user CA under debug-overrides only.",
      "Inspect the merged release resources and test that a user-installed interception CA is rejected.",
    ],
    references: [
      "CWE-295",
      "https://cwe.mitre.org/data/definitions/295.html",
      "https://developer.android.com/privacy-and-security/security-config#ConfigCustom",
    ],
  });
}

function exportedFileProviderFinding(file: string, line: number): Finding {
  return finding({
    ruleId: ANDROID_EXPORTED_FILE_PROVIDER_RULE_ID,
    title: "Android FileProvider is exported to other applications",
    severity: "high",
    cwe: ["CWE-926"],
    file,
    line,
    snippet:
      '<provider android:name="androidx.core.content.FileProvider" android:exported="true">',
    message:
      "The AndroidX/support FileProvider is explicitly exported. FileProvider is designed to remain private and grant narrow, temporary URI permissions instead of exposing the provider itself.",
    summary: "Make FileProvider private and share individual URIs with temporary grants.",
    steps: [
      "Set android:exported=\"false\" on the FileProvider declaration.",
      "Keep android:grantUriPermissions=\"true\" and grant only the required content URI to the receiving app.",
      "Review the referenced FILE_PROVIDER_PATHS resource so it exposes only the minimum directories required.",
    ],
    references: [
      "CWE-926",
      "https://cwe.mitre.org/data/definitions/926.html",
      "https://developer.android.com/reference/androidx/core/content/FileProvider",
    ],
  });
}

function productionManifest(path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  if (/(?:^|\/)(?:debug|profile|test|tests|androidtest|integration_test|example|examples)(?:\/|$)/i.test(normalized)) {
    return false;
  }
  const sourceSet = normalized.match(/(?:^|\/)src\/([^/]+)\/AndroidManifest\.xml$/i)?.[1]?.toLowerCase();
  if (sourceSet) return sourceSet === "main" || sourceSet === "release";
  return basename(path).toLowerCase() === "androidmanifest.xml";
}

function directManifestPath(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  return normalized.match(/src\/[^/]+\/AndroidManifest\.xml$/i)?.[0] ?? basename(path);
}

function productionDomain(value: string): boolean {
  const domain = value.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!domain || domain.includes("$") || domain.includes("*")) return false;
  if (
    domain === "localhost" ||
    domain === "ip6-localhost" ||
    domain === "0.0.0.0" ||
    domain === "127.0.0.1" ||
    domain === "::1" ||
    domain === "10.0.2.2" ||
    domain === "10.0.3.2"
  ) return false;
  if (
    domain === "example.com" || domain.endsWith(".example.com") ||
    domain === "example.org" || domain.endsWith(".example.org") ||
    domain === "example.net" || domain.endsWith(".example.net") ||
    domain.endsWith(".example") || domain.endsWith(".test") || domain.endsWith(".invalid") ||
    domain.endsWith(".localhost") || domain.endsWith(".local")
  ) return false;
  const ipVersion = isIP(domain);
  if (ipVersion === 4) {
    const octets = domain.split(".").map(Number);
    const [first = -1, second = -1] = octets;
    return !(
      first === 0 || first === 10 || first === 127 ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168)
    );
  }
  if (ipVersion === 6) {
    return !(
      domain === "::" || domain === "::1" ||
      /^(?:fc|fd)/i.test(domain) || /^fe[89ab]/i.test(domain)
    );
  }
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain);
}

interface ManifestCoordinates {
  moduleKey: string;
  sourceSet: "main" | "release" | "standalone";
}

function manifestCoordinates(path: string): ManifestCoordinates {
  const normalized = path.replace(/\\/g, "/");
  const match = /^(.*)\/src\/(main|release)\/AndroidManifest\.xml$/i.exec(normalized);
  if (!match) return { moduleKey: normalized, sourceSet: "standalone" };
  return {
    moduleKey: match[1]!,
    sourceSet: match[2]!.toLowerCase() as "main" | "release",
  };
}

function createNoteCollector(): { add: (note: string) => void; finish: () => string[] } {
  const notes = new Set<string>();
  let omitted = 0;
  return {
    add(note) {
      if (notes.has(note)) return;
      if (notes.size < MAX_NOTES - 1) notes.add(note);
      else omitted++;
    },
    finish() {
      return [
        ...notes,
        ...(omitted ? [`${omitted} additional Android configuration limitations omitted.`] : []),
      ].sort();
    },
  };
}

async function loadXml(
  path: string,
  root: string,
  addNote: (note: string) => void,
): Promise<LoadedXml | undefined> {
  const relativePath = relativeXmlPath(root, path);
  try {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      addNote(`Skipped symlinked Android XML file ${relativePath}.`);
      return undefined;
    }
    if (!metadata.isFile()) return undefined;
    if (metadata.size > MAX_XML_BYTES) {
      addNote(`Skipped oversized Android XML file ${relativePath} (limit: 1 MiB).`);
      return undefined;
    }
    const document = parseXml(await readFile(path, "utf8"));
    if (!document.valid) {
      addNote(`Skipped malformed Android XML file ${relativePath}.`);
      return undefined;
    }
    return { path, relativePath, document };
  } catch {
    addNote(`Skipped unreadable Android XML file ${relativePath}.`);
    return undefined;
  }
}

interface ManifestGroup {
  moduleKey: string;
  main?: LoadedXml;
  release?: LoadedXml;
  standalone?: LoadedXml;
}

interface SourcedAttribute {
  attribute: XmlAttribute;
  file: LoadedXml;
}

interface ManifestAnalysis {
  findings: Finding[];
  /** Ordered release-first resource candidates for one effective literal reference. */
  networkConfigCandidates: string[][];
}

function application(file: LoadedXml | undefined): XmlElement | undefined {
  return file?.document.elements.find((element) =>
    element.localName === "application" && element.parent?.localName === "manifest"
  );
}

function toolsNode(element: XmlElement | undefined): string | undefined {
  return element ? namespacedAttribute(element, TOOLS_NAMESPACE, "node")?.value.trim().toLowerCase() : undefined;
}

function toolsRemovesAttribute(element: XmlElement | undefined, localName: string): boolean {
  if (!element) return false;
  const removed = namespacedAttribute(element, TOOLS_NAMESPACE, "remove")?.value ?? "";
  return removed
    .split(/[\s,]+/)
    .map((value) => value.trim().split(":").at(-1))
    .includes(localName);
}

function effectiveApplicationAttribute(
  group: ManifestGroup,
  localName: string,
): SourcedAttribute | undefined {
  const releaseApplication = application(group.release);
  const releaseAttribute = releaseApplication && androidAttribute(releaseApplication, localName);
  if (releaseAttribute && group.release) return { attribute: releaseAttribute, file: group.release };
  if (
    toolsNode(releaseApplication) === "replace" ||
    toolsRemovesAttribute(releaseApplication, localName)
  ) return undefined;
  const baseFile = group.main ?? group.standalone;
  const baseApplication = application(baseFile);
  const baseAttribute = baseApplication && androidAttribute(baseApplication, localName);
  return baseAttribute && baseFile ? { attribute: baseAttribute, file: baseFile } : undefined;
}

interface ProviderDeclaration {
  file: LoadedXml;
  element: XmlElement;
  exported?: XmlAttribute;
  mode?: string;
}

function fileProviderDeclarations(file: LoadedXml | undefined): Map<string, ProviderDeclaration> {
  const providers = new Map<string, ProviderDeclaration>();
  if (!file) return providers;
  for (const element of file.document.elements) {
    if (element.localName !== "provider" || element.parent?.localName !== "application") continue;
    const name = androidAttribute(element, "name")?.value.trim();
    if (!name || !FILE_PROVIDER_CLASSES.has(name)) continue;
    providers.set(name, {
      file,
      element,
      exported: androidAttribute(element, "exported"),
      mode: toolsNode(element),
    });
  }
  return providers;
}

function resourceCandidates(group: ManifestGroup, resourceName: string): string[] {
  const filename = `${resourceName}.xml`;
  if (group.standalone) {
    return [join(dirname(group.standalone.path), "res", "xml", filename)];
  }
  return [
    join(group.moduleKey, "src", "release", "res", "xml", filename),
    join(group.moduleKey, "src", "main", "res", "xml", filename),
  ];
}

function literalBoolean(
  sourced: SourcedAttribute | undefined,
  label: string,
  addNote: (note: string) => void,
): boolean | undefined {
  if (!sourced) return undefined;
  const value = sourced.attribute.value.trim().toLowerCase();
  if (value === "true") return true;
  if (value === "false") return false;
  addNote(
    `Skipped dynamic ${label} in ${sourced.file.relativePath}; the effective release value requires manifest merging.`,
  );
  return undefined;
}

function analyzeManifestGroup(
  group: ManifestGroup,
  addNote: (note: string) => void,
): ManifestAnalysis {
  const findings: Finding[] = [];
  const networkConfigCandidates: string[][] = [];

  // A main-manifest value does not prove a debuggable release because Gradle's
  // release build type can override it. Only explicit src/release evidence fires.
  const releaseApplication = application(group.release);
  const releaseDebuggable = releaseApplication && androidAttribute(releaseApplication, "debuggable");
  if (releaseDebuggable && group.release) {
    const value = literalBoolean(
      { attribute: releaseDebuggable, file: group.release },
      "android:debuggable value",
      addNote,
    );
    if (value === true) {
      findings.push(debuggableFinding(group.release.relativePath, releaseDebuggable.line));
    }
  }

  const effectiveNetworkConfig = effectiveApplicationAttribute(group, "networkSecurityConfig");
  if (effectiveNetworkConfig) {
    const match = /^@xml\/([A-Za-z0-9_.-]+)$/.exec(effectiveNetworkConfig.attribute.value.trim());
    if (match) {
      networkConfigCandidates.push(resourceCandidates(group, match[1]!));
    } else {
      addNote(
        `Could not resolve dynamic Android Network Security Config reference in ${effectiveNetworkConfig.file.relativePath}.`,
      );
    }
    // Android 7+ ignores usesCleartextTraffic when a Network Security Config is
    // present. Analyze the effective referenced resource instead of double-reporting
    // a possibly contradictory manifest flag.
  } else {
    const cleartext = effectiveApplicationAttribute(group, "usesCleartextTraffic");
    if (literalBoolean(cleartext, "android:usesCleartextTraffic value", addNote) === true && cleartext) {
      findings.push(cleartextFinding(cleartext.file.relativePath, cleartext.attribute.line, "application"));
    }
  }

  const baseProviders = fileProviderDeclarations(group.main ?? group.standalone);
  const releaseProviders = fileProviderDeclarations(group.release);
  const providerNames = new Set([...baseProviders.keys(), ...releaseProviders.keys()]);
  for (const providerName of providerNames) {
    const base = baseProviders.get(providerName);
    const overlay = releaseProviders.get(providerName);
    if (overlay?.mode === "remove") continue;
    const effective = overlay?.exported
      ? { attribute: overlay.exported, file: overlay.file }
      : overlay?.mode === "replace" || toolsRemovesAttribute(overlay?.element, "exported")
        ? undefined
        : base?.exported
          ? { attribute: base.exported, file: base.file }
          : undefined;
    if (literalBoolean(effective, "android:exported FileProvider value", addNote) === true && effective) {
      findings.push(exportedFileProviderFinding(effective.file.relativePath, effective.attribute.line));
    }
  }
  return { findings, networkConfigCandidates };
}

function analyzeNetworkSecurityConfig(file: LoadedXml): Finding[] {
  const root = file.document.roots[0];
  if (root?.localName !== "network-security-config") return [];
  const findings: Finding[] = [];
  const globalCleartext = file.document.elements.find((element) =>
    element.localName === "base-config" &&
    element.parent === root &&
    isTrue(plainAttribute(element, "cleartextTrafficPermitted"))
  );
  if (globalCleartext) {
    findings.push(cleartextFinding(
      file.relativePath,
      plainAttribute(globalCleartext, "cleartextTrafficPermitted")!.line,
      "base",
    ));
  }
  for (const element of file.document.elements) {
    const validDomainConfig = element.localName === "domain-config" && (() => {
      let parent = element.parent;
      while (parent && parent !== root) {
        if (parent.localName !== "domain-config") return false;
        parent = parent.parent;
      }
      return parent === root;
    })();
    const cleartext = plainAttribute(element, "cleartextTrafficPermitted");
    if (!globalCleartext && validDomainConfig && isTrue(cleartext)) {
      const hasProductionDomain = element.children
        .filter((child) => child.localName === "domain")
        .some((domain) => productionDomain(domain.text));
      if (hasProductionDomain) {
        findings.push(cleartextFinding(file.relativePath, cleartext!.line, "domain"));
      }
    }

    const trustScope = element.parent?.localName === "trust-anchors"
      ? element.parent.parent
      : undefined;
    const productionTrustScope = (
      trustScope?.localName === "base-config" && trustScope.parent === root
    ) || (
      trustScope?.localName === "domain-config" &&
      (() => {
        let parent = trustScope.parent;
        while (parent && parent !== root) {
          if (parent.localName !== "domain-config") return false;
          parent = parent.parent;
        }
        return parent === root;
      })() &&
      trustScope.children
        .filter((child) => child.localName === "domain")
        .some((domain) => productionDomain(domain.text))
    );
    if (
      element.localName === "certificates" &&
      plainAttribute(element, "src")?.value.trim().toLowerCase() === "user" &&
      element.parent?.localName === "trust-anchors" &&
      productionTrustScope
    ) {
      findings.push(userCaFinding(file.relativePath, plainAttribute(element, "src")!.line));
    }
  }
  return findings;
}

async function findProductionManifests(
  root: string,
  addNote: (note: string) => void,
): Promise<string[]> {
  const manifests: string[] = [];
  let entriesVisited = 0;
  let boundsReported = false;

  async function walk(directory: string, depth: number): Promise<void> {
    if (entriesVisited >= MAX_DIRECTORY_ENTRIES || manifests.length >= MAX_MANIFESTS) {
      if (!boundsReported) {
        boundsReported = true;
        addNote(
          `Android configuration discovery stopped at ${MAX_DIRECTORY_ENTRIES} directory entries or ${MAX_MANIFESTS} production manifests.`,
        );
      }
      return;
    }
    if (depth > MAX_WALK_DEPTH) {
      if (!boundsReported) {
        boundsReported = true;
        addNote(`Android configuration discovery skipped directories deeper than ${MAX_WALK_DEPTH} levels.`);
      }
      return;
    }
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      addNote(`Skipped unreadable Android configuration directory ${relativeXmlPath(root, directory)}.`);
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (entriesVisited++ >= MAX_DIRECTORY_ENTRIES) break;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) await walk(path, depth + 1);
      } else if (
        entry.isFile() &&
        entry.name.toLowerCase() === "androidmanifest.xml" &&
        productionManifest(relative(root, path))
      ) {
        manifests.push(path);
        if (manifests.length >= MAX_MANIFESTS) break;
      }
    }
  }

  await walk(root, 0);
  if (!boundsReported && (entriesVisited > MAX_DIRECTORY_ENTRIES || manifests.length >= MAX_MANIFESTS)) {
    addNote(
      `Android configuration discovery stopped at ${MAX_DIRECTORY_ENTRIES} directory entries or ${MAX_MANIFESTS} production manifests.`,
    );
  }
  return manifests.sort();
}

async function firstExistingResource(candidates: readonly string[]): Promise<string | undefined> {
  for (const candidate of candidates) {
    try {
      const metadata = await lstat(candidate);
      // Return the first effective overlay even when it is a symlink. loadXml()
      // will report and reject it without falling back to a lower-priority file.
      if (metadata.isSymbolicLink()) return candidate;
      if (metadata.isFile()) return candidate;
    } catch {
      // Resource-overlay lookup intentionally falls through from release to main.
    }
  }
  return undefined;
}

/**
 * Analyze explicit production Android XML configuration. Directory scans inspect
 * main/release manifests and only Network Security Config files they reference.
 */
export async function runAndroidConfig(target: string): Promise<NativeAnalyzerResult> {
  const absoluteTarget = resolve(target);
  const notes = createNoteCollector();
  const findings: Finding[] = [];
  let metadata;
  try {
    metadata = await lstat(absoluteTarget);
  } catch {
    return { findings: [], notes: ["Android configuration target was unreadable."] };
  }
  if (metadata.isSymbolicLink()) {
    return { findings: [], notes: ["Android configuration target was a symlink and was not followed."] };
  }
  if (!metadata.isDirectory() && !metadata.isFile()) {
    return { findings: [], notes: ["Android configuration target was not a regular file or directory."] };
  }

  const root = metadata.isDirectory() ? absoluteTarget : dirname(absoluteTarget);
  const manifests = metadata.isDirectory()
    ? await findProductionManifests(absoluteTarget, notes.add)
    : basename(absoluteTarget).toLowerCase() === "androidmanifest.xml" &&
        productionManifest(directManifestPath(absoluteTarget))
      ? [absoluteTarget]
      : [];
  const groups = new Map<string, ManifestGroup>();
  for (const manifestPath of manifests) {
    const manifest = await loadXml(manifestPath, root, notes.add);
    if (!manifest) continue;
    const coordinates = manifestCoordinates(manifestPath);
    const group = groups.get(coordinates.moduleKey) ?? { moduleKey: coordinates.moduleKey };
    group[coordinates.sourceSet] = manifest;
    groups.set(coordinates.moduleKey, group);
  }

  const networkConfigs = new Set<string>();
  for (const group of [...groups.values()].sort((left, right) => left.moduleKey.localeCompare(right.moduleKey))) {
    const analyzed = analyzeManifestGroup(group, notes.add);
    findings.push(...analyzed.findings);
    for (const candidates of analyzed.networkConfigCandidates) {
      const selected = await firstExistingResource(candidates);
      if (selected) networkConfigs.add(selected);
      else {
        const reference = candidates.map((candidate) => relativeXmlPath(root, candidate)).join(" or ");
        notes.add(`Could not resolve referenced Android Network Security Config at ${reference}.`);
      }
    }
  }

  if (
    metadata.isFile() &&
    absoluteTarget.toLowerCase().endsWith(".xml") &&
    basename(absoluteTarget).toLowerCase() !== "androidmanifest.xml"
  ) {
    networkConfigs.add(absoluteTarget);
  }

  for (const configPath of [...networkConfigs].sort()) {
    const config = await loadXml(configPath, root, notes.add);
    if (config) findings.push(...analyzeNetworkSecurityConfig(config));
  }

  findings.sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    left.location.start_line - right.location.start_line ||
    left.rule_id.localeCompare(right.rule_id)
  );
  const finishedNotes = notes.finish();
  return {
    findings,
    ...(finishedNotes.length ? { notes: finishedNotes } : {}),
  };
}
