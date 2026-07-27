import { makeAiFinding } from "../../ai-checks/finding.js";
import type { Finding } from "../../types.js";
import type { NativeAnalyzerResult } from "../types.js";

import {
  plistBoolean,
  plistDictionary,
  plistEntry,
  plistString,
  type PlistDictionary,
  type PlistDictionaryEntry,
} from "./plist.js";
import {
  resolveIosConfigurationProject,
  type IosConfigurationDocument,
  type IosConfigurationInput,
} from "./project.js";

export const IOS_ATS_GLOBAL_ARBITRARY_LOADS_RULE_ID =
  "ci-ios-ats-global-arbitrary-loads";
export const IOS_ATS_INSECURE_DOMAIN_RULE_ID =
  "ci-ios-ats-insecure-domain-exception";
export const IOS_ATS_WEAK_TLS_RULE_ID = "ci-ios-ats-weak-tls";
export const IOS_DATA_PROTECTION_DISABLED_RULE_ID =
  "ci-ios-data-protection-disabled";

export const IOS_CONFIG_RULE_IDS = [
  IOS_ATS_GLOBAL_ARBITRARY_LOADS_RULE_ID,
  IOS_ATS_INSECURE_DOMAIN_RULE_ID,
  IOS_ATS_WEAK_TLS_RULE_ID,
  IOS_DATA_PROTECTION_DISABLED_RULE_ID,
] as const;

const ATS_FINE_GRAINED_GLOBAL_KEYS = [
  "NSAllowsArbitraryLoadsForMedia",
  "NSAllowsArbitraryLoadsInWebContent",
  "NSAllowsLocalNetworking",
] as const;

const INSECURE_HTTP_KEYS = [
  "NSExceptionAllowsInsecureHTTPLoads",
  "NSTemporaryExceptionAllowsInsecureHTTPLoads",
] as const;

const MINIMUM_TLS_KEYS = [
  "NSExceptionMinimumTLSVersion",
  "NSTemporaryExceptionMinimumTLSVersion",
] as const;

const FORWARD_SECRECY_KEYS = [
  "NSExceptionRequiresForwardSecrecy",
  "NSTemporaryExceptionRequiresForwardSecrecy",
] as const;

const RESERVED_DOMAIN_SUFFIXES = [
  ".example",
  ".invalid",
  ".local",
  ".localhost",
  ".test",
] as const;

function entry(dictionary: PlistDictionary, key: string): PlistDictionaryEntry | undefined {
  return plistEntry(dictionary, key);
}

function atsDictionary(document: IosConfigurationDocument): PlistDictionary | undefined {
  if (document.kind !== "info") return undefined;
  return plistDictionary(entry(document.root, "NSAppTransportSecurity")?.value);
}

function concreteNonReservedDomain(value: string): boolean {
  const domain = value.trim().replace(/\.$/, "").toLowerCase();
  if (!domain || domain.length > 253 || /[$*{}()[\]/:\s]/.test(domain)) return false;
  if (["localhost", "local", "test", "example", "invalid", "demo"].includes(domain)) return false;
  if (RESERVED_DOMAIN_SUFFIXES.some((suffix) => domain.endsWith(suffix))) return false;
  if (
    ["example.com", "example.org", "example.net"].some(
      (reserved) => domain === reserved || domain.endsWith(`.${reserved}`),
    )
  ) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return false;
  }
  const topLevel = labels.at(-1)!;
  return /^[a-z]{2,63}$/.test(topLevel) || /^xn--[a-z0-9-]{2,59}$/.test(topLevel);
}

function globalArbitraryLoadsFinding(
  document: IosConfigurationDocument,
  ats: PlistDictionary,
): Finding | undefined {
  const arbitraryLoads = entry(ats, "NSAllowsArbitraryLoads");
  if (!arbitraryLoads || plistBoolean(arbitraryLoads.value) !== true) return undefined;
  // Apple documents that on iOS 10+ the legacy global switch is ignored when
  // any fine-grained global exception key is present, regardless of its value.
  if (ATS_FINE_GRAINED_GLOBAL_KEYS.some((key) => entry(ats, key) !== undefined)) return undefined;
  return makeAiFinding({
    ruleId: IOS_ATS_GLOBAL_ARBITRARY_LOADS_RULE_ID,
    title: "iOS App Transport Security allows arbitrary network loads",
    severity: "medium",
    cwe: ["CWE-319"],
    file: document.path,
    startLine: arbitraryLoads.key.line,
    snippet: "NSAllowsArbitraryLoads = true",
    message:
      "The effective iOS App Transport Security configuration permits arbitrary loads. This weakens transport protections repository-wide, although repository evidence alone does not prove that sensitive traffic uses an insecure connection.",
    remediation: {
      summary: "Keep App Transport Security enabled globally.",
      steps: [
        "Remove NSAllowsArbitraryLoads or set it to false.",
        "Upgrade application endpoints to HTTPS with modern TLS.",
        "If a legacy endpoint is unavoidable, use the narrowest domain-specific exception and document the App Store justification.",
      ],
      references: [
        "CWE-319",
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://developer.apple.com/documentation/security/preventing-insecure-network-connections",
        "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
      ],
    },
    confidence: "high",
  });
}

function domainDictionaries(
  ats: PlistDictionary,
): Array<{ domain: string; settings: PlistDictionary }> {
  const domains = plistDictionary(entry(ats, "NSExceptionDomains")?.value);
  if (!domains) return [];
  return domains.entries.flatMap((domainEntry) => {
    if (!concreteNonReservedDomain(domainEntry.key.value)) return [];
    const settings = plistDictionary(domainEntry.value);
    return settings ? [{ domain: domainEntry.key.value, settings }] : [];
  });
}

function insecureDomainFinding(
  document: IosConfigurationDocument,
  domain: string,
  settings: PlistDictionary,
): Finding | undefined {
  const insecure = INSECURE_HTTP_KEYS
    .map((key) => entry(settings, key))
    .find((candidate) => plistBoolean(candidate?.value) === true);
  if (!insecure) return undefined;
  return makeAiFinding({
    ruleId: IOS_ATS_INSECURE_DOMAIN_RULE_ID,
    title: "iOS ATS permits insecure HTTP for a non-local domain",
    severity: "medium",
    cwe: ["CWE-319"],
    file: document.path,
    startLine: insecure.key.line,
    snippet: "NSExceptionAllowsInsecureHTTPLoads = true",
    message:
      `The ATS exception for ${domain} explicitly permits insecure HTTP loads. Data sent to that domain can be exposed or modified in transit.`,
    remediation: {
      summary: "Remove the insecure HTTP exception and require HTTPS for this domain.",
      steps: [
        "Serve the endpoint over HTTPS with a valid certificate.",
        "Remove the insecure-load key or set it to false.",
        "Keep any unavoidable exception domain-specific and exclude authentication or sensitive data from it.",
      ],
      references: [
        "CWE-319",
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://developer.apple.com/documentation/security/preventing-insecure-network-connections",
        "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
      ],
    },
    confidence: "high",
  });
}

function weakTlsFinding(
  document: IosConfigurationDocument,
  domain: string,
  settings: PlistDictionary,
): Finding | undefined {
  const weakMinimum = MINIMUM_TLS_KEYS
    .map((key) => entry(settings, key))
    .find((candidate) => {
      const version = plistString(candidate?.value)?.trim().toLowerCase();
      return version === "tlsv1.0" || version === "tlsv1.1";
    });
  const noForwardSecrecy = FORWARD_SECRECY_KEYS
    .map((key) => entry(settings, key))
    .find((candidate) => plistBoolean(candidate?.value) === false);
  const unsafe = [weakMinimum, noForwardSecrecy]
    .filter((candidate): candidate is PlistDictionaryEntry => candidate !== undefined)
    .sort((left, right) => left.key.line - right.key.line)[0];
  if (!unsafe) return undefined;

  const weaknesses = [
    weakMinimum ? "a legacy minimum TLS version" : undefined,
    noForwardSecrecy ? "cipher suites without forward secrecy" : undefined,
  ].filter((value): value is string => value !== undefined);
  return makeAiFinding({
    ruleId: IOS_ATS_WEAK_TLS_RULE_ID,
    title: "iOS ATS weakens TLS requirements for a non-local domain",
    severity: "medium",
    cwe: ["CWE-327"],
    file: document.path,
    startLine: unsafe.key.line,
    snippet: weakMinimum
      ? "NSExceptionMinimumTLSVersion = legacy TLS"
      : "NSExceptionRequiresForwardSecrecy = false",
    message:
      `The ATS exception for ${domain} permits ${weaknesses.join(" and ")}. This allows weaker cryptographic negotiation than the ATS defaults.`,
    remediation: {
      summary: "Restore the default ATS TLS requirements for this domain.",
      steps: [
        "Require TLS 1.2 or newer at the endpoint and remove the lowered minimum-version setting.",
        "Remove the forward-secrecy exception or set it to true.",
        "Test the endpoint with the release application's actual ATS policy before removing compatibility settings.",
      ],
      references: [
        "CWE-327",
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://developer.apple.com/documentation/security/preventing-insecure-network-connections",
        "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
      ],
    },
    confidence: "high",
  });
}

function dataProtectionFinding(document: IosConfigurationDocument): Finding | undefined {
  if (document.kind !== "entitlements") return undefined;
  const protection = entry(document.root, "com.apple.developer.default-data-protection");
  if (!protection || plistString(protection.value)?.trim() !== "NSFileProtectionNone") return undefined;
  return makeAiFinding({
    ruleId: IOS_DATA_PROTECTION_DISABLED_RULE_ID,
    title: "iOS default data protection is disabled",
    severity: "medium",
    cwe: ["CWE-311"],
    file: document.path,
    startLine: protection.key.line,
    snippet: "com.apple.developer.default-data-protection = NSFileProtectionNone",
    message:
      "The selected iOS entitlements set the default file-protection class to NSFileProtectionNone. Files that rely on the application default receive no additional data-protection class.",
    remediation: {
      summary: "Use an iOS data-protection class appropriate for stored user data.",
      steps: [
        "Replace NSFileProtectionNone with NSFileProtectionComplete or another explicitly reviewed protected class.",
        "Review files that override the application default and migrate sensitive existing data if necessary.",
        "Verify the effective entitlement in the signed release application.",
      ],
      references: [
        "CWE-311",
        "https://cwe.mitre.org/data/definitions/311.html",
        "https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.default-data-protection",
        "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
      ],
    },
    confidence: "high",
  });
}

/** Run the four explicit iOS configuration checks over bounded repository evidence. */
export async function runIosConfig(
  input: IosConfigurationInput,
): Promise<NativeAnalyzerResult> {
  const project = await resolveIosConfigurationProject(input);
  const findings: Finding[] = [];
  for (const document of project.documents) {
    const ats = atsDictionary(document);
    if (ats) {
      const global = globalArbitraryLoadsFinding(document, ats);
      if (global) findings.push(global);
      for (const { domain, settings } of domainDictionaries(ats)) {
        const insecure = insecureDomainFinding(document, domain, settings);
        if (insecure) findings.push(insecure);
        const weakTls = weakTlsFinding(document, domain, settings);
        if (weakTls) findings.push(weakTls);
      }
    }
    const dataProtection = dataProtectionFinding(document);
    if (dataProtection) findings.push(dataProtection);
  }
  findings.sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    left.location.start_line - right.location.start_line ||
    left.rule_id.localeCompare(right.rule_id)
  );
  return {
    findings,
    ...(project.limitations.length ? { notes: project.limitations } : {}),
  };
}
