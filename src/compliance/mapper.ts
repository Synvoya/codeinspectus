/**
 * Compliance mapper (PRD §10.1). Tags each finding's CWE(s) with framework
 * control IDs from data/cwe_to_controls.json, plus OWASP Web/LLM crosswalks and
 * loose MITRE ATT&CK technique context (never a coverage score, §10.1).
 *
 * Honest scope: code-level control coverage only — never certification.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DATA_DIR } from "../config.js";
import type { Finding, FrameworkTag } from "../types.js";

interface Mapping {
  control: string;
  confidence: string;
  rationale: string;
  source_citation: string;
  reviewer: string;
}
interface CweMapEntry {
  "NIST_CSF_2.0"?: Mapping[];
  "ISO27001:2022"?: Mapping[];
  SOC2?: Mapping[];
  "CIS_v8.1"?: Mapping[];
  EssentialEight?: Mapping[];
  owasp_web?: Mapping[];
  owasp_llm?: Mapping[];
  attack?: string[];
}
interface Bucket {
  cwes: string[];
  controls: CweMapEntry;
}
interface ComplianceData {
  code_visible_controls: Record<string, Array<{ id: string; name: string }>>;
  owasp_web_all_views: Record<string, number>;
  cwe_map: Record<string, CweMapEntry>;
  buckets: Record<string, Bucket>;
}

const FRAMEWORK_KEYS = [
  "NIST_CSF_2.0",
  "ISO27001:2022",
  "SOC2",
  "CIS_v8.1",
  "EssentialEight",
] as const;

let cached: ComplianceData | undefined;

export async function loadComplianceData(): Promise<ComplianceData> {
  if (cached) return cached;
  const raw = await readFile(join(DATA_DIR, "cwe_to_controls.json"), "utf8");
  cached = JSON.parse(raw) as ComplianceData;
  return cached;
}

function isDependencyVuln(f: Finding): boolean {
  return f.engine === "trivy" && /^(cve-|ghsa-)/i.test(f.rule_id);
}
function isMisconfig(f: Finding): boolean {
  return f.engine === "trivy" && /^(avd-|ds-|ksv|kcv|aws-|gcp-|azu-)/i.test(f.rule_id);
}

function addControls(acc: Map<string, Set<string>>, src: CweMapEntry | undefined): void {
  if (!src) return;
  for (const fw of FRAMEWORK_KEYS) {
    const maps = src[fw];
    if (maps && maps.length) {
      const set = acc.get(fw) ?? new Set<string>();
      for (const m of maps) set.add(m.control);
      acc.set(fw, set);
    }
  }
}

/** Tag a single finding in place; returns it for convenience. */
export function tagFinding(f: Finding, data: ComplianceData): Finding {
  const controls = new Map<string, Set<string>>();
  const owaspWeb = new Set<string>(f.owasp_web ?? []);
  const owaspLlm = new Set<string>(f.owasp_llm ?? []);
  const attack = new Set<string>(f.attack_techniques ?? []);

  const applyEntry = (e: CweMapEntry | undefined) => {
    if (!e) return;
    addControls(controls, e);
    for (const w of e.owasp_web ?? []) owaspWeb.add(w.control);
    for (const l of e.owasp_llm ?? []) owaspLlm.add(l.control);
    for (const a of e.attack ?? []) attack.add(a);
  };

  for (const cwe of f.cwe) {
    const entry = data.cwe_map[cwe];
    if (entry) {
      applyEntry(entry);
    } else {
      // Bucket fallback. Skip non-bucket keys (e.g. "_comment") and malformed
      // entries so a dependency-CVE CWE that isn't in cwe_map can't crash tagging.
      for (const [name, bucket] of Object.entries(data.buckets)) {
        if (name.startsWith("_")) continue;
        if (bucket && Array.isArray(bucket.cwes) && bucket.cwes.includes(cwe)) {
          applyEntry(bucket.controls);
        }
      }
    }
  }

  // Context-based buckets independent of CWE.
  if (isDependencyVuln(f)) applyEntry(data.buckets.vulnerable_component?.controls);
  if (isMisconfig(f)) applyEntry(data.buckets.misconfig?.controls);

  const frameworks: FrameworkTag[] = [];
  for (const [framework, set] of controls) {
    if (set.size) frameworks.push({ framework, controls: [...set].sort() });
  }

  f.frameworks = frameworks;
  if (owaspWeb.size) f.owasp_web = [...owaspWeb].sort();
  if (owaspLlm.size) f.owasp_llm = [...owaspLlm].sort();
  if (attack.size) f.attack_techniques = [...attack].sort();
  return f;
}

export async function tagFindings(findings: Finding[]): Promise<Finding[]> {
  const data = await loadComplianceData();
  for (const f of findings) tagFinding(f, data);
  return findings;
}
