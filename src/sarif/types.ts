/**
 * Minimal SARIF 2.1.0 shape — only the fields CodeInspectus consumes. Parsed
 * losslessly enough to normalize; we do not model the entire SARIF spec.
 */

export interface SarifLog {
  version?: string;
  runs?: SarifRun[];
}

export interface SarifRun {
  tool?: { driver?: SarifDriver };
  results?: SarifResult[];
}

export interface SarifDriver {
  name?: string;
  version?: string;
  semanticVersion?: string;
  rules?: SarifRule[];
}

export interface SarifRule {
  id?: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  help?: { text?: string; markdown?: string };
  helpUri?: string;
  defaultConfiguration?: { level?: string };
  properties?: SarifProps;
  relationships?: Array<{ target?: { id?: string; toolComponent?: { name?: string } } }>;
}

export interface SarifProps {
  tags?: string[];
  cwe?: string | string[];
  "security-severity"?: string;
  cvssScore?: string | number;
  severity?: string;
  precision?: string;
  [k: string]: unknown;
}

export interface SarifResult {
  ruleId?: string;
  ruleIndex?: number;
  level?: string; // error | warning | note | none
  message?: { text?: string };
  locations?: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  fingerprints?: Record<string, string>;
  properties?: SarifProps;
}

export interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri?: string };
    region?: {
      startLine?: number;
      endLine?: number;
      snippet?: { text?: string };
    };
  };
}
