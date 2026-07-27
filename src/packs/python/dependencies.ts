/** Conservative dependency-name extraction for bounded Python project manifests. */

import { parse as parseToml } from "smol-toml";

export interface PythonDependencyParseResult {
  names: Set<string>;
  valid: boolean;
}

export function normalizePythonPackageName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

export function isPythonDependencyManifest(baseName: string): boolean {
  const base = baseName.toLowerCase();
  return base === "pyproject.toml" || base === "pipfile" || base === "setup.cfg" ||
    /^requirements(?:[._-][a-z0-9._-]+)?\.(?:txt|in)$/.test(base);
}

function requirementName(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("-") || trimmed.startsWith(".") || trimmed.startsWith("/")) {
    return undefined;
  }
  if (/^(?:git|https?|file):/i.test(trimmed)) return undefined;
  const match = trimmed.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*\[[^\]\r\n]+\])?(?=\s*(?:$|[<>=!~;@]))/);
  return match?.[1] ? normalizePythonPackageName(match[1]) : undefined;
}

function parseRequirements(content: string): PythonDependencyParseResult {
  const names = new Set<string>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    const name = requirementName(line);
    if (name) names.add(name);
  }
  return { names, valid: true };
}

function parseTomlDependencies(baseName: string, content: string): PythonDependencyParseResult {
  const names = new Set<string>();
  let root: Record<string, unknown>;
  try {
    root = parseToml(content) as Record<string, unknown>;
  } catch {
    return { names: new Set(), valid: false };
  }
  const record = (value: unknown): Record<string, unknown> | undefined =>
    value !== null && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : undefined;
  const addRequirements = (value: unknown): boolean => {
    if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return false;
    for (const item of value) {
      const name = requirementName(item);
      if (name) names.add(name);
    }
    return true;
  };
  const validConstraint = (value: unknown): boolean => {
    if (typeof value === "string") return value.trim().length > 0;
    const table = record(value);
    if (table) return Object.keys(table).length > 0;
    return Array.isArray(value) && value.length > 0 && value.every((item) =>
      typeof item === "string" && item.trim().length > 0 || Boolean(record(item) && Object.keys(record(item)!).length)
    );
  };
  const addConstraintTable = (value: unknown): boolean => {
    const table = record(value);
    if (!table) return value === undefined;
    for (const [key, constraint] of Object.entries(table)) {
      if (!validConstraint(constraint)) return false;
      const normalized = normalizePythonPackageName(key);
      if (normalized !== "python") names.add(normalized);
    }
    return true;
  };

  if (baseName.toLowerCase() === "pipfile") {
    if (!addConstraintTable(root.packages) || !addConstraintTable(root["dev-packages"])) {
      return { names: new Set(), valid: false };
    }
    return { names, valid: true };
  }

  const project = record(root.project);
  if (project?.dependencies !== undefined && !addRequirements(project.dependencies)) {
    return { names: new Set(), valid: false };
  }
  const optional = record(project?.["optional-dependencies"]);
  if (project?.["optional-dependencies"] !== undefined && !optional) {
    return { names: new Set(), valid: false };
  }
  for (const dependencies of Object.values(optional ?? {})) {
    if (!addRequirements(dependencies)) return { names: new Set(), valid: false };
  }

  const poetry = record(record(root.tool)?.poetry);
  if (!addConstraintTable(poetry?.dependencies)) return { names: new Set(), valid: false };
  const groups = record(poetry?.group);
  for (const group of Object.values(groups ?? {})) {
    if (!addConstraintTable(record(group)?.dependencies)) return { names: new Set(), valid: false };
  }
  return { names, valid: true };
}

function parseSetupCfg(content: string): PythonDependencyParseResult {
  const names = new Set<string>();
  const lines = content.split(/\r?\n/);
  let section = "";
  let collecting = false;
  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+[;#].*$/, "");
    const trimmed = line.trim();
    const sectionMatch = trimmed.match(/^\[([^\]]+)]$/);
    if (sectionMatch) {
      section = sectionMatch[1]!.trim().toLowerCase();
      collecting = false;
      continue;
    }
    if (section !== "options") continue;
    if (/^install_requires\s*=/i.test(trimmed)) {
      collecting = true;
      const name = requirementName(trimmed.replace(/^install_requires\s*=\s*/i, ""));
      if (name) names.add(name);
      continue;
    }
    if (!collecting) continue;
    if (line.length && !/^\s/.test(line)) {
      collecting = false;
      continue;
    }
    const name = requirementName(trimmed);
    if (name) names.add(name);
  }
  return { names, valid: true };
}

export function parsePythonDependencyManifest(
  baseName: string,
  content: string,
): PythonDependencyParseResult {
  const base = baseName.toLowerCase();
  if (/^requirements(?:[._-][a-z0-9._-]+)?\.(?:txt|in)$/.test(base)) {
    return parseRequirements(content);
  }
  if (base === "pyproject.toml" || base === "pipfile") {
    return parseTomlDependencies(base, content);
  }
  if (base === "setup.cfg") return parseSetupCfg(content);
  return { names: new Set(), valid: true };
}
