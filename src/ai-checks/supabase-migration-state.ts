/**
 * Ordered effective-state model for the Supabase RLS checks.
 *
 * This is deliberately a heuristic SQL reducer, not a PostgreSQL parser. It recognizes the
 * small set of DDL statements that determine whether the RLS findings in supabase-rls.ts are
 * active at the end of a checked migration sequence or standalone SQL snapshot.
 */

import type { SourceFile } from "./walk.js";
import { lineOf } from "./walk.js";

const IDENT = String.raw`(?:"(?:[^"]|"")*"|[a-zA-Z_][a-zA-Z0-9_$]*)`;
const QUALIFIED = String.raw`(?:(${IDENT})\s*\.\s*)?(${IDENT})`;

const CREATE_TABLE_RE = new RegExp(
  String.raw`^\s*create\s+(?:unlogged\s+)?table\s+(if\s+not\s+exists\s+)?${QUALIFIED}`,
  "i",
);
const DROP_TABLE_RE = new RegExp(
  String.raw`^\s*drop\s+table\s+(?:if\s+exists\s+)?([\s\S]+?)\s*$`,
  "i",
);
const QUALIFIED_RE = new RegExp(String.raw`^\s*${QUALIFIED}\s*$`);
const ALTER_RLS_RE = new RegExp(
  String.raw`^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QUALIFIED}\s*\*?\s+(enable|disable)\s+row\s+level\s+security\s*$`,
  "i",
);
const CREATE_POLICY_RE = new RegExp(
  String.raw`^\s*create\s+policy\s+(${IDENT})\s+on\s+${QUALIFIED}([\s\S]*)$`,
  "i",
);
const DROP_POLICY_RE = new RegExp(
  String.raw`^\s*drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+${QUALIFIED}(?:\s+(?:cascade|restrict))?\s*$`,
  "i",
);
const ALTER_POLICY_RE = new RegExp(
  String.raw`^\s*alter\s+policy\s+(${IDENT})\s+on\s+${QUALIFIED}([\s\S]*)$`,
  "i",
);
const ROLE_LIST_RE = new RegExp(
  String.raw`\bto\s+((?:${IDENT})(?:\s*,\s*${IDENT})*)(?=\s+(?:using|with\s+check)\b|\s*$)`,
  "i",
);
const IDENT_RE = new RegExp(IDENT, "g");
const USING_TRUE_RE = /\b(?:using|with\s+check)\s*\(\s*true\s*\)/gi;

export interface RlsSourceLocation {
  file: string;
  line: number;
  content: string;
}

export interface ActivePolicy {
  key: string;
  tableKey: string;
  schema: string;
  table: string;
  name: string;
  body: string;
  commands: string[];
  roles: string[];
  usingClause?: string;
  withCheckClause?: string;
  usingSource?: RlsSourceLocation;
  withCheckSource?: RlsSourceLocation;
  source: RlsSourceLocation;
  permissiveClauses: Array<{
    source: RlsSourceLocation;
    matchedWithCheck: boolean;
  }>;
}

export interface EffectiveTable {
  key: string;
  schema: string;
  table: string;
  created?: RlsSourceLocation;
  columns?: string;
  rlsEnabled: boolean;
  lastRlsChange?: {
    enabled: boolean;
    source: RlsSourceLocation;
  };
}

export interface RlsEffectiveState {
  kind: "sequence" | "snapshot";
  key: string;
  files: SourceFile[];
  ambiguouslyOrderedFiles: string[];
  tables: Map<string, EffectiveTable>;
  policies: Map<string, ActivePolicy>;
}

interface AnalysisUnit {
  kind: "sequence" | "snapshot";
  key: string;
  files: SourceFile[];
  ambiguouslyOrderedFiles: string[];
}

interface ParsedIdentifier {
  value: string;
}

type StateEvent =
  | {
      kind: "create-table";
      index: number;
      schema: string;
      table: string;
      ifNotExists: boolean;
      columns?: string;
      source: RlsSourceLocation;
    }
  | {
      kind: "drop-table";
      index: number;
      schema: string;
      table: string;
    }
  | {
      kind: "alter-rls";
      index: number;
      schema: string;
      table: string;
      enabled: boolean;
      source: RlsSourceLocation;
    }
  | {
      kind: "create-policy";
      index: number;
      policy: ActivePolicy;
    }
  | {
      kind: "drop-policy";
      index: number;
      schema: string;
      table: string;
      name: string;
    }
  | {
      kind: "alter-policy";
      index: number;
      schema: string;
      table: string;
      name: string;
      newName?: string;
      roles?: string[];
      usingClause?: string;
      withCheckClause?: string;
      updatesUsing: boolean;
      updatesWithCheck: boolean;
      permissiveClauses?: ActivePolicy["permissiveClauses"];
      source: RlsSourceLocation;
    };

interface SqlStatement {
  index: number;
  text: string;
}

function dollarDelimiterAt(sql: string, index: number): string | undefined {
  return sql.slice(index).match(/^\$(?:[a-zA-Z_][a-zA-Z0-9_]*)?\$/)?.[0];
}

/** Split only at top-level semicolons; quoted function bodies remain one ignored statement. */
function splitSqlStatements(sql: string): SqlStatement[] {
  const statements: SqlStatement[] = [];
  let start = 0;
  let singleQuoted = false;
  let doubleQuoted = false;
  let lineComment = false;
  let blockDepth = 0;
  let dollarQuote: string | undefined;

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const next = sql[i + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockDepth > 0) {
      if (char === "/" && next === "*") {
        blockDepth += 1;
        i += 1;
      } else if (char === "*" && next === "/") {
        blockDepth -= 1;
        i += 1;
      }
      continue;
    }
    if (dollarQuote) {
      if (sql.startsWith(dollarQuote, i)) {
        i += dollarQuote.length - 1;
        dollarQuote = undefined;
      }
      continue;
    }
    if (singleQuoted) {
      if (char === "'" && next === "'") i += 1;
      else if (char === "'") singleQuoted = false;
      continue;
    }
    if (doubleQuoted) {
      if (char === '"' && next === '"') i += 1;
      else if (char === '"') doubleQuoted = false;
      continue;
    }
    if (char === "-" && next === "-") {
      lineComment = true;
      i += 1;
    } else if (char === "/" && next === "*") {
      blockDepth = 1;
      i += 1;
    } else if (char === "'") {
      singleQuoted = true;
    } else if (char === '"') {
      doubleQuoted = true;
    } else if (char === "$") {
      const delimiter = dollarDelimiterAt(sql, i);
      if (delimiter) {
        dollarQuote = delimiter;
        i += delimiter.length - 1;
      }
    } else if (char === ";") {
      statements.push({ index: start, text: sql.slice(start, i) });
      start = i + 1;
    }
  }
  if (sql.slice(start).trim()) statements.push({ index: start, text: sql.slice(start) });
  return statements;
}

/** Blank comments without treating comment markers inside strings as syntax. */
function blankSqlComments(sql: string): string {
  const chars = [...sql];
  let singleQuoted = false;
  let doubleQuoted = false;
  let lineComment = false;
  let blockDepth = 0;
  let dollarQuote: string | undefined;
  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const next = sql[i + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      else chars[i] = " ";
      continue;
    }
    if (blockDepth > 0) {
      if (char !== "\n") chars[i] = " ";
      if (char === "/" && next === "*") {
        chars[i + 1] = " ";
        blockDepth += 1;
        i += 1;
      } else if (char === "*" && next === "/") {
        chars[i + 1] = " ";
        blockDepth -= 1;
        i += 1;
      }
      continue;
    }
    if (dollarQuote) {
      if (sql.startsWith(dollarQuote, i)) {
        i += dollarQuote.length - 1;
        dollarQuote = undefined;
      }
      continue;
    }
    if (singleQuoted) {
      if (char === "'" && next === "'") i += 1;
      else if (char === "'") singleQuoted = false;
      continue;
    }
    if (doubleQuoted) {
      if (char === '"' && next === '"') i += 1;
      else if (char === '"') doubleQuoted = false;
      continue;
    }
    if (char === "-" && next === "-") {
      chars[i] = " ";
      chars[i + 1] = " ";
      lineComment = true;
      i += 1;
    } else if (char === "/" && next === "*") {
      chars[i] = " ";
      chars[i + 1] = " ";
      blockDepth = 1;
      i += 1;
    } else if (char === "'") singleQuoted = true;
    else if (char === '"') doubleQuoted = true;
    else if (char === "$") {
      const delimiter = dollarDelimiterAt(sql, i);
      if (delimiter) {
        dollarQuote = delimiter;
        i += delimiter.length - 1;
      }
    }
  }
  return chars.join("");
}

function parseIdentifier(raw: string | undefined): ParsedIdentifier {
  const token = raw ?? "";
  if (token.startsWith('"') && token.endsWith('"')) {
    return { value: token.slice(1, -1).replace(/""/g, '"') };
  }
  return { value: token.toLowerCase() };
}

function schemaName(raw: string | undefined): string {
  const parsed = parseIdentifier(raw).value;
  return parsed || "public";
}

function relationKey(schema: string, table: string): string {
  return `${schema}\u0000${table}`;
}

function policyKey(schema: string, table: string, name: string): string {
  return `${relationKey(schema, table)}\u0000${name}`;
}

function sourceAt(file: SourceFile, sql: string, index: number): RlsSourceLocation {
  return { file: file.rel, line: lineOf(sql, index), content: file.content };
}

function numericPrefix(file: SourceFile): bigint | undefined {
  const basename = file.rel.slice(file.rel.lastIndexOf("/") + 1);
  const match = basename.match(/^(\d+)/);
  return match?.[1] === undefined ? undefined : BigInt(match[1]);
}

function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareMigrationFiles(a: SourceFile, b: SourceFile): number {
  const aPrefix = numericPrefix(a);
  const bPrefix = numericPrefix(b);
  if (aPrefix !== undefined && bPrefix !== undefined && aPrefix !== bPrefix) {
    return aPrefix < bPrefix ? -1 : 1;
  }
  if (aPrefix !== undefined && bPrefix === undefined) return -1;
  if (aPrefix === undefined && bPrefix !== undefined) return 1;
  return comparePaths(a.rel, b.rel);
}

function migrationDirectory(rel: string): string | undefined {
  const segments = rel.split("/");
  if (!segments.slice(0, -1).some((segment) => segment.toLowerCase() === "migrations")) {
    return undefined;
  }
  // The immediate containing directory is the sequence boundary. Therefore files directly in
  // migrations/ never compose with migrations/archive/ or any other nested directory.
  return segments.slice(0, -1).join("/");
}

/** Group SQL files into deterministic migration sequences and independent snapshots. */
export function buildRlsAnalysisUnits(sqlFiles: SourceFile[]): AnalysisUnit[] {
  const sequences = new Map<string, SourceFile[]>();
  const snapshots: AnalysisUnit[] = [];

  for (const file of sqlFiles) {
    const directory = migrationDirectory(file.rel);
    if (directory === undefined) {
      snapshots.push({
        kind: "snapshot",
        key: `snapshot:${file.rel}`,
        files: [file],
        ambiguouslyOrderedFiles: [],
      });
      continue;
    }
    const files = sequences.get(directory) ?? [];
    files.push(file);
    sequences.set(directory, files);
  }

  const units: AnalysisUnit[] = [];
  for (const [directory, files] of sequences) {
    const sorted = [...files].sort(compareMigrationFiles);
    units.push({
      kind: "sequence",
      key: `sequence:${directory}`,
      files: sorted,
      ambiguouslyOrderedFiles: sorted
        .filter((file) => numericPrefix(file) === undefined)
        .map((file) => file.rel),
    });
  }
  units.push(...snapshots);
  return units.sort((a, b) => comparePaths(a.key, b.key));
}

function tableColumns(statement: string): string | undefined {
  const open = statement.indexOf("(");
  const close = statement.lastIndexOf(")");
  return open === -1 || close <= open ? undefined : statement.slice(open + 1, close);
}

function splitRelationList(list: string): string[] {
  const relations: string[] = [];
  let start = 0;
  let doubleQuoted = false;
  for (let i = 0; i < list.length; i += 1) {
    if (list[i] === '"' && list[i + 1] === '"' && doubleQuoted) i += 1;
    else if (list[i] === '"') doubleQuoted = !doubleQuoted;
    else if (list[i] === "," && !doubleQuoted) {
      relations.push(list.slice(start, i));
      start = i + 1;
    }
  }
  relations.push(list.slice(start));
  return relations;
}

function parseRoles(body: string): string[] {
  const list = body.match(ROLE_LIST_RE)?.[1];
  if (!list) return [];
  return [...list.matchAll(IDENT_RE)].map((match) => parseIdentifier(match[0]).value);
}

function extractPredicateClause(body: string, kind: "using" | "with-check"): string | undefined {
  const match = (kind === "using" ? /\busing\s*\(/i : /\bwith\s+check\s*\(/i).exec(body);
  if (!match) return undefined;
  const open = body.indexOf("(", match.index);
  let depth = 0;
  let singleQuoted = false;
  let doubleQuoted = false;
  let dollarQuote: string | undefined;
  for (let i = open; i < body.length; i += 1) {
    const char = body[i];
    const next = body[i + 1];
    if (dollarQuote) {
      if (body.startsWith(dollarQuote, i)) {
        i += dollarQuote.length - 1;
        dollarQuote = undefined;
      }
      continue;
    }
    if (singleQuoted) {
      if (char === "'" && next === "'") i += 1;
      else if (char === "'") singleQuoted = false;
      continue;
    }
    if (doubleQuoted) {
      if (char === '"' && next === '"') i += 1;
      else if (char === '"') doubleQuoted = false;
      continue;
    }
    if (char === "'") singleQuoted = true;
    else if (char === '"') doubleQuoted = true;
    else if (char === "$") {
      const delimiter = dollarDelimiterAt(body, i);
      if (delimiter) {
        dollarQuote = delimiter;
        i += delimiter.length - 1;
      }
    } else if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return body.slice(match.index, i + 1);
    }
  }
  return body.slice(match.index);
}

function permissiveClauses(
  file: SourceFile,
  sql: string,
  statement: SqlStatement,
  body: string,
): ActivePolicy["permissiveClauses"] {
  const bodyOffset = statement.text.indexOf(body);
  return [...body.matchAll(USING_TRUE_RE)].map((clause) => ({
    source: sourceAt(file, sql, statement.index + bodyOffset + (clause.index ?? 0)),
    matchedWithCheck: (clause[0] ?? "").toLowerCase().startsWith("with"),
  }));
}

function parseEvents(file: SourceFile): StateEvent[] {
  const sql = blankSqlComments(file.content);
  const events: StateEvent[] = [];

  for (const statement of splitSqlStatements(sql)) {
    const text = statement.text;
    const index = statement.index + (text.search(/\S/) === -1 ? 0 : text.search(/\S/));
    let match = text.match(CREATE_TABLE_RE);
    if (match) {
      events.push({
        kind: "create-table",
        index,
        ifNotExists: Boolean(match[1]),
        schema: schemaName(match[2]),
        table: parseIdentifier(match[3]).value,
        columns: tableColumns(text),
        source: sourceAt(file, sql, index),
      });
      continue;
    }
    match = text.match(DROP_TABLE_RE);
    if (match) {
      const relations = (match[1] ?? "").replace(/\s+(?:cascade|restrict)\s*$/i, "");
      for (const relation of splitRelationList(relations)) {
        const parsed = relation.match(QUALIFIED_RE);
        if (!parsed) continue;
        events.push({
          kind: "drop-table",
          index,
          schema: schemaName(parsed[1]),
          table: parseIdentifier(parsed[2]).value,
        });
      }
      continue;
    }
    match = text.match(ALTER_RLS_RE);
    if (match) {
      events.push({
        kind: "alter-rls",
        index,
        schema: schemaName(match[1]),
        table: parseIdentifier(match[2]).value,
        enabled: (match[3] ?? "").toLowerCase() === "enable",
        source: sourceAt(file, sql, index),
      });
      continue;
    }
    match = text.match(CREATE_POLICY_RE);
    if (match) {
      const name = parseIdentifier(match[1]).value;
      const schema = schemaName(match[2]);
      const table = parseIdentifier(match[3]).value;
      const body = match[4] ?? "";
      const usingClause = extractPredicateClause(body, "using");
      const withCheckClause = extractPredicateClause(body, "with-check");
      const forMatch = body.match(/\bfor\s+(select|insert|update|delete|all)\b/i);
      events.push({
        kind: "create-policy",
        index,
        policy: {
          key: policyKey(schema, table, name),
          tableKey: relationKey(schema, table),
          schema,
          table,
          name,
          body,
          commands: [forMatch?.[1]?.toLowerCase() ?? "all"],
          roles: parseRoles(body),
          usingClause,
          withCheckClause,
          usingSource: usingClause ? sourceAt(file, sql, index) : undefined,
          withCheckSource: withCheckClause ? sourceAt(file, sql, index) : undefined,
          source: sourceAt(file, sql, index),
          permissiveClauses: permissiveClauses(file, sql, statement, body),
        },
      });
      continue;
    }
    match = text.match(DROP_POLICY_RE);
    if (match) {
      events.push({
        kind: "drop-policy",
        index,
        name: parseIdentifier(match[1]).value,
        schema: schemaName(match[2]),
        table: parseIdentifier(match[3]).value,
      });
      continue;
    }
    match = text.match(ALTER_POLICY_RE);
    if (match) {
      const rest = match[4] ?? "";
      const rename = rest.match(new RegExp(String.raw`^\s*rename\s+to\s+(${IDENT})\s*$`, "i"));
      const usingClause = extractPredicateClause(rest, "using");
      const withCheckClause = extractPredicateClause(rest, "with-check");
      events.push({
        kind: "alter-policy",
        index,
        name: parseIdentifier(match[1]).value,
        schema: schemaName(match[2]),
        table: parseIdentifier(match[3]).value,
        newName: rename ? parseIdentifier(rename[1]).value : undefined,
        roles: ROLE_LIST_RE.test(rest) ? parseRoles(rest) : undefined,
        usingClause,
        withCheckClause,
        updatesUsing: usingClause !== undefined,
        updatesWithCheck: withCheckClause !== undefined,
        permissiveClauses:
          usingClause !== undefined || withCheckClause !== undefined
            ? permissiveClauses(file, sql, statement, rest)
            : undefined,
        source: sourceAt(file, sql, index),
      });
    }
  }

  return events.sort((a, b) => a.index - b.index);
}

function reduceUnit(unit: AnalysisUnit): RlsEffectiveState {
  const tables = new Map<string, EffectiveTable>();
  const policies = new Map<string, ActivePolicy>();

  for (const file of unit.files) {
    for (const event of parseEvents(file)) {
      if (event.kind === "create-table") {
        const key = relationKey(event.schema, event.table);
        if (event.ifNotExists && tables.has(key)) continue;
        tables.set(key, {
          key,
          schema: event.schema,
          table: event.table,
          created: event.source,
          columns: event.columns,
          rlsEnabled: false,
        });
      } else if (event.kind === "drop-table") {
        const key = relationKey(event.schema, event.table);
        tables.delete(key);
        for (const [id, policy] of policies) {
          if (policy.tableKey === key) policies.delete(id);
        }
      } else if (event.kind === "alter-rls") {
        const key = relationKey(event.schema, event.table);
        const table = tables.get(key) ?? {
          key,
          schema: event.schema,
          table: event.table,
          rlsEnabled: false,
        };
        table.rlsEnabled = event.enabled;
        table.lastRlsChange = { enabled: event.enabled, source: event.source };
        tables.set(key, table);
      } else if (event.kind === "create-policy") {
        policies.set(event.policy.key, event.policy);
      } else if (event.kind === "drop-policy") {
        policies.delete(policyKey(event.schema, event.table, event.name));
      } else {
        const oldKey = policyKey(event.schema, event.table, event.name);
        const policy = policies.get(oldKey);
        if (!policy) continue;
        if (event.roles !== undefined) policy.roles = event.roles;
        if (event.updatesUsing) {
          policy.usingClause = event.usingClause;
          policy.usingSource = event.source;
          policy.permissiveClauses = [
            ...policy.permissiveClauses.filter((clause) => clause.matchedWithCheck),
            ...(event.permissiveClauses ?? []).filter((clause) => !clause.matchedWithCheck),
          ];
        }
        if (event.updatesWithCheck) {
          policy.withCheckClause = event.withCheckClause;
          policy.withCheckSource = event.source;
          policy.permissiveClauses = [
            ...policy.permissiveClauses.filter((clause) => !clause.matchedWithCheck),
            ...(event.permissiveClauses ?? []).filter((clause) => clause.matchedWithCheck),
          ];
        }
        if (event.updatesUsing || event.updatesWithCheck) {
          policy.body = [policy.usingClause, policy.withCheckClause].filter(Boolean).join(" ");
        }
        if (event.newName !== undefined) {
          policies.delete(oldKey);
          policy.name = event.newName;
          policy.key = policyKey(event.schema, event.table, event.newName);
          policies.set(policy.key, policy);
        }
      }
    }
  }

  return {
    kind: unit.kind,
    key: unit.key,
    files: unit.files,
    ambiguouslyOrderedFiles: unit.ambiguouslyOrderedFiles,
    tables,
    policies,
  };
}

export function reduceRlsEffectiveState(sqlFiles: SourceFile[]): RlsEffectiveState[] {
  return buildRlsAnalysisUnits(sqlFiles).map(reduceUnit);
}
