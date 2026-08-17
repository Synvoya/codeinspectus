/**
 * Ordered, repository-visible effective state for Supabase RLS checks.
 *
 * This is a bounded SQL reducer, not a PostgreSQL parser. It recognizes only the DDL
 * needed by the RLS analyzer and marks uncertain state explicitly instead of choosing a
 * convenient final migration order or treating hosted/database state as repository proof.
 */

import type { SourceFile } from "./walk.js";
import { lineOf } from "./walk.js";

const IDENT = String.raw`(?:"(?:[^"]|"")*"|[a-zA-Z_][a-zA-Z0-9_$]*)`;
const QUALIFIED = String.raw`(?:(${IDENT})\s*\.\s*)?(${IDENT})`;
const MAX_STATEMENTS_PER_FILE = 10_000;
const MAX_STATE_OBJECTS = 20_000;
const MAX_PREDICATE_CHARS = 64 * 1024;

const CREATE_TABLE_RE = new RegExp(
  String.raw`^\s*create\s+(?:(?:global|local)\s+)?(?:(?:temporary|temp)\s+)?(?:unlogged\s+)?table\s+(if\s+not\s+exists\s+)?${QUALIFIED}`,
  "i",
);
const TEMP_TABLE_RE = /^\s*create\s+(?:(?:global|local)\s+)?(?:temporary|temp)\s+table\b/i;
const DROP_TABLE_RE = new RegExp(
  String.raw`^\s*drop\s+table\s+(?:if\s+exists\s+)?([\s\S]+?)\s*$`,
  "i",
);
const QUALIFIED_RE = new RegExp(String.raw`^\s*${QUALIFIED}\s*$`);
const ALTER_RLS_RE = new RegExp(
  String.raw`^\s*alter\s+table\s+(if\s+exists\s+)?(?:only\s+)?${QUALIFIED}\s*\*?\s+(enable|disable)\s+row\s+level\s+security\s*$`,
  "i",
);
const ALTER_RENAME_RE = new RegExp(
  String.raw`^\s*alter\s+table\s+(if\s+exists\s+)?(?:only\s+)?${QUALIFIED}\s+rename\s+to\s+(${IDENT})\s*$`,
  "i",
);
const ALTER_SET_SCHEMA_RE = new RegExp(
  String.raw`^\s*alter\s+table\s+(if\s+exists\s+)?(?:only\s+)?${QUALIFIED}\s+set\s+schema\s+(${IDENT})\s*$`,
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
const IDENT_RE = new RegExp(IDENT, "g");

export type RlsCommand = "all" | "select" | "insert" | "update" | "delete";
export type PolicyMode = "permissive" | "restrictive";
export type PredicateTruth = "true" | "false" | "dynamic" | "unsupported";

export interface RlsSourceLocation {
  file: string;
  line: number;
  content: string;
}

export interface PolicyRole {
  name: string;
  quoted: boolean;
}

export interface PolicyPredicate {
  clause: string;
  expression: string;
  maskedExpression: string;
  truth: PredicateTruth;
  source: RlsSourceLocation;
}

export interface ActivePolicy {
  key: string;
  tableKey: string;
  schema: string;
  table: string;
  name: string;
  body: string;
  command: RlsCommand;
  mode: PolicyMode;
  roles: PolicyRole[];
  using?: PolicyPredicate;
  withCheck?: PolicyPredicate;
  valid: boolean;
  source: RlsSourceLocation;
}

export interface EffectiveTable {
  key: string;
  schema: string;
  table: string;
  created?: RlsSourceLocation;
  columns?: string;
  definedInRepository: boolean;
  rlsEnabled: boolean | "unknown";
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
  conclusive: boolean;
  notes: string[];
  tables: Map<string, EffectiveTable>;
  policies: Map<string, ActivePolicy>;
}

export interface RlsAnalysisUnit {
  kind: "sequence" | "snapshot";
  key: string;
  files: SourceFile[];
  ambiguouslyOrderedFiles: string[];
}

interface ParsedIdentifier {
  value: string;
  quoted: boolean;
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
  | { kind: "drop-table"; index: number; schema: string; table: string }
  | {
      kind: "alter-rls";
      index: number;
      schema: string;
      table: string;
      ifExists: boolean;
      enabled: boolean;
      source: RlsSourceLocation;
    }
  | {
      kind: "move-table";
      index: number;
      schema: string;
      table: string;
      ifExists: boolean;
      newSchema: string;
      newTable: string;
      source: RlsSourceLocation;
    }
  | { kind: "create-policy"; index: number; policy: ActivePolicy }
  | { kind: "drop-policy"; index: number; schema: string; table: string; name: string }
  | {
      kind: "alter-policy";
      index: number;
      schema: string;
      table: string;
      name: string;
      newName?: string;
      roles?: PolicyRole[];
      using?: PolicyPredicate;
      withCheck?: PolicyPredicate;
      updatesUsing: boolean;
      updatesWithCheck: boolean;
      valid: boolean;
      source: RlsSourceLocation;
    };

interface SqlStatement {
  index: number;
  text: string;
}

interface ParsedEvents {
  events: StateEvent[];
  notes: string[];
  conclusive: boolean;
}

function dollarDelimiterAt(sql: string, index: number): string | undefined {
  return sql.slice(index).match(/^\$(?:[a-zA-Z_][a-zA-Z0-9_]*)?\$/)?.[0];
}

/** Split only at top-level semicolons; quoted bodies and literals stay opaque. */
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
    } else if (char === "'") singleQuoted = true;
    else if (char === '"') doubleQuoted = true;
    else if (char === "$") {
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

/** Replace comments with spaces while retaining exact offsets and line numbers. */
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

/** Mask strings, quoted identifiers, and dollar-quoted text without moving offsets. */
function maskSqlLiterals(sql: string): string {
  const chars = [...sql];
  let singleQuoted = false;
  let doubleQuoted = false;
  let dollarQuote: string | undefined;
  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const next = sql[i + 1];
    if (dollarQuote) {
      if (char !== "\n") chars[i] = " ";
      if (sql.startsWith(dollarQuote, i)) {
        for (let j = 0; j < dollarQuote.length; j += 1) chars[i + j] = " ";
        i += dollarQuote.length - 1;
        dollarQuote = undefined;
      }
      continue;
    }
    if (singleQuoted) {
      if (char !== "\n") chars[i] = " ";
      if (char === "'" && next === "'") {
        chars[i + 1] = " ";
        i += 1;
      } else if (char === "'") singleQuoted = false;
      continue;
    }
    if (doubleQuoted) {
      if (char !== "\n") chars[i] = " ";
      if (char === '"' && next === '"') {
        chars[i + 1] = " ";
        i += 1;
      } else if (char === '"') doubleQuoted = false;
      continue;
    }
    if (char === "'") {
      chars[i] = " ";
      singleQuoted = true;
    } else if (char === '"') {
      chars[i] = " ";
      doubleQuoted = true;
    } else if (char === "$") {
      const delimiter = dollarDelimiterAt(sql, i);
      if (delimiter) {
        for (let j = 0; j < delimiter.length; j += 1) chars[i + j] = " ";
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
    return { value: token.slice(1, -1).replace(/""/g, '"'), quoted: true };
  }
  return { value: token.toLowerCase(), quoted: false };
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

export function rlsMigrationDirectory(rel: string): string | undefined {
  const segments = rel.split("/");
  if (!segments.slice(0, -1).some((segment) => segment.toLowerCase() === "migrations")) {
    return undefined;
  }
  return segments.slice(0, -1).join("/");
}

/** Group SQL into deterministic sequences, but name any order the repository cannot prove. */
export function buildRlsAnalysisUnits(sqlFiles: SourceFile[]): RlsAnalysisUnit[] {
  const sequences = new Map<string, SourceFile[]>();
  const snapshots: RlsAnalysisUnit[] = [];

  for (const file of sqlFiles) {
    const directory = rlsMigrationDirectory(file.rel);
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

  const units: RlsAnalysisUnit[] = [];
  for (const [directory, files] of sequences) {
    const sorted = [...files].sort(compareMigrationFiles);
    const prefixCounts = new Map<string, number>();
    for (const file of sorted) {
      const prefix = numericPrefix(file);
      if (prefix !== undefined) prefixCounts.set(prefix.toString(), (prefixCounts.get(prefix.toString()) ?? 0) + 1);
    }
    const ambiguous = sorted.filter((file) => {
      const prefix = numericPrefix(file);
      return prefix === undefined || (prefixCounts.get(prefix.toString()) ?? 0) > 1;
    });
    units.push({
      kind: "sequence",
      key: `sequence:${directory}`,
      files: sorted,
      ambiguouslyOrderedFiles: ambiguous.map((file) => file.rel),
    });
  }
  units.push(...snapshots);
  return units.sort((a, b) => comparePaths(a.key, b.key));
}

function tableColumns(statement: string): string | undefined {
  const syntax = maskSqlLiterals(statement);
  const open = syntax.indexOf("(");
  const close = syntax.lastIndexOf(")");
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

function parseRoles(body: string): PolicyRole[] | undefined {
  const syntax = maskSqlLiterals(body);
  const to = /\bto\b/i.exec(syntax);
  if (!to) return undefined;
  const tail = body.slice(to.index + to[0].length);
  const tailSyntax = syntax.slice(to.index + to[0].length);
  const end = /\b(?:using|with\s+check)\b/i.exec(tailSyntax)?.index ?? tail.length;
  const list = tail.slice(0, end);
  const roles = [...list.matchAll(IDENT_RE)].map((match) => parseIdentifier(match[0]));
  return roles.map(({ value, quoted }) => ({ name: value, quoted }));
}

function stripOuterParentheses(input: string): string {
  let value = input.trim();
  while (value.startsWith("(") && value.endsWith(")")) {
    let depth = 0;
    let enclosesAll = true;
    for (let i = 0; i < value.length; i += 1) {
      if (value[i] === "(") depth += 1;
      else if (value[i] === ")") depth -= 1;
      if (depth === 0 && i < value.length - 1) {
        enclosesAll = false;
        break;
      }
      if (depth < 0) return value;
    }
    if (!enclosesAll || depth !== 0) break;
    value = value.slice(1, -1).trim();
  }
  return value;
}

function predicateTruth(maskedExpression: string): PredicateTruth {
  if (maskedExpression.length > MAX_PREDICATE_CHARS) return "unsupported";
  let expression = stripOuterParentheses(maskedExpression);
  expression = expression.replace(/\s*::\s*(?:boolean|bool)\s*$/i, "");
  expression = stripOuterParentheses(expression).trim();
  if (/^true$/i.test(expression)) return "true";
  if (/^false$/i.test(expression)) return "false";
  const numericEquality = /^([+-]?\d+(?:\.\d+)?)\s*=\s*([+-]?\d+(?:\.\d+)?)$/.exec(expression);
  if (numericEquality) {
    return Number(numericEquality[1]) === Number(numericEquality[2]) ? "true" : "false";
  }
  return "dynamic";
}

function extractPredicate(
  file: SourceFile,
  sql: string,
  statementIndex: number,
  body: string,
  bodyOffset: number,
  kind: "using" | "with-check",
): { predicate?: PolicyPredicate; present: boolean; malformed: boolean } {
  const syntax = maskSqlLiterals(body);
  const match = (kind === "using" ? /\busing\s*\(/i : /\bwith\s+check\s*\(/i).exec(syntax);
  if (!match) return { present: false, malformed: false };
  const open = syntax.indexOf("(", match.index);
  let depth = 0;
  for (let i = open; i < syntax.length; i += 1) {
    if (syntax[i] === "(") depth += 1;
    else if (syntax[i] === ")") {
      depth -= 1;
      if (depth === 0) {
        const clause = body.slice(match.index, i + 1);
        const expression = body.slice(open + 1, i);
        const maskedExpression = syntax.slice(open + 1, i);
        const source = sourceAt(file, sql, statementIndex + bodyOffset + match.index);
        return {
          present: true,
          malformed: false,
          predicate: {
            clause,
            expression,
            maskedExpression,
            truth: predicateTruth(maskedExpression),
            source,
          },
        };
      }
    }
  }
  return { present: true, malformed: true };
}

function parsePolicyDetails(
  file: SourceFile,
  sql: string,
  statement: SqlStatement,
  body: string,
): {
  command: RlsCommand;
  mode: PolicyMode;
  roles: PolicyRole[];
  using?: PolicyPredicate;
  withCheck?: PolicyPredicate;
  valid: boolean;
  notes: string[];
} {
  const bodyOffset = statement.text.indexOf(body);
  const syntax = maskSqlLiterals(body);
  const command = (syntax.match(/\bfor\s+(select|insert|update|delete|all)\b/i)?.[1]?.toLowerCase() ?? "all") as RlsCommand;
  const mode = (syntax.match(/\bas\s+(permissive|restrictive)\b/i)?.[1]?.toLowerCase() ?? "permissive") as PolicyMode;
  const usingResult = extractPredicate(file, sql, statement.index, body, bodyOffset, "using");
  const checkResult = extractPredicate(file, sql, statement.index, body, bodyOffset, "with-check");
  const location = sourceAt(file, sql, statement.index).file;
  const notes: string[] = [];
  let valid = !usingResult.malformed && !checkResult.malformed;
  if (usingResult.malformed || checkResult.malformed) {
    notes.push(`${location}: malformed or unsupported RLS policy predicate; effective openness was not inferred.`);
  }
  if ((command === "select" || command === "delete") && checkResult.present) {
    valid = false;
    notes.push(`${location}: WITH CHECK is not valid for a FOR ${command.toUpperCase()} policy; effective openness was not inferred.`);
  }
  if (command === "insert" && usingResult.present) {
    valid = false;
    notes.push(`${location}: USING is not valid for a FOR INSERT policy; effective openness was not inferred.`);
  }
  if (usingResult.predicate?.truth === "unsupported" || checkResult.predicate?.truth === "unsupported") {
    valid = false;
    notes.push(`${location}: RLS predicate exceeded the ${MAX_PREDICATE_CHARS}-character analysis bound.`);
  }
  return {
    command,
    mode,
    roles: parseRoles(body) ?? [{ name: "public", quoted: false }],
    using: usingResult.predicate,
    withCheck: checkResult.predicate,
    valid,
    notes,
  };
}

function parseEvents(file: SourceFile): ParsedEvents {
  const sql = blankSqlComments(file.content);
  const statements = splitSqlStatements(sql);
  const events: StateEvent[] = [];
  const notes: string[] = [];
  let conclusive = true;
  if (statements.length > MAX_STATEMENTS_PER_FILE) {
    notes.push(`${file.rel}: SQL reduction stopped at the ${MAX_STATEMENTS_PER_FILE}-statement bound; final RLS state is unknown.`);
    conclusive = false;
  }

  for (const statement of statements.slice(0, MAX_STATEMENTS_PER_FILE)) {
    const text = statement.text;
    const leading = text.search(/\S/);
    const index = statement.index + (leading === -1 ? 0 : leading);
    if (TEMP_TABLE_RE.test(text)) continue;
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
        if (!parsed) {
          conclusive = false;
          notes.push(`${file.rel}:${lineOf(sql, index)}: unsupported DROP TABLE target; final RLS state is unknown.`);
          continue;
        }
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
        ifExists: Boolean(match[1]),
        schema: schemaName(match[2]),
        table: parseIdentifier(match[3]).value,
        enabled: (match[4] ?? "").toLowerCase() === "enable",
        source: sourceAt(file, sql, index),
      });
      continue;
    }
    match = text.match(ALTER_RENAME_RE);
    if (match) {
      const schema = schemaName(match[2]);
      events.push({
        kind: "move-table",
        index,
        ifExists: Boolean(match[1]),
        schema,
        table: parseIdentifier(match[3]).value,
        newSchema: schema,
        newTable: parseIdentifier(match[4]).value,
        source: sourceAt(file, sql, index),
      });
      continue;
    }
    match = text.match(ALTER_SET_SCHEMA_RE);
    if (match) {
      events.push({
        kind: "move-table",
        index,
        ifExists: Boolean(match[1]),
        schema: schemaName(match[2]),
        table: parseIdentifier(match[3]).value,
        newSchema: parseIdentifier(match[4]).value,
        newTable: parseIdentifier(match[3]).value,
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
      const parsed = parsePolicyDetails(file, sql, statement, body);
      notes.push(...parsed.notes);
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
          command: parsed.command,
          mode: parsed.mode,
          roles: parsed.roles,
          using: parsed.using,
          withCheck: parsed.withCheck,
          valid: parsed.valid,
          source: sourceAt(file, sql, index),
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
      const parsed = parsePolicyDetails(file, sql, statement, rest);
      const syntax = maskSqlLiterals(rest);
      const updatesUsing = /\busing\s*\(/i.test(syntax);
      const updatesWithCheck = /\bwith\s+check\s*\(/i.test(syntax);
      notes.push(...parsed.notes);
      events.push({
        kind: "alter-policy",
        index,
        name: parseIdentifier(match[1]).value,
        schema: schemaName(match[2]),
        table: parseIdentifier(match[3]).value,
        newName: rename ? parseIdentifier(rename[1]).value : undefined,
        roles: /\bto\b/i.test(syntax) ? parsed.roles : undefined,
        using: parsed.using,
        withCheck: parsed.withCheck,
        updatesUsing,
        updatesWithCheck,
        valid: parsed.valid,
        source: sourceAt(file, sql, index),
      });
      continue;
    }

    const syntax = maskSqlLiterals(text);
    if (/^\s*(?:create|alter|drop)\s+policy\b/i.test(syntax)) {
      conclusive = false;
      notes.push(`${file.rel}:${lineOf(sql, index)}: unsupported policy DDL; final RLS policy state is unknown.`);
    } else if (/^\s*alter\s+table\b[\s\S]*\b(?:row\s+level\s+security|rename\s+to|set\s+schema)\b/i.test(syntax)) {
      conclusive = false;
      notes.push(`${file.rel}:${lineOf(sql, index)}: unsupported RLS-relevant ALTER TABLE; final table state is unknown.`);
    }
  }

  return { events: events.sort((a, b) => a.index - b.index), notes, conclusive };
}

function moveTable(
  tables: Map<string, EffectiveTable>,
  policies: Map<string, ActivePolicy>,
  event: Extract<StateEvent, { kind: "move-table" }>,
): boolean {
  const oldKey = relationKey(event.schema, event.table);
  const newKey = relationKey(event.newSchema, event.newTable);
  if (oldKey !== newKey && tables.has(newKey)) return false;
  const table = tables.get(oldKey) ?? {
    key: oldKey,
    schema: event.schema,
    table: event.table,
    definedInRepository: false,
    rlsEnabled: "unknown" as const,
  };
  tables.delete(oldKey);
  table.key = newKey;
  table.schema = event.newSchema;
  table.table = event.newTable;
  tables.set(newKey, table);

  const movedPolicies = [...policies.values()].filter((policy) => policy.tableKey === oldKey);
  for (const policy of movedPolicies) {
    policies.delete(policy.key);
    policy.schema = event.newSchema;
    policy.table = event.newTable;
    policy.tableKey = newKey;
    policy.key = policyKey(event.newSchema, event.newTable, policy.name);
    policies.set(policy.key, policy);
  }
  return true;
}

function reduceUnit(unit: RlsAnalysisUnit): RlsEffectiveState {
  const tables = new Map<string, EffectiveTable>();
  const policies = new Map<string, ActivePolicy>();
  const knownAbsent = new Set<string>();
  const notes: string[] = [];
  let conclusive = unit.ambiguouslyOrderedFiles.length === 0;
  if (!conclusive) {
    notes.push(
      `${unit.key.slice("sequence:".length)}: migration order is ambiguous for ${unit.ambiguouslyOrderedFiles.join(", ")}; final RLS state was not inferred.`,
    );
  }

  for (const file of unit.files) {
    const parsed = parseEvents(file);
    notes.push(...parsed.notes);
    conclusive &&= parsed.conclusive;
    for (const event of parsed.events) {
      if (tables.size + policies.size >= MAX_STATE_OBJECTS) {
        conclusive = false;
        notes.push(`${unit.key}: RLS reduction stopped at the ${MAX_STATE_OBJECTS}-object state bound.`);
        break;
      }
      if (event.kind === "create-table") {
        const key = relationKey(event.schema, event.table);
        if (event.ifNotExists && tables.has(key)) continue;
        if (event.ifNotExists && !knownAbsent.has(key)) {
          tables.set(key, {
            key,
            schema: event.schema,
            table: event.table,
            definedInRepository: false,
            rlsEnabled: "unknown",
          });
          notes.push(`${event.source.file}:${event.source.line}: CREATE TABLE IF NOT EXISTS may refer to a pre-existing table; its RLS state is unknown.`);
          continue;
        }
        tables.set(key, {
          key,
          schema: event.schema,
          table: event.table,
          created: event.source,
          columns: event.columns,
          definedInRepository: true,
          rlsEnabled: false,
        });
        knownAbsent.delete(key);
      } else if (event.kind === "drop-table") {
        const key = relationKey(event.schema, event.table);
        tables.delete(key);
        knownAbsent.add(key);
        for (const [id, policy] of policies) {
          if (policy.tableKey === key) policies.delete(id);
        }
      } else if (event.kind === "alter-rls") {
        const key = relationKey(event.schema, event.table);
        if (event.ifExists && !tables.has(key)) {
          if (!knownAbsent.has(key)) {
            tables.set(key, {
              key,
              schema: event.schema,
              table: event.table,
              definedInRepository: false,
              rlsEnabled: "unknown",
            });
            notes.push(`${event.source.file}:${event.source.line}: ALTER TABLE IF EXISTS does not prove the table exists; its RLS state is unknown.`);
          }
          continue;
        }
        const table = tables.get(key) ?? {
          key,
          schema: event.schema,
          table: event.table,
          definedInRepository: false,
          rlsEnabled: "unknown" as const,
        };
        table.rlsEnabled = event.enabled;
        table.lastRlsChange = { enabled: event.enabled, source: event.source };
        tables.set(key, table);
        knownAbsent.delete(key);
      } else if (event.kind === "move-table") {
        const oldKey = relationKey(event.schema, event.table);
        if (event.ifExists && !tables.has(oldKey)) {
          if (!knownAbsent.has(oldKey)) {
            notes.push(`${event.source.file}:${event.source.line}: ALTER TABLE IF EXISTS does not prove a rename/schema move occurred.`);
          }
          continue;
        }
        if (!moveTable(tables, policies, event)) {
          conclusive = false;
          notes.push(`${event.source.file}:${event.source.line}: table rename/schema move collided with an existing repository relation; final RLS state is unknown.`);
        }
      } else if (event.kind === "create-policy") {
        policies.set(event.policy.key, event.policy);
      } else if (event.kind === "drop-policy") {
        policies.delete(policyKey(event.schema, event.table, event.name));
      } else {
        const oldKey = policyKey(event.schema, event.table, event.name);
        const policy = policies.get(oldKey);
        if (!policy) continue;
        if (event.roles !== undefined) policy.roles = event.roles;
        if (event.updatesUsing) policy.using = event.using;
        if (event.updatesWithCheck) policy.withCheck = event.withCheck;
        const invalidAlterClause =
          (policy.command === "insert" && event.updatesUsing) ||
          ((policy.command === "select" || policy.command === "delete") && event.updatesWithCheck);
        policy.valid &&= event.valid && !invalidAlterClause;
        if (invalidAlterClause) {
          notes.push(`${event.source.file}:${event.source.line}: ALTER POLICY uses a predicate clause that is invalid for FOR ${policy.command.toUpperCase()}; effective openness was not inferred.`);
        }
        if (event.updatesUsing || event.updatesWithCheck) {
          policy.body = [policy.using?.clause, policy.withCheck?.clause].filter(Boolean).join(" ");
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
    conclusive,
    notes,
    tables,
    policies,
  };
}

export function reduceRlsEffectiveState(sqlFiles: SourceFile[]): RlsEffectiveState[] {
  return buildRlsAnalysisUnits(sqlFiles).map(reduceUnit);
}

/** Exact syntax-only project signal; comments, strings, and quoted identifiers stay opaque. */
export function hasSupabaseAuthReference(sql: string): boolean {
  const syntax = maskSqlLiterals(blankSqlComments(sql));
  return /\bauth\s*\.\s*(?:uid|users|jwt|role)\b/i.test(syntax);
}

export function policyAppliesToCommand(policy: ActivePolicy, command: Exclude<RlsCommand, "all">): boolean {
  return policy.command === "all" || policy.command === command;
}

export function policyAppliesToAudience(policy: ActivePolicy, audience: "anon" | "authenticated"): boolean {
  return policy.roles.some(
    (role) => !role.quoted && (role.name === "public" || role.name === audience),
  );
}

/** PostgreSQL defaults/fallbacks for the row-visibility and new-row check phases. */
export function policyPredicateForPhase(
  policy: ActivePolicy,
  command: Exclude<RlsCommand, "all">,
  phase: "using" | "check",
): { truth: PredicateTruth; source: RlsSourceLocation; predicate?: PolicyPredicate } {
  if (!policy.valid || !policyAppliesToCommand(policy, command)) {
    return { truth: "unsupported", source: policy.source };
  }
  if (phase === "using") {
    if (command === "insert") return { truth: "unsupported", source: policy.source };
    return policy.using
      ? { truth: policy.using.truth, source: policy.using.source, predicate: policy.using }
      : { truth: "true", source: policy.source };
  }
  if (command === "select" || command === "delete") {
    return { truth: "unsupported", source: policy.source };
  }
  const predicate = policy.withCheck ?? policy.using;
  return predicate
    ? { truth: predicate.truth, source: predicate.source, predicate }
    : { truth: "true", source: policy.source };
}
