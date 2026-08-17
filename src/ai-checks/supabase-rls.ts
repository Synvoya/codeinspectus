/**
 * Repository-visible Supabase RLS analysis.
 *
 * Findings are limited to checked SQL state. Deployed schemas, grants, API exposure,
 * dashboard overrides, and migration execution success are never inferred from absence.
 */

import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { basename, extname, isAbsolute, join, relative, resolve } from "node:path";
import type { Finding, Severity, Confidence } from "../types.js";
import type { SourceFile } from "./walk.js";
import { lineText } from "./walk.js";
import { makeAiFinding } from "./finding.js";
import {
  policyAppliesToAudience,
  policyAppliesToCommand,
  policyPredicateForPhase,
  hasSupabaseAuthReference,
  reduceRlsEffectiveState,
  rlsMigrationDirectory,
  type ActivePolicy,
  type EffectiveTable,
  type PolicyPredicate,
  type RlsCommand,
  type RlsEffectiveState,
  type RlsSourceLocation,
} from "./supabase-migration-state.js";

const MAX_SQL_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SQL_FILES = 2_048;
const MAX_TOTAL_SQL_BYTES = 64 * 1024 * 1024;
const MAX_WALK_ENTRIES = 50_000;
const MAX_WALK_DEPTH = 32;
const MAX_FINDINGS = 512;
const MAX_NOTES = 24;
const IGNORE_DIRS = new Set([
  "node_modules", ".git", ".cache", "coverage", ".turbo", ".vercel", ".idea",
  ".vscode", ".pnpm-store", "dist", "build", ".next", "out", ".nuxt",
  ".svelte-kit", ".output",
]);
const TEST_FIXTURE_PATH_RE =
  /(^|\/)(tests?|__tests__|spec|specs|examples?|fixtures?|__fixtures__|mocks?|demo|sandbox)(\/|$)/i;

const SYSTEM_SCHEMAS = new Set([
  "auth", "storage", "realtime", "vault", "extensions", "graphql", "graphql_public",
  "pgbouncer", "net", "cron", "pgsodium", "supabase_functions", "supabase_migrations",
  "information_schema", "pg_catalog", "pg_temp",
]);

const OWNERSHIP_COL_RE = /\b(user_id|owner_id|account_id|profile_id|owner)\b/i;
const PII_COL_RE =
  /\b(email|phone|address|dob|ssn|password|password_hash|token|secret|api_key|stripe_customer\w*)\b|\b\w+_key\b/i;
const CATALOG_TABLES = new Set([
  "products", "product", "prices", "price", "plans", "plan", "categories", "category",
  "tags", "tag", "currencies", "countries", "regions", "languages", "locales",
]);
type Sensitivity = "strong" | "catalog" | "unknown";
type Audience = "anon" | "authenticated";
type Command = Exclude<RlsCommand, "all">;

interface RlsLoadResult {
  files: SourceFile[];
  loadedBytes: number;
  notes: string[];
  incompleteAll: boolean;
  incompleteMigrationDirectories: Set<string>;
}

export interface SupabaseRlsAnalysisResult {
  findings: Finding[];
  notes: string[];
}

interface EffectiveExposure {
  command: Command;
  audiences: Audience[];
  source: RlsSourceLocation;
}

function normalized(rel: string): string {
  return rel.replace(/\\/g, "/");
}

function containedBy(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function isExcludedRlsPath(rel: string): boolean {
  return TEST_FIXTURE_PATH_RE.test(normalized(rel));
}

function addIncompletePath(result: RlsLoadResult, rel: string): void {
  const migrationDirectory = rlsMigrationDirectory(normalized(rel));
  if (migrationDirectory !== undefined) result.incompleteMigrationDirectories.add(migrationDirectory);
}

function noteLoadOmission(result: RlsLoadResult, rel: string, reason: string): void {
  result.notes.push(`${rel}: ${reason}; final RLS state for the affected migration sequence was not inferred.`);
  addIncompletePath(result, rel);
}

async function readSqlFile(
  absolute: string,
  rel: string,
  result: RlsLoadResult,
  root?: string,
): Promise<SourceFile | undefined> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const canonicalBefore = await realpath(absolute);
    if (root && (canonicalBefore !== absolute || !containedBy(root, canonicalBefore))) {
      noteLoadOmission(result, rel, "SQL path escaped the canonical project root");
      return undefined;
    }
    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const before = await handle.stat();
    if (!before.isFile()) return undefined;
    if (before.size > MAX_SQL_FILE_BYTES) {
      noteLoadOmission(result, rel, `SQL file exceeds the ${MAX_SQL_FILE_BYTES}-byte bound`);
      return undefined;
    }
    if (result.files.length >= MAX_SQL_FILES) {
      result.incompleteAll = true;
      result.notes.push(`Supabase RLS SQL discovery stopped at the ${MAX_SQL_FILES}-file bound; effective-state findings were suppressed.`);
      return undefined;
    }
    if (result.loadedBytes + before.size > MAX_TOTAL_SQL_BYTES) {
      result.incompleteAll = true;
      result.notes.push(`Supabase RLS SQL loading stopped at the ${MAX_TOTAL_SQL_BYTES}-byte project bound; effective-state findings were suppressed.`);
      return undefined;
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const canonicalAfter = await realpath(absolute);
    if (
      before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs || bytes.length !== before.size ||
      canonicalBefore !== canonicalAfter || (root !== undefined && !containedBy(root, canonicalAfter))
    ) {
      noteLoadOmission(result, rel, "SQL file changed while it was being read");
      return undefined;
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      noteLoadOmission(result, rel, "SQL file is not valid UTF-8");
      return undefined;
    }
    if (content.includes("\u0000")) {
      noteLoadOmission(result, rel, "binary-looking SQL file was skipped");
      return undefined;
    }
    result.loadedBytes += before.size;
    return { abs: absolute, rel, content, ext: "sql" };
  } catch {
    noteLoadOmission(result, rel, "SQL file was unreadable or was a symbolic link");
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function loadRlsSqlFiles(target: string): Promise<RlsLoadResult> {
  const result: RlsLoadResult = {
    files: [],
    loadedBytes: 0,
    notes: [],
    incompleteAll: false,
    incompleteMigrationDirectories: new Set<string>(),
  };
  const absoluteTarget = resolve(target);
  let targetStat: Awaited<ReturnType<typeof lstat>>;
  try {
    targetStat = await lstat(absoluteTarget);
  } catch {
    return { ...result, notes: ["Supabase RLS target was unreadable; repository state was not inferred."], incompleteAll: true };
  }
  if (targetStat.isSymbolicLink()) {
    return { ...result, notes: ["Supabase RLS target was a symbolic link and was not followed."], incompleteAll: true };
  }
  if (targetStat.isFile()) {
    if (extname(absoluteTarget).toLowerCase() !== ".sql") return result;
    const rel = basename(absoluteTarget);
    const file = await readSqlFile(absoluteTarget, rel, result);
    if (file) result.files.push(file);
    return result;
  }
  if (!targetStat.isDirectory()) {
    return { ...result, notes: ["Supabase RLS target was not a regular file or directory."], incompleteAll: true };
  }

  const root = await realpath(absoluteTarget).catch(() => undefined);
  if (!root) {
    return { ...result, notes: ["Supabase RLS project root could not be resolved."], incompleteAll: true };
  }
  const queue: Array<{ absolute: string; rel: string; depth: number }> = [{ absolute: root, rel: "", depth: 0 }];
  let entriesSeen = 0;

  while (queue.length && !result.incompleteAll) {
    const directory = queue.shift()!;
    if (directory.depth > MAX_WALK_DEPTH) {
      result.notes.push(`${directory.rel || "."}: SQL discovery stopped at the ${MAX_WALK_DEPTH}-level depth bound.`);
      result.incompleteAll = true;
      break;
    }
    const directoryBefore = await lstat(directory.absolute).catch(() => undefined);
    const canonicalBefore = await realpath(directory.absolute).catch(() => undefined);
    if (
      !directoryBefore?.isDirectory() || directoryBefore.isSymbolicLink() ||
      canonicalBefore !== directory.absolute || !containedBy(root, directory.absolute)
    ) {
      result.notes.push(`${directory.rel || "."}: directory identity changed or escaped the project root during Supabase RLS discovery.`);
      result.incompleteAll = true;
      break;
    }
    const entries = await readdir(directory.absolute, { withFileTypes: true }).catch(() => undefined);
    if (!entries) {
      result.notes.push(`${directory.rel || "."}: directory was unreadable during Supabase RLS discovery.`);
      const migrationDirectory = rlsMigrationDirectory(`${directory.rel}/placeholder.sql`);
      if (migrationDirectory) result.incompleteMigrationDirectories.add(migrationDirectory);
      else result.incompleteAll = true;
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      entriesSeen += 1;
      if (entriesSeen > MAX_WALK_ENTRIES) {
        result.incompleteAll = true;
        result.notes.push(`Supabase RLS SQL discovery stopped at the ${MAX_WALK_ENTRIES}-entry project bound; effective-state findings were suppressed.`);
        break;
      }
      const rel = normalized(directory.rel ? `${directory.rel}/${entry.name}` : entry.name);
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name) || isExcludedRlsPath(rel)) continue;
        queue.push({ absolute: join(directory.absolute, entry.name), rel, depth: directory.depth + 1 });
        continue;
      }
      if (entry.isSymbolicLink()) {
        if (entry.name.toLowerCase().endsWith(".sql")) noteLoadOmission(result, rel, "symbolic-link SQL file was not followed");
        continue;
      }
      if (!entry.isFile() || !entry.name.toLowerCase().endsWith(".sql") || isExcludedRlsPath(rel)) continue;
      const file = await readSqlFile(join(directory.absolute, entry.name), rel, result, root);
      if (file) result.files.push(file);
      if (result.incompleteAll) break;
    }
    const directoryAfter = await lstat(directory.absolute).catch(() => undefined);
    const canonicalAfter = await realpath(directory.absolute).catch(() => undefined);
    if (
      !directoryAfter || directoryBefore.dev !== directoryAfter.dev ||
      directoryBefore.ino !== directoryAfter.ino || canonicalAfter !== canonicalBefore
    ) {
      result.notes.push(`${directory.rel || "."}: directory changed during Supabase RLS discovery; effective-state findings were suppressed.`);
      result.incompleteAll = true;
    }
  }
  result.files.sort((a, b) => a.rel.localeCompare(b.rel));
  return result;
}

function tableSensitivity(table: string, cols: string | undefined): Sensitivity {
  const text = cols ?? "";
  if (OWNERSHIP_COL_RE.test(text) || PII_COL_RE.test(text)) return "strong";
  if (CATALOG_TABLES.has(table)) return "catalog";
  return "unknown";
}

function snapshotConfidence(confidence: Confidence, isSnapshot: boolean): Confidence {
  if (!isSnapshot) return confidence;
  return confidence === "high" ? "medium" : "low";
}

function snapshotMessage(message: string, isSnapshot: boolean, subject: string): string {
  if (!isSnapshot) return message;
  return `${subject} found in standalone SQL. If this file represents applied state, ${message.charAt(0).toLowerCase()}${message.slice(1)} Deployed database state remains unverified.`;
}

function stateMigrationDirectory(state: RlsEffectiveState): string | undefined {
  return state.kind === "sequence" ? state.key.slice("sequence:".length) : undefined;
}

function stateAffectedByLoadOmission(state: RlsEffectiveState, load: RlsLoadResult): boolean {
  if (load.incompleteAll) return true;
  const directory = stateMigrationDirectory(state);
  return directory !== undefined && load.incompleteMigrationDirectories.has(directory);
}

function phasesFor(command: Command): Array<"using" | "check"> {
  if (command === "select" || command === "delete") return ["using"];
  if (command === "insert") return ["check"];
  return ["using", "check"];
}

function openPhase(
  policies: ActivePolicy[],
  command: Command,
  audience: Audience,
  phase: "using" | "check",
): { open: boolean; source?: RlsSourceLocation } {
  const applicable = policies.filter(
    (policy) => policy.valid && policyAppliesToCommand(policy, command) && policyAppliesToAudience(policy, audience),
  );
  const permissive = applicable.filter((policy) => policy.mode === "permissive");
  const restrictive = applicable.filter((policy) => policy.mode === "restrictive");
  const openPermissive = permissive
    .map((policy) => policyPredicateForPhase(policy, command, phase))
    .find((predicate) => predicate.truth === "true");
  if (!openPermissive) return { open: false };
  const restrictiveAllTrue = restrictive.every(
    (policy) => policyPredicateForPhase(policy, command, phase).truth === "true",
  );
  return restrictiveAllTrue ? { open: true, source: openPermissive.source } : { open: false };
}

function effectiveExposures(policies: ActivePolicy[]): EffectiveExposure[] {
  const individual: Array<{ command: Command; audience: Audience; source: RlsSourceLocation }> = [];
  for (const command of ["select", "insert", "update", "delete"] as const) {
    for (const audience of ["anon", "authenticated"] as const) {
      const phases = phasesFor(command).map((phase) => openPhase(policies, command, audience, phase));
      if (phases.every((phase) => phase.open)) {
        individual.push({ command, audience, source: phases[0]!.source! });
      }
    }
  }

  const grouped = new Map<string, EffectiveExposure>();
  for (const exposure of individual) {
    const key = `${exposure.command}\u0000${exposure.source.file}\u0000${exposure.source.line}`;
    const existing = grouped.get(key);
    if (existing) existing.audiences.push(exposure.audience);
    else grouped.set(key, { command: exposure.command, audiences: [exposure.audience], source: exposure.source });
  }
  return [...grouped.values()];
}

function audienceLabel(audiences: Audience[]): string {
  if (audiences.includes("anon") && audiences.includes("authenticated")) {
    return "anonymous and authenticated clients";
  }
  return audiences.includes("anon") ? "anonymous clients" : "authenticated clients";
}

function isStorageObjects(schema: string, table: string): boolean {
  return schema === "storage" && table === "objects";
}

function hasInvertedAuth(predicate: PolicyPredicate | undefined): boolean {
  if (!predicate || predicate.truth === "true") return false;
  const hasUid = /\bauth\s*\.\s*uid\s*\(\s*\)/i.test(predicate.maskedExpression);
  const hasBroadRoleComparison =
    /\bauth\s*\.\s*role\s*\(\s*\)\s*=\s*'(?:anon|authenticated)'|'(?:anon|authenticated)'\s*=\s*auth\s*\.\s*role\s*\(\s*\)/i.test(
      predicate.expression,
    );
  let hasBroadJwtComparison = false;
  const jwt = /\bauth\s*\.\s*jwt\s*\(\s*\)/gi;
  for (const match of predicate.maskedExpression.matchAll(jwt)) {
    const offset = match.index ?? 0;
    const originalTail = predicate.expression.slice(offset, offset + 256);
    if (
      /^auth\s*\.\s*jwt\s*\(\s*\)\s*->>?\s*'(?:aud|role)'\s*=\s*'(?:anon|authenticated)'/i.test(
        originalTail,
      )
    ) {
      hasBroadJwtComparison = true;
      break;
    }
  }
  if (!hasBroadRoleComparison && !hasBroadJwtComparison) return false;
  if (!hasUid) return true;

  let expression = predicate.maskedExpression.trim();
  while (expression.startsWith("(") && expression.endsWith(")")) {
    let depth = 0;
    let wrapsAll = true;
    for (let index = 0; index < expression.length; index += 1) {
      if (expression[index] === "(") depth += 1;
      else if (expression[index] === ")") depth -= 1;
      if (depth === 0 && index < expression.length - 1) {
        wrapsAll = false;
        break;
      }
    }
    if (!wrapsAll || depth !== 0) break;
    expression = expression.slice(1, -1).trim();
  }
  let depth = 0;
  for (let index = 0; index < expression.length; index += 1) {
    if (expression[index] === "(") depth += 1;
    else if (expression[index] === ")") depth -= 1;
    else if (
      depth === 0 && /^or\b/i.test(expression.slice(index)) &&
      (index === 0 || !/[\w$]/.test(expression[index - 1]!))
    ) {
      return true;
    }
  }
  return false;
}

function policyTableState(state: RlsEffectiveState, policy: ActivePolicy): EffectiveTable | undefined {
  return state.tables.get(policy.tableKey);
}

function policyStateIsAnalyzable(
  state: RlsEffectiveState,
  policy: ActivePolicy,
  notes: string[],
): boolean {
  const table = policyTableState(state, policy);
  if (table?.rlsEnabled === false) return false;
  if (isStorageObjects(policy.schema, policy.table)) return true;
  if (policy.schema !== "public") {
    if (!SYSTEM_SCHEMAS.has(policy.schema)) {
      notes.push(`${policy.source.file}:${policy.source.line}: schema '${policy.schema}' API exposure is not proven from repository SQL; RLS policy state was not classified.`);
    }
    return false;
  }
  if (!table || table.rlsEnabled === "unknown") {
    notes.push(`${policy.source.file}:${policy.source.line}: public table RLS enablement is not repository-proven; policy openness was not inferred.`);
    return false;
  }
  return table.rlsEnabled;
}

function pushStorageExposure(
  findings: Finding[],
  exposure: EffectiveExposure,
  isSnapshot: boolean,
): void {
  const isWrite = exposure.command !== "select";
  const actors = audienceLabel(exposure.audiences);
  const message = isWrite
    ? `The final applicable policy composition for ${exposure.command.toUpperCase()} is provably TRUE for ${actors}. Repository SQL therefore permits those roles to modify storage.objects rows without an ownership predicate. Deployed bucket state, grants, and runtime controls are not verified.`
    : `The final applicable policy composition for SELECT is provably TRUE for ${actors}. Repository SQL therefore permits those roles to read storage.objects rows without an ownership predicate. Deployed bucket state, grants, and runtime controls are not verified.`;
  findings.push(
    makeAiFinding({
      ruleId: "ci-ai-storage-rls-public",
      title: isWrite
        ? `Storage RLS permits ${exposure.command.toUpperCase()} for ${actors}`
        : `Storage RLS permits SELECT for ${actors}`,
      severity: isWrite ? "critical" : "high",
      cwe: ["CWE-863", "CWE-285"],
      owasp_web: ["A01:2021"],
      file: exposure.source.file,
      startLine: exposure.source.line,
      snippet: lineText(exposure.source.content, exposure.source.line),
      message: snapshotMessage(message, isSnapshot, "Open storage policy composition"),
      remediation: {
        summary: "Scope storage.objects policies to the intended bucket and owner; keep public access only where it is a deliberate product requirement.",
        steps: [
          "Separate genuinely public asset buckets from private uploads.",
          "Use bucket_id and auth.uid()-bound predicates for private data.",
          "Verify deployed bucket privacy, grants, and policies separately.",
        ],
        references: ["CWE-863", "https://supabase.com/docs/guides/storage/security/access-control"],
      },
      confidence: snapshotConfidence("high", isSnapshot),
    }),
  );
}

function pushPublicTableExposure(
  findings: Finding[],
  exposure: EffectiveExposure,
  table: string,
  columns: string | undefined,
  isSnapshot: boolean,
): void {
  const isWrite = exposure.command !== "select";
  const sensitivity = tableSensitivity(table, columns);
  const actors = audienceLabel(exposure.audiences);
  let severity: Severity;
  let confidence: Confidence;
  let title: string;
  if (isWrite) {
    severity = "critical";
    confidence = "high";
    title = `RLS permits ${exposure.command.toUpperCase()} on '${table}' for ${actors}`;
  } else if (sensitivity === "strong") {
    severity = "critical";
    confidence = "high";
    title = `RLS permits SELECT on sensitive table '${table}' for ${actors}`;
  } else if (sensitivity === "catalog") {
    severity = "low";
    confidence = "medium";
    title = `Public read policy on catalog-like table '${table}' — confirm intended`;
  } else {
    severity = "medium";
    confidence = "medium";
    title = `RLS permits SELECT on '${table}' for ${actors} — verify intended`;
  }
  const operation = exposure.command.toUpperCase();
  const baseMessage =
    `The final applicable permissive and restrictive policy composition for ${operation} is provably TRUE for ${actors}. The checked repository SQL therefore contains no row predicate for that operation and role. This does not prove deployed API reachability, table grants, migration application, or hosted configuration.`;
  findings.push(
    makeAiFinding({
      ruleId: "ci-ai-rls-using-true",
      title,
      severity,
      cwe: ["CWE-863", "CWE-285"],
      owasp_web: ["A01:2021"],
      file: exposure.source.file,
      startLine: exposure.source.line,
      snippet: lineText(exposure.source.content, exposure.source.line),
      message: snapshotMessage(baseMessage, isSnapshot, "Open RLS policy composition"),
      remediation: {
        summary: "Replace the open policy composition with operation-specific ownership or authorization predicates unless this access is deliberate.",
        steps: [
          "Confirm which database roles should perform this operation.",
          "Use auth.uid()-bound ownership or a server-controlled authorization predicate.",
          "Review both permissive and restrictive policies for the same command and role.",
          "Verify deployed grants and policy state separately.",
        ],
        references: ["CWE-863", "https://supabase.com/docs/guides/database/postgres/row-level-security"],
      },
      confidence: snapshotConfidence(confidence, isSnapshot),
    }),
  );
}

function pushInvertedAuthFinding(
  findings: Finding[],
  policy: ActivePolicy,
  predicate: PolicyPredicate,
  isSnapshot: boolean,
): void {
  const roles = policy.roles
    .filter((role) => !role.quoted && ["public", "anon", "authenticated"].includes(role.name))
    .map((role) => role.name);
  const roleText = roles.length ? roles.join(", ") : "client-facing roles";
  const message =
    `This permissive policy for ${roleText} keys access off the JWT aud/role claim rather than row ownership via auth.uid(). That can authorize every member of a broad role. Repository SQL does not prove whether that breadth is intended or deployed.`;
  findings.push(
    makeAiFinding({
      ruleId: "ci-ai-rls-inverted-auth",
      title: `Policy on '${policy.table}' may test a broad JWT role instead of row identity`,
      severity: "medium",
      cwe: ["CWE-863"],
      owasp_web: ["A01:2021"],
      file: predicate.source.file,
      startLine: predicate.source.line,
      snippet: lineText(predicate.source.content, predicate.source.line),
      message: snapshotMessage(message, isSnapshot, "Broad-role RLS policy"),
      remediation: {
        summary: "Verify whether the policy should bind rows to auth.uid() rather than authorize a whole JWT role.",
        steps: ["Tie per-user rows to auth.uid(), or document and test the deliberate shared-role access."],
        references: ["CWE-863"],
      },
      confidence: snapshotConfidence("medium", isSnapshot),
    }),
  );
}

function pushMissingRlsFinding(findings: Finding[], table: EffectiveTable, isSnapshot: boolean): void {
  const explicitlyDisabled = table.lastRlsChange?.enabled === false;
  const location = explicitlyDisabled ? table.lastRlsChange!.source : table.created!;
  const title = explicitlyDisabled
    ? `Repository migration explicitly disables Row Level Security on public table '${table.table}'`
    : `Repository-defined public table '${table.table}' lacks Row Level Security`;
  const message = explicitlyDisabled
    ? `The checked repository contains an explicit ALTER TABLE ... DISABLE ROW LEVEL SECURITY for public.${table.table}. This proves the modeled repository migration state leaves RLS off; it does not prove deployed API reachability, table grants, migration application, or hosted configuration.`
    : `The checked repository defines public.${table.table} and does not enable Row Level Security in the conclusive migration sequence. This is a repository-visible missing control, not proof that the deployed table is reachable through an API or granted to client roles.`;
  findings.push(
    makeAiFinding({
      ruleId: "ci-ai-rls-missing",
      title,
      severity: "high",
      cwe: ["CWE-862", "CWE-285"],
      owasp_web: ["A01:2021"],
      file: location.file,
      startLine: location.line,
      snippet: lineText(location.content, location.line),
      message: snapshotMessage(message, isSnapshot, explicitlyDisabled ? "RLS-disabling statement" : "Public table declaration"),
      remediation: {
        summary: `Enable RLS on public.${table.table}, add least-privilege policies, and verify deployed grants separately.`,
        steps: [
          `ALTER TABLE public.${table.table} ENABLE ROW LEVEL SECURITY;`,
          "Add command-specific policies with ownership or authorization predicates.",
          "Verify the applied migration, table grants, and hosted API exposure outside repository analysis.",
        ],
        references: ["CWE-862", "https://supabase.com/docs/guides/database/postgres/row-level-security"],
      },
      confidence: snapshotConfidence("medium", isSnapshot),
    }),
  );
}

function boundedNotes(notes: string[], omittedFindings: number): string[] {
  const unique = [...new Set(notes)].sort();
  const required = omittedFindings > 0
    ? [`${omittedFindings} additional Supabase RLS finding(s) omitted at the ${MAX_FINDINGS}-finding bound.`]
    : [];
  const regularCapacity = MAX_NOTES - required.length;
  if (unique.length <= regularCapacity) return [...unique, ...required];
  const visibleCapacity = Math.max(0, regularCapacity - 1);
  return [
    ...unique.slice(0, visibleCapacity),
    `${unique.length - visibleCapacity} additional Supabase RLS coverage note(s) omitted.`,
    ...required,
  ];
}

export async function runSupabaseRlsAnalysis(target: string): Promise<SupabaseRlsAnalysisResult> {
  const load = await loadRlsSqlFiles(target);
  const notes = [...load.notes];
  const findings: Finding[] = [];
  const looksLikeSupabase =
    load.files.some((file) => /(^|\/)supabase\//i.test(file.rel)) ||
    load.files.some((file) => hasSupabaseAuthReference(file.content));
  if (!looksLikeSupabase) return { findings: [], notes: boundedNotes(notes, 0) };

  for (const state of reduceRlsEffectiveState(load.files)) {
    notes.push(...state.notes);
    if (!state.conclusive || stateAffectedByLoadOmission(state, load)) {
      if (stateAffectedByLoadOmission(state, load)) {
        notes.push(`${state.key}: omitted SQL could change final RLS state; effective-state findings were suppressed.`);
      }
      continue;
    }
    const isSnapshot = state.kind === "snapshot";
    const policiesByTable = new Map<string, ActivePolicy[]>();
    for (const policy of state.policies.values()) {
      const policies = policiesByTable.get(policy.tableKey) ?? [];
      policies.push(policy);
      policiesByTable.set(policy.tableKey, policies);
    }

    for (const policies of policiesByTable.values()) {
      const representative = policies[0]!;
      if (!policyStateIsAnalyzable(state, representative, notes)) continue;
      const exposures = effectiveExposures(policies);
      const tableState = policyTableState(state, representative);
      for (const exposure of exposures) {
        if (isStorageObjects(representative.schema, representative.table)) {
          pushStorageExposure(findings, exposure, isSnapshot);
        } else {
          pushPublicTableExposure(
            findings,
            exposure,
            representative.table,
            tableState?.columns,
            isSnapshot,
          );
        }
      }
      for (const policy of policies) {
        if (
          policy.mode !== "permissive" || !policy.valid ||
          !["public", "anon", "authenticated"].some((role) =>
            policy.roles.some((candidate) => !candidate.quoted && candidate.name === role)
          )
        ) continue;
        const predicate = hasInvertedAuth(policy.using)
          ? policy.using
          : hasInvertedAuth(policy.withCheck) ? policy.withCheck : undefined;
        if (predicate) pushInvertedAuthFinding(findings, policy, predicate, isSnapshot);
      }
    }

    for (const table of state.tables.values()) {
      if (table.schema !== "public" || table.rlsEnabled !== false) continue;
      if (!table.definedInRepository && table.lastRlsChange?.enabled !== false) continue;
      pushMissingRlsFinding(findings, table, isSnapshot);
    }
  }

  const omittedFindings = Math.max(0, findings.length - MAX_FINDINGS);
  return {
    findings: findings.slice(0, MAX_FINDINGS),
    notes: boundedNotes(notes, omittedFindings),
  };
}

/** Backward-compatible findings-only entrypoint; the pack should use runSupabaseRlsAnalysis. */
export async function runSupabaseRlsCheck(target: string): Promise<Finding[]> {
  return (await runSupabaseRlsAnalysis(target)).findings;
}
