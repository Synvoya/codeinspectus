/**
 * Bounded, read-only GitHub Actions workflow analysis.
 *
 * Workflows are parsed as YAML 1.2 data. Target actions, scripts, and expressions
 * are never evaluated or executed, and symbolic links are never followed.
 */

import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readdir, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, join, parse, relative, resolve } from "node:path";
import {
  isMap,
  isScalar,
  isSeq,
  parseDocument,
  type Node as YamlNode,
  type YAMLMap,
} from "yaml";

import { makeAiFinding } from "../../ai-checks/finding.js";
import type { Finding } from "../../types.js";
import type { NativeAnalyzerResult } from "../types.js";

export const GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID =
  "ci-github-actions-untrusted-expression-command";
export const GITHUB_ACTIONS_PWN_REQUEST_RULE_ID =
  "ci-github-actions-pwn-request";

export const GITHUB_ACTIONS_RULE_IDS = [
  GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID,
  GITHUB_ACTIONS_PWN_REQUEST_RULE_ID,
] as const;

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 512;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_NOTES = 24;

interface WorkflowDocument {
  path: string;
  content: string;
}

interface WorkflowProject {
  files: WorkflowDocument[];
  limitations: string[];
}

interface WorkflowStep {
  uses?: YamlNode | null;
  run?: YamlNode | null;
  with?: YAMLMap;
}

function normalized(path: string): string {
  return path.replace(/\\/g, "/");
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(left: BigIntStats, right: BigIntStats): boolean {
  return sameIdentity(left, right) && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function isWorkflowPath(path: string): boolean {
  const extension = extname(path).toLowerCase();
  if (extension !== ".yml" && extension !== ".yaml") return false;
  const parent = dirname(path);
  return basename(parent).toLowerCase() === "workflows" &&
    basename(dirname(parent)).toLowerCase() === ".github";
}

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index++) {
    if (source.charCodeAt(index) === 10) line++;
  }
  return line;
}

function sourceRange(node: YamlNode | null | undefined): [number, number] | undefined {
  if (!node?.range) return undefined;
  return [node.range[0], node.range[2] ?? node.range[1]];
}

function scalarString(node: YamlNode | null | undefined): string | undefined {
  if (!isScalar(node)) return undefined;
  if (typeof node.value === "string") return node.value;
  if (typeof node.value === "number" || typeof node.value === "boolean") {
    return String(node.value);
  }
  return undefined;
}

function mapValue(map: YAMLMap, key: string): YamlNode | null | undefined {
  for (const pair of map.items) {
    if (isScalar(pair.key) && pair.key.value === key) return pair.value as YamlNode | null;
  }
  return undefined;
}

function noteCollector(): { add: (note: string) => void; finish: () => string[] } {
  const notes = new Set<string>();
  let omitted = 0;
  return {
    add(note) {
      if (notes.size < MAX_NOTES - 1) notes.add(note);
      else omitted++;
    },
    finish() {
      return [
        ...notes,
        ...(omitted ? [`${omitted} additional GitHub Actions limitations omitted.`] : []),
      ].sort();
    },
  };
}

async function hasSymbolicLinkAncestor(absoluteTarget: string): Promise<boolean> {
  const filesystemRoot = parse(absoluteTarget).root;
  const ancestors: string[] = [];
  let current = dirname(absoluteTarget);
  while (current !== filesystemRoot) {
    ancestors.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  for (const ancestor of ancestors.reverse()) {
    const metadata = await lstat(ancestor).catch(() => undefined);
    if (!metadata) break;
    if (metadata.isSymbolicLink()) return true;
  }
  return false;
}

async function readWorkflowFile(
  absolute: string,
  displayPath: string,
  remainingBytes: number,
): Promise<{ document?: WorkflowDocument; bytes?: number; limitation?: string; totalExceeded?: boolean }> {
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(absolute, { bigint: true });
    if (before.isSymbolicLink()) {
      return { limitation: `Skipped symbolic-link GitHub Actions workflow ${displayPath}.` };
    }
    if (!before.isFile()) return {};
    if (before.size > BigInt(MAX_FILE_BYTES)) {
      return { limitation: `Skipped oversized GitHub Actions workflow ${displayPath} (limit: ${MAX_FILE_BYTES} bytes).` };
    }
    if (before.size > BigInt(remainingBytes)) return { bytes: Number(before.size), totalExceeded: true };

    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    handle = await open(absolute, constants.O_RDONLY | noFollow);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened)) {
      return { limitation: `Skipped changed GitHub Actions workflow ${displayPath}.` };
    }
    const size = Number(opened.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const result = await handle.read(bytes, offset, size - offset, offset);
      if (result.bytesRead === 0) {
        return { bytes: size, limitation: `Skipped changed GitHub Actions workflow ${displayPath}.` };
      }
      offset += result.bytesRead;
    }
    if (!unchangedFile(opened, await handle.stat({ bigint: true }))) {
      return { bytes: size, limitation: `Skipped changed GitHub Actions workflow ${displayPath}.` };
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return { bytes: size, limitation: `Skipped non-UTF-8 GitHub Actions workflow ${displayPath}.` };
    }
    return { document: { path: normalized(displayPath), content }, bytes: size };
  } catch {
    return { limitation: `Skipped unreadable GitHub Actions workflow ${displayPath}.` };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function loadWorkflowProject(target: string): Promise<WorkflowProject> {
  const absoluteTarget = resolve(target);
  const notes = noteCollector();
  if (await hasSymbolicLinkAncestor(absoluteTarget)) {
    return {
      files: [],
      limitations: [
        "Skipped GitHub Actions target because a symbolic-link ancestor would be followed; symbolic-link ancestors are never allowed.",
      ],
    };
  }
  const targetMetadata = await lstat(absoluteTarget).catch(() => undefined);
  if (!targetMetadata) return { files: [], limitations: ["GitHub Actions target was unreadable."] };
  if (targetMetadata.isSymbolicLink()) {
    return { files: [], limitations: ["Skipped symbolic-link GitHub Actions target; symbolic links are never followed."] };
  }
  if (targetMetadata.isFile()) {
    if (!isWorkflowPath(absoluteTarget)) return { files: [], limitations: [] };
    const loaded = await readWorkflowFile(absoluteTarget, basename(absoluteTarget), MAX_TOTAL_BYTES);
    if (loaded.limitation) notes.add(loaded.limitation);
    return { files: loaded.document ? [loaded.document] : [], limitations: notes.finish() };
  }
  if (!targetMetadata.isDirectory()) return { files: [], limitations: [] };

  const directWorkflowDirectory = basename(absoluteTarget).toLowerCase() === "workflows" &&
    basename(dirname(absoluteTarget)).toLowerCase() === ".github";
  const workflowDirectory = directWorkflowDirectory
    ? absoluteTarget
    : join(absoluteTarget, ".github", "workflows");
  const workflowDirectoryMetadata = await lstat(workflowDirectory).catch(() => undefined);
  if (!workflowDirectoryMetadata) return { files: [], limitations: [] };
  if (workflowDirectoryMetadata.isSymbolicLink()) {
    return { files: [], limitations: ["Skipped symbolic-link .github/workflows directory; symbolic links are never followed."] };
  }
  if (!workflowDirectoryMetadata.isDirectory()) return { files: [], limitations: [] };

  const entries = await readdir(workflowDirectory, { withFileTypes: true }).catch(() => undefined);
  if (!entries) return { files: [], limitations: ["Skipped unreadable .github/workflows directory."] };
  entries.sort((left, right) => left.name.localeCompare(right.name));
  const files: WorkflowDocument[] = [];
  let totalBytes = 0;
  for (const entry of entries) {
    const extension = extname(entry.name).toLowerCase();
    if (extension !== ".yml" && extension !== ".yaml") continue;
    const displayPath = directWorkflowDirectory
      ? entry.name
      : normalized(join(".github", "workflows", entry.name));
    if (entry.isSymbolicLink()) {
      notes.add(`Skipped symbolic-link GitHub Actions workflow ${displayPath}.`);
      continue;
    }
    if (!entry.isFile()) continue;
    if (files.length >= MAX_FILES) {
      notes.add(`Stopped GitHub Actions workflow discovery at the ${MAX_FILES}-file bound.`);
      break;
    }
    const loaded = await readWorkflowFile(
      join(workflowDirectory, entry.name),
      displayPath,
      MAX_TOTAL_BYTES - totalBytes,
    );
    if (loaded.limitation) notes.add(loaded.limitation);
    if (loaded.totalExceeded) {
      notes.add(`Stopped GitHub Actions workflow discovery at the ${MAX_TOTAL_BYTES}-byte project bound.`);
      break;
    }
    totalBytes += loaded.bytes ?? 0;
    if (loaded.document) files.push(loaded.document);
  }
  return { files, limitations: notes.finish() };
}

function hasEvent(node: YamlNode | null | undefined, event: string): boolean {
  if (isScalar(node)) return node.value === event;
  if (isSeq(node)) return node.items.some((item) => isScalar(item) && item.value === event);
  if (isMap(node)) {
    return node.items.some((pair) => isScalar(pair.key) && pair.key.value === event);
  }
  return false;
}

function workflowSteps(root: YAMLMap): WorkflowStep[] {
  const jobs = mapValue(root, "jobs");
  if (!isMap(jobs)) return [];
  const steps: WorkflowStep[] = [];
  for (const job of jobs.items) {
    if (!isMap(job.value)) continue;
    const sequence = mapValue(job.value, "steps");
    if (!isSeq(sequence)) continue;
    for (const item of sequence.items) {
      if (!isMap(item)) continue;
      const withNode = mapValue(item, "with");
      steps.push({
        uses: mapValue(item, "uses"),
        run: mapValue(item, "run"),
        ...(isMap(withNode) ? { with: withNode } : {}),
      });
    }
  }
  return steps;
}

function normalizedExpressionBody(body: string): string {
  return body.toLowerCase().replace(/\s*\.\s*/g, ".").replace(/\s+/g, " ");
}

function isUntrustedExpressionBody(body: string): boolean {
  const value = normalizedExpressionBody(body);
  return [
    /\bgithub\.event\.issue\.(?:title|body)\b/,
    /\bgithub\.event\.pull_request\.(?:title|body)\b/,
    /\bgithub\.event\.pull_request\.head\.(?:ref|label)\b/,
    /\bgithub\.event\.pull_request\.head\.repo\.default_branch\b/,
    /\bgithub\.event\.(?:comment|review|review_comment)\.body\b/,
    /\bgithub\.event\.pages\.\*\.page_name\b/,
    /\bgithub\.event\.(?:commits\.\*|head_commit)\.(?:message|author\.(?:name|email))\b/,
    /\bgithub\.head_ref\b/,
  ].some((pattern) => pattern.test(value));
}

function isShellCommentAt(value: string, offset: number): boolean {
  const lineStart = value.lastIndexOf("\n", offset - 1) + 1;
  let quote: "single" | "double" | "backtick" | undefined;
  let escaped = false;
  for (let index = lineStart; index < offset; index++) {
    const character = value[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "single") {
      escaped = true;
      continue;
    }
    if (quote === "single") {
      if (character === "'") quote = undefined;
      continue;
    }
    if (quote === "double") {
      if (character === '"') quote = undefined;
      continue;
    }
    if (quote === "backtick") {
      if (character === "`") quote = undefined;
      continue;
    }
    if (character === "'") quote = "single";
    else if (character === '"') quote = "double";
    else if (character === "`") quote = "backtick";
    else if (character === "#" && value[index - 1] !== "$") return true;
  }
  return false;
}

function lineSnippet(source: string, offset: number): string {
  const start = source.lastIndexOf("\n", Math.max(0, offset - 1)) + 1;
  const end = source.indexOf("\n", offset);
  return source.slice(start, end === -1 ? source.length : end).trim().slice(0, 240);
}

function expressionInjectionFindings(document: WorkflowDocument, steps: readonly WorkflowStep[]): Finding[] {
  const findings: Finding[] = [];
  for (const step of steps) {
    const range = sourceRange(step.run);
    if (!range) continue;
    const raw = document.content.slice(range[0], range[1]);
    for (const expression of raw.matchAll(/\$\{\{([\s\S]*?)\}\}/g)) {
      if (!isUntrustedExpressionBody(expression[1] ?? "")) continue;
      const localOffset = expression.index ?? 0;
      if (isShellCommentAt(raw, localOffset)) continue;
      const absoluteOffset = range[0] + localOffset;
      findings.push(makeAiFinding({
        ruleId: GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID,
        title: "GitHub Actions script interpolates attacker-controlled event data",
        severity: "high",
        cwe: ["CWE-78", "CWE-94"],
        owasp_web: ["A03:2021"],
        attack_techniques: ["T1059"],
        file: document.path,
        startLine: lineAt(document.content, absoluteOffset),
        snippet: lineSnippet(document.content, absoluteOffset),
        message:
          "A GitHub Actions run script directly interpolates attacker-controlled event data. GitHub substitutes the expression before creating the runner script, allowing crafted input to alter shell syntax.",
        remediation: {
          summary: "Pass untrusted GitHub context data through an intermediate environment variable or a dedicated action.",
          steps: [
            "Move the expression to the step's env mapping instead of embedding it in run.",
            "Reference and quote the environment variable according to the selected shell.",
            "Keep GITHUB_TOKEN permissions and exposed secrets at the minimum required scope.",
          ],
          references: [
            "CWE-78",
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://docs.github.com/en/actions/concepts/security/script-injections",
            "https://docs.github.com/en/actions/reference/security/secure-use",
          ],
        },
        confidence: "high",
      }));
    }
  }
  return findings;
}

function unsafeCheckoutRef(step: WorkflowStep): boolean {
  if (!step.with) return false;
  const ref = scalarString(mapValue(step.with, "ref")) ?? "";
  const repository = scalarString(mapValue(step.with, "repository")) ?? "";
  const normalizedRef = normalizedExpressionBody(ref);
  const normalizedRepository = normalizedExpressionBody(repository);
  return /\bgithub\.event\.pull_request\.(?:head\.(?:sha|ref)|merge_commit_sha)\b/.test(normalizedRef) ||
    /\bgithub\.head_ref\b/.test(normalizedRef) ||
    (/refs\/pull\//i.test(ref) &&
      /\bgithub\.event\.(?:number|pull_request\.number)\b/.test(normalizedRef)) ||
    /\bgithub\.event\.pull_request\.head\.repo\.full_name\b/.test(normalizedRepository);
}

function checkoutProtectionDisabled(step: WorkflowStep): boolean {
  if (!step.with) return false;
  const value = scalarString(mapValue(step.with, "allow-unsafe-pr-checkout"));
  return value?.toLowerCase() === "true";
}

function checkoutMajor(document: WorkflowDocument, uses: YamlNode | null | undefined): number | undefined {
  const value = scalarString(uses);
  if (!value) return undefined;
  const direct = value.match(/^actions\/checkout@v(\d+)(?:\D|$)/i)?.[1];
  if (direct) return Number(direct);
  const range = sourceRange(uses);
  if (!range) return undefined;
  const line = lineSnippet(document.content, range[0]);
  const commentVersion = line.match(/#\s*v(\d+)(?:\.\d+){0,2}\b/i)?.[1];
  return commentVersion ? Number(commentVersion) : undefined;
}

function runExecutesWorkspace(run: string): boolean {
  return [
    /(?:^|[\n;&|])\s*(?:sudo\s+)?(?:npm|pnpm|yarn|bun)\s+(?:ci|install|run|test|build|exec)\b/i,
    /(?:^|[\n;&|])\s*(?:sudo\s+)?make(?:\s|$)/i,
    /(?:^|[\n;&|])\s*(?:sudo\s+)?(?:cargo\s+(?:build|test|run)|go\s+(?:build|test|run|generate)|pytest\b|tox\b)/i,
    /(?:^|[\n;&|])\s*(?:sudo\s+)?(?:\.\/[^\s;|&]+|(?:bash|sh|pwsh|powershell|python3?|ruby|php|node)\s+(?:\.\/|[^\s]+\.(?:sh|ps1|py|rb|php|[cm]?js)))/i,
    /(?:^|[\n;&|])\s*(?:sudo\s+)?(?:\.\/)?(?:mvnw?|gradlew?|dotnet|bundle\s+exec|composer\s+(?:install|run))\b/i,
  ].some((pattern) => pattern.test(run));
}

function executionNode(step: WorkflowStep): YamlNode | null | undefined {
  const uses = scalarString(step.uses);
  if (uses?.startsWith("./")) return step.uses;
  const run = scalarString(step.run);
  if (run && runExecutesWorkspace(run)) return step.run;
  return undefined;
}

function pwnRequestFindings(
  document: WorkflowDocument,
  root: YAMLMap,
  steps: readonly WorkflowStep[],
  notes: ReturnType<typeof noteCollector>,
): Finding[] {
  if (!hasEvent(mapValue(root, "on"), "pull_request_target")) return [];
  for (let index = 0; index < steps.length; index++) {
    const checkout = steps[index]!;
    const uses = scalarString(checkout.uses);
    if (!/^actions\/checkout@/i.test(uses ?? "") || !unsafeCheckoutRef(checkout)) continue;
    const path = scalarString(checkout.with ? mapValue(checkout.with, "path") : undefined);
    if (path && path !== "." && normalizedExpressionBody(path) !== "${{ github.workspace }}") {
      notes.add(`Skipped pwn-request conclusion in ${document.path} because untrusted checkout uses a non-default path.`);
      continue;
    }
    const major = checkoutMajor(document, checkout.uses);
    const protectionDisabled = checkoutProtectionDisabled(checkout);
    if (!protectionDisabled && major !== undefined && major >= 7) continue;
    if (!protectionDisabled && major === undefined) {
      notes.add(
        `Skipped pwn-request conclusion in ${document.path} because the pinned actions/checkout major was not documented.`,
      );
      continue;
    }
    for (const later of steps.slice(index + 1)) {
      const sink = executionNode(later);
      const range = sourceRange(sink);
      if (!range) continue;
      return [makeAiFinding({
        ruleId: GITHUB_ACTIONS_PWN_REQUEST_RULE_ID,
        title: "Privileged GitHub Actions workflow executes untrusted pull request code",
        severity: "critical",
        cwe: ["CWE-94", "CWE-829"],
        owasp_web: ["A08:2021"],
        attack_techniques: ["T1195.002"],
        file: document.path,
        startLine: lineAt(document.content, range[0]),
        snippet: lineSnippet(document.content, range[0]),
        message:
          "A pull_request_target workflow checks out attacker-controlled pull request content and later executes the checked-out workspace in the privileged base-repository context.",
        remediation: {
          summary: "Do not execute untrusted pull request content from pull_request_target.",
          steps: [
            "Run untrusted builds and tests under pull_request with a read-only token and no repository secrets.",
            "Keep privileged pull_request_target automation on trusted base-branch code and treat pull request content only as data.",
            "If results need privileged publication, pass minimal non-executable data to a separate workflow and validate it before use.",
          ],
          references: [
            "CWE-94",
            "https://cwe.mitre.org/data/definitions/94.html",
            "https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target",
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
          ],
        },
        confidence: "high",
      })];
    }
  }
  return [];
}

function analyzeWorkflow(
  document: WorkflowDocument,
  notes: ReturnType<typeof noteCollector>,
): Finding[] {
  const parsed = parseDocument(document.content, {
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
    version: "1.2",
  });
  if (parsed.errors.length > 0 || parsed.warnings.length > 0 || !isMap(parsed.contents)) {
    notes.add(`Skipped malformed or unsupported GitHub Actions workflow ${document.path}.`);
    return [];
  }
  const steps = workflowSteps(parsed.contents);
  return [
    ...expressionInjectionFindings(document, steps),
    ...pwnRequestFindings(document, parsed.contents, steps, notes),
  ];
}

/** Scan checked-in GitHub Actions workflows without executing target code. */
export async function runGithubActionsSecurity(target: string): Promise<NativeAnalyzerResult> {
  const project = await loadWorkflowProject(target);
  const notes = noteCollector();
  for (const limitation of project.limitations) notes.add(limitation);
  const findings = project.files.flatMap((document) => analyzeWorkflow(document, notes));
  const limitations = notes.finish();
  return {
    findings,
    ...(limitations.length ? { notes: limitations } : {}),
  };
}
