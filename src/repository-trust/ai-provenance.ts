import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { basename, dirname, extname, join, relative } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import ExifReader from "exifreader";
import { fingerprint } from "../util/hash.js";
import type {
  RepositoryArtifact,
  RepositoryArtifactConfidence,
  RepositoryArtifactState,
} from "./schemas.js";

const execFileAsync = promisify(execFile);

export const EXPLICIT_AI_ATTRIBUTION_VALIDATOR = "codeinspectus-explicit-ai-attribution@1.0.0" as const;
export const MEDIA_METADATA_VALIDATOR = "codeinspectus-media-metadata@1.0.0" as const;
export const C2PA_VALIDATOR = "contentauth-c2pa-node@0.9.3" as const;

const DEFAULT_MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_METADATA_FILE_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_C2PA_FILE_BYTES = 128 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_ENTRIES = 50_000;
const DEFAULT_MAX_DEPTH = 64;
const DEFAULT_MAX_ARTIFACTS = 1_000;
const DEFAULT_MAX_COMMITS = 500;
const MAX_EVIDENCE_VALUE = 256;

const IGNORED_DIRECTORIES = new Set([
  ".git", ".cache", ".dart_tool", ".gradle", ".idea", ".next", ".nuxt", ".pnpm-store",
  ".terraform", ".turbo", ".venv", ".vercel", ".vscode", "Pods", "__pycache__", "build",
  "coverage", "dist", "generated", "node_modules", "out", "target", "vendor", "venv",
]);

const TEXT_EXTENSIONS = new Set([
  "astro", "bash", "c", "cc", "cfg", "clj", "cljs", "conf", "cpp", "cs", "css", "dart",
  "env", "ex", "exs", "fish", "go", "graphql", "gql", "h", "hpp", "html", "ini", "java",
  "js", "json", "jsx", "kt", "kts", "less", "lua", "mjs", "mts", "php", "plist",
  "properties", "proto", "py", "rb", "rs", "scala", "scss", "sh", "sol", "sql", "svelte",
  "swift", "tf", "toml", "ts", "tsx", "vue", "xml", "xmp", "yaml", "yml", "zig", "zsh",
]);

const TEXT_FILENAMES = new Set([
  ".babelrc", ".editorconfig", ".eslintrc", ".npmrc", ".prettierrc", "Brewfile",
  "CMakeLists.txt", "Containerfile", "Dockerfile", "Gemfile", "Guardfile", "Jenkinsfile",
  "COPYING", "LICENSE", "Makefile", "NOTICE", "Podfile", "Procfile", "Rakefile",
  "THIRD-PARTY-NOTICES.md", "Vagrantfile",
]);

const METADATA_EXTENSIONS = new Set([
  "avif", "gif", "heic", "heif", "jpeg", "jpg", "jxl", "png", "tif", "tiff", "webp",
]);

const C2PA_EXTENSIONS = new Set([
  ...METADATA_EXTENSIONS,
  "avi", "c2pa", "m4a", "m4v", "mov", "mp3", "mp4", "pdf", "svg", "wav",
]);

const PROTECTED_FILE_PATTERNS = [
  /(?:^|\/)(?:license|notice|copying)(?:\.[^/]*)?$/i,
  /(?:^|\/)(?:legal|compliance)(?:\/|$)/i,
  /(?:^|\/)third-party-notices(?:\.[^/]*)?$/i,
];

const AI_VENDOR_PATTERN = /\b(?:anthropic|claude(?:\s+code)?|chatgpt|openai|github\s+copilot|copilot|gemini|google\s+ai|midjourney|stable\s+diffusion|dall[·.-]?e|adobe\s+firefly|runway(?:\s+ai)?|ideogram|leonardo\.ai|flux(?:\s+ai)?)\b/i;
const AI_SOURCE_TYPE_PATTERN = /(?:trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia|algorithmicMedia)/i;
const ATTRIBUTION_LINE_PATTERNS = [
  /^\s*(?:(?:\/\/|#|\/\*+|\*|<!--)\s*)?(?:@generated\b.{0,160}|(?:this\s+(?:file|code)\s+(?:was\s+)?)?(?:generated|created|written|produced)\s+(?:by|with|using)\b.{0,160})/i,
  /^\s*(?:(?:\/\/|#|\/\*+|\*|<!--)\s*)?(?:ai[- ]generated|generated[- ]by[- ]ai)\b.{0,160}/i,
  /^\s*["']?(?:generated_by|generatedBy|ai_generator|aiGenerator|created_by|createdBy)["']?\s*[:=]\s*["']?.{0,160}/i,
];

interface CandidateFile {
  absolute: string;
  relative: string;
  extension: string;
  text: boolean;
  metadata: boolean;
  c2pa: boolean;
}

export interface AiProvenanceOptions {
  maxTextFileBytes?: number;
  maxMetadataFileBytes?: number;
  maxC2paFileBytes?: number;
  maxTotalBytes?: number;
  maxFiles?: number;
  maxEntries?: number;
  maxDepth?: number;
  maxArtifacts?: number;
  maxCommits?: number;
  c2paReader?: C2paReader;
  gitHistoryReader?: GitHistoryReader;
}

interface RequiredOptions {
  maxTextFileBytes: number;
  maxMetadataFileBytes: number;
  maxC2paFileBytes: number;
  maxTotalBytes: number;
  maxFiles: number;
  maxEntries: number;
  maxDepth: number;
  maxArtifacts: number;
  maxCommits: number;
}

export interface CapabilityResult {
  state: "ran" | "partial" | "not_applicable" | "unavailable";
  validators: string[];
  limitations: string[];
}

export interface AiProvenanceResult {
  explicitAttribution: CapabilityResult;
  contentProvenance: CapabilityResult;
  artifacts: RepositoryArtifact[];
}

interface C2paInspection {
  present: boolean;
  embedded?: boolean;
  remoteUrl?: string;
  validationState?: string;
  validationStatusCodes?: string[];
  claimGenerator?: string;
  claimGeneratorInfo?: string[];
  digitalSourceTypes?: string[];
  manifestCount?: number;
  manifestSource?: "embedded" | "external" | "remote";
  sidecarFile?: string;
}

interface C2paAsset {
  path: string;
  buffer: Buffer;
  mimeType: string;
  manifestData?: Buffer;
  sidecarFile?: string;
}

export type C2paReader = (asset: C2paAsset) => Promise<C2paInspection>;

interface GitAttribution {
  commit: string;
  line: string;
}

interface GitHistoryResult {
  applicable: boolean;
  truncated: boolean;
  records: GitAttribution[];
  limitation?: string;
}

export type GitHistoryReader = (target: string, maxCommits: number) => Promise<GitHistoryResult>;

function protectedRecord(path: string): boolean {
  return PROTECTED_FILE_PATTERNS.some((pattern) => pattern.test(path));
}

function clipped(value: unknown): string {
  const rendered = typeof value === "string" ? value : JSON.stringify(value);
  if (!rendered) return "";
  return rendered.length > MAX_EVIDENCE_VALUE ? `${rendered.slice(0, MAX_EVIDENCE_VALUE)}…` : rendered;
}

function matchedDeclaration(value: string): string {
  return AI_SOURCE_TYPE_PATTERN.exec(value)?.[0] ??
    AI_VENDOR_PATTERN.exec(value)?.[0] ??
    /\b(?:ai[- ]generated|generated[- ]by[- ]ai)\b/i.exec(value)?.[0] ??
    "AI attribution";
}

function safeClaimGenerator(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const rendered = clipped(value);
  if (AI_VENDOR_PATTERN.test(rendered)) return matchedDeclaration(rendered);
  return /^(?:[A-Za-z0-9][A-Za-z0-9._+-]*\/[A-Za-z0-9._+-]+)(?: [A-Za-z0-9][A-Za-z0-9._+-]*\/[A-Za-z0-9._+-]+)*$/.test(rendered)
    ? rendered
    : "[untrusted claim-generator value omitted]";
}

function safeRemoteReference(value: string): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    if (parsed.search) parsed.search = "?redacted";
    parsed.hash = "";
    return clipped(parsed.toString());
  } catch {
    return "[unparseable remote reference omitted]";
  }
}

function makeArtifact(input: {
  kind: "explicit_ai_attribution" | "content_provenance";
  markerClass: string;
  file: string;
  field?: string;
  line?: number;
  column?: number;
  summary: string;
  attributes: Array<{ name: string; value: string | number | boolean }>;
  validatorId: string;
  validatorVersion: string;
  method: "deterministic" | "declarative";
  authoritative: boolean;
  state?: RepositoryArtifactState;
  confidence?: RepositoryArtifactConfidence;
  limitations?: string[];
}): RepositoryArtifact {
  const state = input.state ?? "verified";
  const confidence = input.confidence ?? (state === "verified" ? "high" : "low");
  const fp = fingerprint([
    "repository-trust", input.kind, input.markerClass, input.file, input.field ?? "",
    input.line ?? 0, input.column ?? 0, ...input.attributes.map((item) => `${item.name}:${item.value}`),
  ]);
  const isProtected = protectedRecord(input.file) || input.file === ".git" ||
    input.file.startsWith(".git/") || input.kind === "content_provenance";
  return {
    artifact_id: `artifact-${input.kind === "explicit_ai_attribution" ? "ai" : "cp"}-${fp.slice(7, 31)}`,
    fingerprint: fp,
    kind: input.kind,
    state,
    marker_class: input.markerClass,
    location: {
      file: input.file,
      ...(input.line === undefined
        ? { field: input.field ?? "metadata" }
        : {
            start_line: input.line,
            end_line: input.line,
            start_column: input.column ?? 1,
            end_column: input.column ?? 1,
          }),
    },
    evidence: { summary: input.summary, attributes: input.attributes },
    validator: {
      id: input.validatorId,
      version: input.validatorVersion,
      method: input.method,
      authoritative: input.authoritative,
      independently_verifiable: true,
      egress: "none",
    },
    confidence,
    limitations: input.limitations ?? [],
    remediation: {
      eligible: false,
      requires_approval: true,
      reversible: false,
      protected_record: isProtected,
      reason: isProtected
        ? "This provenance or protected attribution record is evidence and is not cleanup-eligible."
        : "V3.2 is read-only. A later approval-gated cleanup workflow must checkpoint, edit, test, and rescan this exact record.",
    },
  };
}

function classify(name: string, direct: boolean): Omit<CandidateFile, "absolute" | "relative"> | undefined {
  const extension = extname(name).slice(1).toLowerCase();
  const text = direct || TEXT_FILENAMES.has(name) || TEXT_EXTENSIONS.has(extension);
  const metadata = METADATA_EXTENSIONS.has(extension);
  const c2pa = C2PA_EXTENSIONS.has(extension);
  return text || metadata || c2pa ? { extension, text, metadata, c2pa } : undefined;
}

async function discoverFiles(target: string, options: RequiredOptions): Promise<{
  files: CandidateFile[];
  limitations: string[];
}> {
  const files: CandidateFile[] = [];
  const limitations = new Set<string>();
  let entries = 0;
  const rootStat = await lstat(target);
  if (rootStat.isSymbolicLink()) {
    return { files, limitations: ["The provenance target was a symbolic link and was not followed."] };
  }
  if (rootStat.isFile()) {
    const kind = classify(basename(target), true);
    if (kind) files.push({ absolute: target, relative: basename(target), ...kind });
    return { files, limitations: [] };
  }
  if (!rootStat.isDirectory()) {
    return { files, limitations: ["The provenance target was not a regular file or directory."] };
  }
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (depth > options.maxDepth) {
      limitations.add(`Provenance discovery exceeded the ${options.maxDepth}-directory depth bound.`);
      return;
    }
    let children;
    try {
      children = await readdir(directory, { withFileTypes: true });
    } catch {
      limitations.add("A repository directory could not be read during provenance discovery.");
      return;
    }
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      entries++;
      if (entries > options.maxEntries) {
        limitations.add(`Provenance discovery exceeded the ${options.maxEntries}-entry bound.`);
        return;
      }
      const absolute = join(directory, child.name);
      const display = relative(target, absolute).split("\\").join("/");
      if (child.isSymbolicLink()) {
        limitations.add("Symbolic links were excluded from provenance inspection.");
        continue;
      }
      if (child.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(child.name)) await walk(absolute, depth + 1);
        continue;
      }
      if (!child.isFile()) continue;
      const kind = classify(child.name, false);
      if (!kind) continue;
      if (files.length >= options.maxFiles) {
        limitations.add(`Provenance discovery exceeded the ${options.maxFiles}-file bound.`);
        return;
      }
      files.push({ absolute, relative: display, ...kind });
    }
  };
  await walk(target, 0);
  files.sort((left, right) => left.relative.localeCompare(right.relative));
  return { files, limitations: [...limitations] };
}

async function safeRead(path: string, maxBytes: number): Promise<{ buffer?: Buffer; bytes: number; limitation?: string }> {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(path, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) return { bytes: 0, limitation: "A discovered provenance path was not a regular file." };
    if (before.size > BigInt(maxBytes)) {
      return { bytes: Number(before.size), limitation: `A provenance file exceeded the ${Math.floor(maxBytes / (1024 * 1024))} MiB parser bound.` };
    }
    const buffer = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || BigInt(buffer.length) !== before.size
    ) {
      return { bytes: buffer.length, limitation: "A provenance file changed while it was being inspected." };
    }
    return { buffer, bytes: buffer.length };
  } catch {
    return { bytes: 0, limitation: "A discovered provenance file could not be opened without following symbolic links." };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function scanTextAttribution(file: CandidateFile, buffer: Buffer): RepositoryArtifact[] {
  if (buffer.includes(0)) return [];
  let content: string;
  try {
    content = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    return [];
  }
  const artifacts: RepositoryArtifact[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    if (!AI_VENDOR_PATTERN.test(line) && !/\b(?:ai[- ]generated|generated[- ]by[- ]ai)\b/i.test(line)) continue;
    if (!ATTRIBUTION_LINE_PATTERNS.some((pattern) => pattern.test(line))) continue;
    const firstNonWhitespace = line.search(/\S/);
    artifacts.push(makeArtifact({
      kind: "explicit_ai_attribution",
      markerClass: "explicit_generator_attribution",
      file: file.relative,
      line: index + 1,
      column: firstNonWhitespace < 0 ? 1 : firstNonWhitespace + 1,
      summary: "An explicit AI-generation attribution statement was deterministically observed.",
      attributes: [
        { name: "matched_declaration", value: matchedDeclaration(line) },
        { name: "source", value: "repository_text" },
      ],
      validatorId: "codeinspectus-explicit-ai-attribution",
      validatorVersion: "1.0.0",
      method: "declarative",
      authoritative: false,
      limitations: ["The statement is observable attribution evidence; CodeInspectus does not prove that the statement is truthful or identify the generating model."],
    }));
  }
  if (file.extension === "xmp") {
    const metadataPattern = /(?:xmp:CreatorTool|photoshop:Credit|dc:creator|Iptc4xmpExt:DigitalSourceType|digitalSourceType)\s*(?:=|>)\s*["']?([^<"']{1,256})/gi;
    for (const match of content.matchAll(metadataPattern)) {
      const value = match[1] ?? "";
      if (!AI_VENDOR_PATTERN.test(value) && !AI_SOURCE_TYPE_PATTERN.test(value)) continue;
      const before = content.slice(0, match.index ?? 0);
      const line = before.split(/\r?\n/).length;
      const column = (before.match(/(?:^|\n)([^\n]*)$/)?.[1]?.length ?? 0) + 1;
      artifacts.push(makeArtifact({
        kind: "explicit_ai_attribution",
        markerClass: AI_SOURCE_TYPE_PATTERN.test(value) ? "declared_ai_source_type" : "explicit_generator_metadata",
        file: file.relative,
        line,
        column,
        summary: AI_SOURCE_TYPE_PATTERN.test(value)
          ? "An XMP sidecar explicitly declares an algorithmic or trained-algorithm source type."
          : "An XMP sidecar explicitly names an AI generator or vendor.",
        attributes: [
          { name: "metadata_field", value: match[0]!.split(/\s/)[0]! },
          { name: "matched_declaration", value: matchedDeclaration(value) },
          { name: "source", value: "xmp_sidecar" },
        ],
        validatorId: "codeinspectus-media-metadata",
        validatorVersion: "1.0.0",
        method: "declarative",
        authoritative: false,
        limitations: ["XMP metadata is declarative and can be added, changed, or removed independently of the referenced media."],
      }));
    }
  }
  return artifacts;
}

function flattenMetadata(value: unknown, path = "", output: Array<{ field: string; value: string }> = []): Array<{ field: string; value: string }> {
  if (output.length >= 2_000 || value === null || value === undefined) return output;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    output.push({ field: path || "metadata", value: clipped(value) });
    return output;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < Math.min(value.length, 64); index++) flattenMetadata(value[index], `${path}[${index}]`, output);
    return output;
  }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 256)) {
      if (["value", "description"].includes(key) || path.split(".").length < 8) {
        flattenMetadata(child, path ? `${path}.${key}` : key, output);
      }
    }
  }
  return output;
}

function scanMediaMetadata(file: CandidateFile, buffer: Buffer): { artifacts: RepositoryArtifact[]; limitation?: string } {
  try {
    const tags = ExifReader.load(buffer, { expanded: true, async: false });
    const artifacts: RepositoryArtifact[] = [];
    const seen = new Set<string>();
    for (const entry of flattenMetadata(tags)) {
      if (!AI_VENDOR_PATTERN.test(entry.value) && !AI_SOURCE_TYPE_PATTERN.test(entry.value)) continue;
      // ExifReader intentionally exposes some container tags through multiple compatibility
      // groups (for example png, pngText, and value/description views). Report one semantic
      // declaration per file/value instead of turning parser aliases into duplicate evidence.
      const key = `${AI_SOURCE_TYPE_PATTERN.test(entry.value) ? "source-type" : "generator"}\u0000${entry.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      artifacts.push(makeArtifact({
        kind: "explicit_ai_attribution",
        markerClass: AI_SOURCE_TYPE_PATTERN.test(entry.value) ? "declared_ai_source_type" : "explicit_generator_metadata",
        file: file.relative,
        field: entry.field,
        summary: AI_SOURCE_TYPE_PATTERN.test(entry.value)
          ? "Media metadata explicitly declares an algorithmic or trained-algorithm source type."
          : "Media metadata explicitly names an AI generator or vendor.",
        attributes: [
          { name: "metadata_field", value: entry.field },
          { name: "matched_declaration", value: matchedDeclaration(entry.value) },
          { name: "source", value: "exif_xmp_iptc" },
        ],
        validatorId: "codeinspectus-media-metadata",
        validatorVersion: "1.0.0",
        method: "declarative",
        authoritative: false,
        limitations: ["Metadata is declarative and can be added, changed, or removed independently of the media content."],
      }));
    }
    return { artifacts };
  } catch (error) {
    if (error instanceof ExifReader.errors.MetadataMissingError) return { artifacts: [] };
    return { artifacts: [], limitation: `${file.relative}: EXIF/XMP metadata could not be parsed.` };
  }
}

function collectDigitalSourceTypes(value: unknown, output = new Set<string>(), depth = 0): Set<string> {
  if (depth > 10 || output.size >= 32 || value === null || value === undefined) return output;
  if (typeof value === "string") {
    if (AI_SOURCE_TYPE_PATTERN.test(value)) output.add(clipped(value));
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 128)) collectDigitalSourceTypes(item, output, depth + 1);
    return output;
  }
  if (typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>).slice(0, 256)) {
      collectDigitalSourceTypes(child, output, depth + 1);
    }
  }
  return output;
}

function c2paMimeType(extension: string): string {
  return ({
    avif: "image/avif", avi: "video/x-msvideo", c2pa: "application/c2pa", gif: "image/gif",
    heic: "image/heic", heif: "image/heif", jpeg: "image/jpeg", jpg: "image/jpeg",
    jxl: "image/jxl", m4a: "audio/mp4", m4v: "video/mp4", mov: "video/quicktime",
    mp3: "audio/mpeg", mp4: "video/mp4", pdf: "application/pdf", png: "image/png",
    svg: "image/svg+xml", tif: "image/tiff", tiff: "image/tiff", wav: "audio/wav",
    webp: "image/webp",
  } as Record<string, string>)[extension] ?? "application/octet-stream";
}

export const defaultC2paReader: C2paReader = async (asset) => {
  const { Reader } = await import("@contentauth/c2pa-node");
  // Pass already-opened, bounded bytes rather than a path so a target cannot be replaced with a
  // symlink between discovery and the native validator opening it.
  const settings = {
    verify: {
      verify_after_reading: true,
      verify_trust: false,
      verify_timestamp_trust: false,
      ocsp_fetch: false,
      remote_manifest_fetch: false,
    },
  };
  const reader = asset.manifestData
    ? await Reader.fromManifestDataAndAsset(asset.manifestData, { buffer: asset.buffer, mimeType: asset.mimeType }, settings)
    : await Reader.fromAsset({ buffer: asset.buffer, mimeType: asset.mimeType }, settings);
  if (!reader) return { present: false };
  const store = reader.json();
  const active = reader.getActive();
  return {
    present: Boolean(active || store.active_manifest),
    embedded: reader.isEmbedded(),
    remoteUrl: safeRemoteReference(reader.remoteUrl()),
    validationState: clipped(store.validation_state) || undefined,
    validationStatusCodes: (store.validation_status ?? []).slice(0, 64).map((status) => clipped(status.code)),
    claimGenerator: safeClaimGenerator(active?.claim_generator ?? undefined),
    claimGeneratorInfo: (active?.claim_generator_info ?? []).slice(0, 32)
      .map((item) => safeClaimGenerator(item.name))
      .filter((item): item is string => Boolean(item)),
    digitalSourceTypes: [...collectDigitalSourceTypes(active?.assertions)],
    manifestCount: Object.keys(store.manifests ?? {}).length,
    manifestSource: asset.manifestData ? "external" : reader.isEmbedded() ? "embedded" : reader.remoteUrl() ? "remote" : undefined,
    sidecarFile: asset.sidecarFile,
  };
};

function c2paArtifact(file: CandidateFile, inspection: C2paInspection): RepositoryArtifact | undefined {
  const remoteReference = inspection.remoteUrl ? safeRemoteReference(inspection.remoteUrl) : undefined;
  const claimGenerator = safeClaimGenerator(inspection.claimGenerator);
  const claimGeneratorInfo = (inspection.claimGeneratorInfo ?? [])
    .map((item) => safeClaimGenerator(item))
    .filter((item): item is string => Boolean(item));
  if (!inspection.present && !remoteReference) return undefined;
  const validationState = inspection.validationState?.toLowerCase();
  const present = inspection.present;
  const state: RepositoryArtifactState = present && ["valid", "trusted"].includes(validationState ?? "")
    ? "verified"
    : validationState === "invalid"
      ? "verified"
      : "informational";
  const markerClass = !present && remoteReference
    ? "c2pa_remote_reference"
    : validationState === "invalid"
      ? "c2pa_invalid_manifest"
      : ["valid", "trusted"].includes(validationState ?? "")
        ? "c2pa_validated_manifest"
        : "c2pa_manifest_present";
  const statusCodes = inspection.validationStatusCodes ?? [];
  const limitations = [
    "C2PA validation does not by itself prove that media was AI-generated; inspect the signed assertions and declared digital source types.",
    ...(validationState === "valid"
      ? ["The manifest was structurally and cryptographically valid, but signer trust was not established by the offline validator."]
      : []),
    ...(!present && remoteReference
      ? ["A remote manifest reference was observed but was not fetched because scan-time network egress is disabled."]
      : []),
  ];
  return makeArtifact({
    kind: "content_provenance",
    markerClass,
    file: file.relative,
    field: "c2pa.manifest_store",
    summary: markerClass === "c2pa_invalid_manifest"
      ? "A C2PA manifest was present and the official validator reported an invalid validation state."
      : markerClass === "c2pa_validated_manifest"
        ? `A C2PA manifest was present and the official validator reported ${validationState} validation.`
        : markerClass === "c2pa_remote_reference"
          ? "A remote C2PA manifest reference was observed but not fetched."
          : "A C2PA manifest was present, but a conclusive validation state was not available.",
    attributes: [
      { name: "embedded", value: inspection.embedded ?? false },
      { name: "validation_state", value: inspection.validationState ?? "not_reported" },
      { name: "manifest_count", value: inspection.manifestCount ?? 0 },
      ...(inspection.manifestSource ? [{ name: "manifest_source", value: inspection.manifestSource }] : []),
      ...(inspection.sidecarFile ? [{ name: "sidecar_file", value: inspection.sidecarFile }] : []),
      ...(remoteReference ? [{ name: "remote_reference", value: remoteReference }] : []),
      ...(claimGenerator ? [{ name: "claim_generator", value: claimGenerator }] : []),
      ...(claimGeneratorInfo.length ? [{ name: "claim_generator_info", value: claimGeneratorInfo.join(", ") }] : []),
      ...(inspection.digitalSourceTypes?.length ? [{ name: "digital_source_types", value: inspection.digitalSourceTypes.join(", ") }] : []),
      ...(statusCodes.length ? [{ name: "validation_status_codes", value: statusCodes.join(", ") }] : []),
    ],
    validatorId: "contentauth-c2pa-node",
    validatorVersion: "0.9.3",
    method: "deterministic",
    authoritative: true,
    state,
    confidence: state === "verified" ? "high" : "low",
    limitations,
  });
}

export const defaultGitHistoryReader: GitHistoryReader = async (target, maxCommits) => {
  const cwd = (await lstat(target)).isDirectory() ? target : dirname(target);
  try {
    const root = (await execFileAsync("git", ["-C", cwd, "rev-parse", "--show-toplevel"], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    })).stdout.trim();
    const output = (await execFileAsync(
      "git",
      ["-C", root, "log", `--max-count=${maxCommits + 1}`, "--format=%H%x00%B%x00", "-z"],
      { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
    )).stdout;
    const fields = output.split("\u0000").filter((field) => field.length > 0);
    const records: GitAttribution[] = [];
    let commits = 0;
    for (let index = 0; index + 1 < fields.length; index += 2) {
      const commit = fields[index]!.trim();
      const body = fields[index + 1]!;
      commits++;
      if (commits > maxCommits) break;
      for (const line of body.split(/\r?\n/)) {
        if (/^Co-Authored-By:/i.test(line) && AI_VENDOR_PATTERN.test(line)) records.push({ commit, line: line.trim() });
      }
    }
    return { applicable: true, truncated: commits > maxCommits, records };
  } catch {
    return { applicable: false, truncated: false, records: [] };
  }
};

function gitArtifacts(records: GitAttribution[]): RepositoryArtifact[] {
  return records.map((record) => makeArtifact({
    kind: "explicit_ai_attribution",
    markerClass: "ai_coauthor_commit_trailer",
    file: ".git",
    field: `commit:${record.commit.slice(0, 12)}:Co-Authored-By`,
    summary: "A git commit contains an explicit AI co-author trailer.",
    attributes: [
      { name: "commit", value: record.commit },
      { name: "matched_identity", value: matchedDeclaration(record.line) },
      { name: "source", value: "git_commit_message" },
    ],
    validatorId: "codeinspectus-explicit-ai-attribution",
    validatorVersion: "1.0.0",
    method: "declarative",
    authoritative: false,
    limitations: ["A commit trailer is declarative attribution and does not prove model authorship or the extent of AI assistance."],
  }));
}

export async function scanAiProvenance(
  target: string,
  inputOptions: AiProvenanceOptions = {},
): Promise<AiProvenanceResult> {
  const options: RequiredOptions = {
    maxTextFileBytes: inputOptions.maxTextFileBytes ?? DEFAULT_MAX_TEXT_FILE_BYTES,
    maxMetadataFileBytes: inputOptions.maxMetadataFileBytes ?? DEFAULT_MAX_METADATA_FILE_BYTES,
    maxC2paFileBytes: inputOptions.maxC2paFileBytes ?? DEFAULT_MAX_C2PA_FILE_BYTES,
    maxTotalBytes: inputOptions.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    maxFiles: inputOptions.maxFiles ?? DEFAULT_MAX_FILES,
    maxEntries: inputOptions.maxEntries ?? DEFAULT_MAX_ENTRIES,
    maxDepth: inputOptions.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxArtifacts: inputOptions.maxArtifacts ?? DEFAULT_MAX_ARTIFACTS,
    maxCommits: inputOptions.maxCommits ?? DEFAULT_MAX_COMMITS,
  };
  const c2paReader = inputOptions.c2paReader ?? defaultC2paReader;
  const gitHistoryReader = inputOptions.gitHistoryReader ?? defaultGitHistoryReader;
  const discovery = await discoverFiles(target, options);
  const c2paAssetsByStem = new Map<string, CandidateFile[]>();
  for (const file of discovery.files) {
    if (!file.c2pa || file.extension === "c2pa") continue;
    const stem = file.relative.slice(0, -(file.extension.length + 1));
    const candidates = c2paAssetsByStem.get(stem) ?? [];
    candidates.push(file);
    c2paAssetsByStem.set(stem, candidates);
  }
  const explicitLimitations = new Set(discovery.limitations);
  const contentLimitations = new Set(discovery.limitations);
  const artifacts = new Map<string, RepositoryArtifact>();
  let totalBytes = 0;
  let textInspected = 0;
  let metadataInspected = 0;
  let c2paInspected = 0;
  let artifactBoundReached = false;

  const add = (artifact: RepositoryArtifact): void => {
    if (artifacts.has(artifact.fingerprint)) return;
    if (artifacts.size >= options.maxArtifacts) {
      artifactBoundReached = true;
      return;
    }
    artifacts.set(artifact.fingerprint, artifact);
  };

  for (const file of discovery.files) {
    if (totalBytes >= options.maxTotalBytes) {
      explicitLimitations.add(`Provenance inspection exceeded the ${Math.floor(options.maxTotalBytes / (1024 * 1024))} MiB aggregate byte bound.`);
      contentLimitations.add(`Provenance inspection exceeded the ${Math.floor(options.maxTotalBytes / (1024 * 1024))} MiB aggregate byte bound.`);
      break;
    }
    let loaded: { buffer?: Buffer; bytes: number; limitation?: string } | undefined;
    if (file.text || file.metadata) {
      loaded = await safeRead(file.absolute, Math.max(
        file.text ? options.maxTextFileBytes : 0,
        file.metadata ? options.maxMetadataFileBytes : 0,
      ));
      totalBytes += loaded.buffer ? loaded.bytes : 0;
    }
    if (file.text) {
      if (loaded?.limitation) explicitLimitations.add(`${file.relative}: ${loaded.limitation}`);
      if (loaded?.buffer) {
        textInspected++;
        if (file.extension === "xmp") metadataInspected++;
        for (const artifact of scanTextAttribution(file, loaded.buffer)) add(artifact);
      }
    }
    if (file.metadata) {
      if (loaded?.limitation) explicitLimitations.add(`${file.relative}: ${loaded.limitation}`);
      if (loaded?.buffer) {
        metadataInspected++;
        const result = scanMediaMetadata(file, loaded.buffer);
        if (result.limitation) explicitLimitations.add(result.limitation);
        for (const artifact of result.artifacts) add(artifact);
      }
    }
    if (file.c2pa) {
      const c2paLoaded = loaded?.buffer
        ? loaded
        : await safeRead(file.absolute, options.maxC2paFileBytes);
      if (c2paLoaded.limitation) {
        contentLimitations.add(`${file.relative}: ${c2paLoaded.limitation}`);
        continue;
      }
      if (!c2paLoaded.buffer) continue;
      const additionalBytes = loaded?.buffer === c2paLoaded.buffer ? 0 : c2paLoaded.bytes;
      if (totalBytes + additionalBytes > options.maxTotalBytes) {
        contentLimitations.add(`C2PA inspection exceeded the ${Math.floor(options.maxTotalBytes / (1024 * 1024))} MiB aggregate byte bound.`);
        break;
      }
      totalBytes += additionalBytes;
      let inspectedFile = file;
      let inspectedBuffer = c2paLoaded.buffer;
      let manifestData: Buffer | undefined;
      let sidecarFile: string | undefined;
      if (file.extension === "c2pa") {
        const stem = file.relative.slice(0, -".c2pa".length);
        const paired = c2paAssetsByStem.get(stem)?.[0];
        if (!paired) {
          contentLimitations.add(`${file.relative}: an external C2PA manifest was found without a same-stem supported asset, so asset binding was not validated.`);
          continue;
        }
        const pairedLoaded = await safeRead(paired.absolute, options.maxC2paFileBytes);
        if (pairedLoaded.limitation || !pairedLoaded.buffer) {
          contentLimitations.add(`${paired.relative}: ${pairedLoaded.limitation ?? "the paired C2PA asset could not be read."}`);
          continue;
        }
        if (totalBytes + pairedLoaded.bytes > options.maxTotalBytes) {
          contentLimitations.add(`C2PA inspection exceeded the ${Math.floor(options.maxTotalBytes / (1024 * 1024))} MiB aggregate byte bound.`);
          break;
        }
        totalBytes += pairedLoaded.bytes;
        inspectedFile = paired;
        inspectedBuffer = pairedLoaded.buffer;
        manifestData = c2paLoaded.buffer;
        sidecarFile = file.relative;
      }
      c2paInspected++;
      try {
        const artifact = c2paArtifact(inspectedFile, await c2paReader({
          path: inspectedFile.absolute,
          buffer: inspectedBuffer,
          mimeType: c2paMimeType(inspectedFile.extension),
          ...(manifestData ? { manifestData, sidecarFile } : {}),
        }));
        if (artifact) add(artifact);
      } catch (error) {
        const message = error instanceof Error ? clipped(error.message) : "unknown validator error";
        contentLimitations.add(`${file.relative}: official C2PA validation could not complete (${message}).`);
      }
    }
    if (artifactBoundReached) break;
  }

  const history = await gitHistoryReader(target, options.maxCommits);
  for (const artifact of gitArtifacts(history.records)) add(artifact);
  if (history.truncated) explicitLimitations.add(`Git attribution inspection was bounded to the newest ${options.maxCommits} commits.`);
  if (history.limitation) explicitLimitations.add(history.limitation);
  if (artifactBoundReached) {
    const limitation = `AI-provenance candidate/output processing exceeded the ${options.maxArtifacts}-artifact bound and was truncated.`;
    explicitLimitations.add(limitation);
    contentLimitations.add(limitation);
  }

  const explicitApplicable = textInspected > 0 || metadataInspected > 0 || history.applicable;
  const contentApplicable = c2paInspected > 0;
  const explicitState = !explicitApplicable && explicitLimitations.size === 0
    ? "not_applicable" as const
    : explicitLimitations.size > 0 ? "partial" as const : "ran" as const;
  const contentState = !contentApplicable && contentLimitations.size === 0
    ? "not_applicable" as const
    : contentLimitations.size > 0 ? "partial" as const : "ran" as const;
  const artifactList = [...artifacts.values()].sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    (left.location.start_line ?? 0) - (right.location.start_line ?? 0) ||
    (left.location.field ?? "").localeCompare(right.location.field ?? "") ||
    left.marker_class.localeCompare(right.marker_class)
  );
  return {
    explicitAttribution: {
      state: explicitState,
      validators: explicitApplicable
        ? [EXPLICIT_AI_ATTRIBUTION_VALIDATOR, ...(metadataInspected ? [MEDIA_METADATA_VALIDATOR] : [])]
        : [],
      limitations: [
        ...explicitLimitations,
        "Explicit statements and metadata are declarative evidence, not statistical proof of AI authorship or vendor origin.",
      ],
    },
    contentProvenance: {
      state: contentState,
      validators: contentApplicable ? [C2PA_VALIDATOR] : [],
      limitations: [
        ...contentLimitations,
        "Remote C2PA manifests and revocation endpoints are never fetched during a scan; offline validation cannot establish online trust or revocation status.",
        "C2PA absence is not proof that an asset is human-created, and C2PA presence is not automatically proof of AI generation.",
      ],
    },
    artifacts: artifactList,
  };
}
