import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { basename, dirname, extname, join, relative } from "node:path";
import { fingerprint } from "../util/hash.js";
import {
  repositoryTrustDocumentSchema,
  type RepositoryArtifact,
  type RepositoryArtifactConfidence,
  type RepositoryArtifactState,
  type RepositoryTrustDocument,
} from "./schemas.js";

export const SOURCE_INTEGRITY_VALIDATOR = "codeinspectus-source-integrity@1.0.0" as const;
const SOURCE_INTEGRITY_VALIDATOR_ID = "codeinspectus-source-integrity";
const SOURCE_INTEGRITY_VALIDATOR_VERSION = "1.0.0";

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_ENTRIES = 50_000;
const DEFAULT_MAX_DEPTH = 64;
const DEFAULT_MAX_ARTIFACTS = 1_000;
const MAX_SEQUENCE_EVIDENCE_CODE_POINTS = 64;
const MAX_IDENTIFIER_EVIDENCE_CODE_POINTS = 128;

const IGNORED_DIRECTORIES = new Set([
  ".git", ".cache", ".dart_tool", ".gradle", ".idea", ".next", ".nuxt", ".pnpm-store",
  ".terraform", ".turbo", ".venv", ".vercel", ".vscode", "Pods", "__pycache__", "build",
  "coverage", "dist", "generated", "node_modules", "out", "target", "vendor", "venv",
]);

const SUPPORTED_EXTENSIONS = new Set([
  "adoc", "astro", "bash", "c", "cc", "cfg", "clj", "cljs", "conf", "cpp", "cs", "css",
  "dart", "env", "ex", "exs", "fish", "go", "graphql", "gql", "h", "hpp", "html", "ini",
  "java", "js", "json", "jsx", "kt", "kts", "less", "lua", "md", "mdx", "mjs", "mts",
  "php", "plist", "properties", "proto", "py", "rb", "rs", "rst", "scala", "scss", "sh",
  "sol", "sql", "svelte", "swift", "tf", "toml", "ts", "tsx", "txt", "vue", "xml", "yaml",
  "yml", "zig", "zsh",
]);

const PROSE_EXTENSIONS = new Set(["adoc", "md", "mdx", "rst", "txt"]);
const IDENTIFIER_EXTENSIONS = new Set([
  "c", "cc", "clj", "cljs", "cpp", "cs", "dart", "ex", "exs", "go", "h", "hpp", "java",
  "js", "jsx", "kt", "kts", "lua", "mjs", "mts", "php", "py", "rb", "rs", "scala", "sol",
  "swift", "ts", "tsx", "zig",
]);
const SUPPORTED_FILENAMES = new Set([
  ".babelrc", ".dockerignore", ".editorconfig", ".env", ".eslintignore", ".eslintrc",
  ".gitattributes", ".gitignore", ".npmrc", ".prettierignore", ".prettierrc", "Brewfile",
  "CMakeLists.txt", "Containerfile", "Dockerfile", "Gemfile", "Guardfile", "Jenkinsfile",
  "LICENSE", "Makefile", "NOTICE", "Podfile", "Procfile", "Rakefile", "Vagrantfile",
]);

const PROTECTED_FILE_PATTERNS = [
  /(?:^|\/)(?:license|notice|copying)(?:\.[^/]*)?$/i,
  /(?:^|\/)(?:legal|compliance)(?:\/|$)/i,
  /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|gemfile\.lock|podfile\.lock)$/i,
  /(?:^|\/)third-party-notices(?:\.[^/]*)?$/i,
];

const UNICODE_NAMES = new Map<number, string>([
  [0x00ad, "SOFT HYPHEN"], [0x034f, "COMBINING GRAPHEME JOINER"], [0x061c, "ARABIC LETTER MARK"],
  [0x180e, "MONGOLIAN VOWEL SEPARATOR"], [0x200b, "ZERO WIDTH SPACE"],
  [0x200c, "ZERO WIDTH NON-JOINER"], [0x200d, "ZERO WIDTH JOINER"],
  [0x200e, "LEFT-TO-RIGHT MARK"], [0x200f, "RIGHT-TO-LEFT MARK"],
  [0x202a, "LEFT-TO-RIGHT EMBEDDING"], [0x202b, "RIGHT-TO-LEFT EMBEDDING"],
  [0x202c, "POP DIRECTIONAL FORMATTING"], [0x202d, "LEFT-TO-RIGHT OVERRIDE"],
  [0x202e, "RIGHT-TO-LEFT OVERRIDE"], [0x2060, "WORD JOINER"],
  [0x2061, "FUNCTION APPLICATION"], [0x2062, "INVISIBLE TIMES"],
  [0x2063, "INVISIBLE SEPARATOR"], [0x2064, "INVISIBLE PLUS"],
  [0x2066, "LEFT-TO-RIGHT ISOLATE"], [0x2067, "RIGHT-TO-LEFT ISOLATE"],
  [0x2068, "FIRST STRONG ISOLATE"], [0x2069, "POP DIRECTIONAL ISOLATE"],
  [0xfeff, "ZERO WIDTH NO-BREAK SPACE"],
]);

const BIDI_OPENERS = new Map<number, { family: "embedding" | "isolate"; override: boolean }>([
  [0x202a, { family: "embedding", override: false }],
  [0x202b, { family: "embedding", override: false }],
  [0x202d, { family: "embedding", override: true }],
  [0x202e, { family: "embedding", override: true }],
  [0x2066, { family: "isolate", override: false }],
  [0x2067, { family: "isolate", override: false }],
  [0x2068, { family: "isolate", override: false }],
]);

const BIDI_CLOSERS = new Map<number, "embedding" | "isolate">([
  [0x202c, "embedding"],
  [0x2069, "isolate"],
]);

const DIRECTIONAL_MARKS = new Set([0x061c, 0x200e, 0x200f]);
const DEFAULT_IGNORABLES = new Set([
  0x00ad, 0x034f, 0x180e, 0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063,
  0x2064, 0xfeff,
]);

const CONFUSABLE_TO_ASCII = new Map<number, string>([
  [0x0391, "A"], [0x0392, "B"], [0x0395, "E"], [0x0396, "Z"], [0x0397, "H"], [0x0399, "I"],
  [0x039a, "K"], [0x039c, "M"], [0x039d, "N"], [0x039f, "O"], [0x03a1, "P"], [0x03a4, "T"],
  [0x03a5, "Y"], [0x03a7, "X"], [0x03b1, "a"], [0x03b5, "e"], [0x03b9, "i"], [0x03ba, "k"],
  [0x03bd, "v"], [0x03bf, "o"], [0x03c1, "p"], [0x03c4, "t"], [0x03c5, "u"], [0x03c7, "x"],
  [0x0405, "S"], [0x0406, "I"], [0x0408, "J"], [0x0410, "A"], [0x0412, "B"], [0x0415, "E"],
  [0x041a, "K"], [0x041c, "M"], [0x041d, "H"], [0x041e, "O"], [0x0420, "P"], [0x0421, "C"],
  [0x0422, "T"], [0x0425, "X"], [0x0430, "a"], [0x0435, "e"], [0x043e, "o"], [0x0440, "p"],
  [0x0441, "c"], [0x0443, "y"], [0x0445, "x"], [0x0455, "s"], [0x0456, "i"], [0x0458, "j"],
]);

interface CandidateFile {
  absolute: string;
  relative: string;
  extension: string;
  prose: boolean;
}

interface SourceIntegrityOptions {
  maxFileBytes?: number;
  maxTotalBytes?: number;
  maxFiles?: number;
  maxEntries?: number;
  maxDepth?: number;
  maxArtifacts?: number;
}

interface MarkerInput {
  file: CandidateFile;
  content: string;
  index: number;
  marker: string;
  markerClass: string;
  state: RepositoryArtifactState;
  confidence: RepositoryArtifactConfidence;
  contextClass: string;
  proposedAction: string;
  limitation?: string;
  sequenceLength?: number;
  locationLength?: number;
  evidenceTruncated?: boolean;
}

interface Position {
  line: number;
  column: number;
  endColumn: number;
  utf8ByteOffset: number;
}

function isSupported(name: string, direct: boolean): boolean {
  if (direct) return true;
  if (SUPPORTED_FILENAMES.has(name) || name.startsWith(".env.")) return true;
  return SUPPORTED_EXTENSIONS.has(extname(name).slice(1).toLowerCase());
}

function createPositionLookup(content: string): (index: number, locationLength: number) => Position {
  const lines = new Uint32Array(content.length + 1);
  const columns = new Uint32Array(content.length + 1);
  const byteOffsets = new Uint32Array(content.length + 1);
  let line = 1;
  let column = 1;
  let byteOffset = 0;
  for (let index = 0; index < content.length;) {
    const character = String.fromCodePoint(content.codePointAt(index)!);
    for (let unit = 0; unit < character.length; unit++) {
      lines[index + unit] = line;
      columns[index + unit] = column;
      byteOffsets[index + unit] = byteOffset;
    }
    byteOffset += Buffer.byteLength(character, "utf8");
    if (character === "\n") {
      line++;
      column = 1;
    } else {
      column++;
    }
    index += character.length;
  }
  lines[content.length] = line;
  columns[content.length] = column;
  byteOffsets[content.length] = byteOffset;
  return (index, locationLength) => ({
    line: lines[index]!,
    column: columns[index]!,
    endColumn: columns[index]! + Math.max(1, locationLength) - 1,
    utf8ByteOffset: byteOffsets[index]!,
  });
}

function codePoints(value: string): number[] {
  return [...value].map((character) => character.codePointAt(0)!);
}

function codePointLabel(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(codePoint <= 0xffff ? 4 : 6, "0")}`;
}

function unicodeName(codePoint: number): string {
  if (codePoint >= 0xe0000 && codePoint <= 0xe007f) return codePoint === 0xe007f ? "CANCEL TAG" : "TAG CHARACTER";
  if (codePoint >= 0xfe00 && codePoint <= 0xfe0f) return `VARIATION SELECTOR-${codePoint - 0xfdff}`;
  if (codePoint >= 0xe0100 && codePoint <= 0xe01ef) return `VARIATION SELECTOR-${codePoint - 0xe00ef}`;
  return UNICODE_NAMES.get(codePoint) ?? "REVIEWED CONFUSABLE CHARACTER";
}

function escaped(value: string): string {
  return codePoints(value).map((codePoint) => `\\u{${codePoint.toString(16).toUpperCase()}}`).join("");
}

function strongRtlLines(content: string): Set<number> {
  const lines = new Set<number>();
  let line = 1;
  for (let index = 0; index < content.length;) {
    const point = content.codePointAt(index)!;
    if (
      (point >= 0x0590 && point <= 0x08ff) ||
      (point >= 0xfb1d && point <= 0xfdfd) ||
      (point >= 0xfe70 && point <= 0xfefc)
    ) lines.add(line);
    if (point === 0x0a) line++;
    index += String.fromCodePoint(point).length;
  }
  return lines;
}

function isAsciiIdentifier(character: string | undefined): boolean {
  return character !== undefined && /[A-Za-z0-9_$]/.test(character);
}

function previousCharacter(content: string, index: number): string | undefined {
  if (index <= 0) return undefined;
  const point = content.codePointAt(index - 1)!;
  if (point >= 0xdc00 && point <= 0xdfff && index >= 2) return String.fromCodePoint(content.codePointAt(index - 2)!);
  return String.fromCodePoint(point);
}

function nextCharacter(content: string, index: number, marker: string): string | undefined {
  const next = index + marker.length;
  return next < content.length ? String.fromCodePoint(content.codePointAt(next)!) : undefined;
}

function isEmoji(character: string | undefined): boolean {
  return character !== undefined && /\p{Extended_Pictographic}/u.test(character);
}

function isNonAsciiLetterOrMark(character: string | undefined): boolean {
  return character !== undefined && character.codePointAt(0)! > 0x7f && /[\p{L}\p{M}]/u.test(character);
}

function isVariationSelector(codePoint: number): boolean {
  return (codePoint >= 0xfe00 && codePoint <= 0xfe0f) || (codePoint >= 0xe0100 && codePoint <= 0xe01ef);
}

function isTag(codePoint: number): boolean {
  return codePoint >= 0xe0000 && codePoint <= 0xe007f;
}

function validEmojiTagSequence(content: string, index: number, end: number, length: number): boolean {
  const previous = previousCharacter(content, index);
  if (previous?.codePointAt(0) !== 0x1f3f4 || length < 2 || previousCharacter(content, end)?.codePointAt(0) !== 0xe007f) {
    return false;
  }
  for (let cursor = index; cursor < end;) {
    const point = content.codePointAt(cursor)!;
    const character = String.fromCodePoint(point);
    cursor += character.length;
    if (cursor === end) return point === 0xe007f;
    if (!((point >= 0xe0030 && point <= 0xe0039) || (point >= 0xe0061 && point <= 0xe007a))) return false;
  }
  return false;
}

function protectedRecord(path: string): boolean {
  return PROTECTED_FILE_PATTERNS.some((pattern) => pattern.test(path));
}

function artifactFrom(
  input: MarkerInput,
  locate: (index: number, locationLength: number) => Position,
): RepositoryArtifact {
  const points = codePoints(input.marker);
  const sequenceLength = input.sequenceLength ?? points.length;
  const position = locate(input.index, input.locationLength ?? sequenceLength);
  const sequenceSuffix = input.evidenceTruncated ? `, … (${sequenceLength} code points total)` : "";
  const fp = fingerprint([
    "repository-trust", "source_integrity", input.markerClass, input.file.relative,
    position.line, position.column, sequenceLength, points.map(codePointLabel).join(","),
  ]);
  const isProtected = protectedRecord(input.file.relative);
  const eligible = input.state === "verified" && !isProtected;
  const names = points.map(unicodeName);
  return {
    artifact_id: `artifact-si-${fp.slice("sha256:".length, "sha256:".length + 24)}`,
    fingerprint: fp,
    kind: "source_integrity",
    state: input.state,
    marker_class: input.markerClass,
    location: {
      file: input.file.relative,
      start_line: position.line,
      end_line: position.line,
      start_column: position.column,
      end_column: position.endColumn,
    },
    evidence: {
      summary: `${names.join(", ")} was deterministically observed in ${input.contextClass} context.`,
      attributes: [
        { name: "code_points", value: `${points.map(codePointLabel).join(",")}${sequenceSuffix}` },
        { name: "unicode_names", value: `${names.join(",")}${sequenceSuffix}` },
        { name: "escaped_sequence", value: `${escaped(input.marker)}${sequenceSuffix}` },
        { name: "sequence_length", value: sequenceLength },
        ...(input.evidenceTruncated ? [{ name: "evidence_truncated", value: true as const }] : []),
        { name: "utf8_byte_offset", value: position.utf8ByteOffset },
        { name: "code_point_column", value: position.column },
        { name: "context_class", value: input.contextClass },
        { name: "proposed_action", value: input.proposedAction },
      ],
    },
    validator: {
      id: SOURCE_INTEGRITY_VALIDATOR_ID,
      version: SOURCE_INTEGRITY_VALIDATOR_VERSION,
      method: "deterministic",
      authoritative: true,
      independently_verifiable: true,
      egress: "none",
    },
    confidence: input.confidence,
    limitations: [
      ...(input.limitation ? [input.limitation] : []),
      ...(input.evidenceTruncated
        ? [`Sequence evidence is capped at ${MAX_SEQUENCE_EVIDENCE_CODE_POINTS} code points; sequence_length and the location span describe the full run.`]
        : []),
      ...(isProtected ? ["This path is a protected legal, compliance, or generated lock record and is not cleanup-eligible."] : []),
    ],
    remediation: {
      eligible,
      requires_approval: true,
      reversible: true,
      protected_record: isProtected,
      reason: eligible
        ? `After explicit approval for ${input.file.relative} and ${points.map(codePointLabel).join(", ")}, apply the smallest reversible edit and rescan.`
        : isProtected
          ? "Do not edit this protected record automatically; review its origin or regenerate it through the owning tool."
          : "The observed character is ambiguous or context-sensitive, so V3.1 provides evidence but no destructive cleanup recommendation.",
    },
  };
}

function scanBidi(file: CandidateFile, content: string, maxMarkers: number, onBound: () => void): MarkerInput[] {
  const markers: MarkerInput[] = [];
  const rtlLines = strongRtlLines(content);
  const stack: Array<{ codePoint: number; index: number; line: number; marker: string; family: "embedding" | "isolate"; override: boolean }> = [];
  let line = 1;
  const add = (marker: MarkerInput): boolean => {
    if (markers.length >= maxMarkers) {
      onBound();
      return false;
    }
    markers.push(marker);
    return true;
  };
  for (let index = 0; index < content.length;) {
    const codePoint = content.codePointAt(index)!;
    const marker = String.fromCodePoint(codePoint);
    const opener = BIDI_OPENERS.get(codePoint);
    if (opener) {
      if (stack.length >= maxMarkers) {
        onBound();
        return markers;
      }
      const entry = { codePoint, index, line, marker, ...opener };
      stack.push(entry);
      if (opener.override) {
        if (!add({
          file, content, index, marker, markerClass: "unicode_bidi_override", state: "verified", confidence: "high",
          contextClass: "bidirectional_override",
          proposedAction: "Remove the exact override only after reviewing the intended token/comment order and approving this file.",
        })) return markers;
      }
    } else {
      const closerFamily = BIDI_CLOSERS.get(codePoint);
      if (closerFamily) {
        const top = stack.at(-1);
        if (!top || top.family !== closerFamily) {
          if (!add({
            file, content, index, marker, markerClass: "unicode_bidi_unbalanced", state: "verified", confidence: "high",
            contextClass: "unpaired_bidirectional_closer",
            proposedAction: "Remove or correctly pair the exact directional closer after file-scoped approval.",
          })) return markers;
        } else {
          stack.pop();
          if (!top.override && !rtlLines.has(top.line)) {
            if (!add({
              file, content, index: top.index, marker: top.marker, markerClass: "unicode_bidi_control",
              state: "informational", confidence: "low", contextClass: "paired_directional_control_without_rtl_text",
              proposedAction: "Review the paired directional control; no cleanup is recommended without confirming the intended display order.",
              limitation: "Balanced directional controls can be legitimate and do not prove deceptive intent.",
            })) return markers;
          }
        }
      } else if (DIRECTIONAL_MARKS.has(codePoint) && !rtlLines.has(line)) {
        if (!add({
          file, content, index, marker, markerClass: "unicode_directional_mark", state: "informational", confidence: "low",
          contextClass: "directional_mark_without_rtl_text",
          proposedAction: "Review the exact mark in display context; V3.1 does not recommend removal automatically.",
          limitation: "Directional marks may be required for legitimate international text.",
        })) return markers;
      }
    }
    if (codePoint === 0x0a) line++;
    index += marker.length;
  }
  for (const entry of stack) {
    if (entry.override) continue;
    if (!add({
      file, content, index: entry.index, marker: entry.marker, markerClass: "unicode_bidi_unbalanced",
      state: "verified", confidence: "high", contextClass: "unterminated_bidirectional_control",
      proposedAction: "Remove or correctly close the exact directional control after file-scoped approval.",
    })) return markers;
  }
  return markers;
}

function scanInvisibleSequences(file: CandidateFile, content: string, maxMarkers: number, onBound: () => void): MarkerInput[] {
  const markers: MarkerInput[] = [];
  const add = (marker: MarkerInput): boolean => {
    if (markers.length >= maxMarkers) {
      onBound();
      return false;
    }
    markers.push(marker);
    return true;
  };
  for (let index = 0; index < content.length;) {
    const codePoint = content.codePointAt(index)!;
    const marker = String.fromCodePoint(codePoint);

    if (isTag(codePoint)) {
      let end = index + marker.length;
      let length = 1;
      let previewEnd = end;
      while (end < content.length && isTag(content.codePointAt(end)!)) {
        const character = String.fromCodePoint(content.codePointAt(end)!);
        end += character.length;
        length++;
        if (length <= MAX_SEQUENCE_EVIDENCE_CODE_POINTS) previewEnd = end;
      }
      if (!validEmojiTagSequence(content, index, end, length)) {
        if (!add({
          file, content, index, marker: content.slice(index, previewEnd), sequenceLength: length,
          locationLength: length, evidenceTruncated: length > MAX_SEQUENCE_EVIDENCE_CODE_POINTS,
          markerClass: "unicode_tag_payload", state: "verified", confidence: "high",
          contextClass: "concealed_unicode_tag_sequence",
          proposedAction: "Remove the exact tag sequence after confirming it is not required data and approving this file.",
        })) return markers;
      }
      index = end;
      continue;
    }

    if (isVariationSelector(codePoint)) {
      let end = index + marker.length;
      let length = 1;
      let previewEnd = end;
      while (end < content.length && isVariationSelector(content.codePointAt(end)!)) {
        const character = String.fromCodePoint(content.codePointAt(end)!);
        end += character.length;
        length++;
        if (length <= MAX_SEQUENCE_EVIDENCE_CODE_POINTS) previewEnd = end;
      }
      const prior = previousCharacter(content, index);
      if (!(length === 1 && (codePoint === 0xfe0e || codePoint === 0xfe0f) && isEmoji(prior))) {
        if (!add({
          file, content, index, marker: content.slice(index, previewEnd), sequenceLength: length,
          locationLength: length, evidenceTruncated: length > MAX_SEQUENCE_EVIDENCE_CODE_POINTS,
          markerClass: length >= 4 ? "unicode_variation_selector_payload" : "unicode_variation_selector_sequence",
          state: length >= 4 ? "verified" : "informational",
          confidence: length >= 4 ? "high" : "low",
          contextClass: length >= 4 ? "encoded_variation_selector_run" : "single_or_short_variation_sequence",
          proposedAction: length >= 4
            ? "Remove the exact selector run only after confirming the intended visible character and approving this file."
            : "Review the variation sequence; single selectors can be legitimate emoji or ideographic variants.",
          ...(length < 4 ? { limitation: "Short variation sequences can be legitimate and are not cleanup-eligible." } : {}),
        })) return markers;
      }
      index = end;
      continue;
    }

    if (DEFAULT_IGNORABLES.has(codePoint)) {
      const previous = previousCharacter(content, index);
      const next = nextCharacter(content, index, marker);
      const isInitialBom = codePoint === 0xfeff && index === 0;
      const legitimateJoiner = (codePoint === 0x200c || codePoint === 0x200d) &&
        ((isEmoji(previous) && isEmoji(next)) || (isNonAsciiLetterOrMark(previous) && isNonAsciiLetterOrMark(next)));
      if (!isInitialBom && !legitimateJoiner) {
        const tokenContext = !file.prose && isAsciiIdentifier(previous) && isAsciiIdentifier(next);
        if (!add({
          file, content, index, marker,
          markerClass: tokenContext ? "unicode_zero_width_token" : "unicode_default_ignorable",
          state: tokenContext ? "verified" : "informational",
          confidence: tokenContext ? "high" : "low",
          contextClass: tokenContext ? "inside_ascii_identifier_or_token" : "context_sensitive_default_ignorable",
          proposedAction: tokenContext
            ? "Remove the exact invisible character after confirming the intended identifier and approving this file."
            : "Review the character in its language and rendering context; V3.1 does not recommend automatic removal.",
          ...(tokenContext ? {} : { limitation: "Default-ignorable characters can have legitimate typography or language semantics." }),
        })) return markers;
      }
    }
    index += marker.length;
  }
  return markers;
}

function scanMixedScriptIdentifiers(file: CandidateFile, content: string, maxMarkers: number, onBound: () => void): MarkerInput[] {
  if (!IDENTIFIER_EXTENSIONS.has(file.extension)) return [];
  const markers: MarkerInput[] = [];
  const masked = maskStringsAndComments(content);
  const identifier = /[$_\p{L}][$_\p{L}\p{N}\p{M}]*/gu;
  for (const match of masked.matchAll(identifier)) {
    const value = match[0];
    if (!/[A-Za-z]/.test(value)) continue;
    let first: string | undefined;
    let identifierLength = 0;
    const skeleton: string[] = [];
    for (const character of value) {
      const mapped = CONFUSABLE_TO_ASCII.get(character.codePointAt(0)!);
      if (mapped !== undefined && first === undefined) first = character;
      if (identifierLength < MAX_IDENTIFIER_EVIDENCE_CODE_POINTS) skeleton.push(mapped ?? character);
      identifierLength++;
    }
    if (first === undefined) continue;
    const characterOffset = value.indexOf(first);
    const index = (match.index ?? 0) + characterOffset;
    const skeletonPreview = `${skeleton.join("")}${identifierLength > MAX_IDENTIFIER_EVIDENCE_CODE_POINTS ? "…" : ""}`;
    if (markers.length >= maxMarkers) {
      onBound();
      return markers;
    }
    markers.push({
      file, content, index, marker: first, markerClass: "unicode_mixed_script_identifier",
      state: "probable", confidence: "medium", contextClass: "mixed_latin_greek_or_cyrillic_identifier",
      proposedAction: `Review identifier '${skeletonPreview}' against its intended spelling; rename only with explicit semantic approval.`,
      limitation: "The mixed-script identifier is observable, but visual similarity does not prove deception or malicious intent." +
        (identifierLength > MAX_IDENTIFIER_EVIDENCE_CODE_POINTS
          ? ` Identifier evidence is capped at ${MAX_IDENTIFIER_EVIDENCE_CODE_POINTS} code points.`
          : ""),
    });
  }
  return markers;
}

/** Offset-preserving conservative mask for common comments and quoted literals. */
function maskStringsAndComments(content: string): string {
  const output = content.split("");
  let quote: "'" | '"' | "`" | undefined;
  let blockComment = false;
  let escapeNext = false;
  for (let index = 0; index < content.length; index++) {
    const current = content[index]!;
    const next = content[index + 1];
    if (blockComment) {
      if (current === "*" && next === "/") {
        output[index] = " ";
        output[index + 1] = " ";
        index++;
        blockComment = false;
      } else if (current !== "\n" && current !== "\r") output[index] = " ";
      continue;
    }
    if (quote) {
      if (current !== "\n" && current !== "\r") output[index] = " ";
      if (escapeNext) escapeNext = false;
      else if (current === "\\") escapeNext = true;
      else if (current === quote) quote = undefined;
      continue;
    }
    if (current === "/" && next === "*") {
      output[index] = " ";
      output[index + 1] = " ";
      index++;
      blockComment = true;
      continue;
    }
    if ((current === "/" && next === "/") || current === "#") {
      while (index < content.length && content[index] !== "\n") {
        output[index] = " ";
        index++;
      }
      index--;
      continue;
    }
    if (current === "'" || current === '"' || current === "`") {
      output[index] = " ";
      quote = current;
    }
  }
  return output.join("");
}

async function discoverFiles(target: string, options: Required<SourceIntegrityOptions>): Promise<{
  files: CandidateFile[];
  limitations: string[];
}> {
  const files: CandidateFile[] = [];
  const limitations = new Set<string>();
  const targetMetadata = await lstat(target);
  const root = targetMetadata.isDirectory() ? target : dirname(target);
  let entries = 0;
  let stopped = false;

  const addFile = (absolute: string, direct: boolean): void => {
    const name = basename(absolute);
    if (!isSupported(name, direct)) return;
    if (files.length >= options.maxFiles) {
      limitations.add(`Source discovery exceeded the ${options.maxFiles}-file bound.`);
      stopped = true;
      return;
    }
    const extension = extname(name).slice(1).toLowerCase();
    files.push({
      absolute,
      relative: direct ? name : relative(root, absolute).replace(/\\/g, "/"),
      extension,
      prose: PROSE_EXTENSIONS.has(extension),
    });
  };

  const walk = async (directory: string, depth: number): Promise<void> => {
    if (stopped) return;
    if (depth > options.maxDepth) {
      limitations.add(`Source discovery exceeded the ${options.maxDepth}-directory-depth bound.`);
      return;
    }
    const children = await readdir(directory, { withFileTypes: true }).catch(() => undefined);
    if (!children) {
      limitations.add("At least one source directory could not be read.");
      return;
    }
    for (const child of children.sort((left, right) => left.name.localeCompare(right.name))) {
      if (stopped) break;
      entries++;
      if (entries > options.maxEntries) {
        limitations.add(`Source discovery exceeded the ${options.maxEntries}-entry bound.`);
        stopped = true;
        break;
      }
      const absolute = join(directory, child.name);
      if (child.isSymbolicLink()) {
        if (isSupported(child.name, false) || !extname(child.name)) {
          limitations.add("Symbolic source paths were excluded and not followed.");
        }
      } else if (child.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(child.name)) await walk(absolute, depth + 1);
      } else if (child.isFile()) {
        addFile(absolute, false);
      }
    }
  };

  if (targetMetadata.isFile()) addFile(target, true);
  else if (targetMetadata.isDirectory()) await walk(target, 0);
  else limitations.add("The source-integrity target was not a regular file or directory.");
  files.sort((left, right) => left.relative.localeCompare(right.relative));
  return { files, limitations: [...limitations] };
}

async function safeRead(file: CandidateFile, maxFileBytes: number): Promise<{
  content?: string;
  bytes: number;
  limitation?: string;
}> {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(file.absolute, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) return { bytes: 0, limitation: "A discovered source path was not a regular file." };
    if (before.size > BigInt(maxFileBytes)) {
      return { bytes: Number(before.size), limitation: `Source files larger than ${maxFileBytes / (1024 * 1024)} MiB were excluded.` };
    }
    const buffer = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || BigInt(buffer.length) !== before.size
    ) {
      return { bytes: buffer.length, limitation: "A source file changed while it was being inspected." };
    }
    if (buffer.includes(0)) return { bytes: buffer.length, limitation: "A supported path contained binary data and was excluded." };
    try {
      return { content: new TextDecoder("utf-8", { fatal: true }).decode(buffer), bytes: buffer.length };
    } catch {
      return { bytes: buffer.length, limitation: "A supported source file was not valid UTF-8 and was excluded." };
    }
  } catch {
    return { bytes: 0, limitation: "A discovered source file could not be opened without following symbolic links." };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export async function scanSourceIntegrity(
  target: string,
  inputOptions: SourceIntegrityOptions = {},
): Promise<RepositoryTrustDocument> {
  const options: Required<SourceIntegrityOptions> = {
    maxFileBytes: inputOptions.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
    maxTotalBytes: inputOptions.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    maxFiles: inputOptions.maxFiles ?? DEFAULT_MAX_FILES,
    maxEntries: inputOptions.maxEntries ?? DEFAULT_MAX_ENTRIES,
    maxDepth: inputOptions.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxArtifacts: inputOptions.maxArtifacts ?? DEFAULT_MAX_ARTIFACTS,
  };
  const discovery = await discoverFiles(target, options);
  const limitations = new Set(discovery.limitations);
  const artifacts = new Map<string, RepositoryArtifact>();
  let totalBytes = 0;
  let inspectedFiles = 0;
  let artifactBoundReached = false;

  for (const file of discovery.files) {
    const loaded = await safeRead(file, options.maxFileBytes);
    if (loaded.limitation) limitations.add(loaded.limitation);
    if (loaded.content === undefined) continue;
    if (totalBytes + loaded.bytes > options.maxTotalBytes) {
      limitations.add(`Source inspection exceeded the ${options.maxTotalBytes / (1024 * 1024)} MiB aggregate byte bound.`);
      break;
    }
    totalBytes += loaded.bytes;
    inspectedFiles++;
    const markerInputs: MarkerInput[] = [];
    const scanners = [scanBidi, scanInvisibleSequences, scanMixedScriptIdentifiers] as const;
    for (const scanner of scanners) {
      const remaining = options.maxArtifacts - artifacts.size - markerInputs.length;
      if (remaining <= 0) {
        artifactBoundReached = true;
        break;
      }
      markerInputs.push(...scanner(file, loaded.content, remaining, () => {
        artifactBoundReached = true;
      }));
      if (artifactBoundReached) break;
    }
    const locate = markerInputs.length ? createPositionLookup(loaded.content) : undefined;
    const candidates = markerInputs.map((input) => artifactFrom(input, locate!)).sort((left, right) =>
      (left.location.start_line ?? 0) - (right.location.start_line ?? 0) ||
      (left.location.start_column ?? 0) - (right.location.start_column ?? 0) ||
      left.marker_class.localeCompare(right.marker_class)
    );
    for (const artifact of candidates) {
      if (artifacts.has(artifact.fingerprint)) continue;
      if (artifacts.size >= options.maxArtifacts) {
        artifactBoundReached = true;
        continue;
      }
      artifacts.set(artifact.fingerprint, artifact);
    }
  }
  if (artifactBoundReached) limitations.add(`Source-integrity candidate/output processing exceeded the ${options.maxArtifacts}-artifact bound and was truncated.`);

  const sourceState = inspectedFiles === 0 && limitations.size === 0
    ? "not_applicable" as const
    : limitations.size > 0
      ? "partial" as const
      : "ran" as const;
  const artifactList = [...artifacts.values()].sort((left, right) =>
    left.location.file.localeCompare(right.location.file) ||
    (left.location.start_line ?? 0) - (right.location.start_line ?? 0) ||
    (left.location.start_column ?? 0) - (right.location.start_column ?? 0) ||
    left.marker_class.localeCompare(right.marker_class)
  );
  const count = (state: RepositoryArtifactState): number => artifactList.filter((artifact) => artifact.state === state).length;
  const sourceLimitations = [...limitations];
  const inherentLimitations = [
    "Mixed-script identifier analysis is limited to a reviewed Greek/Cyrillic-to-ASCII confusable set in supported code extensions; it is not complete Unicode confusable coverage.",
    "Context classification is deterministic and conservative; informational artifacts require human review and are never cleanup-eligible.",
  ];
  const document: RepositoryTrustDocument = {
    schema_version: "1.0.0",
    coverage: {
      state: "partial",
      capabilities: [
        {
          capability: "source_integrity",
          state: sourceState,
          validators: sourceState === "not_applicable" ? [] : [SOURCE_INTEGRITY_VALIDATOR],
          limitations: [...sourceLimitations, ...inherentLimitations],
        },
        {
          capability: "explicit_ai_attribution",
          state: "unavailable",
          validators: [],
          limitations: ["Explicit AI-attribution auditing is not implemented in V3.1; it remains gated for V3.2."],
        },
        {
          capability: "content_provenance",
          state: "unavailable",
          validators: [],
          limitations: ["C2PA and repository-asset provenance validation are not implemented in V3.1; they remain gated for V3.2."],
        },
        {
          capability: "statistical_watermark",
          state: "unavailable",
          validators: [],
          limitations: ["Statistical watermark verification remains unavailable until an authoritative or independently validated detector exists."],
        },
      ],
      limitations: [
        ...(sourceLimitations.length ? ["Source-integrity coverage was partial; inspect its capability limitations."] : []),
        "Only source integrity is implemented in V3.1. Other repository-trust capabilities remain unavailable.",
      ],
    },
    summary: {
      verified: count("verified"),
      probable: count("probable"),
      informational: count("informational"),
      not_verifiable: count("not_verifiable"),
      total: artifactList.length,
    },
    artifacts: artifactList,
  };
  return repositoryTrustDocumentSchema.parse(document);
}
