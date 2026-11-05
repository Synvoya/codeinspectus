/**
 * Declared container images: what a repository says it runs on, read from Dockerfiles, Compose files,
 * Kubernetes and Helm YAML, and GitHub Actions `container` / `services`. Read-only and bounded (see
 * walk.ts); a file that cannot be parsed is reported in `skipped`, never thrown.
 *
 * An image becomes a declaration only when it matches a table: runtime images, then
 * `dataset.imageAliases` (a package), `dataset.productImages` (a product), then `dataset.eol` (an image
 * whose end-of-life is tracked). The first match wins and an unmatched image produces nothing.
 * Declared, not deployed: a tag says what the repository asks for, not what runs.
 */

import { Composer, isAlias, isMap, isScalar, isSeq, LineCounter, Parser, type Document, type Node as YamlNode } from "yaml";

import type { Declaration, ReaderOptions, ReaderResult, RuntimeId, SynvoyaDataset } from "../types.js";

import { yamlText } from "./runtime.js";
import { matchesCandidate, readCandidate, walkCandidates, type WalkMatcher } from "./walk.js";

type ImageTables = Pick<SynvoyaDataset, "imageAliases" | "productImages" | "eol">;
type Precision = Declaration["precision"];

const DOCKERFILE: WalkMatcher = { basename: ["Dockerfile", "Dockerfile.*", "*.Dockerfile"] };
const MATCHERS: readonly WalkMatcher[] = [DOCKERFILE, { suffix: ".yml" }, { suffix: ".yaml" }];

/** Hostile-input bounds: a file inside the 1 MiB cap must not buy unbounded work or output. */
const MAX_DECLARATIONS_PER_FILE = 64;
const MAX_DECLARATIONS_PER_SCAN = 2000;
const MAX_NOTES_PER_FILE = 64;
const MAX_NOTES_PER_SCAN = 2000;
const MAX_YAML_DOCUMENTS = 256;
const MAX_YAML_DEPTH = 32;
const MAX_YAML_NODES = 50_000;
const MAX_DOCKERFILE_ARGS = 256;
const MAX_DOCKERFILE_STAGES = 256;
const MAX_INSTRUCTION_CHARS = 4096;
const MAX_REF_CHARS = 512;
const MAX_TAG_CHARS = 128;
const MAX_SERVICE_NAME_CHARS = 64;
/** A stored or substituted ARG value, and a substituted image reference, never exceeds this. */
const MAX_SUBSTITUTED_CHARS = MAX_REF_CHARS;
/** Total bytes read across one scan; later files are skipped with reason "budget". */
const MAX_SCAN_BYTES = 64 * 1024 * 1024;

class Malformed extends Error {}
/** The YAML does not parse and contains `{{`: a Helm or Go template, not a manifest. */
class Templated extends Error {}

interface Ctx {
  file: string;
  out: Declaration[];
  notes: string[];
  /** The per-file declaration cap was hit; readers stop as soon as they see it. */
  full: boolean;
  lookup: Lookup;
  /** Something the reader saw could not be read into a declaration (an unresolved repository, property, ...). */
  unjudged?: boolean;
  /** Some of the file was not read (a per-file cap or bound): it is reported as skipped "capped", never parsed. */
  capped?: boolean;
}

function note(ctx: Ctx, text: string): void {
  if (ctx.notes.length < MAX_NOTES_PER_FILE) ctx.notes.push(text);
}

// ---- image tables ----

const RUNTIME_IMAGES: ReadonlyMap<string, RuntimeId> = new Map<string, RuntimeId>([
  ["node", "node"],
  ["php", "php"],
  ["python", "python"],
  ["ruby", "ruby"],
  ["golang", "go"],
  ["openjdk", "java"],
  ["eclipse-temurin", "java"],
  ["amazoncorretto", "java"],
  ["mcr.microsoft.com/dotnet/sdk", "dotnet"],
  ["mcr.microsoft.com/dotnet/aspnet", "dotnet"],
  ["mcr.microsoft.com/dotnet/runtime", "dotnet"],
]);

interface Target {
  subject: Declaration["subject"];
  /** A .NET SDK image: its patch band (8.0.100) is the SDK's, not the runtime's. */
  sdk: boolean;
  /** Java tags may carry an update number (8u402). */
  java: boolean;
}

type Lookup = ((repo: string) => Target | undefined) & {
  /** An image whose last path component names a known image (`registry.internal/php`): what it would be, and its name. */
  lookalike: (repo: string) => { target: Target; name: string } | undefined;
};

/** Own properties only: an image named `constructor` or `__proto__` is not a table hit. */
function own<T>(table: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

function buildLookup(dataset: ImageTables): Lookup {
  const eolProducts = new Set<string>();
  for (const entry of dataset.eol) eolProducts.add(entry.product);
  const target = (subject: Declaration["subject"], sdk = false): Target => ({
    subject,
    sdk,
    java: subject.type === "runtime" && subject.runtime === "java",
  });
  const lookup = (repo: string): Target | undefined => {
    // `bitnami/<name>` maps like `<name>`; an exact table entry for the full repo still wins.
    const keys = repo.startsWith("bitnami/") ? [repo, repo.slice("bitnami/".length)] : [repo];
    for (const key of keys) {
      const runtime = RUNTIME_IMAGES.get(key);
      if (runtime) return target({ type: "runtime", runtime }, key.endsWith("/sdk"));
    }
    for (const key of keys) {
      const alias = own(dataset.imageAliases, key);
      if (alias) return target({ type: "package", ecosystem: alias.ecosystem, name: alias.name });
    }
    for (const key of keys) {
      const product = own(dataset.productImages, key);
      if (product) return target({ type: "product", product });
    }
    for (const key of keys) if (eolProducts.has(key)) return target({ type: "image-eol", product: key });
    return undefined;
  };
  // Last path component -> the known repository it names (the first table key wins).
  const byLast = new Map<string, string>();
  for (const key of [...RUNTIME_IMAGES.keys(), ...Object.keys(dataset.imageAliases), ...Object.keys(dataset.productImages), ...eolProducts]) {
    const last = key.slice(key.lastIndexOf("/") + 1);
    if (!byLast.has(last)) byLast.set(last, key);
  }
  const lookalike = (repo: string): { target: Target; name: string } | undefined => {
    if (!repo.includes("/")) return undefined;
    const name = byLast.get(repo.slice(repo.lastIndexOf("/") + 1));
    const found = name === undefined ? undefined : lookup(name);
    return found && name !== undefined ? { target: found, name } : undefined;
  };
  return Object.assign(lookup, { lookalike });
}

// ---- variables and references ----

/** `ARG` defaults (null: declared without a default); empty for YAML, where only `:-default` applies. */
type Vars = ReadonlyMap<string, string | null>;

const NO_VARS: Vars = new Map();
const VARIABLE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;

/**
 * One pass over `text`: a variable is replaced by its value (or its `:-default`) and the replacement is
 * never scanned again, so `ARG A=${A}` cannot loop. Names with no value are returned for the note.
 * The result is built piece by piece and abandoned (`overflow`) the moment it would pass `maxChars`,
 * so a chain of ARGs that each repeat the previous one cannot grow without bound.
 */
function substitute(text: string, vars: Vars, maxChars = MAX_SUBSTITUTED_CHARS): { text: string; missing: string[]; overflow: boolean } {
  const missing: string[] = [];
  if (text.length > maxChars) return { text: "", missing, overflow: true };
  let out = "";
  let last = 0;
  for (const match of text.matchAll(VARIABLE)) {
    out += text.slice(last, match.index);
    last = match.index + match[0].length;
    const name = match[1] ?? match[3]!;
    const value = vars.get(name);
    if (value !== undefined && value !== null && value !== "") out += value;
    else if (match[2] !== undefined) out += match[2];
    else {
      if (missing.length < 4 && !missing.includes(name)) missing.push(name);
      out += match[0];
    }
    if (out.length > maxChars) return { text: "", missing, overflow: true };
  }
  out += text.slice(last);
  return out.length > maxChars ? { text: "", missing, overflow: true } : { text: out, missing, overflow: false };
}

/** Anything still shaped like a variable or a template expression after substitution. */
const hasReference = (text: string): boolean => text.includes("$") || text.includes("{{");

interface ParsedRef {
  /** Lower-cased, `docker.io/` and `library/` removed. */
  repo: string;
  tag?: string;
  /** Digest text without the `@`. */
  digest?: string;
}

const DOCKER_HUB_HOSTS = ["docker.io/", "index.docker.io/", "registry-1.docker.io/"];

/**
 * Public vendor registries that publish an official image under another path: looked up as that image, not
 * as a private-registry lookalike. docker.elastic.co is Elastic's own registry for its products.
 */
const VENDOR_REGISTRY_IMAGES: ReadonlyMap<string, string> = new Map([
  ["docker.elastic.co/elasticsearch/elasticsearch", "elasticsearch"],
  ["docker.elastic.co/kibana/kibana", "kibana"],
  ["docker.elastic.co/logstash/logstash", "logstash"],
]);

/** Docker Hardened Images (dhi.io/<name>) mirror the Docker Official Images' names and version tags. */
const OFFICIAL_MIRROR_HOSTS = ["dhi.io/"];

/** The official image a public vendor registry or mirror path stands for; any other repository as it is. */
function officialRepo(repo: string): string {
  const vendor = VENDOR_REGISTRY_IMAGES.get(repo);
  if (vendor !== undefined) return vendor;
  for (const host of OFFICIAL_MIRROR_HOSTS) {
    // Only a top-level name mirrors an official image; dhi.io/<org>/<name> is someone's own image.
    if (repo.startsWith(host) && !repo.slice(host.length).includes("/")) return repo.slice(host.length);
  }
  return repo;
}

/** `"templated"`: the repository itself is a variable, so there is nothing to look up. */
function parseRef(written: string): ParsedRef | "templated" | undefined {
  let rest = written.trim();
  if (rest === "" || rest.length > MAX_REF_CHARS) return undefined;
  let digest: string | undefined;
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let repo = rest;
  let tag: string | undefined;
  const colon = rest.lastIndexOf(":");
  if (colon > rest.lastIndexOf("/")) {
    repo = rest.slice(0, colon);
    tag = rest.slice(colon + 1);
  }
  if (hasReference(repo)) return "templated";
  repo = repo.toLowerCase();
  if (!/^[a-z0-9][a-z0-9._/:-]*$/.test(repo)) return undefined;
  for (const host of DOCKER_HUB_HOSTS) {
    if (repo.startsWith(host)) {
      repo = repo.slice(host.length);
      break;
    }
  }
  if (repo.startsWith("library/")) repo = repo.slice("library/".length);
  repo = officialRepo(repo);
  return { repo, ...(tag ? { tag } : {}), ...(digest ? { digest } : {}) };
}

const TAG_VERSION = /^(\d{1,15}(?:\.\d{1,15})*)(?:u(\d{1,6}))?(?:[_+]\d+(?:\.\d+)*)?(?:-(.*))?$/s;
/** A real release line starts with 0 or 1-4 digits and no leading zero; `20240101` and `08.1` are not versions. */
const PLAUSIBLE_FIRST = /^(?:0|[1-9]\d{0,3})$/;
/** No component of a real version has a leading zero (`2024.01.01`). */
const PLAUSIBLE_PART = /^(?:0|[1-9]\d*)$/;
const PRERELEASE = /^(?:rc|beta|alpha|preview|ea)(?![a-z])/i;

interface TagVersion {
  spec: string;
  precision: Precision;
  resolved?: string;
  /** Why the version cannot be used; set exactly when `precision` is unresolved. */
  problem?: string;
}

const unresolved = (spec: string, problem: string): TagVersion => ({ spec: spec.slice(0, MAX_TAG_CHARS), precision: "unresolved", problem });

/** The leading version of a tag; suffixes such as `-alpine`, `-jdk` or `_7` carry no version. */
function tagVersion(ref: ParsedRef, target: Target, missing: readonly string[]): TagVersion {
  let tag = ref.tag;
  if (tag === undefined) {
    return ref.digest !== undefined
      ? unresolved(`@${ref.digest}`, "is pinned by digest only, which does not name a version")
      : unresolved("latest", "has no tag, so it floats on latest");
  }
  if (hasReference(tag)) {
    return unresolved(
      tag,
      missing.length > 0 ? `depends on ${missing.join(", ")}, which has no value here` : "contains a reference that is not resolved",
    );
  }
  if (tag.length > MAX_TAG_CHARS) return unresolved(tag, "has a tag too long to read");
  if (tag.toLowerCase() === "latest") return unresolved(tag, "is tagged latest");
  if (target.java) tag = tag.replace(/^(?:jdk|jre)-(?=\d)/i, "");
  // Products publish `v0.49.1`; runtime images use bare versions, so a `v` there is not a version.
  if (target.subject.type !== "runtime") tag = tag.replace(/^v(?=\d)/i, "");
  const match = TAG_VERSION.exec(tag);
  if (!match) return unresolved(tag, `has tag "${tag.slice(0, 40)}", which does not start with a version`);
  const base = match[1]!;
  const parts = base.split(".");
  if (!PLAUSIBLE_FIRST.test(parts[0]!) || !parts.every((part) => PLAUSIBLE_PART.test(part))) return unresolved(tag, `has tag "${tag.slice(0, 40)}", which does not look like a version`);
  // A pre-release (-rc, -beta, ...) is not the release line it names, so it is never exact.
  const prerelease = match[3] !== undefined && PRERELEASE.test(match[3]);
  if (match[2] !== undefined) {
    // 8u402: a Java update release, understood by the java version scheme.
    if (!target.java || parts.length !== 1) return unresolved(tag, `has tag "${tag.slice(0, 40)}", which is not a version of this image`);
    const spec = `${base}u${match[2]}`;
    return prerelease ? { spec, precision: "floating" } : { spec, precision: "exact", resolved: spec };
  }
  if (target.sdk && parts.length === 3 && Number(parts[2]) >= 100) return { spec: `${parts[0]}.${parts[1]}`, precision: "floating" };
  if (prerelease) return { spec: base, precision: "floating" };
  return parts.length >= 3 ? { spec: base, precision: "exact", resolved: base } : { spec: base, precision: "floating" };
}

function emitDeclaration(ctx: Ctx, declaration: Declaration): void {
  if (ctx.full) return;
  if (ctx.out.length >= MAX_DECLARATIONS_PER_FILE) {
    ctx.full = true;
    ctx.capped = true;
    ctx.notes.push(`${ctx.file}: more than ${MAX_DECLARATIONS_PER_FILE} image declarations; extra ignored`);
    return;
  }
  ctx.out.push(declaration);
}

/** One image reference as written: substitute, parse, look up, classify, emit. */
function handleImage(ctx: Ctx, written: string, vars: Vars, line: number, source: string): void {
  if (ctx.full) return;
  // Every source but "Dockerfile FROM" already ends in "image".
  const where = `${ctx.file}:${line}: ${source}${source.endsWith("image") ? "" : " image"}`;
  const shown = written.length > 100 ? `${written.slice(0, 100)}...` : written;
  const substituted = substitute(written, vars);
  // Each branch below that cannot name an image leaves the file not fully checked: the reference may be
  // the image a prior finding came from.
  if (substituted.overflow) {
    ctx.unjudged = true;
    note(ctx, `${where} "${shown}" expands to more than ${MAX_SUBSTITUTED_CHARS} characters; no finding is possible for it.`);
    return;
  }
  const ref = parseRef(substituted.text);
  if (ref === undefined) {
    ctx.unjudged = true;
    note(ctx, `${where} "${shown}" is not an image reference Synvoya can read; no finding is possible for it.`);
    return;
  }
  if (ref === "templated") {
    ctx.unjudged = true;
    note(ctx, `${where} "${shown}" names its repository through a variable that is not resolved; no finding is possible for it.`);
    return;
  }
  const target = ctx.lookup(ref.repo);
  if (!target) {
    // A known image name behind an unknown registry may be a rebuild or a mirror of anything: an unresolved
    // declaration (never a finding) that keeps the file from proving a fix.
    const lookalike = ctx.lookup.lookalike(ref.repo);
    if (!lookalike) return;
    note(ctx, `${where} "${shown}" is an image on a private registry — cannot confirm it is the official ${lookalike.name} image; no finding is possible for it.`);
    emitDeclaration(ctx, {
      subject: lookalike.target.subject,
      spec: (ref.tag ?? (ref.digest ? `@${ref.digest}` : "latest")).slice(0, MAX_TAG_CHARS),
      precision: "unresolved",
      file: ctx.file,
      line,
      source,
      noted: true,
    });
    return;
  }
  const version = tagVersion(ref, target, substituted.missing);
  if (version.problem !== undefined) {
    note(ctx, `${where} "${shown}" ${version.problem}; no finding is possible for it.`);
  }
  emitDeclaration(ctx, {
    subject: target.subject,
    spec: version.spec,
    ...(version.precision === "exact" && version.resolved !== undefined ? { resolved: version.resolved } : {}),
    precision: version.precision,
    file: ctx.file,
    line,
    source,
  });
}

// ---- Dockerfile ----

function readDockerfile(ctx: Ctx, text: string): void {
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  const args = new Map<string, string | null>();
  const stages = new Set<string>();
  let escape = "\\";
  let directives = true;
  let seenFrom = false;
  let pending: string[] = [];
  let pendingChars = 0;
  let startLine = 0;

  const instruction = (logical: string, line: number): void => {
    const match = /^([A-Za-z]+)\s*([\s\S]*)$/.exec(logical.trim());
    if (!match) return;
    const keyword = match[1]!.toUpperCase();
    if (keyword === "ARG" && !seenFrom) {
      // Only ARGs before the first FROM are visible to FROM; each default is substituted once, as declared.
      for (const token of match[2]!.split(/\s+/, 64)) {
        const arg = /^([A-Za-z_][A-Za-z0-9_]*)(?:=([\s\S]*))?$/.exec(token);
        if (!arg) continue;
        if (!args.has(arg[1]!) && args.size >= MAX_DOCKERFILE_ARGS) {
          ctx.capped = true;
          continue;
        }
        // A default that is, or expands to, more than MAX_SUBSTITUTED_CHARS is stored as "no value".
        const value = arg[2] === undefined ? undefined : substitute(arg[2].replace(/^(["'])([\s\S]*)\1$/, "$2"), args);
        args.set(arg[1]!, value === undefined || value.overflow ? null : value.text);
      }
    } else if (keyword === "FROM") {
      seenFrom = true;
      const tokens = match[2]!.split(/\s+/).filter((token) => token !== "" && !token.startsWith("--"));
      const image = tokens[0];
      if (image === undefined) return;
      const alias = tokens[1]?.toLowerCase() === "as" ? tokens[2]?.toLowerCase() : undefined;
      const skip = image.toLowerCase() === "scratch" || stages.has(image.toLowerCase());
      if (alias !== undefined && stages.size < MAX_DOCKERFILE_STAGES) stages.add(alias);
      if (!skip) handleImage(ctx, image, args, line, "Dockerfile FROM");
    }
  };

  for (let index = 0; index < lines.length && !ctx.full; index++) {
    const raw = lines[index]!;
    const trimmed = raw.trim();
    if (directives) {
      const directive = /^#\s*([A-Za-z]+)\s*=\s*(\S+)\s*$/.exec(trimmed);
      if (directive) {
        if (directive[1]!.toLowerCase() === "escape" && (directive[2] === "`" || directive[2] === "\\")) escape = directive[2];
        continue;
      }
      directives = false;
    }
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const line = raw.trimEnd();
    const continues = line.endsWith(escape);
    if (pending.length === 0) startLine = index + 1;
    if (pendingChars < MAX_INSTRUCTION_CHARS) {
      const part = continues ? line.slice(0, -1) : line;
      pending.push(part);
      pendingChars += part.length;
    }
    if (!continues) {
      instruction(pending.join(" "), startLine);
      pending = [];
      pendingChars = 0;
    }
  }
  if (pending.length > 0 && !ctx.full) instruction(pending.join(" "), startLine);
}

// ---- YAML ----

interface Yaml {
  text: string;
  lines: LineCounter;
}

const lineOf = (yaml: Yaml, node: unknown): number => {
  const start = (node as YamlNode | null | undefined)?.range?.[0];
  return start === undefined ? 1 : yaml.lines.linePos(start).line;
};

/** A map's entry as a node (never an expanded alias), or undefined when `map` is not a map. */
function entry(map: unknown, key: string): unknown {
  return isMap(map) ? map.get(key, true) : undefined;
}

/**
 * Documents one at a time, so a file of 100k `---` separators costs 256 documents, not 100k. The
 * composer never expands aliases (only `toJS` does) and `uniqueKeys` is off because its duplicate-key
 * check is quadratic in the number of keys.
 */
function* documents(ctx: Ctx, yaml: Yaml): Generator<Document.Parsed> {
  const composer = new Composer({ uniqueKeys: false, prettyErrors: false });
  const parser = new Parser(yaml.lines.addNewLine);
  let count = 0;
  for (const doc of composer.compose(parser.parse(yaml.text))) {
    if (++count > MAX_YAML_DOCUMENTS) {
      ctx.capped = true;
      note(ctx, `${ctx.file}: more than ${MAX_YAML_DOCUMENTS} YAML documents; extra ignored`);
      return;
    }
    if (doc.errors.length > 0) throw yaml.text.includes("{{") ? new Templated() : new Malformed();
    yield doc;
  }
}

function scalarImage(ctx: Ctx, yaml: Yaml, node: unknown, source: string): void {
  const written = yamlText(node, yaml.text);
  if (written !== undefined) handleImage(ctx, written, NO_VARS, lineOf(yaml, node), source);
}

/** A Helm `image:` map: `repository`, with `registry` and `tag` when present. */
function helmImage(ctx: Ctx, yaml: Yaml, map: unknown, repository: unknown, source: string): void {
  const repo = yamlText(repository, yaml.text);
  if (repo === undefined) return;
  const registry = yamlText(entry(map, "registry"), yaml.text);
  const tag = yamlText(entry(map, "tag"), yaml.text);
  handleImage(ctx, `${registry ? `${registry}/` : ""}${repo}${tag ? `:${tag}` : ""}`, NO_VARS, lineOf(yaml, repository), source);
}

/** Every `image:` in document order: a string, or a Helm map. Depth and node count are bounded. */
function readImageKeys(ctx: Ctx, yaml: Yaml, root: unknown, source: string): void {
  let visited = 0;
  let tooDeep = false;
  let tooMany = false;
  const visit = (node: unknown, depth: number): void => {
    if (ctx.full || tooMany || isAlias(node)) return;
    if (++visited > MAX_YAML_NODES) {
      tooMany = true;
      ctx.capped = true;
      note(ctx, `${ctx.file}: more than ${MAX_YAML_NODES} YAML nodes; the rest is ignored`);
      return;
    }
    if (isSeq(node)) {
      if (depth >= MAX_YAML_DEPTH) tooDeep = true;
      else for (const item of node.items) visit(item, depth + 1);
    } else if (isMap(node)) {
      for (const pair of node.items) {
        if (ctx.full || tooMany) return;
        if (isScalar(pair.key) && pair.key.value === "image") {
          if (isScalar(pair.value)) {
            scalarImage(ctx, yaml, pair.value, source);
            continue;
          }
          const repository = entry(pair.value, "repository");
          if (isScalar(repository)) {
            helmImage(ctx, yaml, pair.value, repository, source);
            continue;
          }
        }
        if (depth >= MAX_YAML_DEPTH) tooDeep = true;
        else visit(pair.value, depth + 1);
      }
    }
  };
  visit(root, 0);
  if (tooDeep) {
    ctx.capped = true;
    note(ctx, `${ctx.file}: YAML nested deeper than ${MAX_YAML_DEPTH} levels; deeper content ignored`);
  }
}

function readCompose(ctx: Ctx, yaml: Yaml): void {
  for (const doc of documents(ctx, yaml)) {
    const services = entry(doc.contents, "services");
    if (!isMap(services)) continue;
    for (const service of services.items) {
      if (ctx.full) return;
      scalarImage(ctx, yaml, entry(service.value, "image"), "compose image");
    }
  }
}

function readWorkflow(ctx: Ctx, yaml: Yaml): void {
  for (const doc of documents(ctx, yaml)) {
    const jobs = entry(doc.contents, "jobs");
    if (!isMap(jobs)) continue;
    for (const job of jobs.items) {
      if (ctx.full) return;
      const container = entry(job.value, "container");
      scalarImage(ctx, yaml, isMap(container) ? entry(container, "image") : container, "GitHub Actions container.image");
      const services = entry(job.value, "services");
      if (!isMap(services)) continue;
      for (const service of services.items) {
        if (ctx.full) return;
        const name = isScalar(service.key) ? String(service.key.value).slice(0, MAX_SERVICE_NAME_CHARS) : "?";
        scalarImage(ctx, yaml, entry(service.value, "image"), `GitHub Actions services.${name}.image`);
      }
    }
  }
}

function readKubernetes(ctx: Ctx, yaml: Yaml): void {
  for (const doc of documents(ctx, yaml)) {
    const root = doc.contents;
    // A document counts only with a top-level apiVersion and kind.
    if (isMap(root) && root.has("apiVersion") && root.has("kind")) readImageKeys(ctx, yaml, root, "Kubernetes image");
  }
}

function readValues(ctx: Ctx, yaml: Yaml): void {
  for (const doc of documents(ctx, yaml)) readImageKeys(ctx, yaml, doc.contents, "Helm values image");
}

// ---- dispatch ----

type Kind = "dockerfile" | "workflow" | "compose" | "values" | "kubernetes";

function kindOf(file: string): Kind {
  if (matchesCandidate(DOCKERFILE, file)) return "dockerfile";
  const name = file.slice(file.lastIndexOf("/") + 1);
  if (file.startsWith(".github/workflows/")) return "workflow";
  if (/^(?:docker-)?compose.*\.ya?ml$/i.test(name)) return "compose";
  if (/^values.*\.ya?ml$/i.test(name)) return "values";
  return "kubernetes";
}

/** False when the file is not one this reader looks at (most YAML is not a manifest); it is then not "parsed". */
function readOne(ctx: Ctx, kind: Kind, text: string): boolean {
  if (kind === "dockerfile") {
    readDockerfile(ctx, text);
    return true;
  }
  if (kind === "kubernetes" && !(text.includes("apiVersion") && text.includes("kind"))) return false;
  const yaml: Yaml = { text, lines: new LineCounter() };
  if (kind === "compose") readCompose(ctx, yaml);
  else if (kind === "workflow") readWorkflow(ctx, yaml);
  else if (kind === "values") readValues(ctx, yaml);
  else readKubernetes(ctx, yaml);
  return true;
}

export async function readImageTags(target: string, dataset: ImageTables, options: ReaderOptions = {}): Promise<ReaderResult> {
  const walked = await walkCandidates(target, MATCHERS, {}, { signal: options.signal, only: options.only });
  const result: ReaderResult = { declarations: [], parsed: [], skipped: [...walked.skipped], notes: [] };
  const lookup = buildLookup(dataset);
  let consumed = 0;
  for (const file of walked.files) {
    if (options.signal?.aborted) {
      result.skipped.push({ file, reason: "deadline" });
      continue;
    }
    if (consumed >= MAX_SCAN_BYTES) {
      if (!result.skipped.some((entry) => entry.reason === "budget")) {
        result.notes.push(`${file}: more than ${MAX_SCAN_BYTES / (1024 * 1024)} MiB read in this scan (scan budget); the remaining files are skipped`);
      }
      result.skipped.push({ file, reason: "budget" });
      continue;
    }
    const text = await readCandidate(target, file);
    if (text === undefined) {
      result.skipped.push({ file, reason: "unreadable" });
      continue;
    }
    consumed += Buffer.byteLength(text);
    let scanFull = false;
    try {
      const ctx: Ctx = { file, out: [], notes: [], full: false, lookup };
      if (!readOne(ctx, kindOf(file), text)) continue;
      // Appended in loops, never spread: the arrays are bounded, but a spread's argument limit is not ours to rely on.
      for (const declaration of ctx.out) {
        if (result.declarations.length >= MAX_DECLARATIONS_PER_SCAN) {
          scanFull = true;
          const capNote = `${file}: more than ${MAX_DECLARATIONS_PER_SCAN} image declarations; extra ignored`;
          ctx.notes.push(capNote);
          (result.priorityNotes ??= []).push(capNote);
          break;
        }
        result.declarations.push(declaration);
      }
      for (const message of ctx.notes) if (result.notes.length < MAX_NOTES_PER_SCAN) result.notes.push(message);
      if (ctx.unjudged) (result.unjudged ??= []).push(file);
      // A file read only in part is not a re-check of everything it declares.
      if (ctx.capped || scanFull) result.skipped.push({ file, reason: "capped" });
      else result.parsed.push(file);
    } catch (error) {
      // Malformed content is reported; any unexpected failure is treated the same way, never thrown.
      result.skipped.push({ file, reason: error instanceof Templated ? "templated" : "malformed" });
    }
    if (scanFull) break;
  }
  return result;
}
