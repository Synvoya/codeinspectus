/**
 * Integrity-checked loader for the bundled Synvoya gap-advisory dataset.
 *
 * Scans never touch the network. The dataset ships inside the package under
 * detection-db/synvoya/ and is trusted only after every file matches the SHA-256
 * digest in manifest.json and passes strict schema validation. Any failure is
 * reported as { ok: false } so the caller can mark the engine unavailable rather
 * than silently reporting zero findings.
 */

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

import { log } from "../logger.js";
import { sha256Hex } from "../util/hash.js";
import {
  SYNVOYA_DATASET_DIR,
  SYNVOYA_DATASET_FILES,
  SYNVOYA_MAX_FILE_BYTES,
} from "./constants.js";
import type { SynvoyaDataset } from "./types.js";

export { SYNVOYA_DATASET_DIR } from "./constants.js";
export type {
  EolEntry,
  OsvEvent,
  RuntimeId,
  SynvoyaAdvisory,
  SynvoyaDataset,
  SynvoyaKind,
  SynvoyaTarget,
} from "./types.js";

const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const httpsUrlSchema = z.string().url().startsWith("https://");
const severitySchema = z.enum(["critical", "high", "medium", "low", "info"]);
const runtimeSchema = z.enum(["node", "php", "python", "ruby", "go", "dotnet", "java"]);
const kindSchema = z.enum(["vulnerability", "malware", "runtime", "eol", "product", "config"]);
const engineSchema = z.enum([
  "opengrep",
  "gitleaks",
  "trivy",
  "osv-scanner",
  "codeinspectus-ai",
  "codeinspectus-pub",
]);

const osvEventSchema = z
  .object({
    introduced: z.string().min(1).optional(),
    fixed: z.string().min(1).optional(),
    last_affected: z.string().min(1).optional(),
    limit: z.string().min(1).optional(),
  })
  .strict()
  .refine((event) => Object.values(event).filter((value) => value !== undefined).length === 1, {
    message: "Each OSV range event must contain exactly one boundary.",
  })
  // Narrow the checked event to the OsvEvent union so the parsed shape is a SynvoyaAdvisory without a cast.
  .pipe(
    z.union([
      z.object({ introduced: z.string() }).strict(),
      z.object({ fixed: z.string() }).strict(),
      z.object({ last_affected: z.string() }).strict(),
      z.object({ limit: z.string() }).strict(),
    ]),
  );

const targetSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("package"),
      ecosystem: z.string().min(1),
      name: z.string().min(1),
    })
    .strict(),
  z.object({ type: z.literal("runtime"), runtime: runtimeSchema }).strict(),
  z.object({ type: z.literal("product"), product: z.string().min(1) }).strict(),
]);

const advisorySchema = z
  .object({
    id: z.string().regex(/^SYN-\d{4}-\d{3,}$/),
    slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
    title: z.string().min(1),
    kind: kindSchema,
    aliases: z.array(z.string().min(1)),
    target: targetSchema,
    affected: z.array(
      z
        .object({
          line: z.string().min(1).optional(),
          events: z.array(osvEventSchema).min(1),
        })
        .strict(),
    ),
    fixed: z.array(z.string().min(1)),
    severity: severitySchema,
    exploited: z.boolean(),
    exploited_source: httpsUrlSchema.optional(),
    remediation_steps: z.array(z.string().min(1)).min(1),
    sources: z.array(httpsUrlSchema).min(1),
    status: z.enum(["active", "covered"]),
    covered_by: engineSchema.optional(),
    covered_since: dateSchema.optional(),
    provisional: z.boolean(),
    product_rule: z.enum(["version-proves", "verify-hotfix"]).optional(),
    requires: z.enum(["M2", "platform-detection"]).optional(),
    no_fix_available: z.literal(true).optional(),
  })
  .strict()
  .refine(
    (advisory) =>
      advisory.provisional ||
      advisory.kind === "eol" ||
      advisory.kind === "malware" ||
      advisory.kind === "config" ||
      advisory.no_fix_available === true ||
      advisory.product_rule === "verify-hotfix" ||
      advisory.fixed.length > 0,
    {
      message:
        "A non-provisional advisory must list at least one fixed version (except eol, malware, config, no_fix_available and verify-hotfix entries).",
    },
  )
  .refine((advisory) => advisory.product_rule === undefined || advisory.target.type === "product", {
    message: "product_rule is only allowed on a product target.",
    path: ["product_rule"],
  })
  .refine((advisory) => advisory.no_fix_available !== true || advisory.fixed.length === 0, {
    message: "no_fix_available is only allowed with an empty fixed list.",
    path: ["no_fix_available"],
  })
  .refine((advisory) => advisory.kind === "eol" || advisory.affected.length > 0, {
    message: "An advisory must list at least one affected range (except eol).",
    path: ["affected"],
  })
  .refine(
    (advisory) =>
      advisory.status === "covered"
        ? advisory.covered_by !== undefined && advisory.covered_since !== undefined
        : advisory.covered_by === undefined && advisory.covered_since === undefined,
    {
      message: "covered_by and covered_since are required when status is covered and forbidden when it is active.",
      path: ["covered_by"],
    },
  );

const advisoriesFileSchema = z
  .object({
    advisories: z.array(advisorySchema).min(1),
  })
  .strict()
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    for (const advisory of file.advisories) {
      if (seen.has(advisory.id)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `Duplicate advisory id ${advisory.id}.` });
      }
      seen.add(advisory.id);
    }
  });

const aliasesFileSchema = z
  .object({
    packages: z.record(z.string().min(1), z.string().min(1)),
    imageAliases: z.record(
      z.string().min(1),
      z.object({ ecosystem: z.string().min(1), name: z.string().min(1) }).strict(),
    ),
    productImages: z.record(z.string().min(1), z.string().min(1)),
  })
  .strict();

const eolEntrySchema = z
  .object({
    product: z.string().min(1),
    cycle: z.string().min(1),
    eol: dateSchema,
    latest: z.string().min(1).optional(),
    source: httpsUrlSchema,
  })
  .strict();

const eolFileSchema = z.object({ entries: z.array(eolEntrySchema).min(1) }).strict();

const manifestSchema = z
  .object({
    schema_version: z.literal("1.0.0"),
    version: z.string().regex(/^\d{4}\.\d{2}\.\d{2}\.\d+$/),
    date: dateSchema,
    files: z
      .object({
        "advisories.json": digestSchema,
        "aliases.json": digestSchema,
        "eol.json": digestSchema,
      })
      .strict(),
  })
  .strict();

/** What the advisory schema accepts; assignable to SynvoyaAdvisory (checked at compile time in dataset.test.ts). */
export type ParsedSynvoyaAdvisory = z.infer<typeof advisorySchema>;

export type SynvoyaLoadResult =
  | { ok: true; dataset: SynvoyaDataset; /** `sha256:<hex>` of manifest.json, which pins every data file. */ digest: string }
  | { ok: false; reason: string };

class DatasetError extends Error {}

function describeSchemaError(error: z.ZodError): string {
  const issue = error.issues[0];
  const where = issue && issue.path.length > 0 ? ` at ${issue.path.join(".")}` : "";
  return `${issue?.message ?? "invalid"}${where}`;
}

const MAX_MIB = SYNVOYA_MAX_FILE_BYTES / (1024 * 1024);

/**
 * Read a regular file at most once, without following links. lstat rejects symlinks,
 * directories and FIFOs before open (a FIFO would block the open), O_NOFOLLOW closes the
 * lstat/open race where the platform supports it, and fstat re-checks the opened handle.
 */
async function readCapped(dir: string, name: string): Promise<Buffer> {
  const path = join(dir, name);
  let info;
  try {
    info = await lstat(path);
  } catch {
    throw new DatasetError(`${name} is missing or unreadable.`);
  }
  if (!info.isFile()) throw new DatasetError(`${name} is not a regular file.`);
  if (info.size > SYNVOYA_MAX_FILE_BYTES) {
    throw new DatasetError(`${name} exceeds the ${MAX_MIB} MiB limit.`);
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch {
    throw new DatasetError(`${name} is not a regular file or is unreadable.`);
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) throw new DatasetError(`${name} is not a regular file.`);
    if (opened.size > SYNVOYA_MAX_FILE_BYTES) {
      throw new DatasetError(`${name} exceeds the ${MAX_MIB} MiB limit.`);
    }
    const bytes = await handle.readFile();
    if (bytes.length > SYNVOYA_MAX_FILE_BYTES) {
      throw new DatasetError(`${name} exceeds the ${MAX_MIB} MiB limit.`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof DatasetError) throw error;
    throw new DatasetError(`${name} is missing or unreadable.`);
  } finally {
    await handle.close();
  }
}

function parseJson<S extends z.ZodTypeAny>(name: string, bytes: Buffer, schema: S): z.infer<S> {
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new DatasetError(`${name} is not valid JSON.`);
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw new DatasetError(`${name} failed schema validation: ${describeSchemaError(parsed.error)}.`);
  }
  return parsed.data;
}

export async function loadSynvoyaDataset(dir: string = SYNVOYA_DATASET_DIR): Promise<SynvoyaLoadResult> {
  try {
    const manifestBytes = await readCapped(dir, "manifest.json");
    const manifest = parseJson("manifest.json", manifestBytes, manifestSchema);

    // Read and verify every file against the manifest BEFORE any of them is parsed.
    const verified = new Map<string, Buffer>();
    for (const name of SYNVOYA_DATASET_FILES) {
      const bytes = await readCapped(dir, name);
      if (`sha256:${sha256Hex(bytes)}` !== manifest.files[name]) {
        throw new DatasetError(`${name} does not match the SHA-256 digest in manifest.json.`);
      }
      verified.set(name, bytes);
    }

    const advisories = parseJson("advisories.json", verified.get("advisories.json")!, advisoriesFileSchema);
    const aliases = parseJson("aliases.json", verified.get("aliases.json")!, aliasesFileSchema);
    const eol = parseJson("eol.json", verified.get("eol.json")!, eolFileSchema);

    return {
      ok: true,
      digest: `sha256:${sha256Hex(manifestBytes)}`,
      dataset: {
        version: manifest.version,
        date: manifest.date,
        advisories: advisories.advisories,
        aliases: aliases.packages,
        imageAliases: aliases.imageAliases,
        productImages: aliases.productImages,
        eol: eol.entries,
      },
    };
  } catch (error) {
    if (error instanceof DatasetError) return { ok: false, reason: error.message };
    log.warn("synvoya dataset load failed unexpectedly", { cause: error instanceof Error ? error.message : String(error) });
    return { ok: false, reason: "The Synvoya dataset could not be loaded." };
  }
}
