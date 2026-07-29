import { compareAgainstBaseline } from "../baseline.js";
import { loadStoredScanForExport } from "../export/index.js";
import { scanIdSchema } from "../schemas.js";
import type { StoredScanResult } from "../store.js";
import { createSealedBundle, verifySealedBundle } from "./index.js";

export interface BundleCliIo { stdout(text: string): void; stderr(text: string): void }
export interface BundleCliDependencies {
  loadScan(scanId: string): Promise<StoredScanResult>;
  create(scan: StoredScanResult, outputDirectory: string): ReturnType<typeof createSealedBundle>;
  verify(directory: string): ReturnType<typeof verifySealedBundle>;
}

class BundleUsageError extends Error {}

export function bundleCliHelp(): string {
  return [
    "Usage:",
    "  codeinspectus bundle create SCAN_ID --output-dir PATH",
    "  codeinspectus bundle verify PATH [--format text|json]",
    "  codeinspectus bundle export PATH --format json|sarif",
    "  codeinspectus bundle compare OLD_PATH NEW_PATH [--format text|json]",
    "",
    "Bundle consumers verify the manifest seal and every artifact before export or comparison.",
    "Creation is atomic, refuses an existing destination, and will not write inside the scanned repository.",
    "",
  ].join("\n");
}

function parseOptions(argv: readonly string[], positionalCount: number, allowedFormats: readonly string[]): { positional: string[]; format?: string; outputDirectory?: string } {
  const positional: string[] = [];
  let format: string | undefined;
  let outputDirectory: string | undefined;
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]!;
    if (value === "--format" || value === "--output-dir") {
      const optionValue = argv[index + 1];
      if (!optionValue || optionValue.startsWith("--")) throw new BundleUsageError(`${value} requires a value.`);
      if (value === "--format") format = optionValue;
      else outputDirectory = optionValue;
      index++;
    } else if (value.startsWith("-")) throw new BundleUsageError(`Unknown bundle option '${value}'.`);
    else positional.push(value);
  }
  if (positional.length !== positionalCount) throw new BundleUsageError(`Expected exactly ${positionalCount} bundle argument${positionalCount === 1 ? "" : "s"}.`);
  if (format && !allowedFormats.includes(format)) throw new BundleUsageError(`Bundle --format must be ${allowedFormats.join(" or ")}.`);
  return { positional, ...(format ? { format } : {}), ...(outputDirectory ? { outputDirectory } : {}) };
}

export async function runBundleCli(
  argv: readonly string[],
  io: BundleCliIo,
  dependencies: BundleCliDependencies = { loadScan: loadStoredScanForExport, create: createSealedBundle, verify: verifySealedBundle },
): Promise<number> {
  try {
    const action = argv[0];
    if (!action || action === "--help" || action === "-h") {
      io.stdout(bundleCliHelp());
      return action ? 0 : 2;
    }
    if (action === "create") {
      const parsed = parseOptions(argv.slice(1), 1, []);
      const id = scanIdSchema.safeParse(parsed.positional[0]);
      if (!id.success) throw new BundleUsageError(id.error.issues[0]?.message ?? "Invalid scan ID.");
      if (!parsed.outputDirectory) throw new BundleUsageError("bundle create requires --output-dir PATH.");
      if (parsed.format) throw new BundleUsageError("bundle create does not accept --format.");
      const scan = await dependencies.loadScan(id.data);
      if (!scan || scan.scan_id !== id.data) throw new BundleUsageError(`No stored CodeInspectus scan found with id '${id.data}'.`);
      const manifest = await dependencies.create(scan, parsed.outputDirectory);
      io.stdout(`Created sealed CodeInspectus bundle ${manifest.bundle_id} for ${manifest.scan_id} at ${parsed.outputDirectory}.\n`);
      return 0;
    }
    if (action === "verify") {
      const parsed = parseOptions(argv.slice(1), 1, ["text", "json"]);
      if (parsed.outputDirectory) throw new BundleUsageError("bundle verify does not accept --output-dir.");
      const bundle = await dependencies.verify(parsed.positional[0]!);
      io.stdout(parsed.format === "json"
        ? `${JSON.stringify(bundle.manifest, null, 2)}\n`
        : `Verified sealed CodeInspectus bundle ${bundle.manifest.bundle_id}: ${bundle.manifest.artifacts.length} artifacts, scan ${bundle.manifest.scan_id}.\n`);
      return 0;
    }
    if (action === "export") {
      const parsed = parseOptions(argv.slice(1), 1, ["json", "sarif"]);
      if (!parsed.format) throw new BundleUsageError("bundle export requires --format json or --format sarif.");
      if (parsed.outputDirectory) throw new BundleUsageError("bundle export does not accept --output-dir.");
      const bundle = await dependencies.verify(parsed.positional[0]!);
      io.stdout(bundle.contents[parsed.format === "sarif" ? "results.sarif" : "artifacts/export.json"].toString("utf8"));
      return 0;
    }
    if (action === "compare") {
      const parsed = parseOptions(argv.slice(1), 2, ["text", "json"]);
      if (parsed.outputDirectory) throw new BundleUsageError("bundle compare does not accept --output-dir.");
      const [oldBundle, newBundle] = await Promise.all([dependencies.verify(parsed.positional[0]!), dependencies.verify(parsed.positional[1]!)]);
      const comparison = compareAgainstBaseline(oldBundle.scan, newBundle.scan);
      io.stdout(parsed.format === "json"
        ? `${JSON.stringify(comparison, null, 2)}\n`
        : `Verified bundle comparison ${comparison.baseline_scan_id} -> ${comparison.scan_id}: ${comparison.summary.New} new, ${comparison.summary.Existing} existing, ${comparison.summary["Not rechecked / unknown"]} unknown; coverage=${comparison.coverage}.\n`);
      if (comparison.partial) io.stderr("CodeInspectus bundle: comparison is partial or unknown.\n");
      return comparison.partial ? 2 : 0;
    }
    throw new BundleUsageError(`Unknown bundle subcommand '${action}'.`);
  } catch (error) {
    io.stderr(`CodeInspectus bundle: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
