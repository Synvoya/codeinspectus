import { dirname, resolve } from "node:path";
import { loadStoredScanForExport } from "../export/index.js";
import { writeExportFile } from "../export/writer.js";
import { inspectTargetPath, outputContainmentRoot } from "../path-safety.js";
import { scanIdSchema } from "../schemas.js";
import type { StoredScanResult } from "../store.js";
import { createIssuePayload } from "./index.js";
import type { DestinationVisibility, IssueAdapter, IssuePayload } from "./schemas.js";

export interface IssuePayloadCliIo { stdout(text: string): void; stderr(text: string): void }
export interface IssuePayloadCliDependencies { load(scanId: string): Promise<StoredScanResult>; create(scan: StoredScanResult, findingId: string, adapter: IssueAdapter, visibility: DestinationVisibility): IssuePayload }
class IssuePayloadUsageError extends Error {}

export function issuePayloadCliHelp(): string {
  return [
    "Usage: codeinspectus issue export SCAN_ID FINDING_ID --adapter <github|jira|linear> --visibility <private|public> [--output FILE]",
    "",
    "Generates one redacted, review-required payload. It never authenticates or submits an issue.",
    "  --adapter <name>       Destination payload shape.",
    "  --visibility <scope>   Required disclosure warning context: private or public.",
    "  --output <file>        Atomic JSON write outside the scanned repository.",
    "",
  ].join("\n");
}

function takeValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1]; if (!value || value.startsWith("--")) throw new IssuePayloadUsageError(`${option} requires a value.`); return value;
}

async function boundary(scan: StoredScanResult): Promise<string> {
  const target = await inspectTargetPath(scan.target);
  return outputContainmentRoot(target) ?? dirname(resolve(scan.target));
}

export async function runIssuePayloadCli(argv: readonly string[], io: IssuePayloadCliIo, dependencies: IssuePayloadCliDependencies = { load: loadStoredScanForExport, create: createIssuePayload }): Promise<number> {
  try {
    if (!argv[0] || argv[0] === "--help" || argv[0] === "-h") { io.stdout(issuePayloadCliHelp()); return argv[0] ? 0 : 2; }
    if (argv[0] !== "export") throw new IssuePayloadUsageError(`Unknown issue subcommand '${argv[0]}'. Automatic submission is not supported.`);
    const scanId = argv[1]; const findingId = argv[2];
    if (!scanId || !findingId || scanId.startsWith("--") || findingId.startsWith("--")) throw new IssuePayloadUsageError("issue export requires exact SCAN_ID and FINDING_ID positional arguments.");
    const parsedId = scanIdSchema.safeParse(scanId); if (!parsedId.success) throw new IssuePayloadUsageError(parsedId.error.issues[0]?.message ?? "Invalid scan ID.");
    if (findingId.length > 128 || /[\0\r\n\x00-\x1f\x7f]/.test(findingId)) throw new IssuePayloadUsageError("FINDING_ID must be a bounded identifier without control characters.");
    let adapter: IssueAdapter | undefined; let visibility: DestinationVisibility | undefined; let output: string | undefined;
    for (let index = 3; index < argv.length; index++) {
      const arg = argv[index]!;
      if (arg === "--adapter") { const value = takeValue(argv, index, arg); if (!(["github", "jira", "linear"] as string[]).includes(value)) throw new IssuePayloadUsageError("--adapter must be github, jira, or linear."); adapter = value as IssueAdapter; index++; }
      else if (arg === "--visibility") { const value = takeValue(argv, index, arg); if (value !== "private" && value !== "public") throw new IssuePayloadUsageError("--visibility must be private or public."); visibility = value; index++; }
      else if (arg === "--output") { output = takeValue(argv, index, arg); index++; }
      else throw new IssuePayloadUsageError(`Unknown issue option '${arg}'. Automatic submission is not supported.`);
    }
    if (!adapter || !visibility) throw new IssuePayloadUsageError("issue export requires explicit --adapter and --visibility.");
    const scan = await dependencies.load(parsedId.data);
    if (!scan || scan.scan_id !== parsedId.data) throw new IssuePayloadUsageError(`No stored CodeInspectus scan found with id '${parsedId.data}'.`);
    const document = dependencies.create(scan, findingId, adapter, visibility);
    const rendered = `${JSON.stringify(document, null, 2)}\n`;
    if (output) await writeExportFile(output, rendered, await boundary(scan), false);
    io.stdout(rendered);
    io.stderr(`${document.destination.warnings[1]} No network submission was performed.\n`);
    return 0;
  } catch (error) {
    io.stderr(`CodeInspectus issue payload: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}
