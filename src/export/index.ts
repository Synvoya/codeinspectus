import { scanIdSchema } from "../schemas.js";
import { getScan, type StoredScanResult } from "../store.js";
import { createJsonExport } from "./model.js";
import { createSarifExport } from "./sarif.js";
import { createCsvExport } from "./csv.js";
import type { JsonExport, SarifExport } from "./schemas.js";
import type { Severity } from "../types.js";

export type ExportFormat = "json" | "sarif" | "csv";

export function createExport(scan: StoredScanResult, format: "json", options?: { failOnSeverity?: Severity }): JsonExport;
export function createExport(scan: StoredScanResult, format: "sarif", options?: { failOnSeverity?: Severity }): SarifExport;
export function createExport(scan: StoredScanResult, format: "csv", options?: { failOnSeverity?: Severity }): string;
export function createExport(scan: StoredScanResult, format: ExportFormat, options?: { failOnSeverity?: Severity }): JsonExport | SarifExport | string;
export function createExport(scan: StoredScanResult, format: ExportFormat, options: { failOnSeverity?: Severity } = {}): JsonExport | SarifExport | string {
  const json = createJsonExport(scan, options);
  return format === "sarif" ? createSarifExport(json) : format === "csv" ? createCsvExport(json) : json;
}

export async function loadStoredScanForExport(scanId: string): Promise<StoredScanResult> {
  const parsed = scanIdSchema.safeParse(scanId);
  if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? "Invalid scan_id.");
  const scan = await getScan(parsed.data);
  if (!scan) throw new Error(`No stored CodeInspectus scan found with id '${scanId}'.`);
  return scan;
}
