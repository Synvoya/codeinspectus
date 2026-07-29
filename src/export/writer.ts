import { randomUUID } from "node:crypto";
import { rename, rm, writeFile } from "node:fs/promises";
import { inspectOutputFile } from "../path-safety.js";

export async function writeExportFile(
  outputFile: string,
  content: string,
  writeBoundary: string | undefined,
  approveInsideTarget = false,
): Promise<void> {
  let inspection = await inspectOutputFile(outputFile, writeBoundary, approveInsideTarget);
  if (!inspection.safe || !inspection.resolved_path) {
    throw new Error(inspection.error ?? "Unsafe output file.");
  }
  const destination = inspection.resolved_path;
  const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx" });
    // Re-inspect immediately before replacement to catch a symlink swap.
    inspection = await inspectOutputFile(outputFile, writeBoundary, approveInsideTarget);
    if (!inspection.safe || inspection.resolved_path !== destination) {
      throw new Error(inspection.error ?? "Output file changed while it was being written.");
    }
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}
