/** Resolve a valid subprocess working directory without changing the absolute scan target. */

import { lstat } from "node:fs/promises";
import { dirname } from "node:path";

export async function engineWorkingDirectory(target: string): Promise<string> {
  const metadata = await lstat(target);
  return metadata.isDirectory() ? target : dirname(target);
}
