/**
 * Temporary directories that hold repository content (for example a materialized commit snapshot,
 * which can include secrets). The CLI's SIGINT/SIGTERM handlers exit synchronously, skipping
 * `finally` blocks, so they remove every live directory here before exiting.
 */
import { rmSync } from "node:fs";

const activeTemporaryDirectories = new Set<string>();

export function trackTemporaryDirectory(path: string): void {
  activeTemporaryDirectories.add(path);
}

export function releaseTemporaryDirectory(path: string): void {
  activeTemporaryDirectories.delete(path);
}

export function removeActiveTemporaryDirectories(): void {
  for (const path of activeTemporaryDirectories) {
    try {
      rmSync(path, { recursive: true, force: true });
    } catch {
      // Best effort during process exit; the directory is 0700 and under the OS temp root.
    }
  }
  activeTemporaryDirectories.clear();
}
