import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Cross-platform verification isolation: scans remain in the worker's in-memory store for
    // rescan/explain tests but never accumulate in the developer's real managed scan history.
    env: {
      CODEINSPECTUS_INTERNAL_DISABLE_SCAN_PERSISTENCE: "1",
      CODEINSPECTUS_INTERNAL_DISABLE_TRIAGE_PERSISTENCE: "1",
    },
  },
});
