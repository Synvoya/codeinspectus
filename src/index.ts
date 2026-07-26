/**
 * CodeInspectus entry point.
 *
 * Default (no args): start the MCP server over stdio.
 * `repair-engines`: explicitly fetch + verify only unhealthy engine/DB state.
 * `install-engines`: backward-compatible setup alias (explicit network step).
 * `pin-engines`: maintainer-only shipped lockfile generation.
 * `verify-engines`: re-verify installed binaries against the SHA lockfile.
 * `--version` / `--help`: info to stderr/stdout.
 *
 * GUARDRAIL: in server mode, stdout carries ONLY JSON-RPC. CLI text for the
 * install/verify/help subcommands is fine on stdout because those modes do not
 * speak the MCP transport.
 */

import { SERVER_VERSION } from "./config.js";
import { log } from "./logger.js";

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  switch (cmd) {
    case "install-engines": {
      const { installEngines } = await import("./install.js");
      await installEngines(argv.slice(1));
      return;
    }
    case "repair-engines": {
      const { repairEngines } = await import("./install.js");
      await repairEngines(argv.slice(1));
      return;
    }
    case "pin-engines": {
      const { pinEngines } = await import("./install.js");
      await pinEngines(argv.slice(1));
      return;
    }
    case "verify-engines": {
      const { verifyEnginesCli } = await import("./install.js");
      await verifyEnginesCli();
      return;
    }
    case "--version":
    case "-v": {
      process.stdout.write(`${SERVER_VERSION}\n`);
      return;
    }
    case "--help":
    case "-h": {
      process.stdout.write(
        [
          "CodeInspectus, by Synvoya — local-first security MCP server.",
          "",
          "Usage:",
          "  codeinspectus                 Start the MCP server over stdio (default).",
          "  codeinspectus repair-engines Repair only missing/mismatched engines or DB state (explicit network step).",
          "    --refresh-db               Refresh the Trivy DB even when current state is healthy.",
          "    [engine names]             Limit repair to opengrep, gitleaks, and/or trivy.",
          "  codeinspectus install-engines Backward-compatible setup alias; refreshes the Trivy DB.",
          "  codeinspectus pin-engines    Maintainer-only: update shipped engine pins.",
          "    --all-platforms            Pin every target platform (cross-platform; downloads + verifies all).",
          "    --platform <key>           Pin a specific platform, e.g. linux-x64 (repeatable).",
          "    --pin-only                 Record SHA256 + provenance only; do not install/run or fetch the DB (CI).",
          "  codeinspectus verify-engines  Re-verify installed binaries against engines.lock.json (--deep = live cosign).",
          "  codeinspectus --version       Print version.",
          "",
          "Register with an MCP agent (identical JSON shape, different config locations):",
          '  { "mcpServers": { "codeinspectus": { "command": "npx", "args": ["-y", "codeinspectus"] } } }',
          "",
          "Zero network egress at scan time. No account. No telemetry.",
          "",
        ].join("\n"),
      );
      return;
    }
    default: {
      if (cmd && cmd.startsWith("-") === false) {
        // Unknown subcommand → guide, then fall through to server.
        log.warn(`Unknown subcommand '${cmd}'. Starting MCP server. See --help for commands.`);
      }
      const { startServer } = await import("./server.js");
      await startServer();
      return;
    }
  }
}

main().catch((err) => {
  log.error("Fatal:", err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
