/**
 * CodeInspectus entry point.
 *
 * Default (no args): start the MCP server over stdio.
 * `install-engines`: fetch + verify the engine binaries and initial Trivy DB
 *   (the ONLY network step; install-time only — PRD §7).
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
          "  codeinspectus install-engines Fetch + SHA/cosign-verify engine binaries + Trivy DB (install-time only).",
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
