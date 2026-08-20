/**
 * CodeInspectus entry point.
 *
 * Default (no args): guided setup on an interactive terminal; MCP over piped stdio.
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

  if (!cmd) {
    if (process.stdin.isTTY && process.stdout.isTTY) {
      const { runSetupCli } = await import("./setup.js");
      process.exitCode = await runSetupCli([], { automatic: true });
      return;
    }
    const { startServer } = await import("./server.js");
    await startServer();
    return;
  }

  switch (cmd) {
    case "scan":
    case "preflight":
    case "export":
    case "scans":
    case "triage":
    case "bundle":
    case "bulk":
    case "history":
    case "issue": {
      const { runCli } = await import("./cli.js");
      process.exitCode = await runCli(argv);
      return;
    }
    case "setup": {
      const { runSetupCli } = await import("./setup.js");
      process.exitCode = await runSetupCli(argv.slice(1));
      return;
    }
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
      const { cliHelp } = await import("./cli.js");
      process.stdout.write(cliHelp());
      return;
    }
    default: {
      log.error(`Unknown subcommand '${cmd}'. See 'codeinspectus --help'.`);
      process.exitCode = 2;
      return;
    }
  }
}

main().catch((err) => {
  log.error("Fatal:", err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
