# Verify — what "done" means for CodeInspectus

Run these before claiming work complete.

## Build (must pass clean)
```bash
npm run build        # tsc --noEmit && tsup — zero type errors
```

## Evals (regression suite, PRD §13)
```bash
npm run eval         # drives the built server over MCP stdio
```
Expected: all non-skipped evals PASS. Engine-dependent evals (E16 Opengrep SQLi,
E17 Trivy SCA) auto-SKIP when the binary/DB is unavailable — that is acceptable,
a FAIL is not.

## MCP transport
```bash
node scripts/smoke-stdio.mjs                      # asserts stdout is pure JSON-RPC
npx @modelcontextprotocol/inspector --cli node dist/index.js --method tools/list
```

## Engine integrity (supply-chain guardrail)
```bash
node dist/index.js verify-engines    # every binary's SHA256 must match engines.lock.json
```

## Fixture scan (manual)
```bash
npx tsx scripts/dev-scan.ts "$(pwd)/fixtures/vulnerable-app"
```
Must detect: client hardcoded secret (CWE-798), USING(true) RLS (CWE-863),
missing RLS (CWE-862), public-env secret, prompt-injection sink (CWE-1426),
SQLi via Opengrep (CWE-89), and — with the Trivy DB present — the lodash/minimist
vulnerable dependency. Safe equivalents (accounts table, parameterized query,
publishable key) must NOT be flagged.

## Guardrail spot-checks
- No `console.log` anywhere in `src/` (stdout must be pure JSON-RPC).
- No raw secret value in any tool output (redaction).
- Compliance output never says "% compliant" / "you pass"; always shows the
  code-visible denominator + disclaimer.
